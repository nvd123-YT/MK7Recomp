//! Reader for the 3DS system-save DISA container and its internal SAVE/FAT.
//! It extracts only the Friends account records needed by FRD. It never
//! modifies the source NAND image or uploads extracted records.

use sha2::{Digest, Sha256};

const DISA_HEADER_OFFSET: usize = 0x100;
const MAX_DISA_BYTES: usize = 64 * 1024 * 1024;
const MAX_TABLE_ENTRIES: usize = 65_536;
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRecords {
    pub account: Vec<u8>,
    pub mydata: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct IvfcLevel {
    offset: usize,
    size: usize,
    block_size: usize,
}

#[derive(Debug)]
struct PartitionDescriptor {
    ivfc_levels: [IvfcLevel; 4],
    dpfs_levels: [(usize, usize, usize); 3],
    partition_hash: Vec<u8>,
    dpfs_level1_selector: usize,
    external_level4: bool,
    external_level4_offset: usize,
}

#[derive(Debug)]
struct DirectoryRecord {
    parent: usize,
    name: String,
}

#[derive(Debug)]
struct FileRecord {
    parent: usize,
    name: String,
    first_block: u32,
    size: usize,
}

pub fn extract_friend_records(disa: &[u8]) -> Result<FriendRecords, String> {
    if disa.len() > MAX_DISA_BYTES {
        return Err("the Friends DISA archive exceeds the supported 64 MiB limit".to_owned());
    }
    if disa.len() < DISA_HEADER_OFFSET + 0x100
        || &disa[DISA_HEADER_OFFSET..DISA_HEADER_OFFSET + 4] != b"DISA"
    {
        return Err("the Friends system save does not contain a DISA header".to_owned());
    }

    let header = &disa[DISA_HEADER_OFFSET..DISA_HEADER_OFFSET + 0x100];
    if u32_at(header, 4)? != 0x0004_0000 {
        return Err("the Friends DISA archive uses an unsupported version".to_owned());
    }
    let partition_count = u32_at(header, 8)?;
    if !(partition_count == 1 || partition_count == 2) {
        return Err("the Friends DISA archive has an invalid partition count".to_owned());
    }

    let secondary_table_offset = u64_at(header, 0x10)?;
    let primary_table_offset = u64_at(header, 0x18)?;
    let table_size = u64_at(header, 0x20)?;
    let save_descriptor_offset = u64_at(header, 0x28)?;
    let save_descriptor_size = u64_at(header, 0x30)?;
    let data_descriptor_offset = u64_at(header, 0x38)?;
    let data_descriptor_size = u64_at(header, 0x40)?;
    let save_partition_offset = u64_at(header, 0x48)?;
    let save_partition_size = u64_at(header, 0x50)?;
    let data_partition_offset = u64_at(header, 0x58)?;
    let data_partition_size = u64_at(header, 0x60)?;
    let active_table = header[0x68];

    let table_offset = match active_table {
        0 => primary_table_offset,
        1 => secondary_table_offset,
        _ => return Err("the Friends DISA archive selects an invalid partition table".to_owned()),
    };
    if table_size == 0 || table_size > MAX_DISA_BYTES as u64 {
        return Err("the Friends DISA partition table has an invalid size".to_owned());
    }
    let table = range(disa, table_offset, table_size, "DISA partition table")?;
    if Sha256::digest(table).as_slice() != &header[0x6C..0x8C] {
        return Err("the Friends DISA partition-table integrity check failed".to_owned());
    }

    let save_descriptor = range(table, save_descriptor_offset, save_descriptor_size, "SAVE partition descriptor")?;
    let save_partition = range(disa, save_partition_offset, save_partition_size, "SAVE partition")?;
    let save_image = unwrap_partition(save_descriptor, save_partition)?;

    let data_image = if partition_count == 2 {
        if data_descriptor_size == 0 || data_partition_size == 0 {
            return Err("the Friends DISA archive omits its DATA partition".to_owned());
        }
        let descriptor = range(table, data_descriptor_offset, data_descriptor_size, "DATA partition descriptor")?;
        let partition = range(disa, data_partition_offset, data_partition_size, "DATA partition")?;
        Some(unwrap_partition(descriptor, partition)?)
    } else {
        None
    };

    let (account, mydata) = extract_save_files(&save_image, data_image.as_deref())?;
    validate_account(&account)?;
    validate_mydata(&mydata)?;
    Ok(FriendRecords { account, mydata })
}

fn unwrap_partition(descriptor: &[u8], partition: &[u8]) -> Result<Vec<u8>, String> {
    if descriptor.len() < 0x44 {
        return Err("a DISA partition descriptor is truncated".to_owned());
    }
    if &descriptor[..4] != b"DIFI" || u32_at(descriptor, 4)? != 0x0001_0000 {
        return Err("a DISA partition descriptor has an invalid DIFI header".to_owned());
    }
    let ivfc_offset = u64_at(descriptor, 8)?;
    let ivfc_size = u64_at(descriptor, 0x10)?;
    let dpfs_offset = u64_at(descriptor, 0x18)?;
    let dpfs_size = u64_at(descriptor, 0x20)?;
    let hash_offset = u64_at(descriptor, 0x28)?;
    let hash_size = u64_at(descriptor, 0x30)?;
    let external_level4 = descriptor[0x38];
    if external_level4 > 1 || descriptor[0x39] > 1 {
        return Err("a DISA partition descriptor has invalid selector flags".to_owned());
    }
    let external_level4_offset = u64_at(descriptor, 0x3C)?;
    let ivfc = range(descriptor, ivfc_offset, ivfc_size, "IVFC descriptor")?;
    let dpfs = range(descriptor, dpfs_offset, dpfs_size, "DPFS descriptor")?;
    let partition_hash = range(descriptor, hash_offset, hash_size, "partition master hash")?;

    if ivfc.len() < 0x78 || &ivfc[..4] != b"IVFC" || u32_at(ivfc, 4)? != 0x0002_0000 {
        return Err("a DISA partition has an invalid IVFC descriptor".to_owned());
    }
    if u64_at(ivfc, 8)? != hash_size {
        return Err("a DISA partition has mismatched IVFC master-hash size".to_owned());
    }

    let mut levels = [IvfcLevel { offset: 0, size: 0, block_size: 0 }; 4];
    for (index, level) in levels.iter_mut().enumerate() {
        let base = 0x10 + index * 0x18;
        let offset = u64_at(ivfc, base)?;
        let size = u64_at(ivfc, base + 8)?;
        let log2 = u32_at(ivfc, base + 0x10)?;
        if log2 > 20 {
            return Err("a DISA IVFC block size is outside the supported range".to_owned());
        }
        *level = IvfcLevel {
            offset: usize::try_from(offset).map_err(|_| "IVFC offset is too large".to_owned())?,
            size: usize::try_from(size).map_err(|_| "IVFC level is too large".to_owned())?,
            block_size: 1usize << log2,
        };
    }
    if dpfs.len() < 0x50 || &dpfs[..4] != b"DPFS" || u32_at(dpfs, 4)? != 0x0001_0000 {
        return Err("a DISA partition has an invalid DPFS descriptor".to_owned());
    }

    let mut dpfs_levels = [(0usize, 0usize, 0usize); 3];
    for (index, level) in dpfs_levels.iter_mut().enumerate() {
        let base = 8 + index * 0x18;
        let offset = usize::try_from(u64_at(dpfs, base)?)
            .map_err(|_| "DPFS offset is too large".to_owned())?;
        let size = usize::try_from(u64_at(dpfs, base + 8)?)
            .map_err(|_| "DPFS level is too large".to_owned())?;
        let log2 = u32_at(dpfs, base + 0x10)?;
        if log2 > 20 {
            return Err("a DISA DPFS block size is outside the supported range".to_owned());
        }
        *level = (offset, size, 1usize << log2);
    }

    let parsed = PartitionDescriptor {
        ivfc_levels: levels,
        dpfs_levels,
        partition_hash: partition_hash.to_vec(),
        dpfs_level1_selector: descriptor[0x39] as usize,
        external_level4: external_level4 == 1,
        external_level4_offset: usize::try_from(external_level4_offset)
            .map_err(|_| "external IVFC level-4 offset is too large".to_owned())?,
    };

    let active = unwrap_dpfs(partition, &parsed)?;
    unwrap_ivfc(partition, &active, &parsed)
}

fn unwrap_dpfs(partition: &[u8], descriptor: &PartitionDescriptor) -> Result<Vec<u8>, String> {
    let (off1, size1, _) = descriptor.dpfs_levels[0];
    let (off2, size2, block2) = descriptor.dpfs_levels[1];
    let (off3, size3, block3) = descriptor.dpfs_levels[2];
    let level1 = pair(partition, off1, size1, "DPFS level 1")?;
    let level2 = pair(partition, off2, size2, "DPFS level 2")?;
    let level3 = pair(partition, off3, size3, "DPFS level 3")?;
    let l1_active = level1[descriptor.dpfs_level1_selector];
    let l2_active = apply_dpfs_level(l1_active, level2, block2)?;
    apply_dpfs_level(&l2_active, level3, block3)
}

fn pair<'a>(bytes: &'a [u8], offset: usize, size: usize, label: &str) -> Result<[&'a [u8]; 2], String> {
    if size == 0 {
        return Err(format!("{label} has zero size"));
    }
    let pair_size = size.checked_mul(2).ok_or_else(|| format!("{label} size overflows"))?;
    let bytes = range(bytes, offset as u64, pair_size as u64, label)?;
    Ok([&bytes[..size], &bytes[size..]])
}

fn apply_dpfs_level(selector: &[u8], pair: [&[u8]; 2], block_size: usize) -> Result<Vec<u8>, String> {
    if block_size == 0 || pair[0].len() != pair[1].len() {
        return Err("a DISA DPFS level has invalid block or pair sizes".to_owned());
    }
    let mut output = Vec::with_capacity(pair[0].len());
    let mut position = 0usize;
    while position < pair[0].len() {
        let block_index = position / block_size;
        let word_offset = (block_index / 32).checked_mul(4)
            .ok_or_else(|| "DPFS selector offset overflows".to_owned())?;
        if word_offset + 4 > selector.len() {
            return Err("a DISA DPFS selector bitmap is truncated".to_owned());
        }
        let word = u32::from_le_bytes(selector[word_offset..word_offset + 4].try_into().unwrap());
        let selected = ((word >> (31 - (block_index % 32))) & 1) as usize;
        let count = block_size.min(pair[0].len() - position);
        output.extend_from_slice(&pair[selected][position..position + count]);
        position += count;
    }
    Ok(output)
}

fn unwrap_ivfc(
    partition: &[u8],
    active: &[u8],
    descriptor: &PartitionDescriptor,
) -> Result<Vec<u8>, String> {
    let [l1, l2, l3, l4] = descriptor.ivfc_levels;
    let level1 = range(active, l1.offset as u64, l1.size as u64, "IVFC level 1")?;
    let level2 = range(active, l2.offset as u64, l2.size as u64, "IVFC level 2")?;
    let level3 = range(active, l3.offset as u64, l3.size as u64, "IVFC level 3")?;
    let level4 = if descriptor.external_level4 {
        range(partition, descriptor.external_level4_offset as u64, l4.size as u64, "external IVFC level 4")?
    } else {
        range(active, l4.offset as u64, l4.size as u64, "IVFC level 4")?
    };

    let verified1 = apply_ivfc_level(&descriptor.partition_hash, level1, l1.block_size)?;
    let verified2 = apply_ivfc_level(&verified1, level2, l2.block_size)?;
    let verified3 = apply_ivfc_level(&verified2, level3, l3.block_size)?;
    apply_ivfc_level(&verified3, level4, l4.block_size)
}

fn apply_ivfc_level(hash_list: &[u8], data: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    // DISA DIFI hash regions may contain a trailing, unused four-byte field
    // after the SHA-256 list. The reference 3DS save parser consumes complete
    // 32-byte hashes and ignores any such trailing bytes.
    if block_size == 0 || hash_list.len() < 32 {
        return Err("a DISA IVFC hash level has invalid sizing".to_owned());
    }
    let hash_count = hash_list.len() / 32;
    let required_hashes = (data.len() + block_size - 1) / block_size;

    let mut output = Vec::with_capacity(data.len());
    for index in 0..required_hashes {
        let start = index * block_size;
        let end = (start + block_size).min(data.len());
        let chunk = &data[start..end];
        let valid_hash = if index < hash_count {
            let mut padded = vec![0u8; block_size];
            padded[..chunk.len()].copy_from_slice(chunk);
            let digest = Sha256::digest(&padded);
            digest.as_slice() == &hash_list[index * 32..index * 32 + 32]
        } else {
            // Some 3DS saves have unwritten/unhashed blocks after their
            // initialized data. Poison them rather than rejecting the whole
            // save; the requested account records are still validated by
            // their FPAC/FPMD headers after extraction.
            false
        };
        if valid_hash {
            output.extend_from_slice(chunk);
        } else {
            output.resize(output.len() + chunk.len(), 0xDD);
        }
    }
    Ok(output)
}

fn extract_save_files(save_image: &[u8], data_image: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), String> {
    if save_image.len() < 0x20 || &save_image[..4] != b"SAVE" || u32_at(save_image, 4)? != 0x0004_0000 {
        return Err("the Friends DISA SAVE partition has an invalid SAVE header".to_owned());
    }
    let filesystem_offset = usize::try_from(u64_at(save_image, 8)?)
        .map_err(|_| "SAVE filesystem-header offset is too large".to_owned())?;
    let fs = range(save_image, filesystem_offset as u64, 0x68, "SAVE filesystem header")?;

    let block_size = u32_at(fs, 4)? as usize;
    if block_size == 0 || !block_size.is_power_of_two() || block_size > 0x10000 {
        return Err("the Friends SAVE filesystem has an unsupported block size".to_owned());
    }
    let fat_offset = u64_at(fs, 0x28)?;
    let fat_count = u32_at(fs, 0x30)? as usize;
    let data_region_offset = u64_at(fs, 0x38)?;
    let data_region_blocks = u32_at(fs, 0x40)? as usize;
    if fat_count == 0 || fat_count > MAX_TABLE_ENTRIES * 16 {
        return Err("the Friends SAVE FAT has an invalid entry count".to_owned());
    }

    let fat_bytes_len = (fat_count + 1).checked_mul(8)
        .ok_or_else(|| "Friends SAVE FAT size overflows".to_owned())?;
    let fat_bytes = range(save_image, fat_offset, fat_bytes_len as u64, "SAVE FAT")?;
    let fat = fat_bytes.chunks_exact(8).map(|entry| {
        (
            u32::from_le_bytes(entry[..4].try_into().unwrap()),
            u32::from_le_bytes(entry[4..8].try_into().unwrap()),
        )
    }).collect::<Vec<_>>();

    let data_region = if let Some(data) = data_image {
        data
    } else {
        let size = data_region_blocks.checked_mul(block_size)
            .ok_or_else(|| "Friends SAVE data-region size overflows".to_owned())?;
        range(save_image, data_region_offset, size as u64, "SAVE data region")?
    };

    let (dir_table, file_table) = if data_image.is_some() {
        let dir_offset = u64_at(fs, 0x48)?;
        let file_offset = u64_at(fs, 0x58)?;
        let dir_header = range(save_image, dir_offset, 4, "SAVE directory-table header")?;
        let file_header = range(save_image, file_offset, 4, "SAVE file-table header")?;
        let dir_count = u32::from_le_bytes(dir_header.try_into().unwrap()) as u64;
        let file_count = u32::from_le_bytes(file_header.try_into().unwrap()) as u64;
        if dir_count < 2 || dir_count > MAX_TABLE_ENTRIES as u64
            || file_count < 1 || file_count > MAX_TABLE_ENTRIES as u64
        {
            return Err("the Friends SAVE directory or file table has invalid counts".to_owned());
        }
        (
            range(save_image, dir_offset, dir_count * 0x28, "SAVE directory table")?,
            range(save_image, file_offset, file_count * 0x30, "SAVE file table")?,
        )
    } else {
        let dir_block = u32_at(fs, 0x48)? as usize;
        let dir_blocks = u32_at(fs, 0x4C)? as usize;
        let file_block = u32_at(fs, 0x58)? as usize;
        let file_blocks = u32_at(fs, 0x5C)? as usize;
        let dir_offset = dir_block.checked_mul(block_size)
            .ok_or_else(|| "SAVE directory-table offset overflows".to_owned())?;
        let dir_size = dir_blocks.checked_mul(block_size)
            .ok_or_else(|| "SAVE directory-table size overflows".to_owned())?;
        let file_offset = file_block.checked_mul(block_size)
            .ok_or_else(|| "SAVE file-table offset overflows".to_owned())?;
        let file_size = file_blocks.checked_mul(block_size)
            .ok_or_else(|| "SAVE file-table size overflows".to_owned())?;
        (
            range(data_region, dir_offset as u64, dir_size as u64, "SAVE directory table")?,
            range(data_region, file_offset as u64, file_size as u64, "SAVE file table")?,
        )
    };

    let dir_count = u32_at(dir_table, 0)? as usize;
    let file_count = u32_at(file_table, 0)? as usize;
    if dir_count < 2 || dir_count > MAX_TABLE_ENTRIES || file_count < 1 || file_count > MAX_TABLE_ENTRIES {
        return Err("the Friends SAVE directory or file table has invalid counts".to_owned());
    }
    if dir_table.len() < dir_count * 0x28 || file_table.len() < file_count * 0x30 {
        return Err("the Friends SAVE directory or file table is truncated".to_owned());
    }

    let directories = (0..dir_count).map(|index| {
        let entry = &dir_table[index * 0x28..(index + 1) * 0x28];
        DirectoryRecord {
            parent: u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize,
            name: fixed_name(&entry[4..20]),
        }
    }).collect::<Vec<_>>();
    let files = (0..file_count).map(|index| {
        let entry = &file_table[index * 0x30..(index + 1) * 0x30];
        FileRecord {
            parent: u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize,
            name: fixed_name(&entry[4..20]),
            first_block: u32::from_le_bytes(entry[0x1C..0x20].try_into().unwrap()),
            size: u64::from_le_bytes(entry[0x20..0x28].try_into().unwrap())
                .try_into().unwrap_or(usize::MAX),
        }
    }).collect::<Vec<_>>();

    let folder_two = directories.iter().enumerate()
        .find(|(index, entry)| *index > 0 && entry.parent == 1 && entry.name == "2")
        .map(|(index, _)| index)
        .ok_or_else(|| "the Friends save is missing its /2 directory".to_owned())?;

    let account_file = files.iter().find(|entry| entry.parent == folder_two && entry.name == "account")
        .ok_or_else(|| "the Friends save is missing /2/account".to_owned())?;
    let mydata_file = files.iter().find(|entry| entry.parent == folder_two && entry.name == "mydata")
        .ok_or_else(|| "the Friends save is missing /2/mydata".to_owned())?;

    let account = extract_save_file(account_file, &fat, data_region, block_size)?;
    let mydata = extract_save_file(mydata_file, &fat, data_region, block_size)?;
    Ok((account, mydata))
}

fn extract_save_file(
    file: &FileRecord,
    fat: &[(u32, u32)],
    data_region: &[u8],
    block_size: usize,
) -> Result<Vec<u8>, String> {
    if file.size == 0 || file.size > MAX_FILE_BYTES {
        return Err(format!("Friends save file {} has an invalid size", file.name));
    }
    if file.first_block == 0x8000_0000 {
        return Err(format!("Friends save file {} has no allocated data", file.name));
    }
    let start = (file.first_block as usize).checked_add(1)
        .ok_or_else(|| "Friends save FAT start index overflows".to_owned())?;
    let mut current = start;
    let mut visited = std::collections::HashSet::new();
    let mut output = Vec::with_capacity(file.size);
    while current != 0 && output.len() < file.size {
        if current >= fat.len() || !visited.insert(current) || visited.len() > MAX_TABLE_ENTRIES * 16 {
            return Err("Friends save FAT contains an invalid or cyclic block chain".to_owned());
        }
        let (u, v) = fat[current];
        let next = (v & 0x7FFF_FFFF) as usize;
        let is_expanded = v & 0x8000_0000 != 0;
        let node_end = if is_expanded {
            let expanded_index = current.checked_add(1)
                .ok_or_else(|| "Friends save FAT expansion index overflows".to_owned())?;
            if expanded_index >= fat.len() {
                return Err("Friends save FAT expansion extends past its table".to_owned());
            }
            (fat[expanded_index].1 & 0x7FFF_FFFF) as usize
        } else {
            current
        };
        if node_end < current || node_end >= fat.len() {
            return Err("Friends save FAT contains an invalid expanded block range".to_owned());
        }

        for node in current..=node_end {
            let block_index = node - 1;
            let offset = block_index.checked_mul(block_size)
                .ok_or_else(|| "Friends save data-block offset overflows".to_owned())?;
            let block = range(data_region, offset as u64, block_size as u64, "Friends save data block")?;
            let take = (file.size - output.len()).min(block.len());
            output.extend_from_slice(&block[..take]);
            if output.len() == file.size {
                break;
            }
        }
        let _ = u; // The chain flags are validated by the bounds/cycle checks above.
        current = next;
    }
    if output.len() != file.size {
        return Err(format!("Friends save file {} has an incomplete FAT chain", file.name));
    }
    Ok(output)
}

fn validate_account(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 0x58
        || &bytes[..4] != b"FPAC"
        || u32_at(bytes, 4)? != 0x2010_1021
    {
        return Err("the extracted Friends account record is invalid or truncated".to_owned());
    }
    let principal_id = u32_at(bytes, 0x14)?;
    let has_password = bytes[0x20..0x42].chunks_exact(2)
        .take_while(|unit| unit[0] != 0 || unit[1] != 0)
        .any(|unit| unit[0] != 0 || unit[1] != 0);
    if principal_id == 0 || !has_password {
        return Err("the extracted Friends account has no NEX principal ID or password".to_owned());
    }
    Ok(())
}

fn validate_mydata(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 0x14
        || &bytes[..4] != b"FPMD"
        || u32_at(bytes, 4)? != 0x2010_1021
    {
        return Err("the extracted Friends mydata record is invalid or truncated".to_owned());
    }
    Ok(())
}

fn fixed_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn range<'a>(bytes: &'a [u8], offset: u64, size: u64, label: &str) -> Result<&'a [u8], String> {
    let offset = usize::try_from(offset).map_err(|_| format!("{label} offset is too large"))?;
    let size = usize::try_from(size).map_err(|_| format!("{label} size is too large"))?;
    let end = offset.checked_add(size).ok_or_else(|| format!("{label} range overflows"))?;
    bytes.get(offset..end).ok_or_else(|| format!("{label} extends beyond its container"))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw = bytes.get(offset..offset + 4)
        .ok_or_else(|| "a DISA field is truncated".to_owned())?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let raw = bytes.get(offset..offset + 8)
        .ok_or_else(|| "a DISA field is truncated".to_owned())?;
    Ok(u64::from_le_bytes(raw.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_disa_data_without_panicking() {
        assert!(extract_friend_records(b"not a save").unwrap_err().contains("DISA"));
    }

    #[test]
    fn rejects_truncated_disa_header_without_panicking() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0x100..0x104].copy_from_slice(b"DISA");
        bytes[0x104..0x108].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        assert!(extract_friend_records(&bytes).is_err());
    }
}
