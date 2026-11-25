//! CTRNAND XORpad and FAT16 extraction for a user's own NAND backup.
//!
//! A NAND image does not contain the boot-ROM-generated NAND keystream. The
//! owner must include the CTRNAND XORpad generated on that same console in
//! the selected NAND.zip. This module only applies that supplied keystream;
//! it does not attempt to derive or manufacture console keys.

use std::io::{self, Read, Seek, SeekFrom, Write};

const O3DS_FAT16_OFFSET: u64 = 0x0B95_CA00;
const N3DS_FAT16_OFFSET: u64 = 0x0B95_AE00;
const O3DS_XORPAD_SIZE: u64 = 0x2F3E_3600;
const N3DS_XORPAD_SIZE: u64 = 0x41D2_D200;
const IO_CHUNK: usize = 1024 * 1024;
const MAX_DIRECTORY_CLUSTERS: usize = 65_536;
const MAX_SYSTEM_SAVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrNandLayout {
    pub offset: u64,
    pub size: u64,
}

pub fn ctrnand_layout(is_new_3ds: bool) -> CtrNandLayout {
    if is_new_3ds {
        CtrNandLayout {
            offset: N3DS_FAT16_OFFSET,
            size: N3DS_XORPAD_SIZE,
        }
    } else {
        CtrNandLayout {
            offset: O3DS_FAT16_OFFSET,
            size: O3DS_XORPAD_SIZE,
        }
    }
}

/// XOR-decrypt the FAT16 image using a fixed-offset CTRNAND padgen output.
/// Both readers begin at byte zero. The NAND reader is advanced to the FAT16
/// partition offset; the xorpad reader is consumed from its first byte.
pub fn decrypt_ctrnand<RN: Read, RX: Read, WO: Write>(
    nand: &mut RN,
    xorpad: &mut RX,
    output: &mut WO,
    layout: CtrNandLayout,
) -> Result<(), String> {
    let mut skip = layout.offset;
    let mut discard = [0u8; 64 * 1024];
    while skip > 0 {
        let count = usize::try_from(skip.min(discard.len() as u64)).unwrap();
        nand.read_exact(&mut discard[..count])
            .map_err(|error| format!("NAND image ended before the CTRNAND partition: {error}"))?;
        skip -= count as u64;
    }

    let mut encrypted = vec![0u8; IO_CHUNK];
    let mut pad = vec![0u8; IO_CHUNK];
    let mut remaining = layout.size;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(IO_CHUNK as u64)).unwrap();
        nand.read_exact(&mut encrypted[..count])
            .map_err(|error| format!("NAND image is truncated inside CTRNAND: {error}"))?;
        xorpad.read_exact(&mut pad[..count])
            .map_err(|error| format!("CTRNAND XORpad is truncated: {error}"))?;
        for (byte, key) in encrypted[..count].iter_mut().zip(&pad[..count]) {
            *byte ^= *key;
        }
        output.write_all(&encrypted[..count])
            .map_err(|error| format!("could not write the decrypted CTRNAND image: {error}"))?;
        remaining -= count as u64;
    }
    output.flush()
        .map_err(|error| format!("could not flush the decrypted CTRNAND image: {error}"))
}

#[derive(Debug, Clone, Copy)]
struct FatEntry {
    name: String,
    attributes: u8,
    first_cluster: u16,
    size: u32,
}

struct Fat16<R> {
    image: R,
    bytes_per_sector: u64,
    sectors_per_cluster: u64,
    reserved_sectors: u64,
    root_entries: u64,
    root_start: u64,
    root_bytes: u64,
    data_start: u64,
    cluster_bytes: u64,
    cluster_count: u64,
}

impl<R: Read + Seek> Fat16<R> {
    fn new(mut image: R) -> Result<Self, String> {
        let mut boot = [0u8; 512];
        image.seek(SeekFrom::Start(0)).map_err(io_error("seek to FAT16 boot sector"))?;
        image.read_exact(&mut boot).map_err(io_error("read FAT16 boot sector"))?;

        if boot[510..512] != [0x55, 0xAA] {
            return Err("the decrypted CTRNAND image has no valid FAT boot-sector signature".to_owned());
        }
        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]) as u64;
        let sectors_per_cluster = boot[13] as u64;
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]) as u64;
        let fat_count = boot[16] as u64;
        let root_entries = u16::from_le_bytes([boot[17], boot[18]]) as u64;
        let total_sectors_16 = u16::from_le_bytes([boot[19], boot[20]]) as u64;
        let sectors_per_fat_16 = u16::from_le_bytes([boot[22], boot[23]]) as u64;
        let total_sectors_32 = u32::from_le_bytes(boot[32..36].try_into().unwrap()) as u64;
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16
        } else {
            total_sectors_32
        };

        if bytes_per_sector != 512
            || sectors_per_cluster == 0
            || !sectors_per_cluster.is_power_of_two()
            || reserved_sectors == 0
            || fat_count == 0
            || sectors_per_fat_16 == 0
            || root_entries == 0
            || total_sectors == 0
        {
            return Err("the decrypted CTRNAND boot sector is not a supported FAT16 volume".to_owned());
        }

        let root_start_sector = reserved_sectors
            .checked_add(fat_count.checked_mul(sectors_per_fat_16)
                .ok_or_else(|| "FAT16 root-directory offset overflow".to_owned())?)
            .ok_or_else(|| "FAT16 root-directory offset overflow".to_owned())?;
        let root_sectors = (root_entries * 32 + bytes_per_sector - 1) / bytes_per_sector;
        let data_start_sector = root_start_sector
            .checked_add(root_sectors)
            .ok_or_else(|| "FAT16 data-region offset overflow".to_owned())?;
        if data_start_sector >= total_sectors {
            return Err("the FAT16 root directory extends beyond the volume".to_owned());
        }
        let cluster_count = (total_sectors - data_start_sector) / sectors_per_cluster;
        if cluster_count < 4 || cluster_count >= 65_525 {
            return Err("the decrypted CTRNAND volume does not have a valid FAT16 cluster count".to_owned());
        }

        Ok(Self {
            image,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            root_entries,
            root_start: root_start_sector * bytes_per_sector,
            root_bytes: root_entries * 32,
            data_start: data_start_sector * bytes_per_sector,
            cluster_bytes: sectors_per_cluster * bytes_per_sector,
            cluster_count,
        })
    }

    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), String> {
        self.image.seek(SeekFrom::Start(offset)).map_err(io_error("seek in FAT16 volume"))?;
        self.image.read_exact(output).map_err(io_error("read FAT16 volume"))
    }

    fn root_entries(&mut self) -> Result<Vec<FatEntry>, String> {
        let mut bytes = vec![0u8; self.root_bytes as usize];
        self.read_at(self.root_start, &mut bytes)?;
        Ok(parse_directory(&bytes))
    }

    fn read_cluster(&mut self, cluster: u16) -> Result<Vec<u8>, String> {
        let cluster = cluster as u64;
        if cluster < 2 || cluster >= self.cluster_count + 2 {
            return Err("FAT16 directory or file references an out-of-range cluster".to_owned());
        }
        let offset = self.data_start + (cluster - 2) * self.cluster_bytes;
        let mut bytes = vec![0u8; self.cluster_bytes as usize];
        self.read_at(offset, &mut bytes)?;
        Ok(bytes)
    }

    fn next_cluster(&mut self, cluster: u16) -> Result<Option<u16>, String> {
        let fat_offset = self.reserved_sectors * self.bytes_per_sector + cluster as u64 * 2;
        let mut raw = [0u8; 2];
        self.read_at(fat_offset, &mut raw)?;
        let next = u16::from_le_bytes(raw);
        match next {
            0x0000 | 0x0001 | 0xFFF0..=0xFFF7 => {
                Err("FAT16 cluster chain contains a free or reserved cluster".to_owned())
            }
            0xFFF8..=0xFFFF => Ok(None),
            _ if next < 2 || next as u64 >= self.cluster_count + 2 => {
                Err("FAT16 cluster chain points outside the volume".to_owned())
            }
            _ => Ok(Some(next)),
        }
    }

    fn directory_entries(&mut self, first_cluster: u16) -> Result<Vec<FatEntry>, String> {
        let mut result = Vec::new();
        let mut cluster = Some(first_cluster);
        let mut visited = std::collections::HashSet::new();
        while let Some(current) = cluster {
            if !visited.insert(current) || visited.len() > MAX_DIRECTORY_CLUSTERS {
                return Err("FAT16 directory contains a cyclic or excessive cluster chain".to_owned());
            }
            let bytes = self.read_cluster(current)?;
            result.extend(parse_directory(&bytes));
            cluster = self.next_cluster(current)?;
        }
        Ok(result)
    }

    fn read_file(&mut self, entry: FatEntry) -> Result<Vec<u8>, String> {
        if entry.size as u64 > MAX_SYSTEM_SAVE_BYTES {
            return Err("the Friends system-save file is larger than the supported limit".to_owned());
        }
        if entry.size == 0 {
            return Ok(Vec::new());
        }
        let mut output = Vec::with_capacity(entry.size as usize);
        let mut cluster = Some(entry.first_cluster);
        let mut visited = std::collections::HashSet::new();
        while let Some(current) = cluster {
            if !visited.insert(current) || visited.len() > MAX_DIRECTORY_CLUSTERS {
                return Err("FAT16 file contains a cyclic or excessive cluster chain".to_owned());
            }
            let bytes = self.read_cluster(current)?;
            let remaining = entry.size as usize - output.len();
            output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
            if output.len() == entry.size as usize {
                break;
            }
            cluster = self.next_cluster(current)?;
        }
        if output.len() != entry.size as usize {
            return Err("FAT16 file cluster chain ended before the declared file size".to_owned());
        }
        Ok(output)
    }
}

/// Locate and extract the Friends system-save DISA file at
/// /data/<ID0>/sysdata/00010032/00000000. The ID0 directory name is
/// console-specific, so it is discovered rather than hard-coded.
pub fn extract_friends_disa<R: Read + Seek>(image: R) -> Result<Vec<u8>, String> {
    let mut fat = Fat16::new(image)?;
    let root = fat.root_entries()?;
    let data_dir = root.into_iter()
        .find(|entry| entry.attributes & 0x10 != 0 && short_name_matches(&entry.name, "data"))
        .ok_or_else(|| "CTRNAND has no /data directory".to_owned())?;

    let mut sysdata_cluster = None;
    for id0 in fat.directory_entries(data_dir.first_cluster)? {
        if id0.attributes & 0x10 == 0 {
            continue;
        }
        for child in fat.directory_entries(id0.first_cluster)? {
            if child.attributes & 0x10 != 0 && short_name_matches(&child.name, "sysdata") {
                sysdata_cluster = Some(child.first_cluster);
                break;
            }
        }
        if sysdata_cluster.is_some() {
            break;
        }
    }
    let sysdata_cluster = sysdata_cluster
        .ok_or_else(|| "CTRNAND has no /data/<ID0>/sysdata directory".to_owned())?;

    let save_dir = fat.directory_entries(sysdata_cluster)?
        .into_iter()
        .find(|entry| entry.attributes & 0x10 != 0 && short_name_matches(&entry.name, "00010032"))
        .ok_or_else(|| "the Friends system save (00010032) is missing from CTRNAND".to_owned())?;
    let save_file = fat.directory_entries(save_dir.first_cluster)?
        .into_iter()
        .find(|entry| entry.attributes & 0x10 == 0 && short_name_matches(&entry.name, "00000000"))
        .ok_or_else(|| "the Friends system-save image (00000000) is missing".to_owned())?;

    let bytes = fat.read_file(save_file)?;
    if bytes.len() < 0x200 || &bytes[0x100..0x104] != b"DISA" {
        return Err("the Friends system-save file is not a valid DISA archive".to_owned());
    }
    Ok(bytes)
}

fn parse_directory(bytes: &[u8]) -> Vec<FatEntry> {
    let mut entries = Vec::new();
    for raw in bytes.chunks_exact(32) {
        let first = raw[0];
        if first == 0x00 {
            break;
        }
        if first == 0xE5 || raw[11] == 0x0F || raw[11] & 0x08 != 0 {
            continue;
        }
        let first_cluster = u16::from_le_bytes([raw[26], raw[27]]);
        let size = u32::from_le_bytes(raw[28..32].try_into().unwrap());
        let base = String::from_utf8_lossy(&raw[..8]).trim_end().to_owned();
        let extension = String::from_utf8_lossy(&raw[8..11]).trim_end().to_owned();
        let name = if extension.is_empty() { base } else { format!("{base}.{extension}") };
        entries.push(FatEntry {
            name,
            attributes: raw[11],
            first_cluster,
            size,
        });
    }
    entries
}

fn short_name_matches(name: &str, expected: &str) -> bool {
    name.eq_ignore_ascii_case(expected)
}

fn io_error(context: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{context}: {error}")
}
