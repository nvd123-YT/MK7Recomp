//! Safe inspection and first-stage import of a user's own GodMode9 NAND backup.
//!
//! This module does not decrypt CTRNAND. It validates the NCSD image and
//! GodMode9's embedded essential.exefs block, then installs the signed
//! device seed and matching SecureInfo locally. Friends save extraction is a
//! separate step and must not be reported as complete until CTRNAND is
//! correctly decrypted and the DISA archive has been parsed.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const SECTOR_SIZE: u64 = 0x200;
const ESSENTIAL_OFFSET: usize = 0x200;
const EXEFS_HEADER_SIZE: usize = 0x200;
const ESSENTIAL_SIZE: usize = 0x2200;
const PREFIX_SIZE: usize = ESSENTIAL_OFFSET + ESSENTIAL_SIZE;
const MAX_IMAGE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NandBackupReport {
    /// File within a ZIP, or the input file name for a raw image.
    pub image_name: String,
    pub image_size: u64,
    pub console_model: &'static str,
    pub region: &'static str,
    /// Device serial is shown only in the local import result, never logged.
    pub serial_number: String,
}

/// Inspect a raw NAND image or a ZIP containing exactly one recognized NAND
/// image. Only the first 0x2400 bytes are read; the multi-gigabyte image is
/// never expanded into memory.
pub fn inspect_nand_backup(path: &Path) -> Result<NandBackupReport, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("could not open NAND backup: {error}"))?;
    let file_size = file.metadata()
        .map_err(|error| format!("could not inspect NAND backup: {error}"))?
        .len();
    if file_size < 4 {
        return Err("the selected file is too small to be a NAND backup".to_owned());
    }

    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)
        .map_err(|error| format!("could not read backup header: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("could not seek in backup: {error}"))?;

    let (image_name, image_size, prefix) = if signature == *b"PK\x03\x04"
        || signature == *b"PK\x05\x06"
        || signature == *b"PK\x07\x08"
    {
        read_zip_image(file)?
    } else {
        if file_size > MAX_IMAGE_SIZE {
            return Err("the NAND image is larger than the supported 4 GiB limit".to_owned());
        }
        if file_size < PREFIX_SIZE as u64 {
            return Err("the NAND image is truncated; a GodMode9 backup with embedded essential.exefs is required".to_owned());
        }
        let mut prefix = vec![0u8; PREFIX_SIZE];
        file.read_exact(&mut prefix)
            .map_err(|error| format!("could not read NAND backup header: {error}"))?;
        (path.file_name().and_then(|name| name.to_str()).unwrap_or("NAND image").to_owned(), file_size, prefix)
    };

    parse_prefix(&image_name, image_size, &prefix)
}

fn read_zip_image(file: File) -> Result<(String, u64, Vec<u8>), String> {
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| format!("NAND.zip is not a readable ZIP archive: {error}"))?;
    if archive.len() == 0 || archive.len() > MAX_ZIP_ENTRIES {
        return Err(format!("the ZIP must contain between 1 and {MAX_ZIP_ENTRIES} entries"));
    }

    let mut candidates = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)
            .map_err(|error| format!("could not inspect ZIP entry {index}: {error}"))?;
        if entry.is_dir() {
            continue;
        }
        let basename = entry.name().rsplit('/').next().unwrap_or(entry.name());
        let normalized = basename.to_ascii_lowercase();
        if matches!(normalized.as_str(), "nand.bin" | "sysnand.bin" | "emunand.bin" | "nandmin.bin") {
            candidates.push((index, entry.name().to_owned(), entry.size()));
        }
    }

    if candidates.is_empty() {
        return Err("NAND.zip does not contain NAND.bin, SysNAND.bin, EmuNAND.bin, or NANDmin.bin".to_owned());
    }
    if candidates.len() != 1 {
        return Err("NAND.zip contains more than one NAND image; keep only the backup you want to import".to_owned());
    }

    let (index, image_name, image_size) = candidates.remove(0);
    if image_size > MAX_IMAGE_SIZE {
        return Err("the NAND image inside the ZIP is larger than the supported 4 GiB limit".to_owned());
    }
    if image_size < PREFIX_SIZE as u64 {
        return Err("the NAND image inside the ZIP is truncated or does not contain an embedded essential backup".to_owned());
    }

    let mut entry = archive.by_index(index)
        .map_err(|error| format!("could not open {image_name} in NAND.zip: {error}"))?;
    let mut prefix = vec![0u8; PREFIX_SIZE];
    entry.read_exact(&mut prefix)
        .map_err(|error| format!("could not read the NAND header and embedded essential backup from {image_name}: {error}"))?;
    Ok((image_name, image_size, prefix))
}

fn parse_prefix(image_name: &str, image_size: u64, prefix: &[u8]) -> Result<NandBackupReport, String> {
    if prefix.len() < PREFIX_SIZE {
        return Err("the NAND header is incomplete".to_owned());
    }
    let ncsd = &prefix[..0x200];
    if &ncsd[0x100..0x104] != b"NCSD" {
        return Err("the selected image does not have a Nintendo 3DS NAND NCSD header".to_owned());
    }

    // GodMode9 rejects cartridge NCSD images here: a NAND header has a zero
    // media ID and at least one FIRM partition.
    if ncsd[0x108..0x110].iter().any(|byte| *byte != 0) {
        return Err("the selected NCSD image has a cartridge media ID, not a NAND media ID".to_owned());
    }
    let declared_sectors = u32::from_le_bytes(ncsd[0x104..0x108].try_into().unwrap()) as u64;
    let declared_bytes = declared_sectors.checked_mul(SECTOR_SIZE)
        .ok_or_else(|| "NAND image size overflows".to_owned())?;
    if declared_bytes > image_size || declared_bytes < PREFIX_SIZE as u64 {
        return Err("the NAND image is truncated or its NCSD size is invalid".to_owned());
    }

    let mut last_end = 0u64;
    let mut partitions = 0usize;
    let mut firm_partitions = 0usize;
    for index in 0..8 {
        let fs_type = ncsd[0x110 + index];
        let offset = u32::from_le_bytes(ncsd[0x120 + index * 8..0x124 + index * 8].try_into().unwrap()) as u64;
        let size = u32::from_le_bytes(ncsd[0x124 + index * 8..0x128 + index * 8].try_into().unwrap()) as u64;
        if size == 0 {
            if fs_type != 0 {
                return Err("the NAND NCSD partition table contains an empty partition with a type".to_owned());
            }
            continue;
        }
        if fs_type == 0 || offset < last_end {
            return Err("the NAND NCSD partition table is malformed or overlapping".to_owned());
        }
        let end = offset.checked_add(size)
            .ok_or_else(|| "NAND partition size overflows".to_owned())?;
        if end > declared_sectors {
            return Err("a NAND partition extends beyond the declared image size".to_owned());
        }
        last_end = end;
        partitions += 1;
        if fs_type == 3 {
            firm_partitions += 1;
        }
    }
    if partitions < 2 || firm_partitions == 0 {
        return Err("the image does not contain the expected NAND and FIRM partitions".to_owned());
    }

    let essential = &prefix[ESSENTIAL_OFFSET..ESSENTIAL_OFFSET + ESSENTIAL_SIZE];
    if &essential[EXEFS_HEADER_SIZE..EXEFS_HEADER_SIZE + 0x200] != ncsd {
        return Err("the embedded essential.exefs NAND header does not match the image header".to_owned());
    }
    validate_essential(essential)?;

    let secure = essential_file(essential, 1);
    let serial_bytes = &secure[0x102..0x111];
    let serial_end = serial_bytes.iter().position(|byte| *byte == 0).unwrap_or(serial_bytes.len());
    let serial_number = std::str::from_utf8(&serial_bytes[..serial_end])
        .map_err(|_| "SecureInfo contains a non-ASCII serial number".to_owned())?
        .trim()
        .to_owned();
    if serial_number.is_empty() {
        return Err("SecureInfo does not contain a serial number".to_owned());
    }
    let model = match serial_number.as_bytes()[0] {
        b'C' => "Old 3DS",
        b'S' => "New 3DS",
        b'A' => "2DS",
        b'Y' => "New 2DS XL",
        b'Q' => "New 3DS XL",
        b'N' => "Nintendo 3DS development unit",
        _ => return Err("SecureInfo contains an unrecognized 3DS model serial prefix".to_owned()),
    };
    let region = match secure[0x100] {
        0 => "Japan",
        1 => "USA",
        2 => "Europe",
        3 => "Australia",
        4 => "China",
        5 => "Korea",
        6 => "Taiwan",
        _ => "Unknown",
    };

    Ok(NandBackupReport {
        image_name: image_name.to_owned(),
        image_size,
        console_model: model,
        region,
        serial_number,
    })
}

/// Extract the device records in GodMode9's essential backup into the
/// application's private sysdata directory. The NAND image itself is never
/// copied, and no console data is uploaded. This does NOT decrypt CTRNAND or
/// extract the Friends system-save archive.
pub fn import_nand_backup(path: &Path, data_dir: &Path) -> Result<NandBackupReport, String> {
    let mut report = inspect_nand_backup(path)?;
    let prefix = read_prefix_again(path, &report.image_name)?;
    let essential = &prefix[ESSENTIAL_OFFSET..ESSENTIAL_OFFSET + ESSENTIAL_SIZE];

    let sysdata = data_dir.join("sysdata");
    fs::create_dir_all(&sysdata)
        .map_err(|error| format!("could not create the application's private system-data folder: {error}"))?;
    set_private_directory_permissions(&sysdata)?;

    let seed = essential_file(essential, 3);
    if seed.len() != 0x110 || seed[0x108..0x110].iter().all(|byte| *byte == 0) {
        return Err("the embedded LocalFriendCodeSeed_B record is empty or invalid".to_owned());
    }
    let secure = essential_file(essential, 1);
    let movable = essential_file(essential, 2);
    let otp = essential_file(essential, 5);

    let mut mac = [0u8; 6];
    generate_virtual_nintendo_mac(&mut mac)?;
    let mac_text = format_mac(mac);
    let nasc_config = serde_json::json!({
        "mac_address": mac_text,
        "bssid": mac_text,
        "apinfo": "01:0000000000",
        "device_name": "Mario Kart 7",
        "serial_number": report.serial_number,
        "fpd_version": 16
    });
    let nasc_bytes = serde_json::to_vec_pretty(&nasc_config)
        .map_err(|error| format!("could not prepare local network configuration: {error}"))?;

    let outputs = [
        (sysdata.join("LocalFriendCodeSeed_B"), seed),
        (sysdata.join("SecureInfo_A"), secure),
        (sysdata.join("movable.sed"), movable),
        (sysdata.join("otp.bin"), otp),
        (sysdata.join("nasc.json"), nasc_bytes.as_slice()),
    ];
    for (target, _) in &outputs {
        if target.exists() {
            return Err(format!(
                "{} already exists; import was stopped without overwriting existing system data",
                target.file_name().and_then(|name| name.to_str()).unwrap_or("system file")
            ));
        }
    }

    let mut staged = Vec::<(PathBuf, PathBuf)>::new();
    for (target, bytes) in outputs {
        let temporary = target.with_extension(format!("import-{}.tmp", std::process::id()));
        if let Err(error) = write_private_new(&temporary, bytes) {
            for (temporary, _) in &staged {
                let _ = fs::remove_file(temporary);
            }
            let _ = fs::remove_file(&temporary);
            return Err(format!("could not stage {}: {error}", target.display()));
        }
        staged.push((temporary, target));
    }

    for (temporary, target) in &staged {
        if let Err(error) = fs::rename(temporary, target) {
            for (_, committed) in &staged {
                let _ = fs::remove_file(committed);
            }
            for (pending, _) in &staged {
                let _ = fs::remove_file(pending);
            }
            return Err(format!("could not install imported system data: {error}"));
        }
    }

    report.image_name = report.image_name.clone();
    Ok(report)
}

fn read_prefix_again(path: &Path, image_name: &str) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("could not reopen NAND backup: {error}"))?;
    let mut signature = [0u8; 4];
    let mut file = file;
    file.read_exact(&mut signature).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
    let mut prefix = vec![0u8; PREFIX_SIZE];
    if signature == *b"PK\x03\x04" || signature == *b"PK\x05\x06" || signature == *b"PK\x07\x08" {
        let mut archive = zip::ZipArchive::new(file).map_err(|error| format!("could not reopen ZIP: {error}"))?;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
            if entry.name() == image_name {
                entry.read_exact(&mut prefix).map_err(|error| format!("could not reread NAND prefix: {error}"))?;
                return Ok(prefix);
            }
        }
        Err("the NAND image disappeared from the ZIP archive".to_owned())
    } else {
        file.read_exact(&mut prefix).map_err(|error| format!("could not reread NAND prefix: {error}"))?;
        Ok(prefix)
    }
}

fn validate_essential(essential: &[u8]) -> Result<(), String> {
    if essential.len() != ESSENTIAL_SIZE {
        return Err("the embedded essential backup has an invalid size".to_owned());
    }
    // The first six records are mandatory. GodMode9 may omit HWCAL0/1 when
    // they cannot be read, so those last two records are optional.
    const REQUIRED: [(&str, u32, u32); 6] = [
        ("nand_hdr", 0x0000, 0x0200),
        ("secinfo",  0x0200, 0x0111),
        ("movable",  0x0400, 0x0140),
        ("frndseed", 0x0600, 0x0110),
        ("nand_cid", 0x0800, 0x0010),
        ("otp",      0x0A00, 0x0100),
    ];
    for (index, (name, offset, size)) in REQUIRED.iter().enumerate() {
        let descriptor = &essential[index * 16..(index + 1) * 16];
        let actual_name = &descriptor[..8];
        let expected_name = name.as_bytes();
        if actual_name[..expected_name.len()] != *expected_name
            || actual_name[expected_name.len()..].iter().any(|byte| *byte != 0)
        {
            return Err(format!("essential.exefs is missing its expected {name} record"));
        }
        let actual_offset = u32::from_le_bytes(descriptor[8..12].try_into().unwrap());
        let actual_size = u32::from_le_bytes(descriptor[12..16].try_into().unwrap());
        if actual_offset != *offset || actual_size != *size {
            return Err(format!("essential.exefs has an unexpected {name} record layout"));
        }
        verify_essential_hash(essential, index, *offset as usize, *size as usize)?;
    }
    for index in 6..8 {
        let descriptor = &essential[index * 16..(index + 1) * 16];
        let name = &descriptor[..8];
        if name.iter().any(|byte| *byte != 0) {
            let offset = u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) as usize;
            let size = u32::from_le_bytes(descriptor[12..16].try_into().unwrap()) as usize;
            if size == 0 || offset.checked_add(size).is_none_or(|end| end > 0x2000) {
                return Err("essential.exefs contains an invalid optional hardware-calibration record".to_owned());
            }
            verify_essential_hash(essential, index, offset, size)?;
        }
    }
    Ok(())
}

fn verify_essential_hash(essential: &[u8], file_index: usize, offset: usize, size: usize) -> Result<(), String> {
    let end = offset.checked_add(size)
        .filter(|end| *end <= 0x2000)
        .ok_or_else(|| "essential.exefs contains a file outside its data area".to_owned())?;
    let payload = &essential[EXEFS_HEADER_SIZE + offset..EXEFS_HEADER_SIZE + end];
    let digest = Sha256::digest(payload);
    let hash_index = 9 - file_index;
    let hash_start = 0xC0 + hash_index * 0x20;
    if essential[hash_start..hash_start + 0x20] != digest[..] {
        return Err("the embedded essential.exefs integrity check failed".to_owned());
    }
    Ok(())
}

fn essential_file<'a>(essential: &'a [u8], index: usize) -> &'a [u8] {
    let descriptor = &essential[index * 16..(index + 1) * 16];
    let offset = u32::from_le_bytes(descriptor[8..12].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(descriptor[12..16].try_into().unwrap()) as usize;
    &essential[EXEFS_HEADER_SIZE + offset..EXEFS_HEADER_SIZE + offset + size]
}

fn generate_virtual_nintendo_mac(out: &mut [u8; 6]) -> Result<(), String> {
    // These are Nintendo OUIs accepted by Pretendo's NASC validator. The
    // address is a stable virtual adapter identifier, not the console's
    // hardware MAC and not a substitute for its signed friend-code seed.
    const OUIS: [[u8; 3]; 8] = [
        [0x18, 0x2A, 0x7B],
        [0x2C, 0x10, 0xC1],
        [0x34, 0x2F, 0xBD],
        [0x40, 0xD2, 0x8A],
        [0x48, 0xA5, 0xE7],
        [0x58, 0x2F, 0x40],
        [0x60, 0x6B, 0xFF],
        [0x64, 0xB5, 0xC6],
    ];
    let mut random = [0u8; 4];
    getrandom::fill(&mut random)
        .map_err(|error| format!("could not generate a virtual network adapter address: {error}"))?;
    let oui = (u32::from_le_bytes(random) as usize) % OUIS.len();
    out[..3].copy_from_slice(&OUIS[oui]);
    out[3..].copy_from_slice(&random[1..4]);
    Ok(())
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

fn write_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_nand_prefix() -> Vec<u8> {
        let mut prefix = vec![0u8; PREFIX_SIZE];
        let ncsd = &mut prefix[..0x200];
        ncsd[0x100..0x104].copy_from_slice(b"NCSD");
        ncsd[0x104..0x108].copy_from_slice(&0x12u32.to_le_bytes());
        ncsd[0x110] = 1;
        ncsd[0x111] = 3;
        ncsd[0x120..0x124].copy_from_slice(&1u32.to_le_bytes());
        ncsd[0x124..0x128].copy_from_slice(&1u32.to_le_bytes());
        ncsd[0x128..0x12C].copy_from_slice(&2u32.to_le_bytes());
        ncsd[0x12C..0x130].copy_from_slice(&1u32.to_le_bytes());

        let essential = &mut prefix[ESSENTIAL_OFFSET..ESSENTIAL_OFFSET + ESSENTIAL_SIZE];
        essential[EXEFS_HEADER_SIZE..EXEFS_HEADER_SIZE + 0x200].copy_from_slice(ncsd);
        const RECORDS: [(&str, usize, usize); 8] = [
            ("nand_hdr", 0x0000, 0x0200),
            ("secinfo",  0x0200, 0x0111),
            ("movable",  0x0400, 0x0140),
            ("frndseed", 0x0600, 0x0110),
            ("nand_cid", 0x0800, 0x0010),
            ("otp",      0x0A00, 0x0100),
            ("hwcal0",   0x0C00, 0x09D0),
            ("hwcal1",   0x1600, 0x09D0),
        ];
        for (index, (name, offset, size)) in RECORDS.iter().enumerate() {
            let descriptor = &mut essential[index * 16..(index + 1) * 16];
            descriptor[..name.len()].copy_from_slice(name.as_bytes());
            descriptor[8..12].copy_from_slice(&(*offset as u32).to_le_bytes());
            descriptor[12..16].copy_from_slice(&(*size as u32).to_le_bytes());
            let data_start = EXEFS_HEADER_SIZE + offset;
            let data_end = data_start + size;
            essential[data_start..data_end].fill((index as u8) + 1);
            if index == 1 {
                essential[data_start + 0x100] = 1; // USA
                essential[data_start + 0x102..data_start + 0x10C].copy_from_slice(b"CTR1234567");
            }
            if index == 3 {
                essential[data_start + 0x108..data_start + 0x110].copy_from_slice(&1u64.to_le_bytes());
            }
            let digest = Sha256::digest(&essential[data_start..data_end]);
            let hash_index = 9 - index;
            let hash_start = 0xC0 + hash_index * 0x20;
            essential[hash_start..hash_start + 0x20].copy_from_slice(&digest);
        }
        prefix
    }

    fn temp_dir() -> PathBuf {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("mk7-nand-import-{}", format_mac([
            random[0], random[1], random[2], random[3], random[4], random[5]
        ])));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn parses_godmode9_nand_and_embedded_essential_backup() {
        let prefix = fake_nand_prefix();
        let report = parse_prefix("NAND.bin", PREFIX_SIZE as u64, &prefix).unwrap();
        assert_eq!(report.console_model, "Old 3DS");
        assert_eq!(report.region, "USA");
        assert_eq!(report.serial_number, "CTR1234567");
    }

    #[test]
    fn rejects_a_non_nand_header() {
        let mut prefix = fake_nand_prefix();
        prefix[0x100..0x104].copy_from_slice(b"NCCH");
        assert!(parse_prefix("wrong.bin", PREFIX_SIZE as u64, &prefix)
            .unwrap_err().contains("NCSD header"));
    }

    #[test]
    fn rejects_a_corrupt_embedded_essential_hash() {
        let mut prefix = fake_nand_prefix();
        prefix[ESSENTIAL_OFFSET + EXEFS_HEADER_SIZE + 0x200 + 0x10] ^= 0x80;
        assert!(parse_prefix("NAND.bin", PREFIX_SIZE as u64, &prefix)
            .unwrap_err().contains("integrity check"));
    }

    #[test]
    fn imports_only_private_system_identity_material_and_nasc_config() {
        let directory = temp_dir();
        let nand = directory.join("NAND.bin");
        fs::write(&nand, fake_nand_prefix()).unwrap();
        let data_dir = directory.join("appdata");
        fs::create_dir_all(&data_dir).unwrap();

        let report = import_nand_backup(&nand, &data_dir).unwrap();
        assert_eq!(report.serial_number, "CTR1234567");
        let sysdata = data_dir.join("sysdata");
        assert_eq!(fs::metadata(sysdata.join("LocalFriendCodeSeed_B")).unwrap().len(), 0x110);
        assert_eq!(fs::metadata(sysdata.join("SecureInfo_A")).unwrap().len(), 0x111);
        let config: serde_json::Value = serde_json::from_slice(&fs::read(sysdata.join("nasc.json")).unwrap()).unwrap();
        assert_eq!(config["serial_number"], "CTR1234567");
        assert_eq!(config["mac_address"].as_str().unwrap().len(), 17);
        assert!(!sysdata.join("NAND.bin").exists());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn import_never_overwrites_existing_device_identity() {
        let directory = temp_dir();
        let nand = directory.join("NAND.bin");
        fs::write(&nand, fake_nand_prefix()).unwrap();
        let data_dir = directory.join("appdata");
        fs::create_dir_all(data_dir.join("sysdata")).unwrap();
        fs::write(data_dir.join("sysdata/LocalFriendCodeSeed_B"), b"existing").unwrap();

        assert!(import_nand_backup(&nand, &data_dir).unwrap_err().contains("already exists"));
        assert_eq!(fs::read(data_dir.join("sysdata/LocalFriendCodeSeed_B")).unwrap(), b"existing");

        fs::remove_dir_all(directory).unwrap();
    }
}
