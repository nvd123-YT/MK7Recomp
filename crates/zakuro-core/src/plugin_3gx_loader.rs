//! 3GX plugin memory mapper and startup trampoline.
//!
//! The 412-byte ARM bootloader payload is derived from Azahar's
//! plugin_3gx_bootloader.h (GPL-2.0-or-later; original payload MIT-licensed
//! by The Pixellizer Group). The mapping and patching code below is a Rust
//! adaptation of the documented Citra/Azahar 3GX loader behavior.

use std::path::{Path, PathBuf};

use zakuro_common::memory_map::PAGE_SIZE;
use zakuro_fs::Title;

use crate::memory::{MemoryRegion, MemoryState, Permission};
use crate::plugin_3gx::{Plugin3gx, PLUGIN_HEADER_ADDRESS, PLUGIN_HEAP_ADDRESS};
use crate::System;

const BOOTLOADER_ADDRESS: u32 = PLUGIN_HEADER_ADDRESS - 0x1000;
const BOOTLOADER_SIZE: u32 = 0x1000;
const PLUGIN_HEADER_SIZE: u32 = 0x100;
// The 3DS-only startup flash writes to a hardware LED register that the
// desktop runtime does not map. Always skip that cosmetic hardware effect.
const NO_FLASH_FOR_EMULATOR: u32 = 1;
const CHECK_RESULT_COMPARE_R0_R1: u32 = 0xE150_0001;
const CHECK_RESULT_COMPARE_R0_R0: u32 = 0xE150_0000;
const BOOTLOADER: [u8; 412] = [
0xff, 0x1f, 0x2d, 0xe9, 0x00, 0x00, 0x0f, 0xe1, 0x01, 0x00, 0x2d, 0xe9, 0xf0, 0x00, 0x8f, 0xe2,
 0x04, 0x10, 0x90, 0xe5, 0x00, 0x00, 0x90, 0xe5, 0xd4, 0x20, 0x8f, 0xe2, 0x0f, 0xe0, 0xa0, 0xe1,
 0xf4, 0xf0, 0x8f, 0xe2, 0xe0, 0x10, 0x8f, 0xe2, 0x00, 0x10, 0x91, 0xe5, 0x01, 0x00, 0x50, 0xe1,
 0xd8, 0x00, 0x8f, 0xe2, 0x00, 0x00, 0x90, 0xe5, 0x01, 0x10, 0xa0, 0x03, 0x00, 0x10, 0xa0, 0x13,
 0x00, 0x10, 0x80, 0xe5, 0x03, 0x00, 0x00, 0x1f, 0xc8, 0x00, 0x8f, 0xe2, 0x00, 0x00, 0xd0, 0xe5,
 0x01, 0x00, 0x50, 0xe3, 0x09, 0x00, 0x00, 0x0a, 0x78, 0x40, 0x9f, 0xe5, 0x78, 0x50, 0x9f, 0xe5,
 0x40, 0x60, 0xa0, 0xe3, 0x00, 0x50, 0x84, 0xe5, 0x70, 0x00, 0x9f, 0xe5, 0x00, 0x10, 0xa0, 0xe3,
 0x0a, 0x00, 0x00, 0xef, 0x01, 0x60, 0x56, 0xe2, 0xf9, 0xff, 0xff, 0x1a, 0x00, 0x60, 0x84, 0xe5,
 0x5c, 0x00, 0x9f, 0xe5, 0x01, 0x10, 0xa0, 0xe3, 0xb3, 0x00, 0x00, 0xef, 0x54, 0x00, 0x8f, 0xe2,
 0x58, 0x10, 0x8f, 0xe2, 0x00, 0x10, 0x91, 0xe5, 0x00, 0x20, 0x90, 0xe5, 0x00, 0x20, 0x81, 0xe5,
 0x04, 0x20, 0x90, 0xe5, 0x04, 0x20, 0x81, 0xe5, 0x94, 0x00, 0x00, 0xef, 0x34, 0x00, 0x8f, 0xe2,
 0x04, 0x00, 0x2d, 0xe5, 0x58, 0x50, 0x8f, 0xe2, 0x00, 0x50, 0x95, 0xe5, 0x35, 0xff, 0x2f, 0xe1,
 0x04, 0xd0, 0x8d, 0xe2, 0x01, 0x00, 0xbd, 0xe8, 0x00, 0xf0, 0x29, 0xe1, 0xff, 0x1f, 0xbd, 0xe8,
 0x18, 0xe0, 0x8f, 0xe2, 0x00, 0xf0, 0x9e, 0xe5, 0x04, 0x22, 0x20, 0x90, 0x33, 0x99, 0xff, 0x01,
 0x40, 0x4b, 0xff, 0x00, 0x01, 0x80, 0xff, 0xff, 0x00, 0x00, 0xad, 0xde, 0x01, 0x00, 0xad, 0xde,
 0x02, 0x00, 0xad, 0xde, 0x03, 0x00, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xad, 0xde, 0x05, 0x00, 0xad, 0xde, 0x06, 0x00, 0xad, 0xde,
 0x07, 0x00, 0xad, 0xde, 0x08, 0x00, 0xad, 0xde, 0x09, 0x00, 0xad, 0xde, 0x0a, 0x00, 0xad, 0xde,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3,
 0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3, 0x1e, 0xff, 0x2f, 0xe1,
];

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("could not read plugin: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid 3GX plugin: {0}")]
    Parse(#[from] crate::plugin_3gx::ParseError),
    #[error("plugin is not marked compatible with emulators")]
    Incompatible,
    #[error("plugin does not target this title")]
    WrongTitle,
    #[error("plugin does not allow loading into homebrew executables")]
    HomebrewExecutable,
    #[error("plugin has no executable checksum function")]
    MissingChecksumFunction,
    #[error("plugin memory region is already mapped")]
    AddressConflict,
    #[error("not enough contiguous FCRAM for plugin")]
    OutOfMemory,
    #[error("could not map plugin memory")]
    MapFailed,
}

/// a stable diagnostic fingerprint for comparing the title's code image
/// with the bytes visible at its guest virtual addresses.
fn code_fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xCBF2_9CE4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

/// Conventional Luma path plus the project's shorter data-directory layout.
fn plugin_roots(sdmc_root: &Path, data_dir: &Path) -> [PathBuf; 4] {
    [
        sdmc_root.join("luma").join("plugins"),
        sdmc_root.join("plugins"),
        data_dir.join("luma").join("plugins"),
        data_dir.join("plugins"),
    ]
}

/// Looks for title-specific plugins first, then a default plugin. Returns the
/// bootloader entry point when a plugin was successfully installed.
pub fn load_for_title(system: &mut System, title: &Title, game_entry: u32) -> Option<u32> {
    if !system.config.plugins_3gx_enabled || !system.services.plgldr.enabled || system.services.plgldr.plugin_loaded {
        return None;
    }
    if ((title.program_id() >> 32) as u32 & 0xFFFF_FFED) != 0x0004_0000 {
        return None;
    }
    let data_dir = system.config.data_dir.as_ref()?.clone();
    // FS:USER maps ARCHIVE_SDMC to user_dir/sdmc. That directory is
    // the guest-visible SD root used by Luma and CTGP-7.
    let sdmc_root = system.services.fs.user_dir.join("sdmc");
    let roots = plugin_roots(&sdmc_root, &data_dir);

    if system.services.plgldr.use_user_load_parameters
        && (system.services.plgldr.low_title_id == 0
            || system.services.plgldr.low_title_id == title.program_id() as u32)
        && !system.services.plgldr.requested_path.is_empty()
    {
        let requested = system.services.plgldr.requested_path
            .trim_start_matches(|character| character == '/' || character == '\\');
        // SetLoadSettings paths are SD-card-relative on real 3DS systems.
        // Keep the data-directory path as a fallback for older configurations.
        let mut paths = vec![sdmc_root.join(requested), data_dir.join(requested)];
        if let Some(name) = Path::new(requested).file_name() {
            for root in &roots { paths.push(root.join(name)); }
        }
        paths.sort();
        paths.dedup();
        for path in paths {
            if path.is_file() {
                match load_path(system, title, game_entry, &path, false) {
                    Ok(()) => {
                        system.services.plgldr.use_user_load_parameters = false;
                        return Some(BOOTLOADER_ADDRESS);
                    }
                    Err(error) => log::warn!("configured 3GX plugin {} was not loaded: {error}", path.display()),
                }
            }
        }
    }

    // CTGP-7's official launcher stores its 3GX at this path and normally
    // passes it to plg:ldr through SetLoadSettings. Also check the same path
    // directly so the recompiled title can launch without the separate
    // homebrew launcher process.
    let ctgp_plugin_paths = [
        sdmc_root.join("CTGP-7").join("resources").join("CTGP-7.3gx"),
        data_dir.join("CTGP-7").join("resources").join("CTGP-7.3gx"),
    ];
    for ctgp_plugin in ctgp_plugin_paths {
        if ctgp_plugin.is_file() {
            match load_path(system, title, game_entry, &ctgp_plugin, false) {
                Ok(()) => return Some(BOOTLOADER_ADDRESS),
                Err(error) => log::warn!("CTGP-7 plugin {} was not loaded: {error}", ctgp_plugin.display()),
            }
        }
    }

    let title_dir_name = format!("{:016X}", title.program_id());
    let mut candidates = Vec::new();
    for root in &roots {
        if let Ok(entries) = std::fs::read_dir(root.join(&title_dir_name)) {
            candidates.extend(entries.filter_map(Result::ok).map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("3gx"))));
        }
    }
    candidates.sort();
    candidates.dedup();
    for path in candidates {
        match load_path(system, title, game_entry, &path, false) {
            Ok(()) => return Some(BOOTLOADER_ADDRESS),
            Err(error) => log::warn!("3GX plugin {} was not loaded: {error}", path.display()),
        }
    }

    for root in &roots {
        let default = root.join("default.3gx");
        if default.is_file() {
            match load_path(system, title, game_entry, &default, true) {
                Ok(()) => return Some(BOOTLOADER_ADDRESS),
                Err(error) => log::warn!("default 3GX plugin {} was not loaded: {error}", default.display()),
            }
        }
    }
    None
}

fn load_path(system: &mut System, title: &Title, game_entry: u32, path: &Path, is_default: bool) -> Result<(), LoadError> {
    let bytes = std::fs::read(path)?;
    let plugin = Plugin3gx::parse(&bytes)?;
    if !plugin.flags.compatibility.supports_emulator() {
        return Err(LoadError::Incompatible);
    }
    if !plugin.supports_title(title.program_id()) {
        return Err(LoadError::WrongTitle);
    }
    if !plugin.flags.allow_homebrew_load {
        let mut first_bytes = [0u8; 4];
        let mut second_bytes = [0u8; 4];
        system.memory.read_bytes(game_entry, &mut first_bytes);
        system.memory.read_bytes(game_entry + 32, &mut second_bytes);
        let first = u32::from_le_bytes(first_bytes);
        let second = u32::from_le_bytes(second_bytes);
        if first == 0xEA00_0006 && second == 0xE1A0_400E {
            return Err(LoadError::HomebrewExecutable);
        }
    }

    // CTGP validates the actual executable image before installing its patches.
    // Record the revision and fingerprints to distinguish mapping errors from
    // an unsupported base/update build without dumping game code bytes.
    let data_dir = system.config.data_dir.as_deref().filter(|_| system.config.mods_enabled);
    let (source_code, code_is_modded) = match crate::mods::code(title, data_dir) {
        Ok(result) => result,
        Err(error) => {
            log::warn!("3GX code-check diagnostics could not read the source image: {error}");
            (Vec::new(), false)
        }
    };
    let mut mapped_code = Vec::new();
    for segment in [title.exheader.text, title.exheader.rodata, title.exheader.data] {
        let size = segment.num_pages.saturating_mul(PAGE_SIZE);
        if size == 0 { continue; }
        let start = mapped_code.len();
        mapped_code.resize(start + size as usize, 0);
        system.memory.read_bytes(segment.address, &mut mapped_code[start..]);
    }
    log::info!(
        "3GX executable-check context: title={:016X} product='{}' ncch_version={} remaster_version={} update_version={:?} modded={} entry=0x{game_entry:08X} source_code_bytes=0x{:X} source_fnv1a64={:016X} mapped_segment_bytes=0x{:X} mapped_fnv1a64={:016X} plugin_checksum={:08X} plugin_args={:08X?} checker_words={}",
        title.program_id(),
        title.ncch.product_code,
        title.ncch.version,
        title.exheader.remaster_version,
        title.update().map(|update| update.version),
        code_is_modded,
        source_code.len(),
        code_fingerprint(&source_code),
        mapped_code.len(),
        code_fingerprint(&mapped_code),
        plugin.executable_checksum,
        plugin.executable_check_args,
        plugin.executable_check.as_ref().map_or(0, Vec::len)
    );

    let load_func = plugin.executable_check.as_deref().ok_or(LoadError::MissingChecksumFunction)?;
    if load_func.len() > 32 {
        return Err(LoadError::MissingChecksumFunction);
    }

    let block_size = plugin.flags.memory_region_size();
    let exe_size = (PLUGIN_HEADER_SIZE as u64
        + plugin.code.len() as u64
        + plugin.rodata.len() as u64
        + plugin.data.len() as u64
        + plugin.bss_size as u64
        + PAGE_SIZE as u64) & !(PAGE_SIZE as u64 - 1);
    let boot_offset = u32::try_from(exe_size).map_err(|_| LoadError::OutOfMemory)?;
    let heap_offset = boot_offset.checked_add(BOOTLOADER_SIZE).ok_or(LoadError::OutOfMemory)?;
    if heap_offset >= block_size {
        return Err(LoadError::OutOfMemory);
    }
    let heap_size = block_size - heap_offset;

    if system.memory.mapping_at(PLUGIN_HEAP_ADDRESS).is_some()
        || system.memory.mapping_at(BOOTLOADER_ADDRESS).is_some()
        || system.memory.mapping_at(PLUGIN_HEADER_ADDRESS).is_some()
    {
        return Err(LoadError::AddressConflict);
    }

    // New 3DS always reserves this block from the top of APPLICATION
    // memory. Old 3DS uses APPLICATION only for explicit Mode 3; otherwise
    // the normal Luma strategy allocates from SYSTEM.
    let use_application_memory = system.config.new3ds || system.services.plgldr.memory_strategy == 1;
    let region = if use_application_memory {
        MemoryRegion::Application
    } else {
        MemoryRegion::System
    };
    let block = match region {
        MemoryRegion::Application => system.memory.phys.allocate_top(region, block_size),
        MemoryRegion::System => system.memory.phys.allocate(region, block_size),
        MemoryRegion::Base => system.memory.phys.allocate(region, block_size),
    }
    .ok_or(LoadError::OutOfMemory)?;

    if !system.memory.zero_physical(block.addr, block.size) {
        system.memory.phys.free(block);
        return Err(LoadError::MapFailed);
    }

    let private = plugin.flags.use_private_memory;
    let state = if private { MemoryState::Private } else { MemoryState::Shared };
    let rwx = Permission::READ | Permission::WRITE | Permission::EXECUTE;

    system.memory.map(PLUGIN_HEADER_ADDRESS, block.addr, exe_size as u32, rwx, state);
    system.memory.map(BOOTLOADER_ADDRESS, block.addr + boot_offset, BOOTLOADER_SIZE, rwx, MemoryState::Private);
    system.memory.map(PLUGIN_HEAP_ADDRESS, block.addr + heap_offset, heap_size, rwx, state);

    let mappings_valid =
        system.memory.mapping_at(PLUGIN_HEADER_ADDRESS).is_some_and(|m| m.paddr == block.addr)
        && system.memory.mapping_at(BOOTLOADER_ADDRESS).is_some_and(|m| m.paddr == block.addr + boot_offset)
        && system.memory.mapping_at(PLUGIN_HEAP_ADDRESS).is_some_and(|m| m.paddr == block.addr + heap_offset);
    if !mappings_valid {
        system.memory.unmap(PLUGIN_HEADER_ADDRESS, exe_size as u32);
        system.memory.unmap(BOOTLOADER_ADDRESS, BOOTLOADER_SIZE);
        system.memory.unmap(PLUGIN_HEAP_ADDRESS, heap_size);
        system.memory.phys.free(block);
        return Err(LoadError::MapFailed);
    }

    let mut header = [0u8; PLUGIN_HEADER_SIZE as usize];
    put_u32(&mut header, 0x00, 0);
    put_u32(&mut header, 0x04, plugin.version);
    put_u32(&mut header, 0x08, PLUGIN_HEAP_ADDRESS);
    put_u32(&mut header, 0x0C, heap_size);
    put_u32(&mut header, 0x10, exe_size as u32);
    put_u32(&mut header, 0x14, is_default as u32);
    put_u32(&mut header, 0x18, PLUGIN_HEADER_ADDRESS - 4);
    put_u32(&mut header, 0x1C, PLUGIN_HEADER_ADDRESS - 8);
    for (index, value) in system.services.plgldr.config.iter().enumerate() {
        put_u32(&mut header, 0x80 + index * 4, *value);
    }
    system.memory.write_bytes(PLUGIN_HEADER_ADDRESS, &header);
    system.memory.write_bytes(PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE, &plugin.code);
    system.memory.write_bytes(PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE + plugin.code.len() as u32, &plugin.rodata);
    system.memory.write_bytes(PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE + plugin.code.len() as u32 + plugin.rodata.len() as u32, &plugin.data);

    let mut original = [0u8; 8];
    system.memory.read_bytes(game_entry, &mut original);
    let mut boot = BOOTLOADER;
    let checksum_size = (plugin.code.len() + plugin.rodata.len() + plugin.data.len()) as u32;
    patch_bootloader(
        &mut boot,
        u32::from_le_bytes(original[0..4].try_into().unwrap()),
        u32::from_le_bytes(original[4..8].try_into().unwrap()),
        game_entry,
        &plugin.executable_check_args,
        PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE,
        PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE + checksum_size,
        plugin.executable_checksum,
        PLUGIN_HEADER_ADDRESS - 0xC,
        PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE,
        NO_FLASH_FOR_EMULATOR,
        load_func,
    );
    let ignore_executable_check = std::env::var("ZAKURO_3GX_IGNORE_EXE_CHECK")
        .is_ok_and(|value| value == "1");
    if ignore_executable_check {
        if !force_executable_check_success(&mut boot) {
            system.memory.unmap(PLUGIN_HEADER_ADDRESS, exe_size as u32);
            system.memory.unmap(BOOTLOADER_ADDRESS, BOOTLOADER_SIZE);
            system.memory.unmap(PLUGIN_HEAP_ADDRESS, heap_size);
            system.memory.phys.free(block);
            return Err(LoadError::MapFailed);
        }
        log::warn!("3GX executable-check result override is enabled for this test session");
    }
    if !system.memory.write_physical(block.addr + boot_offset, &boot) {
        system.memory.unmap(PLUGIN_HEADER_ADDRESS, exe_size as u32);
        system.memory.unmap(BOOTLOADER_ADDRESS, BOOTLOADER_SIZE);
        system.memory.unmap(PLUGIN_HEAP_ADDRESS, heap_size);
        system.memory.phys.free(block);
        return Err(LoadError::MapFailed);
    }

    // Replace the game's entry with an absolute branch to the ARM trampoline.
    // The trampoline restores the two original instructions before calling
    // the plugin and finally resumes the game at its original entry.
    let original_words = [
        u32::from_le_bytes(original[0..4].try_into().unwrap()),
        u32::from_le_bytes(original[4..8].try_into().unwrap()),
    ];
    if !system.memory.write32_privileged(game_entry, 0xE51F_F004)
        || !system.memory.write32_privileged(game_entry + 4, BOOTLOADER_ADDRESS)
    {
        system.memory.write32_privileged(game_entry, original_words[0]);
        system.memory.write32_privileged(game_entry + 4, original_words[1]);
        system.memory.unmap(PLUGIN_HEADER_ADDRESS, exe_size as u32);
        system.memory.unmap(BOOTLOADER_ADDRESS, BOOTLOADER_SIZE);
        system.memory.unmap(PLUGIN_HEAP_ADDRESS, heap_size);
        system.memory.phys.free(block);
        return Err(LoadError::MapFailed);
    }

    // Match Azahar's config_mem app_mem_alloc adjustment only after every
    // mapping and the game-entry patch has succeeded.
    let previous_app_memory_size = if region == MemoryRegion::Application {
        let app_size = system.memory.phys.region_size(MemoryRegion::Application);
        let config_mem = system.memory.phys.config_mem_mut();
        let reported = u32::from_le_bytes(config_mem[0x40..0x44].try_into().unwrap());
        if reported == app_size {
            let adjusted = reported.saturating_sub(block_size);
            config_mem[0x40..0x44].copy_from_slice(&adjusted.to_le_bytes());
            Some(reported)
        } else {
            None
        }
    } else {
        None
    };

    system.services.plgldr.original_game_entry = Some(original_words);
    system.services.plgldr.previous_app_memory_size = previous_app_memory_size;
    system.services.plgldr.plugin_loaded = true;
    system.services.plgldr.plugin_path = path.to_string_lossy().into_owned();
    system.services.plgldr.is_default_path = is_default;
    system.services.plgldr.plugin_process_id = system.kernel.process_id;
    system.services.plgldr.memory_region = if region == MemoryRegion::Application { 1 } else { 2 };
    system.services.plgldr.memory_block = Some(block);
    system.services.plgldr.plugin_entry = game_entry;
    system.services.plgldr.exe_size = exe_size as u32;
    system.services.plgldr.heap_size = heap_size;
    log::info!("loaded 3GX plugin '{}' by {} ({} bytes executable, {} bytes heap)", plugin.title, plugin.author, exe_size, heap_size);
    Ok(())
}

fn patch_bootloader(
    boot: &mut [u8; 412],
    game_instr0: u32,
    game_instr1: u32,
    game_entry: u32,
    load_args: &[u32; 4],
    plugin_start: u32,
    plugin_end: u32,
    checksum: u32,
    launch_status: u32,
    plugin_entry: u32,
    no_flash: u32,
    load_func: &[u32],
) {
    let mut index = 0usize;
    while index < boot.len() / 4 {
        let at = index * 4;
        let word = u32::from_le_bytes(boot[at..at + 4].try_into().unwrap());
        let replacement = match word {
            0xDEAD_0000 => Some(game_instr0),
            0xDEAD_0001 => Some(game_instr1),
            0xDEAD_0002 => Some(game_entry),
            0xDEAD_0004 => Some(plugin_start),
            0xDEAD_0005 => Some(plugin_end),
            0xDEAD_0006 => Some(checksum),
            0xDEAD_0007 => Some(launch_status),
            0xDEAD_0008 => Some(plugin_entry),
            0xDEAD_0009 => Some(no_flash),
            _ => None,
        };
        if let Some(value) = replacement {
            boot[at..at + 4].copy_from_slice(&value.to_le_bytes());
        } else if word == 0xDEAD_0003 {
            // The marker is the first argument slot; overwrite it just as
            // Azahar's MapBootloader does, then skip the remaining slots.
            for (offset, value) in load_args.iter().enumerate() {
                let pos = at + offset * 4;
                boot[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
            }
            index += load_args.len().saturating_sub(1);
        } else if word == 0xDEAD_000A {
            for (offset, value) in load_func.iter().enumerate() {
                let pos = at + offset * 4;
                boot[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
            }
            index += load_func.len().saturating_sub(1);
        }
        index += 1;
    }
}


/// Changes the embedded result comparison so a test session can proceed
/// regardless of the embedded executable check's return value. The check
/// function itself still runs, and the bootloader still records success.
fn force_executable_check_success(boot: &mut [u8; 412]) -> bool {
    let mut compare_offset = None;
    for (index, word) in boot.chunks_exact(4).enumerate() {
        if u32::from_le_bytes(word.try_into().unwrap()) == CHECK_RESULT_COMPARE_R0_R1 {
            if compare_offset.replace(index * 4).is_some() {
                return false;
            }
        }
    }
    let Some(offset) = compare_offset else {
        return false;
    };
    boot[offset..offset + 4].copy_from_slice(&CHECK_RESULT_COMPARE_R0_R0.to_le_bytes());
    true
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Releases plugin mappings and restores the game entry when the title exits.
pub fn unload(system: &mut System) {
    let (
        block,
        exe_size,
        heap_size,
        game_entry,
        original_entry,
        previous_app_memory_size,
    ) = {
        let state = &mut system.services.plgldr;
        if !state.plugin_loaded {
            return;
        }
        (
            state.memory_block.take(),
            state.exe_size,
            state.heap_size,
            state.plugin_entry,
            state.original_game_entry.take(),
            state.previous_app_memory_size.take(),
        )
    };

    if let Some([first, second]) = original_entry {
        system.memory.write32_privileged(game_entry, first);
        system.memory.write32_privileged(game_entry + 4, second);
    }
    if let Some(previous) = previous_app_memory_size {
        let config_mem = system.memory.phys.config_mem_mut();
        config_mem[0x40..0x44].copy_from_slice(&previous.to_le_bytes());
    }
    if let Some(block) = block {
        system.memory.unmap(PLUGIN_HEADER_ADDRESS, exe_size);
        system.memory.unmap(BOOTLOADER_ADDRESS, BOOTLOADER_SIZE);
        system.memory.unmap(PLUGIN_HEAP_ADDRESS, heap_size);
        system.memory.phys.free(block);
    }

    let state = &mut system.services.plgldr;
    state.plugin_loaded = false;
    state.plugin_path.clear();
    state.is_default_path = false;
    state.plugin_process_id = u32::MAX;
    state.memory_region = 0;
    state.exe_size = 0;
    state.heap_size = 0;
    state.plugin_entry = 0;
    state.memory_block = None;
    log::info!("unloaded 3GX plugin");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luma_plugin_roots_are_relative_to_the_guest_sd_root() {
        let sdmc = Path::new("/data/user/sdmc");
        let data = Path::new("/data");
        let roots = plugin_roots(sdmc, data);
        assert_eq!(roots[0], Path::new("/data/user/sdmc/luma/plugins"));
        assert_eq!(roots[1], Path::new("/data/user/sdmc/plugins"));
        assert_eq!(roots[2], Path::new("/data/luma/plugins"));
        assert_eq!(roots[3], Path::new("/data/plugins"));
    }

    #[test]
    fn emulator_bootloader_skips_the_hardware_led_flash() {
        let mut boot = BOOTLOADER;
        patch_bootloader(
            &mut boot,
            0,
            0,
            0,
            &[0; 4],
            PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE,
            PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE,
            0,
            0,
            PLUGIN_HEADER_ADDRESS + PLUGIN_HEADER_SIZE,
            NO_FLASH_FOR_EMULATOR,
            &[0xE320_F000],
        );

        let no_flash_marker = 0x118;
        let value = u32::from_le_bytes(boot[no_flash_marker..no_flash_marker + 4].try_into().unwrap());
        assert_eq!(value, NO_FLASH_FOR_EMULATOR);
    }

    #[test]
    fn executable_check_override_changes_only_the_result_comparison() {
        let mut boot = BOOTLOADER;
        assert!(force_executable_check_success(&mut boot));

        let words: Vec<u32> = boot
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(
            words.iter().filter(|&&word| word == CHECK_RESULT_COMPARE_R0_R1).count(),
            0
        );
        assert_eq!(
            words.iter().filter(|&&word| word == CHECK_RESULT_COMPARE_R0_R0).count(),
            1
        );
    }

    #[test]
    fn bootloader_load_arguments_overwrite_the_marker_word() {
        let mut boot = [0u8; 412];
        boot[0..4].copy_from_slice(&0xDEAD_0003u32.to_le_bytes());
        let args = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        patch_bootloader(
            &mut boot,
            0xAAAA_AAAA,
            0xBBBB_BBBB,
            0x0800_0000,
            &args,
            0x0700_0100,
            0x0700_1100,
            0x1234_5678,
            0x06FF_FFF4,
            0x0700_0100,
            0,
            &[0xE320_F000],
        );
        for (index, expected) in args.into_iter().enumerate() {
            let at = index * 4;
            let actual = u32::from_le_bytes(boot[at..at + 4].try_into().unwrap());
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn bootloader_patches_all_runtime_markers() {
        let mut boot = BOOTLOADER;
        patch_bootloader(&mut boot, 1, 2, 3, &[4, 5, 6, 7], 8, 9, 10, 11, 12, 1, &[13, 14]);
        let words: Vec<u32> = boot.chunks_exact(4).map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap())).collect();
        assert!(words.contains(&1));
        assert!(words.contains(&2));
        assert!(words.contains(&3));
        assert!(words.contains(&4));
        assert!(words.contains(&5));
        assert!(words.contains(&6));
        assert!(words.contains(&7));
        assert!(words.contains(&8));
        assert!(words.contains(&9));
        assert!(words.contains(&10));
        assert!(words.contains(&11));
        assert!(words.contains(&12));
        assert!(words.contains(&13));
        assert!(words.contains(&14));
    }
}
