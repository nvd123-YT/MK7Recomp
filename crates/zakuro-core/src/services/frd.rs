//! frd:u, the friend list and this console's own friend details. the
//! console keeps them itself and answers offline too, as one that never
//! logged in and has no friends. what needs the servers is left to the
//! offline reply.

use std::path::PathBuf;

use zakuro_common::result::errors;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::services::cfg::REGION_USA;
use crate::{NetworkProvider, System};

/// the platform a profile names, the 3DS.
const PLATFORM_CTR: u32 = 2;

/// The Friends system module's account file, imported from the user's
/// own decrypted NAND save at user/nand/system-save/0000000000010032/2/account.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FriendAccount {
    local_account_id: u32,
    principal_id: u32,
    local_friend_code: u64,
    password: String,
    uidhmac: String,
    nasc_environment: u8,
    server_type: u8,
    server_type_number: u8,
}

fn parse_friend_account(bytes: &[u8]) -> Option<FriendAccount> {
    const MIN_SIZE: usize = 0x58;
    if bytes.len() < MIN_SIZE
        || &bytes[..4] != b"FPAC"
        || u32::from_le_bytes(bytes[4..8].try_into().ok()?) != 0x2010_1021
    {
        return None;
    }

    let utf16_field = |start: usize, end: usize| -> Option<String> {
        let mut units = Vec::with_capacity((end - start) / 2);
        for chunk in bytes[start..end].chunks_exact(2) {
            let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
            if unit == 0 { break; }
            units.push(unit);
        }
        let value = String::from_utf16(&units).ok()?;
        if !value.is_ascii() { return None; }
        Some(value)
    };

    Some(FriendAccount {
        local_account_id: u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?),
        principal_id: u32::from_le_bytes(bytes[0x14..0x18].try_into().ok()?),
        local_friend_code: u64::from_le_bytes(bytes[0x18..0x20].try_into().ok()?),
        password: utf16_field(0x20, 0x42)?,
        uidhmac: utf16_field(0x42, 0x54)?,
        nasc_environment: bytes[0x54],
        server_type: bytes[0x55],
        server_type_number: bytes[0x56],
    })
}

fn friend_account_path(system: &System) -> PathBuf {
    system.services.fs.user_dir
        .join("nand/system-save/0000000000010032/2/account")
}

fn load_friend_account(system: &System) -> Option<FriendAccount> {
    let path = friend_account_path(system);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            log::warn!("frd:u could not read the imported Friends account file {}: {error}", path.display());
            return None;
        }
    };
    match parse_friend_account(&bytes) {
        Some(account) if account.principal_id != 0 && !account.password.is_empty() => Some(account),
        Some(_) => {
            log::warn!("frd:u Friends account file has no principal ID or NEX password: {}", path.display());
            None
        }
        None => {
            log::warn!("frd:u Friends account file is invalid or truncated: {}", path.display());
            None
        }
    }
}

fn reply_static_bytes(
    system: &mut System,
    buffer: &CommandBuffer,
    command: u16,
    result: u32,
    bytes: &[u8],
) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    let length = bytes.len().min(capacity as usize);
    system.memory.write_bytes(pointer, &bytes[..length]);
    buffer.set(&mut system.memory, 0, Header::new(command, 1, 2).0);
    buffer.set(&mut system.memory, 1, result);
    buffer.set(&mut system.memory, 2, Descriptor::static_buffer(length as u32, 0));
    buffer.set(&mut system.memory, 3, pointer);
}

/// Local FRD state. The server-side friends service still needs a successful
/// NASC/NEX session; this only implements the console-side login event.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct FrdState {
    #[serde(skip)]
    logged_in: bool,
    last_response_result: u32,
}

pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    let command = header.command_id();
    let (region, language) = (system.config.region, system.config.language);
    match command {
        // HasLoggedIn and IsOnline reflect the local FRD login. This is not a
        // substitute for the title's independent NASC and NEX authentication.
        0x0001 | 0x0002 => {
            let logged_in = system.services.frd.logged_in && system.config.network_provider == NetworkProvider::Pretendo;
            buffer.reply(&mut system.memory, command, &[u32::from(logged_in)]);
        }
        // Login(event) completes the local friends module's login handshake.
        0x0003 => {
            let descriptor = buffer.get(&mut system.memory, header.normal_params() + 1);
            let event_handle = match Descriptor::parse(descriptor) {
                Descriptor::Handles { count, .. } if count > 0 => Some(buffer.get(&mut system.memory, header.normal_params() + 2)),
                _ => None,
            };
            if system.config.network_provider != NetworkProvider::Pretendo {
                system.services.frd.logged_in = false;
                system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
            } else {
                system.services.frd.logged_in = true;
                system.services.frd.last_response_result = 0;
                if let Some(object) = event_handle.and_then(|handle| system.kernel.handles.resolve(handle)) {
                    system.kernel.signal_event(object);
                }
                buffer.reply(&mut system.memory, command, &[]);
            }
        }
        // Logout, AttachToEventNotification, SetNotificationMask and SetClientSdkVersion.
        0x0004 => {
            system.services.frd.logged_in = false;
            system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
            buffer.reply(&mut system.memory, command, &[]);
        }
        0x0020 | 0x0021 | 0x0032 => buffer.reply(&mut system.memory, command, &[]),
        // GetMyFriendKey: PrincipalID, padding, and the 64-bit local friend code.
        0x0005 => {
            let result = load_friend_account(system).map(|account| [
                account.principal_id,
                0,
                account.local_friend_code as u32,
                (account.local_friend_code >> 32) as u32,
            ]);
            match result {
                Some(words) => buffer.reply(&mut system.memory, command, &words),
                None => {
                    if system.config.network_provider == NetworkProvider::Pretendo {
                        buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                    } else {
                        buffer.reply(&mut system.memory, command, &[0; 4]);
                    }
                }
            }
        }
        // GetMyPreference, private, showing neither game
        0x0006 => buffer.reply(&mut system.memory, command, &[0; 3]),
        // GetMyProfile, region, country, area and language, then platform
        0x0007 => {
            let country: u32 = if region == REGION_USA { 49 } else { 110 };
            let first = region as u32 | country << 8 | (language as u32) << 24;
            buffer.reply(&mut system.memory, command, &[first, PLATFORM_CTR]);
        }
        // GetMyPresence, into a static buffer that stays as it is
        0x0008 => buffer.reply(&mut system.memory, command, &[]),
        // GetMyScreenName, the user's name in eleven UTF-16 units
        0x0009 => {
            let mut name = [0u8; 24];
            let username: String = system.config.username.chars().take(10).collect();
            for (i, unit) in username.encode_utf16().enumerate() {
                name[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            let words: Vec<u32> = name.as_chunks::<4>().0.iter().map(|&w| u32::from_le_bytes(w)).collect();
            buffer.reply(&mut system.memory, command, &words);
        }
        // GetMyMii
        0x000A => buffer.reply(&mut system.memory, command, &[0; 24]),
        // GetMyLocalAccountId, from the imported Friends account record.
        0x000B => {
            let id = load_friend_account(system).map_or(0, |account| account.local_account_id);
            buffer.reply(&mut system.memory, command, &[id]);
        }
        // GetMyPlayingGame and GetMyFavoriteGame, a title id, its version
        // and a word more
        0x000C | 0x000D => buffer.reply(&mut system.memory, command, &[0; 4]),
        // GetMyNcPrincipalId
        0x000E => buffer.reply(&mut system.memory, command, &[0]),
        // GetMyComment
        0x000F => buffer.reply(&mut system.memory, command, &[0; 9]),
        // GetMyPassword(size, static output buffer). The Friends account file
        // stores the 16-character NEX password as UTF-16 at offset 0x20.
        0x0010 => {
            let requested = buffer.get(&mut system.memory, 1) as usize;
            match load_friend_account(system) {
                Some(account) => {
                    let mut password = account.password.into_bytes();
                    password.push(0);
                    password.truncate(requested);
                    reply_static_bytes(system, buffer, command, 0, &password);
                }
                None => {
                    reply_static_bytes(system, buffer, command, errors::NOT_CONNECTED.0, &[]);
                }
            }
        }
        // GetFriendKeyList and GetEventNotification, none
        0x0011 | 0x0022 => buffer.reply(&mut system.memory, command, &[0]),
        // lookups on friends the title names, of which it has none to name
        0x0012..=0x001A => buffer.reply(&mut system.memory, command, &[]),
        // IsIncludedInFriendList
        0x001B => buffer.reply(&mut system.memory, command, &[0]),
        // GetLastResponseResult, what the last request to the servers got
        0x0023 => {
            let result = if system.services.frd.logged_in {
                system.services.frd.last_response_result
            } else {
                errors::NOT_CONNECTED.0
            };
            buffer.reply(&mut system.memory, command, &[result]);
        }
        // ResultToErrorCode, no code to show
        0x0027 => buffer.reply(&mut system.memory, command, &[0]),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 0x58];
        bytes[..4].copy_from_slice(b"FPAC");
        bytes[4..8].copy_from_slice(&0x2010_1021u32.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        bytes[0x18..0x20].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        for (index, byte) in b"ABCDEFGHIJKLMNOP".iter().enumerate() {
            bytes[0x20 + index * 2] = *byte;
        }
        for (index, byte) in b"AB12CD34".iter().enumerate() {
            bytes[0x42 + index * 2] = *byte;
        }
        bytes[0x54] = 1;
        bytes[0x55] = b'M';
        bytes[0x56] = b'K';
        bytes
    }

    #[test]
    fn friend_account_parser_reads_principal_password_and_hmac() {
        let account = parse_friend_account(&account_bytes()).unwrap();
        assert_eq!(account.local_account_id, 2);
        assert_eq!(account.principal_id, 0x1234_5678);
        assert_eq!(account.local_friend_code, 0x1122_3344_5566_7788);
        assert_eq!(account.password, "ABCDEFGHIJKLMNOP");
        assert_eq!(account.uidhmac, "AB12CD34");
        assert_eq!(account.nasc_environment, 1);
        assert_eq!(account.server_type, b'M');
        assert_eq!(account.server_type_number, b'K');
    }

    #[test]
    fn friend_account_parser_rejects_bad_magic_and_truncated_data() {
        let mut invalid = account_bytes();
        invalid[0] = 0;
        assert!(parse_friend_account(&invalid).is_none());
        assert!(parse_friend_account(&account_bytes()[..0x57]).is_none());
    }
}
