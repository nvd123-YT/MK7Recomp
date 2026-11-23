//! frd:u, the friend list and this console's own friend details. the
//! console keeps them itself and answers offline too, as one that never
//! logged in and has no friends. what needs the servers is left to the
//! offline reply.

use zakuro_common::result::errors;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::kernel::object::KObject;
use crate::kernel::sync::ResetType;
use crate::services::cfg::REGION_USA;
use crate::{NetworkProvider, System};

/// the platform a profile names, the 3DS.
const PLATFORM_CTR: u32 = 2;

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
        // GetMyFriendKey, a principal id, padding and a friend code seed,
        // none of which a console that never logged in has
        0x0005 => buffer.reply(&mut system.memory, command, &[0; 4]),
        // GetMyPreference, private, showing neither game
        0x0006 => buffer.reply(memory, command, &[0; 3]),
        // GetMyProfile, region, country, area and language, then platform
        0x0007 => {
            let country: u32 = if region == REGION_USA { 49 } else { 110 };
            let first = region as u32 | country << 8 | (language as u32) << 24;
            buffer.reply(memory, command, &[first, PLATFORM_CTR]);
        }
        // GetMyPresence, into a static buffer that stays as it is
        0x0008 => buffer.reply(memory, command, &[]),
        // GetMyScreenName, the user's name in eleven UTF-16 units
        0x0009 => {
            let mut name = [0u8; 24];
            for (i, unit) in system.config.username.chars().take(10).collect::<String>().encode_utf16().enumerate() {
                name[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            let words: Vec<u32> = name.as_chunks::<4>().0.iter().map(|&w| u32::from_le_bytes(w)).collect();
            buffer.reply(memory, command, &words);
        }
        // GetMyMii
        0x000A => buffer.reply(memory, command, &[0; 24]),
        // GetMyLocalAccountId
        0x000B => buffer.reply(memory, command, &[1]),
        // GetMyPlayingGame and GetMyFavoriteGame, a title id, its version
        // and a word more
        0x000C | 0x000D => buffer.reply(memory, command, &[0; 4]),
        // GetMyNcPrincipalId
        0x000E => buffer.reply(memory, command, &[0]),
        // GetMyComment
        0x000F => buffer.reply(memory, command, &[0; 9]),
        // GetFriendKeyList and GetEventNotification, none
        0x0011 | 0x0022 => buffer.reply(memory, command, &[0]),
        // lookups on friends the title names, of which it has none to name
        0x0012..=0x001A => buffer.reply(memory, command, &[]),
        // IsIncludedInFriendList
        0x001B => buffer.reply(memory, command, &[0]),
        // GetLastResponseResult, what the last request to the servers got
        0x0023 => buffer.reply(memory, command, &[errors::NOT_CONNECTED.0]),
        // ResultToErrorCode, no code to show
        0x0027 => buffer.reply(memory, command, &[0]),
        _ => return false,
    }
    true
}
