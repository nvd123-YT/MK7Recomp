//! ac:u / ac:i, the 3DS infrastructure-connection manager.
//!
//! Pretendo mode represents the host's working internet connection to the
//! guest. This is connection-state emulation only; it does not perform NASC
//! authentication or guarantee that the selected endpoint is reachable.

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::kernel::object::ObjectId;
use crate::NetworkProvider;
use crate::System;

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct AcState {
    #[serde(skip)]
    connected: bool,
    #[serde(skip)]
    connect_event: Option<ObjectId>,
    #[serde(skip)]
    disconnect_event: Option<ObjectId>,
    #[serde(skip)]
    close_event: Option<ObjectId>,
}

pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    let command = header.command_id();
    let online_provider = system.config.network_provider == NetworkProvider::Pretendo;
    match command {
        // CreateDefaultConfig: return a zeroed 0x200-byte ACConfig.
        0x0001 => {
            let tls = system.kernel.current().map_or(0, |thread| thread.tls);
            let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
            let bytes = vec![0; (capacity as usize).min(0x200)];
            system.memory.write_bytes(pointer, &bytes);
            buffer.set(&mut system.memory, 0, Header::new(command, 1, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, Descriptor::static_buffer(bytes.len() as u32, 0));
            buffer.set(&mut system.memory, 3, pointer);
        }
        // ConnectAsync(process id, event handle, ACConfig).
        0x0004 => {
            let handles = translated_handles(system, buffer, header);
            let event = handles.first().and_then(|handle| system.kernel.handles.resolve(*handle));
            if !online_provider {
                system.services.ac.connected = false;
                buffer.reply_error(&mut system.memory, command, zakuro_common::result::errors::NOT_CONNECTED.0);
                return true;
            }
            system.services.ac.connect_event = event;
            system.services.ac.connected = true;
            if let Some(event) = event {
                system.kernel.signal_event(event);
            }
            buffer.reply(&mut system.memory, command, &[]);
        }
        // GetConnectResult.
        0x0005 => {
            if system.services.ac.connected && online_provider {
                buffer.reply(&mut system.memory, command, &[]);
            } else {
                buffer.reply_error(&mut system.memory, command, zakuro_common::result::errors::NOT_CONNECTED.0);
            }
        }
        // CancelConnectAsync.
        0x0007 => {
            if system.services.ac.connected {
                buffer.reply_error(&mut system.memory, command, zakuro_common::result::errors::NOT_CONNECTED.0);
            } else {
                buffer.reply(&mut system.memory, command, &[]);
            }
        }
        // CloseAsync(process id, completion event).
        0x0008 => {
            let handles = translated_handles(system, buffer, header);
            let close_event = handles.first().and_then(|handle| system.kernel.handles.resolve(*handle));
            let (was_connected, disconnect_event) = {
                let state = &mut system.services.ac;
                let was_connected = state.connected;
                state.connected = false;
                state.close_event = close_event;
                (was_connected, state.disconnect_event)
            };
            if was_connected {
                if let Some(event) = disconnect_event {
                    system.kernel.signal_event(event);
                }
            }
            if let Some(event) = close_event {
                system.kernel.signal_event(event);
            }
            buffer.reply(&mut system.memory, command, &[]);
        }
        // GetCloseResult.
        0x0009 => buffer.reply(&mut system.memory, command, &[]),
        // GetLastErrorCode / GetCurrentAPInfo (not associated with a failing
        // connection in Pretendo mode; there is no physical AP to describe).
        0x000A => buffer.reply(&mut system.memory, command, &[0]),
        0x000E => buffer.reply(&mut system.memory, command, &[0; 8]),
        // GetStatus: 3 means internet reachable/available to the guest.
        0x000C => {
            let status = if online_provider { 3 } else { 0 };
            buffer.reply(&mut system.memory, command, &[status]);
        }
        // GetWifiStatus: slot 1 is connected in infrastructure mode.
        0x000D => {
            let status = if online_provider { 1 } else { 0 };
            buffer.reply(&mut system.memory, command, &[status]);
        }
        // RegisterDisconnectEvent(process id, event).
        0x0030 => {
            let handles = translated_handles(system, buffer, header);
            let event = handles.first().and_then(|handle| system.kernel.handles.resolve(*handle));
            system.services.ac.disconnect_event = event;
            buffer.reply(&mut system.memory, command, &[]);
        }
        // IsConnected.
        0x003E => {
            buffer.reply(&mut system.memory, command, &[u32::from(system.services.ac.connected && online_provider)]);
        }
        // SetClientVersion.
        0x0040 => buffer.reply(&mut system.memory, command, &[]),
        // Proxy and other AC discovery commands are not needed by the direct
        // HTTP/NASC flow; unsupported commands remain explicit NOT_CONNECTED.
        _ => return false,
    }
    true
}

/// walks the IPC translate descriptors, returning all copied/moved handles.
/// ProcessId and buffers consume two words; each handle descriptor consumes
/// the descriptor plus the number of handle words it names.
fn translated_handles(system: &mut System, buffer: &CommandBuffer, header: Header) -> Vec<u32> {
    let mut handles = Vec::new();
    let mut index = header.normal_params() + 1;
    let end = index + header.translate_params();
    while index < end {
        let raw = buffer.get(&mut system.memory, index);
        match Descriptor::parse(raw) {
            Descriptor::Handles { count, .. } => {
                for offset in 0..count {
                    if index + 1 + offset < end {
                        handles.push(buffer.get(&mut system.memory, index + 1 + offset));
                    }
                }
                index += count + 1;
            }
            Descriptor::CurrentProcessId
            | Descriptor::StaticBuffer { .. }
            | Descriptor::MappedBuffer { .. } => index += 2,
            Descriptor::Unknown(_) => index += 1,
        }
    }
    handles
}
