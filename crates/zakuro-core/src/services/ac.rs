//! ac:u / ac:i, the 3DS infrastructure-connection manager.
//!
//! Pretendo mode exposes the host's Internet connection only after a TCP
//! reachability probe to the NASC endpoint succeeds. This is not a substitute
//! for the game's independent NASC authentication or NEX session setup.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::kernel::object::ObjectId;
use crate::NetworkProvider;
use crate::System;

const NASC_REACHABILITY_ENDPOINT: &str = "nasc.pretendo.cc:443";
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);

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
    #[serde(skip)]
    pending_connect: Option<Receiver<io::Result<()>>>,
    #[serde(default)]
    last_error: u32,
}

/// Checks a TCP endpoint without blocking the emulation thread. Keep this
/// helper separate from the fixed Pretendo target so its socket behaviour can
/// be regression-tested against a local listener in CI.
fn check_tcp_endpoint(endpoint: &str) -> io::Result<()> {
    let addresses = endpoint.to_socket_addrs()?;
    let mut last_error = None;

    for address in addresses.filter(SocketAddr::is_ipv4) {
        match TcpStream::connect_timeout(&address, REACHABILITY_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "the Pretendo NASC endpoint did not resolve to an IPv4 address",
        )
    }))
}

fn start_connectivity_probe() -> Receiver<io::Result<()>> {
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let _ = send.send(check_tcp_endpoint(NASC_REACHABILITY_ENDPOINT));
    });
    receive
}

/// Completes AC's asynchronous connect request and signals the guest event.
/// A failed probe must never leave the guest believing it has Internet access.
pub fn poll(system: &mut System) {
    if system.config.network_provider != NetworkProvider::Pretendo {
        let (was_connecting, event) = {
            let state = &mut system.services.ac;
            let was_connecting = state.pending_connect.take().is_some();
            state.connected = false;
            state.last_error = zakuro_common::result::errors::NOT_CONNECTED.0;
            (was_connecting, state.connect_event)
        };
        if was_connecting {
            if let Some(event) = event {
                system.kernel.signal_event(event);
            }
        }
        return;
    }

    let ready = system.services.ac.pending_connect.as_ref().and_then(|pending| {
        match pending.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Pretendo reachability worker stopped",
            ))),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    });

    let Some(result) = ready else { return };
    let (event, failure) = {
        let state = &mut system.services.ac;
        state.pending_connect = None;
        state.connected = result.is_ok();
        state.last_error = if state.connected {
            0
        } else {
            zakuro_common::result::errors::NOT_CONNECTED.0
        };
        (state.connect_event, result.err())
    };

    if let Some(error) = failure {
        log::warn!("ac:u could not reach Pretendo NASC at {NASC_REACHABILITY_ENDPOINT}: {error}");
    }
    if let Some(event) = event {
        system.kernel.signal_event(event);
    }
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
                system.services.ac.last_error = zakuro_common::result::errors::NOT_CONNECTED.0;
                buffer.reply_error(&mut system.memory, command, system.services.ac.last_error);
                return true;
            }
            let Some(event) = event else {
                system.services.ac.last_error = zakuro_common::result::errors::NOT_CONNECTED.0;
                buffer.reply_error(&mut system.memory, command, system.services.ac.last_error);
                return true;
            };

            if system.services.ac.pending_connect.is_some() {
                buffer.reply_error(
                    &mut system.memory,
                    command,
                    zakuro_common::result::errors::NOT_CONNECTED.0,
                );
                return true;
            }
            system.services.ac.connect_event = Some(event);
            if system.services.ac.connected {
                system.kernel.signal_event(event);
            } else {
                system.services.ac.last_error = 0;
                system.services.ac.pending_connect = Some(start_connectivity_probe());
            }
            // ConnectAsync returns once the request is queued. Completion is
            // reported later through the supplied event handle.
            buffer.reply(&mut system.memory, command, &[]);
        }
        // GetConnectResult.
        0x0005 => {
            if system.services.ac.connected && online_provider {
                buffer.reply(&mut system.memory, command, &[]);
            } else {
                let error = if system.services.ac.last_error == 0 {
                    zakuro_common::result::errors::NOT_CONNECTED.0
                } else {
                    system.services.ac.last_error
                };
                buffer.reply_error(&mut system.memory, command, error);
            }
        }
        // CancelConnectAsync.
        0x0007 => {
            if system.services.ac.pending_connect.take().is_some() {
                system.services.ac.connected = false;
                system.services.ac.last_error = zakuro_common::result::errors::NOT_CONNECTED.0;
                if let Some(event) = system.services.ac.connect_event {
                    system.kernel.signal_event(event);
                }
                buffer.reply(&mut system.memory, command, &[]);
            } else if system.services.ac.connected {
                buffer.reply_error(&mut system.memory, command, zakuro_common::result::errors::NOT_CONNECTED.0);
            } else {
                buffer.reply(&mut system.memory, command, &[]);
            }
        }
        // CloseAsync(process id, completion event).
        0x0008 => {
            let handles = translated_handles(system, buffer, header);
            let close_event = handles.first().and_then(|handle| system.kernel.handles.resolve(*handle));
            let (was_connected, was_connecting, disconnect_event, connect_event) = {
                let state = &mut system.services.ac;
                let was_connected = state.connected;
                let was_connecting = state.pending_connect.take().is_some();
                state.connected = false;
                state.last_error = zakuro_common::result::errors::NOT_CONNECTED.0;
                state.close_event = close_event;
                (was_connected, was_connecting, state.disconnect_event, state.connect_event)
            };
            if was_connected {
                if let Some(event) = disconnect_event {
                    system.kernel.signal_event(event);
                }
            }
            if was_connecting {
                if let Some(event) = connect_event {
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
        // GetLastErrorCode and GetLastDetailErrorCode.
        0x000A | 0x000B => buffer.reply(&mut system.memory, command, &[system.services.ac.last_error]),
        // AC configuration setters mutate only the supplied 0x200-byte
        // Wi-Fi profile. Host-routed Pretendo networking does not use that
        // profile, but these documented commands must still succeed.
        0x0022 | 0x0025 | 0x002D => buffer.reply(&mut system.memory, command, &[]),
        // GetInfraPriority returns the default infrastructure priority.
        0x0027 => buffer.reply(&mut system.memory, command, &[0]),
        // GetStatus: 3 means Internet reachable/available to the guest.
        0x000C => {
            let status = if system.services.ac.connected && online_provider { 3 } else { 0 };
            buffer.reply(&mut system.memory, command, &[status]);
        }
        // GetWifiStatus returns AC_AP_TYPE_* flags; slot 1 is BIT(1) = 0x02.
        0x000D => {
            let status = if system.services.ac.connected && online_provider { 0x02 } else { 0 };
            buffer.reply(&mut system.memory, command, &[status]);
        }
        // The host network provider has no guest-visible Wi-Fi SSID,
        // access-point security or proxy configuration.
        0x0033 => buffer.reply(&mut system.memory, command, &[0]),
        0x0034 => write_static_output(system, buffer, command, &[0; 0x20]),
        0x0035 | 0x0036 | 0x0038 => buffer.reply(&mut system.memory, command, &[0]),
        0x0039 => write_static_output(system, buffer, command, &[0; 0x100]),
        0x003A | 0x003B => write_static_output(system, buffer, command, &[0; 0x20]),
        // RegisterDisconnectEvent(process id, event).
        0x0030 => {
            let handles = translated_handles(system, buffer, header);
            let event = handles.first().and_then(|handle| system.kernel.handles.resolve(*handle));
            system.services.ac.disconnect_event = event;
            buffer.reply(&mut system.memory, command, &[]);
        }
        // IsConnected.
        0x003E => {
            buffer.reply(
                &mut system.memory,
                command,
                &[u32::from(system.services.ac.connected && online_provider)],
            );
        }
        // Legacy SetClientVersion.
        0x0040 => buffer.reply(&mut system.memory, command, &[]),
        // ACI_LoadNetworkSetting(slot) succeeds because Pretendo routes through
        // the host network instead of opening a physical 3DS Wi-Fi profile.
        0x0401 => buffer.reply(&mut system.memory, command, &[]),
        // ACI_GetNetworkWirelessEssidSecuritySsid.
        0x040F => write_static_output(system, buffer, command, &[0; 0x20]),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::tests::system_with_thread;
    use std::net::TcpListener;

    #[test]
    fn wifi_status_requires_a_completed_internet_connection() {
        let (mut system, buffer) = system_with_thread();
        system.config.network_provider = NetworkProvider::Pretendo;
        buffer.set(&mut system.memory, 0, Header::new(0x000D, 0, 0).0);
        let header = buffer.header(&mut system.memory);
        handle(&mut system, &buffer, header);
        assert_eq!(buffer.get(&mut system.memory, 2), 0);

        system.services.ac.connected = true;
        buffer.set(&mut system.memory, 0, Header::new(0x000D, 0, 0).0);
        let header = buffer.header(&mut system.memory);
        handle(&mut system, &buffer, header);
        assert_eq!(buffer.get(&mut system.memory, 2), 0x02);
    }

    #[test]
    fn connect_async_translation_extracts_the_guest_completion_event() {
        let (mut system, buffer) = system_with_thread();
        let (object, handle) = system
            .kernel
            .create_event(crate::kernel::sync::ResetType::OneShot, "AC completion");
        // libctru ACU_ConnectAsync sends PID descriptor, one copied event
        // handle, then the config static buffer (0x40006 translate words).
        buffer.set(&mut system.memory, 0, Header::new(0x0004, 0, 6).0);
        buffer.set(&mut system.memory, 1, 0x20);
        buffer.set(&mut system.memory, 2, 0x1234);
        buffer.set(&mut system.memory, 3, Descriptor::handles(1));
        buffer.set(&mut system.memory, 4, handle);
        buffer.set(&mut system.memory, 5, Descriptor::static_buffer(0x200, 1));
        buffer.set(&mut system.memory, 6, 0x0800_1000);
        let header = buffer.header(&mut system.memory);

        let translated = translated_handles(&mut system, &buffer, header);
        assert_eq!(translated.len(), 1);
        assert_eq!(system.kernel.handles.resolve(translated[0]), Some(object));
    }

    #[test]
    fn ac_poll_signals_the_guest_event_after_a_successful_probe() {
        let (mut system, _) = system_with_thread();
        system.config.network_provider = NetworkProvider::Pretendo;
        let (object, _) = system
            .kernel
            .create_event(crate::kernel::sync::ResetType::OneShot, "AC completion");
        let (send, receive) = mpsc::channel();
        send.send(Ok(())).unwrap();
        system.services.ac.connect_event = Some(object);
        system.services.ac.pending_connect = Some(receive);

        poll(&mut system);

        assert!(system.services.ac.connected);
        assert_eq!(system.services.ac.last_error, 0);
        let signaled = match system.kernel.objects.get(object) {
            Some(crate::kernel::object::KObject::Event(event)) => event.signaled,
            _ => false,
        };
        assert!(signaled);
    }

    #[test]
    fn ac_poll_preserves_disconnected_state_when_probe_fails() {
        let (mut system, _) = system_with_thread();
        system.config.network_provider = NetworkProvider::Pretendo;
        let (object, _) = system
            .kernel
            .create_event(crate::kernel::sync::ResetType::OneShot, "AC completion");
        let (send, receive) = mpsc::channel();
        send.send(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "test failure"))).unwrap();
        system.services.ac.connect_event = Some(object);
        system.services.ac.pending_connect = Some(receive);

        poll(&mut system);

        assert!(!system.services.ac.connected);
        assert_eq!(system.services.ac.last_error, zakuro_common::result::errors::NOT_CONNECTED.0);
        let signaled = match system.kernel.objects.get(object) {
            Some(crate::kernel::object::KObject::Event(event)) => event.signaled,
            _ => false,
        };
        assert!(signaled);
    }

    #[test]
    fn ac_wifi_configuration_setters_succeed_for_the_host_network_provider() {
        let (mut system, buffer) = system_with_thread();
        for command in [0x0022, 0x0025, 0x002D, 0x0401] {
            buffer.set(&mut system.memory, 0, Header::new(command, 0, 0).0);
            let header = buffer.header(&mut system.memory);
            assert!(handle(&mut system, &buffer, header));
            assert_eq!(buffer.get(&mut system.memory, 1), 0, "command 0x{command:04X}");
        }
    }

    #[test]
    fn ac_wifi_and_proxy_queries_report_no_physical_wifi_or_proxy() {
        let (mut system, buffer) = system_with_thread();
        for (command, expected) in [(0x0033, 0), (0x0035, 0), (0x0036, 0), (0x0038, 0)] {
            buffer.set(&mut system.memory, 0, Header::new(command, 0, 0).0);
            let header = buffer.header(&mut system.memory);
            assert!(handle(&mut system, &buffer, header));
            assert_eq!(buffer.get(&mut system.memory, 2), expected, "command 0x{command:04X}");
        }
    }

    #[test]
    fn switching_the_provider_off_clears_a_connected_ac_state() {
        let (mut system, _) = system_with_thread();
        system.services.ac.connected = true;
        system.config.network_provider = NetworkProvider::Off;
        poll(&mut system);
        assert!(!system.services.ac.connected);
    }

    #[test]
    fn tcp_reachability_probe_works_against_a_local_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        assert!(check_tcp_endpoint(&endpoint).is_ok());
    }

    #[test]
    fn tcp_reachability_probe_reports_a_closed_endpoint() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert!(check_tcp_endpoint(&endpoint).is_err());
    }
}


/// Writes an AC query's fixed-size output into TLS static-buffer slot 0.
fn write_static_output(system: &mut System, buffer: &CommandBuffer, command: u16, bytes: &[u8]) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    if capacity < bytes.len() as u32 {
        buffer.reply_error(
            &mut system.memory,
            command,
            zakuro_common::result::errors::NOT_CONNECTED.0,
        );
        return;
    }
    system.memory.write_bytes(pointer, bytes);
    buffer.reply(&mut system.memory, command, &[]);
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
