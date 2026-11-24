//! soc:U, the guest TCP/UDP socket interface used by HTTP and NEX.
//!
//! Host sockets are deliberately non-blocking after creation. A guest which
//! wants a blocking connect gets a bounded wait; a non-blocking connect is
//! completed on a worker and reported through the normal poll/read path.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::{NetworkProvider, System};

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
// libctru/include/poll.h (CTR): these values differ from some host poll APIs.
const POLLIN: u32 = 0x01;
const POLLPRI: u32 = 0x02;
const POLLHUP: u32 = 0x04;
const POLLERR: u32 = 0x08;
const POLLOUT: u32 = 0x10;
const POLLNVAL: u32 = 0x20;
const SOC_SOL_CONFIG: u32 = 0xFFFE;
const MAX_PACKET: usize = 0x10000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

enum HostSocket {
    UdpUnbound,
    Udp { socket: UdpSocket, peer: Option<SocketAddr> },
    TcpUnbound,
    TcpConnecting(Receiver<io::Result<TcpStream>>),
    Tcp(TcpStream),
    TcpListener(TcpListener),
    TcpFailed(i32),
}

struct SocketEntry {
    socket: HostSocket,
    nonblocking: bool,
    accepted: VecDeque<(TcpStream, SocketAddr)>,
}

impl SocketEntry {
    fn new(socket: HostSocket) -> Self {
        Self { socket, nonblocking: false, accepted: VecDeque::new() }
    }

    fn update(&mut self) {
        let completed = match &self.socket {
            HostSocket::TcpConnecting(receiver) => match receiver.try_recv() {
                Ok(Ok(stream)) => Some(Ok(stream)),
                Ok(Err(error)) => Some(Err(errno(&error))),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(-5)),
                Err(mpsc::TryRecvError::Empty) => None,
            },
            _ => None,
        };
        if let Some(completed) = completed {
            self.socket = match completed {
                Ok(stream) => HostSocket::Tcp(stream),
                Err(code) => HostSocket::TcpFailed(code),
            };
        }
    }
}

/// Runtime-only sockets are intentionally omitted from save states. Restoring
/// a save state must not resurrect stale host file descriptors or credentials.
pub struct SocState {
    sockets: BTreeMap<u32, SocketEntry>,
    initialized: bool,
    next_socket: u32,
}

impl Default for SocState {
    fn default() -> Self {
        Self { sockets: BTreeMap::new(), initialized: false, next_socket: 3 }
    }
}

impl SocState {
    fn allocate(&mut self, socket: HostSocket) -> u32 {
        let id = self.next_socket.max(3);
        self.next_socket = id.wrapping_add(1).max(3);
        self.sockets.insert(id, SocketEntry::new(socket));
        id
    }

    fn close_all(&mut self) {
        self.sockets.clear();
        self.initialized = false;
        self.next_socket = 3;
    }
}

/// Handles the commands exposed by libctru's soc:U service.
pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    let command = header.command_id();
    let word = |system: &mut System, index| buffer.get(&mut system.memory, index);
    match command {
        // InitializeSockets(memory size, process id, shared memory)
        0x0001 => {
            system.services.soc.initialized = true;
            buffer.reply(&mut system.memory, command, &[]);
        }
        // Socket(domain, type, protocol)
        0x0002 => {
            let (domain, kind, protocol) = (word(system, 1), word(system, 2), word(system, 3));
            let result = if domain != AF_INET {
                -5
            } else if protocol != 0 && !matches!((kind, protocol), (SOCK_STREAM, IPPROTO_TCP) | (SOCK_DGRAM, IPPROTO_UDP)) {
                -68
            } else {
                match kind {
                    SOCK_STREAM => {
                        let id = system.services.soc.allocate(HostSocket::TcpUnbound);
                        id as i32
                    }
                    SOCK_DGRAM => {
                        let id = system.services.soc.allocate(HostSocket::UdpUnbound);
                        id as i32
                    }
                    _ => -69,
                }
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Listen(fd, backlog). Binding creates the host listener in std::net.
        0x0003 => {
            let id = word(system, 1);
            let result = match system.services.soc.sockets.get(&id) {
                Some(entry) if matches!(entry.socket, HostSocket::TcpListener(_)) => 0,
                Some(_) => -22,
                None => -8,
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Accept(fd, max address length)
        0x0004 => {
            let (id, max_address) = (word(system, 1), word(system, 2));
            accept(system, buffer, command, id, max_address);
        }
        // Bind(fd, address length, current pid), address in static buffer 0.
        0x0005 => {
            let (id, address_length) = (word(system, 1), word(system, 2) as usize);
            let address_bytes = read_static(system, buffer, 0, address_length.min(28));
            let address = parse_address(&address_bytes);
            let result = match (address, system.services.soc.sockets.get_mut(&id)) {
                (Ok(address), Some(entry)) => {
                    match &entry.socket {
                        HostSocket::UdpUnbound => match UdpSocket::bind(address) {
                            Ok(socket) => {
                                let _ = socket.set_nonblocking(true);
                                entry.socket = HostSocket::Udp { socket, peer: None };
                                0
                            }
                            Err(error) => errno(&error),
                        },
                        HostSocket::TcpUnbound => match TcpListener::bind(address) {
                            Ok(listener) => {
                                let _ = listener.set_nonblocking(true);
                                entry.socket = HostSocket::TcpListener(listener);
                                0
                            }
                            Err(error) => errno(&error),
                        },
                        _ => -22,
                    }
                }
                (Err(code), _) => code,
                (_, None) => -8,
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Connect(fd, address length, pid), address in static buffer 0.
        0x0006 => {
            let (id, address_length) = (word(system, 1), word(system, 2) as usize);
            let address_bytes = read_static(system, buffer, 0, address_length.min(28));
            let result = match parse_address(&address_bytes) {
                Err(code) => code,
                Ok(SocketAddr::V6(_)) => -5,
                Ok(SocketAddr::V4(address)) => match system.services.soc.sockets.get_mut(&id) {
                    None => -8,
                    Some(entry) => {
                        // Change the remembered default peer without applying
                        // an immutable borrow to the socket enum.
                        if let HostSocket::Udp { peer, .. } = &mut entry.socket {
                            *peer = Some(SocketAddr::V4(address));
                            0
                        } else {
                            match &entry.socket {
                                HostSocket::UdpUnbound => match UdpSocket::bind("0.0.0.0:0") {
                                    Ok(socket) => {
                                        let _ = socket.set_nonblocking(true);
                                        // Keep the host socket unconnected so incoming
                                        // peer-to-peer race packets are not filtered.
                                        entry.socket = HostSocket::Udp {
                                            socket,
                                            peer: Some(SocketAddr::V4(address)),
                                        };
                                        0
                                    }
                                    Err(error) => errno(&error),
                                },
                                HostSocket::TcpUnbound => {
                                    let (send, receive) = mpsc::channel();
                                    thread::spawn(move || {
                                        let result = TcpStream::connect_timeout(
                                            &SocketAddr::V4(address),
                                            CONNECT_TIMEOUT,
                                        )
                                        .and_then(|stream| {
                                            stream.set_nonblocking(true)?;
                                            Ok(stream)
                                        });
                                        let _ = send.send(result);
                                    });
                                    let blocking = !entry.nonblocking;
                                    if blocking {
                                        match receive.recv_timeout(CONNECT_TIMEOUT) {
                                            Ok(Ok(stream)) => {
                                                entry.socket = HostSocket::Tcp(stream);
                                                0
                                            }
                                            Ok(Err(error)) => errno(&error),
                                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                                entry.socket = HostSocket::TcpConnecting(receive);
                                                -26
                                            }
                                            Err(mpsc::RecvTimeoutError::Disconnected) => -5,
                                        }
                                    } else {
                                        entry.socket = HostSocket::TcpConnecting(receive);
                                        -26
                                    }
                                }
                                HostSocket::TcpConnecting(_) => -7,
                                HostSocket::Tcp(_) => -30,
                                HostSocket::TcpListener(_) => -22,
                                HostSocket::TcpFailed(code) => *code,
                                HostSocket::Udp { .. } => unreachable!(),
                            }
                        }
                    }
                },
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // RecvFromOther uses a mapped buffer; it shares the same receive path
        // as RecvFrom where possible. See receive() for the ordinary SDK path.
        0x0007 => receive_other(system, buffer, header),
        // RecvFrom(fd, length, flags, address length), output buffers 0 and 1.
        0x0008 => {
            let (id, length, flags, address_length) = (word(system, 1), word(system, 2) as usize, word(system, 3), word(system, 4) as usize);
            receive(system, buffer, command, id, length, flags, address_length);
        }
        // SendToOther uses a mapped buffer.
        0x0009 => send_other(system, buffer, header),
        // SendToSingle uses static buffer slot 2 for payload and slot 1 for address.
        0x000A => {
            let (id, length, address_length) = (word(system, 1), word(system, 2) as usize, word(system, 4) as usize);
            let payload = read_static(system, buffer, 2, length.min(MAX_PACKET));
            let address = if address_length > 0 {
                parse_address(&read_static(system, buffer, 1, address_length.min(28))).ok()
            } else { None };
            let result = send_data(system.services.soc.sockets.get_mut(&id), &payload, address);
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Close(fd)
        0x000B => {
            let id = word(system, 1);
            let result = if system.services.soc.sockets.remove(&id).is_some() { 0 } else { -8 };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Shutdown(fd, how)
        0x000C => {
            let (id, how) = (word(system, 1), word(system, 2));
            let result = match system.services.soc.sockets.get_mut(&id) {
                Some(entry) => match &mut entry.socket {
                    HostSocket::Tcp(stream) => {
                        let how = match how { 0 => std::net::Shutdown::Read, 1 => std::net::Shutdown::Write, 2 => std::net::Shutdown::Both, _ => { buffer.reply(&mut system.memory, command, &[(-22i32) as u32]); return true; } };
                        stream.shutdown(how).map_or_else(|error| errno(&error), |_| 0)
                    }
                    HostSocket::Udp { .. } | HostSocket::UdpUnbound => 0,
                    HostSocket::TcpListener(_) => -22,
                    HostSocket::TcpUnbound | HostSocket::TcpConnecting(_) => -107,
                    HostSocket::TcpFailed(code) => *code,
                },
                None => -8,
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // GetHostByName(name length, output length), input in buffer 0.
        0x000D => {
            let length = word(system, 1) as usize;
            let name = c_string(read_static(system, buffer, 0, length.min(256)));
            let name_for_dns = rewrite_network_hostname(&name, system.config.network_provider);
            let (error, result) = host_by_name(&name_for_dns);
            reply_static(system, buffer, command, &[error as u32], &result);
        }
        // GetHostByAddr(address length, family, output length), input in buffer 0.
        0x000E => {
            let address = read_static(system, buffer, 0, 28);
            let (error, result) = match parse_address(&address) {
                Ok(SocketAddr::V4(address)) => host_by_name(&address.ip().to_string()),
                _ => (-5, vec![0; 0x1A88]),
            };
            reply_static(system, buffer, command, &[error as u32], &result);
        }
        // GetAddrInfo(node length, service length, hints length, output size).
        0x000F => get_addr_info(system, buffer, command),
        // GetNameInfo
        0x0010 => get_name_info(system, buffer, command),
        // GetSockOpt(fd, level, option, length), output in buffer 0.
        0x0011 => {
            let (id, level, option, length) = (word(system, 1), word(system, 2), word(system, 3), word(system, 4) as usize);
            let (error, value) = get_sock_opt(system.services.soc.sockets.get_mut(&id), level, option, length);
            reply_static(system, buffer, command, &[error as u32, value.len() as u32], &value);
        }
        // SetSockOpt(fd, level, option, length), input in buffer 0.
        0x0012 => {
            let (id, level, option, length) = (word(system, 1), word(system, 2), word(system, 3), word(system, 4) as usize);
            let value = read_static(system, buffer, 0, length.min(256));
            let result = set_sock_opt(system.services.soc.sockets.get_mut(&id), level, option, &value);
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Fcntl(fd, command, argument)
        0x0013 => {
            let (id, operation, argument) = (word(system, 1), word(system, 2), word(system, 3));
            let result = match system.services.soc.sockets.get_mut(&id) {
                Some(entry) => match operation {
                    3 => if entry.nonblocking { 4 } else { 0 },
                    4 => { entry.nonblocking = argument & 4 != 0; 0 }
                    _ => -22,
                },
                None => -8,
            };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // Poll(count, timeout), pollfd array in static buffer 0.
        0x0014 => {
            let (count, timeout) = (word(system, 1) as usize, word(system, 2) as i32);
            poll(system, buffer, command, count, timeout);
        }
        // SockAtMark
        0x0015 => {
            let id = word(system, 1);
            let result = if system.services.soc.sockets.contains_key(&id) { 0 } else { -8 };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        // GetHostId, the guest-visible IPv4 address selected by the host's
        // active route rather than a loopback address.
        0x0016 => {
            let host_id = local_interface_ipv4()
                .map(|address| u32::from_ne_bytes(address.octets()))
                .unwrap_or(0);
            buffer.reply(&mut system.memory, command, &[host_id]);
        }
        // GetSockName / GetPeerName
        0x0017 | 0x0018 => {
            let (id, address_length) = (word(system, 1), word(system, 2) as usize);
            let peer = command == 0x0018;
            let result = match system.services.soc.sockets.get_mut(&id) {
                Some(entry) => {
                    entry.update();
                    socket_address(entry, peer).map(|address| address_bytes(address)).unwrap_or_default()
                }
                None => Vec::new(),
            };
            let code = if result.is_empty() { -107 } else { 0 };
            reply_static(system, buffer, command, &[code as u32], &result[..result.len().min(address_length)]);
        }
        // ShutdownSockets
        0x0019 => {
            system.services.soc.close_all();
            buffer.reply(&mut system.memory, command, &[]);
        }
        // GetNetworkOpt(level, option, length), output in buffer 0.
        0x001A => {
            let (level, option, length) = (word(system, 1), word(system, 2), word(system, 3) as usize);
            let result = network_option(system, level, option, length);
            let error = if result.is_empty() { -22 } else { 0 };
            reply_static(system, buffer, command, &[error as u32, result.len() as u32], &result);
        }
        // SendToMultiple is not used by the 3DS TCP/IP path used by NEX.
        0x0020 => buffer.reply(&mut system.memory, command, &[(-38i32) as u32]),
        // CloseSockets
        0x0021 => {
            system.services.soc.sockets.clear();
            buffer.reply(&mut system.memory, command, &[]);
        }
        // AddGlobalSocket
        0x0023 => {
            let id = word(system, 1);
            let result = if system.services.soc.sockets.contains_key(&id) { 0 } else { -8 };
            buffer.reply(&mut system.memory, command, &[result as u32]);
        }
        _ => return false,
    }
    true
}

fn translated_buffer(
    system: &mut System,
    buffer: &CommandBuffer,
    header: Header,
    mapped: bool,
    ordinal: u32,
) -> Option<(u32, u32, usize)> {
    let mut index = header.normal_params() + 1;
    let end = index + header.translate_params();
    let mut found = 0u32;
    while index < end {
        let raw = buffer.get(&mut system.memory, index);
        match Descriptor::parse(raw) {
            Descriptor::Handles { count, .. } => index += count + 1,
            Descriptor::CurrentProcessId => index += 2,
            Descriptor::StaticBuffer { size, .. } => {
                if !mapped && found == ordinal {
                    let pointer = buffer.get(&mut system.memory, index + 1);
                    return Some((raw, pointer, size as usize));
                }
                if !mapped { found += 1; }
                index += 2;
            }
            Descriptor::MappedBuffer { size, .. } => {
                let pointer = buffer.get(&mut system.memory, index + 1);
                if mapped && found == ordinal {
                    return Some((raw, pointer, size as usize));
                }
                if mapped { found += 1; }
                index += 2;
            }
            Descriptor::Unknown(_) => index += 1,
        }
    }
    None
}

fn read_static(system: &mut System, buffer: &CommandBuffer, id: u32, length: usize) -> Vec<u8> {
    let header = buffer.header(&mut system.memory);
    let Some((_, pointer, capacity)) = translated_buffer(system, buffer, header, false, id) else {
        return Vec::new();
    };
    let length = length.min(capacity);
    let mut bytes = vec![0; length];
    system.memory.read_bytes(pointer, &mut bytes);
    bytes
}

fn mapped_buffer(
    system: &mut System,
    buffer: &CommandBuffer,
    header: Header,
    ordinal: u32,
    requested: usize,
) -> Option<(u32, u32, usize)> {
    let (descriptor, pointer, capacity) = translated_buffer(system, buffer, header, true, ordinal)?;
    Some((descriptor, pointer, capacity.min(requested)))
}

fn reply_mapped(
    system: &mut System,
    buffer: &CommandBuffer,
    command: u16,
    values: &[u32],
    descriptor: u32,
    pointer: u32,
) {
    let normal = values.len() as u32 + 1;
    buffer.set(&mut system.memory, 0, Header::new(command, normal, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    for (index, value) in values.iter().enumerate() {
        buffer.set(&mut system.memory, index as u32 + 2, *value);
    }
    buffer.set(&mut system.memory, normal + 1, descriptor);
    buffer.set(&mut system.memory, normal + 2, pointer);
}

fn reply_static_mapped(
    system: &mut System,
    buffer: &CommandBuffer,
    command: u16,
    values: &[u32],
    address: &[u8],
    mapped_descriptor: u32,
    mapped_pointer: u32,
) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (address_pointer, address_capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    let address_length = address.len().min(address_capacity as usize);
    system.memory.write_bytes(address_pointer, &address[..address_length]);

    let normal = values.len() as u32 + 1;
    buffer.set(&mut system.memory, 0, Header::new(command, normal, 4).0);
    buffer.set(&mut system.memory, 1, 0);
    for (index, value) in values.iter().enumerate() {
        buffer.set(&mut system.memory, index as u32 + 2, *value);
    }
    buffer.set(&mut system.memory, normal + 1, Descriptor::static_buffer(address_length as u32, 0));
    buffer.set(&mut system.memory, normal + 2, address_pointer);
    buffer.set(&mut system.memory, normal + 3, mapped_descriptor);
    buffer.set(&mut system.memory, normal + 4, mapped_pointer);
}

fn reply_static(system: &mut System, buffer: &CommandBuffer, command: u16, words: &[u32], bytes: &[u8]) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (destination, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    let length = bytes.len().min(capacity as usize);
    system.memory.write_bytes(destination, &bytes[..length]);
    let normal = words.len() as u32 + 1;
    buffer.set(&mut system.memory, 0, Header::new(command, normal, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    for (index, value) in words.iter().enumerate() {
        buffer.set(&mut system.memory, index as u32 + 2, *value);
    }
    buffer.set(&mut system.memory, normal + 1, Descriptor::static_buffer(length as u32, 0));
    buffer.set(&mut system.memory, normal + 2, destination);
}

fn reply_static_two(system: &mut System, buffer: &CommandBuffer, command: u16, words: &[u32], first: &[u8], second: &[u8]) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (first_ptr, first_cap) = buffer.static_buffer(&mut system.memory, tls, 0);
    let (second_ptr, second_cap) = buffer.static_buffer(&mut system.memory, tls, 1);
    let first_len = first.len().min(first_cap as usize);
    let second_len = second.len().min(second_cap as usize);
    system.memory.write_bytes(first_ptr, &first[..first_len]);
    system.memory.write_bytes(second_ptr, &second[..second_len]);
    let normal = words.len() as u32 + 1;
    buffer.set(&mut system.memory, 0, Header::new(command, normal, 4).0);
    buffer.set(&mut system.memory, 1, 0);
    for (index, value) in words.iter().enumerate() {
        buffer.set(&mut system.memory, index as u32 + 2, *value);
    }
    buffer.set(&mut system.memory, normal + 1, Descriptor::static_buffer(first_len as u32, 0));
    buffer.set(&mut system.memory, normal + 2, first_ptr);
    buffer.set(&mut system.memory, normal + 3, Descriptor::static_buffer(second_len as u32, 1));
    buffer.set(&mut system.memory, normal + 4, second_ptr);
}

/// Applies the same domain-family substitutions used by the official
/// Pretendo 3DS HTTP/socket patches. URL callers should use
/// [rewrite_network_url] as well, so the HTTP Host header and TLS SNI match.
pub fn rewrite_network_hostname(host: &str, provider: NetworkProvider) -> String {
    if provider != NetworkProvider::Pretendo {
        return host.to_owned();
    }
    let lower = host.to_ascii_lowercase();
    // The Friends sysmodule uses a fixed Pretendo NASC URL rather than the
    // generic test-environment URL replacement performed by http:C.
    if matches!(lower.as_str(), "nasc.nintendowifi.net" | "nasc.test.nintendowifi.net" | "nasc.dev.nintendowifi.net") {
        return "nasc.pretendo.cc".to_owned();
    }
    for suffix in ["nintendowifi.net", "nintendo.net", "pokemon-gl.com"] {
        if lower == suffix {
            return "pretendo.cc".to_owned();
        }
        if lower.ends_with(&format!(".{suffix}")) {
            let prefix_length = host.len() - suffix.len();
            return format!("{}pretendo.cc", &host[..prefix_length]);
        }
    }
    host.to_owned()
}

/// Rewrites a URL's authority host without touching path, query or fragment.
pub fn rewrite_network_url(url: &str, provider: NetworkProvider) -> String {
    if provider != NetworkProvider::Pretendo {
        return url.to_owned();
    }
    let Some(scheme_end) = url.find("://") else { return url.to_owned() };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(|ch| matches!(ch, '/' | '?' | '#'))
        .map_or(url.len(), |offset| authority_start + offset);
    let authority = &url[authority_start..authority_end];
    let host_start = authority.rfind('@').map_or(0, |at| at + 1);
    let host_port = &authority[host_start..];
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => (host, Some(port)),
        _ => (host_port, None),
    };
    let rewritten = rewrite_network_hostname(host, provider);
    if rewritten == host {
        return url.to_owned();
    }
    let replacement = match port {
        Some(port) => format!("{rewritten}:{port}"),
        None => rewritten,
    };
    let mut output = String::with_capacity(url.len() + replacement.len());
    output.push_str(&url[..authority_start + host_start]);
    output.push_str(&replacement);
    output.push_str(&url[authority_end..]);
    output
}

fn c_string(bytes: Vec<u8>) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

fn parse_address(bytes: &[u8]) -> Result<SocketAddr, i32> {
    if bytes.len() < 8 || bytes[0] < 8 || bytes[1] as u32 != AF_INET {
        return Err(-22);
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

fn address_bytes(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(address) => {
            let mut bytes = vec![0; 28];
            bytes[0] = 8;
            bytes[1] = AF_INET as u8;
            bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&address.ip().octets());
            bytes
        }
        SocketAddr::V6(_) => Vec::new(),
    }
}

fn errno(error: &io::Error) -> i32 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => -2,
        io::ErrorKind::AddrInUse => -3,
        io::ErrorKind::AddrNotAvailable => -4,
        io::ErrorKind::ConnectionAborted => -13,
        io::ErrorKind::ConnectionRefused => -14,
        io::ErrorKind::ConnectionReset => -15,
        io::ErrorKind::NotConnected => -56,
        io::ErrorKind::TimedOut => -76,
        io::ErrorKind::WouldBlock => -6,
        io::ErrorKind::InvalidInput => -28,
        io::ErrorKind::InvalidData => -9,
        io::ErrorKind::BrokenPipe => -66,
        io::ErrorKind::Interrupted => -27,
        io::ErrorKind::OutOfMemory => -49,
        _ => -5,
    }
}

fn send_data(entry: Option<&mut SocketEntry>, payload: &[u8], address: Option<SocketAddr>) -> i32 {
    let Some(entry) = entry else { return -8 };
    entry.update();
    match &mut entry.socket {
        HostSocket::UdpUnbound => {
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    let _ = socket.set_nonblocking(true);
                    entry.socket = HostSocket::Udp { socket, peer: None };
                    send_data(Some(entry), payload, address)
                }
                Err(error) => errno(&error),
            }
        }
        HostSocket::Udp { socket, peer } => {
            let destination = address.or(*peer);
            let result = match destination {
                Some(address) => socket.send_to(payload, address),
                None => return -56,
            };
            result.map_or_else(|error| errno(&error), |sent| sent as i32)
        }
        HostSocket::Tcp(stream) => stream.write(payload).map_or_else(|error| errno(&error), |sent| sent as i32),
        HostSocket::TcpConnecting(_) => -6,
        HostSocket::TcpFailed(code) => *code,
        HostSocket::TcpListener(_) | HostSocket::TcpUnbound => -107,
    }
}

const BLOCKING_RECV_TIMEOUT: Duration = Duration::from_secs(30);

fn recv_udp(
    socket: &UdpSocket,
    payload: &mut [u8],
    peek: bool,
    blocking: bool,
) -> io::Result<(usize, SocketAddr)> {
    let started = std::time::Instant::now();
    loop {
        let result = if peek { socket.peek_from(payload) } else { socket.recv_from(payload) };
        match result {
            Ok(received) => return Ok(received),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && blocking => {
                if started.elapsed() >= BLOCKING_RECV_TIMEOUT {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "guest blocking UDP receive timed out"));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn recv_tcp(
    stream: &mut TcpStream,
    payload: &mut [u8],
    peek: bool,
    blocking: bool,
) -> io::Result<usize> {
    let started = std::time::Instant::now();
    loop {
        let result = if peek { stream.peek(payload) } else { stream.read(payload) };
        match result {
            Ok(received) => return Ok(received),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && blocking => {
                if started.elapsed() >= BLOCKING_RECV_TIMEOUT {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "guest blocking TCP receive timed out"));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn receive(system: &mut System, buffer: &CommandBuffer, command: u16, id: u32, length: usize, flags: u32, address_length: usize) {
    let length = length.min(MAX_PACKET);
    let result = match system.services.soc.sockets.get_mut(&id) {
        None => Err(-8),
        Some(entry) => {
            entry.update();
            let blocking = !entry.nonblocking && flags & 4 == 0;
            let peek = flags & 2 != 0;
            let mut payload = vec![0; length];
            match &mut entry.socket {
                HostSocket::Udp { socket, .. } => recv_udp(socket, &mut payload, peek, blocking)
                    .map(|(size, address)| (size, Some(address)))
                    .map_err(|error| errno(&error)),
                HostSocket::Tcp(stream) => recv_tcp(stream, &mut payload, peek, blocking)
                    .map(|size| {
                        let address = if address_length > 0 { stream.peer_addr().ok() } else { None };
                        (size, address)
                    })
                    .map_err(|error| errno(&error)),
                HostSocket::TcpConnecting(_) => Err(-6),
                HostSocket::TcpFailed(code) => Err(*code),
                HostSocket::TcpListener(_) | HostSocket::TcpUnbound | HostSocket::UdpUnbound => Err(-107),
            }.map(|(size, address)| {
                payload.truncate(size);
                let address = address.map(address_bytes).unwrap_or_default();
                (payload, address)
            })
        }
    };
    match result {
        Ok((payload, address)) => {
            let address = if address_length > 0 { &address[..address.len().min(address_length)] } else { &[] };
            reply_static_two(system, buffer, command, &[payload.len() as u32, payload.len() as u32], &payload, address);
        }
        Err(code) => reply_static_two(system, buffer, command, &[code as u32, 0], &[], &[]),
    }
}

fn accept(system: &mut System, buffer: &CommandBuffer, command: u16, id: u32, max_address: u32) {
    let accepted = match system.services.soc.sockets.get_mut(&id) {
        Some(entry) => {
            entry.update();
            if let Some(queued) = entry.accepted.pop_front() {
                Ok(queued)
            } else {
                match &mut entry.socket {
                    HostSocket::TcpListener(listener) => listener.accept().map_err(|error| errno(&error)),
                    _ => Err(-22),
                }
            }
        }
        None => Err(-8),
    };
    match accepted {
        Ok((stream, address)) => {
            let _ = stream.set_nonblocking(true);
            let new_id = system.services.soc.allocate(HostSocket::Tcp(stream));
            let mut bytes = address_bytes(address);
            bytes.truncate(bytes.len().min(max_address as usize));
            reply_static(system, buffer, command, &[new_id], &bytes);
        }
        Err(code) => reply_static(system, buffer, command, &[code as u32], &[]),
    }
}

fn socket_address(entry: &mut SocketEntry, peer: bool) -> Option<SocketAddr> {
    entry.update();
    match &entry.socket {
        HostSocket::Udp { socket, peer: remote } => if peer { *remote } else { socket.local_addr().ok() },
        HostSocket::Tcp(stream) => if peer { stream.peer_addr().ok() } else { stream.local_addr().ok() },
        HostSocket::TcpListener(listener) if !peer => listener.local_addr().ok(),
        _ => None,
    }
}

fn poll_ready(entry: &mut SocketEntry) -> (bool, bool, bool, bool) {
    entry.update();
    match &mut entry.socket {
        HostSocket::Udp { socket, .. } => {
            let mut byte = [0u8; 1];
            let readable = match socket.peek_from(&mut byte) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
                Err(_) => true,
            };
            (readable, true, false, false)
        }
        HostSocket::Tcp(stream) => {
            let mut byte = [0u8; 1];
            let mut hangup = false;
            let readable = match stream.peek(&mut byte) {
                Ok(0) => { hangup = true; true }
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
                Err(_) => true,
            };
            (readable, !hangup, false, hangup)
        }
        HostSocket::TcpListener(listener) => match listener.accept() {
            Ok((stream, address)) => {
                entry.accepted.push_back((stream, address));
                (true, false, false, false)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (false, false, false, false),
            Err(_) => (false, false, true, false),
        },
        HostSocket::TcpConnecting(_) => (false, false, false, false),
        HostSocket::TcpFailed(_) => (false, false, true, true),
        HostSocket::UdpUnbound | HostSocket::TcpUnbound => (false, false, false, false),
    }
}

fn poll(system: &mut System, buffer: &CommandBuffer, command: u16, count: usize, timeout_ms: i32) {
    // CTRPollFD is { u32 fd, u32 events, u32 revents } (12 bytes).
    // Preserve the guest's input fields and return the number of ready fds.
    let count = count.min(256);
    let input = read_static(system, buffer, 0, count.saturating_mul(12));
    let mut descriptors = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * 12;
        if input.len() < at + 12 { break; }
        let id = u32::from_le_bytes(input[at..at + 4].try_into().unwrap());
        let events = u32::from_le_bytes(input[at + 4..at + 8].try_into().unwrap());
        descriptors.push((id, events));
    }

    let started = std::time::Instant::now();
    // The HLE syscall runs on the emulation thread, unlike the asynchronous
    // scheduler used by the hardware/other emulators. Return in short slices
    // for an infinite guest poll so the title can retry without freezing the
    // entire emulator if its network peer has disappeared.
    let timeout = Some(if timeout_ms < 0 {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(timeout_ms as u64)
    });
    let mut output = vec![0; descriptors.len() * 12];
    let ready_count = loop {
        let mut ready_count = 0u32;
        for (index, (id, events)) in descriptors.iter().copied().enumerate() {
            let at = index * 12;
            let mut ready = 0u32;
            // libctru normalizes every negative guest fd to -1 and poll
            // ignores it. The fd field is a signed int carried as u32.
            if id == u32::MAX {
                output[at..at + 4].copy_from_slice(&id.to_le_bytes());
                output[at + 4..at + 8].copy_from_slice(&events.to_le_bytes());
                output[at + 8..at + 12].copy_from_slice(&0u32.to_le_bytes());
                continue;
            }
            if let Some(entry) = system.services.soc.sockets.get_mut(&id) {
                let (readable, writable, error, hangup) = poll_ready(entry);
                if readable && events & POLLIN != 0 { ready |= POLLIN; }
                if writable && events & POLLOUT != 0 { ready |= POLLOUT; }
                if error { ready |= POLLERR; }
                if hangup { ready |= POLLHUP; }
            } else {
                ready |= POLLNVAL;
            }
            if ready != 0 { ready_count += 1; }
            output[at..at + 4].copy_from_slice(&id.to_le_bytes());
            output[at + 4..at + 8].copy_from_slice(&events.to_le_bytes());
            output[at + 8..at + 12].copy_from_slice(&ready.to_le_bytes());
        }

        if ready_count != 0 || timeout_ms == 0 {
            break ready_count;
        }
        if timeout.is_some_and(|limit| started.elapsed() >= limit) {
            break 0;
        }
        // A 1 ms sleep avoids burning a CPU core while a guest NEX socket
        // waits for a server ACK or a peer packet. A negative timeout follows
        // POSIX poll semantics and waits until an fd becomes ready.
        thread::sleep(Duration::from_millis(1));
    };
    reply_static(system, buffer, command, &[ready_count], &output);
}

fn host_by_name(name: &str) -> (i32, Vec<u8>) {
    let mut data = vec![0; 0x1A88];
    data[0..2].copy_from_slice(&2u16.to_le_bytes());
    data[2..4].copy_from_slice(&4u16.to_le_bytes());
    if name.is_empty() { return (-305, data); }
    let mut addresses = Vec::new();
    if let Ok(iter) = (name, 0u16).to_socket_addrs() {
        for address in iter {
            if let SocketAddr::V4(address) = address {
                if !addresses.contains(address.ip()) { addresses.push(*address.ip()); }
            }
        }
    }
    if addresses.is_empty() { return (-305, data); }
    data[4..6].copy_from_slice(&(addresses.len().min(24) as u16).to_le_bytes());
    let hostname = name.as_bytes();
    let host_length = hostname.len().min(255);
    data[8..8 + host_length].copy_from_slice(&hostname[..host_length]);
    let start = 8 + 256 + 24 * 256;
    for (index, address) in addresses.iter().take(24).enumerate() {
        data[start + index * 16..start + index * 16 + 4].copy_from_slice(&address.octets());
    }
    (0, data)
}

fn get_addr_info(system: &mut System, buffer: &CommandBuffer, command: u16) {
    let node_length = buffer.get(&mut system.memory, 1) as usize;
    let service_length = buffer.get(&mut system.memory, 2) as usize;
    let hints_length = buffer.get(&mut system.memory, 3) as usize;
    let output_size = (buffer.get(&mut system.memory, 4) as usize).min(0x10000);
    let node = c_string(read_static(system, buffer, 0, node_length.min(256)));
    let node_for_dns = rewrite_network_hostname(&node, system.config.network_provider);
    let service = c_string(read_static(system, buffer, 1, service_length.min(32)));
    let hints = read_static(system, buffer, 2, hints_length.min(0x130));
    let port = service.parse::<u16>().unwrap_or(0);
    let socktype = if hints.len() >= 12 { u32::from_le_bytes(hints[8..12].try_into().unwrap()) } else { 0 };
    let protocol = if hints.len() >= 16 { u32::from_le_bytes(hints[12..16].try_into().unwrap()) } else { 0 };
    let resolved = if node.is_empty() {
        ("0.0.0.0", port).to_socket_addrs()
    } else {
        (node_for_dns.as_str(), port).to_socket_addrs()
    };
    let mut output = Vec::new();
    let mut count = 0u32;
    let error = match resolved {
        Ok(addresses) => {
            for address in addresses {
                let SocketAddr::V4(address) = address else { continue };
                let mut info = vec![0; 0x130];
                info[4..8].copy_from_slice(&AF_INET.to_le_bytes());
                let resolved_type = if socktype != 0 { socktype } else if protocol == IPPROTO_TCP { SOCK_STREAM } else { SOCK_DGRAM };
                let resolved_protocol = if protocol != 0 { protocol } else if resolved_type == SOCK_STREAM { IPPROTO_TCP } else { IPPROTO_UDP };
                info[8..12].copy_from_slice(&resolved_type.to_le_bytes());
                info[12..16].copy_from_slice(&resolved_protocol.to_le_bytes());
                info[16..20].copy_from_slice(&8i32.to_le_bytes());
                info[276..304].copy_from_slice(&address_bytes(SocketAddr::V4(address)));
                if output.len() + info.len() <= output_size { output.extend_from_slice(&info); }
                count += 1;
            }
            if count == 0 { -305 } else { 0 }
        }
        Err(error) => -match error.kind() {
            io::ErrorKind::OutOfMemory => 304,
            io::ErrorKind::Interrupted => 302,
            _ => 305,
        },
    };
    reply_static(system, buffer, command, &[error as u32, count], &output);
}

fn get_name_info(system: &mut System, buffer: &CommandBuffer, command: u16) {
    let host_length = buffer.get(&mut system.memory, 2) as usize;
    let service_length = buffer.get(&mut system.memory, 3) as usize;
    let bytes = read_static(system, buffer, 0, 28);
    let parsed = parse_address(&bytes);
    let (host, service, error) = match parsed {
        Ok(SocketAddr::V4(address)) => (address.ip().to_string(), address.port().to_string(), 0),
        _ => (String::new(), String::new(), -22),
    };
    let mut host_bytes = vec![0; host_length.min(256)];
    let mut service_bytes = vec![0; service_length.min(32)];
    let h = host.as_bytes();
    let s = service.as_bytes();
    let hlen = h.len().min(host_bytes.len().saturating_sub(1));
    let slen = s.len().min(service_bytes.len().saturating_sub(1));
    host_bytes[..hlen].copy_from_slice(&h[..hlen]);
    service_bytes[..slen].copy_from_slice(&s[..slen]);
    reply_static_two(system, buffer, command, &[error as u32], &host_bytes, &service_bytes);
}

fn get_sock_opt(entry: Option<&mut SocketEntry>, _level: u32, option: u32, length: usize) -> (i32, Vec<u8>) {
    let Some(entry) = entry else { return (-8, Vec::new()) };
    entry.update();
    let value: i32 = match option {
        0x1008 => match entry.socket { HostSocket::Udp { .. } | HostSocket::UdpUnbound => SOCK_DGRAM as i32, _ => SOCK_STREAM as i32 },
        0x1009 => match entry.socket { HostSocket::TcpFailed(code) => -code, _ => 0 },
        _ => 0,
    };
    let bytes = value.to_le_bytes();
    (0, bytes[..bytes.len().min(length)].to_vec())
}

fn set_sock_opt(entry: Option<&mut SocketEntry>, level: u32, option: u32, value: &[u8]) -> i32 {
    let Some(entry) = entry else { return -8 };
    entry.update();
    if level == 0xFFFF && option == 0x0004 { return 0; } // SO_REUSEADDR
    if level == 0xFFFF && option == 0x1001 { return 0; } // SO_SNDBUF
    if level == 0xFFFF && option == 0x1002 { return 0; } // SO_RCVBUF
    if level == 0x0006 && option == 0x2001 {
        let enabled = value.first().copied().unwrap_or(0) != 0;
        if let HostSocket::Tcp(stream) = &entry.socket {
            return stream.set_nodelay(enabled).map_or_else(|error| errno(&error), |_| 0);
        }
        return 0;
    }
    0
}

/// Select the host IPv4 address used for outbound Internet traffic.
fn local_interface_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:53").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(address) if !address.ip().is_unspecified() && !address.ip().is_loopback() => {
            Some(*address.ip())
        }
        _ => None,
    }
}

/// Return the actual address, netmask and directed-broadcast address for the
/// interface selected by the host's default Internet route.
#[cfg(unix)]
fn local_interface_info() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    use std::ptr;

    let selected = local_interface_ipv4()?;
    let mut interfaces: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs initializes a linked list, which is released below
    // with freeifaddrs on every successful allocation.
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return None;
    }

    let mut found = None;
    let mut current = interfaces;
    while !current.is_null() {
        // SAFETY: current is a node in the getifaddrs list.
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null()
            && !interface.ifa_netmask.is_null()
            // SAFETY: both pointers have AF_INET family and therefore point
            // to sockaddr_in values.
            && unsafe { (*interface.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            let address = unsafe {
                (*(interface.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr.to_ne_bytes()
            };
            if Ipv4Addr::from(address) == selected {
                let mask = unsafe {
                    (*(interface.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr.to_ne_bytes()
                };
                let broadcast = std::array::from_fn(|index| address[index] | !mask[index]);
                found = Some((selected, Ipv4Addr::from(mask), Ipv4Addr::from(broadcast)));
                break;
            }
        }
        current = interface.ifa_next;
    }

    // SAFETY: interfaces was initialized by a successful getifaddrs call.
    unsafe { libc::freeifaddrs(interfaces) };
    found
}

/// Windows does not expose getifaddrs. Query the adapter selected by the
/// default IPv4 route using the inbox PowerShell networking cmdlets.
#[cfg(windows)]
fn local_interface_info() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    use std::process::Command;

    let address = local_interface_ipv4()?;
    let script = format!(
        "$ip='{}'; $route=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($null -eq $route) {{ exit 2 }}; Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex | Where-Object {{ $_.IPAddress -eq $ip }} | Select-Object -ExpandProperty PrefixLength",
        address
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8_lossy(&output.stdout).trim().parse::<u8>().ok()?;
    ipv4_info_from_prefix(address, prefix)
}

#[cfg(not(any(unix, windows)))]
fn local_interface_info() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    local_interface_ipv4().map(|address| ipv4_info_from_prefix(address, 32))
}

/// Derive a subnet mask and broadcast address from an IPv4 prefix length.
fn ipv4_info_from_prefix(address: Ipv4Addr, prefix: u8) -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    if prefix > 32 {
        return None;
    }
    let address_number = u32::from_be_bytes(address.octets());
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let broadcast = (address_number & mask) | !mask;
    Some((
        address,
        Ipv4Addr::from(mask.to_be_bytes()),
        Ipv4Addr::from(broadcast.to_be_bytes()),
    ))
}

fn parse_mac_address(value: &str) -> Option<[u8; 6]> {
    let hex: String = value.chars().filter(|ch| *ch != ':' && *ch != '-').collect();
    if hex.len() != 12 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut mac = [0u8; 6];
    for (index, slot) in mac.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// NASC and SOCU must report the same hardware address for a Pretendo
/// session; it comes from the user's imported wireless configuration.
fn configured_network_mac(system: &System) -> Option<[u8; 6]> {
    let path = system.config.data_dir.as_ref()?.join("sysdata/nasc.json");
    let bytes = std::fs::read(path).ok()?;
    let config: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let value = config.get("mac_address")?.as_str()?;
    parse_mac_address(value)
}

fn network_option(system: &System, level: u32, option: u32, length: usize) -> Vec<u8> {
    if level != SOC_SOL_CONFIG { return Vec::new(); }
    let mut bytes = vec![0; length.min(256)];
    match option {
        // SOC_CONFIG_MAC_ADDRESS. Derive a stable locally administered MAC
        // from the emulated console ID, so separate emulator instances don't
        // all claim the same hard-coded address.
        0x1004 if bytes.len() >= 6 => {
            let mac = if system.config.network_provider == NetworkProvider::Pretendo {
                configured_network_mac(system)
            } else {
                let id = system.config.console_id.to_be_bytes();
                Some([0x02, id[2], id[3], id[4], id[5], id[6]])
            };
            let Some(mac) = mac else {
                log::warn!("soc:U MAC address is unavailable; Pretendo mode needs a valid mac_address in sysdata/nasc.json");
                return Vec::new();
            };
            bytes[..6].copy_from_slice(&mac);
        }
        // SOC_CONFIG_IP_INFO: [IPv4, netmask, broadcast]. We can determine
        // the selected outbound address portably with std::net, but standard
        // Rust has no portable interface-netmask API. Use a host-route mask
        // instead of inventing a LAN subnet or incorrectly claiming 127/8.
        0x4003 if bytes.len() >= 12 => {
            let Some((address, netmask, broadcast)) = local_interface_info() else { return Vec::new() };
            bytes[0..4].copy_from_slice(&address.octets());
            bytes[4..8].copy_from_slice(&netmask.octets());
            bytes[8..12].copy_from_slice(&broadcast.octets());
        }
        _ => return Vec::new(),
    }
    bytes
}

fn send_other(system: &mut System, buffer: &CommandBuffer, header: Header) {
    let command = header.command_id();
    let id = buffer.get(&mut system.memory, 1);
    let length = buffer.get(&mut system.memory, 2) as usize;
    let address_length = buffer.get(&mut system.memory, 4) as usize;
    let mapped = mapped_buffer(system, buffer, header, 0, length.min(MAX_PACKET));
    let result = match mapped {
        Some((_, pointer, size)) => {
            let mut payload = vec![0; size];
            system.memory.read_bytes(pointer, &mut payload);
            let destination = if address_length > 0 {
                parse_address(&read_static(system, buffer, 1, address_length.min(28))).ok()
            } else {
                None
            };
            send_data(system.services.soc.sockets.get_mut(&id), &payload, destination)
        }
        None => -38,
    };

    match mapped {
        Some((descriptor, pointer, _)) => {
            reply_mapped(system, buffer, command, &[result as u32], descriptor, pointer);
        }
        None => buffer.reply(&mut system.memory, command, &[result as u32]),
    }
}

fn receive_other(system: &mut System, buffer: &CommandBuffer, header: Header) {
    let command = header.command_id();
    let id = buffer.get(&mut system.memory, 1);
    let length = buffer.get(&mut system.memory, 2) as usize;
    let flags = buffer.get(&mut system.memory, 3);
    let address_length = buffer.get(&mut system.memory, 4) as usize;
    let mapped = mapped_buffer(system, buffer, header, 0, length.min(MAX_PACKET));
    let Some((descriptor, pointer, capacity)) = mapped else {
        buffer.reply(&mut system.memory, command, &[(-38i32) as u32]);
        return;
    };

    let result = match system.services.soc.sockets.get_mut(&id) {
        Some(entry) => {
            entry.update();
            let blocking = !entry.nonblocking && flags & 4 == 0;
            let peek = flags & 2 != 0;
            let mut bytes = vec![0; capacity];
            match &mut entry.socket {
                HostSocket::Udp { socket, .. } => recv_udp(socket, &mut bytes, peek, blocking)
                    .map(|(size, address)| {
                        bytes.truncate(size);
                        (bytes, address_bytes(address))
                    })
                    .map_err(|error| errno(&error)),
                HostSocket::Tcp(stream) => recv_tcp(stream, &mut bytes, peek, blocking)
                    .map(|size| {
                        bytes.truncate(size);
                        let address = if address_length > 0 {
                            stream.peer_addr().ok().map(address_bytes).unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        (bytes, address)
                    })
                    .map_err(|error| errno(&error)),
                HostSocket::TcpConnecting(_) => Err(-6),
                HostSocket::TcpFailed(code) => Err(*code),
                _ => Err(-107),
            }
        }
        None => Err(-8),
    };

    match result {
        Ok((bytes, address)) => {
            system.memory.write_bytes(pointer, &bytes);
            let address = &address[..address.len().min(address_length)];
            reply_static_mapped(system, buffer, command, &[bytes.len() as u32], address, descriptor, pointer);
        }
        Err(code) => {
            reply_static_mapped(system, buffer, command, &[code as u32], &[], descriptor, pointer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socu_translation_walker_skips_pid_and_static_buffers() {
        use zakuro_common::memory_map::TLS_IPC_STATIC_BUFFERS;

        let (mut system, buffer) = crate::services::tests::system_with_thread();
        let tls = system.kernel.current().unwrap().tls;
        let static_descriptor = Descriptor::static_buffer(0x20, 0);
        let static_pointer: u32 = 0x0800_1000;
        let mapped_descriptor = (0x30 << 4) | 0xC;
        let mapped_pointer = 0x0800_2000;
        system.memory.write_bytes(tls + TLS_IPC_STATIC_BUFFERS, &static_descriptor.to_le_bytes());
        system.memory.write_bytes(tls + TLS_IPC_STATIC_BUFFERS + 4, &static_pointer.to_le_bytes());

        let header = Header::new(0x0002, 2, 6);
        buffer.set(&mut system.memory, 3, 0x20);
        buffer.set(&mut system.memory, 4, 0x1234);
        buffer.set(&mut system.memory, 5, static_descriptor);
        buffer.set(&mut system.memory, 6, static_pointer);
        buffer.set(&mut system.memory, 7, mapped_descriptor);
        buffer.set(&mut system.memory, 8, mapped_pointer);

        assert_eq!(
            translated_buffer(&mut system, &buffer, header, false, 0),
            Some((static_descriptor, static_pointer, 0x20))
        );
        assert_eq!(
            mapped_buffer(&mut system, &buffer, header, 0, 0x40),
            Some((mapped_descriptor, mapped_pointer, 0x30))
        );
    }

    #[test]
    fn mac_address_parser_accepts_colon_and_compact_formats() {
        assert_eq!(parse_mac_address("02:11:22:33:44:55"), Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(parse_mac_address("021122334455"), Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(parse_mac_address("02:11:22:33:44"), None);
    }

    #[test]
    fn poll_event_masks_match_libctru_ctr_values() {
        assert_eq!(POLLIN, 0x01);
        assert_eq!(POLLPRI, 0x02);
        assert_eq!(POLLHUP, 0x04);
        assert_eq!(POLLERR, 0x08);
        assert_eq!(POLLOUT, 0x10);
        assert_eq!(POLLNVAL, 0x20);
    }

    #[test]
    fn interface_network_info_uses_prefix_length() {
        let (address, mask, broadcast) = ipv4_info_from_prefix(Ipv4Addr::new(192, 168, 1, 64), 26).unwrap();
        assert_eq!(address, Ipv4Addr::new(192, 168, 1, 64));
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 192));
        assert_eq!(broadcast, Ipv4Addr::new(192, 168, 1, 127));
        assert!(ipv4_info_from_prefix(address, 33).is_none());
    }

    #[test]
    fn ctr_ipv4_sockaddr_round_trips_network_byte_order() {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 24873));
        let encoded = address_bytes(address);
        assert_eq!(encoded[0], 8);
        assert_eq!(encoded[1], 2);
        assert_eq!(parse_address(&encoded).unwrap(), address);
    }

    #[test]
    fn pretendo_host_rewrite_matches_the_documented_3ds_domains() {
        assert_eq!(
            rewrite_network_hostname("nasc.test.nintendowifi.net", NetworkProvider::Pretendo),
            "nasc.pretendo.cc"
        );
        assert_eq!(
            rewrite_network_hostname("nncs1.app.nintendowifi.net", NetworkProvider::Pretendo),
            "nncs1.app.pretendo.cc"
        );
        assert_eq!(
            rewrite_network_hostname("account.nintendo.net", NetworkProvider::Pretendo),
            "account.pretendo.cc"
        );
        assert_eq!(
            rewrite_network_hostname("api.pokemon-gl.com", NetworkProvider::Pretendo),
            "api.pretendo.cc"
        );
        assert_eq!(
            rewrite_network_hostname("example.com", NetworkProvider::Pretendo),
            "example.com"
        );
        assert_eq!(
            rewrite_network_hostname("nasc.test.nintendowifi.net", NetworkProvider::Off),
            "nasc.test.nintendowifi.net"
        );
    }

    #[test]
    fn pretendo_url_rewrite_preserves_port_path_and_query() {
        assert_eq!(
            rewrite_network_url("https://account.nintendo.net:443/v1/api/?a=1", NetworkProvider::Pretendo),
            "https://account.pretendo.cc:443/v1/api/?a=1"
        );
        assert_eq!(
            rewrite_network_url("https://example.com/path", NetworkProvider::Pretendo),
            "https://example.com/path"
        );
    }

    /// a UDP socket connected to the NEX station must still accept peer
    /// datagrams from other source addresses for race traffic.
    #[test]
    fn udp_default_peer_does_not_filter_peer_to_peer_race_packets() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket_address = socket.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let server_address = server.local_addr().unwrap();

        let mut entry = SocketEntry::new(HostSocket::Udp {
            socket,
            peer: Some(server_address),
        });
        assert_eq!(send_data(Some(&mut entry), b"nex station", None), 11);
        let mut received = [0u8; 32];
        let started = std::time::Instant::now();
        let server_size = loop {
            match server.recv_from(&mut received) {
                Ok((size, _)) => break size,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("NEX destination did not receive UDP datagram: {error}"),
            }
        };
        assert_eq!(&received[..server_size], b"nex station");

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"race peer", socket_address).unwrap();
        let HostSocket::Udp { socket, .. } = &mut entry.socket else {
            panic!("expected UDP socket");
        };
        let started = std::time::Instant::now();
        let (peer_size, peer_address) = loop {
            match socket.recv_from(&mut received) {
                Ok(received) => break received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("UDP socket filtered peer traffic: {error}"),
            }
        };
        assert_eq!(&received[..peer_size], b"race peer");
        assert_eq!(peer_address, peer.local_addr().unwrap());
    }

    #[test]
    fn blocking_udp_receive_waits_for_a_peer_packet() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(15));
            sender.send_to(b"prudp", destination).unwrap();
        });
        let mut bytes = [0u8; 16];
        let (size, _) = recv_udp(&receiver, &mut bytes, false, true).unwrap();
        worker.join().unwrap();
        assert_eq!(&bytes[..size], b"prudp");
    }

    #[test]
    fn nonblocking_udp_receive_returns_would_block_without_waiting() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut bytes = [0u8; 8];
        let error = recv_udp(&receiver, &mut bytes, false, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn host_errno_translation_matches_soc_errno_numbers() {
        assert_eq!(errno(&io::Error::from(io::ErrorKind::WouldBlock)), -6);
        assert_eq!(errno(&io::Error::from(io::ErrorKind::ConnectionRefused)), -14);
        assert_eq!(errno(&io::Error::from(io::ErrorKind::TimedOut)), -76);
    }
}
