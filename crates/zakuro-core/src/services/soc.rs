//! Host-backed SOCU sockets for the game's native NEX/PRUDP client.
//! Host sockets are runtime-only and are discarded when a save state is loaded.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::System;

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const O_NONBLOCK: u32 = 4;
const SOCKADDR_SIZE: usize = 8;
const ADDRINFO_SIZE: usize = 0x130;
const HOST_BY_NAME_SIZE: usize = 0x1A88;
const IO_TIMEOUT: Duration = Duration::from_millis(100);

enum Socket {
    Unbound { kind: u32, local: Option<SocketAddr> },
    Udp(UdpSocket),
    Tcp(TcpStream),
    Listener(TcpListener),
}

struct SocketEntry {
    socket: Socket,
    blocking: bool,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct SocState {
    initialized: bool,
    next_handle: u32,
    #[serde(skip, default)]
    sockets: HashMap<u32, SocketEntry>,
}

impl SocState {
    fn allocate(&mut self) -> u32 {
        if self.next_handle < 3 { self.next_handle = 3; }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(3);
        handle
    }
}

fn errno(error: &io::Error) -> i32 {
    use io::ErrorKind::*;
    -match error.kind() {
        WouldBlock | TimedOut => 11,
        AddrInUse => 98,
        AddrNotAvailable => 99,
        ConnectionAborted => 103,
        ConnectionRefused => 111,
        ConnectionReset => 104,
        NotConnected => 107,
        InvalidInput | InvalidData => 22,
        PermissionDenied => 13,
        Unsupported => 95,
        _ => 5,
    }
}

fn reply(system: &mut System, buffer: &CommandBuffer, command: u16, values: &[u32]) {
    buffer.reply(&mut system.memory, command, values);
}

fn reply_ret(system: &mut System, buffer: &CommandBuffer, command: u16, ret: i32) {
    reply(system, buffer, command, &[ret as u32]);
}

/// Reads a translated inline static/mapped buffer (descriptor followed by pointer).
fn inline_buffer(system: &mut System, buffer: &CommandBuffer, descriptor_index: u32, length: usize) -> Vec<u8> {
    let descriptor = Descriptor::parse(buffer.get(&mut system.memory, descriptor_index));
    let pointer = buffer.get(&mut system.memory, descriptor_index + 1);
    let capacity = match descriptor {
        Descriptor::StaticBuffer { size, .. } | Descriptor::MappedBuffer { size, .. } => size as usize,
        _ => 0,
    };
    let length = length.min(capacity);
    let mut bytes = vec![0; length];
    if pointer != 0 && length > 0 { system.memory.read_bytes(pointer, &mut bytes); }
    bytes
}

fn tls_read(system: &mut System, buffer: &CommandBuffer, tls: u32, id: u32, length: usize) -> (u32, usize) {
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, id);
    (pointer, length.min(capacity as usize))
}

fn tls_write(system: &mut System, buffer: &CommandBuffer, tls: u32, id: u32, bytes: &[u8]) -> (u32, u32) {
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, id);
    let length = bytes.len().min(capacity as usize);
    if pointer != 0 && length > 0 { system.memory.write_bytes(pointer, &bytes[..length]); }
    (pointer, length as u32)
}

fn decode_address(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < SOCKADDR_SIZE || bytes[0] as usize != SOCKADDR_SIZE || bytes[1] != AF_INET as u8 {
        return None;
    }
    Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
    )))
}

fn encode_address(address: SocketAddr) -> Option<[u8; SOCKADDR_SIZE]> {
    let SocketAddr::V4(address) = address else { return None };
    let mut bytes = [0u8; SOCKADDR_SIZE];
    bytes[0] = SOCKADDR_SIZE as u8;
    bytes[1] = AF_INET as u8;
    bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
    bytes[4..8].copy_from_slice(&address.ip().octets());
    Some(bytes)
}

/// Hostname suffix redirects used by Nimbus for Nintendo Network services.
pub fn redirect_pretendo_host(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    for suffix in ["nintendowifi.net", "nintendo.net", "pokemon-gl.com"] {
        if host == suffix { return "pretendo.cc".to_owned(); }
        if let Some(prefix) = host.strip_suffix(&format!(".{suffix}")) {
            return format!("{prefix}.pretendo.cc");
        }
    }
    host
}

pub fn redirect_pretendo_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_owned() };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let (user, host_port) = authority.rsplit_once('@').map_or(("", authority), |(u, h)| (u, h));
    if host_port.starts_with('[') { return url.to_owned(); }
    let (host, port) = host_port.rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok()).unwrap_or((host_port, ""));
    let host = redirect_pretendo_host(host);
    let authority = if port.is_empty() { format!("{user}{host}") } else { format!("{user}{host}:{port}") };
    format!("{scheme}://{authority}{}", &rest[end..])
}

fn port_number(service: Option<&str>) -> Option<u16> {
    match service.unwrap_or("0") {
        "http" => Some(80),
        "https" => Some(443),
        "domain" => Some(53),
        number => number.parse().ok(),
    }
}

fn new_udp(address: SocketAddr, blocking: bool) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(address)?;
    socket.set_nonblocking(!blocking)?;
    if blocking {
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    Ok(socket)
}

fn new_tcp(address: SocketAddr, blocking: bool) -> io::Result<TcpStream> {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(!blocking)?;
    if blocking {
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    Ok(socket)
}

fn set_blocking(entry: &mut SocketEntry, blocking: bool) -> io::Result<()> {
    match &entry.socket {
        Socket::Udp(socket) => {
            socket.set_nonblocking(!blocking)?;
            if blocking {
                socket.set_read_timeout(Some(IO_TIMEOUT))?;
                socket.set_write_timeout(Some(IO_TIMEOUT))?;
            }
        }
        Socket::Tcp(socket) => {
            socket.set_nonblocking(!blocking)?;
            if blocking {
                socket.set_read_timeout(Some(IO_TIMEOUT))?;
                socket.set_write_timeout(Some(IO_TIMEOUT))?;
            }
        }
        Socket::Listener(socket) => socket.set_nonblocking(true)?,
        Socket::Unbound { .. } => {}
    }
    entry.blocking = blocking;
    Ok(())
}

fn socket_type(entry: &SocketEntry) -> u32 {
    match &entry.socket {
        Socket::Unbound { kind, .. } => *kind,
        Socket::Udp(_) => SOCK_DGRAM,
        Socket::Tcp(_) | Socket::Listener(_) => SOCK_STREAM,
    }
}

fn socket_address(entry: &SocketEntry, peer: bool) -> io::Result<SocketAddr> {
    match &entry.socket {
        Socket::Udp(socket) => if peer { socket.peer_addr() } else { socket.local_addr() },
        Socket::Tcp(socket) => if peer { socket.peer_addr() } else { socket.local_addr() },
        Socket::Listener(socket) => {
            if peer { Err(io::Error::from(io::ErrorKind::NotConnected)) } else { socket.local_addr() }
        }
        Socket::Unbound { .. } => Err(io::Error::from(io::ErrorKind::NotConnected)),
    }
}

fn reply_socket_address(system: &mut System, buffer: &CommandBuffer, tls: u32, command: u16, peer: bool) {
    let id = buffer.get(&mut system.memory, 1);
    let result = system.services.soc.sockets.get(&id)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
        .and_then(|entry| socket_address(entry, peer));
    let (bytes, ret) = match result {
        Ok(address) => match encode_address(address) {
            Some(bytes) => (bytes.to_vec(), 0),
            None => (Vec::new(), -97),
        },
        Err(error) => (Vec::new(), errno(&error)),
    };
    let (pointer, size) = tls_write(system, buffer, tls, 0, &bytes);
    buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    buffer.set(&mut system.memory, 2, ret as u32);
    buffer.set(&mut system.memory, 3, Descriptor::static_buffer(size, 0));
    buffer.set(&mut system.memory, 4, pointer);
}

fn get_addr_info(system: &mut System, buffer: &CommandBuffer, tls: u32, command: u16) {
    let node_len = buffer.get(&mut system.memory, 1) as usize;
    let service_len = buffer.get(&mut system.memory, 2) as usize;
    let hints_len = buffer.get(&mut system.memory, 3) as usize;
    let output_len = buffer.get(&mut system.memory, 4) as usize;
    let node_data = inline_buffer(system, buffer, 5, node_len);
    let service_data = inline_buffer(system, buffer, 7, service_len);
    let hints = inline_buffer(system, buffer, 9, hints_len);
    let (output_pointer, output_capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    let c_string = |bytes: &[u8]| {
        let bytes = bytes.split(|byte| *byte == 0).next().unwrap_or_default();
        if bytes.is_empty() { None } else { Some(String::from_utf8_lossy(bytes).into_owned()) }
    };
    let node = c_string(&node_data).map(|host| redirect_pretendo_host(&host));
    let service = c_string(&service_data);
    let flags = hints.get(0..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
    let family = hints.get(4..8).map_or(AF_INET as i32, |b| i32::from_le_bytes(b.try_into().unwrap()));
    let sock_type = hints.get(8..12).map_or(0, |b| i32::from_le_bytes(b.try_into().unwrap()));
    let protocol = hints.get(12..16).map_or(0, |b| i32::from_le_bytes(b.try_into().unwrap()));
    let mut records = Vec::new();
    let mut error = 0i32;

    if family != 0 && family != AF_INET as i32 {
        error = -6;
    } else if let Some(port) = port_number(service.as_deref()) {
        let host = node.as_deref().unwrap_or(if flags & 1 != 0 { "0.0.0.0" } else { "127.0.0.1" });
        match (host, port).to_socket_addrs() {
            Ok(addresses) => {
                for address in addresses {
                    let SocketAddr::V4(address) = address else { continue };
                    let mut record = [0u8; ADDRINFO_SIZE];
                    record[0..4].copy_from_slice(&flags.to_le_bytes());
                    record[4..8].copy_from_slice(&(AF_INET as i32).to_le_bytes());
                    let kind = if sock_type == SOCK_STREAM as i32 || sock_type == SOCK_DGRAM as i32 {
                        sock_type
                    } else if protocol == 6 { SOCK_STREAM as i32 } else { SOCK_DGRAM as i32 };
                    let proto = if protocol == 6 || protocol == 17 {
                        protocol
                    } else if kind == SOCK_STREAM as i32 { 6 } else { 17 };
                    record[8..12].copy_from_slice(&kind.to_le_bytes());
                    record[12..16].copy_from_slice(&proto.to_le_bytes());
                    record[16..20].copy_from_slice(&(SOCKADDR_SIZE as i32).to_le_bytes());
                    if flags & 2 != 0 {
                        let count = host.len().min(255);
                        record[20..20 + count].copy_from_slice(&host.as_bytes()[..count]);
                    }
                    if let Some(address) = encode_address(SocketAddr::V4(address)) {
                        record[276..284].copy_from_slice(&address);
                        records.push(record);
                    }
                }
                if records.is_empty() { error = -2; }
            }
            Err(_) => error = -2,
        }
    } else {
        error = -2;
    }

    let count = records.len();
    let capacity = output_len.min(output_capacity as usize);
    let mut written = 0usize;
    for record in records {
        if written + ADDRINFO_SIZE > capacity { break; }
        system.memory.write_bytes(output_pointer + written as u32, &record);
        written += ADDRINFO_SIZE;
    }
    buffer.set(&mut system.memory, 0, Header::new(command, 3, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    buffer.set(&mut system.memory, 2, error as u32);
    buffer.set(&mut system.memory, 3, count as u32);
    buffer.set(&mut system.memory, 4, Descriptor::static_buffer(capacity as u32, 0));
    buffer.set(&mut system.memory, 5, output_pointer);
}

fn get_host_by_name(system: &mut System, buffer: &CommandBuffer, command: u16) {
    let name_len = buffer.get(&mut system.memory, 1) as usize;
    let _output_len = buffer.get(&mut system.memory, 2);
    let name_data = inline_buffer(system, buffer, 3, name_len);
    let name = name_data.split(|byte| *byte == 0).next().unwrap_or_default();
    let host = redirect_pretendo_host(&String::from_utf8_lossy(name));
    let mut output = vec![0u8; HOST_BY_NAME_SIZE];
    let mut error = -2i32;

    if let Ok(addresses) = (host.as_str(), 0).to_socket_addrs() {
        let mut count = 0usize;
        for address in addresses {
            let SocketAddr::V4(address) = address else { continue };
            let start = 8 + 256 + (24 * 256) + count * 16;
            output[start..start + 4].copy_from_slice(&address.ip().octets());
            count += 1;
            if count == 24 { break; }
        }
        if count > 0 {
            output[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
            output[2..4].copy_from_slice(&4u16.to_le_bytes());
            output[4..6].copy_from_slice(&(count as u16).to_le_bytes());
            output[6..8].copy_from_slice(&0u16.to_le_bytes());
            let length = host.len().min(255);
            output[8..8 + length].copy_from_slice(&host.as_bytes()[..length]);
            error = 0;
        }
    }
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (pointer, size) = tls_write(system, buffer, tls, 0, if error == 0 { &output } else { &[] });
    buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    buffer.set(&mut system.memory, 2, error as u32);
    buffer.set(&mut system.memory, 3, Descriptor::static_buffer(size, 0));
    buffer.set(&mut system.memory, 4, pointer);
}

fn get_network_option(system: &mut System, buffer: &CommandBuffer, tls: u32, command: u16) {
    let level = buffer.get(&mut system.memory, 1);
    let option = buffer.get(&mut system.memory, 2);
    let requested = buffer.get(&mut system.memory, 3) as usize;
    let (pointer, capacity) = tls_read(system, buffer, tls, 0, requested);
    let mut output = vec![0u8; capacity];
    let mut error = -22i32;

    if level == 0xFFFE {
        match option {
            0x1004 => {
                if output.len() >= 6 {
                    output[..6].copy_from_slice(&system.config.console_id.to_le_bytes()[..6]);
                }
                error = 0;
            }
            0x4003 => {
                if output.len() >= 12 {
                    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                        .and_then(|socket| { socket.connect(("8.8.8.8", 53))?; socket.local_addr() });
                    if let Ok(SocketAddr::V4(address)) = route {
                        let octets = address.ip().octets();
                        output[0..4].copy_from_slice(&u32::from_ne_bytes(octets).to_ne_bytes());
                        output[4..8].copy_from_slice(&u32::from_ne_bytes([255,255,255,0]).to_ne_bytes());
                        output[8..12].copy_from_slice(&u32::from_ne_bytes([octets[0],octets[1],octets[2],255]).to_ne_bytes());
                    }
                }
                error = 0;
            }
            0x4004 => {
                if output.len() >= 4 { output[..4].copy_from_slice(&1500u32.to_ne_bytes()); }
                error = 0;
            }
            0xB003 => error = 0,
            _ => {}
        }
    }
    if pointer != 0 && !output.is_empty() { system.memory.write_bytes(pointer, &output); }
    buffer.set(&mut system.memory, 0, Header::new(command, 3, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    buffer.set(&mut system.memory, 2, error as u32);
    buffer.set(&mut system.memory, 3, output.len() as u32);
    buffer.set(&mut system.memory, 4, Descriptor::static_buffer(output.len() as u32, 0));
    buffer.set(&mut system.memory, 5, pointer);
}

fn reply_recv(
    system: &mut System,
    buffer: &CommandBuffer,
    command: u16,
    tls: u32,
    bytes: &[u8],
    source: Option<SocketAddr>,
    ret: i32,
) {
    let (data_pointer, data_size) = tls_write(system, buffer, tls, 0, bytes);
    let address_bytes = source.and_then(encode_address).unwrap_or([0; SOCKADDR_SIZE]);
    let address_data: &[u8] = if source.is_some() { &address_bytes } else { &[] };
    let (address_pointer, address_size) = tls_write(system, buffer, tls, 1, address_data);
    buffer.set(&mut system.memory, 0, Header::new(command, 3, 4).0);
    buffer.set(&mut system.memory, 1, 0);
    buffer.set(&mut system.memory, 2, ret as u32);
    buffer.set(&mut system.memory, 3, data_size);
    buffer.set(&mut system.memory, 4, Descriptor::static_buffer(data_size, 0));
    buffer.set(&mut system.memory, 5, data_pointer);
    buffer.set(&mut system.memory, 6, Descriptor::static_buffer(address_size, 1));
    buffer.set(&mut system.memory, 7, address_pointer);
}

fn poll_ready(entry: &mut SocketEntry, events: u32) -> u32 {
    let mut ready = 0;
    if events & 1 != 0 {
        let readable = match &mut entry.socket {
            Socket::Udp(socket) => { let mut byte = [0u8; 1]; socket.peek_from(&mut byte).is_ok() }
            Socket::Tcp(socket) => { let mut byte = [0u8; 1]; socket.peek(&mut byte).is_ok() }
            Socket::Listener(_) | Socket::Unbound { .. } => false,
        };
        if readable { ready |= 1; }
    }
    if events & 0x18 != 0 && !matches!(&entry.socket, Socket::Unbound { .. }) {
        ready |= events & 0x18;
    }
    ready
}

pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    if !system.config.pretendo_network { return false; }
    let Some(tls) = system.kernel.current().map(|thread| thread.tls) else { return false };
    let command = header.command_id();

    match command {
        0x0001 => {
            system.services.soc.initialized = true;
            reply(system, buffer, command, &[]);
        }
        0x0002 => {
            let domain = buffer.get(&mut system.memory, 1);
            let kind = buffer.get(&mut system.memory, 2);
            let protocol = buffer.get(&mut system.memory, 3);
            let ret = if !system.services.soc.initialized { -55 }
                else if domain != AF_INET || !matches!(kind, SOCK_STREAM | SOCK_DGRAM)
                    || !matches!(protocol, 0 | 6 | 17)
                    || (kind == SOCK_STREAM && protocol == 17)
                    || (kind == SOCK_DGRAM && protocol == 6) { -97 }
                else {
                    let id = system.services.soc.allocate();
                    system.services.soc.sockets.insert(id, SocketEntry {
                        socket: Socket::Unbound { kind, local: None }, blocking: true
                    });
                    id as i32
                };
            reply_ret(system, buffer, command, ret);
        }
        0x0003 => {
            let id = buffer.get(&mut system.memory, 1);
            let ret = match system.services.soc.sockets.get_mut(&id) {
                None => -9,
                Some(entry) => {
                    let old = std::mem::replace(&mut entry.socket, Socket::Unbound { kind: SOCK_STREAM, local: None });
                    match old {
                        Socket::Unbound { kind: SOCK_STREAM, local } => {
                            let address = local.unwrap_or(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                            match TcpListener::bind(address).and_then(|listener| { listener.set_nonblocking(true)?; Ok(listener) }) {
                                Ok(listener) => { entry.socket = Socket::Listener(listener); 0 }
                                Err(error) => { entry.socket = Socket::Unbound { kind: SOCK_STREAM, local }; errno(&error) }
                            }
                        }
                        other => { entry.socket = other; -22 }
                    }
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x0004 => {
            let id = buffer.get(&mut system.memory, 1);
            let max_address = buffer.get(&mut system.memory, 2) as usize;
            let accepted = {
                match system.services.soc.sockets.get(&id) {
                    None => Err(-9),
                    Some(entry) => match &entry.socket {
                        Socket::Listener(listener) => listener.accept().map_err(|error| errno(&error)),
                        _ => Err(-22),
                    }
                }
            };
            let (ret, address) = match accepted {
                Ok((stream, address)) => {
                    let result = stream.set_nonblocking(true).and_then(|_| stream.set_nodelay(true));
                    match result {
                        Ok(()) => {
                            let socket_id = system.services.soc.allocate();
                            system.services.soc.sockets.insert(socket_id, SocketEntry {
                                socket: Socket::Tcp(stream), blocking: true
                            });
                            (socket_id as i32, Some(address))
                        }
                        Err(error) => (errno(&error), None)
                    }
                }
                Err(error) => (error, None)
            };
            let address_bytes = address.and_then(encode_address).unwrap_or([0; SOCKADDR_SIZE]);
            let bytes: &[u8] = if address.is_some() { &address_bytes[..max_address.min(SOCKADDR_SIZE)] } else { &[] };
            let (pointer, size) = tls_write(system, buffer, tls, 0, bytes);
            buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ret as u32);
            buffer.set(&mut system.memory, 3, Descriptor::static_buffer(size, 0));
            buffer.set(&mut system.memory, 4, pointer);
        }
        0x0005 => {
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let address = decode_address(&inline_buffer(system, buffer, 4, length));
            let ret = match (address, system.services.soc.sockets.get_mut(&id)) {
                (Some(address), Some(entry)) => {
                    let kind = match &entry.socket { Socket::Unbound { kind, .. } => Some(*kind), _ => None };
                    match kind {
                        Some(SOCK_DGRAM) => match new_udp(address, entry.blocking) {
                            Ok(socket) => { entry.socket = Socket::Udp(socket); 0 }
                            Err(error) => errno(&error)
                        },
                        Some(SOCK_STREAM) => {
                            entry.socket = Socket::Unbound { kind: SOCK_STREAM, local: Some(address) };
                            0
                        }
                        _ => -22
                    }
                }
                (None, _) => -22,
                (_, None) => -9
            };
            reply_ret(system, buffer, command, ret);
        }
        0x0006 => {
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let address = decode_address(&inline_buffer(system, buffer, 4, length));
            let ret = match address {
                None => -22,
                Some(address) => match system.services.soc.sockets.get_mut(&id) {
                    None => -9,
                    Some(entry) => {
                        let old = std::mem::replace(&mut entry.socket, Socket::Unbound { kind: SOCK_DGRAM, local: None });
                        match old {
                            Socket::Unbound { kind: SOCK_DGRAM, local } => {
                                let bind_address = local.unwrap_or(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                                match new_udp(bind_address, entry.blocking).and_then(|socket| { socket.connect(address)?; Ok(socket) }) {
                                    Ok(socket) => { entry.socket = Socket::Udp(socket); 0 }
                                    Err(error) => { entry.socket = Socket::Unbound { kind: SOCK_DGRAM, local }; errno(&error) }
                                }
                            }
                            Socket::Unbound { kind: SOCK_STREAM, .. } => match new_tcp(address, entry.blocking) {
                                Ok(socket) => { entry.socket = Socket::Tcp(socket); 0 }
                                Err(error) => { entry.socket = Socket::Unbound { kind: SOCK_STREAM, local: None }; errno(&error) }
                            }
                            other => { entry.socket = other; -106 }
                        }
                    }
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x0007 => {
            // recvfrom using a mapped output buffer. This is the large-buffer
            // variant used by libctru when a packet does not fit a small IPC
            // static buffer.
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let flags = buffer.get(&mut system.memory, 3);
            let address_length = buffer.get(&mut system.memory, 4) as usize;
            let descriptor = buffer.get(&mut system.memory, 6);
            let pointer = buffer.get(&mut system.memory, 7);
            let capacity = match Descriptor::parse(descriptor) {
                Descriptor::MappedBuffer { size, .. } => size as usize,
                _ => 0,
            };
            let mut bytes = vec![0; length.min(capacity).min(65_507)];
            let received = match system.services.soc.sockets.get_mut(&id) {
                None => Err(-9),
                Some(entry) => match &mut entry.socket {
                    Socket::Udp(socket) => {
                        let result = if flags & 2 != 0 { socket.peek_from(&mut bytes) } else { socket.recv_from(&mut bytes) };
                        result.map(|(count, address)| (count, Some(address))).map_err(|error| errno(&error))
                    }
                    Socket::Tcp(socket) => {
                        let result = if flags & 2 != 0 { socket.peek(&mut bytes) } else { socket.read(&mut bytes) };
                        result.map(|count| (count, socket.peer_addr().ok())).map_err(|error| errno(&error))
                    }
                    _ => Err(-107),
                },
            };
            let (ret, source) = match received {
                Ok((count, source)) => {
                    bytes.truncate(count);
                    (count as i32, if address_length > 0 { source } else { None })
                }
                Err(error) => {
                    bytes.clear();
                    (error, None)
                }
            };
            if pointer != 0 && !bytes.is_empty() {
                system.memory.write_bytes(pointer, &bytes);
            }
            let source_bytes = source.and_then(encode_address).unwrap_or([0; SOCKADDR_SIZE]);
            let source_data: &[u8] = if source.is_some() { &source_bytes } else { &[] };
            let (address_pointer, address_size) = tls_write(system, buffer, tls, 1, source_data);
            buffer.set(&mut system.memory, 0, Header::new(command, 3, 4).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ret as u32);
            buffer.set(&mut system.memory, 3, bytes.len() as u32);
            buffer.set(&mut system.memory, 4, descriptor);
            buffer.set(&mut system.memory, 5, pointer);
            buffer.set(&mut system.memory, 6, Descriptor::static_buffer(address_size, 1));
            buffer.set(&mut system.memory, 7, address_pointer);
        }
        0x0008 => {
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let flags = buffer.get(&mut system.memory, 3);
            let address_length = buffer.get(&mut system.memory, 4) as usize;
            let (_, capacity) = tls_read(system, buffer, tls, 0, length);
            let mut bytes = vec![0; length.min(capacity).min(65_507)];
            let received = match system.services.soc.sockets.get_mut(&id) {
                None => Err(-9),
                Some(entry) => match &mut entry.socket {
                    Socket::Udp(socket) => {
                        let result = if flags & 2 != 0 { socket.peek_from(&mut bytes) } else { socket.recv_from(&mut bytes) };
                        result.map(|(count, address)| (count, Some(address))).map_err(|error| errno(&error))
                    }
                    Socket::Tcp(socket) => {
                        let result = if flags & 2 != 0 { socket.peek(&mut bytes) } else { socket.read(&mut bytes) };
                        result.map(|count| (count, socket.peer_addr().ok())).map_err(|error| errno(&error))
                    }
                    _ => Err(-107)
                }
            };
            match received {
                Ok((count, address)) => {
                    bytes.truncate(count);
                    reply_recv(system, buffer, command, tls, &bytes, if address_length > 0 { address } else { None }, count as i32);
                }
                Err(error) => reply_recv(system, buffer, command, tls, &[], None, error)
            }
        }
        0x0009 => {
            // sendto using a mapped input buffer, the large-buffer counterpart
            // of SendToSingle.
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let address_length = buffer.get(&mut system.memory, 4) as usize;
            let destination = inline_buffer(system, buffer, 6, address_length);
            let descriptor = buffer.get(&mut system.memory, 8);
            let pointer = buffer.get(&mut system.memory, 9);
            let capacity = match Descriptor::parse(descriptor) {
                Descriptor::MappedBuffer { size, .. } => size as usize,
                _ => 0,
            };
            let mut payload = vec![0; length.min(capacity)];
            if pointer != 0 && !payload.is_empty() {
                system.memory.read_bytes(pointer, &mut payload);
            }
            let ret = if payload.len() != length {
                -90
            } else {
                match system.services.soc.sockets.get_mut(&id) {
                    None => -9,
                    Some(entry) => match &mut entry.socket {
                        Socket::Udp(socket) => if address_length > 0 {
                            decode_address(&destination).map_or(-22, |address| socket.send_to(&payload, address).map(|count| count as i32).unwrap_or_else(|error| errno(&error)))
                        } else {
                            socket.send(&payload).map(|count| count as i32).unwrap_or_else(|error| errno(&error))
                        },
                        Socket::Tcp(socket) => if address_length > 0 { -89 } else {
                            socket.write(&payload).map(|count| count as i32).unwrap_or_else(|error| errno(&error))
                        },
                        _ => -107,
                    },
                }
            };
            buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ret as u32);
            buffer.set(&mut system.memory, 3, descriptor);
            buffer.set(&mut system.memory, 4, pointer);
        }
        0x000A => {
            let id = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let address_length = buffer.get(&mut system.memory, 4) as usize;
            let payload = inline_buffer(system, buffer, 6, length);
            let address = inline_buffer(system, buffer, 8, address_length);
            let ret = if payload.len() != length { -90 } else {
                match system.services.soc.sockets.get_mut(&id) {
                    None => -9,
                    Some(entry) => match &mut entry.socket {
                        Socket::Udp(socket) => if address_length > 0 {
                            decode_address(&address).map_or(-22, |address| socket.send_to(&payload, address).map(|count| count as i32).unwrap_or_else(|error| errno(&error)))
                        } else {
                            socket.send(&payload).map(|count| count as i32).unwrap_or_else(|error| errno(&error))
                        },
                        Socket::Tcp(socket) => if address_length > 0 { -89 } else {
                            socket.write(&payload).map(|count| count as i32).unwrap_or_else(|error| errno(&error))
                        },
                        _ => -107
                    }
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x000B => {
            let id = buffer.get(&mut system.memory, 1);
            reply_ret(system, buffer, command, if system.services.soc.sockets.remove(&id).is_some() { 0 } else { -9 });
        }
        0x000C => {
            let id = buffer.get(&mut system.memory, 1);
            let how = buffer.get(&mut system.memory, 2);
            let ret = match system.services.soc.sockets.get(&id) {
                None => -9,
                Some(entry) => match &entry.socket {
                    Socket::Tcp(socket) => socket.shutdown(match how {
                        0 => std::net::Shutdown::Read,
                        1 => std::net::Shutdown::Write,
                        _ => std::net::Shutdown::Both
                    }).map_or_else(|error| errno(&error), |_| 0),
                    _ => 0
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x000D => get_host_by_name(system, buffer, command),
        0x000F => get_addr_info(system, buffer, tls, command),
        0x0011 => {
            let id = buffer.get(&mut system.memory, 1);
            let option = buffer.get(&mut system.memory, 3);
            let length = buffer.get(&mut system.memory, 4) as usize;
            let (_, capacity) = tls_read(system, buffer, tls, 0, length);
            let mut value = vec![0; capacity];
            let ret = match system.services.soc.sockets.get(&id) {
                None => -9,
                Some(entry) => {
                    let option_value = match option {
                        0x1008 => Some(socket_type(entry) as i32),
                        0x1009 => Some(0i32),
                        0x2001 => match &entry.socket { Socket::Tcp(socket) => Some(socket.nodelay().unwrap_or(false) as i32), _ => Some(0i32) },
                        _ => None
                    };
                    if let Some(option_value) = option_value {
                        if value.len() >= 4 { value[..4].copy_from_slice(&(option_value as u32).to_le_bytes()); }
                        0
                    } else { -92 }
                }
            };
            let (pointer, size) = tls_write(system, buffer, tls, 0, &value);
            buffer.set(&mut system.memory, 0, Header::new(command, 3, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ret as u32);
            buffer.set(&mut system.memory, 3, size);
            buffer.set(&mut system.memory, 4, Descriptor::static_buffer(size, 0));
            buffer.set(&mut system.memory, 5, pointer);
        }
        0x0012 => {
            let id = buffer.get(&mut system.memory, 1);
            let option = buffer.get(&mut system.memory, 3);
            let length = buffer.get(&mut system.memory, 4) as usize;
            let value = inline_buffer(system, buffer, 6, length);
            let enabled = value.first().copied().unwrap_or(0) != 0;
            let ret = match system.services.soc.sockets.get_mut(&id) {
                None => -9,
                Some(entry) => match (&mut entry.socket, option) {
                    (Socket::Tcp(socket), 0x2001) => socket.set_nodelay(enabled).map_or_else(|error| errno(&error), |_| 0),
                    (Socket::Udp(socket), 0x0008) => {
                        let ttl = value.get(0..4).map_or(64, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
                        socket.set_ttl(ttl).map_or_else(|error| errno(&error), |_| 0)
                    }
                    (_, 0x0004 | 0x0080 | 0x0100 | 0x1001 | 0x1002) => 0,
                    _ => -92
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x0013 => {
            let id = buffer.get(&mut system.memory, 1);
            let operation = buffer.get(&mut system.memory, 2);
            let argument = buffer.get(&mut system.memory, 3);
            let ret = match system.services.soc.sockets.get_mut(&id) {
                None => -9,
                Some(entry) => match operation {
                    3 => if entry.blocking { 0 } else { O_NONBLOCK as i32 },
                    4 => set_blocking(entry, argument & O_NONBLOCK == 0).map_or_else(|error| errno(&error), |_| 0),
                    _ => -22
                }
            };
            reply_ret(system, buffer, command, ret);
        }
        0x0014 => {
            let count = buffer.get(&mut system.memory, 1) as usize;
            let timeout = buffer.get(&mut system.memory, 2) as i32;
            let mut poll_fds = inline_buffer(system, buffer, 4, count.saturating_mul(12));
            let item_count = poll_fds.len() / 12;
            let mut ready = 0i32;
            for _ in 0..2 {
                ready = 0;
                for index in 0..item_count {
                    let offset = index * 12;
                    let id = u32::from_le_bytes(poll_fds[offset..offset+4].try_into().unwrap());
                    let events = u32::from_le_bytes(poll_fds[offset+4..offset+8].try_into().unwrap());
                    let result = if id == u32::MAX { 0 } else {
                        system.services.soc.sockets.get_mut(&id).map_or(0x20, |entry| poll_ready(entry, events))
                    };
                    poll_fds[offset+8..offset+12].copy_from_slice(&result.to_le_bytes());
                    if result != 0 { ready += 1; }
                }
                if ready > 0 || timeout <= 0 { break; }
                std::thread::sleep(Duration::from_millis((timeout as u64).min(10)));
            }
            let (pointer, size) = tls_write(system, buffer, tls, 0, &poll_fds);
            buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ready as u32);
            buffer.set(&mut system.memory, 3, Descriptor::static_buffer(size, 0));
            buffer.set(&mut system.memory, 4, pointer);
        }
        0x0010 => {
            // Return numeric host and service strings when reverse DNS is not
            // available; this keeps getnameinfo useful for NEX diagnostics.
            let address_length = buffer.get(&mut system.memory, 1) as usize;
            let host_length = buffer.get(&mut system.memory, 2) as usize;
            let service_length = buffer.get(&mut system.memory, 3) as usize;
            let _flags = buffer.get(&mut system.memory, 4);
            let address = decode_address(&inline_buffer(system, buffer, 5, address_length));
            let (host, service, ret) = match address {
                Some(SocketAddr::V4(address)) => (address.ip().to_string(), address.port().to_string(), 0),
                None => (String::new(), String::new(), -22),
            };
            let mut host_bytes = host.into_bytes();
            let mut service_bytes = service.into_bytes();
            host_bytes.push(0);
            service_bytes.push(0);
            host_bytes.truncate(host_length);
            service_bytes.truncate(service_length);
            let (host_pointer, host_size) = tls_write(system, buffer, tls, 0, &host_bytes);
            let (service_pointer, service_size) = tls_write(system, buffer, tls, 1, &service_bytes);
            buffer.set(&mut system.memory, 0, Header::new(command, 2, 4).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, ret as u32);
            buffer.set(&mut system.memory, 3, Descriptor::static_buffer(host_size, 0));
            buffer.set(&mut system.memory, 4, host_pointer);
            buffer.set(&mut system.memory, 5, Descriptor::static_buffer(service_size, 1));
            buffer.set(&mut system.memory, 6, service_pointer);
        }
        0x0015 => {
            // SockAtMark: stream sockets do not expose an urgent-data mark.
            reply_ret(system, buffer, command, 0);
        }
        0x0016 => {
            let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .and_then(|socket| { socket.connect(("8.8.8.8", 53))?; socket.local_addr() });
            let ret = match route { Ok(SocketAddr::V4(address)) => u32::from_ne_bytes(address.ip().octets()) as i32, _ => 0 };
            reply_ret(system, buffer, command, ret);
        }
        0x0017 => reply_socket_address(system, buffer, tls, command, false),
        0x0018 => reply_socket_address(system, buffer, tls, command, true),
        0x0019 | 0x0021 => {
            system.services.soc.sockets.clear();
            if command == 0x0019 { system.services.soc.initialized = false; }
            reply(system, buffer, command, &[]);
        }
        0x001A => get_network_option(system, buffer, tls, command),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretendo_host_redirects_only_nintendo_network_domains() {
        assert_eq!(redirect_pretendo_host("nasc.nintendowifi.net"), "nasc.pretendo.cc");
        assert_eq!(redirect_pretendo_host("account.nintendo.net"), "account.pretendo.cc");
        assert_eq!(redirect_pretendo_host("nncs1.app.nintendowifi.net"), "nncs1.app.pretendo.cc");
        assert_eq!(redirect_pretendo_host("example.com"), "example.com");
    }

    #[test]
    fn url_redirect_keeps_scheme_port_path_and_query() {
        assert_eq!(
            redirect_pretendo_url("https://account.nintendo.net:443/v1/token?x=1"),
            "https://account.pretendo.cc:443/v1/token?x=1"
        );
    }

    #[test]
    fn ipv4_socket_address_round_trips() {
        let address = "203.0.113.42:6007".parse::<SocketAddr>().unwrap();
        let encoded = encode_address(address).unwrap();
        assert_eq!(encoded, [8, 2, 0x17, 0x77, 203, 0, 113, 42]);
        assert_eq!(decode_address(&encoded), Some(address));
    }
}
