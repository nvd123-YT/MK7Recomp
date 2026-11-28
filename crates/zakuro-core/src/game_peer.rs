//! Direct PRUDP Game-stream transport for MK7 peer-to-peer race sessions.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    decode_prudp_v0, encode_prudp_v0, PrudpPacket, Rc4, Station,
    MK7_PRUDP_ACCESS_KEY, STREAM_TYPE_GAME,
};
use crate::prudp_client::{connection_signature, establish_session, new_payload_ciphers, PrudpSession};

const LOCAL_VIRTUAL_PORT: u8 = 1;

const PIA_NAT_PROBE_REQUEST: u8 = 0;
const PIA_NAT_PROBE_REPLY: u8 = 1;

/// PIA NAT probe datagram, with the variable ID appended on PIA 5.11+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiaNatProbeData {
    pub service_variable_id: u32,
    pub probe_type: u8,
    pub system_time: u64,
    pub variable_id: Option<u32>,
}

pub fn encode_pia_nat_probe_data(data: PiaNatProbeData) -> Result<Vec<u8>, String> {
    if !matches!(data.probe_type, PIA_NAT_PROBE_REQUEST | PIA_NAT_PROBE_REPLY | 0xFF) {
        return Err("PIA NAT probe has an unsupported probe type".to_owned());
    }
    let mut output = Vec::with_capacity(if data.variable_id.is_some() { 20 } else { 16 });
    output.extend_from_slice(&data.service_variable_id.to_be_bytes());
    output.push(data.probe_type);
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&data.system_time.to_be_bytes());
    if let Some(variable_id) = data.variable_id {
        output.extend_from_slice(&variable_id.to_be_bytes());
    }
    Ok(output)
}

pub fn decode_pia_nat_probe_data(bytes: &[u8]) -> Result<PiaNatProbeData, String> {
    if bytes.len() != 16 && bytes.len() != 20 {
        return Err(format!("PIA NAT probe datagram has invalid size {}", bytes.len()));
    }
    let service_variable_id = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let probe_type = bytes[4];
    if !matches!(probe_type, PIA_NAT_PROBE_REQUEST | PIA_NAT_PROBE_REPLY | 0xFF) {
        return Err(format!("PIA NAT probe type {probe_type} is invalid"));
    }
    if bytes[5..8] != [0; 3] {
        return Err("PIA NAT probe reserved padding is not zero".to_owned());
    }
    let system_time = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let variable_id = if bytes.len() == 20 {
        Some(u32::from_be_bytes(bytes[16..20].try_into().unwrap()))
    } else {
        None
    };
    Ok(PiaNatProbeData { service_variable_id, probe_type, system_time, variable_id })
}

pub const PIA_NAT_PROTOCOL_TYPE: u16 = 0x0400;
pub const PIA_PACKET_MAGIC: u32 = 0x6498_AB32;
pub const PIA_STATION_INDEX_UNIDENTIFIED: u8 = 253;
pub const PIA_MESSAGE_FLAG_DESTINATION_IS_CONSTANT_ID: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiaNatDatagram {
    pub probe: PiaNatProbeData,
    pub protocol_port: u16,
    pub source_pid: u32,
    pub destination_pid: u32,
    pub source_timer: u16,
    pub destination_timer: u16,
}

/// Wrap NatProbeData in the legacy PIA common-packet and protocol-message headers.
///
/// For a not-yet-connected station, the common packet uses connection ID 0,
/// packet ID 0, the unencrypted state, and an unidentified source station index.
/// The protocol message is addressed by the peer's Constant ID (NEX PID).
pub fn encode_pia_nat_datagram(
    data: PiaNatProbeData,
    pia_511_plus: bool,
    source_pid: u32,
    destination_pid: u32,
    source_timer: u16,
    destination_timer: u16,
) -> Result<Vec<u8>, String> {
    if source_pid == 0 || destination_pid == 0 {
        return Err("PIA NAT datagrams require non-zero source and destination PIDs".to_owned());
    }
    if pia_511_plus != data.variable_id.is_some() {
        return Err("PIA NatProbeData variable-ID format does not match the selected PIA version".to_owned());
    }
    let port = if pia_511_plus {
        0u16
    } else {
        match data.probe_type {
            PIA_NAT_PROBE_REQUEST => 1,
            PIA_NAT_PROBE_REPLY => 2,
            0xFF => 3,
            _ => return Err("PIA NAT probe type is invalid".to_owned()),
        }
    };
    let body = encode_pia_nat_probe_data(data)?;
    let mut packet = Vec::with_capacity(12 + 20 + body.len());

    // PIA common::Packet header. The magic is stored in its native wire order.
    packet.extend_from_slice(&PIA_PACKET_MAGIC.to_le_bytes());
    packet.push(1); // packet is not encrypted
    packet.push(0); // no established PIA station connection yet
    packet.extend_from_slice(&0u16.to_be_bytes()); // packet ID
    packet.extend_from_slice(&source_timer.to_be_bytes());
    packet.extend_from_slice(&destination_timer.to_be_bytes());

    // transport::ProtocolMessage header. NAT probes are addressed to a PID.
    packet.push(PIA_MESSAGE_FLAG_DESTINATION_IS_CONSTANT_ID);
    packet.push(PIA_STATION_INDEX_UNIDENTIFIED);
    packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
    packet.extend_from_slice(&destination_pid.to_be_bytes());
    packet.extend_from_slice(&source_pid.to_be_bytes());
    packet.extend_from_slice(&PIA_NAT_PROTOCOL_TYPE.to_be_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // reserved
    packet.extend_from_slice(&body);
    while packet.len() % 4 != 0 {
        packet.push(0);
    }
    Ok(packet)
}

/// Decode and validate one complete PIA NAT-traversal datagram.
pub fn decode_pia_nat_datagram(
    packet: &[u8],
    pia_511_plus: bool,
) -> Result<PiaNatDatagram, String> {
    if packet.len() < 48 {
        return Err(format!("PIA packet is shorter than its headers and probe body: {}", packet.len()));
    }
    if packet[0..4] != PIA_PACKET_MAGIC.to_le_bytes() || packet[4] != 1 {
        return Err("PIA common-packet magic or encryption state is invalid".to_owned());
    }
    if packet[5] != 0 || u16::from_be_bytes(packet[6..8].try_into().unwrap()) != 0 {
        return Err("unconnected PIA NAT packet must use connection ID and packet ID zero".to_owned());
    }
    let source_timer = u16::from_be_bytes(packet[8..10].try_into().unwrap());
    let destination_timer = u16::from_be_bytes(packet[10..12].try_into().unwrap());

    if packet[12] != PIA_MESSAGE_FLAG_DESTINATION_IS_CONSTANT_ID
        || packet[13] != PIA_STATION_INDEX_UNIDENTIFIED
    {
        return Err("PIA NAT message must be PID-addressed from an unidentified station".to_owned());
    }
    let payload_size = u16::from_be_bytes(packet[14..16].try_into().unwrap()) as usize;
    let destination_pid = u32::from_be_bytes(packet[16..20].try_into().unwrap());
    let source_pid = u32::from_be_bytes(packet[20..24].try_into().unwrap());
    let protocol_type = u16::from_be_bytes(packet[24..26].try_into().unwrap());
    let protocol_port = u16::from_be_bytes(packet[26..28].try_into().unwrap());
    let reserved = u32::from_be_bytes(packet[28..32].try_into().unwrap());
    if source_pid == 0 || destination_pid == 0 || reserved != 0 {
        return Err("PIA NAT message has invalid PIDs or reserved field".to_owned());
    }
    if protocol_type != PIA_NAT_PROTOCOL_TYPE {
        return Err("PIA packet is not a NAT traversal message".to_owned());
    }
    let padded_size = (payload_size + 3) & !3;
    if packet.len() != 32 + padded_size {
        return Err("PIA message payload size does not match datagram length".to_owned());
    }
    if packet[32 + payload_size..].iter().any(|byte| *byte != 0) {
        return Err("PIA message padding must be zero".to_owned());
    }
    let probe = decode_pia_nat_probe_data(&packet[32..32 + payload_size])?;
    if pia_511_plus {
        if protocol_port != 0 || probe.variable_id.is_none() {
            return Err("PIA 5.11+ NAT packet requires protocol port 0 and a variable ID".to_owned());
        }
    } else {
        if probe.variable_id.is_some() {
            return Err("legacy PIA NAT packet cannot contain a variable ID".to_owned());
        }
        let expected_port = match probe.probe_type {
            PIA_NAT_PROBE_REQUEST => 1,
            PIA_NAT_PROBE_REPLY => 2,
            0xFF => 3,
            _ => return Err("legacy PIA NAT probe type is invalid".to_owned()),
        };
        if protocol_port != expected_port {
            return Err("legacy PIA NAT probe type does not match protocol port".to_owned());
        }
    }
    Ok(PiaNatDatagram {
        probe,
        protocol_port,
        source_pid,
        destination_pid,
        source_timer,
        destination_timer,
    })
}

/// Bidirectionally punch through NAT using the same UDP socket later used for
/// the Game-stream PRUDP handshake. include_variable_id selects the PIA
/// 5.11+ 20-byte form; the legacy form is 16 bytes.
pub fn punch_through_nat(
    socket: &UdpSocket,
    local_station: &Station,
    peer_station: &Station,
    timeout: Duration,
    include_variable_id: bool,
) -> Result<Duration, String> {
    if timeout.is_zero() {
        return Err("PIA NAT probe timeout must be greater than zero".to_owned());
    }
    if local_station.stream_type != STREAM_TYPE_GAME || peer_station.stream_type != STREAM_TYPE_GAME {
        return Err("PIA NAT probe requires two Game-stream StationURLs".to_owned());
    }
    if local_station.rv_connection_id == 0 || peer_station.rv_connection_id == 0 {
        return Err("PIA NAT probe requires RVCID on both StationURLs".to_owned());
    }
    if local_station.principal_id == 0 || peer_station.principal_id == 0 {
        return Err("PIA NAT probe requires non-zero PIDs on both StationURLs".to_owned());
    }
    if include_variable_id && (local_station.connection_id == 0 || peer_station.connection_id == 0) {
        return Err("PIA 5.11+ NAT probe requires CID on both StationURLs".to_owned());
    }
    let peer = (peer_station.address.as_str(), peer_station.port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve PIA peer {}: {error}", peer_station.address))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(address),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("PIA peer {} did not resolve to IPv4", peer_station.address))?;
    let previous_timeout = socket.read_timeout()
        .map_err(|error| format!("could not read PIA UDP socket timeout: {error}"))?;
    let started = std::time::Instant::now();
    let deadline = started + timeout;
    let system_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_nanos() as u64;
    let mut got_peer_request = false;
    let mut got_reply = false;
    let mut last_sent: Option<std::time::Instant> = None;
    let result = (|| {
        let mut buffer = [0u8; 256];
        while std::time::Instant::now() < deadline {
            let now = std::time::Instant::now();
            if last_sent.map_or(true, |last| now.duration_since(last) >= Duration::from_millis(200)) {
                let request = encode_pia_nat_datagram(
                    PiaNatProbeData {
                        service_variable_id: peer_station.rv_connection_id,
                        probe_type: PIA_NAT_PROBE_REQUEST,
                        system_time,
                        variable_id: if include_variable_id { Some(peer_station.connection_id) } else { None },
                    },
                    include_variable_id,
                    local_station.principal_id,
                    peer_station.principal_id,
                    started.elapsed().as_millis() as u16,
                    0,
                )?;
                socket.send_to(&request, peer)
                    .map_err(|error| format!("could not send PIA NAT probe: {error}"))?;
                last_sent = Some(now);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            socket.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))
                .map_err(|error| format!("could not set PIA NAT probe timeout: {error}"))?;
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    if source != SocketAddr::V4(peer) { continue; }
                    let datagram = match decode_pia_nat_datagram(&buffer[..length], include_variable_id) {
                        Ok(datagram) => datagram,
                        Err(_) => continue,
                    };
                    if datagram.source_pid != peer_station.principal_id
                        || datagram.destination_pid != local_station.principal_id
                    {
                        continue;
                    }
                    let probe = datagram.probe;
                    let addressed_to_us = probe.service_variable_id == local_station.rv_connection_id
                        && (!include_variable_id || probe.variable_id == Some(local_station.connection_id));
                    if !addressed_to_us { continue; }
                    match probe.probe_type {
                        PIA_NAT_PROBE_REQUEST => {
                            got_peer_request = true;
                            let reply = encode_pia_nat_datagram(
                                PiaNatProbeData {
                                    service_variable_id: peer_station.rv_connection_id,
                                    probe_type: PIA_NAT_PROBE_REPLY,
                                    system_time: probe.system_time,
                                    variable_id: if include_variable_id { Some(peer_station.connection_id) } else { None },
                                },
                                include_variable_id,
                                local_station.principal_id,
                                peer_station.principal_id,
                                started.elapsed().as_millis() as u16,
                                datagram.source_timer,
                            )?;
                            socket.send_to(&reply, source)
                                .map_err(|error| format!("could not send PIA NAT probe reply: {error}"))?;
                        }
                        PIA_NAT_PROBE_REPLY if probe.system_time == system_time => got_reply = true,
                        _ => {},
                    }
                    if got_peer_request && got_reply { return Ok(started.elapsed()); }
                }
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {},
                Err(error) => return Err(format!("could not receive PIA NAT probe: {error}")),
            }
        }
        Err(format!("PIA NAT hole punch timed out (peer request received: {got_peer_request}, reply received: {got_reply})"))
    })();
    let restore = socket.set_read_timeout(previous_timeout);
    match (result, restore) {
        (Ok(rtt), Ok(())) => Ok(rtt),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(format!("PIA NAT probe succeeded but socket timeout could not be restored: {error}")),
    }
}


/// A direct peer connection on MK7's Game stream (PRUDP stream type 9).
///
/// The P2P link is separate from the authenticated secure Rendez-Vous
/// connection. MK7's 3DS Game stream uses the default CD&ML RC4 payload key
/// and an empty PRUDP session-key input; it does not use a gathering key.
pub struct GamePeerSession {
    socket: UdpSocket,
    server: SocketAddrV4,
    session: PrudpSession,
    outgoing_cipher: Rc4,
    incoming_cipher: Rc4,
}

/// Connect directly to a peer's Game-stream StationURL.
///
/// The StationURL must advertise stream type 9 and a valid IPv4-resolvable
/// address. Relay/NAT fallback is not yet attempted here; if a direct UDP path
/// cannot be established, the caller gets the underlying transport error.
pub fn connect_to_peer(
    station: &Station,
    timeout: Duration,
) -> Result<GamePeerSession, String> {
    if station.stream_type != STREAM_TYPE_GAME {
        return Err(format!(
            "peer StationURL uses stream type {}, expected Game stream type {}",
            station.stream_type, STREAM_TYPE_GAME
        ));
    }
    if station.port == 0 || station.stream_id > 15 {
        return Err("peer StationURL has an invalid port or stream ID".to_owned());
    }

    let endpoint = (station.address.as_str(), station.port);
    let server = endpoint
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve peer station {}: {error}", station.address))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(address),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("peer station {} did not resolve to IPv4", station.address))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("could not bind peer Game-stream UDP socket: {error}"))?;
    connect_to_peer_with_socket(socket, station, server, timeout)
}

/// Connect using an already-bound UDP socket. Use this when the socket's public
/// mapping has been advertised by NEX and both peers must punch simultaneously.
pub fn connect_to_peer_with_socket(
    socket: UdpSocket,
    station: &Station,
    server: SocketAddrV4,
    timeout: Duration,
) -> Result<GamePeerSession, String> {
    if station.stream_type != STREAM_TYPE_GAME {
        return Err("peer station is not a Game stream".to_owned());
    }
    let session = establish_session(
        &socket,
        server,
        station.stream_type,
        LOCAL_VIRTUAL_PORT,
        station.stream_id,
        &[],
        timeout,
    )?;
    let (outgoing_cipher, incoming_cipher) = new_payload_ciphers(&[])?;

    Ok(GamePeerSession {
        socket,
        server,
        session,
        outgoing_cipher,
        incoming_cipher,
    })
}


/// Accept an incoming peer connection on an already-bound Game-stream UDP socket.
///
/// advertised_address must be the IPv4 address and mapped port published in
/// the host's StationURL (for example, the mapping found by the NEX/NAT layer).
/// It can differ from socket.local_addr() when the host is behind NAT.
///
/// The host side responds to the remote player's SYN and CONNECT packets,
/// then returns a normal bidirectional GamePeerSession. Use this for the host
/// role; the joining peer uses connect_to_peer().
pub fn accept_peer(
    socket: UdpSocket,
    advertised_address: SocketAddrV4,
    timeout: Duration,
) -> Result<(GamePeerSession, SocketAddrV4), String> {
    if advertised_address.port() == 0 || advertised_address.ip().is_unspecified() {
        return Err("peer Game-stream advertised address must be a concrete IPv4 endpoint".to_owned());
    }
    if timeout.is_zero() {
        return Err("peer Game-stream handshake timeout must be greater than zero".to_owned());
    }

    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("could not configure peer Game-stream timeout: {error}"))?;
    let mut bytes = [0u8; 65_535];
    let (length, peer) = socket
        .recv_from(&mut bytes)
        .map_err(|error| format!("could not receive peer Game-stream SYN: {error}"))?;
    let peer = match peer {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => return Err("peer Game-stream client must use IPv4".to_owned()),
    };
    let syn = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[])
        .map_err(|error| format!("could not decode peer Game-stream SYN: {error}"))?;
    if syn.packet_type != 0
        || syn.flags & 0x04 == 0
        || syn.flags & 0x01 != 0
        || syn.session_id != 0
        || syn.packet_id != 0
        || syn.fragment_id != 0
        || syn.source_type != STREAM_TYPE_GAME
        || syn.destination_type != STREAM_TYPE_GAME
        || !syn.payload.is_empty()
    {
        return Err("peer sent an invalid Game-stream SYN packet".to_owned());
    }

    let peer_signature = connection_signature(peer);
    // This must be the externally advertised mapping used in the host's
    // StationURL, not necessarily the socket's private bind address.
    let server_signature = connection_signature(advertised_address);
    let syn_ack = PrudpPacket {
        packet_type: 0,
        flags: 0x01 | 0x08,
        source_type: syn.destination_type,
        source_port: syn.destination_port,
        destination_type: syn.source_type,
        destination_port: syn.source_port,
        session_id: 0,
        packet_id: 0,
        fragment_id: 0,
        signature: [0; 4],
        connection_signature: peer_signature,
        payload: Vec::new(),
    };
    socket
        .send_to(
            &encode_prudp_v0(&syn_ack, MK7_PRUDP_ACCESS_KEY, &[]),
            peer,
        )
        .map_err(|error| format!("could not send peer Game-stream SYN acknowledgement: {error}"))?;

    let (length, connect_peer) = socket
        .recv_from(&mut bytes)
        .map_err(|error| format!("could not receive peer Game-stream CONNECT: {error}"))?;
    if connect_peer != SocketAddr::V4(peer) {
        return Err("Game-stream CONNECT arrived from a different peer than the SYN".to_owned());
    }
    let connect = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[])
        .map_err(|error| format!("could not decode peer Game-stream CONNECT: {error}"))?;
    if connect.packet_type != 1
        || connect.flags & (0x01 | 0x02 | 0x04 | 0x08) != (0x02 | 0x04 | 0x08)
        || connect.packet_id != 1
        || connect.fragment_id != 0
        || connect.source_type != syn.source_type
        || connect.destination_type != syn.destination_type
        || connect.source_port != syn.source_port
        || connect.destination_port != syn.destination_port
        || connect.signature != peer_signature
        || connect.connection_signature != server_signature
        || !connect.payload.is_empty()
    {
        return Err("peer sent an invalid Game-stream CONNECT packet".to_owned());
    }

    let connect_ack = PrudpPacket {
        packet_type: 1,
        flags: 0x01 | 0x08,
        source_type: connect.destination_type,
        source_port: connect.destination_port,
        destination_type: connect.source_type,
        destination_port: connect.source_port,
        session_id: connect.session_id,
        packet_id: 1,
        fragment_id: 0,
        signature: connect.connection_signature,
        connection_signature: [0; 4],
        payload: Vec::new(),
    };
    socket
        .send_to(
            &encode_prudp_v0(&connect_ack, MK7_PRUDP_ACCESS_KEY, &[]),
            peer,
        )
        .map_err(|error| format!("could not send peer Game-stream CONNECT acknowledgement: {error}"))?;

    let (outgoing_cipher, incoming_cipher) = new_payload_ciphers(&[])?;
    let session = PrudpSession {
        client_session_id: connect.session_id,
        server_session_id: connect.session_id,
        server_connection_signature: peer_signature,
        client_connection_signature: server_signature,
        connect_response: Vec::new(),
        source_type: connect.destination_type,
        destination_type: connect.source_type,
        source_port: connect.destination_port,
        destination_port: connect.source_port,
        next_reliable_packet_id: 1,
        pending_server_pushes: Vec::new(),
    };

    Ok((
        GamePeerSession {
            socket,
            server: peer,
            session,
            outgoing_cipher,
            incoming_cipher,
        },
        peer,
    ))
}

impl GamePeerSession {
    /// Exchange a reliable game-protocol payload with the connected host.
    ///
    /// The payload is opaque to NEX. MK7's game code defines the contents;
    /// this method supplies ordered reliable PRUDP delivery, RC4, signatures,
    /// retransmission, and the peer's acknowledgement.
    pub fn exchange_reliable(
        &mut self,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.session.send_reliable_message(
            &self.socket,
            self.server,
            payload,
            &[],
            &mut self.outgoing_cipher,
            &mut self.incoming_cipher,
            timeout,
        )
    }

    /// The peer's Game-stream socket address.
    pub fn peer_address(&self) -> SocketAddrV4 {
        self.server
    }

    /// Whether the local UDP socket and PRUDP session are established.
    pub fn is_connected(&self) -> bool {
        self.socket.local_addr().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nex_bootstrap::{
        decode_prudp_v0, encode_prudp_v0, PrudpPacket, MK7_PRUDP_ACCESS_KEY,
    };
    use crate::prudp_client::connection_signature;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;
    use std::thread;

    const TYPE_SYN: u8 = 0;
    const TYPE_CONNECT: u8 = 1;
    const TYPE_DATA: u8 = 2;
    const FLAG_ACK: u8 = 0x01;
    const FLAG_RELIABLE: u8 = 0x02;
    const FLAG_NEED_ACK: u8 = 0x04;
    const FLAG_HAS_SIZE: u8 = 0x08;

    fn game_station(address: SocketAddrV4) -> Station {
        Station {
            address: address.ip().to_string(),
            port: address.port(),
            stream_id: 1,
            stream_type: STREAM_TYPE_GAME,
            principal_id: 42,
            rv_connection_id: 88,
            raw_url: String::new(),
            connection_id: 77,
        }
    }

    #[test]
    fn pia_nat_probe_data_encodes_legacy_and_modern_forms() {
        let legacy = PiaNatProbeData {
            service_variable_id: 0x0102_0304,
            probe_type: PIA_NAT_PROBE_REQUEST,
            system_time: 0x0102_0304_0506_0708,
            variable_id: None,
        };
        let raw = encode_pia_nat_probe_data(legacy).unwrap();
        assert_eq!(raw.len(), 16);
        assert_eq!(decode_pia_nat_probe_data(&raw).unwrap(), legacy);

        let packet = encode_pia_nat_datagram(legacy, false, 0x1122_3344, 0x5566_7788, 0x1234, 0x5678).unwrap();
        assert_eq!(packet.len(), 48);
        assert_eq!(&packet[..4], &[0x32, 0xAB, 0x98, 0x64]);
        assert_eq!(&packet[4..12], &[1, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(packet[12], PIA_MESSAGE_FLAG_DESTINATION_IS_CONSTANT_ID);
        assert_eq!(packet[13], PIA_STATION_INDEX_UNIDENTIFIED);
        assert_eq!(u16::from_be_bytes(packet[14..16].try_into().unwrap()), 16);
        assert_eq!(&packet[16..20], &0x5566_7788u32.to_be_bytes());
        assert_eq!(&packet[20..24], &0x1122_3344u32.to_be_bytes());
        assert_eq!(&packet[24..28], &[0x04, 0x00, 0x00, 0x01]);
        assert_eq!(&packet[28..32], &[0; 4]);
        assert_eq!(&packet[32..36], &[1, 2, 3, 4]);
        let decoded = decode_pia_nat_datagram(&packet, false).unwrap();
        assert_eq!(decoded.probe, legacy);
        assert_eq!(decoded.protocol_port, 1);
        assert_eq!(decoded.source_pid, 0x1122_3344);
        assert_eq!(decoded.destination_pid, 0x5566_7788);
        assert_eq!(decoded.source_timer, 0x1234);
        assert_eq!(decoded.destination_timer, 0x5678);

        let modern = PiaNatProbeData { variable_id: Some(0xA1B2_C3D4), ..legacy };
        let raw = encode_pia_nat_probe_data(modern).unwrap();
        assert_eq!(raw.len(), 20);
        assert_eq!(decode_pia_nat_probe_data(&raw).unwrap(), modern);
        let packet = encode_pia_nat_datagram(modern, true, 42, 77, 1, 0).unwrap();
        assert_eq!(packet.len(), 52);
        assert_eq!(&packet[24..28], &[0x04, 0x00, 0x00, 0x00]);
        assert_eq!(decode_pia_nat_datagram(&packet, true).unwrap().probe, modern);
        assert!(decode_pia_nat_probe_data(&raw[..15]).is_err());

        let mut invalid = packet.clone();
        invalid[12] = 0x08;
        assert!(decode_pia_nat_datagram(&invalid, true).is_err());
    }

    #[test]
    fn two_peers_complete_bidirectional_pia_nat_probes_on_their_bound_sockets() {
        let a = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let b = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let a_addr = match a.local_addr().unwrap() { SocketAddr::V4(v) => v, _ => unreachable!() };
        let b_addr = match b.local_addr().unwrap() { SocketAddr::V4(v) => v, _ => unreachable!() };
        let a_station = Station { address: a_addr.ip().to_string(), port: a_addr.port(), stream_id: 1, stream_type: STREAM_TYPE_GAME, principal_id: 41, rv_connection_id: 0x1111, raw_url: String::new(), connection_id: 0xAAAA };
        let b_station = Station { address: b_addr.ip().to_string(), port: b_addr.port(), stream_id: 1, stream_type: STREAM_TYPE_GAME, principal_id: 42, rv_connection_id: 0x2222, raw_url: String::new(), connection_id: 0xBBBB };
        let a_station_for_a = a_station.clone();
        let b_station_for_a = b_station.clone();
        let a_station_for_b = a_station.clone();
        let b_station_for_b = b_station.clone();
        let a_thread = thread::spawn(move || punch_through_nat(&a, &a_station_for_a, &b_station_for_a, Duration::from_secs(2), true).unwrap());
        let b_thread = thread::spawn(move || punch_through_nat(&b, &b_station_for_b, &a_station_for_b, Duration::from_secs(2), true).unwrap());
        assert!(a_thread.join().unwrap() < Duration::from_secs(2));
        assert!(b_thread.join().unwrap() < Duration::from_secs(2));
    }
    #[test]
    fn rejects_a_non_game_station() {
        let station = Station {
            address: "127.0.0.1".to_owned(),
            port: 1234,
            stream_id: 1,
            stream_type: 10,
            principal_id: 42,
            rv_connection_id: 77,
            raw_url: String::new(),
            connection_id: 77,
        };
        assert!(connect_to_peer(&station, Duration::from_millis(10))
            .err()
            .unwrap()
            .contains("expected Game stream type"));
    }

    #[test]
    fn game_stream_uses_the_default_cdml_payload_key() {
        let station = Station {
            address: "127.0.0.1".to_owned(),
            port: 1234,
            stream_id: 1,
            stream_type: STREAM_TYPE_GAME,
            principal_id: 42,
            rv_connection_id: 77,
            raw_url: String::new(),
            connection_id: 77,
        };
        let (mut outgoing, mut incoming) = new_payload_ciphers(&[]).unwrap();
        let encrypted = outgoing.apply(b"MK7 PIA peer data");
        assert_eq!(incoming.apply(&encrypted), b"MK7 PIA peer data");
    }

    #[test]
    fn game_stream_host_acceptor_and_joining_client_exchange_data() {
        let listener = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_address = match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game peer listener did not bind IPv4"),
        };
        let station = game_station(host_address);
        // Host receives and answers the joining peer's PRUDP SYN/CONNECT.
        let host_thread = thread::spawn(move || {
            let (mut host, remote) =
                accept_peer(listener, host_address, Duration::from_secs(2)).unwrap();
            assert_eq!(remote.ip(), &Ipv4Addr::LOCALHOST);
            assert!(host.is_connected());
            host.exchange_reliable(b"frame from host", Duration::from_secs(2))
                .unwrap()
        });

        let mut client = connect_to_peer(
            &station,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(client.is_connected());
        let response = client
            .exchange_reliable(b"frame from client", Duration::from_secs(2))
            .unwrap();

        assert_eq!(response, b"frame from host");
        assert_eq!(host_thread.join().unwrap(), b"frame from client");
    }


    #[test]
    fn game_stream_handshake_and_default_cdml_reliable_exchange_work() {
        let server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_address = match server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game peer server did not bind IPv4"),
        };

        let (send, receive) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let mut bytes = [0u8; 65_535];
            let (length, client_address) = server.recv_from(&mut bytes).unwrap();
            let syn = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
            assert_eq!(syn.packet_type, TYPE_SYN);
            assert_eq!(syn.source_type, STREAM_TYPE_GAME);
            assert_eq!(syn.destination_type, STREAM_TYPE_GAME);

            let client_address = match client_address {
                SocketAddr::V4(address) => address,
                _ => panic!("Game peer client did not use IPv4"),
            };
            let syn_ack = PrudpPacket {
                packet_type: TYPE_SYN,
                flags: FLAG_ACK | FLAG_HAS_SIZE,
                source_type: syn.destination_type,
                source_port: syn.destination_port,
                destination_type: syn.source_type,
                destination_port: syn.source_port,
                session_id: 0,
                packet_id: 0,
                fragment_id: 0,
                signature: [0; 4],
                connection_signature: connection_signature(client_address),
                payload: Vec::new(),
            };
            server
                .send_to(
                    &encode_prudp_v0(&syn_ack, MK7_PRUDP_ACCESS_KEY, &[]),
                    client_address,
                )
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let connect = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
            assert_eq!(connect.packet_type, TYPE_CONNECT);
            assert_eq!(connect.source_type, STREAM_TYPE_GAME);
            assert_eq!(connect.destination_type, STREAM_TYPE_GAME);
            assert!(connect.payload.is_empty());

            let peer_signature = connection_signature(client_address);
            let server_signature = connection_signature(server_address);
            assert_eq!(connect.signature, peer_signature);
            assert_eq!(connect.connection_signature, server_signature);
            let connect_ack = PrudpPacket {
                packet_type: TYPE_CONNECT,
                flags: FLAG_ACK | FLAG_HAS_SIZE,
                source_type: connect.destination_type,
                source_port: connect.destination_port,
                destination_type: connect.source_type,
                destination_port: connect.source_port,
                session_id: connect.session_id,
                packet_id: 1,
                fragment_id: 0,
                signature: connect.connection_signature,
                connection_signature: [0; 4],
                payload: Vec::new(),
            };
            server
                .send_to(
                    &encode_prudp_v0(&connect_ack, MK7_PRUDP_ACCESS_KEY, &[]),
                    client_address,
                )
                .unwrap();

            let (length, peer) = server.recv_from(&mut bytes).unwrap();
            assert_eq!(peer, SocketAddr::V4(client_address));
            let request = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                &[],
            )
            .unwrap();
            assert_eq!(request.packet_type, TYPE_DATA);
            assert_eq!(request.source_type, STREAM_TYPE_GAME);
            assert_eq!(request.destination_type, STREAM_TYPE_GAME);
            assert_eq!(request.flags, FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE);
            let mut decrypt = Rc4::new(b"CD&ML").unwrap();
            assert_eq!(decrypt.apply(&request.payload), b"race frame from client");

            let ack = PrudpPacket {
                packet_type: TYPE_DATA,
                flags: FLAG_ACK,
                source_type: request.destination_type,
                source_port: request.destination_port,
                destination_type: request.source_type,
                destination_port: request.source_port,
                session_id: request.session_id,
                packet_id: request.packet_id,
                fragment_id: request.fragment_id,
                signature: 0x12345678u32.to_le_bytes(),
                connection_signature: [0; 4],
                payload: Vec::new(),
            };
            server
                .send_to(
                    &encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, &[]),
                    client_address,
                )
                .unwrap();

            let mut encrypt = Rc4::new(b"CD&ML").unwrap();
            let response_payload = encrypt.apply(b"race frame accepted");
            let response = PrudpPacket {
                packet_type: TYPE_DATA,
                flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                source_type: request.destination_type,
                source_port: request.destination_port,
                destination_type: request.source_type,
                destination_port: request.source_port,
                session_id: request.session_id,
                packet_id: 1,
                fragment_id: 0,
                signature: [0; 4],
                connection_signature: [0; 4],
                payload: response_payload,
            };
            server
                .send_to(
                    &encode_prudp_v0(&response, MK7_PRUDP_ACCESS_KEY, &[]),
                    client_address,
                )
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let response_ack = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                &[],
            )
            .unwrap();
            assert_eq!(response_ack.flags, FLAG_ACK);
            assert_eq!(response_ack.packet_id, 1);
            let _ = send.send(());
        });

        let mut peer = connect_to_peer(
            &game_station(server_address),
            Duration::from_millis(250),
        )
        .unwrap();
        assert!(peer.is_connected());
        assert_eq!(peer.peer_address(), server_address);
        let response = peer
            .exchange_reliable(
                b"race frame from client",
                Duration::from_millis(250),
            )
            .unwrap();
        assert_eq!(response, b"race frame accepted");

        server_thread.join().unwrap();
        receive.recv().unwrap();
    }
}
