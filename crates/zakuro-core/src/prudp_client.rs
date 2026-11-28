//! PRUDP v0 UDP client transport used by the MK7 NEX endpoints.
//!
//! This module implements the connection handshake only. RMC authentication,
//! Kerberos ticket construction, reliable DATA delivery, and matchmaking are
//! separate layers built on top of the returned session.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    STREAM_TYPE_GAME, STREAM_TYPE_RV_SECURE, decode_prudp_v0, decode_rmc_response, encode_prudp_v0, encode_rmc_request, PrudpPacket, Rc4, RmcResponse, MK7_PRUDP_ACCESS_KEY,
};

const TYPE_SYN: u8 = 0;
const TYPE_CONNECT: u8 = 1;
const TYPE_DATA: u8 = 2;
const SECURE_STREAM_TYPE: u8 = STREAM_TYPE_RV_SECURE;

const FLAG_ACK: u8 = 0x01;
const FLAG_RELIABLE: u8 = 0x02;
const FLAG_NEED_ACK: u8 = 0x04;
const FLAG_HAS_SIZE: u8 = 0x08;

const MAX_HANDSHAKE_ATTEMPTS: usize = 3;
const RELIABLE_FRAGMENT_SIZE: usize = 962;

/// State retained after a successful PRUDP v0 SYN/CONNECT exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrudpSession {
    /// Session ID chosen by this client for outgoing packets.
    pub client_session_id: u8,
    /// Session ID selected by the server in its CONNECT acknowledgement.
    pub server_session_id: u8,
    /// Signature the server sent in its SYN acknowledgement, derived from the
    /// client's public address and source port.
    pub server_connection_signature: [u8; 4],
    /// Signature the client sends in CONNECT, derived from the server address.
    pub client_connection_signature: [u8; 4],
    /// Data returned by a secure endpoint in the CONNECT acknowledgement.
    /// Ordinary authentication endpoints return an empty payload.
    pub connect_response: Vec<u8>,
    /// Local and remote virtual ports selected by the NEX station URLs.
    pub source_type: u8,
    pub destination_type: u8,
    pub source_port: u8,
    pub destination_port: u8,
    /// The CONNECT request consumes reliable sequence ID 1.
    pub next_reliable_packet_id: u16,
    /// Server-initiated RMC requests received while a client request was in flight.
    pub(crate) pending_server_pushes: Vec<Vec<u8>>,
}

/// Calculate the PRUDP v0 connection signature for an IPv4 socket address.
///
/// The value is the first four bytes of MD5(address || big-endian port), in
/// reverse byte order, matching the NEX PRUDP v0 connection-signature format.
pub fn connection_signature(address: SocketAddrV4) -> [u8; 4] {
    let mut input = Vec::with_capacity(6);
    input.extend_from_slice(&address.ip().octets());
    input.extend_from_slice(&address.port().to_be_bytes());

    let digest = crate::nex_bootstrap::md5_digest(&input);
    [digest[3], digest[2], digest[1], digest[0]]
}

/// Establish a PRUDP v0 session over an already-bound IPv4 UDP socket.
///
/// connect_payload is empty for the NEX authentication endpoint. The secure
/// endpoint instead expects the encrypted Kerberos connection ticket here.
/// The returned response payload is left to the caller to validate.
pub fn establish_session(
    socket: &UdpSocket,
    server: SocketAddrV4,
    stream_type: u8,
    source_port: u8,
    destination_port: u8,
    connect_payload: &[u8],
    timeout: Duration,
) -> Result<PrudpSession, String> {
    if connect_payload.len() > u16::MAX as usize {
        return Err("PRUDP CONNECT payload exceeds the v0 size limit".to_owned());
    }
    if timeout.is_zero() {
        return Err("PRUDP handshake timeout must be greater than zero".to_owned());
    }

    let previous_timeout = socket
        .read_timeout()
        .map_err(|error| format!("could not read UDP socket timeout: {error}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("could not configure UDP handshake timeout: {error}"))?;

    let result = establish_session_inner(
        socket,
        server,
        stream_type,
        source_port,
        destination_port,
        connect_payload,
    );
    let restore = socket.set_read_timeout(previous_timeout);

    match (result, restore) {
        (Ok(session), Ok(())) => Ok(session),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "PRUDP session was established but socket timeout could not be restored: {error}"
        )),
    }
}

fn establish_session_inner(
    socket: &UdpSocket,
    server: SocketAddrV4,
    stream_type: u8,
    source_port: u8,
    destination_port: u8,
    connect_payload: &[u8],
) -> Result<PrudpSession, String> {
    let mut random_session_id = [0u8; 1];
    getrandom::fill(&mut random_session_id)
        .map_err(|error| format!("could not generate PRUDP session ID: {error}"))?;
    let client_session_id = random_session_id[0];

    let syn = PrudpPacket {
        packet_type: TYPE_SYN,
        flags: FLAG_NEED_ACK,
        source_type: stream_type,
        source_port,
        destination_type: stream_type,
        destination_port,
        session_id: 0,
        packet_id: 0,
        fragment_id: 0,
        signature: [0; 4],
        connection_signature: [0; 4],
        payload: Vec::new(),
    };
    let mut peer_session_id = None;
    let syn_ack = send_and_receive(socket, server, &syn, TYPE_SYN, 0, &[], &mut peer_session_id)?;

    if syn_ack.flags & (FLAG_ACK | FLAG_HAS_SIZE) != (FLAG_ACK | FLAG_HAS_SIZE)
        || syn_ack.session_id != 0
        || syn_ack.packet_id != 0
        || syn_ack.fragment_id != 0
        || syn_ack.signature != [0; 4]
        || !syn_ack.payload.is_empty()
    {
        return Err("server returned an invalid PRUDP SYN acknowledgement".to_owned());
    }

    let client_connection_signature = connection_signature(server);
    let connect = PrudpPacket {
        packet_type: TYPE_CONNECT,
        flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
        source_type: stream_type,
        source_port,
        destination_type: stream_type,
        destination_port,
        session_id: client_session_id,
        packet_id: 1,
        fragment_id: 0,
        signature: syn_ack.connection_signature,
        connection_signature: client_connection_signature,
        payload: connect_payload.to_vec(),
    };
    let connect_ack = send_and_receive(
        socket,
        server,
        &connect,
        TYPE_CONNECT,
        client_session_id,
        &[],
        &mut peer_session_id,
    )?;

    if connect_ack.flags & (FLAG_ACK | FLAG_HAS_SIZE) != (FLAG_ACK | FLAG_HAS_SIZE)
        || connect_ack.packet_id != 1
        || connect_ack.fragment_id != 0
        || connect_ack.signature != client_connection_signature
        || connect_ack.connection_signature != [0; 4]
    {
        return Err("server returned an invalid PRUDP CONNECT acknowledgement".to_owned());
    }

    Ok(PrudpSession {
        client_session_id,
        server_session_id: peer_session_id.unwrap_or(connect_ack.session_id),
        server_connection_signature: syn_ack.connection_signature,
        client_connection_signature,
        connect_response: connect_ack.payload,
        source_type: stream_type,
        destination_type: stream_type,
        source_port,
        destination_port,
        next_reliable_packet_id: 2,
        pending_server_pushes: Vec::new(),
    })
}


/// Create independent outgoing and incoming RC4 streams for a PRUDP session.
///
/// The non-secure NEX authentication endpoint starts with the protocol's
/// default CD&ML key. The secure endpoint uses the Kerberos ticket session key.
pub fn new_payload_ciphers(session_key: &[u8]) -> Result<(Rc4, Rc4), String> {
    let key = if session_key.is_empty() {
        b"CD&ML".as_slice()
    } else {
        session_key
    };
    Ok((
        Rc4::new(key).map_err(|error| format!("could not initialize outgoing PRUDP RC4: {error}"))?,
        Rc4::new(key).map_err(|error| format!("could not initialize incoming PRUDP RC4: {error}"))?,
    ))
}

impl PrudpSession {
    pub fn take_server_push(&mut self) -> Option<Vec<u8>> {
        if self.pending_server_pushes.is_empty() { None } else { Some(self.pending_server_pushes.remove(0)) }
    }

    /// Send a one-way reliable RMC response to a server-initiated request.
    pub fn send_reliable_oneway(
        &mut self, socket: &UdpSocket, server: SocketAddrV4, message: &[u8],
        session_key: &[u8], outgoing_cipher: &mut Rc4, incoming_cipher: &mut Rc4, timeout: Duration,
    ) -> Result<(), String> {
        if timeout.is_zero() { return Err("PRUDP one-way response timeout must be greater than zero".to_owned()); }
        if message.len() > RELIABLE_FRAGMENT_SIZE { return Err("one-way PRUDP RMC response exceeds one fragment".to_owned()); }
        let previous_timeout = socket.read_timeout().map_err(|e| e.to_string())?;
        socket.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let result = (|| {
            let packet_id = self.next_reliable_packet_id;
            self.next_reliable_packet_id = self.next_reliable_packet_id.wrapping_add(1);
            let encrypted = outgoing_cipher.apply(message);
            let request = PrudpPacket {
                packet_type: TYPE_DATA,
                flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                source_type: self.source_type, source_port: self.source_port,
                destination_type: self.destination_type, destination_port: self.destination_port,
                session_id: self.client_session_id, packet_id, fragment_id: 0,
                signature: [0; 4], connection_signature: [0; 4], payload: encrypted,
            };
            let encoded = encode_prudp_v0(&request, MK7_PRUDP_ACCESS_KEY, session_key);
            for _ in 0..MAX_HANDSHAKE_ATTEMPTS {
                socket.send_to(&encoded, server).map_err(|e| format!("could not send server-push response: {e}"))?;
                loop {
                    let Some(mut packet) = receive_from_server(socket, server, session_key)? else { break; };
                    if packet.packet_type != TYPE_DATA { continue; }
                    validate_session_packet(&packet, self.server_session_id, self.source_type, self.source_port, self.destination_port)?;
                    if packet.flags & FLAG_ACK != 0 && packet.packet_id == packet_id { return Ok(()); }
                    if packet.flags & FLAG_ACK == 0 {
                        if packet.flags & FLAG_NEED_ACK != 0 {
                            let ack = make_data_ack(&packet, self.source_type, self.source_port, self.destination_type, self.destination_port);
                            socket.send_to(&encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, session_key), server)
                                .map_err(|e| format!("could not acknowledge concurrent server data: {e}"))?;
                        }
                        let clear = incoming_cipher.apply(&packet.payload);
                        if is_rmc_request_message(&clear) { self.pending_server_pushes.push(clear); }
                    }
                }
            }
            Err(format!("server did not acknowledge RMC push response packet {packet_id}"))
        })();
        let restore = socket.set_read_timeout(previous_timeout);
        match (result, restore) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(format!("one-way response sent but socket timeout restore failed: {error}")),
        }
    }

    /// Send one reliable NEX message and return its reassembled response.
    ///
    /// Keep the two RC4 streams alive and pass them back on every call: PRUDP
    /// encrypts a continuous stream per direction, not each RMC message anew.
    pub fn send_reliable_message(
        &mut self,
        socket: &UdpSocket,
        server: SocketAddrV4,
        message: &[u8],
        session_key: &[u8],
        outgoing_cipher: &mut Rc4,
        incoming_cipher: &mut Rc4,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if timeout.is_zero() {
            return Err("PRUDP data timeout must be greater than zero".to_owned());
        }
        let previous_timeout = socket
            .read_timeout()
            .map_err(|error| format!("could not read UDP socket timeout: {error}"))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("could not configure PRUDP data timeout: {error}"))?;

        let result = self.send_reliable_message_inner(
            socket,
            server,
            message,
            session_key,
            outgoing_cipher,
            incoming_cipher,
        );
        let restore = socket.set_read_timeout(previous_timeout);

        match (result, restore) {
            (Ok(response), Ok(())) => Ok(response),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(format!(
                "PRUDP message completed but socket timeout could not be restored: {error}"
            )),
        }
    }

    /// Send an RMC request and validate the matching NEX response envelope.
    pub fn request_rmc(
        &mut self,
        socket: &UdpSocket,
        server: SocketAddrV4,
        protocol: u8,
        method: u32,
        call_id: u32,
        body: &[u8],
        session_key: &[u8],
        outgoing_cipher: &mut Rc4,
        incoming_cipher: &mut Rc4,
        timeout: Duration,
    ) -> Result<RmcResponse, String> {
        let request = encode_rmc_request(protocol, method, call_id, body);
        let response = self.send_reliable_message(
            socket,
            server,
            &request,
            session_key,
            outgoing_cipher,
            incoming_cipher,
            timeout,
        )?;
        decode_rmc_response(&response, protocol, method, call_id)
    }

    fn send_reliable_message_inner(
        &mut self,
        socket: &UdpSocket,
        server: SocketAddrV4,
        message: &[u8],
        session_key: &[u8],
        outgoing_cipher: &mut Rc4,
        incoming_cipher: &mut Rc4,
    ) -> Result<Vec<u8>, String> {
        let fragments = if message.is_empty() {
            vec![&message[..]]
        } else {
            message.chunks(RELIABLE_FRAGMENT_SIZE).collect::<Vec<_>>()
        };
        if fragments.len() > u8::MAX as usize {
            return Err("PRUDP message exceeds the v0 fragment-count limit".to_owned());
        }

        let mut pending_response = std::collections::VecDeque::new();
        for (index, fragment) in fragments.iter().enumerate() {
            let fragment_id = if index + 1 == fragments.len() {
                0
            } else {
                (index + 1) as u8
            };
            let packet_id = self.next_reliable_packet_id;
            self.next_reliable_packet_id = self.next_reliable_packet_id.wrapping_add(1);

            let encrypted = outgoing_cipher.apply(fragment);
            let request = PrudpPacket {
                packet_type: TYPE_DATA,
                flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                source_type: self.source_type,
                source_port: self.source_port,
                destination_type: self.destination_type,
                destination_port: self.destination_port,
                session_id: self.client_session_id,
                packet_id,
                fragment_id,
                signature: [0; 4],
                connection_signature: [0; 4],
                payload: encrypted,
            };
            let encoded = encode_prudp_v0(&request, MK7_PRUDP_ACCESS_KEY, session_key);
            let mut acknowledged = false;

            for _ in 0..MAX_HANDSHAKE_ATTEMPTS {
                socket
                    .send_to(&encoded, server)
                    .map_err(|error| format!("could not send reliable PRUDP DATA: {error}"))?;

                loop {
                    let Some(packet) = receive_from_server(socket, server, session_key)? else {
                        break;
                    };
                    if packet.packet_type != TYPE_DATA {
                        continue;
                    }
                    validate_session_packet(
                        &packet,
                        self.server_session_id,
                        self.source_type,
                        self.source_port,
                        self.destination_port,
                    )?;

                    if packet.flags & FLAG_ACK != 0 {
                        if packet.packet_id == packet_id {
                            acknowledged = true;
                            break;
                        }
                    } else {
                        let mut packet = packet;
                        if packet.flags & FLAG_NEED_ACK != 0 {
                            let acknowledgement = PrudpPacket {
                                packet_type: TYPE_DATA,
                                flags: FLAG_ACK,
                                source_type: self.source_type,
                                source_port: self.source_port,
                                destination_type: self.destination_type,
                                destination_port: self.destination_port,
                                session_id: packet.session_id,
                                packet_id: packet.packet_id,
                                fragment_id: packet.fragment_id,
                                signature: [0; 4],
                                connection_signature: [0; 4],
                                payload: Vec::new(),
                            };
                            socket
                                .send_to(&encode_prudp_v0(&acknowledgement, MK7_PRUDP_ACCESS_KEY, session_key), server)
                                .map_err(|error| format!("could not acknowledge simultaneous peer DATA: {error}"))?;
                            packet.flags &= !FLAG_NEED_ACK;
                        }
                        let clear = incoming_cipher.apply(&packet.payload);
                        if is_rmc_request_message(&clear) {
                            self.pending_server_pushes.push(clear);
                        } else {
                            packet.payload = clear;
                            pending_response.push_back(packet);
                        }
                    }
                }

                if acknowledged {
                    break;
                }
            }

            if !acknowledged {
                return Err(format!(
                    "PRUDP reliable DATA packet {packet_id} was not acknowledged"
                ));
            }
        }

        let mut response = Vec::new();
        loop {
            let (mut packet, already_decrypted) = match pending_response.pop_front() {
                Some(packet) => (packet, true),
                None => (receive_from_server(socket, server, session_key)?
                    .ok_or_else(|| "timed out waiting for the NEX RMC response".to_owned())?, false),
            };
            if packet.packet_type != TYPE_DATA {
                continue;
            }
            validate_session_packet(
                &packet,
                self.server_session_id,
                self.source_type,
                self.source_port,
                self.destination_port,
            )?;
            if packet.flags & FLAG_ACK != 0 {
                continue;
            }

            if packet.flags & FLAG_NEED_ACK != 0 {
                let ack = PrudpPacket {
                    packet_type: TYPE_DATA,
                    flags: FLAG_ACK,
                    source_type: self.source_type,
                    source_port: self.source_port,
                    destination_type: self.destination_type,
                    destination_port: self.destination_port,
                    session_id: packet.session_id,
                    packet_id: packet.packet_id,
                    fragment_id: packet.fragment_id,
                    signature: [0; 4],
                    connection_signature: [0; 4],
                    payload: Vec::new(),
                };
                socket
                    .send_to(&encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, session_key), server)
                    .map_err(|error| format!("could not acknowledge server PRUDP DATA: {error}"))?;
            }

            if packet.flags & FLAG_RELIABLE == 0 {
                return Err("NEX RMC response arrived as unreliable PRUDP DATA".to_owned());
            }
            if !already_decrypted {
                let clear = incoming_cipher.apply(&packet.payload);
                if is_rmc_request_message(&clear) {
                    self.pending_server_pushes.push(clear);
                    continue;
                }
                packet.payload = clear;
            }
            response.extend_from_slice(&packet.payload);
            if packet.fragment_id == 0 {
                return Ok(response);
            }
        }
    }
}

pub(crate) fn validate_session_packet(
    packet: &PrudpPacket,
    expected_session_id: u8,
    expected_stream_type: u8,
    source_port: u8,
    destination_port: u8,
) -> Result<(), String> {
    if packet.session_id != expected_session_id
        || packet.source_type != expected_stream_type
        || packet.destination_type != expected_stream_type
        || packet.source_port != destination_port
        || packet.destination_port != source_port
    {
        return Err("received PRUDP DATA for a different session or virtual port".to_owned());
    }
    Ok(())
}

/// Receive one packet from the connected NEX endpoint. None means the socket
/// read timeout elapsed; packets from unrelated UDP peers are discarded.
pub(crate) fn is_rmc_request_message(message: &[u8]) -> bool {
    if message.len() < 13 { return false; }
    let declared = u32::from_le_bytes(message[0..4].try_into().unwrap()) as usize;
    declared == message.len() - 4 && message[4] & 0x80 != 0
}

pub(crate) fn make_data_ack(
    packet: &PrudpPacket, source_type: u8, source_port: u8, destination_type: u8, destination_port: u8,
) -> PrudpPacket {
    PrudpPacket {
        packet_type: TYPE_DATA, flags: FLAG_ACK, source_type, source_port, destination_type, destination_port,
        session_id: packet.session_id, packet_id: packet.packet_id, fragment_id: packet.fragment_id,
        signature: [0; 4], connection_signature: [0; 4], payload: Vec::new(),
    }
}
pub(crate) fn receive_from_server(
    socket: &UdpSocket,
    server: SocketAddrV4,
    session_key: &[u8],
) -> Result<Option<PrudpPacket>, String> {
    let expected_peer = SocketAddr::V4(server);
    let mut response = [0u8; 65_535];
    loop {
        match socket.recv_from(&mut response) {
            Ok((length, peer)) => {
                if peer != expected_peer {
                    continue;
                }
                let packet = decode_prudp_v0(
                    &response[..length],
                    MK7_PRUDP_ACCESS_KEY,
                    session_key,
                )
                .map_err(|error| format!("could not decode PRUDP DATA packet: {error}"))?;
                return Ok(Some(packet));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(format!("could not receive PRUDP DATA packet: {error}"));
            }
        }
    }
}

fn send_and_receive(
    socket: &UdpSocket,
    server: SocketAddrV4,
    request: &PrudpPacket,
    expected_type: u8,
    expected_session_id: u8,
    session_key: &[u8],
    peer_session_id: &mut Option<u8>,
) -> Result<PrudpPacket, String> {
    let encoded = encode_prudp_v0(request, MK7_PRUDP_ACCESS_KEY, session_key);
    let expected_peer = SocketAddr::V4(server);
    let mut response = [0u8; 65_535];

    for _ in 0..MAX_HANDSHAKE_ATTEMPTS {
        socket
            .send_to(&encoded, server)
            .map_err(|error| format!("could not send PRUDP handshake packet: {error}"))?;

        loop {
            match socket.recv_from(&mut response) {
                Ok((length, peer)) => {
                    if peer != expected_peer {
                        continue;
                    }

                    let packet = decode_prudp_v0(
                        &response[..length],
                        MK7_PRUDP_ACCESS_KEY,
                        session_key,
                    )
                    .map_err(|error| format!("could not decode PRUDP handshake response: {error}"))?;

                    // Two Game-stream peers may initiate simultaneously. Answer
                    // the peer's SYN and CONNECT while progressing our own handshake.
                    if request.source_type == STREAM_TYPE_GAME
                        && packet.flags & FLAG_ACK == 0
                        && packet.source_type == request.destination_type
                        && packet.destination_type == request.source_type
                        && packet.source_port == request.destination_port
                        && packet.destination_port == request.source_port
                    {
                        match (expected_type, packet.packet_type) {
                            (TYPE_SYN, TYPE_SYN) => {
                                let peer_address = match peer {
                                    SocketAddr::V4(address) => address,
                                    SocketAddr::V6(_) => return Err("Game peers must use IPv4".to_owned()),
                                };
                                let acknowledgement = PrudpPacket {
                                    packet_type: TYPE_SYN,
                                    flags: FLAG_ACK | FLAG_HAS_SIZE,
                                    source_type: packet.destination_type,
                                    source_port: packet.destination_port,
                                    destination_type: packet.source_type,
                                    destination_port: packet.source_port,
                                    session_id: 0,
                                    packet_id: packet.packet_id,
                                    fragment_id: 0,
                                    signature: [0; 4],
                                    connection_signature: connection_signature(peer_address),
                                    payload: Vec::new(),
                                };
                                socket
                                    .send_to(&encode_prudp_v0(&acknowledgement, MK7_PRUDP_ACCESS_KEY, &[]), peer)
                                    .map_err(|error| format!("could not answer peer PRUDP SYN: {error}"))?;
                                continue;
                            }
                            (TYPE_CONNECT, TYPE_CONNECT) => {
                                *peer_session_id = Some(packet.session_id);
                                let acknowledgement = PrudpPacket {
                                    packet_type: TYPE_CONNECT,
                                    flags: FLAG_ACK | FLAG_HAS_SIZE,
                                    source_type: packet.destination_type,
                                    source_port: packet.destination_port,
                                    destination_type: packet.source_type,
                                    destination_port: packet.source_port,
                                    session_id: packet.session_id,
                                    packet_id: 1,
                                    fragment_id: 0,
                                    signature: packet.connection_signature,
                                    connection_signature: [0; 4],
                                    payload: Vec::new(),
                                };
                                socket
                                    .send_to(&encode_prudp_v0(&acknowledgement, MK7_PRUDP_ACCESS_KEY, &[]), peer)
                                    .map_err(|error| format!("could not answer peer PRUDP CONNECT: {error}"))?;
                                continue;
                            }
                            _ => {}
                        }
                    }

                    if packet.flags & FLAG_ACK == 0 || packet.packet_type != expected_type
                        || packet.session_id != expected_session_id
                        || packet.packet_id != request.packet_id
                        || packet.source_type != request.destination_type
                        || packet.destination_type != request.source_type
                        || packet.source_port != request.destination_port
                        || packet.destination_port != request.source_port
                    {
                        continue;
                    }

                    return Ok(packet);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => {
                    return Err(format!("could not receive PRUDP handshake response: {error}"));
                }
            }
        }
    }

    Err(format!(
        "PRUDP v0 handshake timed out waiting for packet type {expected_type}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn rmc_request_round_trip_uses_rc4_and_packet_acknowledgements() {
        let server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_address = match server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("test server did not bind IPv4"),
        };
        let client = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (send, receive) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let mut bytes = [0u8; 65_535];
            let (length, client_address) = server.recv_from(&mut bytes).unwrap();
            let syn = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
            assert_eq!(syn.packet_type, TYPE_SYN);
            let client_address = match client_address {
                SocketAddr::V4(address) => address,
                _ => panic!("test client did not use IPv4"),
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
                .send_to(&encode_prudp_v0(&syn_ack, MK7_PRUDP_ACCESS_KEY, &[]), client_address)
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let connect = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
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
                .send_to(&encode_prudp_v0(&connect_ack, MK7_PRUDP_ACCESS_KEY, &[]), client_address)
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let request = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
            assert_eq!(request.packet_type, TYPE_DATA);
            assert_eq!(request.packet_id, 2);
            assert_eq!(
                request.flags,
                FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE
            );
            let mut decrypt = Rc4::new(b"CD&ML").unwrap();
            let clear_request = decrypt.apply(&request.payload);
            assert_eq!(u32::from_le_bytes(clear_request[..4].try_into().unwrap()) as usize, clear_request.len() - 4);
            assert_eq!(clear_request[4], 0x8A);
            assert_eq!(u32::from_le_bytes(clear_request[5..9].try_into().unwrap()), 1);
            assert_eq!(u32::from_le_bytes(clear_request[9..13].try_into().unwrap()), 2);
            assert_eq!(&clear_request[13..], b"login parameters");

            let request_ack = PrudpPacket {
                packet_type: TYPE_DATA,
                flags: FLAG_ACK,
                source_type: request.destination_type,
                source_port: request.destination_port,
                destination_type: request.source_type,
                destination_port: request.source_port,
                session_id: request.session_id,
                packet_id: request.packet_id,
                fragment_id: request.fragment_id,
                signature: [0; 4],
                connection_signature: [0; 4],
                payload: Vec::new(),
            };
            server
                .send_to(&encode_prudp_v0(&request_ack, MK7_PRUDP_ACCESS_KEY, &[]), client_address)
                .unwrap();

            let mut response_bytes = Vec::new();
            response_bytes.extend_from_slice(&10u32.to_le_bytes());
            response_bytes.push(0x0A);
            response_bytes.push(1);
            response_bytes.extend_from_slice(&1u32.to_le_bytes());
            response_bytes.extend_from_slice(&(2u32 | 0x8000).to_le_bytes());

            let mut encrypt = Rc4::new(b"CD&ML").unwrap();
            let encrypted_response = encrypt.apply(&response_bytes);
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
                payload: encrypted_response,
            };
            server
                .send_to(&encode_prudp_v0(&response, MK7_PRUDP_ACCESS_KEY, &[]), client_address)
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let response_ack = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
            assert_eq!(response_ack.packet_type, TYPE_DATA);
            assert_eq!(response_ack.flags, FLAG_ACK);
            assert_eq!(response_ack.packet_id, 1);
            assert!(response_ack.payload.is_empty());
            let _ = send.send(());
        });

        let mut session = establish_session(
            &client,
            server_address,
            SECURE_STREAM_TYPE,
            2,
            1,
            &[],
            Duration::from_millis(250),
        )
        .unwrap();
        let (mut outgoing, mut incoming) = new_payload_ciphers(&[]).unwrap();
        let response = session
            .request_rmc(
                &client,
                server_address,
                0x0A,
                2,
                1,
                b"login parameters",
                &[],
                &mut outgoing,
                &mut incoming,
                Duration::from_millis(250),
            )
            .unwrap();

        server_thread.join().unwrap();
        receive.recv().unwrap();
        assert_eq!(response.protocol, 0x0A);
        assert_eq!(response.method, 2);
        assert_eq!(response.call_id, 1);
        assert!(response.body.is_empty());
        assert_eq!(session.next_reliable_packet_id, 3);
    }
    #[test]
    fn connection_signature_matches_the_ipv4_and_port_vector() {
        let address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 12_345);
        assert_eq!(connection_signature(address), [0x42, 0xb4, 0x89, 0x98]);
    }

    #[test]
    fn udp_handshake_completes_syn_and_connect_with_server_ack_signatures() {
        let server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_address = match server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("test server did not bind IPv4"),
        };

        let client = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (send, receive) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let mut bytes = [0u8; 65_535];

            let (length, client_address) = server.recv_from(&mut bytes).unwrap();
            let syn = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                &[],
            )
            .unwrap();
            assert_eq!(syn.packet_type, TYPE_SYN);
            assert_eq!(syn.flags, FLAG_NEED_ACK);

            let client_address = match client_address {
                SocketAddr::V4(address) => address,
                _ => panic!("test client did not use IPv4"),
            };
            let client_signature = connection_signature(client_address);
            let server_signature = connection_signature(server_address);
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
                connection_signature: client_signature,
                payload: Vec::new(),
            };
            server
                .send_to(
                    &encode_prudp_v0(&syn_ack, MK7_PRUDP_ACCESS_KEY, &[]),
                    client_address,
                )
                .unwrap();

            let (length, client_address) = server.recv_from(&mut bytes).unwrap();
            let connect = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                &[],
            )
            .unwrap();
            assert_eq!(connect.packet_type, TYPE_CONNECT);
            assert_eq!(connect.flags, FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE);
            assert_eq!(connect.packet_id, 1);
            assert_eq!(connect.signature, client_signature);
            assert_eq!(
                connect.connection_signature,
                connection_signature(server_address)
            );
            assert_eq!(connect.payload, b"ticket payload");

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
            let _ = send.send(());
        });

        let session = establish_session(
            &client,
            server_address,
            SECURE_STREAM_TYPE,
            2,
            1,
            b"ticket payload",
            Duration::from_millis(250),
        )
        .unwrap();

        server_thread.join().unwrap();
        receive.recv().unwrap();
        // PRUDP v0 permits a randomly selected session ID of zero.
        assert_eq!(session.server_session_id, session.client_session_id);
        assert_eq!(
            session.client_connection_signature,
            connection_signature(server_address)
        );
        assert_eq!(session.connect_response, Vec::<u8>::new());
    }
}
