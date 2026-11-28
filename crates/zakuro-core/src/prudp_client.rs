//! PRUDP v0 UDP client transport used by the MK7 NEX endpoints.
//!
//! This module implements the connection handshake only. RMC authentication,
//! Kerberos ticket construction, reliable DATA delivery, and matchmaking are
//! separate layers built on top of the returned session.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    decode_prudp_v0, encode_prudp_v0, PrudpPacket, MK7_PRUDP_ACCESS_KEY,
};

const TYPE_SYN: u8 = 0;
const TYPE_CONNECT: u8 = 1;

const FLAG_ACK: u8 = 0x01;
const FLAG_RELIABLE: u8 = 0x02;
const FLAG_NEED_ACK: u8 = 0x04;
const FLAG_HAS_SIZE: u8 = 0x08;

const MAX_HANDSHAKE_ATTEMPTS: usize = 3;

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
        source_port,
        destination_port,
        session_id: 0,
        packet_id: 0,
        fragment_id: 0,
        signature: [0; 4],
        connection_signature: [0; 4],
        payload: Vec::new(),
    };
    let syn_ack = send_and_receive(socket, server, &syn, TYPE_SYN, 0, &[])?;

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
        source_port,
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
        server_session_id: connect_ack.session_id,
        server_connection_signature: syn_ack.connection_signature,
        client_connection_signature,
        connect_response: connect_ack.payload,
    })
}

fn send_and_receive(
    socket: &UdpSocket,
    server: SocketAddrV4,
    request: &PrudpPacket,
    expected_type: u8,
    expected_session_id: u8,
    session_key: &[u8],
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

                    if packet.packet_type != expected_type
                        || packet.session_id != expected_session_id
                        || packet.packet_id != request.packet_id
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
            let server_signature = connection_signature(client_address);
            let syn_ack = PrudpPacket {
                packet_type: TYPE_SYN,
                flags: FLAG_ACK | FLAG_HAS_SIZE,
                source_port: 1,
                destination_port: 2,
                session_id: 0,
                packet_id: 0,
                fragment_id: 0,
                signature: [0; 4],
                connection_signature: server_signature,
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
            assert_eq!(connect.signature, server_signature);
            assert_eq!(
                connect.connection_signature,
                connection_signature(server_address)
            );
            assert_eq!(connect.payload, b"ticket payload");

            let connect_ack = PrudpPacket {
                packet_type: TYPE_CONNECT,
                flags: FLAG_ACK | FLAG_HAS_SIZE,
                source_port: 1,
                destination_port: 2,
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
            2,
            1,
            b"ticket payload",
            Duration::from_millis(250),
        )
        .unwrap();

        server_thread.join().unwrap();
        receive.recv().unwrap();
        assert_ne!(session.client_session_id, 0);
        assert_eq!(session.server_session_id, session.client_session_id);
        assert_eq!(
            session.client_connection_signature,
            connection_signature(server_address)
        );
        assert_eq!(session.connect_response, Vec::<u8>::new());
    }
}
