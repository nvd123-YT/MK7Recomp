//! Direct PRUDP Game-stream transport for MK7 peer-to-peer race sessions.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    decode_prudp_v0, encode_prudp_v0, PrudpPacket, Rc4, Station,
    MK7_PRUDP_ACCESS_KEY, STREAM_TYPE_GAME,
};
use crate::prudp_client::{connection_signature, establish_session, new_payload_ciphers, PrudpSession};

const LOCAL_VIRTUAL_PORT: u8 = 1;

/// A direct peer connection established with a Matchmake Join session key.
///
/// This is the Game stream (PRUDP stream type 9), separate from the secure
/// Rendez-Vous server connection (stream type 10). session_key is the
/// per-gathering key returned by JoinMatchmakeSession.
pub struct GamePeerSession {
    socket: UdpSocket,
    server: SocketAddrV4,
    session: PrudpSession,
    session_key: Vec<u8>,
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
    session_key: &[u8],
    timeout: Duration,
) -> Result<GamePeerSession, String> {
    if station.stream_type != STREAM_TYPE_GAME {
        return Err(format!(
            "peer StationURL uses stream type {}, expected Game stream type {}",
            station.stream_type, STREAM_TYPE_GAME
        ));
    }
    if session_key.is_empty() {
        return Err("peer Game-stream session key is empty".to_owned());
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
    connect_to_peer_with_socket(socket, station, server, session_key, timeout)
}

/// Connect using an already-bound UDP socket. Use this when the socket's public
/// mapping has been advertised by NEX and both peers must punch simultaneously.
pub fn connect_to_peer_with_socket(
    socket: UdpSocket,
    station: &Station,
    server: SocketAddrV4,
    session_key: &[u8],
    timeout: Duration,
) -> Result<GamePeerSession, String> {
    if station.stream_type != STREAM_TYPE_GAME || session_key.is_empty() {
        return Err("peer station or session key is invalid".to_owned());
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
    let (outgoing_cipher, incoming_cipher) = new_payload_ciphers(session_key)?;

    Ok(GamePeerSession {
        socket,
        server,
        session,
        session_key: session_key.to_vec(),
        outgoing_cipher,
        incoming_cipher,
    })
}


/// Accept an incoming peer connection on an already-bound Game-stream UDP socket.
///
/// The host side responds to the remote player's SYN and CONNECT packets,
/// then returns a normal bidirectional GamePeerSession. Use this for the host
/// role; the joining peer uses connect_to_peer().
pub fn accept_peer(
    socket: UdpSocket,
    session_key: &[u8],
    timeout: Duration,
) -> Result<(GamePeerSession, SocketAddrV4), String> {
    if session_key.is_empty() {
        return Err("peer Game-stream session key is empty".to_owned());
    }
    if timeout.is_zero() {
        return Err("peer Game-stream handshake timeout must be greater than zero".to_owned());
    }

    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("could not configure peer Game-stream timeout: {error}"))?;
    let local_address = match socket
        .local_addr()
        .map_err(|error| format!("could not read peer Game-stream socket address: {error}"))?
    {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => return Err("peer Game-stream listener must use IPv4".to_owned()),
    };

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
    let server_signature = connection_signature(local_address);
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

    let (outgoing_cipher, incoming_cipher) = new_payload_ciphers(session_key)?;
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
    };

    Ok((
        GamePeerSession {
            socket,
            server: peer,
            session,
            session_key: session_key.to_vec(),
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
            &self.session_key,
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
            connection_id: 77,
        }
    }

    #[test]
    fn rejects_a_non_game_station() {
        let station = Station {
            address: "127.0.0.1".to_owned(),
            port: 1234,
            stream_id: 1,
            stream_type: 10,
            principal_id: 42,
            connection_id: 77,
        };
        assert!(connect_to_peer(&station, b"key", Duration::from_millis(10))
            .err()
            .unwrap()
            .contains("expected Game stream type"));
    }

    #[test]
    fn rejects_an_empty_peer_session_key() {
        let station = Station {
            address: "127.0.0.1".to_owned(),
            port: 1234,
            stream_id: 1,
            stream_type: STREAM_TYPE_GAME,
            principal_id: 42,
            connection_id: 77,
        };
        assert!(connect_to_peer(&station, &[], Duration::from_millis(10))
            .err()
            .unwrap()
            .contains("session key is empty"));
    }

    #[test]
    fn game_stream_host_acceptor_and_joining_client_exchange_data() {
        let listener = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_address = match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game peer listener did not bind IPv4"),
        };
        let station = game_station(host_address);
        let key = b"shared MK7 gathering key".to_vec();
        let host_key = key.clone();

        // Host receives and answers the joining peer's PRUDP SYN/CONNECT.
        let host_thread = thread::spawn(move || {
            let (mut host, remote) =
                accept_peer(listener, &host_key, Duration::from_secs(2)).unwrap();
            assert_eq!(remote.ip(), &Ipv4Addr::LOCALHOST);
            assert!(host.is_connected());
            host.exchange_reliable(b"frame from host", Duration::from_secs(2))
                .unwrap()
        });

        let mut client = connect_to_peer(
            &station,
            &key,
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
    fn game_stream_handshake_and_keyed_reliable_exchange_work() {
        let server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_address = match server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game peer server did not bind IPv4"),
        };

        let session_key = b"mk7-gathering-session-key".to_vec();
        let server_key = session_key.clone();
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
                &server_key,
            )
            .unwrap();
            assert_eq!(request.packet_type, TYPE_DATA);
            assert_eq!(request.source_type, STREAM_TYPE_GAME);
            assert_eq!(request.destination_type, STREAM_TYPE_GAME);
            assert_eq!(request.flags, FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE);
            let mut decrypt = Rc4::new(&server_key).unwrap();
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
                    &encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, &server_key),
                    client_address,
                )
                .unwrap();

            let mut encrypt = Rc4::new(&server_key).unwrap();
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
                    &encode_prudp_v0(&response, MK7_PRUDP_ACCESS_KEY, &server_key),
                    client_address,
                )
                .unwrap();

            let (length, _) = server.recv_from(&mut bytes).unwrap();
            let response_ack = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                &server_key,
            )
            .unwrap();
            assert_eq!(response_ack.flags, FLAG_ACK);
            assert_eq!(response_ack.packet_id, 1);
            let _ = send.send(());
        });

        let mut peer = connect_to_peer(
            &game_station(server_address),
            &session_key,
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
