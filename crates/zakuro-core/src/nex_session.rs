//! Two-stage NEX authentication and secure-server session setup for Mario Kart 7.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    build_secure_connect_payload, decode_client_kerberos_ticket,
    decode_ticket_granting_login_ex_response, encode_ticket_granting_login_ex_body,
    verify_secure_connect_response, ClientKerberosTicket, RmcResponse,
    Station, STREAM_TYPE_RV,
};
use crate::nex_bootstrap::Rc4;
use crate::prudp_client::{
    establish_session, new_payload_ciphers, PrudpSession,
};

const TICKET_GRANTING_PROTOCOL: u8 = 0x0A;
const TICKET_GRANTING_LOGIN_EX: u32 = 0x02;
const MK7_SESSION_KEY_LENGTH: usize = 32;
const CLIENT_VIRTUAL_PORT: u8 = 1;
const AUTHENTICATION_STREAM_TYPE: u8 = STREAM_TYPE_RV;

/// A completed LoginEx plus secure PRUDP session.
///
/// The socket, session counters, and RC4 streams remain together so follow-up
/// matchmaking, NAT traversal, and game-server requests reuse the same state.
pub struct NexOnlineSession {
    socket: UdpSocket,
    server: SocketAddrV4,
    session: PrudpSession,
    ticket: ClientKerberosTicket,
    outgoing_cipher: Rc4,
    incoming_cipher: Rc4,
    next_call_id: u32,
    pub principal_id: u32,
    pub secure_station: Station,
}

/// Authenticate with the NEX endpoint returned by NASC LOGIN and open the
/// secure station supplied by TicketGranting::LoginEx.
///
/// game_server_locator is NASC LOGIN's host:port string. NASC SVCLOC instead
/// returns an independent-service token and may return svchost="n/a".
/// nex_token is the NEX token from NASC LOGIN; username is the account UID-HMAC.
pub fn connect(
    game_server_locator: &str,
    username: &str,
    password: &str,
    principal_id: u32,
    local_friend_code: u64,
    nex_token: &str,
    timeout: Duration,
) -> Result<NexOnlineSession, String> {
    let authentication_address = parse_game_server_locator(game_server_locator)?;
    // The MK7 authentication endpoint is a PRUDP endpoint on stream ID 1.
    let authentication_station = Station {
        address: authentication_address.ip().to_string(),
        port: authentication_address.port(),
        stream_id: 1,
        stream_type: AUTHENTICATION_STREAM_TYPE,
        principal_id: 0,
        connection_id: 0,
    };

    let authentication_socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("could not bind NEX authentication UDP socket: {error}"))?;
    let mut authentication_session = establish_session(
        &authentication_socket,
        authentication_address,
        authentication_station.stream_type,
        CLIENT_VIRTUAL_PORT,
        authentication_station.stream_id,
        &[],
        timeout,
    )?;
    let (mut auth_outgoing, mut auth_incoming) = new_payload_ciphers(&[])?;
    let login_body = encode_ticket_granting_login_ex_body(
        username,
        local_friend_code,
        nex_token,
    );
    let login_response = authentication_session.request_rmc(
        &authentication_socket,
        authentication_address,
        TICKET_GRANTING_PROTOCOL,
        TICKET_GRANTING_LOGIN_EX,
        1,
        &login_body,
        &[],
        &mut auth_outgoing,
        &mut auth_incoming,
        timeout,
    )?;

    let login = decode_ticket_granting_login_ex_response(
        &login_response.body,
        principal_id,
    )?;
    let ticket = decode_client_kerberos_ticket(
        &login.ticket,
        principal_id,
        password.as_bytes(),
        MK7_SESSION_KEY_LENGTH,
    )?;
    if ticket.target_principal_id != login.secure_station.principal_id {
        return Err(format!(
            "LoginEx ticket targets principal {}, but secure StationURL targets {}",
            ticket.target_principal_id,
            login.secure_station.principal_id
        ));
    }

    let secure_address = resolve_station(&login.secure_station)?;
    let mut check_bytes = [0u8; 4];
    getrandom::fill(&mut check_bytes)
        .map_err(|error| format!("could not generate secure NEX connection check: {error}"))?;
    let check_value = u32::from_le_bytes(check_bytes);
    let connect_payload = build_secure_connect_payload(
        &ticket,
        principal_id,
        login.secure_station.connection_id,
        check_value,
    )?;

    let secure_socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("could not bind NEX secure UDP socket: {error}"))?;
    let secure_session = establish_session(
        &secure_socket,
        secure_address,
        login.secure_station.stream_type,
        CLIENT_VIRTUAL_PORT,
        login.secure_station.stream_id,
        &connect_payload,
        timeout,
    )?;
    verify_secure_connect_response(&secure_session.connect_response, check_value)?;

    let (outgoing_cipher, incoming_cipher) =
        new_payload_ciphers(&ticket.session_key)?;

    Ok(NexOnlineSession {
        socket: secure_socket,
        server: secure_address,
        session: secure_session,
        ticket,
        outgoing_cipher,
        incoming_cipher,
        next_call_id: 1,
        principal_id,
        secure_station: login.secure_station,
    })
}

impl NexOnlineSession {
    /// Send an RMC call over the authenticated secure NEX session.
    pub fn request(
        &mut self,
        protocol: u8,
        method: u32,
        body: &[u8],
        timeout: Duration,
    ) -> Result<RmcResponse, String> {
        let call_id = self.next_call_id;
        self.next_call_id = self.next_call_id.wrapping_add(1);
        self.session.request_rmc(
            &self.socket,
            self.server,
            protocol,
            method,
            call_id,
            body,
            &self.ticket.session_key,
            &mut self.outgoing_cipher,
            &mut self.incoming_cipher,
            timeout,
        )
    }


    /// Browse MK7's Matchmake Extension for sessions matching the supplied
    /// game-specific search fields.
    pub fn browse_matchmake_sessions(
        &mut self,
        criteria: &crate::nex_bootstrap::MatchmakeSearchCriteria,
        range_offset: u32,
        range_size: u32,
        timeout: Duration,
    ) -> Result<Vec<crate::nex_bootstrap::MatchmakeSessionSummary>, String> {
        let body = crate::nex_bootstrap::encode_matchmake_browse_request(
            criteria,
            range_offset,
            range_size,
        )?;
        let response = self.request(0x6D, 0x2A, &body, timeout)?;
        crate::nex_bootstrap::decode_matchmake_session_list(&response.body)
    }

    /// Ask the NEX server to place this user into a public MK7 gathering.
    ///
    /// This is the actual title-style matchmaking operation; it may block
    /// until a compatible session is found or the server rejects the request.
    pub fn auto_matchmake(
        &mut self,
        criteria: &crate::nex_bootstrap::MatchmakeSearchCriteria,
        message: &str,
        timeout: Duration,
    ) -> Result<crate::nex_bootstrap::MatchmakeAutoResult, String> {
        let body = crate::nex_bootstrap::encode_matchmake_auto_request(criteria, message)?;
        let response = self.request(0x6D, 0x0F, &body, timeout)?;
        crate::nex_bootstrap::decode_matchmake_auto_response(&response.body)
    }

    /// Join a known gathering and return the P2P session key.
    pub fn join_matchmake_session(
        &mut self,
        gathering_id: u32,
        message: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let body = crate::nex_bootstrap::encode_matchmake_join_request(gathering_id, message);
        let response = self.request(0x6D, 0x07, &body, timeout)?;
        crate::nex_bootstrap::decode_nex_buffer_response(&response.body)
    }

    /// Retrieve the StationURLs for the P2P host/participants of a gathering.
    pub fn get_matchmake_session_urls(
        &mut self,
        gathering_id: u32,
        timeout: Duration,
    ) -> Result<Vec<Station>, String> {
        let response = self.request(0x15, 0x29, &gathering_id.to_le_bytes(), timeout)?;
        crate::nex_bootstrap::decode_station_url_list(&response.body)
    }

    /// Join a gathering and establish its host's Game-stream PRUDP session.
    ///
    /// The host peer is selected by the PID returned in the auto-match result;
    /// the per-gathering key returned by JoinMatchmakeSession is used for
    /// subsequent PRUDP DATA signatures and RC4 payload encryption.
    pub fn connect_to_matchmake_host(
        &mut self,
        result: &crate::nex_bootstrap::MatchmakeAutoResult,
        message: &str,
        timeout: Duration,
    ) -> Result<crate::game_peer::GamePeerSession, String> {
        if result.host_pid == 0 {
            return Err("automatic matchmaking returned a zero host PID".to_owned());
        }
        let session_key = self.join_matchmake_session(result.gathering_id, message, timeout)?;
        if session_key.is_empty() {
            return Err("JoinMatchmakeSession returned an empty P2P session key".to_owned());
        }
        let stations = self.get_matchmake_session_urls(result.gathering_id, timeout)?;
        let host = stations
            .iter()
            .find(|station| {
                station.principal_id == result.host_pid
                    && station.stream_type == crate::nex_bootstrap::STREAM_TYPE_GAME
            })
            .ok_or_else(|| format!(
                "GetSessionURLs did not return a Game-stream StationURL for host PID {}",
                result.host_pid
            ))?;
        crate::game_peer::connect_to_peer(host, &session_key, timeout)
    }

    /// The principal ID authenticated by the NEX TicketGranting server.
    pub fn principal_id(&self) -> u32 {
        self.principal_id
    }

    /// Address of the secure NEX endpoint.
    pub fn server_address(&self) -> SocketAddrV4 {
        self.server
    }

    /// Whether the PRUDP session is represented by a bound UDP endpoint.
    pub fn is_connected(&self) -> bool {
        self.socket.local_addr().is_ok()
            && self.session.server_session_id == self.session.client_session_id
    }
}


fn parse_game_server_locator(locator: &str) -> Result<SocketAddrV4, String> {
    let (host, port) = locator
        .rsplit_once(':')
        .ok_or_else(|| "NASC LOGIN locator omitted its port".to_owned())?;
    if host.is_empty() {
        return Err("NASC LOGIN locator has an empty host".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "NASC LOGIN locator has an invalid port".to_owned())?;
    if port == 0 {
        return Err("NASC LOGIN locator port is zero".to_owned());
    }
    let endpoint = (host, port);
    endpoint
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve NASC LOGIN locator {locator}: {error}"))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(address),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("NASC LOGIN locator {locator} did not resolve to IPv4"))
}

fn resolve_station(station: &Station) -> Result<SocketAddrV4, String> {
    if station.port == 0 {
        return Err("NEX StationURL port is zero".to_owned());
    }
    let endpoint = (station.address.as_str(), station.port);
    endpoint
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve NEX station {}: {error}", station.address))?
        .find_map(|address| match address {
            SocketAddr::V4(address) => Some(address),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("NEX station {} did not resolve to IPv4", station.address))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nex_bootstrap::{
        decode_nex_string, decode_prudp_v0, derive_kerberos_key, encode_nex_string,
        encode_prudp_v0, kerberos_decrypt, kerberos_encrypt, MatchmakeSearchCriteria,
        PrudpPacket, Rc4, MK7_PRUDP_ACCESS_KEY, STREAM_TYPE_RV, STREAM_TYPE_RV_SECURE,
    };
    use crate::prudp_client::connection_signature;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::thread;

    const TEST_TYPE_SYN: u8 = 0;
    const TEST_TYPE_CONNECT: u8 = 1;
    const TEST_TYPE_DATA: u8 = 2;
    const TEST_FLAG_ACK: u8 = 0x01;
    const TEST_FLAG_RELIABLE: u8 = 0x02;
    const TEST_FLAG_NEED_ACK: u8 = 0x04;
    const TEST_FLAG_HAS_SIZE: u8 = 0x08;

    fn test_read_u32(data: &[u8], cursor: &mut usize) -> u32 {
        let end = *cursor + 4;
        let value = u32::from_le_bytes(data[*cursor..end].try_into().unwrap());
        *cursor = end;
        value
    }

    fn test_take_buffer(data: &[u8], cursor: &mut usize) -> Vec<u8> {
        let length = test_read_u32(data, cursor) as usize;
        let end = *cursor + length;
        let bytes = data[*cursor..end].to_vec();
        *cursor = end;
        bytes
    }

    fn test_put_buffer(bytes: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        output.extend_from_slice(bytes);
    }

    fn test_encode_rmc_response(protocol: u8, method: u32, call_id: u32, body: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.push(protocol);
        content.push(1);
        content.extend_from_slice(&call_id.to_le_bytes());
        content.extend_from_slice(&(method | 0x8000).to_le_bytes());
        content.extend_from_slice(body);
        let mut response = Vec::new();
        response.extend_from_slice(&(content.len() as u32).to_le_bytes());
        response.extend_from_slice(&content);
        response
    }

    fn test_accept_prudp(
        socket: &UdpSocket,
        expected_stream_type: u8,
        connect_payload: impl FnOnce(&PrudpPacket) -> Vec<u8>,
    ) -> (SocketAddrV4, u8) {
        let mut bytes = [0u8; 65_535];
        let (length, client_address) = socket.recv_from(&mut bytes).unwrap();
        let syn = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
        assert_eq!(syn.packet_type, TEST_TYPE_SYN);
        assert_eq!(syn.source_type, expected_stream_type);
        assert_eq!(syn.destination_type, expected_stream_type);
        let client_address = match client_address {
            SocketAddr::V4(address) => address,
            _ => panic!("test NEX client did not use IPv4"),
        };
        let server_address = match socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("test NEX server did not bind IPv4"),
        };

        let syn_ack = PrudpPacket {
            packet_type: TEST_TYPE_SYN,
            flags: TEST_FLAG_ACK | TEST_FLAG_HAS_SIZE,
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
        socket
            .send_to(
                &encode_prudp_v0(&syn_ack, MK7_PRUDP_ACCESS_KEY, &[]),
                client_address,
            )
            .unwrap();

        let (length, peer) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(peer, SocketAddr::V4(client_address));
        let connect = decode_prudp_v0(&bytes[..length], MK7_PRUDP_ACCESS_KEY, &[]).unwrap();
        assert_eq!(connect.packet_type, TEST_TYPE_CONNECT);
        assert_eq!(connect.signature, connection_signature(client_address));
        assert_eq!(connect.connection_signature, connection_signature(server_address));

        let response_payload = connect_payload(&connect);
        let connect_ack = PrudpPacket {
            packet_type: TEST_TYPE_CONNECT,
            flags: TEST_FLAG_ACK | TEST_FLAG_HAS_SIZE,
            source_type: connect.destination_type,
            source_port: connect.destination_port,
            destination_type: connect.source_type,
            destination_port: connect.source_port,
            session_id: connect.session_id,
            packet_id: 1,
            fragment_id: 0,
            signature: connect.connection_signature,
            connection_signature: [0; 4],
            payload: response_payload,
        };
        socket
            .send_to(
                &encode_prudp_v0(&connect_ack, MK7_PRUDP_ACCESS_KEY, &[]),
                client_address,
            )
            .unwrap();
        (client_address, connect.session_id)
    }

    fn test_serve_rmc_call(
        socket: &UdpSocket,
        client: SocketAddrV4,
        session_id: u8,
        request_packet_id: u16,
        response_packet_id: u16,
        expected_protocol: u8,
        expected_method: u32,
        expected_call_id: u32,
        session_key: &[u8],
        incoming_cipher: &mut Rc4,
        outgoing_cipher: &mut Rc4,
        response_body: &[u8],
    ) -> Vec<u8> {
        let mut bytes = [0u8; 65_535];
        let (length, peer) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(peer, SocketAddr::V4(client));
        let request = decode_prudp_v0(
            &bytes[..length],
            MK7_PRUDP_ACCESS_KEY,
            session_key,
        )
        .unwrap();
        assert_eq!(request.packet_type, TEST_TYPE_DATA);
        assert_eq!(request.flags, TEST_FLAG_RELIABLE | TEST_FLAG_NEED_ACK | TEST_FLAG_HAS_SIZE);
        assert_eq!(request.session_id, session_id);
        assert_eq!(request.packet_id, request_packet_id);

        let clear_request = incoming_cipher.apply(&request.payload);
        let declared_length = test_read_u32(&clear_request, &mut 0usize);
        assert_eq!(declared_length as usize, clear_request.len() - 4);
        assert_eq!(clear_request[4], expected_protocol | 0x80);
        let mut cursor = 5usize;
        let call_id = test_read_u32(&clear_request, &mut cursor);
        let method = test_read_u32(&clear_request, &mut cursor);
        assert_eq!(call_id, expected_call_id);
        assert_eq!(method, expected_method);
        let request_body = clear_request[cursor..].to_vec();

        let ack = PrudpPacket {
            packet_type: TEST_TYPE_DATA,
            flags: TEST_FLAG_ACK,
            source_type: request.destination_type,
            source_port: request.destination_port,
            destination_type: request.source_type,
            destination_port: request.source_port,
            session_id,
            packet_id: request.packet_id,
            fragment_id: request.fragment_id,
            signature: [0; 4],
            connection_signature: [0; 4],
            payload: Vec::new(),
        };
        socket
            .send_to(
                &encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, session_key),
                client,
            )
            .unwrap();

        let clear_response = test_encode_rmc_response(
            expected_protocol,
            expected_method,
            expected_call_id,
            response_body,
        );
        let encrypted_response = outgoing_cipher.apply(&clear_response);
        let response = PrudpPacket {
            packet_type: TEST_TYPE_DATA,
            flags: TEST_FLAG_RELIABLE | TEST_FLAG_NEED_ACK | TEST_FLAG_HAS_SIZE,
            source_type: request.destination_type,
            source_port: request.destination_port,
            destination_type: request.source_type,
            destination_port: request.source_port,
            session_id,
            packet_id: response_packet_id,
            fragment_id: 0,
            signature: [0; 4],
            connection_signature: [0; 4],
            payload: encrypted_response,
        };
        socket
            .send_to(
                &encode_prudp_v0(&response, MK7_PRUDP_ACCESS_KEY, session_key),
                client,
            )
            .unwrap();

        let (length, peer) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(peer, SocketAddr::V4(client));
        let response_ack = decode_prudp_v0(
            &bytes[..length],
            MK7_PRUDP_ACCESS_KEY,
            session_key,
        )
        .unwrap();
        assert_eq!(response_ack.packet_type, TEST_TYPE_DATA);
        assert_eq!(response_ack.flags, TEST_FLAG_ACK);
        assert_eq!(response_ack.packet_id, response_packet_id);
        assert!(response_ack.payload.is_empty());
        request_body
    }

    #[test]
    fn login_secure_handshake_and_matchmaking_calls_work_end_to_end() {
        let password = "mk7-test-password";
        let principal_id = 42u32;
        let target_principal_id = 2u32;
        let session_key = vec![0x5A; 32];
        let internal_ticket = b"pretend secure-server internal ticket".to_vec();

        let auth_server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        auth_server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let auth_address = match auth_server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("authentication mock did not bind IPv4"),
        };

        let secure_server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        secure_server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let secure_address = match secure_server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("secure mock did not bind IPv4"),
        };

        let game_peer_server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        game_peer_server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let game_peer_address = match game_peer_server.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game peer mock did not bind IPv4"),
        };

        let mut outer_ticket = session_key.clone();
        outer_ticket.extend_from_slice(&target_principal_id.to_le_bytes());
        test_put_buffer(&internal_ticket, &mut outer_ticket);
        let user_key = derive_kerberos_key(principal_id, password.as_bytes());
        let encrypted_ticket = kerberos_encrypt(&user_key, &outer_ticket).unwrap();

        let station_url = format!(
            "prudp:/address=127.0.0.1;port={};sid=1;stream=10;PID={};CID=77;type=1",
            secure_address.port(),
            target_principal_id,
        );
        let mut login_body = Vec::new();
        login_body.extend_from_slice(&0u32.to_le_bytes());
        login_body.extend_from_slice(&principal_id.to_le_bytes());
        test_put_buffer(&encrypted_ticket, &mut login_body);
        encode_nex_string(&station_url, &mut login_body);
        login_body.extend_from_slice(&0u32.to_le_bytes());
        encode_nex_string("", &mut login_body);
        encode_nex_string("MK7 mock secure service", &mut login_body);

        let auth_thread = thread::spawn(move || {
            let (client, session_id) = test_accept_prudp(&auth_server, STREAM_TYPE_RV, |_| Vec::new());
            let mut incoming_cipher = Rc4::new(b"CD&ML").unwrap();
            let mut outgoing_cipher = Rc4::new(b"CD&ML").unwrap();
            let response_body = login_body;
            let received = test_serve_rmc_call(
                &auth_server,
                client,
                session_id,
                2,
                1,
                0x0A,
                0x02,
                1,
                &[],
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &response_body,
            );
            assert!(String::from_utf8_lossy(&received).contains("nex-test-token"));
        });

        let secure_thread = thread::spawn(move || {
            let server_session_key = session_key.clone();
            let (client, session_id) = test_accept_prudp(&secure_server, STREAM_TYPE_RV_SECURE, |connect| {
                let mut cursor = 0usize;
                assert_eq!(test_take_buffer(&connect.payload, &mut cursor), internal_ticket);
                let encrypted_request = test_take_buffer(&connect.payload, &mut cursor);
                assert_eq!(cursor, connect.payload.len());
                let request = kerberos_decrypt(&server_session_key, &encrypted_request).unwrap();
                assert_eq!(&request[..4], &principal_id.to_le_bytes());
                assert_eq!(&request[4..8], &77u32.to_le_bytes());
                let check_value = u32::from_le_bytes(request[8..12].try_into().unwrap());
                let mut response = Vec::new();
                test_put_buffer(&check_value.wrapping_add(1).to_le_bytes(), &mut response);
                response
            });

            let mut incoming_cipher = Rc4::new(&server_session_key).unwrap();
            let mut outgoing_cipher = Rc4::new(&server_session_key).unwrap();

            // MK7's automatic matchmaking method: one search criteria, one
            // empty GatheringHolder, then the in-game matchmaking message.
            let mut auto_response = Vec::new();
            encode_nex_string("MatchmakeSession", &mut auto_response);
            let mut auto_object = Vec::new();
            auto_object.extend_from_slice(&1234u32.to_le_bytes());
            auto_object.extend_from_slice(&42u32.to_le_bytes());
            auto_object.extend_from_slice(&77u32.to_le_bytes());
            auto_response.extend_from_slice(&((auto_object.len() + 4) as u32).to_le_bytes());
            test_put_buffer(&auto_object, &mut auto_response);

            let auto_request = test_serve_rmc_call(
                &secure_server,
                client,
                session_id,
                2,
                1,
                0x6D,
                0x0F,
                1,
                &server_session_key,
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &auto_response,
            );
            let mut auto_cursor = 0usize;
            assert_eq!(test_read_u32(&auto_request, &mut auto_cursor), 1);
            assert_eq!(test_read_u32(&auto_request, &mut auto_cursor), 6);
            for _ in 0..6 {
                assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "");
            }
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "");
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "");
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "");
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "1");
            assert_eq!(auto_request[auto_cursor..auto_cursor + 3], [1, 1, 0]);
            auto_cursor += 3;
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "Gathering");
            let holder_length = test_read_u32(&auto_request, &mut auto_cursor) as usize;
            let gathering = test_take_buffer(&auto_request, &mut auto_cursor);
            assert_eq!(holder_length, gathering.len() + 4);
            assert_eq!(decode_nex_string(&auto_request, &mut auto_cursor).unwrap(), "MK7 public race");
            assert_eq!(auto_cursor, auto_request.len());

            let mut browse_response = Vec::new();
            browse_response.extend_from_slice(&0u32.to_le_bytes());
            let browse_request = test_serve_rmc_call(
                &secure_server,
                client,
                session_id,
                3,
                2,
                0x6D,
                0x2A,
                2,
                &server_session_key,
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &browse_response,
            );
            assert!(!browse_request.is_empty());

            let mut join_response = Vec::new();
            test_put_buffer(b"p2p-session-key", &mut join_response);
            let join_request = test_serve_rmc_call(
                &secure_server,
                client,
                session_id,
                4,
                3,
                0x6D,
                0x07,
                3,
                &server_session_key,
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &join_response,
            );
            assert_eq!(u32::from_le_bytes(join_request[..4].try_into().unwrap()), 1234);

            let mut urls_response = Vec::new();
            urls_response.extend_from_slice(&1u32.to_le_bytes());
            encode_nex_string(
                &format!(
                    "prudp:/address=127.0.0.1;port={};sid=1;stream=9;PID=77;CID=77;type=1",
                    game_peer_address.port()
                ),
                &mut urls_response,
            );
            let urls_request = test_serve_rmc_call(
                &secure_server,
                client,
                session_id,
                5,
                4,
                0x15,
                0x29,
                4,
                &server_session_key,
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &urls_response,
            );
            assert_eq!(u32::from_le_bytes(urls_request[..4].try_into().unwrap()), 1234);

            // The matchmake session key authenticates the Game-stream P2P link.
            let (peer_client, peer_session_id) =
                test_accept_prudp(&game_peer_server, STREAM_TYPE_GAME, |_| Vec::new());
            let (length, peer_address) = game_peer_server.recv_from(&mut bytes).unwrap();
            assert_eq!(peer_address, SocketAddr::V4(peer_client));
            let peer_request = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                b"p2p-session-key",
            )
            .unwrap();
            assert_eq!(peer_request.packet_type, TEST_TYPE_DATA);
            assert_eq!(peer_request.session_id, peer_session_id);
            assert_eq!(peer_request.source_type, STREAM_TYPE_GAME);
            assert_eq!(peer_request.destination_type, STREAM_TYPE_GAME);
            let mut game_decrypt = Rc4::new(b"p2p-session-key").unwrap();
            assert_eq!(game_decrypt.apply(&peer_request.payload), b"race frame from client");

            let peer_ack = PrudpPacket {
                packet_type: TEST_TYPE_DATA,
                flags: TEST_FLAG_ACK,
                source_type: peer_request.destination_type,
                source_port: peer_request.destination_port,
                destination_type: peer_request.source_type,
                destination_port: peer_request.source_port,
                session_id: peer_session_id,
                packet_id: peer_request.packet_id,
                fragment_id: peer_request.fragment_id,
                signature: 0x12345678u32.to_le_bytes(),
                connection_signature: [0; 4],
                payload: Vec::new(),
            };
            game_peer_server
                .send_to(
                    &encode_prudp_v0(&peer_ack, MK7_PRUDP_ACCESS_KEY, b"p2p-session-key"),
                    peer_client,
                )
                .unwrap();

            let mut game_encrypt = Rc4::new(b"p2p-session-key").unwrap();
            let peer_response = PrudpPacket {
                packet_type: TEST_TYPE_DATA,
                flags: TEST_FLAG_RELIABLE | TEST_FLAG_NEED_ACK | TEST_FLAG_HAS_SIZE,
                source_type: peer_request.destination_type,
                source_port: peer_request.destination_port,
                destination_type: peer_request.source_type,
                destination_port: peer_request.source_port,
                session_id: peer_session_id,
                packet_id: 1,
                fragment_id: 0,
                signature: [0; 4],
                connection_signature: [0; 4],
                payload: game_encrypt.apply(b"race frame accepted"),
            };
            game_peer_server
                .send_to(
                    &encode_prudp_v0(&peer_response, MK7_PRUDP_ACCESS_KEY, b"p2p-session-key"),
                    peer_client,
                )
                .unwrap();

            let (length, _) = game_peer_server.recv_from(&mut bytes).unwrap();
            let peer_response_ack = decode_prudp_v0(
                &bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                b"p2p-session-key",
            )
            .unwrap();
            assert_eq!(peer_response_ack.flags, TEST_FLAG_ACK);
            assert_eq!(peer_response_ack.packet_id, 1);

        });

        let locator = format!("127.0.0.1:{}", auth_address.port());
        let mut online = connect(
            &locator,
            "AB12CD34",
            password,
            principal_id,
            0x1122_3344_5566_7788,
            "nex-test-token",
            Duration::from_secs(2),
        )
        .unwrap();

        assert_eq!(online.principal_id(), principal_id);
        assert!(online.is_connected());
        let auto_result = online
            .auto_matchmake(
                &MatchmakeSearchCriteria::default(),
                "MK7 public race",
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(auto_result.object_id, "MatchmakeSession");
        assert_eq!(auto_result.gathering_id, 1234);

        let sessions = online
            .browse_matchmake_sessions(
                &MatchmakeSearchCriteria::default(),
                0,
                10,
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(sessions.is_empty());

        assert_eq!(auto_result.owner_pid, 42);
        assert_eq!(auto_result.host_pid, 77);
        let mut peer = online
            .connect_to_matchmake_host(
                &auto_result,
                "hello race",
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(peer.is_connected());
        assert_eq!(peer.peer_address().port(), game_peer_address.port());
        let peer_response = peer
            .exchange_reliable(
                b"race frame from client",
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(peer_response, b"race frame accepted");

        auth_thread.join().unwrap();
        secure_thread.join().unwrap();
    }




    #[test]
    fn game_server_locator_parses_ipv4_and_rejects_invalid_ports() {
        assert_eq!(
            parse_game_server_locator("127.0.0.1:6000").unwrap(),
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 6000)
        );
        assert!(parse_game_server_locator("127.0.0.1").is_err());
        assert!(parse_game_server_locator("127.0.0.1:0").is_err());
        assert!(parse_game_server_locator("127.0.0.1:not-a-port").is_err());
    }

    #[test]
    fn station_resolution_rejects_zero_ports_before_dns() {
        let station = Station {
            address: "invalid.invalid".to_owned(),
            port: 0,
            stream_id: 1,
            stream_type: 10,
            principal_id: 2,
            connection_id: 3,
        };
        assert!(resolve_station(&station)
            .unwrap_err()
            .contains("port is zero"));
    }

    #[test]
    fn station_resolution_accepts_ipv4_literals() {
        let station = Station {
            address: "127.0.0.1".to_owned(),
            port: 1234,
            stream_id: 1,
            stream_type: 10,
            principal_id: 2,
            connection_id: 3,
        };
        assert_eq!(
            resolve_station(&station).unwrap(),
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1234)
        );
    }
}
