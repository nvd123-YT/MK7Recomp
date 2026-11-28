//! Two-stage NEX authentication and secure-server session setup for Mario Kart 7.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    build_secure_connect_payload, decode_client_kerberos_ticket,
    decode_ticket_granting_login_ex_response, encode_ticket_granting_login_ex_body,
    verify_secure_connect_response, ClientKerberosTicket, RmcResponse,
    Station, STREAM_TYPE_RV, MK7_PRUDP_ACCESS_KEY, encode_prudp_v0, decode_rmc_request,
    encode_rmc_success_response, decode_nex_string,
};
use crate::nex_bootstrap::{Rc4, parse_station_url};
use crate::prudp_client::{
    establish_session, make_data_ack, new_payload_ciphers, receive_from_server,
    validate_session_packet, PrudpSession,
};
use crate::game_peer::{punch_through_nat, connect_to_peer_with_socket, GamePeerSession};

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
    game_socket: Option<UdpSocket>,
    local_game_station: Option<Station>,
    public_game_station: Option<Station>,
    local_friend_code: u64,
    nex_token: String,
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
        rv_connection_id: 0,
        raw_url: String::new(),
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
        game_socket: None,
        local_game_station: None,
        public_game_station: None,
        local_friend_code,
        nex_token: nex_token.to_owned(),
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


    /// Bind a Game-stream socket, discover its public mapping with STUN, and register both StationURLs.
    pub fn register_game_station(&mut self, timeout: Duration) -> Result<Station, String> {
        if timeout.is_zero() { return Err("Game station registration timeout must be greater than zero".to_owned()); }
        if let Some(station) = &self.public_game_station { return Ok(station.clone()); }
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| format!("could not bind Game-stream UDP socket: {error}"))?;
        let stun_servers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
        let mut resolved_servers = Vec::new();
        for server in stun_servers {
            if let Ok(addresses) = server.to_socket_addrs() {
                if let Some(address) = addresses.into_iter().find(|addr| matches!(addr, SocketAddr::V4(_))) { resolved_servers.push(address); }
            }
        }
        if resolved_servers.is_empty() { return Err("could not resolve an IPv4 STUN server for Game-stream registration".to_owned()); }
        let route_probe = UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| format!("could not create route probe socket: {error}"))?;
        route_probe.connect(resolved_servers[0])
            .map_err(|error| format!("could not select the Game-stream network route: {error}"))?;
        let local_ip = match route_probe.local_addr().map_err(|e| e.to_string())? {
            SocketAddr::V4(address) => *address.ip(),
            SocketAddr::V6(_) => return Err("Game-stream registration currently requires IPv4".to_owned()),
        };
        let local_port = match socket.local_addr().map_err(|e| e.to_string())? {
            SocketAddr::V4(address) => address.port(),
            SocketAddr::V6(_) => return Err("Game-stream socket did not bind IPv4".to_owned()),
        };
        let previous_timeout = socket.read_timeout().map_err(|e| e.to_string())?;
        let mut mappings = Vec::new();
        for server in resolved_servers.iter().copied() {
            let mapped = crate::services::frd::stun_binding(&socket, server, 0).map(|pair| pair.0);
            socket.set_read_timeout(previous_timeout).map_err(|e| format!("could not restore Game socket timeout: {e}"))?;
            if let Some(SocketAddr::V4(address)) = mapped { mappings.push(address); }
        }
        if mappings.is_empty() { return Err("STUN did not return a public mapping for the bound Game-stream socket".to_owned()); }
        let public_address = mappings[0];
        let mapping_type = if mappings.len() > 1 && mappings.iter().all(|mapping| *mapping == public_address) { 1u8 } else if mappings.len() > 1 { 2u8 } else { 0u8 };
        let local_address = SocketAddrV4::new(local_ip, local_port);
        let station = self.register_game_station_with_mapping(socket, local_address, public_address, mapping_type, 0, timeout)?;
        self.report_nat_properties(u32::from(mapping_type), 0, 0, timeout)?;
        Ok(station)
    }

    /// Register a caller-supplied local/public mapping. The normal application
    /// path should use register_game_station(), which discovers the mapping.
    pub fn register_game_station_with_mapping(
        &mut self,
        socket: UdpSocket,
        local_address: SocketAddrV4,
        public_address: SocketAddrV4,
        nat_mapping: u8,
        nat_filtering: u8,
        timeout: Duration,
    ) -> Result<Station, String> {
        if self.public_game_station.is_some() { return Err("Game station is already registered on this NEX session".to_owned()); }
        if local_address.port() == 0 || public_address.port() == 0 || local_address.ip().is_unspecified() || public_address.ip().is_unspecified() {
            return Err("Game station local/public IPv4 endpoints must be concrete".to_owned());
        }
        if socket.local_addr().map_err(|e| e.to_string())?.port() != local_address.port() {
            return Err("Game station local endpoint port does not match the bound UDP socket".to_owned());
        }
        let mut cid_bytes = [0u8; 4];
        getrandom::fill(&mut cid_bytes).map_err(|e| format!("could not generate Game-stream CID: {e}"))?;
        let mut cid = u32::from_le_bytes(cid_bytes);
        if cid == 0 { cid = 1; }
        let common = format!("sid=1;stream={};PID={};CID={};natm={};natf={}", crate::nex_bootstrap::STREAM_TYPE_GAME, self.principal_id, cid, nat_mapping, nat_filtering);
        let local_url = format!("prudp:/address={};port={};{};type=1", local_address.ip(), local_address.port(), common);
        let public_url = format!("prudp:/address={};port={};{};type=3", public_address.ip(), public_address.port(), common);
        let body = crate::nex_bootstrap::encode_secure_register_ex_request(&[local_url.clone(), public_url], self.local_friend_code, &self.nex_token)?;
        let response = self.request(0x0B, 0x04, &body, timeout)?;
        let (connection_id, public_station) = crate::nex_bootstrap::decode_secure_register_ex_response(&response.body)?;
        let local_station_url = format!("{};RVCID={}", local_url, connection_id);
        let local_station = crate::nex_bootstrap::parse_station_url(&local_station_url)?;
        self.game_socket = Some(socket);
        self.local_game_station = Some(local_station);
        self.public_game_station = Some(public_station.clone());
        Ok(public_station)
    }
    pub fn registered_game_station(&self) -> Option<&Station> { self.public_game_station.as_ref() }

    /// Report the NAT mapping/filtering information to the secure NEX server.
    pub fn report_nat_properties(
        &mut self,
        mapping: u32,
        filtering: u32,
        rtt_ms: u32,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&mapping.to_le_bytes());
        body.extend_from_slice(&filtering.to_le_bytes());
        body.extend_from_slice(&rtt_ms.to_le_bytes());
        let response = self.request(0x03, 0x05, &body, timeout)?;
        if !response.body.is_empty() {
            return Err("NATTraversal::ReportNATProperties returned an unexpected body".to_owned());
        }
        Ok(())
    }

    /// Wait for the server-pushed NATTraversal::InitiateProbe request, acknowledge
    /// its RMC call, and return the peer's StationURL.
    pub fn wait_for_initiate_probe(&mut self, timeout: Duration) -> Result<Station, String> {
        if timeout.is_zero() {
            return Err("waiting for a NAT InitiateProbe requires a positive timeout".to_owned());
        }
        let previous_timeout = self.socket.read_timeout().map_err(|e| e.to_string())?;
        let deadline = std::time::Instant::now() + timeout;
        let result = (|| {
            let push = loop {
                if let Some(queued) = self.session.take_server_push() {
                    break queued;
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err("timed out waiting for server-pushed InitiateProbe".to_owned());
                }
                self.socket.set_read_timeout(Some(remaining))
                    .map_err(|e| format!("could not set NEX push timeout: {e}"))?;
                let Some(packet) = receive_from_server(&self.socket, self.server, &self.ticket.session_key)? else {
                    return Err("timed out waiting for server-pushed InitiateProbe".to_owned());
                };
                if packet.packet_type != 2 || packet.flags & 0x01 != 0 {
                    continue;
                }
                validate_session_packet(
                    &packet,
                    self.session.server_session_id,
                    self.session.source_type,
                    self.session.source_port,
                    self.session.destination_port,
                )?;
                if packet.flags & 0x04 != 0 {
                    let ack = make_data_ack(
                        &packet,
                        self.session.source_type,
                        self.session.source_port,
                        self.session.destination_type,
                        self.session.destination_port,
                    );
                    self.socket.send_to(
                        &encode_prudp_v0(&ack, MK7_PRUDP_ACCESS_KEY, &self.ticket.session_key),
                        self.server,
                    ).map_err(|e| format!("could not acknowledge NEX server push: {e}"))?;
                }
                if packet.flags & 0x02 == 0 {
                    continue;
                }
                let clear = self.incoming_cipher.apply(&packet.payload);
                if crate::prudp_client::is_rmc_request_message(&clear) {
                    break clear;
                }
            };
            let request = decode_rmc_request(&push)?;
            if request.protocol != 0x03 || request.method != 0x02 {
                return Err(format!(
                    "received unsupported NEX server push protocol 0x{:02X}, method 0x{:X}",
                    request.protocol, request.method
                ));
            }
            let mut cursor = 0usize;
            let station_url = decode_nex_string(&request.body, &mut cursor)?;
            if cursor != request.body.len() {
                return Err("InitiateProbe contained unexpected trailing data".to_owned());
            }
            let peer = parse_station_url(&station_url)?;
            if peer.rv_connection_id == 0 {
                return Err("InitiateProbe StationURL omitted RVCID".to_owned());
            }
            let response = encode_rmc_success_response(&request, &[]);
            self.session.send_reliable_oneway(
                &self.socket,
                self.server,
                &response,
                &self.ticket.session_key,
                &mut self.outgoing_cipher,
                &mut self.incoming_cipher,
                timeout,
            )?;
            Ok(peer)
        })();
        let restore = self.socket.set_read_timeout(previous_timeout);
        match (result, restore) {
            (Ok(peer), Ok(())) => Ok(peer),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(format!("NEX probe was processed but socket timeout restore failed: {error}")),
        }
    }

    /// Report the per-peer probe result to the secure server. The MK7 3DS
    /// NEX 2.4.3 signature has CID and Bool only (no newer RTT field).
    pub fn report_nat_traversal_result(
        &mut self,
        peer_rvcid: u32,
        succeeded: bool,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut body = Vec::with_capacity(5);
        body.extend_from_slice(&peer_rvcid.to_le_bytes());
        body.push(u8::from(succeeded));
        let response = self.request(0x03, 0x04, &body, timeout)?;
        if !response.body.is_empty() {
            return Err("NATTraversal::ReportNATTraversalResult returned an unexpected body".to_owned());
        }
        Ok(())
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
        self.register_game_station(timeout)?;
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
        self.register_game_station(timeout)?;
        let body = crate::nex_bootstrap::encode_matchmake_auto_request(criteria, message)?;
        let response = self.request(0x6D, 0x0F, &body, timeout)?;
        crate::nex_bootstrap::decode_matchmake_auto_response(&response.body)
    }

    /// Join a known MK7 3DS gathering.
    ///
    /// The game's NEX 2.4.3 MatchMaking schema acknowledges participation
    /// without returning a per-gathering session key.
    pub fn join_matchmake_session(
        &mut self,
        gathering_id: u32,
        message: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let body = crate::nex_bootstrap::encode_matchmake_join_request(gathering_id, message);
        let response = self.request(0x6D, 0x07, &body, timeout)?;
        if !response.body.is_empty() {
            return Err(format!(
                "MK7 3DS JoinMatchmakeSession returned {} unexpected response bytes",
                response.body.len()
            ));
        }
        Ok(())
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

    /// Ask the NEX server to push InitiateProbe to the named peer connections.
    ///
    /// Target StationURLs must come from GetSessionURLs and contain RVCID.
    /// station_to_probe must be this client's registered Game-stream URL.
    /// This starts the PIA UDP hole-punch; it does not itself establish PRUDP.
    pub fn request_probe_initiation_ext(
        &mut self,
        targets: &[crate::nex_bootstrap::Station],
        station_to_probe: &crate::nex_bootstrap::Station,
        timeout: Duration,
    ) -> Result<(), String> {
        let target_urls = targets
            .iter()
            .map(|station| station.raw_url.clone())
            .collect::<Vec<_>>();
        let body = crate::nex_bootstrap::encode_nat_probe_initiation_ext_request(
            &target_urls,
            &station_to_probe.raw_url,
        )?;
        let _ = self.request(0x03, 0x03, &body, timeout)?;
        Ok(())
    }

    /// Establish the direct Game-stream peer connection after AutoMatchmake.
    /// The auto-match call already joins the caller to the gathering.
    pub fn connect_to_matchmake_host(
        &mut self,
        result: &crate::nex_bootstrap::MatchmakeAutoResult,
        timeout: Duration,
    ) -> Result<GamePeerSession, String> {
        self.connect_to_matchmake_host_with_pia_format(result, timeout, false)
    }

    /// Same as connect_to_matchmake_host, with an explicit PIA 5.11+
    /// variable-ID switch. Use true only when the title's PIA probe protocol
    /// appends CID to its NatProbeData.
    pub fn connect_to_matchmake_host_with_pia_format(
        &mut self,
        result: &crate::nex_bootstrap::MatchmakeAutoResult,
        timeout: Duration,
        include_variable_id: bool,
    ) -> Result<GamePeerSession, String> {
        if result.host_pid == 0 { return Err("automatic matchmaking returned a zero host PID".to_owned()); }
        self.register_game_station(timeout)?;
        let own_station = self.public_game_station.clone()
            .ok_or_else(|| "Game station registration did not produce a public StationURL".to_owned())?;
        let peer_from_gathering = if result.host_pid == self.principal_id {
            None
        } else {
            let stations = self.get_matchmake_session_urls(result.gathering_id, timeout)?;
            let mut candidates = stations.into_iter().filter(|station|
                station.principal_id == result.host_pid && station.stream_type == crate::nex_bootstrap::STREAM_TYPE_GAME
            ).collect::<Vec<_>>();
            let selected = candidates.iter().position(|station| station.is_public()).unwrap_or(0);
            if candidates.is_empty() {
                return Err(format!("GetSessionURLs did not return a Game-stream StationURL for host PID {}", result.host_pid));
            }
            Some(candidates.swap_remove(selected))
        };
        if let Some(peer) = &peer_from_gathering {
            self.request_probe_initiation_ext(std::slice::from_ref(peer), &own_station, timeout)?;
        }
        // The host gets the joining client's StationURL through InitiateProbe;
        // the joiner gets the host's reciprocal StationURL the same way.
        let peer = self.wait_for_initiate_probe(timeout)?;
        if let Some(expected) = &peer_from_gathering {
            if peer.principal_id != expected.principal_id {
                return Err(format!("InitiateProbe came from PID {}, expected host PID {}", peer.principal_id, expected.principal_id));
            }
        }
        let probe_result = {
            let game_socket = self.game_socket.as_ref()
                .ok_or_else(|| "Game UDP socket is not registered".to_owned())?;
            punch_through_nat(game_socket, &own_station, &peer, timeout, include_variable_id)
        };
        match probe_result {
            Ok(_) => self.report_nat_traversal_result(peer.rv_connection_id, true, timeout)?,
            Err(error) => {
                let _ = self.report_nat_traversal_result(peer.rv_connection_id, false, timeout);
                return Err(error);
            }
        }
        let peer_address = resolve_station(&peer)?;
        let game_socket = self.game_socket.take()
            .ok_or_else(|| "Game-stream station was registered without a retained UDP socket".to_owned())?;
        connect_to_peer_with_socket(game_socket, &peer, peer_address, timeout)
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
        PrudpPacket, Rc4, MK7_PRUDP_ACCESS_KEY, STREAM_TYPE_GAME, STREAM_TYPE_RV, STREAM_TYPE_RV_SECURE,
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

            // Register the Game UDP socket before entering a gathering.
            let mut register_response = Vec::new();
            register_response.extend_from_slice(&0u32.to_le_bytes()); // QResult success
            register_response.extend_from_slice(&99u32.to_le_bytes()); // assigned secure connection ID
            encode_nex_string(
                &format!(
                    "prudp:/address=127.0.0.1;port={};sid=1;stream=9;PID=42;CID=99;RVCID=99;natm=0;natf=0;type=3",
                    game_client_address.port()
                ),
                &mut register_response,
            );
            let register_request = test_serve_rmc_call(
                &secure_server, client, session_id, 2, 1, 0x0B, 0x04, 1,
                &server_session_key, &mut incoming_cipher, &mut outgoing_cipher, &register_response,
            );
            let mut register_cursor = 0usize;
            assert_eq!(test_read_u32(&register_request, &mut register_cursor), 2);
            let local_url = decode_nex_string(&register_request, &mut register_cursor).unwrap();
            let public_url = decode_nex_string(&register_request, &mut register_cursor).unwrap();
            assert!(local_url.contains("stream=9"));
            assert!(local_url.contains("type=1"));
            assert!(public_url.contains("type=3"));
            assert!(local_url.contains("natm="));
            assert!(local_url.contains("natf="));
            assert_eq!(decode_nex_string(&register_request, &mut register_cursor).unwrap(), "AccountExtraInfo");
            let total_length = test_read_u32(&register_request, &mut register_cursor) as usize;
            let fields_length = test_read_u32(&register_request, &mut register_cursor) as usize;
            let fields = test_take_buffer(&register_request, &mut register_cursor);
            assert_eq!(total_length, fields_length + 4);
            assert_eq!(fields.len(), fields_length);
            let mut fields_cursor = 0usize;
            assert_ne!(u64::from_le_bytes(fields[fields_cursor..fields_cursor + 8].try_into().unwrap()), 0);
            fields_cursor += 12; // LocalFriendCode + MoveCount
            assert_eq!(decode_nex_string(&fields, &mut fields_cursor).unwrap(), "nex-test-token");

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
                3,
                2,
                0x6D,
                0x0F,
                2,
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
                4,
                3,
                0x6D,
                0x2A,
                3,
                &server_session_key,
                &mut incoming_cipher,
                &mut outgoing_cipher,
                &browse_response,
            );
            assert!(!browse_request.is_empty());

            let mut urls_response = Vec::new();
            urls_response.extend_from_slice(&1u32.to_le_bytes());
            encode_nex_string(
                &format!(
                    "prudp:/address=127.0.0.1;port={};sid=1;stream=9;PID=77;CID=77;RVCID=77;natm=0;natf=0;type=3",
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

            // Joiner requests that the gathering host start the reciprocal PIA probe.
            let mut nat_response = Vec::new(); // successful NATTraversal response is empty
            let nat_request = test_serve_rmc_call(
                &secure_server, client, session_id, 6, 5, 0x03, 0x03, 5,
                &server_session_key, &mut incoming_cipher, &mut outgoing_cipher, &nat_response,
            );
            let mut nat_cursor = 0usize;
            assert_eq!(test_read_u32(&nat_request, &mut nat_cursor), 1);
            let nat_target = decode_nex_string(&nat_request, &mut nat_cursor).unwrap();
            let nat_own = decode_nex_string(&nat_request, &mut nat_cursor).unwrap();
            assert!(nat_target.contains("RVCID=77"));
            assert!(nat_own.contains("RVCID=99"));
            assert_eq!(nat_cursor, nat_request.len());

            // Simulate the host-side NEX connection pushing InitiateProbe back to
            // the joiner. The client must ACK the PRUDP DATA packet and then send
            // the NEX RMC success response for call ID 0xFFFF0005.
            let host_station_url = format!(
                "prudp:/address=127.0.0.1;port={};sid=1;stream=9;PID=77;CID=77;RVCID=77;natm=0;natf=0;type=3",
                game_peer_address.port(),
            );
            let mut push_body = Vec::new();
            encode_nex_string(&host_station_url, &mut push_body);
            let push_rmc = crate::nex_bootstrap::encode_rmc_request(0x03, 0x02, 0xFFFF_0005, &push_body);
            let mut push_ciphertext = outgoing_cipher.apply(&push_rmc);
            let push_packet = PrudpPacket {
                packet_type: TEST_TYPE_DATA,
                flags: TEST_FLAG_RELIABLE | TEST_FLAG_NEED_ACK | TEST_FLAG_HAS_SIZE,
                source_type: STREAM_TYPE_RV_SECURE,
                source_port: 1,
                destination_type: STREAM_TYPE_RV_SECURE,
                destination_port: 1,
                session_id,
                packet_id: 6,
                fragment_id: 0,
                signature: [0; 4],
                connection_signature: [0; 4],
                payload: std::mem::take(&mut push_ciphertext),
            };
            secure_server.send_to(
                &encode_prudp_v0(&push_packet, MK7_PRUDP_ACCESS_KEY, &server_session_key),
                client,
            ).unwrap();
            let mut secure_bytes = [0u8; 65_535];
            let (ack_len, ack_peer) = secure_server.recv_from(&mut secure_bytes).unwrap();
            assert_eq!(ack_peer, SocketAddr::V4(client));
            let push_ack = decode_prudp_v0(&secure_bytes[..ack_len], MK7_PRUDP_ACCESS_KEY, &server_session_key).unwrap();
            assert_eq!(push_ack.flags, TEST_FLAG_ACK);
            assert_eq!(push_ack.packet_id, 6);
            let (reply_len, reply_peer) = secure_server.recv_from(&mut secure_bytes).unwrap();
            assert_eq!(reply_peer, SocketAddr::V4(client));
            let push_reply = decode_prudp_v0(&secure_bytes[..reply_len], MK7_PRUDP_ACCESS_KEY, &server_session_key).unwrap();
            assert_eq!(push_reply.packet_id, 7);
            let push_reply_plain = incoming_cipher.apply(&push_reply.payload);
            let mut push_reply_cursor = 0usize;
            assert_eq!(test_read_u32(&push_reply_plain, &mut push_reply_cursor) as usize, push_reply_plain.len() - 4);
            assert_eq!(push_reply_plain[push_reply_cursor], 0x03);
            push_reply_cursor += 1;
            assert_eq!(push_reply_plain[push_reply_cursor], 1);
            push_reply_cursor += 1;
            assert_eq!(test_read_u32(&push_reply_plain, &mut push_reply_cursor), 0xFFFF_0005);
            assert_eq!(test_read_u32(&push_reply_plain, &mut push_reply_cursor), 0x02 | 0x8000);
            let push_reply_ack = PrudpPacket {
                packet_type: TEST_TYPE_DATA, flags: TEST_FLAG_ACK,
                source_type: STREAM_TYPE_RV_SECURE, source_port: 1,
                destination_type: STREAM_TYPE_RV_SECURE, destination_port: 1,
                session_id, packet_id: 7, fragment_id: 0, signature: [0; 4],
                connection_signature: [0; 4], payload: Vec::new(),
            };
            secure_server.send_to(&encode_prudp_v0(&push_reply_ack, MK7_PRUDP_ACCESS_KEY, &server_session_key), client).unwrap();

            // PIA probes use the registered Game socket. Send the host's
            // simultaneous probe to the joiner's registered public StationURL.
            let local_station = crate::nex_bootstrap::parse_station_url(&nat_own).unwrap();
            let joiner_game_address = SocketAddrV4::new(local_station.address.parse().unwrap(), local_station.port);
            let host_probe_time = 0x1122_3344_5566_7788u64;
            let host_probe = crate::game_peer::encode_pia_nat_probe_data(crate::game_peer::PiaNatProbeData {
                service_variable_id: local_station.rv_connection_id,
                probe_type: 0,
                system_time: host_probe_time,
                variable_id: None,
            }).unwrap();
            game_peer_server.send_to(&host_probe, joiner_game_address).unwrap();
            let mut saw_joiner_request = false;
            let mut saw_joiner_reply = false;
            while !(saw_joiner_request && saw_joiner_reply) {
                let (probe_len, probe_peer) = game_peer_server.recv_from(&mut peer_bytes).unwrap();
                assert_eq!(probe_peer, SocketAddr::V4(joiner_game_address));
                let probe = crate::game_peer::decode_pia_nat_probe_data(&peer_bytes[..probe_len]).unwrap();
                if probe.service_variable_id == 77 && probe.probe_type == 0 {
                    saw_joiner_request = true;
                    let reply = crate::game_peer::encode_pia_nat_probe_data(crate::game_peer::PiaNatProbeData {
                        service_variable_id: local_station.rv_connection_id,
                        probe_type: 1, system_time: probe.system_time, variable_id: None,
                    }).unwrap();
                    game_peer_server.send_to(&reply, joiner_game_address).unwrap();
                } else if probe.service_variable_id == 77 && probe.probe_type == 1 && probe.system_time == host_probe_time {
                    saw_joiner_reply = true;
                }
            }

            // The client reports its successful PIA traversal to NEX.
            let nat_result_response = Vec::new();
            let nat_result_request = test_serve_rmc_call(
                &secure_server, client, session_id, 8, 7, 0x03, 0x04, 6,
                &server_session_key, &mut incoming_cipher, &mut outgoing_cipher, &nat_result_response,
            );
            assert_eq!(test_read_u32(&nat_result_request, &mut 0usize), 77);
            assert_eq!(nat_result_request[4], 1);

            // The Game stream uses the default CD&ML payload key; it has no gathering key.
            let mut peer_bytes = [0u8; 65_535];
            let (peer_client, peer_session_id) =
                test_accept_prudp(&game_peer_server, STREAM_TYPE_GAME, |_| Vec::new());
            let (length, peer_address) = game_peer_server.recv_from(&mut peer_bytes).unwrap();
            assert_eq!(peer_address, SocketAddr::V4(peer_client));
            let peer_request = decode_prudp_v0(
                &peer_bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                b"",
            )
            .unwrap();
            assert_eq!(peer_request.packet_type, TEST_TYPE_DATA);
            assert_eq!(peer_request.session_id, peer_session_id);
            assert_eq!(peer_request.source_type, STREAM_TYPE_GAME);
            assert_eq!(peer_request.destination_type, STREAM_TYPE_GAME);
            let mut game_decrypt = Rc4::new(b"CD&ML").unwrap();
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
                    &encode_prudp_v0(&peer_ack, MK7_PRUDP_ACCESS_KEY, b""),
                    peer_client,
                )
                .unwrap();

            let mut game_encrypt = Rc4::new(b"CD&ML").unwrap();
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
                    &encode_prudp_v0(&peer_response, MK7_PRUDP_ACCESS_KEY, b""),
                    peer_client,
                )
                .unwrap();

            let (length, _) = game_peer_server.recv_from(&mut peer_bytes).unwrap();
            let peer_response_ack = decode_prudp_v0(
                &peer_bytes[..length],
                MK7_PRUDP_ACCESS_KEY,
                b"",
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
        let game_client_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let game_client_address = match game_client_socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => panic!("Game client mock did not bind IPv4"),
        };
        online.register_game_station_with_mapping(
            game_client_socket,
            game_client_address,
            game_client_address,
            0,
            0,
            Duration::from_secs(2),
        ).unwrap();
        let auto_result = online
            .auto_matchmake(
                &MatchmakeSearchCriteria::public(),
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
