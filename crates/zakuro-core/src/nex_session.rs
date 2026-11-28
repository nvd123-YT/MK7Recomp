//! Two-stage NEX authentication and secure-server session setup for Mario Kart 7.

use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::nex_bootstrap::{
    build_secure_connect_payload, decode_client_kerberos_ticket,
    decode_ticket_granting_login_ex_response, encode_ticket_granting_login_ex_body,
    parse_station_url, verify_secure_connect_response, ClientKerberosTicket, RmcResponse,
    Station,
};
use crate::nex_bootstrap::Rc4;
use crate::prudp_client::{
    establish_session, new_payload_ciphers, PrudpSession,
};

const TICKET_GRANTING_PROTOCOL: u8 = 0x0A;
const TICKET_GRANTING_LOGIN_EX: u32 = 0x02;
const MK7_SESSION_KEY_LENGTH: usize = 32;
const CLIENT_VIRTUAL_PORT: u8 = 1;

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

/// Authenticate with the service-locator station and open the returned secure
/// station using the Kerberos ticket supplied by TicketGranting::LoginEx.
///
/// service_station_url is the NEX StationURL returned in FRD SVCLOC.
/// username is the account UID-HMAC; nex_token is the SVCLOC service token.
pub fn connect(
    service_station_url: &str,
    username: &str,
    password: &str,
    principal_id: u32,
    local_friend_code: u64,
    nex_token: &str,
    timeout: Duration,
) -> Result<NexOnlineSession, String> {
    let authentication_station = parse_station_url(service_station_url)?;
    let authentication_address = resolve_station(&authentication_station)?;

    let authentication_socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("could not bind NEX authentication UDP socket: {error}"))?;
    let mut authentication_session = establish_session(
        &authentication_socket,
        authentication_address,
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

    #[test]
    fn station_resolution_rejects_zero_ports_before_dns() {
        let station = Station {
            address: "invalid.invalid".to_owned(),
            port: 0,
            stream_id: 1,
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
            principal_id: 2,
            connection_id: 3,
        };
        assert_eq!(
            resolve_station(&station).unwrap(),
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1234)
        );
    }
}
