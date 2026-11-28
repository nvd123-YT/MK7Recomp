//! NEX 1.1 / PRUDP v0 wire primitives used by Pretendo's 3DS Friends bootstrap.
//! Network orchestration is kept separate so packet and serialization formats
//! can be tested without a real console identity or a live Pretendo account.

use md5::{Digest, Md5};

// Mario Kart 7 uses this key on both its NEX authentication and secure endpoints.
const ACCESS_KEY: &[u8] = b"6181dff1";
pub const MK7_PRUDP_ACCESS_KEY: &[u8] = ACCESS_KEY;
const TYPE_SYN: u8 = 0;
const TYPE_CONNECT: u8 = 1;
const TYPE_DATA: u8 = 2;
const TYPE_DISCONNECT: u8 = 3;
const LEGACY_ACCESS_KEY: &[u8] = b"ridfebb9";
const FLAG_ACK: u8 = 1;
const FLAG_RELIABLE: u8 = 2;
const FLAG_NEED_ACK: u8 = 4;
const FLAG_HAS_SIZE: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmcResponse {
    pub protocol: u8,
    pub call_id: u32,
    pub method: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub address: String,
    pub port: u16,
    pub stream_id: u8,
    pub principal_id: u32,
    pub connection_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrudpPacket {
    pub packet_type: u8,
    pub flags: u8,
    pub source_port: u8,
    pub destination_port: u8,
    pub session_id: u8,
    pub packet_id: u16,
    pub fragment_id: u8,
    /// Four-byte header signature, separate from the SYN/CONNECT connection signature.
    pub signature: [u8; 4],
    pub connection_signature: [u8; 4],
    pub payload: Vec<u8>,
}

#[derive(Clone)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.is_empty() {
            return Err("RC4 key is empty".to_owned());
        }
        let mut state = [0u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0u8;
        for index in 0..256usize {
            j = j.wrapping_add(state[index]).wrapping_add(key[index % key.len()]);
            state.swap(index, j as usize);
        }
        Ok(Self { state, i: 0, j: 0 })
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let position = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
            output.push(*byte ^ self.state[position as usize]);
        }
        output
    }
}

pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&md5_digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(data);
    let mut outer = Vec::with_capacity(80);
    outer.extend(block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&md5_digest(&inner));
    md5_digest(&outer)
}

fn checksum_v0(bytes: &[u8], access_key: &[u8]) -> u8 {
    let mut checksum: u32 = access_key.iter().map(|byte| u32::from(*byte)).sum();
    let full_len = bytes.len() & !3;
    let mut words = 0u32;
    for chunk in bytes[..full_len].chunks_exact(4) {
        words = words.wrapping_add(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    checksum = checksum
        .wrapping_add(words)
        .wrapping_add(bytes[full_len..].iter().map(|byte| u32::from(*byte)).sum::<u32>())
        .wrapping_add(words.to_le_bytes().iter().map(|byte| u32::from(*byte)).sum::<u32>());
    checksum as u8
}

fn data_signature(
    payload: &[u8],
    sequence_id: u16,
    fragment_id: u8,
    access_key: &[u8],
    session_key: &[u8],
) -> [u8; 4] {
    let mut authenticated = Vec::with_capacity(session_key.len() + 3 + payload.len());
    if access_key != LEGACY_ACCESS_KEY {
        authenticated.extend_from_slice(session_key);
        authenticated.extend_from_slice(&sequence_id.to_le_bytes());
        authenticated.push(fragment_id);
    }
    authenticated.extend_from_slice(payload);
    if authenticated.is_empty() {
        return 0x12345678u32.to_le_bytes();
    }
    let digest = hmac_md5(&md5_digest(access_key), &authenticated);
    [digest[0], digest[1], digest[2], digest[3]]
}

pub fn encode_prudp_v0(
    packet: &PrudpPacket,
    access_key: &[u8],
    session_key: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(20 + packet.payload.len());
    output.push(packet.source_port | (10 << 4));
    output.push(packet.destination_port | (10 << 4));
    output.extend_from_slice(&(u16::from(packet.packet_type) | (u16::from(packet.flags) << 4)).to_le_bytes());
    output.push(packet.session_id);
    let signature = match packet.packet_type {
        TYPE_SYN => [0; 4],
        TYPE_DATA => data_signature(
            &packet.payload,
            packet.packet_id,
            packet.fragment_id,
            access_key,
            session_key,
        ),
        TYPE_DISCONNECT if access_key != LEGACY_ACCESS_KEY => data_signature(
            &packet.payload,
            packet.packet_id,
            packet.fragment_id,
            access_key,
            session_key,
        ),
        _ => packet.signature,
    };
    output.extend_from_slice(&signature);
    output.extend_from_slice(&packet.packet_id.to_le_bytes());
    if packet.packet_type == TYPE_SYN || packet.packet_type == TYPE_CONNECT {
        output.extend_from_slice(&packet.connection_signature);
    }
    if packet.packet_type == TYPE_DATA {
        output.push(packet.fragment_id);
    }
    if packet.flags & FLAG_HAS_SIZE != 0 {
        output.extend_from_slice(&(packet.payload.len() as u16).to_le_bytes());
    }
    output.extend_from_slice(&packet.payload);
    let checksum = checksum_v0(&output, access_key);
    output.push(checksum);
    output
}

pub fn decode_prudp_v0(bytes: &[u8], access_key: &[u8], session_key: &[u8]) -> Result<PrudpPacket, String> {
    if bytes.len() < 12 {
        return Err("PRUDP packet is truncated".to_owned());
    }

    let mut cursor = 0usize;
    let source = take(bytes, &mut cursor, 1)?[0];
    let destination = take(bytes, &mut cursor, 1)?[0];
    if source >> 4 != 10 || destination >> 4 != 10 {
        return Err("PRUDP packet used an unexpected transport type".to_owned());
    }

    let type_flags = u16::from_le_bytes(
        take(bytes, &mut cursor, 2)?
            .try_into()
            .map_err(|_| "PRUDP packet omitted its type and flags".to_owned())?,
    );
    let packet_type = (type_flags & 0x0f) as u8;
    let flags = (type_flags >> 4) as u8;
    let session_id = take(bytes, &mut cursor, 1)?[0];
    let signature: [u8; 4] = take(bytes, &mut cursor, 4)?
        .try_into()
        .map_err(|_| "PRUDP packet omitted its signature".to_owned())?;
    let packet_id = u16::from_le_bytes(
        take(bytes, &mut cursor, 2)?
            .try_into()
            .map_err(|_| "PRUDP packet omitted its packet ID".to_owned())?,
    );

    let mut connection_signature = [0u8; 4];
    let fragment_id;
    if packet_type == TYPE_SYN || packet_type == TYPE_CONNECT {
        connection_signature.copy_from_slice(
            take(bytes, &mut cursor, 4)
                .map_err(|_| "PRUDP handshake packet omitted its connection signature".to_owned())?,
        );
        fragment_id = 0;
    } else if packet_type == TYPE_DATA {
        fragment_id = take(bytes, &mut cursor, 1)
            .map_err(|_| "PRUDP data packet omitted its fragment ID".to_owned())?[0];
    } else {
        fragment_id = 0;
    }

    let payload_length = if flags & FLAG_HAS_SIZE != 0 {
        u16::from_le_bytes(
            take(bytes, &mut cursor, 2)?
                .try_into()
                .map_err(|_| "PRUDP packet omitted its payload size".to_owned())?,
        ) as usize
    } else {
        bytes.len()
            .checked_sub(cursor)
            .and_then(|remaining| remaining.checked_sub(1))
            .ok_or_else(|| "PRUDP packet omitted its checksum".to_owned())?
    };
    let end = cursor
        .checked_add(payload_length)
        .ok_or_else(|| "PRUDP payload length overflowed".to_owned())?;
    if end.checked_add(1) != Some(bytes.len()) {
        return Err("PRUDP packet payload length is inconsistent".to_owned());
    }
    if checksum_v0(&bytes[..end], access_key) != bytes[end] {
        return Err("PRUDP packet checksum mismatch".to_owned());
    }
    if (packet_type == TYPE_DATA
        || (packet_type == TYPE_DISCONNECT && access_key != LEGACY_ACCESS_KEY))
        && signature != data_signature(&bytes[cursor..end], packet_id, fragment_id, access_key, session_key)
    {
        return Err("PRUDP packet data signature mismatch".to_owned());
    }

    Ok(PrudpPacket {
        packet_type,
        flags,
        source_port: source & 0x0f,
        destination_port: destination & 0x0f,
        session_id,
        packet_id,
        fragment_id,
        signature,
        connection_signature,
        payload: bytes[cursor..end].to_vec(),
    })
}

pub fn encode_nex_string(value: &str, output: &mut Vec<u8>) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    output.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    output.extend_from_slice(&bytes);
}

pub fn decode_nex_string(data: &[u8], cursor: &mut usize) -> Result<String, String> {
    let length = read_u16(data, cursor)? as usize;
    let bytes = take(data, cursor, length)?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| "NEX string is not valid UTF-8".to_owned())
}

pub fn encode_rmc_request(protocol: u8, method: u32, call_id: u32, body: &[u8]) -> Vec<u8> {
    let payload_length = 1 + 4 + 4 + body.len();
    let mut output = Vec::with_capacity(4 + payload_length);
    output.extend_from_slice(&(payload_length as u32).to_le_bytes());
    output.push(protocol | 0x80);
    output.extend_from_slice(&call_id.to_le_bytes());
    output.extend_from_slice(&method.to_le_bytes());
    output.extend_from_slice(body);
    output
}

pub fn decode_rmc_response(data: &[u8], protocol: u8, method: u32, call_id: u32) -> Result<RmcResponse, String> {
    let mut cursor = 0usize;
    let length = read_u32(data, &mut cursor)? as usize;
    if length != data.len() - 4 {
        return Err("RMC response length did not match its contents".to_owned());
    }
    let response_protocol = *take(data, &mut cursor, 1)?.first().unwrap();
    if response_protocol & 0x80 != 0 || response_protocol & 0x7f != protocol {
        return Err("RMC response used an unexpected protocol ID".to_owned());
    }
    let success = *take(data, &mut cursor, 1)?.first().unwrap() != 0;
    if !success {
        let result = read_u32(data, &mut cursor)?;
        let response_call = read_u32(data, &mut cursor)?;
        return Err(format!("NEX call failed with result 0x{result:08X} (call {response_call})"));
    }
    let response_call = read_u32(data, &mut cursor)?;
    let response_method = read_u32(data, &mut cursor)? & !0x8000;
    if response_call != call_id || response_method != method {
        return Err("RMC response call ID or method ID did not match".to_owned());
    }
    Ok(RmcResponse {
        protocol,
        call_id,
        method,
        body: data[cursor..].to_vec(),
    })
}

pub fn encode_account_extra_info(token: &str) -> Vec<u8> {
    encode_account_extra_info_for_user(0, token)
}

/// Encode the AccountExtraInfo DataHolder used by TicketGranting::LoginEx.
/// The MK7 server's default byte-stream settings do not enable structure
/// headers, so the structure body is written directly inside the DataHolder.
pub fn encode_account_extra_info_for_user(local_friend_code: u64, token: &str) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&local_friend_code.to_le_bytes()); // LocalFriendCode
    fields.extend_from_slice(&0u32.to_le_bytes()); // MoveCount
    encode_nex_string(token, &mut fields);

    let mut holder = Vec::new();
    encode_nex_string("AccountExtraInfo", &mut holder);
    holder.extend_from_slice(&((fields.len() + 4) as u32).to_le_bytes());
    encode_buffer(&fields, &mut holder);
    holder
}

/// Encode the TicketGranting::LoginEx parameters for a 3DS account.
pub fn encode_ticket_granting_login_ex_body(
    username: &str,
    local_friend_code: u64,
    nex_token: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    encode_nex_string(username, &mut body);
    body.extend_from_slice(&encode_account_extra_info_for_user(local_friend_code, nex_token));
    body
}

/// The decrypted client-visible portion of a NEX Kerberos ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKerberosTicket {
    pub session_key: Vec<u8>,
    pub target_principal_id: u32,
    pub internal_data: Vec<u8>,
}

/// TicketGranting::LoginEx data needed to connect to the secure endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketGrantingLogin {
    pub principal_id: u32,
    pub ticket: Vec<u8>,
    pub secure_station: Station,
    pub server_name: String,
}

/// Derive the legacy 3DS Kerberos key used by NEX authentication endpoints.
pub fn derive_kerberos_key(principal_id: u32, password: &[u8]) -> [u8; 16] {
    let iterations = 65_000u32 + principal_id % 1024;
    let mut key = password.to_vec();
    for _ in 0..iterations {
        key = md5_digest(&key).to_vec();
    }
    key.try_into().expect("MD5 always produces a 16-byte key")
}

/// Encrypt a NEX Kerberos payload using RC4 plus an HMAC-MD5 integrity tag.
pub fn kerberos_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut cipher = Rc4::new(key)?;
    let encrypted = cipher.apply(plaintext);
    let checksum = hmac_md5(key, &encrypted);
    let mut output = encrypted;
    output.extend_from_slice(&checksum);
    Ok(output)
}

/// Verify and decrypt a NEX Kerberos payload.
pub fn kerberos_decrypt(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < 16 {
        return Err("Kerberos payload is shorter than its HMAC-MD5 checksum".to_owned());
    }
    let split = payload.len() - 16;
    let (encrypted, checksum) = payload.split_at(split);
    let expected = hmac_md5(key, encrypted);
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(checksum) {
        difference |= left ^ right;
    }
    if difference != 0 {
        return Err("Kerberos payload HMAC-MD5 verification failed".to_owned());
    }
    Ok(Rc4::new(key)?.apply(encrypted))
}

/// Decrypt the LoginEx ticket for the authenticated source account.
pub fn decode_client_kerberos_ticket(
    encrypted_ticket: &[u8],
    principal_id: u32,
    password: &[u8],
    session_key_length: usize,
) -> Result<ClientKerberosTicket, String> {
    let key = derive_kerberos_key(principal_id, password);
    let plaintext = kerberos_decrypt(&key, encrypted_ticket)?;
    let mut cursor = 0usize;
    let session_key = take(&plaintext, &mut cursor, session_key_length)?.to_vec();
    let target_principal_id = read_u32(&plaintext, &mut cursor)?;
    let internal_length = read_u32(&plaintext, &mut cursor)? as usize;
    let internal_data = take(&plaintext, &mut cursor, internal_length)?.to_vec();
    if cursor != plaintext.len() {
        return Err("Kerberos ticket contained unexpected trailing bytes".to_owned());
    }
    Ok(ClientKerberosTicket {
        session_key,
        target_principal_id,
        internal_data,
    })
}

/// Build the two-buffer CONNECT payload expected by a secure NEX endpoint.
pub fn build_secure_connect_payload(
    ticket: &ClientKerberosTicket,
    source_principal_id: u32,
    connection_id: u32,
    check_value: u32,
) -> Result<Vec<u8>, String> {
    let mut request_data = Vec::with_capacity(12);
    request_data.extend_from_slice(&source_principal_id.to_le_bytes());
    request_data.extend_from_slice(&connection_id.to_le_bytes());
    request_data.extend_from_slice(&check_value.to_le_bytes());
    let encrypted_request = kerberos_encrypt(&ticket.session_key, &request_data)?;

    let mut payload = Vec::new();
    encode_buffer(&ticket.internal_data, &mut payload);
    encode_buffer(&encrypted_request, &mut payload);
    Ok(payload)
}

/// Verify the secure endpoint's CONNECT response to the Kerberos check value.
pub fn verify_secure_connect_response(
    response: &[u8],
    check_value: u32,
) -> Result<(), String> {
    let mut cursor = 0usize;
    let length = read_u32(response, &mut cursor)? as usize;
    if length != 4 || response.len() != 8 {
        return Err("secure PRUDP CONNECT response had an unexpected buffer size".to_owned());
    }
    let returned = read_u32(response, &mut cursor)?;
    if returned != check_value.wrapping_add(1) {
        return Err("secure PRUDP CONNECT response check value did not match".to_owned());
    }
    Ok(())
}

/// Parse the successful TicketGranting::LoginEx response body for MK7's
/// default NEX 2.4.3 byte-stream layout.
pub fn decode_ticket_granting_login_ex_response(
    body: &[u8],
    expected_principal_id: u32,
) -> Result<TicketGrantingLogin, String> {
    let mut cursor = 0usize;
    let result = read_u32(body, &mut cursor)?;
    if result & 0x8000_0000 != 0 {
        return Err(format!("TicketGranting::LoginEx failed with result 0x{result:08X}"));
    }
    let principal_id = read_u32(body, &mut cursor)?;
    if principal_id != expected_principal_id {
        return Err(format!(
            "TicketGranting::LoginEx returned principal ID {principal_id}, expected {expected_principal_id}"
        ));
    }
    let ticket_length = read_u32(body, &mut cursor)? as usize;
    let ticket = take(body, &mut cursor, ticket_length)?.to_vec();
    if ticket.is_empty() {
        return Err("TicketGranting::LoginEx returned an empty Kerberos ticket".to_owned());
    }

    // RVConnectionData: station URL, special-protocol list, alternate station
    // URL. The MK7 server uses the default non-structure-header byte stream.
    let station_url = decode_nex_string(body, &mut cursor)?;
    let special_protocol_count = read_u32(body, &mut cursor)? as usize;
    let _special_protocols = take(body, &mut cursor, special_protocol_count)?;
    let _special_station_url = decode_nex_string(body, &mut cursor)?;
    let server_name = decode_nex_string(body, &mut cursor)?;
    if cursor != body.len() {
        return Err("TicketGranting::LoginEx response contained unexpected trailing bytes".to_owned());
    }
    let secure_station = parse_station_url(&station_url)?;
    Ok(TicketGrantingLogin {
        principal_id,
        ticket,
        secure_station,
        server_name,
    })
}

pub fn parse_station_url(value: &str) -> Result<Station, String> {
    let (_, parameters) = value.split_once(":/")
        .ok_or_else(|| "NEX station URL is invalid".to_owned())?;
    let mut fields = std::collections::BTreeMap::new();
    for parameter in parameters.split(';') {
        if let Some((key, value)) = parameter.split_once('=') {
            fields.insert(key, value);
        }
    }
    let get = |key: &str| fields.get(key).copied()
        .ok_or_else(|| format!("NEX station URL omitted {key}"));
    Ok(Station {
        address: get("address")?.to_owned(),
        port: get("port")?.parse().map_err(|_| "NEX station URL port is invalid".to_owned())?,
        stream_id: get("sid")?.parse().map_err(|_| "NEX station URL stream ID is invalid".to_owned())?,
        principal_id: get("PID")?.parse().map_err(|_| "NEX station URL principal ID is invalid".to_owned())?,
        connection_id: get("CID")?.parse().map_err(|_| "NEX station URL connection ID is invalid".to_owned())?,
    })
}

fn encode_buffer(data: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(data.len() as u32).to_le_bytes());
    output.extend_from_slice(data);
}

fn read_u16(data: &[u8], cursor: &mut usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(take(data, cursor, 2)?.try_into().unwrap()))
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(data, cursor, 4)?.try_into().unwrap()))
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(take(data, cursor, 8)?.try_into().unwrap()))
}

fn take<'a>(data: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], String> {
    let end = cursor.checked_add(length).ok_or_else(|| "NEX field length overflowed".to_owned())?;
    if end > data.len() {
        return Err("NEX message was truncated".to_owned());
    }
    let result = &data[*cursor..end];
    *cursor = end;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_standard_test_vector() {
        let mut cipher = Rc4::new(b"Key").unwrap();
        assert_eq!(cipher.apply(b"Plaintext"), [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
    }

    #[test]
    fn rmc_request_has_a_length_prefix_and_request_flag() {
        let request = encode_rmc_request(0x19, 0x1b, 7, &[1, 2, 3]);
        assert_eq!(u32::from_le_bytes(request[..4].try_into().unwrap()), (request.len() - 4) as u32);
        assert_eq!(request[4], 0x99);
        assert_eq!(u32::from_le_bytes(request[5..9].try_into().unwrap()), 7);
    }

    #[test]
    fn rmc_success_response_round_trips() {
        let mut response = Vec::new();
        response.extend_from_slice(&14u32.to_le_bytes());
        response.push(0x19);
        response.push(1);
        response.extend_from_slice(&2u32.to_le_bytes());
        response.extend_from_slice(&(0x1bu32 | 0x8000).to_le_bytes());
        response.extend_from_slice(&99u32.to_le_bytes());
        let parsed = decode_rmc_response(&response, 0x19, 0x1b, 2).unwrap();
        assert_eq!(parsed.body, 99u32.to_le_bytes());
    }

    #[test]
    fn account_extra_info_is_a_typed_data_holder() {
        let bytes = encode_account_extra_info_for_user(0x1122_3344_5566_7788, "friends-nex-token");
        let mut cursor = 0usize;
        assert_eq!(decode_nex_string(&bytes, &mut cursor).unwrap(), "AccountExtraInfo");
        let total = read_u32(&bytes, &mut cursor).unwrap() as usize;
        let length = read_u32(&bytes, &mut cursor).unwrap() as usize;
        let structure = take(&bytes, &mut cursor, length).unwrap();
        assert_eq!(total, length + 4);

        let mut fields = 0usize;
        assert_eq!(read_u64(structure, &mut fields).unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(read_u32(structure, &mut fields).unwrap(), 0);
        assert_eq!(decode_nex_string(structure, &mut fields).unwrap(), "friends-nex-token");
        assert_eq!(fields, structure.len());
        assert_eq!(cursor, bytes.len());
    }
    #[test]
    fn prudp_v0_packet_round_trips() {
        let packet = PrudpPacket {
            packet_type: TYPE_DATA,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            source_port: 1,
            destination_port: 2,
            session_id: 7,
            packet_id: 42,
            fragment_id: 0,
            signature: data_signature(b"test payload", 42, 0, ACCESS_KEY, b"mk7 test session key"),
            connection_signature: [0; 4],
            payload: b"test payload".to_vec(),
        };
        let session_key = b"mk7 test session key";
        let encoded = encode_prudp_v0(&packet, ACCESS_KEY, session_key);
        let decoded = decode_prudp_v0(&encoded, ACCESS_KEY, session_key).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn mario_kart_7_prudp_access_key_matches_its_server_endpoints() {
        assert_eq!(ACCESS_KEY, b"6181dff1");
    }

    #[test]
    fn prudp_data_signature_uses_session_sequence_and_fragment() {
        let payload = b"race packet";
        let session_key = b"mk7 session key";
        let signature = data_signature(payload, 42, 1, ACCESS_KEY, session_key);
        assert_ne!(signature, data_signature(payload, 43, 1, ACCESS_KEY, session_key));
        assert_ne!(signature, data_signature(payload, 42, 2, ACCESS_KEY, session_key));
        assert_ne!(signature, data_signature(payload, 42, 1, ACCESS_KEY, b"other session"));
    }

    #[test]
    fn prudp_legacy_access_key_keeps_the_legacy_payload_signature() {
        let payload = b"legacy payload";
        let signature = data_signature(payload, 42, 1, LEGACY_ACCESS_KEY, b"ignored session");
        let expected = hmac_md5(&md5_digest(LEGACY_ACCESS_KEY), payload);
        assert_eq!(&signature[..], &expected[..4]);
    }

    #[test]
    fn prudp_v0_disconnect_ack_without_optional_fields_is_a_valid_12_byte_packet() {
        let packet = PrudpPacket {
            packet_type: TYPE_DISCONNECT,
            flags: FLAG_ACK,
            source_port: 1,
            destination_port: 2,
            session_id: 3,
            packet_id: 4,
            fragment_id: 0,
            signature: data_signature(&[], 4, 0, ACCESS_KEY, b""),
            connection_signature: [0; 4],
            payload: Vec::new(),
        };
        let encoded = encode_prudp_v0(&packet, ACCESS_KEY, b"");
        assert_eq!(encoded.len(), 12);
        assert_eq!(decode_prudp_v0(&encoded, ACCESS_KEY, b"").unwrap(), packet);
    }

    #[test]
    fn prudp_connect_header_signature_is_separate_from_connection_signature() {
        let packet = PrudpPacket {
            packet_type: TYPE_CONNECT,
            flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
            source_port: 1,
            destination_port: 1,
            session_id: 7,
            packet_id: 1,
            fragment_id: 0,
            signature: [1, 2, 3, 4],
            connection_signature: [5, 6, 7, 8],
            payload: Vec::new(),
        };
        let encoded = encode_prudp_v0(&packet, ACCESS_KEY, b"");
        let decoded = decode_prudp_v0(&encoded, ACCESS_KEY, b"").unwrap();
        assert_eq!(decoded.signature, [1, 2, 3, 4]);
        assert_eq!(decoded.connection_signature, [5, 6, 7, 8]);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn prudp_decoder_rejects_truncated_handshake_signatures() {
        for packet_type in [TYPE_SYN, TYPE_CONNECT] {
            let mut bytes = vec![0u8; 13];
            bytes[0] = 0xA1;
            bytes[1] = 0xA2;
            bytes[2..4].copy_from_slice(&u16::from(packet_type).to_le_bytes());
            assert!(
                decode_prudp_v0(&bytes, ACCESS_KEY, b"test session").is_err(),
                "truncated packet type {packet_type} should be rejected"
            );
        }
    }

    #[test]
    fn prudp_decoder_rejects_a_truncated_payload_size() {
        let mut bytes = vec![0u8; 13];
        bytes[0] = 0xA1;
        bytes[1] = 0xA2;
        let type_flags = u16::from(TYPE_DATA) | (u16::from(FLAG_HAS_SIZE) << 4);
        bytes[2..4].copy_from_slice(&type_flags.to_le_bytes());
        assert!(decode_prudp_v0(&bytes, ACCESS_KEY, b"test session").is_err());
    }

    #[test]
    fn kerberos_key_derivation_matches_the_3ds_legacy_iterations() {
        let derived = derive_kerberos_key(1234, b"test password");
        let mut expected = b"test password".to_vec();
        for _ in 0..(65_000 + 1234 % 1024) {
            expected = md5_digest(&expected).to_vec();
        }
        assert_eq!(derived.as_slice(), expected.as_slice());
    }

    #[test]
    fn kerberos_payload_encrypts_and_checks_its_hmac() {
        let key = b"kerberos session key";
        let encrypted = kerberos_encrypt(key, b"ticket check data").unwrap();
        assert_eq!(kerberos_decrypt(key, &encrypted).unwrap(), b"ticket check data");
        let mut tampered = encrypted;
        tampered[0] ^= 1;
        assert!(kerberos_decrypt(key, &tampered).is_err());
    }

    #[test]
    fn secure_connect_payload_has_the_two_kerberos_buffers() {
        let ticket = ClientKerberosTicket {
            session_key: b"session key for secure connect".to_vec(),
            target_principal_id: 2,
            internal_data: b"encrypted server ticket".to_vec(),
        };
        let payload = build_secure_connect_payload(&ticket, 1234, 77, 0x12345678).unwrap();
        let mut cursor = 0usize;
        let internal_length = read_u32(&payload, &mut cursor).unwrap() as usize;
        assert_eq!(take(&payload, &mut cursor, internal_length).unwrap(), b"encrypted server ticket");
        let encrypted_length = read_u32(&payload, &mut cursor).unwrap() as usize;
        let encrypted = take(&payload, &mut cursor, encrypted_length).unwrap();
        let decrypted = kerberos_decrypt(&ticket.session_key, encrypted).unwrap();
        assert_eq!(&decrypted[..4], &1234u32.to_le_bytes());
        assert_eq!(&decrypted[4..8], &77u32.to_le_bytes());
        assert_eq!(&decrypted[8..12], &0x12345678u32.to_le_bytes());
        assert_eq!(cursor, payload.len());
    }

    #[test]
    fn secure_connect_response_validates_the_incremented_check_value() {
        let mut response = Vec::new();
        encode_buffer(&0x12345679u32.to_le_bytes(), &mut response);
        verify_secure_connect_response(&response, 0x12345678).unwrap();
        assert!(verify_secure_connect_response(&response, 0x12345677).is_err());
    }

    #[test]
    fn ticket_granting_login_ex_response_yields_secure_station_and_ticket() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // successful QResult
        body.extend_from_slice(&42u32.to_le_bytes());
        encode_buffer(b"client ticket", &mut body);
        encode_nex_string(
            "prudp:/address=127.0.0.1;port=1234;sid=1;PID=2;CID=77;stream=1;type=1",
            &mut body,
        );
        body.extend_from_slice(&0u32.to_le_bytes()); // special protocol count
        encode_nex_string("", &mut body);
        encode_nex_string("MK7 server", &mut body);

        let result = decode_ticket_granting_login_ex_response(&body, 42).unwrap();
        assert_eq!(result.principal_id, 42);
        assert_eq!(result.ticket, b"client ticket");
        assert_eq!(result.server_name, "MK7 server");
        assert_eq!(result.secure_station.address, "127.0.0.1");
        assert_eq!(result.secure_station.port, 1234);
        assert_eq!(result.secure_station.principal_id, 2);
        assert_eq!(result.secure_station.connection_id, 77);
    }

    #[test]
    fn ticket_granting_login_ex_body_encodes_account_extra_info() {
        let body = encode_ticket_granting_login_ex_body("AB12CD34", 0x1122, "service-token");
        let mut cursor = 0usize;
        assert_eq!(decode_nex_string(&body, &mut cursor).unwrap(), "AB12CD34");
        let data_holder = &body[cursor..];
        let mut holder_cursor = 0usize;
        assert_eq!(decode_nex_string(data_holder, &mut holder_cursor).unwrap(), "AccountExtraInfo");
        assert!(data_holder.len() > holder_cursor);
    }

    #[test]
    fn station_url_parser_extracts_secure_server_fields() {
        let station = parse_station_url("prudp:/address=127.0.0.1;port=1234;sid=1;PID=2;CID=3;type=1").unwrap();
        assert_eq!(station.address, "127.0.0.1");
        assert_eq!(station.port, 1234);
        assert_eq!(station.stream_id, 1);
        assert_eq!(station.principal_id, 2);
        assert_eq!(station.connection_id, 3);
    }
}
