//! NEX 1.1 / PRUDP v0 wire primitives used by Pretendo's 3DS Friends bootstrap.
//! Network orchestration is kept separate so packet and serialization formats
//! can be tested without a real console identity or a live Pretendo account.

use md5::{Digest, Md5};

// Mario Kart 7 uses this key on both its NEX authentication and secure endpoints.
const ACCESS_KEY: &[u8] = b"6181dff1";
const TYPE_SYN: u8 = 0;
const TYPE_CONNECT: u8 = 1;
const TYPE_DATA: u8 = 2;
const TYPE_ACK: u8 = 3;
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
        TYPE_CONNECT => packet.connection_signature,
        TYPE_DATA => data_signature(
            &packet.payload,
            packet.packet_id,
            packet.fragment_id,
            access_key,
            session_key,
        ),
        _ => [0; 4],
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
    if packet_type == TYPE_DATA && signature != data_signature(&bytes[cursor..end], packet_id, fragment_id, access_key, session_key) {
        return Err("PRUDP data signature mismatch".to_owned());
    }

    Ok(PrudpPacket {
        packet_type,
        flags,
        source_port: source & 0x0f,
        destination_port: destination & 0x0f,
        session_id,
        packet_id,
        fragment_id,
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
    let mut fields = Vec::new();
    fields.extend_from_slice(&0u64.to_le_bytes()); // LocalFriendCode
    fields.extend_from_slice(&0u32.to_le_bytes()); // MoveCount
    encode_nex_string(token, &mut fields);

    // NEX 1.1 structure header: version byte followed by a length-prefixed body.
    let mut structure = vec![0u8];
    encode_buffer(&fields, &mut structure);

    let mut holder = Vec::new();
    encode_nex_string("AccountExtraInfo", &mut holder);
    holder.extend_from_slice(&((structure.len() + 4) as u32).to_le_bytes());
    encode_buffer(&structure, &mut holder);
    holder
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
        let bytes = encode_account_extra_info("friends-nasc-token");
        let mut cursor = 0usize;
        assert_eq!(decode_nex_string(&bytes, &mut cursor).unwrap(), "AccountExtraInfo");
        let total = read_u32(&bytes, &mut cursor).unwrap() as usize;
        let length = read_u32(&bytes, &mut cursor).unwrap() as usize;
        let structure = take(&bytes, &mut cursor, length).unwrap();
        assert_eq!(total, length + 4);
        assert_eq!(structure[0], 0);
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
    fn prudp_v0_ack_without_optional_fields_is_a_valid_12_byte_packet() {
        let packet = PrudpPacket {
            packet_type: TYPE_ACK,
            flags: 0,
            source_port: 1,
            destination_port: 2,
            session_id: 3,
            packet_id: 4,
            fragment_id: 0,
            connection_signature: [0; 4],
            payload: Vec::new(),
        };
        let encoded = encode_prudp_v0(&packet, ACCESS_KEY, b"");
        assert_eq!(encoded.len(), 12);
        assert_eq!(decode_prudp_v0(&encoded, ACCESS_KEY, b"").unwrap(), packet);
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
    fn station_url_parser_extracts_secure_server_fields() {
        let station = parse_station_url("prudp:/address=127.0.0.1;port=1234;sid=1;PID=2;CID=3;type=1").unwrap();
        assert_eq!(station.address, "127.0.0.1");
        assert_eq!(station.port, 1234);
        assert_eq!(station.stream_id, 1);
        assert_eq!(station.principal_id, 2);
        assert_eq!(station.connection_id, 3);
    }
}
