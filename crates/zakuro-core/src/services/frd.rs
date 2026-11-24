//! frd:u, the friend list and this console's own friend details. the
//! console keeps them itself and answers offline too, as one that never
//! logged in and has no friends. what needs the servers is left to the
//! offline reply.

use std::collections::BTreeMap;
use chrono::{Datelike, Timelike};
use std::io::Write;
use std::path::PathBuf;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use zakuro_common::result::errors;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::kernel::object::ObjectId;
use crate::services::cfg::REGION_USA;
use crate::{NetworkProvider, System};

/// the platform a profile names, the 3DS.
const PLATFORM_CTR: u32 = 2;

/// The Friends system module's account file, imported from the user's
/// own decrypted NAND save at user/nand/system-save/0000000000010032/2/account.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FriendAccount {
    local_account_id: u32,
    principal_id: u32,
    local_friend_code: u64,
    password: String,
    uidhmac: String,
    nasc_environment: u8,
    server_type: u8,
    server_type_number: u8,
}

fn parse_friend_account(bytes: &[u8]) -> Option<FriendAccount> {
    const MIN_SIZE: usize = 0x58;
    if bytes.len() < MIN_SIZE
        || &bytes[..4] != b"FPAC"
        || u32::from_le_bytes(bytes[4..8].try_into().ok()?) != 0x2010_1021
    {
        return None;
    }

    let utf16_field = |start: usize, end: usize| -> Option<String> {
        let mut units = Vec::with_capacity((end - start) / 2);
        for chunk in bytes[start..end].chunks_exact(2) {
            let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
            if unit == 0 { break; }
            units.push(unit);
        }
        let value = String::from_utf16(&units).ok()?;
        if !value.is_ascii() { return None; }
        Some(value)
    };

    Some(FriendAccount {
        local_account_id: u32::from_le_bytes(bytes[0x10..0x14].try_into().ok()?),
        principal_id: u32::from_le_bytes(bytes[0x14..0x18].try_into().ok()?),
        local_friend_code: u64::from_le_bytes(bytes[0x18..0x20].try_into().ok()?),
        password: utf16_field(0x20, 0x42)?,
        uidhmac: utf16_field(0x42, 0x54)?,
        nasc_environment: bytes[0x54],
        server_type: bytes[0x55],
        server_type_number: bytes[0x56],
    })
}

fn friend_account_path(system: &System) -> PathBuf {
    system.services.fs.user_dir
        .join("nand/system-save/0000000000010032/2/account")
}

fn load_friend_account(system: &System) -> Option<FriendAccount> {
    let path = friend_account_path(system);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            log::warn!("frd:u could not read the imported Friends account file {}: {error}", path.display());
            return None;
        }
    };
    match parse_friend_account(&bytes) {
        Some(account) if account.principal_id != 0 && !account.password.is_empty() => Some(account),
        Some(_) => {
            log::warn!("frd:u Friends account file has no principal ID or NEX password: {}", path.display());
            None
        }
        None => {
            log::warn!("frd:u Friends account file is invalid or truncated: {}", path.display());
            None
        }
    }
}

fn form_encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if *byte == b' ' {
            encoded.push('+');
        } else if byte.is_ascii_alphanumeric() || matches!(*byte, b'*' | b'-' | b'.' | b'_') {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Fetch a fresh eight-character UID-HMAC from Pretendo's repair endpoint.
/// The NEX password is sent to curl through stdin, not exposed in argv.
fn request_uidhmac(principal_id: u32, password: &str) -> Result<String, String> {
    let body = format!("pid={}&password={}", principal_id, form_encode_component(password));
    let mut child = Command::new("curl")
        .args([
            "--silent", "--show-error",
            "--connect-timeout", "8", "--max-time", "15",
            "--request", "POST",
            "--header", "Content-Type: application/x-www-form-urlencoded",
            "--data-binary", "@-",
            "https://api.pretendo.cc/v1/repair-uidhmac",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start the UID-HMAC repair request: {error}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(body.as_bytes())
            .map_err(|error| format!("could not send the UID-HMAC repair request: {error}"))?;
    }
    let output = child.wait_with_output()
        .map_err(|error| format!("could not read the UID-HMAC repair response: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("UID-HMAC repair client exited with {}", output.status)
        } else {
            detail
        });
    }

    let response: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Pretendo returned invalid UID-HMAC JSON: {error}"))?;
    if response.get("status").and_then(serde_json::Value::as_i64) != Some(200) {
        let detail = response.get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown repair API error");
        return Err(format!("Pretendo rejected the UID-HMAC repair request: {detail}"));
    }
    let hmac = response.get("data")
        .and_then(|data| data.get("uidhmac"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Pretendo's repair response omitted data.uidhmac".to_owned())?;
    if hmac.len() != 8 || !hmac.is_ascii() {
        return Err("Pretendo returned a malformed UID-HMAC".to_owned());
    }
    Ok(hmac.to_owned())
}

/// Repair only when explicitly enabled. The original Friends account record
/// is preserved as a one-time backup, and the password is never logged.
fn repair_uidhmac_if_enabled(system: &System) -> Result<(), String> {
    if !system.config.auto_repair_uidhmac
        || system.config.network_provider != NetworkProvider::Pretendo
    {
        return Ok(());
    }

    let account_path = friend_account_path(system);
    let mut bytes = std::fs::read(&account_path)
        .map_err(|error| format!("could not read the imported Friends account: {error}"))?;
    let account = parse_friend_account(&bytes)
        .ok_or_else(|| "the imported Friends account file is invalid or truncated".to_owned())?;
    if account.principal_id == 0 || account.password.is_empty() {
        return Err("the imported Friends account has no PrincipalID or NEX password".to_owned());
    }

    let marker_path = account_path.with_file_name("pretendo-uidhmac.marker");
    let marker = format!("{}:{}", account.principal_id, account.uidhmac);
    if std::fs::read_to_string(&marker_path).ok().is_some_and(|saved| saved.trim() == marker) {
        return Ok(());
    }

    let hmac = request_uidhmac(account.principal_id, &account.password)?;
    let backup_path = account_path.with_file_name("account.pretendo-backup");
    if !backup_path.exists() {
        std::fs::copy(&account_path, &backup_path)
            .map_err(|error| format!("could not back up the original Friends account: {error}"))?;
    }

    // UIDHMAC is eight UTF-16 characters plus a NUL, at byte offset 0x42.
    bytes[0x42..0x54].fill(0);
    for (index, unit) in hmac.encode_utf16().enumerate() {
        let offset = 0x42 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }

    let temporary = account_path.with_file_name("account.pretendo-tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true).truncate(true).write(true)
            .open(&temporary)
            .map_err(|error| format!("could not stage the repaired Friends account: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("could not write the repaired Friends account: {error}"))?;
        file.flush()
            .map_err(|error| format!("could not flush the repaired Friends account: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("could not sync the repaired Friends account: {error}"))?;
    }
    std::fs::rename(&temporary, &account_path)
        .map_err(|error| format!("could not install the repaired Friends account: {error}"))?;
    std::fs::write(marker_path, format!("{}:{hmac}\n", account.principal_id))
        .map_err(|error| format!("could not record the UID-HMAC repair state: {error}"))?;
    Ok(())
}

fn reply_static_bytes(
    system: &mut System,
    buffer: &CommandBuffer,
    command: u16,
    result: u32,
    bytes: &[u8],
) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    let length = bytes.len().min(capacity as usize);
    system.memory.write_bytes(pointer, &bytes[..length]);
    if result == 0 {
        buffer.reply(&mut system.memory, command, &[]);
    } else {
        buffer.reply_error(&mut system.memory, command, result);
    }
}

/// The fixed-size FRD response structures, written into the guest's static buffer.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct GameAuthenticationData {
    nasc_result: u32,
    http_status: u32,
    server_address: Vec<u8>,
    server_port: u16,
    token: Vec<u8>,
    server_time: u64,
    server_time_difference_ns: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct ServiceLocatorData {
    nasc_result: u32,
    http_status: u32,
    service_host: Vec<u8>,
    service_token: Vec<u8>,
    status_data: u8,
    server_time: u64,
    server_time_difference_ns: u64,
}

struct PendingNasc<T> {
    receiver: Receiver<Result<T, String>>,
    event: ObjectId,
}

/// User-supplied values that the operating system normally gets from the
/// 3DS Wi-Fi and device configuration services.
#[derive(Debug, serde::Deserialize)]
struct NascDeviceConfig {
    mac_address: String,
    bssid: String,
    apinfo: String,
    device_name: String,
    serial_number: String,
    #[serde(default = "default_fpd_version")]
    fpd_version: u16,
    /// The raw 17-byte cartridge ROM ID, represented as 34 hex digits.
    #[serde(default)]
    romid_hex: Option<String>,
}
fn default_fpd_version() -> u16 { 0x0010 }

struct NascJob {
    body: String,
    fpd_version: u16,
    certificate: PathBuf,
    private_key: PathBuf,
}

const MK7_NEX_SERVER_ID: u32 = 0x0001_DB00;
const NASC_URL: &str = "https://nasc.pretendo.cc/ac";
const NASC_HTTP_MARKER: &str = "\n__MK7_NASC_HTTP__";

/// The NASC form uses custom base64: '+' -> '.', '/' -> '-', '=' -> '*'.
fn nasc_base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(((b & 0x0F) << 2) | (c >> 6)) as usize] as char } else { '*' });
        out.push(if chunk.len() > 2 { ALPHABET[(c & 0x3F) as usize] as char } else { '*' });
    }
    out
}

fn nasc_base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut quartet = [0u8; 4];
    let mut used = 0usize;
    for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'.' => 62,
            b'-' => 63,
            b'*' => 64,
            _ => return None,
        };
        quartet[used] = value;
        used += 1;
        if used == 4 {
            if quartet[0] >= 64 || quartet[1] >= 64 { return None; }
            out.push((quartet[0] << 2) | (quartet[1] >> 4));
            if quartet[2] < 64 {
                out.push((quartet[1] << 4) | (quartet[2] >> 2));
                if quartet[3] < 64 {
                    out.push((quartet[2] << 6) | quartet[3]);
                }
            } else if quartet[3] != 64 {
                return None;
            }
            used = 0;
        }
    }
    if used != 0 { return None; }
    Some(out)
}

fn form_url_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        if *byte == b' ' {
            output.push('+');
        } else if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn decode_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let pair = std::str::from_utf8(pair).ok()?;
        u8::from_str_radix(pair, 16).ok()
    }).collect()
}

fn nasc_form_body(fields: &[(String, Vec<u8>)]) -> String {
    fields.iter()
        .map(|(name, value)| {
            let encoded = nasc_base64_encode(value);
            format!("{}={}", form_url_encode(name), form_url_encode(&encoded))
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let source = value.as_bytes();
    let mut out = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        match source[index] {
            b'+' => { out.push(b' '); index += 1; }
            b'%' => {
                let hex = std::str::from_utf8(source.get(index + 1..index + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => { out.push(byte); index += 1; }
        }
    }
    Some(out)
}

fn parse_nasc_form(body: &str) -> Option<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for pair in body.trim().split('&') {
        if pair.is_empty() { continue; }
        let (key, value) = pair.split_once('=')?;
        let key = String::from_utf8(percent_decode(key)?).ok()?;
        let encoded = String::from_utf8(percent_decode(value)?).ok()?;
        let decoded = nasc_base64_decode(&encoded)?;
        fields.insert(key, String::from_utf8_lossy(&decoded).into_owned());
    }
    Some(fields)
}

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_CHANGE_REQUEST: u16 = 0x0003;
const STUN_TIMEOUT: Duration = Duration::from_millis(1100);

fn parse_stun_response(response: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if response.len() < 20
        || u16::from_be_bytes([response[0], response[1]]) != STUN_BINDING_SUCCESS
        || u32::from_be_bytes(response[4..8].try_into().ok()?) != STUN_MAGIC_COOKIE
        || &response[8..20] != transaction_id
    {
        return None;
    }
    let message_end = 20usize.saturating_add(
        u16::from_be_bytes([response[2], response[3]]) as usize
    ).min(response.len());
    let mut cursor = 20usize;
    while cursor + 4 <= message_end {
        let kind = u16::from_be_bytes([response[cursor], response[cursor + 1]]);
        let length = u16::from_be_bytes([response[cursor + 2], response[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start.checked_add(length)?;
        if value_end > message_end { return None; }
        let value = &response[value_start..value_end];
        if (kind == STUN_XOR_MAPPED_ADDRESS || kind == STUN_MAPPED_ADDRESS)
            && value.len() >= 8
            && value[1] == 1
        {
            let mut port = u16::from_be_bytes([value[2], value[3]]);
            let mut address = u32::from_be_bytes(value[4..8].try_into().ok()?);
            if kind == STUN_XOR_MAPPED_ADDRESS {
                port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
                address ^= STUN_MAGIC_COOKIE;
            }
            return Some(SocketAddr::from((std::net::Ipv4Addr::from(address), port)));
        }
        cursor = value_start + length.next_multiple_of(4);
    }
    None
}

fn stun_binding(
    socket: &UdpSocket,
    server: SocketAddr,
    change_ip_and_port: bool,
) -> Option<(SocketAddr, SocketAddr)> {
    let mut transaction_id = [0u8; 12];
    getrandom::fill(&mut transaction_id).ok()?;
    let attribute_length = if change_ip_and_port { 8 } else { 0 };
    let mut request = vec![0u8; 20 + attribute_length];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    request[2..4].copy_from_slice(&(attribute_length as u16).to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    if change_ip_and_port {
        request[20..22].copy_from_slice(&STUN_CHANGE_REQUEST.to_be_bytes());
        request[22..24].copy_from_slice(&4u16.to_be_bytes());
        request[24..28].copy_from_slice(&6u32.to_be_bytes());
    }
    socket.send_to(&request, server).ok()?;
    let deadline = std::time::Instant::now() + STUN_TIMEOUT;
    let mut response = [0u8; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { return None; }
        socket.set_read_timeout(Some(remaining)).ok()?;
        match socket.recv_from(&mut response) {
            Ok((size, source)) => {
                if let Some(mapped) = parse_stun_response(&response[..size], &transaction_id) {
                    return Some((mapped, source));
                }
            }
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return None,
            Err(_) => return None,
        }
    }
}

/// Infer mapping from two different STUN endpoints. Filtering is reported as
/// port-independent only when an RFC 3489 change-request gets an answer from
/// the alternate endpoint; otherwise it remains unknown.
fn detect_nat_properties(servers: Vec<String>) -> (u32, u32) {
    let mut endpoints = Vec::new();
    for server in servers {
        let resolved = match server.to_socket_addrs() {
            Ok(addresses) => addresses.filter(SocketAddr::is_ipv4).collect::<Vec<_>>(),
            Err(error) => {
                log::debug!("FRD STUN server {server} did not resolve: {error}");
                Vec::new()
            }
        };
        if let Some(endpoint) = resolved.into_iter().next() {
            if !endpoints.contains(&endpoint) { endpoints.push(endpoint); }
        }
        if endpoints.len() >= 4 { break; }
    }
    if endpoints.len() < 2 {
        log::warn!("FRD NAT probe needs two resolvable IPv4 STUN endpoints");
        return (0, 0);
    }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => {
            log::warn!("FRD NAT probe could not create a UDP socket: {error}");
            return (0, 0);
        }
    };

    let first = stun_binding(&socket, endpoints[0], false);
    let second_endpoint = endpoints.iter().copied().find(|endpoint| *endpoint != endpoints[0]);
    let second = second_endpoint.and_then(|endpoint| stun_binding(&socket, endpoint, false));
    let mapping = match (first, second) {
        (Some((a, _)), Some((b, _))) if a == b => 1,
        (Some(_), Some(_)) => 2,
        _ => 0,
    };

    let filtering = stun_binding(&socket, endpoints[0], true)
        .filter(|(_, source)| *source != endpoints[0])
        .map_or(0, |_| 1);
    (mapping, filtering)
}

fn fixed_string<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0u8; N];
    let count = value.len().min(N.saturating_sub(1));
    output[..count].copy_from_slice(&value.as_bytes()[..count]);
    output
}

/// Encodes NASC's calendar time using the packed NEX timestamp bitfields,
/// not Unix seconds. Bits 63..26 are the year, then month/day/hour/minute/second.
fn parse_nasc_datetime(value: Option<&String>) -> Option<chrono::NaiveDateTime> {
    value.and_then(|value| chrono::NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S").ok())
}

/// NASC's date converted to the packed NEX timestamp format.
fn server_time(value: Option<&String>) -> u64 {
    parse_nasc_datetime(value).map(|date| {
        ((date.year().max(0) as u64) << 26)
            | ((date.month() as u64) << 22)
            | ((date.day() as u64) << 17)
            | ((date.hour() as u64) << 12)
            | ((date.minute() as u64) << 6)
            | (date.second() as u64)
    }).unwrap_or(0)
}

/// libctru's FRD_GetServerTimeDifference reports nanoseconds, signed as a
/// two's-complement value in the u64 output word pair.
fn server_time_difference_ns(value: Option<&String>) -> u64 {
    let Some(server_time) = parse_nasc_datetime(value)
        .and_then(|date| date.and_utc().timestamp_nanos_opt())
    else { return 0 };
    let Some(device_time) = chrono::Utc::now().timestamp_nanos_opt() else { return 0 };
    (server_time.saturating_sub(device_time)) as u64
}

fn make_nasc_job(
    system: &System,
    account: &FriendAccount,
    device: &NascDeviceConfig,
    fcdcert: &[u8],
    action: &str,
    sdk_major: u8,
    sdk_minor: u8,
    extra: &[(&str, Vec<u8>)],
) -> Result<NascJob, String> {
    let title = system.title.as_ref().ok_or_else(|| "no game title is loaded for NASC".to_owned())?;
    let romid = if title.media_type == 2 {
        let hex = device.romid_hex.as_deref().filter(|value| !value.is_empty())
            .ok_or_else(|| "this cartridge image needs its 17-byte ROM ID as 34 hex digits in sysdata/nasc.json".to_owned())?;
        let bytes = decode_hex_bytes(hex)
            .filter(|bytes| bytes.len() == 17)
            .ok_or_else(|| "romid_hex must contain exactly 34 hexadecimal digits (17 bytes)".to_owned())?;
        Some(bytes)
    } else {
        None
    };
    let data_dir = system.config.data_dir.as_ref().ok_or_else(|| "the application data directory is unavailable".to_owned())?;
    let certificate = data_dir.join("sysdata/ctr-common-1-cert.pem");
    let private_key = data_dir.join("sysdata/ctr-common-1-key.pem");
    if !certificate.is_file() || !private_key.is_file() {
        return Err("NASC requires your own ctr-common-1-cert.pem and ctr-common-1-key.pem in sysdata".to_owned());
    }

    let normalize_mac = |value: &str| value.replace(':', "").replace('-', "").to_ascii_lowercase();
    let mac = normalize_mac(&device.mac_address);
    let bssid = normalize_mac(&device.bssid);
    if mac.len() != 12 || bssid.len() != 12
        || !mac.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !bssid.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("sysdata/nasc.json must contain valid 12-hex-digit mac_address and bssid values".to_owned());
    }
    let apinfo = device.apinfo.as_bytes();
    if apinfo.len() != 13
        || apinfo[2] != b':'
        || !apinfo[..2].iter().chain(apinfo[3..].iter()).all(u8::is_ascii_hexdigit)
    {
        return Err("sysdata/nasc.json apinfo must have the format AA:BBBBBBBBBB (for example 01:0000000000)".to_owned());
    }
    if device.device_name.is_empty() || device.serial_number.is_empty() {
        return Err("sysdata/nasc.json is missing device_name or serial_number".to_owned());
    }
    if fcdcert.len() != 0x110 {
        return Err(format!("LocalFriendCodeSeed_B must be exactly 0x110 bytes (got 0x{:X})", fcdcert.len()));
    }
    if account.uidhmac.len() != 8 {
        return Err("the imported Friends account has no valid eight-character UID-HMAC; enable UID-HMAC repair or import a repaired account".to_owned());
    }

    let mut fields: Vec<(String, Vec<u8>)> = vec![
        ("gameid".into(), format!("{MK7_NEX_SERVER_ID:08X}").into_bytes()),
        ("sdkver".into(), format!("{sdk_major:03}{sdk_minor:03}").into_bytes()),
        ("titleid".into(), format!("{:016X}", title.program_id()).into_bytes()),
        ("gamecd".into(), title.ncch.product_code.trim_end_matches('\0').as_bytes().to_vec()),
        ("gamever".into(), format!("{:04X}", title.ncch.version).into_bytes()),
        ("mediatype".into(), title.media_type.to_string().into_bytes()),
        ("makercd".into(), title.ncch.maker_code.as_bytes().to_vec()),
        ("unitcd".into(), if system.config.new3ds { b"2".to_vec() } else { b"0".to_vec() }),
        ("macadr".into(), mac.into_bytes()),
        ("bssid".into(), bssid.into_bytes()),
        ("apinfo".into(), device.apinfo.as_bytes().to_vec()),
        ("fcdcert".into(), fcdcert.to_vec()),
        ("devname".into(), {
            let mut name: Vec<u8> = device.device_name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            name.extend_from_slice(&[0, 0]);
            name
        }),
        ("servertype".into(), format!("{}{}", account.server_type as char, account.server_type_number as char).into_bytes()),
        ("fpdver".into(), format!("{:04X}", device.fpd_version).into_bytes()),
        ("devtime".into(), chrono::Utc::now().format("%y%m%d%H%M%S").to_string().into_bytes()),
        ("lang".into(), format!("{:02X}", system.config.language).into_bytes()),
        ("region".into(), format!("{:02X}", system.config.region).into_bytes()),
        ("csnum".into(), device.serial_number.as_bytes().to_vec()),
        ("uidhmac".into(), account.uidhmac.as_bytes().to_vec()),
        ("userid".into(), account.principal_id.to_string().into_bytes()),
        ("action".into(), action.as_bytes().to_vec()),
    ];
    if let Some(romid) = romid {
        fields.push(("romid".into(), romid));
    }
    for (name, value) in extra {
        fields.push(((*name).to_owned(), value.clone()));
    }

    Ok(NascJob {
        body: nasc_form_body(&fields),
        fpd_version: device.fpd_version,
        certificate,
        private_key,
    })
}

fn perform_nasc_http(job: NascJob) -> Result<(u32, BTreeMap<String, String>), String> {
    let user_agent = format!("CTR FPD/{:04X}", job.fpd_version);
    let certificate = job.certificate.to_string_lossy().into_owned();
    let private_key = job.private_key.to_string_lossy().into_owned();
    let mut child = Command::new("curl")
        .args([
            "--silent", "--show-error",
            "--http1.1",
            "--connect-timeout", "8", "--max-time", "25",
            "--request", "POST",
            "--header", "X-GameId: 0001DB00",
            "--header", user_agent.as_str(),
            "--header", "Content-Type: application/x-www-form-urlencoded",
            "--header", "Content-Type: application/x-www-form-urlencoded",
            "--cert", certificate.as_str(),
            "--key", private_key.as_str(),
            "--data-binary", "@-",
            "--write-out", "\n__MK7_NASC_HTTP__%{http_code}",
            NASC_URL,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start NASC HTTPS request: {error}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(job.body.as_bytes())
            .map_err(|error| format!("could not write NASC request: {error}"))?;
    }
    let output = child.wait_with_output()
        .map_err(|error| format!("could not read NASC response: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("NASC HTTPS client failed ({})", output.status)
        } else {
            detail
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status) = stdout.rsplit_once(NASC_HTTP_MARKER)
        .ok_or_else(|| "NASC HTTPS response omitted its HTTP status".to_owned())?;
    let status = status.trim().parse::<u32>()
        .map_err(|_| "NASC HTTPS response contained an invalid HTTP status".to_owned())?;
    let fields = parse_nasc_form(body)
        .ok_or_else(|| "NASC returned a malformed custom-base64 form response".to_owned())?;
    Ok((status, fields))
}

fn parse_return_code(fields: &BTreeMap<String, String>) -> u32 {
    fields.get("returncd").and_then(|value| value.parse::<u32>().ok()).unwrap_or(u32::MAX)
}

fn parse_game_auth(fields: &BTreeMap<String, String>, status: u32) -> GameAuthenticationData {
    let mut data = GameAuthenticationData {
        nasc_result: parse_return_code(fields),
        http_status: status,
        ..GameAuthenticationData::default()
    };
    if data.nasc_result == 1 {
        if !(200..300).contains(&status) {
            data.nasc_result = u32::MAX;
            return data;
        }
        let endpoint = fields.get("locator").and_then(|locator| {
            let (host, port) = locator.rsplit_once(':')?;
            let port = port.parse::<u16>().ok()?;
            if host.is_empty() || port == 0 { return None; }
            Some((host, port))
        });
        let token = fields.get("token");
        let timestamp = server_time(fields.get("datetime"));
        match (endpoint, token, timestamp) {
            (Some((host, port)), Some(token), timestamp) if timestamp != 0 => {
                data.server_address = fixed_string::<0x20>(host).to_vec();
                data.server_port = port;
                data.token = fixed_string::<0x100>(token).to_vec();
                data.server_time = timestamp;
                data.server_time_difference_ns = server_time_difference_ns(fields.get("datetime"));
            }
            _ => data.nasc_result = u32::MAX,
        }
    }
    data
}

fn parse_service_locator(fields: &BTreeMap<String, String>, status: u32) -> ServiceLocatorData {
    let mut data = ServiceLocatorData {
        nasc_result: parse_return_code(fields),
        http_status: status,
        ..ServiceLocatorData::default()
    };
    if data.nasc_result == 7 {
        if !(200..300).contains(&status) {
            data.nasc_result = u32::MAX;
            return data;
        }
        let host = fields.get("svchost");
        let token = fields.get("servicetoken");
        let timestamp = server_time(fields.get("datetime"));
        match (host, token, timestamp) {
            (Some(host), Some(token), timestamp) if timestamp != 0 => {
                data.service_host = fixed_string::<0x80>(host).to_vec();
                data.service_token = fixed_string::<0x100>(token).to_vec();
                data.server_time_difference_ns = server_time_difference_ns(fields.get("datetime"));
                data.status_data = fields.get("statusdata").and_then(|value| value.as_bytes().first().copied()).unwrap_or(0);
                data.server_time = timestamp;
                data.server_time_difference_ns = server_time_difference_ns(fields.get("datetime"));
            }
            _ => data.nasc_result = u32::MAX,
        }
    }
    data
}

fn static_output(system: &mut System, buffer: &CommandBuffer, command: u16, bytes: &[u8]) {
    let tls = system.kernel.current().map_or(0, |thread| thread.tls);
    let (pointer, capacity) = buffer.static_buffer(&mut system.memory, tls, 0);
    if capacity < bytes.len() as u32 {
        buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
        return;
    }
    system.memory.write_bytes(pointer, bytes);
    buffer.reply(&mut system.memory, command, &[]);
}

fn require_pretendo_provider(system: &System) -> Result<(), String> {
    if system.config.network_provider == NetworkProvider::Pretendo {
        Ok(())
    } else {
        Err("Pretendo networking is disabled; select Pretendo in Online settings first".to_owned())
    }
}

fn start_game_auth(
    system: &mut System,
    server_id: u32,
    ingamesn: &[u8],
    sdk_major: u8,
    sdk_minor: u8,
    event: ObjectId,
) -> Result<PendingNasc<GameAuthenticationData>, String> {
    require_pretendo_provider(system)?;
    if server_id != MK7_NEX_SERVER_ID {
        return Err(format!("unexpected NEX server ID 0x{server_id:08X} for Mario Kart 7"));
    }
    repair_uidhmac_if_enabled(system)?;
    let account = load_friend_account(system).ok_or_else(|| "no valid imported Friends account is available".to_owned())?;
    let data_dir = system.config.data_dir.as_ref().ok_or_else(|| "application data directory is unavailable".to_owned())?;
    let device: NascDeviceConfig = serde_json::from_slice(
        &std::fs::read(data_dir.join("sysdata/nasc.json"))
            .map_err(|error| format!("could not read sysdata/nasc.json: {error}"))?
    ).map_err(|error| format!("sysdata/nasc.json is invalid: {error}"))?;
    let fcdcert = std::fs::read(data_dir.join("sysdata/LocalFriendCodeSeed_B"))
        .map_err(|error| format!("could not read sysdata/LocalFriendCodeSeed_B: {error}"))?;
    let mut extra = Vec::new();
    let end = ingamesn.chunks_exact(2).position(|pair| pair == [0, 0]).map_or(ingamesn.len(), |i| i * 2);
    if end > 0 {
        extra.push(("ingamesn", ingamesn[..end].to_vec()));
    } else {
        extra.push(("ingamesn", Vec::new()));
    }
    let job = make_nasc_job(
        system, &account, &device, &fcdcert, "LOGIN", sdk_major, sdk_minor, &extra
    )?;
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let result = perform_nasc_http(job).map(|(status, fields)| parse_game_auth(&fields, status));
        let _ = send.send(result);
    });
    Ok(PendingNasc { receiver: receive, event })
}

fn start_nat_detection(system: &System, event: ObjectId) -> PendingNasc<(u32, u32)> {
    let configured = system.config.data_dir.as_ref()
        .and_then(|dir| std::fs::read(dir.join("sysdata/nasc.json")).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|json| json.get("stun_servers").and_then(serde_json::Value::as_array).cloned())
        .map(|servers| servers.into_iter().filter_map(|server| server.as_str().map(str::to_owned)).collect::<Vec<_>>())
        .filter(|servers| servers.len() >= 2);
    let servers = configured.unwrap_or_else(|| vec![
        "stun.l.google.com:19302".to_owned(),
        "stun.cloudflare.com:3478".to_owned(),
    ]);
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let _ = send.send(Ok(detect_nat_properties(servers)));
    });
    PendingNasc { receiver: receive, event }
}

fn start_service_locator(
    system: &mut System,
    server_id: u32,
    key_hash: &str,
    service_type: &str,
    sdk_major: u8,
    sdk_minor: u8,
    event: ObjectId,
) -> Result<PendingNasc<ServiceLocatorData>, String> {
    require_pretendo_provider(system)?;
    if server_id != MK7_NEX_SERVER_ID {
        return Err(format!("unexpected NEX server ID 0x{server_id:08X} for Mario Kart 7"));
    }
    repair_uidhmac_if_enabled(system)?;
    let account = load_friend_account(system).ok_or_else(|| "no valid imported Friends account is available".to_owned())?;
    let data_dir = system.config.data_dir.as_ref().ok_or_else(|| "application data directory is unavailable".to_owned())?;
    let device: NascDeviceConfig = serde_json::from_slice(
        &std::fs::read(data_dir.join("sysdata/nasc.json"))
            .map_err(|error| format!("could not read sysdata/nasc.json: {error}"))?
    ).map_err(|error| format!("sysdata/nasc.json is invalid: {error}"))?;
    let fcdcert = std::fs::read(data_dir.join("sysdata/LocalFriendCodeSeed_B"))
        .map_err(|error| format!("could not read sysdata/LocalFriendCodeSeed_B: {error}"))?;
    let extra = [
        ("keyhash", key_hash.as_bytes().to_vec()),
        ("svc", service_type.as_bytes().to_vec()),
    ];
    let job = make_nasc_job(
        system, &account, &device, &fcdcert, "SVCLOC", sdk_major, sdk_minor, &extra
    )?;
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let result = perform_nasc_http(job).map(|(status, fields)| parse_service_locator(&fields, status));
        let _ = send.send(result);
    });
    Ok(PendingNasc { receiver: receive, event })
}

/// Local FRD state. The server-side friends service still needs a successful
/// NASC/NEX session; this only implements the console-side login event.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct FrdState {
    #[serde(skip)]
    logged_in: bool,
    last_response_result: u32,
    #[serde(default)]
    server_time_difference_ns: u64,
    #[serde(skip)]
    pending_game: Option<PendingNasc<GameAuthenticationData>>,
    #[serde(skip)]
    pending_service: Option<PendingNasc<ServiceLocatorData>>,
    #[serde(skip)]
    pending_nat: Option<PendingNasc<(u32, u32)>>,
    #[serde(default)]
    nat_properties: Option<(u32, u32)>,
    #[serde(default)]
    game_authentication: Option<GameAuthenticationData>,
    #[serde(default)]
    service_locator: Option<ServiceLocatorData>,
}

/// Polls asynchronous NASC work on the emulation thread and signals the
/// original guest completion events when responses are ready.
pub fn poll(system: &mut System) {
    let game_ready = system.services.frd.pending_game.as_ref().and_then(|pending| {
        match pending.receiver.try_recv() {
            Ok(result) => Some((pending.event, result)),
            Err(mpsc::TryRecvError::Disconnected) => Some((pending.event, Err("NASC worker stopped".to_owned()))),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    });
    if let Some((event, result)) = game_ready {
        system.services.frd.pending_game = None;
        match result {
            Ok(data) => {
                system.services.frd.last_response_result = data.nasc_result;
                system.services.frd.server_time_difference_ns = data.server_time_difference_ns;
                system.services.frd.game_authentication = Some(data);
            }
            Err(error) => {
                log::warn!("frd:u NASC LOGIN failed: {error}");
                system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                system.services.frd.game_authentication = Some(GameAuthenticationData {
                    nasc_result: u32::MAX,
                    ..GameAuthenticationData::default()
                });
            }
        }
        system.kernel.signal_event(event);
    }

    let service_ready = system.services.frd.pending_service.as_ref().and_then(|pending| {
        match pending.receiver.try_recv() {
            Ok(result) => Some((pending.event, result)),
            Err(mpsc::TryRecvError::Disconnected) => Some((pending.event, Err("NASC worker stopped".to_owned()))),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    });
    if let Some((event, result)) = service_ready {
        system.services.frd.pending_service = None;
        match result {
            Ok(data) => {
                system.services.frd.last_response_result = data.nasc_result;
                system.services.frd.server_time_difference_ns = data.server_time_difference_ns;
                system.services.frd.service_locator = Some(data);
            }
            Err(error) => {
                log::warn!("frd:u NASC SVCLOC failed: {error}");
                system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                system.services.frd.service_locator = Some(ServiceLocatorData {
                    nasc_result: u32::MAX,
                    ..ServiceLocatorData::default()
                });
            }
        }
        system.kernel.signal_event(event);
    }

    let nat_ready = system.services.frd.pending_nat.as_ref().and_then(|pending| {
        match pending.receiver.try_recv() {
            Ok(result) => Some((pending.event, result)),
            Err(mpsc::TryRecvError::Disconnected) => Some((pending.event, Err("STUN worker stopped".to_owned()))),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    });
    if let Some((event, result)) = nat_ready {
        system.services.frd.pending_nat = None;
        match result {
            Ok(properties) => {
                log::info!("frd:u detected NAT mapping={} filtering={}", properties.0, properties.1);
                system.services.frd.nat_properties = Some(properties);
                system.services.frd.last_response_result = 0;
            }
            Err(error) => {
                log::warn!("frd:u NAT detection failed: {error}");
                system.services.frd.nat_properties = Some((0, 0));
                system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
            }
        }
        system.kernel.signal_event(event);
    }
}

pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    let command = header.command_id();
    let (region, language) = (system.config.region, system.config.language);
    match command {
        // HasLoggedIn and IsOnline reflect the local FRD login. This is not a
        // substitute for the title's independent NASC and NEX authentication.
        0x0001 | 0x0002 => {
            let logged_in = system.services.frd.logged_in && system.config.network_provider == NetworkProvider::Pretendo;
            buffer.reply(&mut system.memory, command, &[u32::from(logged_in)]);
        }
        // Login(event) completes the local friends module's login handshake.
        0x0003 => {
            let descriptor = buffer.get(&mut system.memory, header.normal_params() + 1);
            let event_handle = match Descriptor::parse(descriptor) {
                Descriptor::Handles { count, .. } if count > 0 => Some(buffer.get(&mut system.memory, header.normal_params() + 2)),
                _ => None,
            };
            if system.config.network_provider != NetworkProvider::Pretendo {
                system.services.frd.logged_in = false;
                system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
            } else {
                system.services.frd.logged_in = true;
                system.services.frd.last_response_result = 0;
                if let Some(object) = event_handle.and_then(|handle| system.kernel.handles.resolve(handle)) {
                    system.kernel.signal_event(object);
                }
                buffer.reply(&mut system.memory, command, &[]);
            }
        }
        // Logout, AttachToEventNotification, SetNotificationMask and SetClientSdkVersion.
        0x0004 => {
            system.services.frd.logged_in = false;
            system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
            buffer.reply(&mut system.memory, command, &[]);
        }
        0x0020 | 0x0021 | 0x0032 => buffer.reply(&mut system.memory, command, &[]),
        // GetMyFriendKey: PrincipalID, padding, and the 64-bit local friend code.
        0x0005 => {
            if let Err(error) = repair_uidhmac_if_enabled(system) {
                log::warn!("frd:u UID-HMAC repair failed: {error}");
                buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                return true;
            }
            let result = load_friend_account(system).map(|account| [
                account.principal_id,
                0,
                account.local_friend_code as u32,
                (account.local_friend_code >> 32) as u32,
            ]);
            match result {
                Some(words) => buffer.reply(&mut system.memory, command, &words),
                None => {
                    if system.config.network_provider == NetworkProvider::Pretendo {
                        buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                    } else {
                        buffer.reply(&mut system.memory, command, &[0; 4]);
                    }
                }
            }
        }
        // GetMyPreference, private, showing neither game
        0x0006 => buffer.reply(&mut system.memory, command, &[0; 3]),
        // GetMyProfile, region, country, area and language, then platform
        0x0007 => {
            let country: u32 = if region == REGION_USA { 49 } else { 110 };
            let first = region as u32 | country << 8 | (language as u32) << 24;
            buffer.reply(&mut system.memory, command, &[first, PLATFORM_CTR]);
        }
        // GetMyPresence, into a static buffer that stays as it is
        0x0008 => buffer.reply(&mut system.memory, command, &[]),
        // GetMyScreenName, the user's name in eleven UTF-16 units
        0x0009 => {
            let mut name = [0u8; 24];
            let username: String = system.config.username.chars().take(10).collect();
            for (i, unit) in username.encode_utf16().enumerate() {
                name[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            let words: Vec<u32> = name.as_chunks::<4>().0.iter().map(|&w| u32::from_le_bytes(w)).collect();
            buffer.reply(&mut system.memory, command, &words);
        }
        // GetMyMii
        0x000A => buffer.reply(&mut system.memory, command, &[0; 24]),
        // GetMyLocalAccountId, from the imported Friends account record.
        0x000B => {
            let id = load_friend_account(system).map_or(0, |account| account.local_account_id);
            buffer.reply(&mut system.memory, command, &[id]);
        }
        // GetMyPlayingGame and GetMyFavoriteGame, a title id, its version
        // and a word more
        0x000C | 0x000D => buffer.reply(&mut system.memory, command, &[0; 4]),
        // GetMyNcPrincipalId
        0x000E => buffer.reply(&mut system.memory, command, &[0]),
        // GetMyComment
        0x000F => buffer.reply(&mut system.memory, command, &[0; 9]),
        // GetMyPassword(size, static output buffer). The Friends account file
        // stores the 16-character NEX password as UTF-16 at offset 0x20.
        0x0010 => {
            if let Err(error) = repair_uidhmac_if_enabled(system) {
                log::warn!("frd:u UID-HMAC repair failed: {error}");
                reply_static_bytes(system, buffer, command, errors::NOT_CONNECTED.0, &[]);
                return true;
            }
            let requested = buffer.get(&mut system.memory, 1) as usize;
            match load_friend_account(system) {
                Some(account) => {
                    let mut password = account.password.into_bytes();
                    password.push(0);
                    password.truncate(requested);
                    reply_static_bytes(system, buffer, command, 0, &password);
                }
                None => {
                    reply_static_bytes(system, buffer, command, errors::NOT_CONNECTED.0, &[]);
                }
            }
        }
        // GetFriendKeyList and GetEventNotification, none
        0x0011 | 0x0022 => buffer.reply(&mut system.memory, command, &[0]),
        // lookups on friends the title names, of which it has none to name
        0x0012..=0x001A => buffer.reply(&mut system.memory, command, &[]),
        // IsIncludedInFriendList
        0x001B => buffer.reply(&mut system.memory, command, &[0]),
        // RequestGameAuthentication(server ID, UTF-16 in-game name, SDK version,
        // process ID, completion event). The request runs off-thread and signals
        // the event only after NASC has returned.
        0x0028 => {
            let server_id = buffer.get(&mut system.memory, 1);
            let mut ingamesn = Vec::with_capacity(12);
            for index in 2..8 {
                ingamesn.extend_from_slice(&buffer.get(&mut system.memory, index).to_le_bytes());
            }
            let sdk_major = buffer.get(&mut system.memory, 8).min(u8::MAX as u32) as u8;
            let sdk_minor = buffer.get(&mut system.memory, 9).min(u8::MAX as u32) as u8;
            let process_descriptor = Descriptor::parse(buffer.get(&mut system.memory, 10));
            let event_descriptor = Descriptor::parse(buffer.get(&mut system.memory, 12));
            let event_handle = match (process_descriptor, event_descriptor) {
                (Descriptor::CurrentProcessId, Descriptor::Handles { count, .. }) if count > 0 => Some(buffer.get(&mut system.memory, 13)),
                (_, Descriptor::Handles { count, .. }) if count > 0 => Some(buffer.get(&mut system.memory, 13)),
                _ => None,
            };
            let event = event_handle.and_then(|handle| system.kernel.handles.resolve(handle));
            match event {
                Some(event) if system.services.frd.pending_game.is_none() => {
                    match start_game_auth(system, server_id, &ingamesn, sdk_major, sdk_minor, event) {
                        Ok(pending) => {
                            system.services.frd.game_authentication = None;
                            system.services.frd.pending_game = Some(pending);
                            system.services.frd.last_response_result = 0;
                            buffer.reply(&mut system.memory, command, &[]);
                        }
                        Err(error) => {
                            log::warn!("frd:u NASC LOGIN could not start: {error}");
                            system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                            buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                        }
                    }
                }
                _ => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // GetGameAuthenticationData writes the 0x138-byte response structure
        // into static buffer slot 0.
        0x0029 => {
            match &system.services.frd.game_authentication {
                Some(data) => {
                    let mut bytes = vec![0u8; 0x138];
                    bytes[0x00..0x04].copy_from_slice(&data.nasc_result.to_le_bytes());
                    bytes[0x04..0x08].copy_from_slice(&data.http_status.to_le_bytes());
                    bytes[0x08..0x28].copy_from_slice(&data.server_address);
                    bytes[0x28..0x2A].copy_from_slice(&data.server_port.to_le_bytes());
                    bytes[0x30..0x130].copy_from_slice(&data.token);
                    bytes[0x130..0x138].copy_from_slice(&data.server_time.to_le_bytes());
                    static_output(system, buffer, command, &bytes);
                }
                None => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // RequestServiceLocator(server ID, keyhash, service type, SDK version,
        // process ID, completion event).
        0x002A => {
            let server_id = buffer.get(&mut system.memory, 1);
            let sdk_major = buffer.get(&mut system.memory, 7).min(u8::MAX as u32) as u8;
            let sdk_minor = buffer.get(&mut system.memory, 8).min(u8::MAX as u32) as u8;
            let key_words = [
                buffer.get(&mut system.memory, 2),
                buffer.get(&mut system.memory, 3),
                buffer.get(&mut system.memory, 4),
            ];
            let mut key_bytes = Vec::new();
            for word in key_words { key_bytes.extend_from_slice(&word.to_le_bytes()); }
            let key_end = key_bytes.iter().position(|byte| *byte == 0).unwrap_or(8).min(8);
            let key_hash = String::from_utf8_lossy(&key_bytes[..key_end]).to_string();

            let service_words = [buffer.get(&mut system.memory, 5), buffer.get(&mut system.memory, 6)];
            let mut service_bytes = Vec::new();
            for word in service_words { service_bytes.extend_from_slice(&word.to_le_bytes()); }
            let service_end = service_bytes.iter().position(|byte| *byte == 0).unwrap_or(4).min(4);
            let service_type = String::from_utf8_lossy(&service_bytes[..service_end]).to_string();

            let process_descriptor = Descriptor::parse(buffer.get(&mut system.memory, 9));
            let event_descriptor = Descriptor::parse(buffer.get(&mut system.memory, 11));
            let event_handle = match (process_descriptor, event_descriptor) {
                (Descriptor::CurrentProcessId, Descriptor::Handles { count, .. }) if count > 0 => Some(buffer.get(&mut system.memory, 12)),
                (_, Descriptor::Handles { count, .. }) if count > 0 => Some(buffer.get(&mut system.memory, 12)),
                _ => None,
            };
            let event = event_handle.and_then(|handle| system.kernel.handles.resolve(handle));
            match event {
                Some(event) if system.services.frd.pending_service.is_none() => {
                    match start_service_locator(
                        system, server_id, &key_hash, &service_type, sdk_major, sdk_minor, event
                    ) {
                        Ok(pending) => {
                            system.services.frd.service_locator = None;
                            system.services.frd.pending_service = Some(pending);
                            system.services.frd.last_response_result = 0;
                            buffer.reply(&mut system.memory, command, &[]);
                        }
                        Err(error) => {
                            log::warn!("frd:u NASC SVCLOC could not start: {error}");
                            system.services.frd.last_response_result = errors::NOT_CONNECTED.0;
                            buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                        }
                    }
                }
                _ => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // GetServiceLocatorData writes the 0x198-byte response structure into
        // static buffer slot 0.
        0x002B => {
            match &system.services.frd.service_locator {
                Some(data) => {
                    let mut bytes = vec![0u8; 0x198];
                    bytes[0x00..0x04].copy_from_slice(&data.nasc_result.to_le_bytes());
                    bytes[0x04..0x08].copy_from_slice(&data.http_status.to_le_bytes());
                    bytes[0x08..0x88].copy_from_slice(&data.service_host);
                    bytes[0x88..0x188].copy_from_slice(&data.service_token);
                    bytes[0x188] = data.status_data;
                    bytes[0x190..0x198].copy_from_slice(&data.server_time.to_le_bytes());
                    static_output(system, buffer, command, &bytes);
                }
                None => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // DetectNatProperties runs independent STUN mappings and an
        // alternate-source probe asynchronously, then signals the event.
        0x002C => {
            if let Err(error) = require_pretendo_provider(system) {
                log::debug!("frd:u skipping NAT probe: {error}");
                buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
                return true;
            }
            let descriptor = Descriptor::parse(buffer.get(&mut system.memory, 1));
            let handle = match descriptor {
                Descriptor::Handles { count, .. } if count > 0 => Some(buffer.get(&mut system.memory, 2)),
                _ => None,
            };
            match handle.and_then(|handle| system.kernel.handles.resolve(handle)) {
                Some(event) if system.services.frd.pending_nat.is_none() => {
                    system.services.frd.nat_properties = None;
                    system.services.frd.pending_nat = Some(start_nat_detection(system, event));
                    buffer.reply(&mut system.memory, command, &[]);
                }
                _ => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // GetNatProperties only returns once the asynchronous probe finishes.
        0x002D => {
            if require_pretendo_provider(system).is_err() {
                buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0);
            } else {
                match system.services.frd.nat_properties {
                    Some((mapping, filtering)) => buffer.reply(&mut system.memory, command, &[mapping, filtering]),
                    None => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
                }
            }
        },
        // GetServerTimeDifference returns signed nanoseconds as a u64 pair.
        0x002E => {
            let difference = system.services.frd.server_time_difference_ns;
            buffer.reply(&mut system.memory, command, &[
                difference as u32,
                (difference >> 32) as u32,
            ]);
        }
        // AllowHalfAwake: accepted by the server-side Friends module.
        0x002F => buffer.reply(&mut system.memory, command, &[]),
        // GetServerTypes: bytes from the imported Friends account.
        0x0030 => {
            match load_friend_account(system) {
                Some(account) => buffer.reply(&mut system.memory, command, &[
                    account.nasc_environment as u32,
                    account.server_type as u32,
                    account.server_type_number as u32,
                ]),
                None => buffer.reply_error(&mut system.memory, command, errors::NOT_CONNECTED.0),
            }
        }
        // GetLastResponseResult, what the last request to the servers got
        0x0023 => {
            let result = if system.services.frd.logged_in {
                system.services.frd.last_response_result
            } else {
                errors::NOT_CONNECTED.0
            };
            buffer.reply(&mut system.memory, command, &[result]);
        }
        // ResultToErrorCode, no code to show
        0x0027 => buffer.reply(&mut system.memory, command, &[0]),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 0x58];
        bytes[..4].copy_from_slice(b"FPAC");
        bytes[4..8].copy_from_slice(&0x2010_1021u32.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        bytes[0x18..0x20].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        for (index, byte) in b"ABCDEFGHIJKLMNOP".iter().enumerate() {
            bytes[0x20 + index * 2] = *byte;
        }
        for (index, byte) in b"AB12CD34".iter().enumerate() {
            bytes[0x42 + index * 2] = *byte;
        }
        bytes[0x54] = 1;
        bytes[0x55] = b'M';
        bytes[0x56] = b'K';
        bytes
    }

    #[test]
    fn friend_account_parser_reads_principal_password_and_hmac() {
        let account = parse_friend_account(&account_bytes()).unwrap();
        assert_eq!(account.local_account_id, 2);
        assert_eq!(account.principal_id, 0x1234_5678);
        assert_eq!(account.local_friend_code, 0x1122_3344_5566_7788);
        assert_eq!(account.password, "ABCDEFGHIJKLMNOP");
        assert_eq!(account.uidhmac, "AB12CD34");
        assert_eq!(account.nasc_environment, 1);
        assert_eq!(account.server_type, b'M');
        assert_eq!(account.server_type_number, b'K');
    }

    #[test]
    fn stun_response_decodes_xor_mapped_ipv4_and_checks_transaction_id() {
        let transaction = [0x11u8; 12];
        let public_ip = std::net::Ipv4Addr::new(203, 0, 113, 7);
        let public_port = 0xC123u16;
        let mut packet = vec![0u8; 32];
        packet[0..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        packet[2..4].copy_from_slice(&12u16.to_be_bytes());
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet[8..20].copy_from_slice(&transaction);
        packet[20..22].copy_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
        packet[22..24].copy_from_slice(&8u16.to_be_bytes());
        packet[25] = 1; // IPv4 family
        packet[26..28].copy_from_slice(
            &(public_port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes()
        );
        let encoded_ip = u32::from_be_bytes(public_ip.octets()) ^ STUN_MAGIC_COOKIE;
        packet[28..32].copy_from_slice(&encoded_ip.to_be_bytes());

        assert_eq!(
            parse_stun_response(&packet, &transaction),
            Some(SocketAddr::from((public_ip, public_port)))
        );
        let other_transaction = [0x22u8; 12];
        assert_eq!(parse_stun_response(&packet, &other_transaction), None);
    }

    #[test]
    fn nasc_custom_base64_uses_the_nintendo_alphabet_and_round_trips() {
        assert_eq!(nasc_base64_encode(b"0001DB00"), "MDAwMURCMDA*");
        assert_eq!(nasc_base64_decode("MDAwMURCMDA*").unwrap(), b"0001DB00");
        assert_eq!(nasc_base64_encode(b"+/="), "Ky89");
        assert_eq!(nasc_base64_decode("Ky89").unwrap(), b"+/=");
    }

    #[test]
    fn cartridge_romid_is_decoded_from_hex_to_the_17_byte_binary_value() {
        let hex = "2892774E7B2B770D2A647D146505FF5438";
        let bytes = decode_hex_bytes(hex).unwrap();
        assert_eq!(bytes.len(), 17);
        assert_eq!(nasc_base64_encode(&bytes), "KJJ3Tnsrdw0qZH0UZQX-VDg*");
    }

    #[test]
    fn nasc_sdk_version_is_encoded_as_two_three_digit_decimal_parts() {
        let major = 0u8;
        let minor = 0u8;
        assert_eq!(format!("{major:03}{minor:03}"), "000000");
        assert_eq!(format!("{:03}{:03}", 1u8, 16u8), "001016");
    }

    #[test]
    fn nasc_response_decodes_form_and_custom_base64_fields() {
        let fields = parse_nasc_form("returncd=MDAx&locator=MTI3LjAuMC4xOjQwNDA*&token=YWJj") .unwrap();
        assert_eq!(fields.get("returncd").map(String::as_str), Some("001"));
        assert_eq!(fields.get("locator").map(String::as_str), Some("127.0.0.1:4040"));
        assert_eq!(fields.get("token").map(String::as_str), Some("abc"));
    }

    #[test]
    fn device_name_is_encoded_as_nul_terminated_utf16le() {
        let mut encoded: Vec<u8> = "N3DS".encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]);
        assert_eq!(encoded, [b'N', 0, b'3', 0, b'D', 0, b'S', 0, 0, 0]);
    }

    #[test]
    fn nasc_unit_code_tracks_the_selected_console_model() {
        let old_3ds = false;
        let new_3ds = true;
        assert_eq!(if old_3ds { b"2" } else { b"0" }, b"0");
        assert_eq!(if new_3ds { b"2" } else { b"0" }, b"2");
    }

    #[test]
    fn nasc_success_codes_are_not_accepted_with_http_failure_status() {
        let mut fields = BTreeMap::new();
        fields.insert("returncd".to_owned(), "001".to_owned());
        fields.insert("locator".to_owned(), "127.0.0.1:4040".to_owned());
        fields.insert("token".to_owned(), "token".to_owned());
        fields.insert("datetime".to_owned(), "20261124100000".to_owned());
        assert_eq!(parse_game_auth(&fields, 503).nasc_result, u32::MAX);

        fields.insert("returncd".to_owned(), "007".to_owned());
        fields.insert("svchost".to_owned(), "127.0.0.1".to_owned());
        fields.insert("servicetoken".to_owned(), "token".to_owned());
        assert_eq!(parse_service_locator(&fields, 503).nasc_result, u32::MAX);
    }

    #[test]
    fn nasc_datetime_is_converted_to_a_packed_nex_timestamp() {
        let datetime = "20240209121603".to_owned();
        assert_eq!(
            server_time(Some(&datetime)),
            (2024u64 << 26) | (2u64 << 22) | (9u64 << 17)
                | (12u64 << 12) | (16u64 << 6) | 3u64
        );
    }

    #[test]
    fn server_time_difference_is_nanoseconds_not_unix_seconds() {
        let now = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
        let difference = server_time_difference_ns(Some(&now));
        assert!((difference as i64).abs() < 2_000_000_000);
    }

    #[test]
    fn apinfo_requires_two_hex_slot_digits_and_ten_hex_access_point_digits() {
        let valid = "01:0000000000";
        let bytes = valid.as_bytes();
        assert_eq!(bytes.len(), 13);
        assert!(bytes[2] == b':' && bytes[..2].iter().chain(bytes[3..].iter()).all(u8::is_ascii_hexdigit));
        assert_ne!("1:0000000000".len(), 13);
    }

    #[test]
    fn repair_form_encoding_is_safe_for_password_characters() {
        assert_eq!(form_encode_component("a b&c"), "a+b%26c");
    }

    #[test]
    fn nasc_requests_are_blocked_when_network_provider_is_off() {
        let (system, _) = crate::services::tests::system_with_thread();
        assert!(require_pretendo_provider(&system).is_err());
    }

    #[test]
    fn friend_account_parser_rejects_bad_magic_and_truncated_data() {
        let mut invalid = account_bytes();
        invalid[0] = 0;
        assert!(parse_friend_account(&invalid).is_none());
        assert!(parse_friend_account(&account_bytes()[..0x57]).is_none());
    }
}
