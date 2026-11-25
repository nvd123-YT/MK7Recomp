//! Per-install identity for the independent MK7Recomp network service.
//!
//! This is deliberately NOT a Nintendo console identity. It contains no
//! LocalFriendCodeSeed, Nintendo device certificate, serial number, or MAC
//! address, and must never be sent to Pretendo's 3DS NASC endpoint. A future
//! MK7Recomp-owned backend can use it to distinguish installations without
//! asking players to dump system data.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const IDENTITY_SCHEMA: u32 = 1;
const ID_BYTES: usize = 16;
const CREDENTIAL_BYTES: usize = 32;
const MAX_IDENTITY_FILE_SIZE: u64 = 512;

/// Unique, locally persisted identity for the MK7Recomp-owned network.
///
/// The credential is a random per-install secret for the future independent
/// backend. It is not a Pretendo credential or a Nintendo-signed device key.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkIdentity {
    account_id: [u8; ID_BYTES],
    credential: [u8; CREDENTIAL_BYTES],
}

impl fmt::Debug for NetworkIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkIdentity")
            .field("account_id", &self.account_id_hex())
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    schema: u32,
    account_id: String,
    credential: String,
}

impl NetworkIdentity {
    /// Load this installation's identity, creating one on first use.
    ///
    /// Identity files live under `data_dir/network/mk7recomp/identity.json`.
    /// They are created with owner-only permissions on Unix. Existing corrupt
    /// files fail closed: they are never silently replaced with a new identity.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        let directory = identity_directory(data_dir);
        fs::create_dir_all(&directory)?;
        set_private_directory_permissions(&directory)?;

        let path = directory.join("identity.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let identity = Self::generate()?;
                let stored = StoredIdentity {
                    schema: IDENTITY_SCHEMA,
                    account_id: encode_hex(&identity.account_id),
                    credential: encode_hex(&identity.credential),
                };
                let bytes = serde_json::to_vec_pretty(&stored)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

                if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                Ok(identity)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::read_existing(&path)
            }
            Err(error) => Err(error),
        }
    }

    /// The stable opaque identifier assigned to this installation.
    pub fn account_id_hex(&self) -> String {
        encode_hex(&self.account_id)
    }

    /// The private credential for the MK7Recomp network backend.
    ///
    /// Callers must only transmit it to a configured MK7Recomp-owned service
    /// over authenticated TLS. Never log it or reuse it with Pretendo/Nintendo.
    pub fn credential(&self) -> &[u8; CREDENTIAL_BYTES] {
        &self.credential
    }

    /// The persisted identity file, useful for diagnostics without reading
    /// or displaying its secret contents.
    pub fn file_path(data_dir: &Path) -> PathBuf {
        identity_directory(data_dir).join("identity.json")
    }

    fn generate() -> io::Result<Self> {
        let mut account_id = [0u8; ID_BYTES];
        let mut credential = [0u8; CREDENTIAL_BYTES];
        getrandom::fill(&mut account_id)
            .map_err(|error| io::Error::other(format!("secure random generation failed: {error}")))?;
        getrandom::fill(&mut credential)
            .map_err(|error| io::Error::other(format!("secure random generation failed: {error}")))?;
        Ok(Self { account_id, credential })
    }

    fn read_existing(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_IDENTITY_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MK7Recomp network identity file is unexpectedly large",
            ));
        }

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        fs::File::open(path)?
            .take(MAX_IDENTITY_FILE_SIZE + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_IDENTITY_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MK7Recomp network identity file is unexpectedly large",
            ));
        }

        let stored: StoredIdentity = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if stored.schema != IDENTITY_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported MK7Recomp network identity schema {}", stored.schema),
            ));
        }

        let account_id = decode_hex::<ID_BYTES>(&stored.account_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid MK7Recomp network account ID")
        })?;
        let credential = decode_hex::<CREDENTIAL_BYTES>(&stored.credential).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid MK7Recomp network credential")
        })?;

        Ok(Self { account_id, credential })
    }
}

fn identity_directory(data_dir: &Path) -> PathBuf {
    data_dir.join("network").join("mk7recomp")
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut decoded = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory() -> PathBuf {
        let mut suffix = [0u8; 12];
        getrandom::fill(&mut suffix).expect("OS random source");
        let path = std::env::temp_dir().join(format!(
            "mk7recomp-network-identity-{}",
            encode_hex(&suffix)
        ));
        fs::create_dir(&path).expect("create temporary test directory");
        path
    }

    #[test]
    fn identity_is_created_once_and_survives_reopen() {
        let directory = temporary_directory();
        let first = NetworkIdentity::load_or_create(&directory).unwrap();
        let second = NetworkIdentity::load_or_create(&directory).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.account_id_hex().len(), ID_BYTES * 2);
        assert_eq!(first.credential().len(), CREDENTIAL_BYTES);
        assert!(NetworkIdentity::file_path(&directory).is_file());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn separate_data_directories_receive_independent_identities() {
        let first_directory = temporary_directory();
        let second_directory = temporary_directory();
        let first = NetworkIdentity::load_or_create(&first_directory).unwrap();
        let second = NetworkIdentity::load_or_create(&second_directory).unwrap();

        assert_ne!(first.account_id_hex(), second.account_id_hex());
        assert_ne!(first.credential(), second.credential());

        fs::remove_dir_all(first_directory).unwrap();
        fs::remove_dir_all(second_directory).unwrap();
    }

    #[test]
    fn malformed_identity_is_not_silently_replaced() {
        let directory = temporary_directory();
        let path = NetworkIdentity::file_path(&directory);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{not valid json").unwrap();
        let original = fs::read(&path).unwrap();

        let error = NetworkIdentity::load_or_create(&directory).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read(&path).unwrap(), original);

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_directory_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = temporary_directory();
        let _identity = NetworkIdentity::load_or_create(&directory).unwrap();
        let identity_directory = identity_directory(&directory);
        let directory_mode = fs::metadata(&identity_directory).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(NetworkIdentity::file_path(&directory))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn debug_output_never_contains_the_private_credential() {
        let directory = temporary_directory();
        let identity = NetworkIdentity::load_or_create(&directory).unwrap();
        let debug = format!("{identity:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&encode_hex(identity.credential())));

        fs::remove_dir_all(directory).unwrap();
    }
}
