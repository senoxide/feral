// Persistent identity: an Ed25519 keypair stored on disk so a node
// keeps the same cryptographic identity across restarts, plus the
// TOFU-pinned table of peer keys that makes that useful. No address
// book is kept here -- peer discovery is dynamic (UDP broadcast) since
// IPs on a DHCP LAN aren't stable enough to be worth caching; see
// net::discovery. Files live under paths::data_dir() (~/feral on
// Linux, %APPDATA%\feral on Windows).
use crate::paths;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::io::Write;

pub const IDENTITY_FILE: &str = "identity";
pub const KNOWN_PEERS_FILE: &str = "known_peers";

fn restrict_permissions(path: &std::path::Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(f) = std::fs::File::open(path) {
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Loads the identity key from disk, or generates and saves a new one
/// on first run. The seed is the only secret ever written to disk or
/// held in memory; it never goes over the network.
pub fn load_or_create() -> SigningKey {
    let path = paths::file(IDENTITY_FILE);
    if let Ok(hex_seed) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = hex::decode(hex_seed.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return SigningKey::from_bytes(&arr);
            }
        }
        eprintln!("Warning: {} is corrupt; generating a new identity.", path.display());
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    if std::fs::write(&path, hex::encode(key.to_bytes())).is_ok() {
        restrict_permissions(&path);
    }
    key
}

/// short_id -> (full fingerprint, pubkey hex), TOFU-pinned the first
/// time each identity completes a handshake and persisted across
/// restarts so a later connection claiming the same short_id with a
/// *different* key is flagged rather than silently trusted.
pub fn load_known_peers() -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(paths::file(KNOWN_PEERS_FILE)) {
        for line in content.lines() {
            let parts: Vec<&str> = line.trim().splitn(3, '=').collect();
            if parts.len() == 3 {
                out.insert(parts[0].to_string(), (parts[1].to_string(), parts[2].to_string()));
            }
        }
    }
    out
}

pub fn append_known_peer(short_id: &str, fp: &str, pubkey_hex: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(paths::file(KNOWN_PEERS_FILE)) {
        let _ = writeln!(f, "{}={}={}", short_id, fp, pubkey_hex);
    }
}

pub fn pubkey_from_hex(hex_str: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}
