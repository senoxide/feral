// Wire framing and cryptographic origin authentication.
//
// feral has no transport or room encryption: traffic is plaintext on the
// wire and readable to anyone who can sniff the LAN. What's authenticated
// is *origin*: every packet is signed with the sender's persistent
// Ed25519 identity key, so a relay cannot forge packets claiming to be
// from someone else, and a restarted node keeps the same identity.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHAT_PORT: u16 = 5001;
pub const DISCOVERY_PORT: u16 = 5002;

pub const MAX_PEER_DEGREE: usize = 12;
pub const RELAY_TTL: u32 = 24;

/// Packets timestamped further than this from our clock (past or
/// future) are rejected, bounding how long a captured packet can be
/// replayed even after it ages out of the seen-id dedup cache.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

pub fn escape_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\p"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

pub fn unescape_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'p' => { out.push('|'); i += 2; continue; }
                'n' => { out.push('\n'); i += 2; continue; }
                '\\' => { out.push('\\'); i += 2; continue; }
                _ => {}
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Strips C0/C1 control characters (including DEL and ANSI escape
/// starters) from peer-supplied text before it reaches the terminal.
pub fn sanitize_for_display(text: &str) -> String {
    text.chars()
        .filter(|&c| {
            let code = c as u32;
            !(code < 0x20 || code == 0x7f || (0x80..0xa0).contains(&code))
        })
        .collect()
}

pub fn new_id(nbytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn new_packet_id() -> String {
    new_id(6)
}

pub fn new_msg_id() -> String {
    new_id(2)
}

/// SHA-256 fingerprint of a public key, hex-encoded (64 chars). This is
/// the actual security-critical identity binding; the 8-char peer_id
/// used in wire fields is only `fingerprint[..8]` for display and
/// addressing convenience, not itself collision-resistant.
pub fn fingerprint(pubkey: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(pubkey.as_bytes()))
}

pub fn short_id(fp: &str) -> &str {
    &fp[..8.min(fp.len())]
}

pub fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Signs `ts|inner_line` with our identity key. The signature and the
/// timestamp are carried together in the RELAY envelope so a verifier
/// can check both authorship and freshness.
pub fn sign(key: &SigningKey, ts: i64, inner_line: &str) -> Signature {
    key.sign(format!("{}|{}", ts, inner_line).as_bytes())
}

pub fn verify(pubkey: &VerifyingKey, ts: i64, inner_line: &str, sig: &Signature) -> bool {
    pubkey.verify(format!("{}|{}", ts, inner_line).as_bytes(), sig).is_ok()
}

/// `RELAY|packet_id|ttl|ts|sig_hex|inner_line`. Only the originator
/// signs; relays decrement ttl and forward the envelope unchanged
/// otherwise (see net::relay_onward).
pub fn wrap_relay(key: &SigningKey, inner_line: &str) -> (String, String) {
    let packet_id = new_packet_id();
    let ts = now_epoch();
    let sig = sign(key, ts, inner_line);
    let line = format!("RELAY|{}|{}|{}|{}|{}", packet_id, RELAY_TTL, ts, hex::encode(sig.to_bytes()), inner_line);
    (packet_id, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_roundtrip() {
        let s = "a|b\\c\nd";
        assert_eq!(unescape_field(&escape_field(s)), s);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let ts = now_epoch();
        let sig = sign(&key, ts, "MSG|deadbeef|0|alice|hi|abcd|");
        assert!(verify(&key.verifying_key(), ts, "MSG|deadbeef|0|alice|hi|abcd|", &sig));
        assert!(!verify(&key.verifying_key(), ts, "MSG|deadbeef|0|alice|tampered|abcd|", &sig));
        assert!(!verify(&key.verifying_key(), ts + 1, "MSG|deadbeef|0|alice|hi|abcd|", &sig));
    }

    #[test]
    fn fingerprint_matches_short_id_length() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let fp = fingerprint(&key.verifying_key());
        assert_eq!(fp.len(), 64);
        assert_eq!(short_id(&fp).len(), 8);
    }
}
