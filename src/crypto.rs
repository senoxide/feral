// Per-connection transport encryption. This is separate from the
// Ed25519 identity in protocol.rs: identity is long-term and signs
// gossip content end-to-end across relay hops; the keys here are
// ephemeral, exist only for one TCP connection, and encrypt that one
// hop against a network observer. The identity key signs the ephemeral
// key at handshake time (authenticating it against MITM) but never
// touches the symmetric cipher directly.
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use zeroize::Zeroize;

/// ephemeral X25519 pubkey (32) || Ed25519 signature over it (64) ||
/// Ed25519 identity pubkey (32).
pub const HANDSHAKE_LEN: usize = 32 + 64 + 32;

pub struct HandshakeInit {
    ephemeral_public: XPublicKey,
    ephemeral_secret: EphemeralSecret,
    pub message: [u8; HANDSHAKE_LEN],
}

pub fn start_handshake(identity: &SigningKey) -> HandshakeInit {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = XPublicKey::from(&secret);
    let sig = identity.sign(public.as_bytes());
    let mut message = [0u8; HANDSHAKE_LEN];
    message[0..32].copy_from_slice(public.as_bytes());
    message[32..96].copy_from_slice(&sig.to_bytes());
    message[96..128].copy_from_slice(identity.verifying_key().as_bytes());
    HandshakeInit { ephemeral_public: public, ephemeral_secret: secret, message }
}

pub struct PeerHandshake {
    pub identity_pubkey: VerifyingKey,
    pub peer_ephemeral: XPublicKey,
}

/// Verifies the peer actually holds the private key for the identity
/// they claim, by checking their signature over their own ephemeral
/// key. Without this, anyone could present someone else's previously
/// pinned identity_pubkey without ever having the matching private key.
pub fn verify_handshake(bytes: &[u8]) -> Option<PeerHandshake> {
    if bytes.len() != HANDSHAKE_LEN {
        return None;
    }
    let ephemeral_bytes: [u8; 32] = bytes[0..32].try_into().ok()?;
    let sig_bytes: [u8; 64] = bytes[32..96].try_into().ok()?;
    let identity_bytes: [u8; 32] = bytes[96..128].try_into().ok()?;
    let identity_pubkey = VerifyingKey::from_bytes(&identity_bytes).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    identity_pubkey.verify(&ephemeral_bytes, &sig).ok()?;
    Some(PeerHandshake { identity_pubkey, peer_ephemeral: XPublicKey::from(ephemeral_bytes) })
}

pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

/// Derives two independent, direction-specific keys from the ECDH
/// shared secret via HKDF. Which label is "send" vs "recv" is decided
/// by comparing the two ephemeral public keys byte-for-byte, so both
/// sides agree without needing to track who initiated the TCP connect.
pub fn derive_session_keys(init: HandshakeInit, their_ephemeral: &XPublicKey) -> SessionKeys {
    let HandshakeInit { ephemeral_public: my_public, ephemeral_secret, .. } = init;
    let mut shared = ephemeral_secret.diffie_hellman(their_ephemeral).to_bytes();

    let (send_label, recv_label): (&[u8], &[u8]) = if my_public.as_bytes() < their_ephemeral.as_bytes() {
        (b"feral-AtoB", b"feral-BtoA")
    } else {
        (b"feral-BtoA", b"feral-AtoB")
    };

    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    hk.expand(send_label, &mut send_key).expect("32 bytes is a valid HKDF output length");
    hk.expand(recv_label, &mut recv_key).expect("32 bytes is a valid HKDF output length");

    shared.zeroize();
    SessionKeys { send_key, recv_key }
}

fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_from_counter(counter);
    cipher.encrypt(Nonce::from_slice(&nonce), plaintext).expect("chacha20poly1305 encryption does not fail")
}

pub fn decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_from_counter(counter);
    cipher.decrypt(Nonce::from_slice(&nonce), ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_session_roundtrip() {
        let id_a = SigningKey::generate(&mut OsRng);
        let id_b = SigningKey::generate(&mut OsRng);

        let init_a = start_handshake(&id_a);
        let init_b = start_handshake(&id_b);

        let parsed_by_b = verify_handshake(&init_a.message).unwrap();
        let parsed_by_a = verify_handshake(&init_b.message).unwrap();
        assert_eq!(parsed_by_b.identity_pubkey, id_a.verifying_key());
        assert_eq!(parsed_by_a.identity_pubkey, id_b.verifying_key());

        let keys_a = derive_session_keys(init_a, &parsed_by_a.peer_ephemeral);
        let keys_b = derive_session_keys(init_b, &parsed_by_b.peer_ephemeral);

        // A's send key must equal B's recv key and vice versa.
        assert_eq!(keys_a.send_key, keys_b.recv_key);
        assert_eq!(keys_a.recv_key, keys_b.send_key);

        let ct = encrypt(&keys_a.send_key, 0, b"hello");
        let pt = decrypt(&keys_b.recv_key, 0, &ct).unwrap();
        assert_eq!(pt, b"hello");

        // wrong counter (nonce reuse boundary) must fail to decrypt
        assert!(decrypt(&keys_b.recv_key, 1, &ct).is_none());
    }

    #[test]
    fn tampered_signature_rejected() {
        let id_a = SigningKey::generate(&mut OsRng);
        let mut init_a = start_handshake(&id_a);
        init_a.message[0] ^= 0xff; // corrupt the ephemeral pubkey after signing
        assert!(verify_handshake(&init_a.message).is_none());
    }
}
