//! Keyed local encryption for bulk client data (chat history, contacts).
//!
//! Unlike the [`vault`](crate::vault), which is password-sealed (Argon2id) and opened
//! once at unlock, this is a cheap symmetric AEAD under the account's stable `data_key`.
//! It re-encrypts on every save without the memory-hard KDF cost — the vault already
//! protects the `data_key` itself at rest.
//!
//! Format: `nonce(24) || XChaCha20-Poly1305 ciphertext`.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

const NONCE_LEN: usize = 24;

/// Encrypt `plaintext` under a 32-byte key. A fresh random nonce is used each call.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("XChaCha20-Poly1305 encryption does not fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a blob produced by [`seal`]. Returns `None` on a wrong key or tampering.
pub fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(XNonce::from_slice(nonce), ct).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_key_fails() {
        let key = [3u8; 32];
        let blob = seal(&key, b"chat history bytes");
        assert_eq!(open(&key, &blob).unwrap(), b"chat history bytes");
        assert!(open(&[4u8; 32], &blob).is_none()); // wrong key
        assert!(!blob.windows(4).any(|w| w == b"chat")); // no plaintext in blob
    }

    #[test]
    fn tamper_is_rejected() {
        let key = [5u8; 32];
        let mut blob = seal(&key, b"x");
        let n = blob.len() - 1;
        blob[n] ^= 0xff;
        assert!(open(&key, &blob).is_none());
    }
}
