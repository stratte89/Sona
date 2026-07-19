//! Quick unlock: PIN / biometric / auto-unlock without weakening the password vault.
//!
//! The design principle: the vault format and its Argon2id(password) [+ device key]
//! derivation are **never** touched. A quick-unlock method stores a *wrapped copy of the
//! cached vault seal key* (the same [`vault::SealKey`] an unlocked session already holds)
//! in a separate blob next to the vault. Unwrapping it opens the vault with zero KDF work
//! and — crucially — without the password, so the password still never has to be stored
//! or kept in memory.
//!
//! Wrapping keys (KEKs):
//!
//! * **PIN** — `HKDF(Argon2id(pin, salt) || device_key)`. A 4–8 character PIN has far too
//!   little entropy to stand alone against an offline attacker, so the OS-keyring /
//!   Keystore **device key is mandatory**: a stolen `quick_pin.bin` + vault blob cannot be
//!   brute-forced off the device at all — the attacker must come through this code path on
//!   the device, where the client layer enforces an attempt counter (wipe after N
//!   failures). No device key available ⇒ PIN unlock cannot be enabled.
//! * **Auto-unlock** — `HKDF(device_key)` alone. Opt-in convenience: possession of the
//!   unlocked OS session is the whole gate. The blob is useless off-device.
//! * **Biometric (Android)** — the seal-key bytes are encrypted by an Android Keystore
//!   AES-GCM key that requires a BIOMETRIC_STRONG authentication per use; that wrapping
//!   happens on the Kotlin side (the key is non-exportable), so this module only supplies
//!   the seal-key byte export/import (see [`vault::SealKey::to_bytes`]).
//!
//! Because every method wraps the *seal key* (not the password), a password change
//! rotates the seal key and instantly invalidates every quick-unlock blob — the client
//! re-wraps (PIN/auto) or drops (biometric) them as part of the change ceremony.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{SealKey, VaultError};
use crate::DEVICE_KEY_LEN;

const MAGIC: &[u8; 4] = b"SQK1"; // Sona Quick-unlock blob, v1
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Blob kind discriminator (stored in the header, bound as AAD).
const KIND_PIN: u8 = 1;
const KIND_AUTO: u8 = 2;

/// Argon2id cost for the PIN KDF. Deliberately the same class as the vault's: the PIN is
/// only ever brute-forceable *on device* (the device key is a mandatory input), so this
/// mostly slows an on-device guessing loop between the client layer's counted attempts.
const ARGON_MEM_KIB: u32 = 65_536;
const ARGON_TIME: u32 = 3;
const ARGON_LANES: u32 = 1;

/// PIN policy: 4–8 characters, digits or anything printable (the user picks the style).
pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 8;
/// High-value ceremonies (username/password change) require a PIN of at least this length.
pub const CEREMONY_MIN_PIN_LEN: usize = 6;

/// Result of checking a candidate PIN against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinStrength {
    pub acceptable: bool,
    /// Human-readable reasons the PIN was rejected (empty when acceptable).
    pub problems: Vec<String>,
    /// Whether this PIN is long enough (≥ [`CEREMONY_MIN_PIN_LEN`]) to authorize
    /// username/password changes.
    pub ceremony_grade: bool,
}

/// Validate a PIN: 4–8 characters, no whitespace/control characters, not a trivial
/// sequence (all-same like `1111`, or a straight run like `1234`/`4321`/`abcd`).
pub fn check_pin(pin: &str) -> PinStrength {
    let mut problems = Vec::new();
    let n = pin.chars().count();
    if n < PIN_MIN_LEN {
        problems.push(format!("at least {PIN_MIN_LEN} characters"));
    }
    if n > PIN_MAX_LEN {
        problems.push(format!("at most {PIN_MAX_LEN} characters"));
    }
    if pin.chars().any(|c| c.is_whitespace() || c.is_control()) {
        problems.push("no spaces or control characters".into());
    }
    let chars: Vec<char> = pin.chars().collect();
    if n >= PIN_MIN_LEN {
        if chars.iter().all(|&c| c == chars[0]) {
            problems.push("not all the same character".into());
        } else {
            let ascending = chars.windows(2).all(|w| (w[1] as i64) - (w[0] as i64) == 1);
            let descending = chars.windows(2).all(|w| (w[0] as i64) - (w[1] as i64) == 1);
            if ascending || descending {
                problems.push("not a simple sequence".into());
            }
        }
    }
    PinStrength {
        acceptable: problems.is_empty(),
        ceremony_grade: problems.is_empty() && n >= CEREMONY_MIN_PIN_LEN,
        problems,
    }
}

/// Derive the PIN wrapping key. Both inputs are required: Argon2id stretches the PIN,
/// then HKDF binds in the device key so the result is meaningless off this device.
fn pin_kek(
    pin: &str,
    device_key: &[u8; DEVICE_KEY_LEN],
    salt: &[u8],
) -> Result<[u8; KEY_LEN], VaultError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_TIME, ARGON_LANES, Some(KEY_LEN))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; KEY_LEN];
    argon
        .hash_password_into(pin.as_bytes(), salt, &mut stretched)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;

    let mut ikm = [0u8; KEY_LEN + DEVICE_KEY_LEN];
    ikm[..KEY_LEN].copy_from_slice(&stretched);
    ikm[KEY_LEN..].copy_from_slice(device_key);
    stretched.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut kek = [0u8; KEY_LEN];
    hk.expand(b"sona-quick-unlock-pin-v1", &mut kek)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    ikm.zeroize();
    Ok(kek)
}

/// Derive the auto-unlock wrapping key from the device key alone.
fn auto_kek(device_key: &[u8; DEVICE_KEY_LEN], salt: &[u8]) -> Result<[u8; KEY_LEN], VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), device_key);
    let mut kek = [0u8; KEY_LEN];
    hk.expand(b"sona-quick-unlock-auto-v1", &mut kek)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(kek)
}

/// Seal `seal_key` into a quick-unlock blob:
/// `MAGIC(4) || kind(1) || salt(16) || nonce(24) || ct`, with the header bound as AAD so a
/// blob cannot be replayed under a different kind.
fn wrap(
    kind: u8,
    kek: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    seal_key: &SealKey,
) -> Result<Vec<u8>, VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut header = Vec::with_capacity(4 + 1 + SALT_LEN);
    header.extend_from_slice(MAGIC);
    header.push(kind);
    header.extend_from_slice(salt);

    let cipher = XChaCha20Poly1305::new(kek.into());
    let plaintext = seal_key.to_bytes();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultError::Decryption)?;

    let mut blob = header;
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Open a quick-unlock blob with a derived KEK. Any tampering, wrong PIN, or wrong
/// device key fails as an indistinguishable [`VaultError::Decryption`].
fn unwrap(
    kind: u8,
    blob: &[u8],
    kek_for_salt: impl FnOnce(&[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], VaultError>,
) -> Result<SealKey, VaultError> {
    const HEADER: usize = 4 + 1 + SALT_LEN;
    if blob.len() < HEADER + NONCE_LEN {
        return Err(VaultError::Malformed);
    }
    if &blob[0..4] != MAGIC || blob[4] != kind {
        return Err(VaultError::Malformed);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[5..5 + SALT_LEN]);
    let nonce = &blob[HEADER..HEADER + NONCE_LEN];
    let ct = &blob[HEADER + NONCE_LEN..];

    let mut kek = kek_for_salt(&salt)?;
    let cipher = XChaCha20Poly1305::new((&kek).into());
    kek.zeroize();
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: &blob[0..HEADER],
            },
        )
        .map_err(|_| VaultError::Decryption)?;
    let plaintext = Zeroizing::new(plaintext);
    SealKey::from_bytes(&plaintext)
}

/// Wrap the seal key under a PIN + the device key (mandatory — see module docs).
pub fn wrap_seal_key_pin(
    seal_key: &SealKey,
    pin: &str,
    device_key: &[u8; DEVICE_KEY_LEN],
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut kek = pin_kek(pin, device_key, &salt)?;
    let blob = wrap(KIND_PIN, &kek, &salt, seal_key);
    kek.zeroize();
    blob
}

/// Recover the seal key from a PIN blob. Wrong PIN / wrong device key / tampering all
/// return [`VaultError::Decryption`]. The caller (client layer) must count failures.
pub fn unwrap_seal_key_pin(
    pin: &str,
    device_key: &[u8; DEVICE_KEY_LEN],
    blob: &[u8],
) -> Result<SealKey, VaultError> {
    unwrap(KIND_PIN, blob, |salt| pin_kek(pin, device_key, salt))
}

/// Wrap the seal key under the device key alone (auto-unlock).
pub fn wrap_seal_key_auto(
    seal_key: &SealKey,
    device_key: &[u8; DEVICE_KEY_LEN],
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut kek = auto_kek(device_key, &salt)?;
    let blob = wrap(KIND_AUTO, &kek, &salt, seal_key);
    kek.zeroize();
    blob
}

/// Recover the seal key from an auto-unlock blob.
pub fn unwrap_seal_key_auto(
    device_key: &[u8; DEVICE_KEY_LEN],
    blob: &[u8],
) -> Result<SealKey, VaultError> {
    unwrap(KIND_AUTO, blob, |salt| auto_kek(device_key, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{derive_seal_key, seal_with_key, VaultPayload};

    fn seal_key() -> SealKey {
        derive_seal_key("Correct-Horse-Battery-9", Some(&[7u8; DEVICE_KEY_LEN])).unwrap()
    }

    #[test]
    fn pin_policy() {
        assert!(!check_pin("123").acceptable); // too short
        assert!(!check_pin("123456789").acceptable); // too long
        assert!(!check_pin("1111").acceptable); // repeated
        assert!(!check_pin("1234").acceptable); // ascending run
        assert!(!check_pin("9876").acceptable); // descending run
        assert!(!check_pin("12 4").acceptable); // whitespace
        let ok = check_pin("2846");
        assert!(ok.acceptable && !ok.ceremony_grade);
        let strong = check_pin("284617");
        assert!(strong.acceptable && strong.ceremony_grade);
        let alpha = check_pin("k9x!Qz");
        assert!(alpha.acceptable && alpha.ceremony_grade);
    }

    #[test]
    fn pin_round_trip_and_wrong_inputs_fail() {
        let dk = [3u8; DEVICE_KEY_LEN];
        let sk = seal_key();
        let blob = wrap_seal_key_pin(&sk, "2846", &dk).unwrap();

        let out = unwrap_seal_key_pin("2846", &dk, &blob).unwrap();
        // The recovered key seals blobs identical in format to the original key's.
        let payload = VaultPayload {
            account_id: "a".into(),
            secret_state: vec![1; 8],
            data_key: vec![2; 32],
        };
        let sealed = seal_with_key(&out, &payload).unwrap();
        assert!(crate::vault::open_with_seal_key(&sk, &sealed).is_ok());

        assert!(matches!(
            unwrap_seal_key_pin("2847", &dk, &blob),
            Err(VaultError::Decryption)
        ));
        let wrong_dk = [4u8; DEVICE_KEY_LEN];
        assert!(matches!(
            unwrap_seal_key_pin("2846", &wrong_dk, &blob),
            Err(VaultError::Decryption)
        ));
    }

    #[test]
    fn auto_round_trip_and_kind_confusion_rejected() {
        let dk = [5u8; DEVICE_KEY_LEN];
        let sk = seal_key();
        let auto = wrap_seal_key_auto(&sk, &dk).unwrap();
        assert!(unwrap_seal_key_auto(&dk, &auto).is_ok());
        // An auto blob must not open through the PIN path (kind byte + AAD bind it).
        assert!(unwrap_seal_key_pin("2846", &dk, &auto).is_err());
        // Tampered ciphertext is rejected.
        let mut bad = auto.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(matches!(
            unwrap_seal_key_auto(&dk, &bad),
            Err(VaultError::Decryption)
        ));
    }
}
