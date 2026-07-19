//! Fuzz the at-rest decoders an attacker with a stolen disk controls: the vault blob
//! parser (both formats) and the localbox AEAD. Invariants: no panics, and nothing
//! fabricated ever decrypts.
//!
//! Note: inputs with a valid vault header reach Argon2id (64 MiB, 3 passes), so this
//! target is inherently slow per-exec. Run it separately and let the cheap header
//! rejections dominate: `cargo +nightly fuzz run vault_open -- -rss_limit_mb=4096`

#![no_main]
use crypto_core::{localbox, vault, DEVICE_KEY_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Wrong-password/garbage-blob opens must error, never panic or "succeed".
    assert!(vault::open("fuzz-password", data).is_err());
    let dk = [7u8; DEVICE_KEY_LEN];
    assert!(vault::open_with("fuzz-password", Some(&dk), data).is_err());

    // Localbox: 24-byte nonce + AEAD ciphertext under a fixed key. Forged blobs must
    // never authenticate.
    let key = [9u8; 32];
    assert!(localbox::open(&key, data).is_none());
});
