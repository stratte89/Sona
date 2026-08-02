//! Fuzz the sync-blob openers (SP-20). Both parse bytes the **relay** hands back —
//! `open_history` on a device restoring history during a link, `open_provisioning` on
//! the provisioning handshake — so an untrusted relay chooses every byte, and a panic
//! here aborts device linking.
//!
//! Invariants: never panic, and never authenticate a blob the fuzzer produced. Wrong
//! secret and tampering must stay indistinguishable (no oracle) — both are a decryption
//! error, which is what the `is_err` assertions below pin down.

#![no_main]
use crypto_core::sync::{open_history, open_provisioning, LINK_SECRET_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let link = [3u8; LINK_SECRET_LEN];
    assert!(open_history("fuzz-secret", &link, data).is_err());
    assert!(open_provisioning(&link, data).is_err());
    // A second, different link secret: still nothing forged ever opens.
    let other = [200u8; LINK_SECRET_LEN];
    assert!(open_provisioning(&other, data).is_err());
});
