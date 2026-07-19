//! Fuzz the Key Transparency proof/head decoders: everything a malicious *server* (or
//! MITM) can feed a verifying client. Invariants: no panics on arbitrary base64/JSON;
//! a garbage signed tree head never verifies under a random pinned key.

#![no_main]
use kt_log::{
    consistency_from_b64, inclusion_from_b64, verify_sth_b64, verifying_key_from_b64,
    SignedTreeHead,
};
use libfuzzer_sys::fuzz_target;

// A fixed, valid-shape pinned key (all zeros is not a valid Ed25519 point, which is
// itself a path worth exercising) plus a syntactically valid random-ish one.
const PIN_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PIN_B: &str = "LRkBD8QzCQoz4UEMZBDh89dTrqUnoDCTg2smcdvM6MY";

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = inclusion_from_b64(s);
        let _ = consistency_from_b64(s);
        let _ = verifying_key_from_b64(s);
    }
    if let Ok(sth) = serde_json::from_slice::<SignedTreeHead>(data) {
        // Fuzzer-fabricated heads must never verify (forging an Ed25519 signature via
        // libFuzzer would be a bigger headline than this messenger).
        assert!(!verify_sth_b64(PIN_A, &sth));
        assert!(!verify_sth_b64(PIN_B, &sth));
        let _ = sth.root_bytes();
    }
});
