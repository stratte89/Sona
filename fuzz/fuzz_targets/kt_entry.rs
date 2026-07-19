//! Fuzz KT entry validation: the bytes an attacker can POST to /v1/register. The
//! server calls `verify_signature()` on the parsed entry before appending; that path
//! must never panic, and a fabricated entry must never carry a valid signature.

#![no_main]
use kt_log::KtEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = serde_json::from_slice::<KtEntry>(data) {
        // Exercises base64 decoding of keys/signatures and the domain-separated
        // payload construction. A fuzzer-built entry verifying would mean signature
        // forgery — assert it can't happen.
        assert!(!entry.verify_signature());
        let _ = entry.leaf_bytes();
        let _ = entry.signing_payload();
    }
});
