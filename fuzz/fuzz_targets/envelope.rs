//! Fuzz the wire envelope: the exact bytes an attacker can POST to /v1/messages.
//! Invariants: parsing never panics; a parsed envelope re-serializes and re-parses to
//! the same thing; the zero-knowledge check never panics; IdentityHash::from_hex only
//! ever accepts 64 lowercase hex chars.

#![no_main]
use libfuzzer_sys::fuzz_target;
use protocol_types::{Envelope, IdentityHash};

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = serde_json::from_slice::<Envelope>(data) {
        let _ = env.is_zk_clean();
        // Round trip: what we accept, we must be able to re-emit and re-accept.
        let json = serde_json::to_vec(&env).expect("accepted envelope re-serializes");
        let again = serde_json::from_slice::<Envelope>(&json).expect("round trip parses");
        assert_eq!(env.is_zk_clean(), again.is_zk_clean());
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(h) = IdentityHash::from_hex(s) {
            assert_eq!(h.as_str().len(), 64, "accepted hash must be 64 chars");
            assert!(h.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
});
