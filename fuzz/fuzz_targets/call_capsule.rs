//! Fuzz the capsule opener a **locked** device runs (SP-20).
//!
//! This is the highest-privilege parser reachable by an unauthenticated stranger: the
//! public call key is served by `/v1/callkey/{hash}` to anyone, so anyone can seal a
//! capsule to any device, and a locked phone AEAD-opens it before any signature check.
//! A panic here aborts the locked-device drain — precisely the path that has to be
//! robust, because it is the one that rings the phone.
//!
//! The authorization side is fail-closed and correct (`store_locked` refuses to drain
//! without a usable screening index, and an unplaceable caller yields no key); this
//! target is about parser robustness, not an auth hole.
//!
//! Invariants: never panic, and never open a capsule the fuzzer produced.

#![no_main]
use crypto_core::CallKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A fixed key, so the fuzzer spends its budget on the header/length/AEAD parser
    // rather than on X25519 arithmetic it can never satisfy.
    let key = CallKey::from_bytes(&[5u8; 64]);
    assert!(key.open_capsule(data).is_none());
});
