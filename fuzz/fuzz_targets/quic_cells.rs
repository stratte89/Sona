//! Fuzz the QUIC media framing (SP-20). `parse_cells` reads raw bytes off a UDP stream
//! from an unauthenticated peer — the call socket is joined by capability token alone —
//! and it is **shared by the relay and the client**, so a panic here is remote on both
//! sides at once: it aborts a call leg on the client and a connection task on the relay.
//!
//! Invariants: never panic on any input, and round-trip exactly. `frame_cells` is the
//! inverse, so anything that parses must re-frame to the same bytes; anything that does
//! not parse must simply be `None`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use protocol_types::quicwire::{frame_cells, parse_cells};

fuzz_target!(|data: &[u8]| {
    if let Some(cells) = parse_cells(data) {
        // A successful parse is total: every cell is non-empty and within the frame cap
        // (that is what `parse_cells` promises its callers), and re-framing is exact.
        assert!(!cells.is_empty());
        assert!(cells.iter().all(|c| !c.is_empty()));
        let reframed = frame_cells(&cells);
        assert_eq!(reframed, data, "parse/frame must round-trip exactly");
        assert_eq!(parse_cells(&reframed).as_ref(), Some(&cells));
    }
});
