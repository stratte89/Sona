//! Sona blind relay.
//!
//! The server's entire job is to hold opaque ciphertext for offline recipients and
//! hand it over when they connect, addressing everything by [`protocol_types::IdentityHash`]
//! alone. It never sees plaintext, holds no private keys, and — thanks to sealed sender
//! — never learns who sent a message.
//!
//! Modules:
//! * [`store`]  — the blind, hash-addressed message queue (no I/O, no crypto).
//! * [`auth`]   — Ed25519 signature verification, single-use login nonces, rate limiting.
//! * [`access`] — discoverability tiers (open/token/stealth) + optional IP allowlist.
//! * [`state`]  — shared in-memory state (directory, queue, live channels).
//! * [`http`]   — the Axum REST + WebSocket surface.

pub mod access;
pub mod auth;
pub mod call;
pub mod db;
pub mod http;
pub mod push;
pub mod quic;
pub mod state;
pub mod store;

pub use db::Db;
pub use http::app;
pub use state::{AppState, Config};
pub use store::{MessageStore, RelayError, MAX_MAILBOX_DEPTH};
