//! Multi-device (Signal-style) client logic — Phase 2/3.
//!
//! Everything here is **capability-gated** and roster-driven: a single-device account, or
//! any account whose contact has published no roster, keeps the exact 1:1 path from
//! `lib.rs`. The security-critical piece is [`Client::resolve_account_devices`], which
//! resolves a contact's device set **only** from a KT-verified, anti-rollback-pinned
//! roster — a relay that serves a stale epoch (to resurrect a revoked device) or deletes a
//! roster (to downgrade a multi-device account) is caught and the send fails closed.
//!
//! Layers:
//! * **Resolution + pinning** — [`Client::resolve_account_devices`].
//! * **Fan-out** — [`Client::prepare_text_fanout`] / [`prepare_receipt_fanout`]: one
//!   sealed envelope per recipient device *and* per own other device (self-sync), sharing
//!   one message id so every copy dedups. Own-device copies are latency-tolerant, so the
//!   caller posts them after a random jitter ([`self_sync_jitter_secs`]) to blunt the
//!   burst-correlation the relay could otherwise do.
//! * **Attribution** — done in [`crate::History`] (`attribute_device` / `is_own_device`).
//! * **Linking** — [`Client::create_link_request`] (new device),
//!   [`Client::authorize_link`] (primary), [`Client::complete_link`] (new device).
//! * **History sync** — [`Client::export_history`] / [`Client::import_history`], gated by
//!   the account password/PIN + the link secret (`crypto_core::sync`).
//! * **Self-audit** — [`Client::audit_own_roster`].

use crypto_core::sync as csync;
use crypto_core::Account;
use kt_log::{
    verify_roster_inclusion_b64, verify_sth_b64, DeviceRecord, KtEntry, KtRosterEntry,
    SignedTreeHead, MAX_DEVICES, PRIMARY_DEVICE_ID,
};
use protocol_types::{device_mailbox_hash, IdentityHash};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::history::{RosterDevice, RosterRollback};
use crate::{
    now, random_msg_id, seal_payload_to, AttachmentRef, ChatPayload, Client, ClientError, Contact,
    Envelope, Group, History, InboundEvent, ReplyRef, Result, Subscription,
};

/// The relay capability string that gates every multi-device path (re-exported so shells
/// need not depend on `protocol-types` directly).
pub use protocol_types::{CAP_GIF_SEARCH, CAP_HISTORY_SYNC, CAP_MULTI_DEVICE};

/// Upper bound (seconds) of the random delay applied to own-device self-sync copies, so a
/// send doesn't produce a tight, correlatable burst of envelopes to the sender's mailboxes.
/// Tuning: a few seconds of spread (plus ordinary network timing noise) already breaks
/// tight-burst correlation; 25 s made cross-device history feel broken (a sent message
/// took up to half a minute to appear on the sender's other devices).
pub const SELF_SYNC_MAX_JITTER_SECS: u64 = 8;

/// A random own-device self-sync delay in `0..=SELF_SYNC_MAX_JITTER_SECS` seconds.
pub fn self_sync_jitter_secs() -> u64 {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    u64::from_le_bytes(b) % (SELF_SYNC_MAX_JITTER_SECS + 1)
}

/// The devices resolved for an account from its (verified, pinned) roster.
#[derive(Debug, Clone)]
pub struct ResolvedDevices {
    /// The account's primary (KT-bound) identity key — the stable conversation id.
    pub primary_key: String,
    /// `Some(epoch)` when a roster was verified; `None` for a single-device account.
    pub roster_seq: Option<u64>,
    /// Every device (primary included). Single-device accounts get just the primary.
    pub devices: Vec<RosterDevice>,
}

/// A prepared multi-device fan-out: sealed envelopes ready to relay. `immediate` targets
/// the recipient's devices; `deferred` are self-sync copies to the sender's own other
/// devices (post after [`self_sync_jitter_secs`]).
#[derive(Debug, Clone)]
pub struct Fanout {
    pub msg_id: String,
    pub sent_at: u64,
    pub immediate: Vec<Envelope>,
    pub deferred: Vec<Envelope>,
}

/// Outcome of [`Client::complete_link`]: the imported history plus whether the encrypted
/// history blob was actually retrieved+decrypted. `history_synced == false` means the
/// device is fully linked and functional, but pre-existing history did **not** transfer
/// (the blob expired past its TTL, or the primary hadn't uploaded yet) — the caller should
/// prompt a re-sync rather than dead-ending.
#[derive(Debug, Clone)]
pub struct LinkResult {
    pub history: History,
    pub history_synced: bool,
}

/// The QR / short-code payload a **new** device shows to the primary to be linked. Carries
/// only public material plus the link secret (which never reaches the relay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequest {
    /// The new device's self-minted id (32 hex).
    pub device_id: String,
    /// The new device's proof-of-possession record (signed by its own key, bound to the
    /// account username hash).
    pub record: DeviceRecord,
    /// 256-bit link secret, base64 — mixed into the history-sync and provisioning keys.
    pub link_secret_b64: String,
    /// Capability id (32 hex) where the primary PUTs the provisioning blob.
    pub provisioning_id: String,
    /// Capability id (32 hex) where the new device PUT its Android hardware-attestation
    /// chain, sealed under the link secret (an attestation chain is several KB — far too
    /// big for the QR itself). The chain attests an ephemeral Keystore key whose
    /// challenge is `attest::link_attest_challenge(device_id, record.identity_key)`.
    /// Optional and advisory: absent on desktop/older devices; the primary fetches it
    /// (`fetch_link_attestation`), verifies (`verify_link_attestation`), and shows the
    /// verdict before the user confirms — it never gates the link by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest_id: Option<String>,
}

/// What the primary seals (under the link secret) into the provisioning blob for the new
/// device to fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Provisioning {
    username: String,
    /// Capability id of the sealed history blob.
    history_sync_id: String,
    /// The account primary (KT-bound) identity key, so the new device can pin attribution.
    primary_key: String,
}

/// Result of [`Client::audit_own_roster`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterAudit {
    /// No roster published for our account (single-device) — nothing to audit.
    SingleDevice,
    /// The published roster matches what we last pinned/authorized.
    Ok { seq: u64, devices: usize },
    /// The roster contains device(s) we do not recognize from our last pinned view — a
    /// possible rogue enrollment. (On the primary this should never happen unless the
    /// account key was compromised.)
    UnknownDevices {
        seq: u64,
        unknown_device_ids: Vec<String>,
    },
}

/// Result of [`Client::verify_device_revocation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationCheck {
    /// KT-verified: this device's key is absent from the account's binding and roster —
    /// it really was removed from the account.
    Revoked,
    /// This device's key is still the account binding (primary) or in the roster
    /// (linked). Local device identity was fixed up if the roster had moved us — the
    /// caller should re-subscribe on the (possibly new) mailbox.
    StillActive,
}

/// A random 32-hex-char id (128 bits), for device ids and provisioning capability ids.
fn random_hex_id() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
mod link;
mod revoke;
mod roster;
mod selfsync;
