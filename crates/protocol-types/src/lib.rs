//! Shared wire types for Sona.
//!
//! This crate is the contract between client and server. It deliberately contains
//! **no cryptography and no I/O** — only the shapes of data that cross the wire and
//! the rules for how the server is allowed to address users.
//!
//! Design rule (the zero-knowledge invariant): the server addresses users **only**
//! by [`IdentityHash`]. A raw account identifier must never appear in a wire frame.
//! [`Envelope::is_zk_clean`] enforces this; the server rejects any frame that fails it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// SHA-256 of a user's stable account identifier, hex-encoded (64 chars).
///
/// The server stores and routes on this value alone. It cannot reverse the hash to
/// recover the identifier, so it never learns *who* a mailbox belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct IdentityHash(String);

/// Deserialize through [`IdentityHash::from_hex`], so the 64-lowercase-hex invariant
/// holds for values that arrive **off the wire** too (SP-16).
///
/// Deriving `Deserialize` on the inner `String` bypassed the constructor entirely:
/// `POST /v1/messages` takes a `Json<Envelope>` and never re-validated `to`, so an
/// arbitrary string — a literal username, or multibyte text that then panicked a
/// diagnostic log slice (SP-17) — became a mailbox key in the store and landed in the
/// cleartext `messages.target_hash` column. `is_zk_clean` did not catch it: that checks
/// the separate `raw_identifier` field.
impl<'de> Deserialize<'de> for IdentityHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        IdentityHash::from_hex(&s)
            .ok_or_else(|| serde::de::Error::custom("malformed identity hash"))
    }
}

impl IdentityHash {
    /// Derive the routing hash from a raw account identifier (e.g. the account UUID).
    /// The raw identifier stays on the client; only the hash is ever sent.
    pub fn from_identifier(identifier: &str) -> Self {
        let mut h = Sha256::new();
        h.update(identifier.as_bytes());
        IdentityHash(hex::encode(h.finalize()))
    }

    /// Wrap an already-computed 64-char hex hash. Returns `None` if the input is not
    /// a well-formed lowercase hex SHA-256 digest — malformed hashes never enter the system.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(IdentityHash(s))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ─────────────────────────── Multi-device (capability-gated) ───────────────────────────

/// Server capability string: the relay understands device rosters
/// (`/v1/kt/roster`) and per-device mailboxes. Clients must treat its absence
/// (old relay, `/v1/capabilities` 404) as "single-device only".
pub const CAP_MULTI_DEVICE: &str = "multi-device-v1";
/// Server capability string: the relay stores opaque history-sync blobs (`/v1/sync`).
pub const CAP_HISTORY_SYNC: &str = "history-sync-v1";
/// Server capability string: the relay proxies GIF search + media (`/v1/gif/*`) so
/// client IPs never reach the GIF provider. Absent = clients hide the GIF UI.
pub const CAP_GIF_SEARCH: &str = "gif-search-v1";
/// Server capability string: the relay fires content-free wake POSTs to a registered
/// webhook endpoint (`/v1/push/register` with an https URL — the UnifiedPush shape).
pub const CAP_PUSH_WEBHOOK: &str = "push-webhook-v1";
/// Server capability string: the relay accepts `fcm:<token>` push endpoints and wakes
/// them through Firebase Cloud Messaging (data-only, constant payload). Advertised only
/// when the relay is configured with an FCM service account.
pub const CAP_PUSH_FCM: &str = "push-fcm-v1";
/// Server capability string: first-time account registration requires a single-use
/// invite code (`x-sona-invite` header on `POST /v1/register`). Rotations, renames,
/// and linked-device mailboxes are unaffected — only brand-new claims are gated.
/// Clients show an invite-code field at account creation when this is advertised.
pub const CAP_INVITE_REGISTER: &str = "invite-register-v1";

/// The reserved id of an account's primary device (mirrors `kt_log::PRIMARY_DEVICE_ID`;
/// duplicated here because this crate must stay dependency-light).
pub const PRIMARY_DEVICE_ID: &str = "0";

/// The mailbox hash for one of an account's devices.
///
/// * The **primary** device keeps the legacy account mailbox (`SHA-256(username)`) —
///   this is what keeps old senders and single-device accounts working unchanged.
/// * A **linked** device gets a domain-separated hash of the account mailbox and its
///   device id, so any sender holding the (KT-verified) roster can derive every
///   device's mailbox without learning anything new, and the relay still only ever
///   sees opaque hashes.
///
/// Returns `None` if `username_hash` is not a well-formed identity hash.
pub fn device_mailbox_hash(username_hash: &str, device_id: &str) -> Option<IdentityHash> {
    let base = IdentityHash::from_hex(username_hash)?;
    if device_id == PRIMARY_DEVICE_ID {
        return Some(base);
    }
    let mut h = Sha256::new();
    h.update(b"sona-device-mailbox-v1|");
    h.update(base.as_str().as_bytes());
    h.update(b"|");
    h.update(device_id.as_bytes());
    Some(IdentityHash(hex::encode(h.finalize())))
}

/// The **call-control mailbox** of one device: where minimal incoming-call capsules are
/// delivered, kept separate from the device's message mailbox on purpose.
///
/// A locked device drains this one with its call-control key alone, so it must not be the
/// mailbox that carries chat ciphertext — and the primary gets a derived hash too (unlike
/// [`device_mailbox_hash`], which maps the primary back to the account mailbox), because
/// the account mailbox is exactly the one it must not be.
pub fn call_mailbox_hash(username_hash: &str, device_id: &str) -> Option<IdentityHash> {
    let base = IdentityHash::from_hex(username_hash)?;
    let mut h = Sha256::new();
    h.update(b"sona-call-mailbox-v1|");
    h.update(base.as_str().as_bytes());
    h.update(b"|");
    h.update(device_id.as_bytes());
    Some(IdentityHash(hex::encode(h.finalize())))
}

/// The exact decoded length of a WebSocket login nonce. The relay issues 32 random
/// bytes ([`server::auth::ChallengeStore::issue`]); both sides refuse anything else, so
/// the relay cannot smuggle a longer structure through the challenge field (SP-01).
pub const WS_AUTH_NONCE_LEN: usize = 32;

/// Canonical bytes signed to authenticate a WebSocket/mailbox session.
///
/// **This is the fix for the blind-signing oracle (SP-01).** The relay chooses the
/// challenge nonce, and the key that signs it is the account's long-term Ed25519
/// identity key — the same key that signs KT bindings, device rosters, device
/// proofs-of-possession, group epochs, and every `*_signing_message` below. When the
/// client signed the *raw* nonce, a hostile relay could serve any other context's
/// signing payload as the "nonce" and harvest a genuine signature over it, one per
/// reconnect. Domain-separating the login message makes that impossible: a login
/// signature can never coincide with any other signing context.
///
/// `mailbox_hash` is bound in deliberately — with `prefix || nonce` alone, a signature
/// harvested from one mailbox would still authenticate a *different* mailbox the relay
/// controls.
pub fn ws_auth_signing_message(mailbox_hash: &str, nonce_b64: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-ws-auth-v1|");
    v.extend_from_slice(mailbox_hash.as_bytes());
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// Canonical bytes an account signs to enumerate **its own** Key Transparency leaves.
///
/// The enumeration is gated (SP-13) rather than public: "every leaf under this username"
/// served to anyone would be a fresh activity-enumeration oracle on top of an already
/// reversible mailbox hash. Domain-separated and bound to a single-use server nonce, so
/// a request cannot be replayed or moved to another account.
pub fn kt_leaves_signing_message(identity_hash: &str, nonce_b64: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-kt-leaves-v1|");
    v.extend_from_slice(identity_hash.as_bytes());
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// Canonical bytes a client signs (Ed25519, with its identity signing key) to authorize
/// adding one-time keys to its own directory record. Domain-separated and binds the hash
/// to the exact key list, so a signature can't be replayed for a different set.
pub fn one_time_keys_signing_message(identity_hash: &str, one_time_keys: &[String]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-otk-upload-v1|");
    v.extend_from_slice(identity_hash.as_bytes());
    for k in one_time_keys {
        v.push(b'|');
        v.extend_from_slice(k.as_bytes());
    }
    v
}

/// Canonical bytes a client signs to register a content-free push endpoint for its own
/// mailbox. Domain-separated, and binds the exact endpoint *and* a single-use server
/// nonce — so it can't be replayed later, replayed for a different URL, or confused
/// with the (raw-nonce) WebSocket login signature.
pub fn push_register_signing_message(
    identity_hash: &str,
    endpoint: &str,
    nonce_b64: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-push-register-v1|");
    v.extend_from_slice(identity_hash.as_bytes());
    v.push(b'|');
    v.extend_from_slice(endpoint.as_bytes());
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// Canonical bytes a device signs to publish its call-control key. Bound to the exact
/// mailbox, the key being published, its mint time, and a single-use server nonce — so a
/// publication cannot be replayed, moved to another mailbox, or rolled back to an older
/// key by a relay that recorded an earlier request.
pub fn call_key_publish_signing_message(
    mailbox_hash: &str,
    call_key: &str,
    created_at: u64,
    nonce_b64: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-call-key-publish-v1|");
    v.extend_from_slice(mailbox_hash.as_bytes());
    v.push(b'|');
    v.extend_from_slice(call_key.as_bytes());
    v.push(b'|');
    v.extend_from_slice(created_at.to_string().as_bytes());
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// Canonical bytes a client signs to remove its push endpoint. Same properties as
/// [`push_register_signing_message`].
pub fn push_unregister_signing_message(identity_hash: &str, nonce_b64: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-push-unregister-v1|");
    v.extend_from_slice(identity_hash.as_bytes());
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// Canonical bytes the account's primary device signs to delete the account from the
/// relay. Domain-separated and bound to a single-use server nonce (no replay) and to
/// the exact set of alias mailboxes (former usernames) being deleted along with it —
/// the server independently verifies each alias belongs to the same signing key before
/// touching it, so the list can widen the deletion only to mailboxes the signer owns.
pub fn account_delete_signing_message(
    identity_hash: &str,
    alias_hashes: &[String],
    nonce_b64: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"sona-account-delete-v1|");
    v.extend_from_slice(identity_hash.as_bytes());
    for a in alias_hashes {
        v.push(b'|');
        v.extend_from_slice(a.as_bytes());
    }
    v.push(b'|');
    v.extend_from_slice(nonce_b64.as_bytes());
    v
}

/// A recipient's published key material, used by a sender to start a Double Ratchet
/// session. The server stores and serves these blindly (and, later, mirrors each one
/// into the Key Transparency log so a swapped key is detectable). All fields base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// Long-term Curve25519 identity key — the peer's stable cryptographic identity.
    pub identity_key: String,
    /// Long-term Ed25519 key — used to verify Key Transparency entries are really theirs.
    pub signing_key: String,
    /// A one-time Curve25519 key, consumed when a session is established.
    pub one_time_key: String,
}

/// One Double Ratchet ciphertext on the wire. The server treats this as opaque; it
/// rides inside [`Envelope::ciphertext`] (JSON-encoded) so the envelope stays generic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextMessage {
    /// Olm message type: `0` = pre-key (session-initiating), `1` = normal ratchet message.
    pub message_type: u8,
    /// Base64 of the serialized ratchet message body.
    pub body: String,
}

/// The kind of payload an [`Envelope`] carries. The server treats every variant as
/// opaque ciphertext — these tags exist only so the *recipient* can route to the
/// right handler after decryption, and so the server can apply per-kind retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    /// A chat message (Double Ratchet ciphertext).
    Message,
    /// A friend request / contact handshake.
    ContactRequest,
    /// A key-change / verification notice between a user's own devices.
    DeviceSync,
    /// A minimal incoming-call capsule, sealed to a device's call-control key and
    /// addressed to its call-control mailbox. Never a ratchet ciphertext: a locked
    /// device opens it without touching the account vault.
    CallCapsule,
}

/// Sender-declared wake class. Read by the relay ONLY to decide whether/how to fire a
/// content-free push wake for an offline recipient — it is never stored beyond routing
/// and carries no identifier. `None` = never wake (receipts, typing, self-sync);
/// `Normal` = debounced wake (chat messages); `Call` = immediate ring wake (fresh call
/// offers only); `CallControl` = urgent but silent wake (winner/cancel/terminal controls).
/// Absent on the wire decodes as `Normal`. The two call classes are intentionally
/// separate: an asleep device must wake to stop an existing ring without presenting a
/// new generic ring while its vault is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeClass {
    None,
    #[default]
    Normal,
    Call,
    CallControl,
}

impl WakeClass {
    /// The constant webhook body the relay POSTs for this class — identical for every
    /// user and every message, and the ONLY thing a UnifiedPush distributor (or any
    /// webhook broker) ever carries. It is the wire between the relay and the Android
    /// receiver that turns it back into a wake class, so both sides read it from here.
    pub const fn wake_body(self) -> &'static str {
        match self {
            Self::Call => "wake-call",
            Self::CallControl => "wake-call-control",
            Self::None | Self::Normal => "wake",
        }
    }

    /// The class tag inside an FCM data-only wake (`{"t": …}`) — the same contract as
    /// [`wake_body`](Self::wake_body) for the Google transport, parsed back by the
    /// Android messaging service. Short because it rides in every wake.
    pub const fn fcm_tag(self) -> &'static str {
        match self {
            Self::Call => "c",
            Self::CallControl => "x",
            Self::None | Self::Normal => "m",
        }
    }
}

/// One unit of traffic between two clients, relayed blindly by the server.
///
/// Everything sensitive lives inside `ciphertext`, which the server never opens.
/// The only fields the server reads are `to` (for routing), `kind`/`expires_at`
/// (for retention), and `wake` (push-wake routing) — never anything that identifies
/// the sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Recipient mailbox — the routing hash. The *only* address the server understands.
    pub to: IdentityHash,
    /// Opaque, end-to-end-encrypted body. Base64 of the ratchet ciphertext.
    pub ciphertext: String,
    pub kind: PayloadKind,
    /// Per-message id (client-generated, random) used for dedup and delivery receipts.
    pub msg_id: String,
    /// Unix seconds after which the server must drop the message if still undelivered.
    pub expires_at: Option<u64>,
    /// Sender-declared wake class (see [`WakeClass`]). Old clients omit it ⇒ `Normal`.
    #[serde(default)]
    pub wake: WakeClass,
    /// Reserved for the deprecated raw-identifier field. Must always be absent.
    /// Present here purely so [`Envelope::is_zk_clean`] can reject any client/server
    /// build that tries to smuggle a raw id through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_identifier: Option<String>,
}

impl Envelope {
    /// The zero-knowledge invariant: a frame is clean only if it carries no raw
    /// identifier. The server rejects (`false`) anything that fails this — fail-closed.
    pub fn is_zk_clean(&self) -> bool {
        self.raw_identifier.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SP-16: the `from_hex` invariant must hold for values that arrive off the wire,
    /// not just ones built through the constructor. A derived `Deserialize` on the inner
    /// String let an arbitrary attacker-chosen string become a mailbox key.
    #[test]
    fn identity_hash_deserializes_only_well_formed_hashes() {
        let good = IdentityHash::from_identifier("bob");
        let json = serde_json::to_string(&good).unwrap();
        assert_eq!(serde_json::from_str::<IdentityHash>(&json).unwrap(), good);

        for bad in [
            "\"bob\"",                      // a literal username
            "\"\"",                         // empty
            "\"\u{20ac}\u{20ac}\u{20ac}\"", // multibyte — also the SP-17 log panic
            "\"zz\"",                       // non-hex
            "\"AA\"",                       // right alphabet, wrong length
        ] {
            assert!(
                serde_json::from_str::<IdentityHash>(bad).is_err(),
                "{bad} must not deserialize into an IdentityHash",
            );
        }
        // Uppercase hex of the right length is normalized, not rejected — `from_hex`
        // lowercases and trims, and a stored hash must round-trip stably.
        let upper = format!("\"{}\"", "A".repeat(64));
        assert_eq!(
            serde_json::from_str::<IdentityHash>(&upper)
                .unwrap()
                .as_str(),
            "a".repeat(64),
        );
    }

    #[test]
    fn identity_hash_is_deterministic_and_64_hex() {
        let a = IdentityHash::from_identifier("alice-uuid");
        let b = IdentityHash::from_identifier("alice-uuid");
        assert_eq!(a, b);
        assert_eq!(a.as_str().len(), 64);
        assert!(a.as_str().bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_identifiers_differ() {
        assert_ne!(
            IdentityHash::from_identifier("alice"),
            IdentityHash::from_identifier("bob")
        );
    }

    #[test]
    fn from_hex_rejects_malformed() {
        assert!(IdentityHash::from_hex("not-hex").is_none());
        assert!(IdentityHash::from_hex(&"a".repeat(63)).is_none());
        assert!(IdentityHash::from_hex(&"a".repeat(64)).is_some());
        assert!(IdentityHash::from_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn call_mailboxes_are_distinct_from_every_message_mailbox() {
        let account = IdentityHash::from_identifier("alice");
        let device = "a".repeat(32);
        let call = call_mailbox_hash(account.as_str(), &device).unwrap();
        // Never the account mailbox, never the device's message mailbox — including for
        // the primary, whose message mailbox IS the account mailbox.
        assert_ne!(call, account);
        assert_ne!(
            call,
            device_mailbox_hash(account.as_str(), &device).unwrap()
        );
        let primary_call = call_mailbox_hash(account.as_str(), PRIMARY_DEVICE_ID).unwrap();
        assert_ne!(primary_call, account);
        assert_ne!(primary_call, call);
        // Deterministic and well-formed.
        assert_eq!(call, call_mailbox_hash(account.as_str(), &device).unwrap());
        assert!(IdentityHash::from_hex(call.as_str()).is_some());
        assert!(call_mailbox_hash("not-a-hash", &device).is_none());
    }

    #[test]
    fn device_mailbox_hashes_are_derived_and_distinct() {
        let account = IdentityHash::from_identifier("alice");
        // Primary keeps the legacy account mailbox.
        let primary = device_mailbox_hash(account.as_str(), PRIMARY_DEVICE_ID).unwrap();
        assert_eq!(primary, account);
        // Linked devices get distinct, well-formed, deterministic hashes.
        let d1 = device_mailbox_hash(account.as_str(), &"a".repeat(32)).unwrap();
        let d2 = device_mailbox_hash(account.as_str(), &"b".repeat(32)).unwrap();
        assert_ne!(d1, primary);
        assert_ne!(d1, d2);
        assert_eq!(
            d1,
            device_mailbox_hash(account.as_str(), &"a".repeat(32)).unwrap()
        );
        assert!(IdentityHash::from_hex(d1.as_str()).is_some());
        // Malformed account hash is refused.
        assert!(device_mailbox_hash("not-a-hash", &"a".repeat(32)).is_none());
    }

    #[test]
    fn envelope_zk_clean_only_without_raw_identifier() {
        let mut env = Envelope {
            to: IdentityHash::from_identifier("bob"),
            ciphertext: "Zm9v".into(),
            kind: PayloadKind::Message,
            msg_id: "abc123".into(),
            expires_at: None,
            wake: WakeClass::default(),
            raw_identifier: None,
        };
        assert!(env.is_zk_clean());
        env.raw_identifier = Some("bob-real-uuid".into());
        assert!(!env.is_zk_clean());
    }

    // Back-compat both directions: an OLD envelope without `wake` decodes as `Normal`
    // (today's behavior), and each class round-trips under its snake_case name.
    #[test]
    fn wake_class_wire_compat() {
        let legacy = r#"{"to":"TO","ciphertext":"Zm9v","kind":"message","msg_id":"m1",
                         "expires_at":null}"#
            .replace("TO", &"a".repeat(64));
        let env: Envelope = serde_json::from_str(&legacy).unwrap();
        assert_eq!(env.wake, WakeClass::Normal);

        for (class, name) in [
            (WakeClass::None, "\"none\""),
            (WakeClass::Normal, "\"normal\""),
            (WakeClass::Call, "\"call\""),
            (WakeClass::CallControl, "\"call_control\""),
        ] {
            let json = serde_json::to_string(&class).unwrap();
            assert_eq!(json, name);
            assert_eq!(serde_json::from_str::<WakeClass>(&json).unwrap(), class);
        }
    }

    /// Both wake transports carry the class as a STRING that Kotlin parses back into the
    /// JNI wake class, and neither side would fail loudly if the two drifted: a renamed
    /// tag downgrades every call wake to a debounced message wake — no ring, no
    /// cancellation, just a phone that rings late or not at all, which is precisely the
    /// bug this work exists to remove. The mapping is four lines in one `when` on each
    /// side, and this is the only place they can be compared at all.
    #[test]
    fn the_android_receivers_parse_exactly_these_wake_tags() {
        let kotlin = |name: &str| {
            std::fs::read_to_string(format!(
                "{}/../../clients/desktop/scripts/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap_or_else(|e| panic!("{name} receives these wakes: {e}"))
        };
        let up = kotlin("UnifiedPush.kt");
        let fcm = kotlin("SonaFirebaseService.kt");
        // The receivers' own wake-class numbering (push.rs `PushWakeClass::from_jni`).
        for (class, jni) in [
            (WakeClass::Call, "1"),
            (WakeClass::CallControl, "2"),
            (WakeClass::Normal, "0"),
        ] {
            // `Normal` is each `when`'s else arm — the safe default for an unknown tag.
            let fallback = format!("else -> {jni}");
            for (src, name, tag) in [
                (&up, "UnifiedPush.kt", class.wake_body()),
                (&fcm, "SonaFirebaseService.kt", class.fcm_tag()),
            ] {
                let arm = format!("\"{tag}\" -> {jni}");
                assert!(
                    src.contains(&arm) || (class == WakeClass::Normal && src.contains(&fallback)),
                    "{name} must map {arm}"
                );
            }
        }
        // A silent class never reaches a transport, so it must not need a tag of its own.
        assert_eq!(WakeClass::None.wake_body(), WakeClass::Normal.wake_body());
        assert_eq!(WakeClass::None.fcm_tag(), WakeClass::Normal.fcm_tag());
    }
}

/// QUIC media-path constants and cell framing, shared verbatim by the relay and the
/// clients (the relay bridges these framings between WebSocket and QUIC members, so
/// both sides must agree byte-for-byte). Design rationale lives in the server's
/// `quic` module and the client's media engine.
pub mod quicwire {
    /// ALPN for the media endpoint (not HTTP/3 — a bespoke mapping).
    pub const ALPN: &[u8] = b"sona-media-v1";
    /// Hard cap per media frame/cell — must match the relay's WebSocket cap.
    pub const MAX_FRAME_BYTES: usize = 1 + 8 + 16 * 1024 + 16;
    /// One reliable stream group = one encoded video frame's cells (engine bounds an
    /// encoded frame at 256 KiB; cell framing adds ~3%).
    pub const MAX_STREAM_GROUP_BYTES: usize = 300 * 1024;

    /// Frames whose loss is tolerable ride QUIC datagrams; everything else needs a
    /// reliable stream. Decided by the first wire byte: `0` = v1 voice frame, `3` =
    /// screen-audio cell — both periodic, self-contained, played-as-silence when
    /// missing. Video and control cells must not be dropped.
    pub fn lossy_ok(frame: &[u8]) -> bool {
        matches!(frame.first(), Some(0) | Some(3))
    }

    /// Length-prefix a group of cells for a unidirectional stream (`u16 BE || cell`).
    pub fn frame_cells(cells: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::with_capacity(cells.iter().map(|c| 2 + c.len()).sum());
        for cell in cells {
            debug_assert!(cell.len() <= u16::MAX as usize);
            out.extend_from_slice(&(cell.len() as u16).to_be_bytes());
            out.extend_from_slice(cell);
        }
        out
    }

    /// Split a received stream group back into cells. `None` = malformed (drop the
    /// group — neither relay nor client may amplify garbage framing).
    pub fn parse_cells(mut buf: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut cells = Vec::new();
        while !buf.is_empty() {
            if buf.len() < 2 {
                return None;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if len == 0 || len > MAX_FRAME_BYTES || buf.len() < 2 + len {
                return None;
            }
            cells.push(buf[2..2 + len].to_vec());
            buf = &buf[2 + len..];
        }
        (!cells.is_empty()).then_some(cells)
    }
}
