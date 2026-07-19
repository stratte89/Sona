use super::*;

/// A reference to an end-to-end-encrypted attachment. Travels inside the ratchet (so the
/// server never sees the key); the ciphertext blob itself is uploaded to the relay opaque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// Server-side id of the opaque ciphertext blob.
    pub blob_id: String,
    /// Base64 symmetric key that decrypts the blob (only the recipient learns it).
    pub key: String,
    pub filename: String,
    pub size: usize,
    /// Base64 SHA-256 of the *ciphertext*, so the recipient can verify the downloaded
    /// blob is the exact one referenced before decrypting.
    pub content_hash: String,
    pub ts: u64,
    /// This attachment is a recorded voice message (renders as a player, not a file).
    /// Travels inside the ratchet like the rest of the reference; the server sees only
    /// an opaque padded blob either way.
    #[serde(default)]
    pub voice: bool,
    /// Voice messages: recorded length in seconds (sender-declared, display only).
    #[serde(default)]
    pub duration_secs: u32,
    /// Optional caption text sent alongside the attachment (rendered under the image/file
    /// chip in the same bubble). Backward compatible: old clients omit it and old messages
    /// decode with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// Voice messages: ~60 amplitude peaks (0–255) captured during recording, for a bar
    /// waveform. Backward compatible: absent ⇒ the player falls back to a flat progress bar.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peaks: Vec<u8>,
}

/// A quoted-reply reference carried inside a text payload: the replied-to message's id
/// plus a short plaintext snippet (so the recipient can render the quote even if the
/// original is gone). Both travel inside the ratchet ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRef {
    pub msg_id: String,
    pub preview: String,
}

/// A member of a group: their username and identity key (so any member can KT-verify and
/// establish a session with any other).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub username: String,
    pub identity_key: String,
}

/// A group the local user belongs to. Groups are pairwise: a message is fanned out to each
/// member over the existing 1:1 sessions, so no new group-key management is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub members: Vec<GroupMember>,
}

/// What [`Client::send_file`] returns.
#[derive(Debug, Clone)]
pub struct SentAttachment {
    pub msg_id: String,
    pub sent_at: u64,
    pub blob_id: String,
}

/// What [`Client::send`] returns so the caller can record the sent message locally with
/// the same id and timestamp the recipient will see.
#[derive(Debug, Clone)]
pub struct SentMessage {
    pub msg_id: String,
    pub sent_at: u64,
}

/// A message encrypted and ready to relay ([`Client::prepare_message`]). Splitting
/// "encrypt" (needs the account, fast) from "post" (network, slow) lets a caller hold its
/// account lock only for the encryption and do the network round-trip unlocked.
#[derive(Debug, Clone)]
pub struct PreparedMessage {
    pub envelope: Envelope,
    pub msg_id: String,
    pub sent_at: u64,
}

#[derive(Deserialize)]
pub(crate) struct KtProofResponse {
    pub(crate) entry: KtEntry,
    pub(crate) index: u64,
    pub(crate) proof_b64: String,
    pub(crate) sth: SignedTreeHead,
}

/// Header carrying a private relay's shared access token (`ACCESS_MODE=token/stealth`
/// server-side). Must ride on EVERY request, including WebSocket upgrades.
pub const ACCESS_HEADER: &str = "x-sona-access";
