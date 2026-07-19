//! The Double Ratchet engine — Sona's end-to-end encryption.
//!
//! Wraps vodozemac's audited Olm implementation. Olm gives us exactly the guarantees
//! the design calls for:
//!
//! * **Forward secrecy** — each message uses a fresh chain key; compromising today's
//!   keys does not expose yesterday's messages.
//! * **Post-compromise security** — the ratchet heals; after an attacker who stole
//!   keys goes away, future messages become secure again as new DH ratchet steps run.
//!
//! Handshake (Olm's triple Diffie-Hellman): the recipient publishes a [`PreKeyBundle`]
//! (long-term identity key + a one-time key). The sender mixes those with a fresh
//! ephemeral key to derive the initial shared secret, then both sides ratchet forward.
//!
//! Sessions are keyed by the peer's **Curve25519 identity key** (base64) — the stable
//! cryptographic identity of the peer, not any server-assigned name. A peer may hold
//! **several live sessions** (up to [`MAX_SESSIONS_PER_PEER`], most-recently-used
//! first): two sides can establish sessions to each other simultaneously (e.g. a linked
//! device's hello is still queued when the peer opens its own session), and a
//! one-slot-per-peer model can never converge from that — each pre-key would *replace*
//! the slot the other side is actively sending on, silently destroying messages. Keeping
//! both sessions makes the race harmless: decryption tries every session, encryption
//! uses the most recently working one.
//!
//! **Replay containment:** a pre-key message whose `session_id` matches a session we
//! already hold is never allowed to re-create that session — it must decrypt with the
//! existing state or be rejected. Without this, a replayed pre-key message built against
//! the *fallback* key (which, unlike one-time keys, is reusable and long-lived) could
//! resurrect an old session over a live one — and since undecryptable envelopes are
//! acked out of the mailbox, that would be permanent message loss an untrusted relay
//! could inflict at will.

use std::collections::HashMap;

use protocol_types::{CiphertextMessage, PreKeyBundle};
use serde::{Deserialize, Serialize};
use vodozemac::olm::{
    Account, AccountPickle, InboundCreationResult, OlmMessage, Session, SessionConfig,
    SessionPickle,
};
use vodozemac::Curve25519PublicKey;

/// Live sessions kept per peer identity key. Distinct sessions only accumulate through
/// distinct handshakes (simultaneous establishment, a peer's reinstall, a fallback-key
/// handshake while one-time keys were drained), so this stays tiny in practice; the
/// bound caps vault growth. Eviction drops the *least recently used* session.
pub const MAX_SESSIONS_PER_PEER: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("no session with this contact and message is not a session-initiating pre-key")]
    NoSession,
    #[error("malformed key or message: {0}")]
    Malformed(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("session establishment failed: {0}")]
    Establish(String),
    #[error("state (de)serialization failed: {0}")]
    State(String),
}

/// One peer's session pickles on disk. Older vaults stored exactly one session per peer
/// (a bare pickle object); current vaults store a most-recently-used-first list. The
/// untagged enum reads both, so no vault ever needs a migration step.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum SessionSlot {
    Many(Vec<SessionPickle>),
    One(Box<SessionPickle>),
}

/// Serialized form of a [`RatchetEngine`], stored (encrypted) in the vault.
#[derive(Serialize, Deserialize)]
struct RatchetState {
    account: AccountPickle,
    /// peer identity key (base64) -> session pickle(s), most recently used first
    sessions: HashMap<String, SessionSlot>,
}

/// One user's ratchet: their long-term Olm account plus live sessions per contact
/// (most recently used first — encryption always uses the front session).
pub struct RatchetEngine {
    account: Account,
    sessions: HashMap<String, Vec<Session>>,
}

impl RatchetEngine {
    /// Create a brand-new identity (fresh Olm account, no sessions yet).
    pub fn new() -> Self {
        Self {
            account: Account::new(),
            sessions: HashMap::new(),
        }
    }

    /// This identity's long-term Curve25519 public key (base64). This is the value
    /// peers use to address sessions and the value a Key Transparency log will pin.
    pub fn identity_key(&self) -> String {
        self.account.curve25519_key().to_base64()
    }

    /// This identity's Ed25519 public key (base64) — used later to sign Key
    /// Transparency entries so peers can verify the binding is really ours.
    pub fn signing_key(&self) -> String {
        self.account.ed25519_key().to_base64()
    }

    /// Sign a message with this identity's Ed25519 key, returning the base64 signature.
    /// Used to prove identity ownership during registration and the login challenge —
    /// no password or long-term secret ever leaves the device.
    pub fn sign(&self, message: &[u8]) -> String {
        self.account.sign(message).to_base64()
    }

    /// Generate `count` one-time keys and mark them published. Returns the public
    /// halves (base64) for upload to the server's bundle store. The private halves
    /// stay in the account so we can answer an inbound pre-key message later.
    pub fn generate_one_time_keys(&mut self, count: usize) -> Vec<String> {
        let result = self.account.generate_one_time_keys(count);
        self.account.mark_keys_as_published();
        result.created.iter().map(|k| k.to_base64()).collect()
    }

    /// Generate (rotating) this identity's **fallback key** and return its public part
    /// (base64). A fallback key is a *reusable* last-resort pre-key: the server serves it
    /// when a user's one-time keys are exhausted, so a new contact can always start a
    /// session. Unlike one-time keys it is not consumed on use (the account keeps the
    /// secret), which closes the "drain a victim's one-time keys" denial-of-service.
    pub fn generate_fallback_key(&mut self) -> String {
        self.account.generate_fallback_key();
        self.account
            .fallback_key()
            .values()
            .next()
            .map(|k| k.to_base64())
            .unwrap_or_default()
    }

    /// Build a pre-key bundle for *this* user that a peer can use to start a session.
    /// Generates a fresh one-time key as a side effect (one-time keys are consumed per
    /// new inbound session, so each published bundle should carry an unused one).
    pub fn create_bundle(&mut self) -> PreKeyBundle {
        let one_time_key = self
            .generate_one_time_keys(1)
            .into_iter()
            .next()
            .expect("generating one one-time key always yields one");
        PreKeyBundle {
            identity_key: self.identity_key(),
            signing_key: self.signing_key(),
            one_time_key,
        }
    }

    /// Establish an outbound session to a peer from their published bundle. After this,
    /// the first [`encrypt`](Self::encrypt) to that peer produces a pre-key message.
    pub fn establish_outbound(&mut self, bundle: &PreKeyBundle) -> Result<(), RatchetError> {
        // Re-fetching a peer's bundle when we already have a live session must NOT add
        // another one: a fresh outbound session diverges the ratchet from the one the peer
        // is using — keep what we have. A genuine key change arrives under a *different*
        // identity_key, so it lands here as a new peer entry, not a clobber.
        if self.has_session(&bundle.identity_key) {
            return Ok(());
        }
        let identity_key = Curve25519PublicKey::from_base64(&bundle.identity_key)
            .map_err(|e| RatchetError::Malformed(format!("identity_key: {e}")))?;
        let one_time_key = Curve25519PublicKey::from_base64(&bundle.one_time_key)
            .map_err(|e| RatchetError::Malformed(format!("one_time_key: {e}")))?;
        // Olm session config. NOTE (L-1): vodozemac 0.10.0 gates `version_2()` behind the
        // `experimental-session-config` feature — v2 is experimental on this pinned version,
        // not the stable default. We deliberately stay on v1 rather than enable an
        // experimental feature on the core ratchet; revisit when vodozemac stabilizes v2.
        let session = self
            .account
            .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
            .map_err(|e| RatchetError::Establish(e.to_string()))?;
        self.push_session(&bundle.identity_key, session);
        Ok(())
    }

    /// Insert a session as the peer's most-recently-used one, evicting the least
    /// recently used session past the cap.
    fn push_session(&mut self, peer_identity_key: &str, session: Session) {
        let list = self
            .sessions
            .entry(peer_identity_key.to_string())
            .or_default();
        list.insert(0, session);
        list.truncate(MAX_SESSIONS_PER_PEER);
    }

    /// Move the session at `idx` to the front of the peer's list (it just proved live).
    fn promote_session(&mut self, peer_identity_key: &str, idx: usize) {
        if idx == 0 {
            return;
        }
        if let Some(list) = self.sessions.get_mut(peer_identity_key) {
            if idx < list.len() {
                let s = list.remove(idx);
                list.insert(0, s);
            }
        }
    }

    /// Encrypt a message for a peer we already have a session with — always the most
    /// recently used one. The first message after
    /// [`establish_outbound`](Self::establish_outbound) is a pre-key message
    /// (`message_type == 0`); subsequent ones are normal (`== 1`).
    pub fn encrypt(
        &mut self,
        peer_identity_key: &str,
        plaintext: &str,
    ) -> Result<CiphertextMessage, RatchetError> {
        let session = self
            .sessions
            .get_mut(peer_identity_key)
            .and_then(|l| l.first_mut())
            .ok_or(RatchetError::NoSession)?;
        let olm = session
            .encrypt(plaintext)
            .map_err(|e| RatchetError::Encrypt(e.to_string()))?;
        let (message_type, body) = olm.to_parts();
        Ok(CiphertextMessage {
            message_type: message_type as u8,
            body: vodozemac::base64_encode(body),
        })
    }

    /// Decrypt a message from a known peer, creating a session if this is a
    /// session-initiating pre-key message. Same rules as
    /// [`decrypt_unattributed`](Self::decrypt_unattributed), with the sender fixed.
    pub fn decrypt(
        &mut self,
        peer_identity_key: &str,
        msg: &CiphertextMessage,
    ) -> Result<String, RatchetError> {
        let body = vodozemac::base64_decode(&msg.body)
            .map_err(|e| RatchetError::Malformed(format!("body: {e}")))?;
        let olm = OlmMessage::from_parts(msg.message_type as usize, &body)
            .map_err(|e| RatchetError::Malformed(e.to_string()))?;
        match &olm {
            OlmMessage::PreKey(_) => {
                let (sender, plaintext) = self.decrypt_olm(&olm)?;
                if sender != peer_identity_key {
                    return Err(RatchetError::Decrypt(
                        "pre-key message is from a different identity".into(),
                    ));
                }
                Ok(plaintext)
            }
            OlmMessage::Normal(_) => {
                let list = self
                    .sessions
                    .get_mut(peer_identity_key)
                    .ok_or(RatchetError::NoSession)?;
                let mut hit = None;
                for (idx, session) in list.iter_mut().enumerate() {
                    if let Ok(bytes) = session.decrypt(&olm) {
                        hit = Some((idx, bytes));
                        break;
                    }
                }
                let (idx, bytes) = hit.ok_or(RatchetError::NoSession)?;
                self.promote_session(peer_identity_key, idx);
                String::from_utf8(bytes)
                    .map_err(|e| RatchetError::Decrypt(format!("invalid utf8: {e}")))
            }
        }
    }

    /// Decrypt an inbound message **without being told who sent it** — the property
    /// that lets the server stay blind to the sender (sealed sender).
    ///
    /// * A pre-key message (type 0) carries the sender's identity key inside the Olm
    ///   message itself, so we learn the sender cryptographically. If its `session_id`
    ///   names a session we already hold, it must decrypt with that state (a failure is
    ///   a replay/corruption and changes nothing); a *new* session id bootstraps an
    ///   additional session — never replacing the ones the peer may still be using.
    /// * A normal message (type 1) is tried against every known session; the one that
    ///   decrypts identifies the sender. (Fine at friends-scale; a wrong-session attempt
    ///   fails cleanly without yielding plaintext.)
    ///
    /// Returns `(sender_identity_key_b64, plaintext)`.
    pub fn decrypt_unattributed(
        &mut self,
        msg: &CiphertextMessage,
    ) -> Result<(String, String), RatchetError> {
        let body = vodozemac::base64_decode(&msg.body)
            .map_err(|e| RatchetError::Malformed(format!("body: {e}")))?;
        let olm = OlmMessage::from_parts(msg.message_type as usize, &body)
            .map_err(|e| RatchetError::Malformed(e.to_string()))?;
        self.decrypt_olm(&olm)
    }

    fn decrypt_olm(&mut self, olm: &OlmMessage) -> Result<(String, String), RatchetError> {
        match olm {
            OlmMessage::PreKey(pre_key) => {
                let sender = pre_key.identity_key().to_base64();
                let wanted = pre_key.session_id();
                let known = self.sessions.get_mut(&sender).and_then(|list| {
                    list.iter_mut()
                        .enumerate()
                        .find(|(_, s)| s.session_id() == wanted)
                        .map(|(idx, s)| (idx, s.decrypt(olm)))
                });
                let plaintext = match known {
                    // The initiating message (or a benign duplicate) of a session we
                    // already hold: it must open with that state.
                    Some((idx, Ok(plaintext))) => {
                        self.promote_session(&sender, idx);
                        plaintext
                    }
                    // A pre-key message for a session we hold that its own session can't
                    // open is a replay or corruption. Recreating the session here would
                    // let anyone who can replay traffic (the relay) rewind our live
                    // ratchet state — refuse, changing nothing.
                    Some((_, Err(e))) => return Err(RatchetError::Decrypt(e.to_string())),
                    // A handshake we haven't seen: bootstrap an ADDITIONAL session. This
                    // is safe — the Olm handshake bakes the sender's identity key into
                    // the shared secret (no impersonation) and needs the private half of
                    // the pre-key we published. Existing sessions are kept: the peer may
                    // still be sending on one of them (simultaneous establishment).
                    None => {
                        let InboundCreationResult { session, plaintext } = self
                            .account
                            .create_inbound_session(
                                SessionConfig::version_1(),
                                pre_key.identity_key(),
                                pre_key,
                            )
                            .map_err(|e| RatchetError::Establish(e.to_string()))?;
                        self.push_session(&sender, session);
                        plaintext
                    }
                };
                let text = String::from_utf8(plaintext)
                    .map_err(|e| RatchetError::Decrypt(format!("invalid utf8: {e}")))?;
                Ok((sender, text))
            }
            OlmMessage::Normal(_) => {
                let mut hit = None;
                'outer: for (sender, list) in self.sessions.iter_mut() {
                    for (idx, session) in list.iter_mut().enumerate() {
                        if let Ok(bytes) = session.decrypt(olm) {
                            hit = Some((sender.clone(), idx, bytes));
                            break 'outer;
                        }
                    }
                }
                let (sender, idx, bytes) = hit.ok_or(RatchetError::NoSession)?;
                self.promote_session(&sender, idx);
                let text = String::from_utf8(bytes)
                    .map_err(|e| RatchetError::Decrypt(format!("invalid utf8: {e}")))?;
                Ok((sender, text))
            }
        }
    }

    pub fn has_session(&self, peer_identity_key: &str) -> bool {
        self.sessions
            .get(peer_identity_key)
            .is_some_and(|l| !l.is_empty())
    }

    /// Serialize the full ratchet state (account + all sessions) for vault storage.
    pub fn export_state(&self) -> Result<Vec<u8>, RatchetError> {
        let state = RatchetState {
            account: self.account.pickle(),
            sessions: self
                .sessions
                .iter()
                .map(|(id, list)| {
                    (
                        id.clone(),
                        SessionSlot::Many(list.iter().map(|s| s.pickle()).collect()),
                    )
                })
                .collect(),
        };
        serde_json::to_vec(&state).map_err(|e| RatchetError::State(e.to_string()))
    }

    /// Restore a ratchet engine from previously exported state (either the current
    /// multi-session layout or a pre-multi-session vault with one pickle per peer).
    pub fn import_state(bytes: &[u8]) -> Result<Self, RatchetError> {
        let state: RatchetState =
            serde_json::from_slice(bytes).map_err(|e| RatchetError::State(e.to_string()))?;
        let account = Account::from_pickle(state.account);
        let sessions = state
            .sessions
            .into_iter()
            .map(|(id, slot)| {
                let list = match slot {
                    SessionSlot::Many(pickles) => {
                        pickles.into_iter().map(Session::from_pickle).collect()
                    }
                    SessionSlot::One(pickle) => vec![Session::from_pickle(*pickle)],
                };
                (id, list)
            })
            .collect();
        Ok(Self { account, sessions })
    }
}

impl Default for RatchetEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_and_message_exchange() {
        // Bob publishes a bundle; Alice uses it to open a session and send.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let bob_id = bob.identity_key();
        let alice_id = alice.identity_key();

        let bundle = bob.create_bundle();
        alice.establish_outbound(&bundle).unwrap();

        // First message: pre-key (type 0). Bob creates the inbound session on receipt.
        let c1 = alice.encrypt(&bob_id, "hello bob").unwrap();
        assert_eq!(c1.message_type, 0);
        assert_eq!(bob.decrypt(&alice_id, &c1).unwrap(), "hello bob");

        // Bob now has a session and can reply.
        let r1 = bob.encrypt(&alice_id, "hi alice").unwrap();
        assert_eq!(alice.decrypt(&bob_id, &r1).unwrap(), "hi alice");

        // Subsequent Alice→Bob messages are normal ratchet messages (type 1).
        let c2 = alice.encrypt(&bob_id, "second").unwrap();
        assert_eq!(c2.message_type, 1);
        assert_eq!(bob.decrypt(&alice_id, &c2).unwrap(), "second");
    }

    #[test]
    fn reestablishing_before_each_send_keeps_the_session_alive() {
        // Regression: the client re-resolves a contact (KT-verify) and calls
        // `establish_outbound` before *every* send. If that re-established (clobbered) an
        // existing session, replies could no longer be decrypted. Mirror the app's flow —
        // establish-before-send on both sides, sealed-sender decrypt — and require every
        // hop to decrypt, including the reply and messages after it.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let alice_id = alice.identity_key();
        let bob_id = bob.identity_key();

        // Alice → Bob (first contact).
        alice.establish_outbound(&bob.create_bundle()).unwrap();
        let m1 = alice.encrypt(&bob_id, "hello bob").unwrap();
        assert_eq!(
            bob.decrypt_unattributed(&m1).unwrap(),
            (alice_id.clone(), "hello bob".into())
        );

        // Bob → Alice reply. The app re-establishes first; that must not clobber the
        // session Bob just built from Alice's pre-key.
        bob.establish_outbound(&alice.create_bundle()).unwrap();
        let r1 = bob.encrypt(&alice_id, "hey alice").unwrap();
        assert_eq!(
            alice.decrypt_unattributed(&r1).unwrap(),
            (bob_id.clone(), "hey alice".into())
        );

        // Alice → Bob again (re-establish again before sending).
        alice.establish_outbound(&bob.create_bundle()).unwrap();
        let m2 = alice.encrypt(&bob_id, "still here").unwrap();
        assert_eq!(
            bob.decrypt_unattributed(&m2).unwrap(),
            (alice_id, "still here".into())
        );
    }

    #[test]
    fn simultaneous_establishment_converges_without_message_loss() {
        // Both sides establish outbound sessions to each other before either processes
        // the other's pre-key message — the multi-device linking race (the hello is
        // queued while the primary opens its own session). With one session slot per
        // peer this ping-pongs forever, silently destroying messages; with the
        // multi-session store every direction keeps decrypting.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let alice_id = alice.identity_key();
        let bob_id = bob.identity_key();

        alice.establish_outbound(&bob.create_bundle()).unwrap();
        bob.establish_outbound(&alice.create_bundle()).unwrap();

        // Both send their initial pre-key messages "in flight" simultaneously.
        let a1 = alice.encrypt(&bob_id, "from alice").unwrap();
        let b1 = bob.encrypt(&alice_id, "from bob").unwrap();

        // Cross-delivery: each side bootstraps the other's session IN ADDITION to its own.
        assert_eq!(
            bob.decrypt_unattributed(&a1).unwrap(),
            (alice_id.clone(), "from alice".into())
        );
        assert_eq!(
            alice.decrypt_unattributed(&b1).unwrap(),
            (bob_id.clone(), "from bob".into())
        );

        // Every later message decrypts, both directions, repeatedly — no bricked state.
        for i in 0..3 {
            let a = alice.encrypt(&bob_id, &format!("a{i}")).unwrap();
            assert_eq!(
                bob.decrypt_unattributed(&a).unwrap(),
                (alice_id.clone(), format!("a{i}"))
            );
            let b = bob.encrypt(&alice_id, &format!("b{i}")).unwrap();
            assert_eq!(
                alice.decrypt_unattributed(&b).unwrap(),
                (bob_id.clone(), format!("b{i}"))
            );
        }
    }

    #[test]
    fn replayed_fallback_prekey_message_cannot_rewind_a_live_session() {
        // Bob's one-time keys are "drained": Alice starts the session from Bob's
        // REUSABLE fallback key. The relay later replays Alice's initial pre-key
        // message. Since the fallback secret is still held, a naive receiver would
        // re-create the (old) session and clobber the advanced one — after which every
        // real message from Alice fails to decrypt and is acked away: permanent loss.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let alice_id = alice.identity_key();
        let bob_id = bob.identity_key();

        let fallback_bundle = PreKeyBundle {
            identity_key: bob.identity_key(),
            signing_key: bob.signing_key(),
            one_time_key: bob.generate_fallback_key(),
        };
        alice.establish_outbound(&fallback_bundle).unwrap();

        let initial = alice.encrypt(&bob_id, "first").unwrap();
        assert_eq!(initial.message_type, 0, "must be a pre-key message");
        assert_eq!(
            bob.decrypt_unattributed(&initial).unwrap(),
            (alice_id.clone(), "first".into())
        );

        // The conversation advances well past the handshake.
        let m2 = alice.encrypt(&bob_id, "second").unwrap();
        bob.decrypt_unattributed(&m2).unwrap();
        let r = bob.encrypt(&alice_id, "reply").unwrap();
        alice.decrypt_unattributed(&r).unwrap();

        // Relay replays the captured initial pre-key message: must be REFUSED (its
        // session is known but already ratcheted past it), not re-bootstrapped.
        assert!(bob.decrypt_unattributed(&initial).is_err());

        // And the live session is untouched — the next real message still decrypts.
        let m3 = alice.encrypt(&bob_id, "third").unwrap();
        assert_eq!(
            bob.decrypt_unattributed(&m3).unwrap(),
            (alice_id, "third".into())
        );
    }

    #[test]
    fn session_count_per_peer_is_capped() {
        // Each fallback-key handshake from the same identity creates a distinct session;
        // the store must not grow unboundedly (vault size / trial-decrypt cost).
        let mut bob = RatchetEngine::new();
        let bob_id = bob.identity_key();
        let fallback = bob.generate_fallback_key();
        for i in 0..(MAX_SESSIONS_PER_PEER + 3) {
            // A fresh sender engine each time simulates repeated re-installs — same
            // trick an abuser would script. (Same identity would require the same
            // account; distinct identities each get their own capped list.)
            let bundle = PreKeyBundle {
                identity_key: bob.identity_key(),
                signing_key: bob.signing_key(),
                one_time_key: fallback.clone(),
            };
            let mut alice = RatchetEngine::new();
            alice.establish_outbound(&bundle).unwrap();
            let m = alice.encrypt(&bob_id, &format!("hello {i}")).unwrap();
            bob.decrypt_unattributed(&m).unwrap();
        }
        let total: usize = bob.sessions.values().map(|l| l.len()).sum();
        assert!(bob
            .sessions
            .values()
            .all(|l| l.len() <= MAX_SESSIONS_PER_PEER));
        assert!(total <= (MAX_SESSIONS_PER_PEER + 3)); // one list per distinct identity
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let bundle = bob.create_bundle();
        alice.establish_outbound(&bundle).unwrap();
        let c = alice
            .encrypt(&bob.identity_key(), "secret message")
            .unwrap();
        assert!(!c.body.contains("secret"));
        // The decoded ciphertext bytes must not contain the plaintext either.
        let raw = vodozemac::base64_decode(&c.body).unwrap();
        assert!(raw.windows(6).all(|w| w != b"secret"));
    }

    #[test]
    fn state_survives_export_import_round_trip() {
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let bob_id = bob.identity_key();
        let alice_id = alice.identity_key();

        let bundle = bob.create_bundle();
        alice.establish_outbound(&bundle).unwrap();
        let c1 = alice.encrypt(&bob_id, "before reload").unwrap();
        bob.decrypt(&alice_id, &c1).unwrap();

        // Persist both sides, drop them, restore from bytes.
        let alice_state = alice.export_state().unwrap();
        let bob_state = bob.export_state().unwrap();
        drop(alice);
        drop(bob);
        let mut alice = RatchetEngine::import_state(&alice_state).unwrap();
        let mut bob = RatchetEngine::import_state(&bob_state).unwrap();

        // The restored sessions keep ratcheting — a new message still decrypts.
        let c2 = alice.encrypt(&bob_id, "after reload").unwrap();
        assert_eq!(bob.decrypt(&alice_id, &c2).unwrap(), "after reload");
        let r = bob.encrypt(&alice_id, "reply after reload").unwrap();
        assert_eq!(alice.decrypt(&bob_id, &r).unwrap(), "reply after reload");
    }

    #[test]
    fn legacy_single_session_vault_state_still_imports() {
        // Vaults written before the multi-session store held ONE pickle per peer.
        // Simulate that exact on-disk layout and require a lossless import.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let bob_id = bob.identity_key();
        let alice_id = alice.identity_key();
        alice.establish_outbound(&bob.create_bundle()).unwrap();
        let c1 = alice.encrypt(&bob_id, "hi").unwrap();
        bob.decrypt(&alice_id, &c1).unwrap();

        // Rewrite Bob's exported state into the legacy shape: bare pickle, not a list.
        let modern: serde_json::Value =
            serde_json::from_slice(&bob.export_state().unwrap()).unwrap();
        let mut legacy = modern.clone();
        let sessions = legacy["sessions"].as_object_mut().unwrap();
        for (_, v) in sessions.iter_mut() {
            let first = v.as_array().unwrap()[0].clone();
            *v = first; // exactly what old vaults stored
        }
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();

        let mut bob2 = RatchetEngine::import_state(&legacy_bytes).unwrap();
        let c2 = alice.encrypt(&bob_id, "post-migration").unwrap();
        assert_eq!(
            bob2.decrypt_unattributed(&c2).unwrap(),
            (alice_id, "post-migration".into())
        );
    }

    #[test]
    fn unattributed_decrypt_learns_sender() {
        // Bob is not told who the message is from — he must learn it from the message.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let alice_id = alice.identity_key();
        let bundle = bob.create_bundle();
        alice.establish_outbound(&bundle).unwrap();

        // First (pre-key) message: Bob recovers Alice's identity from the message itself.
        let c1 = alice.encrypt(&bob.identity_key(), "who am i").unwrap();
        let (sender, text) = bob.decrypt_unattributed(&c1).unwrap();
        assert_eq!(sender, alice_id);
        assert_eq!(text, "who am i");

        // Follow-up (normal) message: Bob attributes it by trial over known sessions.
        let c2 = alice.encrypt(&bob.identity_key(), "still me").unwrap();
        let (sender2, text2) = bob.decrypt_unattributed(&c2).unwrap();
        assert_eq!(sender2, alice_id);
        assert_eq!(text2, "still me");
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        // Eve has a different account; Alice's message to Bob must not open for Eve.
        let mut alice = RatchetEngine::new();
        let mut bob = RatchetEngine::new();
        let mut eve = RatchetEngine::new();
        let bundle = bob.create_bundle();
        alice.establish_outbound(&bundle).unwrap();
        let c = alice.encrypt(&bob.identity_key(), "for bob only").unwrap();
        // Eve tries to treat it as an inbound pre-key from Alice — wrong OTK, must fail.
        assert!(eve.decrypt(&alice.identity_key(), &c).is_err());
    }
}
