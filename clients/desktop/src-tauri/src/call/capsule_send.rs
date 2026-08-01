//! The **outbound** half of the capsule layer: warming the keys a capsule is sealed to,
//! minting and signing one per recipient device, and posting the batch off-lock.
//!
//! Split from [`super::capsule`], which owns the receiving half — draining the
//! call-control mailbox and converging what it finds with this device's call state. The
//! two halves share nothing but the payload type, and the send side is the one that must
//! stay network-free under the session lock: preparation is local (signing borrows the
//! account, sealing needs only the recipient's published key) and the relay work happens
//! with the lock released.

use crate::*;
use client_core::callcapsule::{CallCapsule, CapsuleKind, CapsulePlan};
use client_core::{CallKeyBinding, CapsuleDelivery};

/// How long a fetched binding is reused. Short enough that a device that rotated its
/// call-control identity is picked up before its old key goes stale, long enough that
/// back-to-back calls do not re-fetch. A capsule sealed to a rotated key is simply not
/// opened; the encrypted offer still rings that device.
pub(crate) const BINDING_TTL_SECS: u64 = 300;
/// Bound on cached accounts, so the cache cannot grow with every account ever called.
const MAX_CACHED_ACCOUNTS: usize = 32;

/// Refresh one account's verified call-key bindings without holding `Session` across a
/// network wait.
///
/// Best effort by design, exactly like [`warm_call_routes`](super::route::warm_call_routes):
/// an unreachable relay, a device that never published, or a binding that fails
/// verification simply means no capsule for that device — the encrypted offer still rings
/// it once its vault is open.
pub(crate) async fn warm_call_bindings(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    username: &str,
) {
    let device_ids = {
        let s = inner.lock().await;
        if !is_current(&s, client) || s.account.is_none() {
            return;
        }
        if s.call_bindings
            .get(username)
            .is_some_and(|cached| now_secs().saturating_sub(cached.fetched_at) < BINDING_TTL_SECS)
        {
            return;
        }
        let Some(pin) = s.history.pinned_roster(username) else {
            return; // no KT-verified roster ⇒ nothing to trust a call key against
        };
        pin.devices
            .iter()
            .map(|device| device.device_id.clone())
            .collect::<Vec<_>>()
    };
    let fetched = client.fetch_device_call_keys(username, &device_ids).await;
    let mut s = inner.lock().await;
    if !is_current(&s, client) {
        return;
    }
    // Verify against the *live* pin rather than the one read before the fetch: the same
    // anti-rollback rule the roster warm uses, so a roster that changed meanwhile decides.
    let Some(pin) = s.history.pinned_roster(username).cloned() else {
        return;
    };
    let devices: Vec<(String, CallKeyBinding)> = device_ids
        .into_iter()
        .zip(fetched)
        .filter_map(|(device_id, binding)| {
            let verified =
                client_core::verified_call_key_binding(&pin, username, &device_id, binding?)?;
            Some((device_id, verified))
        })
        .collect();
    if s.call_bindings.len() >= MAX_CACHED_ACCOUNTS && !s.call_bindings.contains_key(username) {
        // Bounded: drop the stalest entry rather than growing without limit.
        if let Some(stalest) = s
            .call_bindings
            .iter()
            .min_by_key(|(_, cached)| cached.fetched_at)
            .map(|(name, _)| name.clone())
        {
            s.call_bindings.remove(&stalest);
        }
    }
    s.call_bindings.insert(
        username.to_string(),
        CallBindings {
            fetched_at: now_secs(),
            devices,
        },
    );
}

/// Which of `username`'s devices we can currently seal a capsule to, skipping
/// `exclude_device_id` (ours, when the target account is our own).
fn capsule_targets(
    s: &Session,
    username: &str,
    exclude_device_id: Option<&str>,
) -> Vec<(String, CallKeyBinding)> {
    let Some(cached) = s.call_bindings.get(username) else {
        return Vec::new();
    };
    if now_secs().saturating_sub(cached.fetched_at) >= BINDING_TTL_SECS {
        return Vec::new();
    }
    cached
        .devices
        .iter()
        .filter(|(device_id, _)| Some(device_id.as_str()) != exclude_device_id)
        .cloned()
        .collect()
}

/// Everything a batch of capsules shares. Kept separate from [`CapsulePlan`] because one
/// batch mints one capsule per recipient device, each with its own `to_device_id`, random
/// `ring_handle`, and nonce.
pub(crate) struct CapsuleBatch<'a> {
    pub(crate) kind: CapsuleKind,
    pub(crate) call_instance_id: &'a str,
    pub(crate) offer_id: &'a str,
    pub(crate) video: bool,
    pub(crate) group: bool,
    pub(crate) created_at: u64,
    pub(crate) ring_expires_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) reason: Option<client_core::callstate::CallTerminalReason>,
}

/// Mint and sign one capsule per reachable device of `username`.
///
/// Local only — signing borrows the account, sealing needs just the recipient's published
/// key — so this fits inside the same short critical section that seals the encrypted
/// offers, and [`spawn_capsule_posts`] does the relay work off-lock.
pub(crate) fn prepare_capsules(
    s: &mut Session,
    client: &Arc<Client>,
    username: &str,
    batch: &CapsuleBatch<'_>,
) -> Vec<CapsuleDelivery> {
    let my_device_id = s.history.self_device_id();
    let Some(account) = s.account.as_ref() else {
        return Vec::new();
    };
    let me = account.account_id().to_string();
    let mine = me == username;
    let Ok(reply_to_mailbox) = client.device_mailbox(&me, &my_device_id) else {
        return Vec::new();
    };
    // Where a recipient whose vault is locked can answer us: our own call-control mailbox
    // and public call key, carried inside the signed payload so that device needs neither
    // our account name nor a relay fetch it could not verify (`internal/CALL_PLAN.md` §3.4).
    let reply_call_mailbox =
        client_core::call_mailbox_for(account.identity_hash().as_str(), &my_device_id)
            .unwrap_or_default();
    let reply_call_key = s
        .call_key
        .as_ref()
        .map(|key| key.public_b64())
        .unwrap_or_default();
    let account = s.account.as_ref().expect("checked above");
    let caller_identity_key = account.ratchet_ref().identity_key();
    let targets = capsule_targets(s, username, mine.then_some(my_device_id.as_str()));
    let account = s.account.as_ref().expect("checked above");
    targets
        .into_iter()
        .filter_map(|(device_id, binding)| {
            let capsule = CallCapsule::new(
                CapsulePlan {
                    kind: batch.kind,
                    call_instance_id: batch.call_instance_id.to_string(),
                    offer_id: batch.offer_id.to_string(),
                    from: me.clone(),
                    caller_identity_key: caller_identity_key.clone(),
                    caller_device_id: my_device_id.clone(),
                    to_device_id: device_id,
                    video: batch.video,
                    group: batch.group,
                    // The recipient's notification privacy level is theirs to apply; the
                    // caller can only say who it is, which `from` already carries.
                    display_name: me.clone(),
                    created_at: batch.created_at,
                    ring_expires_at: batch.ring_expires_at,
                    expires_at: batch.expires_at,
                    reply_to_mailbox: reply_to_mailbox.clone(),
                    reply_call_mailbox: reply_call_mailbox.clone(),
                    reply_call_key: reply_call_key.clone(),
                    signer: client_core::callcapsule::CapsuleSigner::Roster,
                    reason: batch.reason,
                },
                |payload| account.ratchet_ref().sign(payload),
            );
            capsule.well_formed().then(|| CapsuleDelivery {
                username: username.to_string(),
                binding,
                plaintext: capsule.encode(),
                ring: matches!(batch.kind, CapsuleKind::Offer),
                expires_at: batch.expires_at,
            })
        })
        .collect()
}

/// Send a final outcome on the capsule layer to every reachable device of `username`
/// (skipping this one when the account is ours).
///
/// This is the half of a terminal control that can stop a ring on a device whose vault is
/// locked, or whose process went back to sleep after posting a native ring — the encrypted
/// terminal reaches it only once it can decrypt again.
pub(crate) fn send_terminal_capsules(
    s: &mut Session,
    client: &Arc<Client>,
    username: &str,
    call_instance_id: &str,
    offer_id: &str,
    reason: client_core::callstate::CallTerminalReason,
    expires_at: u64,
) {
    let capsules = prepare_capsules(
        s,
        client,
        username,
        &CapsuleBatch {
            kind: CapsuleKind::Terminal,
            call_instance_id,
            offer_id,
            video: false,
            group: false,
            created_at: now_secs(),
            ring_expires_at: expires_at,
            expires_at,
            reason: Some(reason),
        },
    );
    spawn_capsule_posts(client, capsules);
}

/// Post a prepared batch concurrently, with the session lock released. Best effort: the
/// encrypted offer/control is the layer that must arrive, and a capsule that does not is
/// only the locked-device shortcut going missing.
pub(crate) fn spawn_capsule_posts(client: &Arc<Client>, capsules: Vec<CapsuleDelivery>) {
    if capsules.is_empty() {
        return;
    }
    let client = client.clone();
    eng().spawn(async move {
        client.post_call_capsules_concurrent(&capsules).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::callstate::{random_call_id, CallTerminalReason, CALL_SIGNAL_TTL_SECS};

    /// A group terminal must reach the capsule layer too, keyed by the **ring id**.
    ///
    /// The offer fan gained capsules in `c11aa4c` and the terminal fan did not, so a
    /// member's locked phone adopted the group ring and then never heard it end — the only
    /// terminal it could get was one it cannot decrypt (§3.6). This pins the mint side:
    /// one capsule per bound device, kind `Terminal`, keyed by the ring id rather than a
    /// per-member offer id.
    #[test]
    fn a_group_terminal_mints_one_capsule_per_bound_device_under_the_ring_id() {
        let client = Arc::new(Client::new("http://127.0.0.1:1", "ws://127.0.0.1:1", ""));
        let account = crypto_core::create_account_with_username("alice", "Alice-Password-123!")
            .unwrap()
            .0;
        let mut s = Session::default();
        s.account = Some(account);
        let peer_device = "d".repeat(32);
        s.call_bindings.insert(
            "bob".into(),
            CallBindings {
                fetched_at: now_secs(),
                devices: vec![(
                    peer_device.clone(),
                    CallKeyBinding {
                        device_id: peer_device.clone(),
                        call_key: crypto_core::CallKey::generate().public_b64(),
                        call_signing_key: "bob-call-signing-key".into(),
                        created_at: now_secs(),
                        signature: String::new(),
                    },
                )],
            },
        );
        let (call, ring_id) = (random_call_id(), random_call_id());
        let now = now_secs();
        let capsules = prepare_capsules(
            &mut s,
            &client,
            "bob",
            &CapsuleBatch {
                kind: CapsuleKind::Terminal,
                call_instance_id: &call,
                offer_id: &ring_id,
                video: false,
                group: true,
                created_at: now,
                ring_expires_at: now + CALL_SIGNAL_TTL_SECS,
                expires_at: now + CALL_SIGNAL_TTL_SECS,
                reason: Some(CallTerminalReason::CallerCancelled),
            },
        );
        assert_eq!(capsules.len(), 1);
        let minted = CallCapsule::decode(&capsules[0].plaintext).unwrap();
        assert_eq!(minted.kind, CapsuleKind::Terminal);
        assert!(minted.group);
        assert_eq!(minted.offer_id, ring_id, "keyed by the ring, not a leg");
        assert_eq!(minted.to_device_id, peer_device);
        assert_eq!(
            minted.reason,
            Some(CallTerminalReason::CallerCancelled),
            "the reason the UI has to show honestly"
        );
        assert!(
            !capsules[0].ring,
            "a terminal takes the urgent silent wake, never the ring one"
        );
    }

    /// A-22's silent failure mode, pinned end to end: **the mint and the check must agree.**
    ///
    /// `prepare_capsules` builds `reply_call_mailbox` from `account.identity_hash()`;
    /// `PendingRing::from_capsule` rebuilds it from `IdentityHash::from_identifier(from)` and
    /// drops the route when the two differ. If they ever disagreed by a character, every
    /// locked decline would silently become local-only and nothing would log it — the ring
    /// would still stop here, the caller would still time out, and no test would notice.
    ///
    /// So this goes through the real mint and the real ingest, for an account whose username
    /// is what `from` carries.
    #[test]
    fn the_reply_route_a_capsule_mints_is_the_one_the_receiver_derives() {
        use client_core::callstore::PendingRing;

        let client = Arc::new(Client::new("http://127.0.0.1:1", "ws://127.0.0.1:1", ""));
        let account = crypto_core::create_account_with_username("alice", "Alice-Password-123!")
            .unwrap()
            .0;
        let mut s = Session::default();
        s.account = Some(account);
        s.call_key = Some(Arc::new(crypto_core::CallKey::generate()));
        let peer_device = "d".repeat(32);
        s.call_bindings.insert(
            "bob".into(),
            CallBindings {
                fetched_at: now_secs(),
                devices: vec![(
                    peer_device.clone(),
                    CallKeyBinding {
                        device_id: peer_device.clone(),
                        call_key: crypto_core::CallKey::generate().public_b64(),
                        call_signing_key: "bob-call-signing-key".into(),
                        created_at: now_secs(),
                        signature: String::new(),
                    },
                )],
            },
        );
        let (call, offer) = (random_call_id(), random_call_id());
        let now = now_secs();
        let capsules = prepare_capsules(
            &mut s,
            &client,
            "bob",
            &CapsuleBatch {
                kind: CapsuleKind::Offer,
                call_instance_id: &call,
                offer_id: &offer,
                video: false,
                group: false,
                created_at: now,
                ring_expires_at: now + client_core::callstate::CALL_RING_TIMEOUT_SECS,
                expires_at: now + CALL_SIGNAL_TTL_SECS,
                reason: None,
            },
        );
        assert_eq!(capsules.len(), 1);
        let minted = CallCapsule::decode(&capsules[0].plaintext).unwrap();
        assert!(
            !minted.reply_call_mailbox.is_empty(),
            "this device published a call key, so it must offer a reply route"
        );

        let ring = PendingRing::from_capsule(&minted);
        assert_eq!(
            ring.reply_call_mailbox, minted.reply_call_mailbox,
            "the receiver's derivation must reproduce the sender's mint, or every locked \
             decline silently degrades to local-only"
        );
        assert_eq!(
            ring.reply_call_key, minted.reply_call_key,
            "the key is not derivable and must still be carried"
        );
    }
}
