//! Authentication & anti-abuse primitives for the relay.
//!
//! The server holds **no secrets and no passwords**. A client proves control of an
//! identity by signing, with its Ed25519 key, either:
//!
//! * a registration request (self-signature — proves it owns the keys it is registering), or
//! * a fresh server-issued nonce (challenge-response — proves it owns the identity it
//!   claims when connecting).
//!
//! Because nonces are single-use and short-lived, a captured signature cannot be
//! replayed — so the auth scheme does not even rely on TLS to stay unforgeable (TLS is
//! still required for metadata confidentiality; see the server docs).
//!
//! Replay is only half of it. The **relay chooses the challenge bytes**, and the key
//! signing them is the account's long-term identity key, so the challenge is also a
//! potential blind signing oracle: serve another context's signing payload as the
//! "nonce" and the client hands back a genuine signature over it (SP-01). That is why
//! the client never signs the nonce directly — it signs
//! [`protocol_types::ws_auth_signing_message`], which is domain-separated from every
//! other signing context and bound to the mailbox being authenticated. `issue` mints
//! exactly [`protocol_types::WS_AUTH_NONCE_LEN`] random bytes and both sides refuse
//! anything else, so no longer structure can ride the challenge field either.

use std::collections::HashMap;

use rand::RngCore;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

/// Canonical bytes signed during registration. Binding all three fields together stops
/// a registrant from claiming someone else's identity key under a different hash.
pub fn registration_message(identity_hash: &str, identity_key: &str, signing_key: &str) -> Vec<u8> {
    format!("sona-register-v1|{identity_hash}|{identity_key}|{signing_key}").into_bytes()
}

/// Verify an Ed25519 signature (all base64) over `message` against `signing_key_b64`.
/// Returns `false` on any malformed input — fail-closed, no panics on bad data.
pub fn verify(signing_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let (Ok(key), Ok(sig)) = (
        Ed25519PublicKey::from_base64(signing_key_b64),
        Ed25519Signature::from_base64(signature_b64),
    ) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

/// Single-use, TTL-bound login nonces, keyed by identity hash.
///
/// Each hash holds a small **set** of live nonces, not one slot (SP-07). With one slot,
/// every issue overwrote the previous one — and `GET /v1/challenge?hash=…` is
/// unauthenticated with a publicly computable hash, so anyone could poll a victim's hash
/// and overwrite whatever nonce that victim had just fetched, in the multi-step window
/// between fetching it and sending the `Auth` frame. The victim's `Auth` then always
/// presented a stale nonce and always failed. At 20/min per source IP that is a poison
/// every three seconds from one address, trivially multiplied — a targeted denial of
/// authentication against any named user, which also took out push register/unregister,
/// call-key publish, and account deletion (same store). It was very likely also the cause
/// of self-inflicted intermittent auth failures when one account opened two authenticated
/// sockets on the same mailbox concurrently.
#[derive(Default)]
pub struct ChallengeStore {
    // hash -> [(nonce_b64, expires_at_unix); at most MAX_NONCES_PER_HASH], oldest first
    nonces: HashMap<String, Vec<(String, u64)>>,
}

/// How long a login nonce is valid. Short window bounds the replay/relay surface.
pub const NONCE_TTL_SECS: u64 = 60;

/// Live nonces one identity hash may hold at once.
///
/// The set must be bounded, or the fix would only move the DoS from "poison one nonce"
/// to "exhaust memory issuing nonces for one hash" — so over the cap the **oldest** live
/// entry is dropped. That leaves a residual: an attacker who can push this many fresh
/// challenges for the victim's hash *inside the victim's few-second auth window* still
/// rolls the victim's nonce out. The bound is therefore sized against that window rather
/// than against real client concurrency (a client has at most a handful of sockets in
/// flight). At the 20/min per-IP `auth_rate`, evicting a specific in-flight nonce takes
/// on the order of this many distinct source addresses acting inside a window of
/// seconds, instead of the single poll that used to be enough — and the victim's retry
/// re-arms with a fresh nonce that has to be pushed out all over again.
///
/// It cannot be closed completely at this layer: `/v1/challenge` is unauthenticated by
/// design and addressed by a publicly computable hash, so *some* per-hash resource is
/// always reachable. Raising the cost and removing the "one request, one poisoning"
/// primitive is the available win.
pub const MAX_NONCES_PER_HASH: usize = 64;

/// Hard ceiling on outstanding nonces. A live nonce is at most [`NONCE_TTL_SECS`] old,
/// so a rate-limited `/challenge` cannot accumulate more than a bounded set — but cap it
/// anyway as a fail-safe against unbounded memory growth (M-3). Counted across all
/// hashes, so the per-hash set cannot be used to slip past it either.
pub const MAX_NONCES: usize = 100_000;

impl ChallengeStore {
    /// Issue a fresh [`protocol_types::WS_AUTH_NONCE_LEN`]-byte random nonce for `hash`,
    /// **adding** it to that hash's live set rather than replacing it (SP-07) — a
    /// concurrent challenge for the same hash, whoever asked for it, must not invalidate
    /// one already in flight. The length is a wire contract, not an implementation
    /// detail: both sides reject an off-length nonce (SP-01). Prunes any nonces that have
    /// already expired first, so the map cannot grow without bound when many distinct
    /// hashes each request a challenge (M-3).
    pub fn issue(&mut self, hash: &str, now: u64) -> String {
        // Only sweep once we are actually carrying some backlog, to keep the common path
        // cheap; the ceiling is the fail-safe if a sweep can't keep up.
        if self.live() >= 1024 {
            self.sweep(now);
        }
        let mut buf = [0u8; protocol_types::WS_AUTH_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let nonce = vodozemac::base64_encode(buf);
        // Fail-safe: if we are still at the ceiling after sweeping (a flood of live,
        // un-expired nonces), refuse to grow further — an existing hash may still refresh
        // its own set, but no new hash gets one until the pressure drains.
        if self.live() >= MAX_NONCES && !self.nonces.contains_key(hash) {
            return nonce; // handed back but never stored ⇒ unusable, self-limiting
        }
        let set = self.nonces.entry(hash.to_string()).or_default();
        set.retain(|(_, expires)| now < *expires);
        // Bounded per hash: a challenge flood against one hash rolls its own oldest
        // entries out instead of growing memory. Eight is far more than any real client
        // has in flight, so this only ever bites an attacker.
        if set.len() >= MAX_NONCES_PER_HASH {
            set.remove(0);
        }
        set.push((nonce.clone(), now + NONCE_TTL_SECS));
        nonce
    }

    /// Consume `nonce` for `hash` if it is in that hash's live set and has not expired.
    /// Single-use: the matched entry is removed so it can never be replayed. Only the
    /// matched nonce is removed — the other in-flight challenges for that hash survive,
    /// which is the point of the set.
    pub fn consume(&mut self, hash: &str, nonce: &str, now: u64) -> bool {
        let Some(set) = self.nonces.get_mut(hash) else {
            return false;
        };
        let Some(i) = set.iter().position(|(stored, _)| stored == nonce) else {
            // No match: also a good moment to shed this hash's expired entries, so a
            // failed attempt cannot be used to pin them for the full TTL.
            set.retain(|(_, expires)| now < *expires);
            if set.is_empty() {
                self.nonces.remove(hash);
            }
            return false;
        };
        let (_, expires) = set.remove(i);
        if set.is_empty() {
            self.nonces.remove(hash);
        }
        now < expires
    }

    /// Drop every expired nonce. Called opportunistically on issue and periodically by the
    /// relay's reaper so abandoned challenges never pin memory.
    pub fn sweep(&mut self, now: u64) {
        self.nonces.retain(|_, set| {
            set.retain(|(_, expires)| now < *expires);
            !set.is_empty()
        });
    }

    /// Total live nonces across every hash — what [`MAX_NONCES`] bounds.
    fn live(&self) -> usize {
        self.nonces.values().map(Vec::len).sum()
    }
}

/// A minimal fixed-window rate limiter. **Fail-closed**: once a key is over its limit
/// within the window, further requests are denied until the window rolls over. Keyed by
/// a pseudonymized client identifier (never a raw IP).
pub struct RateLimiter {
    window_secs: u64,
    limit: u32,
    buckets: HashMap<String, (u64, u32)>, // key -> (window_start, count)
}

impl RateLimiter {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            window_secs,
            limit,
            buckets: HashMap::new(),
        }
    }

    /// Returns `true` if the request is allowed, `false` if it should be rejected.
    pub fn check(&mut self, key: &str, now: u64) -> bool {
        // Opportunistic eviction: an untended `buckets` map grows one entry per distinct
        // client key forever (M-3). Once it gets large, drop every bucket whose window has
        // rolled over — those clients start fresh anyway, so nothing is lost.
        if self.buckets.len() >= 100_000 {
            self.sweep(now);
        }
        let entry = self.buckets.entry(key.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.window_secs {
            *entry = (now, 0); // new window
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Evict buckets whose window has already elapsed (their count would reset on next
    /// use). Called opportunistically and by the relay's periodic reaper.
    pub fn sweep(&mut self, now: u64) {
        let window = self.window_secs;
        self.buckets
            .retain(|_, (start, _)| now.saturating_sub(*start) < window);
    }
}

/// A fixed-window **byte** budget per client, for the blob/sync surfaces where the
/// request-count limiter alone is toothless (60 requests/min × 32 MiB = a ~2 GiB/min
/// disk-fill or egress-drain per address). Fail-closed like [`RateLimiter`]: a request
/// that would exceed the window's byte budget is refused and nothing is charged.
pub struct ByteBudget {
    window_secs: u64,
    limit: u64,
    buckets: HashMap<String, (u64, u64)>, // key -> (window_start, bytes_used)
}

impl ByteBudget {
    pub fn new(limit: u64, window_secs: u64) -> Self {
        Self {
            window_secs,
            limit,
            buckets: HashMap::new(),
        }
    }

    /// Try to spend `bytes` from `key`'s window. `true` = charged and allowed.
    pub fn charge(&mut self, key: &str, bytes: u64, now: u64) -> bool {
        if self.buckets.len() >= 100_000 {
            self.sweep(now);
        }
        let entry = self.buckets.entry(key.to_string()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= self.window_secs {
            *entry = (now, 0);
        }
        match entry.1.checked_add(bytes) {
            Some(total) if total <= self.limit => {
                entry.1 = total;
                true
            }
            _ => false,
        }
    }

    /// Evict buckets whose window has elapsed. Called by the relay's periodic reaper.
    pub fn sweep(&mut self, now: u64) {
        let window = self.window_secs;
        self.buckets
            .retain(|_, (start, _)| now.saturating_sub(*start) < window);
    }
}

/// Pseudonymize a client identifier (e.g. peer IP) for rate-limit keys, so raw IPs are
/// never held in memory. Keyed HMAC-style with a per-process secret would be stronger;
/// a salted SHA-256 is sufficient for an in-memory limiter that resets on restart.
pub fn pseudonymize(client_id: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b"|");
    h.update(client_id.as_bytes());
    hex::encode(&h.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let acct = Account::new();
        let signing_key = acct.ed25519_key().to_base64();
        let msg = registration_message("hash", "idk", &signing_key);
        let sig = acct.sign(&msg).to_base64();
        assert!(verify(&signing_key, &msg, &sig));
        // Tampered message must fail.
        let other = registration_message("hash", "DIFFERENT", &signing_key);
        assert!(!verify(&signing_key, &other, &sig));
        // Garbage inputs fail closed, no panic.
        assert!(!verify("not-a-key", &msg, &sig));
        assert!(!verify(&signing_key, &msg, "not-a-sig"));
    }

    #[test]
    fn nonce_is_single_use_and_expires() {
        let mut cs = ChallengeStore::default();
        let n = cs.issue("bob", 1000);
        // Wrong nonce fails.
        assert!(!cs.consume("bob", "wrong", 1000));
        // Correct nonce works once...
        let n2 = cs.issue("bob", 1000);
        assert!(cs.consume("bob", &n2, 1010));
        // ...and cannot be reused.
        assert!(!cs.consume("bob", &n2, 1010));
        // Expired nonce fails.
        let n3 = cs.issue("bob", 2000);
        assert!(!cs.consume("bob", &n3, 2000 + NONCE_TTL_SECS + 1));
        let _ = n;
    }

    #[test]
    fn rate_limiter_denies_over_limit_then_recovers_next_window() {
        let mut rl = RateLimiter::new(3, 60);
        assert!(rl.check("k", 0));
        assert!(rl.check("k", 1));
        assert!(rl.check("k", 2));
        assert!(!rl.check("k", 3)); // 4th in window -> denied (fail-closed)
        assert!(rl.check("k", 61)); // next window -> allowed again
    }

    #[test]
    fn challenge_sweep_drops_expired_nonces() {
        let mut cs = ChallengeStore::default();
        cs.issue("a", 1000);
        cs.issue("b", 1000);
        // Well past the TTL: a sweep clears the map so it can't grow without bound (M-3).
        cs.sweep(1000 + NONCE_TTL_SECS + 1);
        assert!(!cs.consume("a", "anything", 1000 + NONCE_TTL_SECS + 2));
        assert!(cs.nonces.is_empty());
    }

    /// SP-07: `/v1/challenge` is unauthenticated and the hash is public, so anyone can
    /// ask for a challenge on someone else's mailbox. Doing so must not invalidate the
    /// nonce that mailbox already has in flight — with one slot per hash it did, which
    /// is a targeted denial of authentication against any named user.
    #[test]
    fn a_concurrent_challenge_does_not_poison_one_already_in_flight() {
        let mut cs = ChallengeStore::default();
        let victim = cs.issue("victim", 1000);
        // One attacker address can spend its whole 20/min `auth_rate` budget on the
        // victim's hash and still not touch the nonce already in flight.
        for _ in 0..20 {
            cs.issue("victim", 1000);
        }
        assert!(
            cs.consume("victim", &victim, 1010),
            "the victim's own nonce must still authenticate"
        );
        // Still single-use.
        assert!(!cs.consume("victim", &victim, 1010));
    }

    /// The set is bounded, or the fix would trade one DoS for another: unbounded growth
    /// per hash. Over the cap the oldest live nonce rolls out.
    #[test]
    fn the_per_hash_nonce_set_is_bounded() {
        let mut cs = ChallengeStore::default();
        let issued: Vec<String> = (0..MAX_NONCES_PER_HASH * 3)
            .map(|_| cs.issue("bob", 1000))
            .collect();
        assert_eq!(cs.nonces["bob"].len(), MAX_NONCES_PER_HASH);
        // The newest MAX_NONCES_PER_HASH survive; the oldest are gone.
        assert!(!cs.consume("bob", &issued[0], 1010));
        assert!(cs.consume("bob", issued.last().unwrap(), 1010));
    }

    /// Two concurrent sockets on the same mailbox — the everyday version of the same bug.
    #[test]
    fn two_sockets_on_one_mailbox_can_both_authenticate() {
        let mut cs = ChallengeStore::default();
        let a = cs.issue("me", 1000);
        let b = cs.issue("me", 1000);
        assert!(cs.consume("me", &a, 1001));
        assert!(cs.consume("me", &b, 1002));
    }

    /// A failed consume must not leave the hash's expired entries pinned for the TTL.
    #[test]
    fn a_failed_consume_sheds_expired_entries() {
        let mut cs = ChallengeStore::default();
        cs.issue("bob", 1000);
        assert!(!cs.consume("bob", "wrong", 1000 + NONCE_TTL_SECS + 1));
        assert!(cs.nonces.is_empty());
    }

    #[test]
    fn rate_limiter_sweep_evicts_stale_buckets() {
        let mut rl = RateLimiter::new(3, 60);
        rl.check("k", 0);
        assert_eq!(rl.buckets.len(), 1);
        // A window later, the bucket is stale and evictable (M-3).
        rl.sweep(120);
        assert!(rl.buckets.is_empty());
    }

    #[test]
    fn byte_budget_denies_over_limit_and_recovers() {
        let mut bb = ByteBudget::new(100, 60);
        assert!(bb.charge("k", 60, 0));
        assert!(bb.charge("k", 40, 1)); // exactly at the limit
        assert!(!bb.charge("k", 1, 2)); // over -> denied, nothing charged
        assert!(bb.charge("k", 100, 61)); // next window -> fresh budget
                                          // Denied charge must not have consumed budget.
        let mut bb2 = ByteBudget::new(100, 60);
        assert!(!bb2.charge("k", 101, 0));
        assert!(bb2.charge("k", 100, 1));
        // Overflow-shaped input fails closed.
        assert!(!bb2.charge("k2", u64::MAX, 0));
    }

    #[test]
    fn byte_budget_sweep_evicts_stale_buckets() {
        let mut bb = ByteBudget::new(100, 60);
        bb.charge("k", 1, 0);
        assert_eq!(bb.buckets.len(), 1);
        bb.sweep(120);
        assert!(bb.buckets.is_empty());
    }

    #[test]
    fn pseudonymize_is_stable_and_hides_input() {
        let a = pseudonymize("1.2.3.4", "salt");
        let b = pseudonymize("1.2.3.4", "salt");
        assert_eq!(a, b);
        assert!(!a.contains("1.2.3.4"));
        assert_ne!(a, pseudonymize("1.2.3.5", "salt"));
    }
}
