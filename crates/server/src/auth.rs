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
#[derive(Default)]
pub struct ChallengeStore {
    // hash -> (nonce_b64, expires_at_unix)
    nonces: HashMap<String, (String, u64)>,
}

/// How long a login nonce is valid. Short window bounds the replay/relay surface.
pub const NONCE_TTL_SECS: u64 = 60;

/// Hard ceiling on outstanding nonces. A live nonce is at most [`NONCE_TTL_SECS`] old,
/// so a rate-limited `/challenge` cannot accumulate more than a bounded set — but cap it
/// anyway as a fail-safe against unbounded memory growth (M-3).
pub const MAX_NONCES: usize = 100_000;

impl ChallengeStore {
    /// Issue a fresh 32-byte random nonce for `hash`, replacing any prior one. Prunes any
    /// nonces that have already expired first, so the map cannot grow without bound when
    /// many distinct hashes each request a challenge (M-3).
    pub fn issue(&mut self, hash: &str, now: u64) -> String {
        // Only sweep once we are actually carrying some backlog, to keep the common path
        // cheap; the ceiling is the fail-safe if a sweep can't keep up.
        if self.nonces.len() >= 1024 {
            self.sweep(now);
        }
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let nonce = vodozemac::base64_encode(buf);
        // Fail-safe: if we are still at the ceiling after sweeping (a flood of live,
        // un-expired nonces), refuse to grow further — an existing hash may still refresh
        // its own slot, but no new hash gets one until the pressure drains.
        if self.nonces.len() >= MAX_NONCES && !self.nonces.contains_key(hash) {
            return nonce; // handed back but never stored ⇒ unusable, self-limiting
        }
        self.nonces
            .insert(hash.to_string(), (nonce.clone(), now + NONCE_TTL_SECS));
        nonce
    }

    /// Consume the nonce for `hash` if it matches and has not expired. Single-use:
    /// a successful (or expired) check removes it so it can never be replayed.
    pub fn consume(&mut self, hash: &str, nonce: &str, now: u64) -> bool {
        match self.nonces.remove(hash) {
            Some((stored, expires)) => stored == nonce && now < expires,
            None => false,
        }
    }

    /// Drop every expired nonce. Called opportunistically on issue and periodically by the
    /// relay's reaper so abandoned challenges never pin memory.
    pub fn sweep(&mut self, now: u64) {
        self.nonces.retain(|_, (_, expires)| now < *expires);
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
