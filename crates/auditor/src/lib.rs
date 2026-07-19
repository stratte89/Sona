//! Key Transparency **witness** logic.
//!
//! An auditor is an independent process (run it anywhere — another machine, a friend's
//! server) that periodically fetches the relay's signed tree head and holds it to one
//! rule: *the log only ever grows*. Every new head must be provably consistent with the
//! last one this witness saw. Because heads are Ed25519-signed by the relay's pinned KT
//! key, a violation leaves the operator holding two conflicting signatures — evidence
//! anyone can verify, not an accusation.
//!
//! This module is transport-free (the binary in `main.rs` does the HTTP): [`Witness`]
//! is fed heads and a way to fetch consistency proofs, and answers with an [`Outcome`].
//! That keeps every attack path unit-testable against an in-memory [`kt_log::KtLog`].

use kt_log::{verify_consistency_b64, verify_sth_b64, SignedTreeHead};
use serde::{Deserialize, Serialize};

/// Shape of `GET /v1/kt/consistency?from=` — proof and current head from one lock, so
/// the pair cannot drift between two requests.
#[derive(Deserialize)]
pub struct ConsistencyResponse {
    pub proof_b64: String,
    pub sth: SignedTreeHead,
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status().as_u16()));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

/// One observation cycle against a live relay. Returns the witness verdict, or a
/// transport error (network trouble is *not* an alarm — a log can't lie by being
/// unreachable, and alarming on it would let an attacker DoS the witness into noise).
pub async fn observe_once(
    client: &reqwest::Client,
    base: &str,
    witness: &mut Witness,
) -> Result<Outcome, String> {
    // When we already hold a head, ask for the consistency proof up front (see
    // [`ConsistencyResponse`]).
    if let Some(last) = witness.last.clone() {
        let url = format!("{base}/v1/kt/consistency?from={}", last.tree_size);
        match fetch_json::<ConsistencyResponse>(client, &url).await {
            Ok(r) => {
                let proof = r.proof_b64;
                return Ok(witness.observe(r.sth, move |_| Some(proof)));
            }
            // 400 = "from exceeds current size": the served tree shrank below the head
            // we hold. Fetch the bare head and let the witness raise the rollback alarm.
            Err(_) => {
                let sth: SignedTreeHead = fetch_json(client, &format!("{base}/v1/kt/sth")).await?;
                return Ok(witness.observe(sth, |_| None));
            }
        }
    }
    let sth: SignedTreeHead = fetch_json(client, &format!("{base}/v1/kt/sth")).await?;
    Ok(witness.observe(sth, |_| None))
}

/// What a single observation of the relay's current head concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// First head this witness has ever seen — pinned as the baseline.
    FirstHead,
    /// Same size, same root as before.
    Unchanged,
    /// The log grew and proved append-only consistency with our last head.
    Extended { from: u64, to: u64 },
    /// Misbehavior. The witness state is deliberately NOT advanced, so the conflicting
    /// baseline head is preserved as one half of the evidence.
    Alarm(Alarm),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlarmKind {
    /// The head is not signed by the pinned KT key.
    BadSignature,
    /// The served head commits a *smaller* tree than one it already signed. An honest
    /// current head never goes backward — this is a restore-from-backup at best and a
    /// history rewrite at worst; either way past bindings can no longer be trusted.
    Rollback,
    /// Same tree size, different root: two signed, conflicting histories. The classic
    /// split-view attack, and non-repudiable.
    Equivocation,
    /// The log grew but the server could not (or would not) prove the growth was
    /// append-only from our head. An honest server can always produce this proof.
    BadConsistency,
}

/// Evidence bundle for an alarm: both signed heads (and the failed proof, if any).
/// Everything needed for a third party to re-verify the misbehavior offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alarm {
    pub kind: AlarmKind,
    /// The baseline head this witness had already verified (absent only for
    /// [`AlarmKind::BadSignature`] on first contact).
    pub old: Option<SignedTreeHead>,
    /// The offending head as served.
    pub new: SignedTreeHead,
    /// The consistency proof that failed verification, if one was supplied.
    pub proof_b64: Option<String>,
}

/// A witness's persistent view: the pinned KT public key and the last verified head.
/// Serialize this to disk between runs — the whole point is continuity over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub pinned_key_b64: String,
    pub last: Option<SignedTreeHead>,
}

impl Witness {
    pub fn new(pinned_key_b64: impl Into<String>) -> Self {
        Witness {
            pinned_key_b64: pinned_key_b64.into(),
            last: None,
        }
    }

    /// Observe the relay's currently-served head. `fetch_proof(from)` is called at most
    /// once, only when the tree grew, and must return the base64 consistency proof from
    /// tree size `from` to `new`'s size (i.e. what `GET /v1/kt/consistency?from=` serves).
    ///
    /// State advances only on honest outcomes; every [`Outcome::Alarm`] leaves `last`
    /// untouched so the evidence pair stays intact.
    pub fn observe<F>(&mut self, new: SignedTreeHead, fetch_proof: F) -> Outcome
    where
        F: FnOnce(u64) -> Option<String>,
    {
        if !verify_sth_b64(&self.pinned_key_b64, &new) {
            return Outcome::Alarm(Alarm {
                kind: AlarmKind::BadSignature,
                old: self.last.clone(),
                new,
                proof_b64: None,
            });
        }
        let Some(old) = self.last.clone() else {
            self.last = Some(new);
            return Outcome::FirstHead;
        };

        if new.tree_size < old.tree_size {
            return Outcome::Alarm(Alarm {
                kind: AlarmKind::Rollback,
                old: Some(old),
                new,
                proof_b64: None,
            });
        }
        if new.tree_size == old.tree_size {
            return if new.root_b64 == old.root_b64 {
                Outcome::Unchanged
            } else {
                Outcome::Alarm(Alarm {
                    kind: AlarmKind::Equivocation,
                    old: Some(old),
                    new,
                    proof_b64: None,
                })
            };
        }

        // Growth from an *empty* baseline needs no proof: the empty tree is trivially a
        // prefix of every tree (RFC 6962 defines no consistency proof from size 0, and
        // the relay's endpoint refuses from=0 for the same reason).
        if old.tree_size == 0 {
            let to = new.tree_size;
            self.last = Some(new);
            return Outcome::Extended { from: 0, to };
        }

        let proof = fetch_proof(old.tree_size);
        match &proof {
            Some(p) if verify_consistency_b64(&old, &new, p) => {
                let (from, to) = (old.tree_size, new.tree_size);
                self.last = Some(new);
                Outcome::Extended { from, to }
            }
            _ => Outcome::Alarm(Alarm {
                kind: AlarmKind::BadConsistency,
                old: Some(old),
                new,
                proof_b64: proof,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use kt_log::{consistency_to_b64, KtEntry, KtLog};
    use rand::rngs::OsRng;

    /// Same no-pad base64 the rest of the codebase uses on the wire.
    fn b64e(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        STANDARD_NO_PAD.encode(bytes)
    }

    fn claim(name: &str) -> KtEntry {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = b64e(sk.verifying_key().as_bytes());
        KtEntry::new_claim(name.into(), "id".into(), vk, 1, |p| {
            b64e(&sk.sign(p).to_bytes())
        })
    }

    #[test]
    fn honest_growth_is_accepted() {
        let mut log = KtLog::generate();
        let mut w = Witness::new(log.verifying_key_b64());

        log.append(claim("alice")).unwrap();
        assert_eq!(w.observe(log.sth(1), |_| None), Outcome::FirstHead);
        assert_eq!(w.observe(log.sth(2), |_| None), Outcome::Unchanged);

        log.append(claim("bob")).unwrap();
        log.append(claim("carol")).unwrap();
        let outcome = w.observe(log.sth(3), |from| {
            Some(consistency_to_b64(&log.consistency(from as usize).unwrap()))
        });
        assert_eq!(outcome, Outcome::Extended { from: 1, to: 3 });
        assert_eq!(w.last.as_ref().unwrap().tree_size, 3);
    }

    #[test]
    fn growth_from_empty_baseline_needs_no_proof() {
        let mut log = KtLog::generate();
        let mut w = Witness::new(log.verifying_key_b64());
        assert_eq!(w.observe(log.sth(1), |_| None), Outcome::FirstHead);
        log.append(claim("alice")).unwrap();
        // No consistency proof exists from size 0; the empty tree is a prefix of all.
        assert_eq!(
            w.observe(log.sth(2), |_| None),
            Outcome::Extended { from: 0, to: 1 }
        );
    }

    #[test]
    fn split_view_same_size_is_equivocation() {
        let seed = KtLog::generate().signing_key_seed_b64();
        let mut real = KtLog::from_seed_b64(&seed).unwrap();
        let mut fork = KtLog::from_seed_b64(&seed).unwrap();
        let mut w = Witness::new(real.verifying_key_b64());

        real.append(claim("alice")).unwrap();
        fork.append(claim("attacker")).unwrap();

        assert_eq!(w.observe(real.sth(1), |_| None), Outcome::FirstHead);
        match w.observe(fork.sth(2), |_| None) {
            Outcome::Alarm(a) => {
                assert_eq!(a.kind, AlarmKind::Equivocation);
                // Both halves of the evidence are present and independently verifiable.
                assert!(a.old.is_some());
            }
            other => panic!("expected equivocation alarm, got {other:?}"),
        }
        // The baseline is preserved for the evidence pair.
        assert_eq!(w.last.as_ref().unwrap().root_b64, real.sth(1).root_b64);
    }

    #[test]
    fn shrunken_tree_is_rollback() {
        let mut log = KtLog::generate();
        let mut w = Witness::new(log.verifying_key_b64());
        log.append(claim("alice")).unwrap();
        log.append(claim("bob")).unwrap();
        let big = log.sth(1);

        // Simulate a restore-from-backup: a freshly signed head at size 1.
        let seed_log = {
            let mut l = KtLog::from_seed_b64(&log.signing_key_seed_b64()).unwrap();
            l.append(claim("alice")).unwrap();
            l
        };
        assert_eq!(w.observe(big, |_| None), Outcome::FirstHead);
        match w.observe(seed_log.sth(2), |_| None) {
            Outcome::Alarm(a) => assert_eq!(a.kind, AlarmKind::Rollback),
            other => panic!("expected rollback alarm, got {other:?}"),
        }
    }

    #[test]
    fn growth_without_valid_proof_is_bad_consistency() {
        let seed = KtLog::generate().signing_key_seed_b64();
        let mut real = KtLog::from_seed_b64(&seed).unwrap();
        let mut fork = KtLog::from_seed_b64(&seed).unwrap();
        let mut w = Witness::new(real.verifying_key_b64());

        real.append(claim("alice")).unwrap();
        assert_eq!(w.observe(real.sth(1), |_| None), Outcome::FirstHead);

        // A *forked* history that grew past our size can produce a proof — but not one
        // that links from OUR head, so verification must fail.
        fork.append(claim("attacker")).unwrap();
        fork.append(claim("bob")).unwrap();
        let outcome = w.observe(fork.sth(2), |from| {
            Some(consistency_to_b64(
                &fork.consistency(from as usize).unwrap(),
            ))
        });
        match outcome {
            Outcome::Alarm(a) => {
                assert_eq!(a.kind, AlarmKind::BadConsistency);
                assert!(a.proof_b64.is_some(), "failed proof is kept as evidence");
            }
            other => panic!("expected bad-consistency alarm, got {other:?}"),
        }

        // No proof at all is the same verdict.
        match w.observe(fork.sth(3), |_| None) {
            Outcome::Alarm(a) => assert_eq!(a.kind, AlarmKind::BadConsistency),
            other => panic!("expected bad-consistency alarm, got {other:?}"),
        }
    }

    #[test]
    fn foreign_signature_is_rejected() {
        let mut log = KtLog::generate();
        log.append(claim("alice")).unwrap();
        let mut w = Witness::new(KtLog::generate().verifying_key_b64()); // wrong pin
        match w.observe(log.sth(1), |_| None) {
            Outcome::Alarm(a) => assert_eq!(a.kind, AlarmKind::BadSignature),
            other => panic!("expected bad-signature alarm, got {other:?}"),
        }
        assert!(w.last.is_none(), "unverified heads are never pinned");
    }

    #[test]
    fn witness_state_round_trips_through_json() {
        let mut log = KtLog::generate();
        let mut w = Witness::new(log.verifying_key_b64());
        log.append(claim("alice")).unwrap();
        w.observe(log.sth(1), |_| None);

        let saved = serde_json::to_string(&w).unwrap();
        let mut restored: Witness = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.observe(log.sth(2), |_| None), Outcome::Unchanged);
    }
}
