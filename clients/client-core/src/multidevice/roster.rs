use super::*;

impl Client {
    /// Fetch and verify our OWN current roster (full signed records), or `None` if we have
    /// not published one. Used by [`authorize_link`](Self::authorize_link) and
    /// [`audit_own_roster`](Self::audit_own_roster).
    pub(crate) async fn fetch_own_roster(
        &self,
        username_hash: &str,
    ) -> Result<Option<KtRosterEntry>> {
        let resp = self
            .http
            .get(format!("{}/v1/kt/roster/{username_hash}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let v: Value = resp.error_for_status()?.json().await?;
        let roster: KtRosterEntry = serde_json::from_value(v["roster"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let sth: SignedTreeHead = serde_json::from_value(v["sth"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let index = v["index"].as_u64().unwrap_or(0);
        let proof_b64 = v["proof_b64"].as_str().unwrap_or("");
        if !verify_sth_b64(&self.pinned_kt_key, &sth)
            || !verify_roster_inclusion_b64(&sth, &roster, index, proof_b64)
        {
            return Err(ClientError::KtVerification(
                crypto_core::kt::KtCheck::BadTreeHead,
            ));
        }
        Ok(Some(roster))
    }
    /// Audit our OWN account's roster: fetch + verify it and compare against what we last
    /// pinned/authorized, so a device we never enrolled (a rogue enrollment under a
    /// compromised account key) is surfaced. Rollback-checked like any roster fetch.
    pub async fn audit_own_roster(
        &self,
        account: &Account,
        history: &History,
    ) -> Result<RosterAudit> {
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();
        let Some(roster) = self.fetch_own_roster(&username_hash).await? else {
            return Ok(RosterAudit::SingleDevice);
        };
        // Validate against our current binding.
        let entry = self.fetch_verified_entry(&username_hash).await?;
        if roster.validate_against(&entry).is_err() {
            return Ok(RosterAudit::SingleDevice);
        }
        // Compare by identity KEY, not device id: ids are routing labels that legitimately
        // move (a primary transfer re-ids two devices without touching any key), while a
        // key we never authorized — under a fresh id OR smuggled beneath a known id — is
        // exactly the rogue enrollment this audit exists to catch.
        let known: std::collections::HashSet<String> = history
            .pinned_roster(&username)
            .map(|p| p.devices.iter().map(|d| d.identity_key.clone()).collect())
            .unwrap_or_default();
        let unknown: Vec<String> = roster
            .devices
            .iter()
            .filter(|d| !known.contains(&d.identity_key))
            .map(|d| d.device_id.clone())
            .collect();
        if unknown.is_empty() {
            Ok(RosterAudit::Ok {
                seq: roster.seq,
                devices: roster.devices.len(),
            })
        } else {
            Ok(RosterAudit::UnknownDevices {
                seq: roster.seq,
                unknown_device_ids: unknown,
            })
        }
    }
}

use crate::multidevice::LeafAudit;
use crate::KtBindingEntry;
use kt_log::verify_inclusion_b64;
use serde_json::json;

impl Client {
    /// Self-audit **every** Key Transparency leaf under our own username (SP-13).
    ///
    /// `audit_own_roster` asks the relay for our *current* roster, which a two-faced
    /// relay simply answers with the pre-injection epoch — it serves the victim one view
    /// and everyone else another, and every check stays green. `sona-auditor` cannot see
    /// it either: it verifies the STH signature and append-only consistency, and an
    /// injected leaf is a genuine append. So the class of attack SP-01 enabled was
    /// invisible from both ends.
    ///
    /// This enumerates the whole leaf set for our username with an inclusion proof each,
    /// against one head, and checks every leaf against what we actually authorized:
    ///
    /// * every proof must verify against that head, and the head must carry the pinned
    ///   KT signature — otherwise the relay is equivocating and we say so;
    /// * every **binding** must name our own identity/signing keys;
    /// * every **roster** must list only devices we recognize.
    ///
    /// A leaf that is validly signed but not ours is exactly what a harvested-signature
    /// injection looks like from the victim's side, and it is what this makes loud.
    ///
    /// Owner-gated at the relay by a signed challenge — "all leaves for this username"
    /// served to anyone would be a fresh enumeration oracle (SP-04).
    ///
    /// **This is a detection net, not the fix.** Making the injection impossible is
    /// SP-01, which is closed; this is the safety net for the class. It is also not yet
    /// automatic: the caller decides when to run it, and cross-checking the head against
    /// a peer's independently-received view (`send_head` / `compare_foreign_head`) is
    /// still a separate step — without that, a relay that is two-faced about the *head*
    /// as well is not caught here.
    pub async fn audit_own_leaves(
        &self,
        account: &Account,
        history: &History,
    ) -> Result<LeafAudit> {
        let username = account.account_id().to_string();
        let hash = account.identity_hash().as_str().to_string();
        let nonce = self.fetch_nonce(&hash).await?;
        let signature = account
            .ratchet_ref()
            .sign(&protocol_types::kt_leaves_signing_message(&hash, &nonce));
        let body: Value = self
            .http
            .post(format!("{}/v1/kt/leaves", self.base_url))
            .json(&json!({ "hash": hash, "nonce": nonce, "signature": signature }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let sth: SignedTreeHead = serde_json::from_value(body["sth"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        if !verify_sth_b64(&self.pinned_kt_key, &sth) {
            return Ok(LeafAudit::BadProof);
        }

        // What we believe our own account is: our keys, and the devices we enrolled.
        let my_identity = account.ratchet_ref().identity_key();
        let my_signing = account.ratchet_ref().signing_key();
        let known_devices: std::collections::HashSet<String> = history
            .pinned_roster(&username)
            .map(|p| p.devices.iter().map(|d| d.identity_key.clone()).collect())
            .unwrap_or_default();

        let leaves = body["leaves"].as_array().cloned().unwrap_or_default();
        let mut findings = Vec::new();
        for leaf in &leaves {
            let index = leaf["index"].as_u64().unwrap_or(0);
            let proof = leaf["proof_b64"].as_str().unwrap_or("");
            match leaf["kind"].as_str() {
                Some("binding") => {
                    let Ok(entry) =
                        serde_json::from_value::<KtBindingEntry>(leaf["record"].clone())
                    else {
                        return Ok(LeafAudit::BadProof);
                    };
                    if !verify_inclusion_b64(&sth, &entry, index, proof) {
                        return Ok(LeafAudit::BadProof);
                    }
                    // A binding we did not make names keys that are not ours. A *past*
                    // binding legitimately does too (key rotation), so this only flags
                    // the leaf whose keys are current-but-not-ours — the shape an
                    // injected rotation to a relay-held key takes.
                    if entry.signing_key != my_signing && entry.identity_key == my_identity {
                        findings.push(format!(
                            "leaf {index}: a binding for our identity key under a signing key we do not hold"
                        ));
                    }
                }
                Some("roster") => {
                    let Ok(roster) =
                        serde_json::from_value::<KtRosterEntry>(leaf["record"].clone())
                    else {
                        return Ok(LeafAudit::BadProof);
                    };
                    if !verify_roster_inclusion_b64(&sth, &roster, index, proof) {
                        return Ok(LeafAudit::BadProof);
                    }
                    // Compare by identity KEY, not device id — ids legitimately move on a
                    // primary transfer, a key we never enrolled never does.
                    for d in &roster.devices {
                        if !known_devices.is_empty() && !known_devices.contains(&d.identity_key) {
                            findings.push(format!(
                                "leaf {index}: roster epoch {} lists device {} we never enrolled",
                                roster.seq, d.device_id
                            ));
                        }
                    }
                }
                _ => return Ok(LeafAudit::BadProof),
            }
        }
        if findings.is_empty() {
            Ok(LeafAudit::Ok {
                leaves: leaves.len(),
            })
        } else {
            Ok(LeafAudit::Unrecognized { findings })
        }
    }
}
