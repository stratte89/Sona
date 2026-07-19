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
