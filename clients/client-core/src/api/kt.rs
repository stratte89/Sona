use crate::*;

impl Client {
    /// Bootstrap helper: fetch the server's KT public key. In production the pin is
    /// shipped out-of-band; trusting this endpoint blindly defeats the purpose, so use
    /// it only for first setup and confirm the value through a second channel.
    /// `access_token` is required here too when the relay is private — this call
    /// happens before a `Client` exists.
    pub async fn fetch_kt_pubkey(base_url: &str, access_token: Option<&str>) -> Result<String> {
        Self::fetch_kt_pubkey_via(base_url, access_token, None).await
    }

    /// [`fetch_kt_pubkey`](Self::fetch_kt_pubkey) through an optional SOCKS5 proxy —
    /// the bootstrap fetch must honor the proxy too, or first setup leaks the relay
    /// hostname and the user's IP outside Tor.
    pub async fn fetch_kt_pubkey_via(
        base_url: &str,
        access_token: Option<&str>,
        proxy: Option<&str>,
    ) -> Result<String> {
        let proxy = normalize_proxy(proxy.map(str::to_string));
        let v: Value = build_http(
            access_token.filter(|t| !t.trim().is_empty()),
            proxy.as_deref(),
        )
        .get(format!("{base_url}/v1/kt/pubkey"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
        v["pubkey"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ClientError::Protocol("missing pubkey".into()))
    }

    /// Fetch the log's current signed tree head (verifying it's signed by the pinned key).
    pub async fn fetch_tree_head(&self) -> Result<SignedTreeHead> {
        let sth: SignedTreeHead = self
            .http
            .get(format!("{}/v1/kt/sth", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !verify_sth_b64(&self.pinned_kt_key, &sth) {
            return Err(ClientError::KtVerification(KtCheck::BadTreeHead));
        }
        Ok(sth)
    }

    async fn fetch_consistency(&self, from: u64) -> Result<(String, SignedTreeHead)> {
        let v: Value = self
            .http
            .get(format!("{}/v1/kt/consistency?from={from}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let proof = v["proof_b64"]
            .as_str()
            .ok_or_else(|| ClientError::Protocol("missing proof".into()))?
            .to_string();
        let sth: SignedTreeHead = serde_json::from_value(v["sth"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        Ok((proof, sth))
    }

    /// Gossip step over time: fetch the current tree head and check it is a consistent,
    /// append-only continuation of the last one we witnessed. Detects a server that rolls
    /// back or forks the log **against us**. Persist the returned head as the new witness
    /// when the verdict is `Consistent`.
    pub async fn advance_witness(
        &self,
        previous: Option<&SignedTreeHead>,
    ) -> Result<(SignedTreeHead, GossipVerdict)> {
        let current = self.fetch_tree_head().await?;
        let Some(prev) = previous else {
            return Ok((current, GossipVerdict::Consistent));
        };
        let verdict = if prev.tree_size == current.tree_size {
            check_heads(&self.pinned_kt_key, prev, &current, None)
        } else if prev.tree_size == 0 {
            // The empty tree is trivially a prefix of any tree.
            GossipVerdict::Consistent
        } else if prev.tree_size < current.tree_size {
            let (proof, resp) = self.fetch_consistency(prev.tree_size).await?;
            check_heads(&self.pinned_kt_key, prev, &resp, Some(&proof))
        } else {
            // Our server presents a SMALLER tree than we already saw. An append-only log
            // never shrinks — this is a rollback, i.e. equivocation.
            GossipVerdict::Equivocation
        };
        Ok((current, verdict))
    }

    /// Cross-client gossip: compare a tree head **someone else** saw (shared out-of-band or
    /// in-band) against our own current view. If the server showed them a different history
    /// (split view), this catches it.
    pub async fn compare_foreign_head(&self, other: &SignedTreeHead) -> Result<GossipVerdict> {
        let current = self.fetch_tree_head().await?;
        if other.tree_size == current.tree_size {
            return Ok(check_heads(&self.pinned_kt_key, other, &current, None));
        }
        if other.tree_size == 0 {
            return Ok(GossipVerdict::Consistent); // empty is a prefix of our view
        }
        if other.tree_size < current.tree_size {
            let (proof, resp) = self.fetch_consistency(other.tree_size).await?;
            return Ok(check_heads(&self.pinned_kt_key, other, &resp, Some(&proof)));
        }
        // They saw a bigger tree than our server admits — our view may just be stale.
        Ok(GossipVerdict::Inconclusive)
    }

    /// Fetch the latest KT entry for `hash` and verify it against the pinned log key
    /// (signed tree head + inclusion proof + username binding). Trusts nothing the
    /// server said that isn't proven.
    pub(crate) async fn fetch_verified_entry(&self, hash: &str) -> Result<KtEntry> {
        let resp = self
            .http
            .get(format!("{}/v1/kt/proof/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::UserNotFound);
        }
        let proof: KtProofResponse = resp.error_for_status()?.json().await?;
        if !verify_sth_b64(&self.pinned_kt_key, &proof.sth) {
            return Err(ClientError::KtVerification(KtCheck::BadTreeHead));
        }
        if !verify_inclusion_b64(&proof.sth, &proof.entry, proof.index, &proof.proof_b64) {
            return Err(ClientError::KtVerification(KtCheck::NotInLog));
        }
        if proof.entry.username_hash != hash {
            return Err(ClientError::KtVerification(KtCheck::WrongUsername));
        }
        Ok(proof.entry)
    }

    /// Audit our OWN identity in the Key Transparency log: confirm the log still binds our
    /// username to the keys we expect. If it binds a *different* key, someone (a malicious
    /// server, or an attacker) published a rogue entry under our name — detectable exactly
    /// because the log is public and append-only.
    ///
    /// The account binding always carries the **primary's** keys. On the primary those are
    /// this device's own keys; a **linked** device instead checks the primary key it pinned
    /// at link time (its own key lives in the device roster, not the binding — see
    /// [`audit_own_roster`](Self::audit_own_roster) for that half of the audit).
    pub async fn audit_own_key(
        &self,
        account: &Account,
        history: &History,
    ) -> Result<AuditOutcome> {
        let hash = account.identity_hash().as_str().to_string();
        let resp = self
            .http
            .get(format!("{}/v1/kt/proof/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(AuditOutcome::NotRegistered);
        }
        let proof: KtProofResponse = resp.error_for_status()?.json().await?;
        if !verify_sth_b64(&self.pinned_kt_key, &proof.sth) {
            return Err(ClientError::KtVerification(KtCheck::BadTreeHead));
        }
        if !verify_inclusion_b64(&proof.sth, &proof.entry, proof.index, &proof.proof_b64) {
            return Err(ClientError::KtVerification(KtCheck::NotInLog));
        }
        let intact = if history.is_primary_device() {
            proof.entry.identity_key == account.ratchet_ref().identity_key()
                && proof.entry.signing_key == account.ratchet_ref().signing_key()
        } else if let Some(primary_key) = history.self_primary_key() {
            proof.entry.identity_key == primary_key
        } else {
            // A linked device without a pinned primary key can't attribute the binding.
            false
        };
        if intact {
            Ok(AuditOutcome::Ok)
        } else {
            Ok(AuditOutcome::RogueKey {
                published_identity_key: proof.entry.identity_key,
            })
        }
    }
}
