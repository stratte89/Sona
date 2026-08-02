use crate::*;

impl Client {
    /// Publish this identity to the relay: append our KT claim entry and upload one-time
    /// keys so others can start sessions with us.
    ///
    /// The log's chain per name is append-only, so a fresh seq-0 claim is refused (409)
    /// whenever the name has any history. Two recoverable cases are retried here with
    /// the correct chained entry:
    /// * the chain already binds OUR keys (changing the username back to a previous one)
    ///   → append a continuation rotation, which also clears any release;
    /// * the chain is **released** by its previous owner → append a self-signed takeover
    ///   claim; the relay accepts it once the grace period has passed.
    ///
    /// A name currently bound to someone else's keys stays a hard 409.
    pub async fn register(&self, account: &mut Account, num_one_time_keys: usize) -> Result<()> {
        self.register_with_invite(account, num_one_time_keys, None)
            .await
    }

    /// [`Client::register`] carrying a single-use invite code, for relays that gate
    /// brand-new accounts (`CAP_INVITE_REGISTER`). The code rides only on this call —
    /// rotations/renames never need one.
    pub async fn register_with_invite(
        &self,
        account: &mut Account,
        num_one_time_keys: usize,
        invite_code: Option<&str>,
    ) -> Result<()> {
        let one_time_keys = account.ratchet().generate_one_time_keys(num_one_time_keys);
        // A reusable last-resort key so others can still start a session if our one-time
        // keys are ever drained (defends against a one-time-key-drain DoS).
        let fallback_key = account.ratchet().generate_fallback_key();
        let entry = account.kt_claim_entry(now());
        match self
            .post_register(&entry, &one_time_keys, &fallback_key, invite_code)
            .await
        {
            Err(ClientError::Status(409)) => {
                let hash = account.identity_hash().as_str().to_string();
                let current = self.fetch_verified_entry(&hash).await?;
                let ours = current.identity_key == account.ratchet_ref().identity_key()
                    && current.signing_key == account.ratchet_ref().signing_key();
                let retry = if ours {
                    kt_log::KtEntry::new_rotation(
                        current.seq + 1,
                        hash,
                        account.ratchet_ref().identity_key(),
                        account.ratchet_ref().signing_key(),
                        current.signing_key,
                        now(),
                        false,
                        |p| account.ratchet_ref().sign(p),
                    )
                } else if current.released {
                    kt_log::KtEntry::new_reclaim(
                        current.seq + 1,
                        hash,
                        account.ratchet_ref().identity_key(),
                        account.ratchet_ref().signing_key(),
                        now(),
                        |p| account.ratchet_ref().sign(p),
                    )
                } else {
                    return Err(ClientError::Status(409));
                };
                // Chained entries (rotation/reclaim) are never invite-gated server-side.
                self.post_register(&retry, &one_time_keys, &fallback_key, None)
                    .await
            }
            other => other,
        }
    }

    async fn post_register(
        &self,
        entry: &KtEntry,
        one_time_keys: &[String],
        fallback_key: &str,
        invite_code: Option<&str>,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(format!("{}/v1/register", self.base_url))
            .json(&json!({
                "entry": entry,
                "one_time_keys": one_time_keys,
                "fallback_key": fallback_key,
            }));
        if let Some(code) = invite_code.map(str::trim).filter(|c| !c.is_empty()) {
            req = req.header("x-sona-invite", code);
        }
        let resp = req.send().await?;
        ensure_ok(resp).await
    }

    /// Does the KT log still bind `username` to this account's keys? Used by the alias
    /// drains: when a released former name's grace runs out and someone else takes it
    /// over, its mailbox auth starts failing and this check (KT-verified, not relay
    /// say-so) tells the client to drop the alias for good.
    pub async fn owns_username(&self, account: &Account, username: &str) -> Result<bool> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        let entry = self.fetch_verified_entry(&hash).await?;
        Ok(entry.identity_key == account.ratchet_ref().identity_key()
            && entry.signing_key == account.ratchet_ref().signing_key())
    }

    /// Release a username we own (typically the OLD name right after a rename): append a
    /// signed release entry to its KT chain. We keep the name — the alias mailbox keeps
    /// draining and we can take it back with a plain re-registration — until the grace
    /// period ([`kt_log::RELEASE_GRACE_SECS`]) runs out, after which anyone may claim it.
    pub async fn release_username(&self, account: &Account, username: &str) -> Result<()> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        let current = self.fetch_verified_entry(&hash).await?;
        if current.identity_key != account.ratchet_ref().identity_key()
            || current.signing_key != account.ratchet_ref().signing_key()
        {
            return Err(ClientError::Protocol(
                "cannot release a username bound to different keys".into(),
            ));
        }
        if current.released {
            return Ok(()); // already released (idempotent retry)
        }
        let release = kt_log::KtEntry::new_rotation(
            current.seq + 1,
            hash,
            account.ratchet_ref().identity_key(),
            account.ratchet_ref().signing_key(),
            current.signing_key,
            now(),
            true,
            |p| account.ratchet_ref().sign(p),
        );
        // No key material rides along: a release must not touch the mailbox's directory
        // record (the relay skips the directory for released entries anyway).
        let resp = self
            .http
            .post(format!("{}/v1/register", self.base_url))
            .json(&json!({ "entry": release, "one_time_keys": [] }))
            .send()
            .await?;
        ensure_ok(resp).await
    }

    /// Delete this account from the relay: the directory records (account mailbox,
    /// device mailboxes, owned former-username mailboxes), all queued ciphertext for
    /// them, their push subscriptions, and any live sockets (kicked with a terminal
    /// `revoked` frame). Authorized by a single-use challenge signed with the account
    /// signing key. The KT log is untouched (append-only); pair this with
    /// [`release_username`](Self::release_username) so the name unbinds and becomes
    /// claimable after the grace period.
    pub async fn delete_account(
        &self,
        account: &Account,
        previous_usernames: &[String],
    ) -> Result<()> {
        let hash = account.identity_hash().as_str().to_string();
        let alias_hashes: Vec<String> = previous_usernames
            .iter()
            .map(|u| IdentityHash::from_identifier(u).as_str().to_string())
            .collect();
        let nonce = self.fetch_nonce(&hash).await?;
        let msg = protocol_types::account_delete_signing_message(&hash, &alias_hashes, &nonce);
        let signature = account.ratchet_ref().sign(&msg);
        let resp = self
            .http
            .post(format!("{}/v1/account/delete", self.base_url))
            .json(&json!({
                "hash": hash,
                "alias_hashes": alias_hashes,
                "nonce": nonce,
                "signature": signature,
            }))
            .send()
            .await?;
        ensure_ok(resp).await
    }

    /// Top up our own one-time keys so others can keep starting sessions with us. Asks
    /// the relay whether the stock is `plenty`; if not, generates a fresh batch, signs the
    /// upload with our identity key, and publishes it. Returns how many keys were
    /// generated and uploaded (`0` = nothing needed).
    ///
    /// The relay answers with a coarse bucket rather than an exact count (SP-10), so this
    /// uploads a whole batch rather than a computed difference — the relay dedups and
    /// caps, so overshooting costs only bandwidth, whereas undershooting would starve the
    /// key stock and push new sessions onto the reusable fallback key.
    ///
    /// Call on login and periodically. NOTE: this advances the ratchet account state, so
    /// the caller should re-seal the vault afterward if any keys were added.
    pub async fn replenish_own_keys(&self, account: &mut Account, target: usize) -> Result<usize> {
        let hash = account.identity_hash().as_str().to_string();
        let status: Value = self
            .http
            .get(format!("{}/v1/keys/count/{hash}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // The relay publishes a coarse bucket, never an exact count (SP-10): an exact
        // count is a first-contact activity oracle for anyone who can spell a username,
        // because each new inbound session consumes exactly one key. "plenty" is the only
        // answer that means "do nothing"; otherwise upload a full batch. Over-uploading
        // is free — the relay dedups and caps at MAX_ONE_TIME_KEYS — and an old relay
        // that still answers with `remaining` simply reads as "not plenty", so this
        // fails safe in the top-up direction rather than the starve direction.
        if status["level"].as_str() == Some("plenty") {
            return Ok(0);
        }
        // Top up past the relay's watermark, not merely to `target` — a target at or
        // below the watermark would leave the level "low" and re-upload on every cycle.
        let need = target.max(status["low_watermark"].as_u64().unwrap_or(0) as usize + 1);
        let keys = account.ratchet().generate_one_time_keys(need);
        let msg = protocol_types::one_time_keys_signing_message(&hash, &keys);
        let signature = account.ratchet_ref().sign(&msg);
        let resp = self
            .http
            .post(format!("{}/v1/onetimekeys", self.base_url))
            .json(&json!({
                "identity_hash": hash,
                "one_time_keys": keys,
                "signature": signature,
            }))
            .send()
            .await?;
        ensure_ok(resp).await?;
        Ok(need)
    }

    /// Fetch a single-use auth nonce for our own mailbox.
    pub(crate) async fn fetch_nonce(&self, hash: &str) -> Result<String> {
        let challenge: Value = self
            .http
            .get(format!("{}/v1/challenge?hash={hash}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        challenge["nonce"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ClientError::Protocol("missing nonce".into()))
    }

    /// Register a **content-free push endpoint** (UnifiedPush-style URL) for our
    /// mailbox. While we are offline, the relay POSTs a constant body there when a
    /// message is queued — no content, no sender, no identity; the app then drains the
    /// mailbox over the authenticated channel. Registration is authorized by signing a
    /// single-use challenge bound to the exact endpoint, so nobody else can subscribe
    /// to our message timing.
    pub async fn register_push(&self, account: &Account, endpoint: &str) -> Result<()> {
        let hash = account.identity_hash().as_str().to_string();
        self.register_push_as(account, &hash, endpoint).await
    }

    /// Like [`register_push`](Self::register_push), for an explicit mailbox hash —
    /// the mirror of [`subscribe_as`](Self::subscribe_as). A **linked device** registers
    /// its *device* mailbox (whose directory record carries this device's signing key,
    /// so the signed challenge authenticates); a primary registers the account mailbox.
    pub async fn register_push_as(
        &self,
        account: &Account,
        hash: &str,
        endpoint: &str,
    ) -> Result<()> {
        let nonce = self.fetch_nonce(hash).await?;
        let msg = protocol_types::push_register_signing_message(hash, endpoint, &nonce);
        let signature = account.ratchet_ref().sign(&msg);
        let resp = self
            .http
            .post(format!("{}/v1/push/register", self.base_url))
            .json(&json!({
                "hash": hash,
                "endpoint": endpoint,
                "nonce": nonce,
                "signature": signature,
            }))
            .send()
            .await?;
        ensure_ok(resp).await
    }

    /// Remove our push endpoint (e.g. on logout or when the distributor rotates it).
    pub async fn unregister_push(&self, account: &Account) -> Result<()> {
        let hash = account.identity_hash().as_str().to_string();
        self.unregister_push_as(account, &hash).await
    }

    /// Like [`unregister_push`](Self::unregister_push), for an explicit mailbox hash
    /// (a linked device's device mailbox — see [`register_push_as`](Self::register_push_as)).
    pub async fn unregister_push_as(&self, account: &Account, hash: &str) -> Result<()> {
        let nonce = self.fetch_nonce(hash).await?;
        let msg = protocol_types::push_unregister_signing_message(hash, &nonce);
        let signature = account.ratchet_ref().sign(&msg);
        let resp = self
            .http
            .post(format!("{}/v1/push/unregister", self.base_url))
            .json(&json!({
                "hash": hash,
                "nonce": nonce,
                "signature": signature,
            }))
            .send()
            .await?;
        ensure_ok(resp).await
    }
}
