use super::*;

impl Client {
    /// Resolve an account's devices from its **KT-verified, anti-rollback-pinned** roster.
    ///
    /// Fail-closed security gate:
    /// * The current binding is fetched + verified (STH + inclusion) via
    ///   [`fetch_verified_entry`](Client::fetch_verified_entry).
    /// * If a roster exists, its Merkle inclusion is verified and it is validated against
    ///   that binding ([`KtRosterEntry::validate_against`]).
    /// * The epoch is **pinned monotonically**: a served epoch lower than the one we
    ///   pinned, or a roster that vanished after we pinned one (append-only rosters are
    ///   never deleted), returns [`ClientError::RosterRollback`] — the caller must abort.
    /// * A roster that fails semantic validation (e.g. stale, from before an account-key
    ///   rotation) is **ignored** and we fall back to single-device delivery to the current
    ///   KT-bound key — never to an unverified device list.
    pub async fn resolve_account_devices(
        &self,
        history: &mut History,
        username: &str,
    ) -> Result<ResolvedDevices> {
        let (resolved, update) = self.fetch_account_devices(username).await?;
        history.apply_roster_update(username, &update)?;
        Ok(resolved)
    }
    /// Prepare a delivery/read receipt addressed to the DEVICE that actually sent us the
    /// message, instead of to the account mailbox.
    ///
    /// [`contact_for`](crate::contact_for) addresses `IdentityHash::from_identifier(username)`
    /// — the account mailbox, which only the PRIMARY device drains. A receipt sealed to a
    /// **linked** device's key but posted there is undecryptable junk for the primary (which
    /// acks and drops it), and never reaches the device that sent the message: that sender
    /// sits on a single tick forever, while the primary logs a spurious "couldn't decrypt".
    ///
    /// Resolve the sender's device from the pinned roster — network-free, so this stays
    /// cheap enough for the delivery loop — and address its own mailbox. Falls back to the
    /// account mailbox when we have no roster; the primary needs no special case, since
    /// `device_mailbox_hash` maps `PRIMARY_DEVICE_ID` back to the account mailbox.
    pub fn prepare_receipt_to_sender(
        &self,
        account: &mut Account,
        history: &History,
        username: &str,
        sender_key: &str,
        ids: Vec<String>,
        seen: bool,
    ) -> Result<Option<Envelope>> {
        if ids.is_empty() {
            return Ok(None);
        }
        let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
        let mailbox = history
            .pinned_roster(username)
            .and_then(|pin| {
                pin.devices
                    .iter()
                    .find(|d| d.identity_key == sender_key)
                    .map(|d| d.device_id.clone())
            })
            .and_then(|device_id| device_mailbox_hash(&account_hash, &device_id))
            .map(|h| h.as_str().to_string())
            .unwrap_or(account_hash);
        seal_payload_to(
            account,
            &mailbox,
            sender_key,
            &ChatPayload::Receipt { ids, seen },
            &random_msg_id(),
        )
        .map(Some)
    }

    /// Drop our ratchet sessions with EVERY device of `username`, so the next message to
    /// them performs a fresh handshake instead of continuing a dead one.
    ///
    /// The cure for a desynced session. [`ensure_device_session`](Self::ensure_device_session)
    /// short-circuits on `has_session`, so once a session exists we reuse it forever — and a
    /// session the peer can no longer open is invisible to us (we keep encrypting; they get
    /// `NoSession` and silently drop). A non-prekey message carries no cleartext sender, so
    /// the peer cannot even tell us which session to reset: recovery must be unilateral
    /// here. See [`crypto_core::RatchetEngine::remove_sessions`].
    ///
    /// Resolves the roster so linked devices are covered too, but stays useful offline by
    /// falling back to the pinned roster and the caller's known key. Returns how many
    /// device sessions were dropped.
    pub async fn reset_sessions_with(
        &self,
        account: &mut Account,
        history: &mut History,
        username: &str,
        fallback_key: &str,
    ) -> Result<usize> {
        let mut keys: Vec<String> = Vec::new();
        // Live roster when the network allows; the pin otherwise. Both, deduped, so a
        // roster that drifted mid-rotation can't leave a stale session behind.
        if let Ok(rec) = self.resolve_account_devices(history, username).await {
            keys.extend(rec.devices.iter().map(|d| d.identity_key.clone()));
            keys.push(rec.primary_key);
        }
        if let Some(pin) = history.pinned_roster(username) {
            keys.extend(pin.devices.iter().map(|d| d.identity_key.clone()));
            keys.push(pin.primary_key.clone());
        }
        if !fallback_key.is_empty() {
            keys.push(fallback_key.to_string());
        }
        keys.sort();
        keys.dedup();
        let mut dropped = 0;
        for k in keys {
            if account.ratchet().remove_sessions(&k) {
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    /// Establish (if absent) a session to a specific device from the bundle at its mailbox,
    /// verifying the bundle's identity key equals the (roster-verified) `expected_key`.
    pub(crate) async fn ensure_device_session(
        &self,
        account: &mut Account,
        mailbox_hash: &str,
        expected_key: &str,
    ) -> Result<()> {
        if account.ratchet_ref().has_session(expected_key) {
            return Ok(());
        }
        let bundle = self.fetch_device_bundle(mailbox_hash, expected_key).await?;
        account
            .ratchet()
            .establish_outbound(&bundle)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        Ok(())
    }

    /// The network half of [`ensure_device_session`](Self::ensure_device_session): fetch
    /// one device's bundle and refuse it unless it carries the (roster-verified)
    /// `expected_key`. Touches no local state.
    pub(crate) async fn fetch_device_bundle(
        &self,
        mailbox_hash: &str,
        expected_key: &str,
    ) -> Result<protocol_types::PreKeyBundle> {
        let bundle: protocol_types::PreKeyBundle = self
            .http
            .get(format!("{}/v1/bundle/{mailbox_hash}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if bundle.identity_key != expected_key {
            return Err(ClientError::KtVerification(
                crypto_core::kt::KtCheck::KeyMismatch,
            ));
        }
        Ok(bundle)
    }
    /// Post a batch of prepared envelopes (each a distinct mailbox — order-independent).
    pub async fn post_envelopes(&self, envelopes: &[Envelope]) -> Result<()> {
        for result in self.post_envelopes_concurrent(envelopes).await {
            result?;
        }
        Ok(())
    }

    /// Post an already-prepared device fanout concurrently, with a fixed bound so one
    /// slow mailbox cannot serialize every sibling ring. Results preserve input order
    /// and every target is attempted even when another post fails.
    pub async fn post_envelopes_concurrent(&self, envelopes: &[Envelope]) -> Vec<Result<()>> {
        use futures_util::{stream, StreamExt};

        stream::iter(envelopes.iter().cloned())
            .map(|envelope| async move { self.post_envelope(&envelope).await })
            .buffered(8)
            .collect()
            .await
    }
    /// A device's mailbox hash. Errors only on a malformed username.
    pub fn device_mailbox(&self, username: &str, device_id: &str) -> Result<String> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        Ok(device_mailbox_hash(&hash, device_id)
            .ok_or_else(|| ClientError::Protocol("bad device mailbox".into()))?
            .as_str()
            .to_string())
    }
    /// Open a live subscription on this device's own mailbox. For the primary (or a legacy
    /// single device) that is the account mailbox — identical to [`Client::subscribe`].
    pub async fn subscribe_device(
        &self,
        account: &Account,
        username: &str,
        device_id: &str,
    ) -> Result<Subscription> {
        if device_id == PRIMARY_DEVICE_ID {
            return self.subscribe(account).await;
        }
        let mailbox = self.device_mailbox(username, device_id)?;
        self.subscribe_as(account, &mailbox).await
    }
    /// Replenish one-time keys for a **linked device's** mailbox (its directory record was
    /// created when the primary published the roster). Signed by this device's key.
    pub async fn replenish_device_keys(
        &self,
        account: &mut Account,
        username: &str,
        device_id: &str,
        target: usize,
    ) -> Result<usize> {
        let mailbox = self.device_mailbox(username, device_id)?;
        let status: Value = self
            .http
            .get(format!("{}/v1/keys/count/{mailbox}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // Coarse bucket, not an exact count — see `replenish_own_keys` (SP-10).
        if status["level"].as_str() == Some("plenty") {
            return Ok(0);
        }
        // Top up past the relay's watermark, not merely to `target` — a target at or
        // below the watermark would leave the level "low" and re-upload on every cycle.
        let need = target.max(status["low_watermark"].as_u64().unwrap_or(0) as usize + 1);
        let keys = account.ratchet().generate_one_time_keys(need);
        let msg = protocol_types::one_time_keys_signing_message(&mailbox, &keys);
        let signature = account.ratchet_ref().sign(&msg);
        let resp = self
            .http
            .post(format!("{}/v1/onetimekeys", self.base_url))
            .json(&serde_json::json!({
                "identity_hash": mailbox,
                "one_time_keys": keys,
                "signature": signature,
            }))
            .send()
            .await?;
        crate::ensure_ok(resp).await?;
        Ok(need)
    }
    /// (New device) Build the QR/link request: a fresh device id, a proof-of-possession
    /// record over the account username hash, and a link secret + provisioning id. The
    /// caller shows this to the primary and retains it for [`complete_link`](Self::complete_link).
    /// `account` is this device's freshly created account whose `account_id` is the username.
    pub fn create_link_request(&self, account: &Account) -> LinkRequest {
        let username_hash = account.identity_hash().as_str().to_string();
        let device_id = random_hex_id();
        let record = account.device_record(&username_hash, &device_id, now());
        let link_secret = csync::generate_link_secret();
        LinkRequest {
            device_id,
            record,
            link_secret_b64: csync::link_secret_b64(&link_secret),
            provisioning_id: random_hex_id(),
            // The shell attaches this where the platform can attest (Android): the
            // Keystore call needs JNI, which this crate's pure-Rust path can't reach —
            // see `attach_link_attestation`.
            attest_id: None,
        }
    }

    /// (New device, optional) Upload a hardware-attestation chain for this link request:
    /// seal it under the link secret, PUT it at a fresh capability id, and record that id
    /// on the request. Must run BEFORE the QR is shown — the id travels inside it.
    /// The chain (base64 DER, leaf first) must attest a key whose challenge is
    /// [`attest::link_attest_challenge`](crate::attest::link_attest_challenge) over
    /// (`device_id`, `record.identity_key`).
    pub async fn attach_link_attestation(
        &self,
        req: &mut LinkRequest,
        chain_b64: &[String],
    ) -> Result<()> {
        let link_secret = csync::link_secret_from_b64(&req.link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;
        let body = serde_json::json!({ "t": "hw_attest", "chain": chain_b64 });
        let blob = csync::seal_provisioning(
            &link_secret,
            &serde_json::to_vec(&body).expect("chain serializes"),
        )
        .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let id = random_hex_id();
        let resp = self
            .http
            .put(format!("{}/v1/sync/{id}", self.base_url))
            .body(blob)
            .send()
            .await?;
        crate::ensure_ok(resp).await?;
        req.attest_id = Some(id);
        Ok(())
    }

    /// (Primary) Fetch + unseal the attestation chain a scanned request points at.
    /// `Ok(None)` when the request carries no attestation (desktop/older linkers);
    /// errors when one is promised but missing/expired or fails to unseal — the UI
    /// should surface that as "couldn't check", not as "no attestation".
    pub async fn fetch_link_attestation(&self, req: &LinkRequest) -> Result<Option<Vec<String>>> {
        let Some(id) = &req.attest_id else {
            return Ok(None);
        };
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ClientError::Protocol("malformed attestation id".into()));
        }
        let link_secret = csync::link_secret_from_b64(&req.link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;
        let resp = self
            .http
            .get(format!("{}/v1/sync/{id}", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(ClientError::Status(resp.status().as_u16()));
        }
        // The attest_id in a scanned QR is attacker-controlled: it may point at any
        // capability blob (the sync store accepts up to 32 MiB for history transfers).
        // A real chain is a few KB, which seals into exactly one 64 KiB padding bucket
        // (+ header/nonce/tag) — refuse anything larger before buffering it.
        const MAX_ATTEST_BLOB: usize = 128 * 1024;
        if resp
            .content_length()
            .is_some_and(|l| l > MAX_ATTEST_BLOB as u64)
        {
            return Err(ClientError::Protocol("attestation blob too large".into()));
        }
        let blob = resp.bytes().await?;
        if blob.len() > MAX_ATTEST_BLOB {
            return Err(ClientError::Protocol("attestation blob too large".into()));
        }
        let plain = csync::open_provisioning(&link_secret, &blob)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let v: serde_json::Value = serde_json::from_slice(&plain)
            .map_err(|_| ClientError::Protocol("bad attestation blob".into()))?;
        if v["t"] != "hw_attest" {
            return Err(ClientError::Protocol("bad attestation blob".into()));
        }
        let chain: Vec<String> = serde_json::from_value(v["chain"].clone())
            .map_err(|_| ClientError::Protocol("bad attestation blob".into()))?;
        Ok(Some(chain))
    }

    /// (Primary) Verify a fetched attestation chain against THIS link request's expected
    /// challenge. Pure wrapper over [`attest::verify_hw_attestation`] so shells don't
    /// re-derive the challenge binding.
    pub fn verify_link_attestation(
        req: &LinkRequest,
        chain_b64: &[String],
    ) -> std::result::Result<crate::attest::HwAttestation, crate::attest::AttestError> {
        let challenge =
            crate::attest::link_attest_challenge(&req.device_id, &req.record.identity_key);
        crate::attest::verify_hw_attestation(chain_b64, &challenge)
    }
    /// (Primary device) Authorize a scanned [`LinkRequest`]: publish a new roster epoch
    /// enrolling the device, seal + upload the current history under the account password
    /// and the link secret, and PUT the provisioning blob for the new device to fetch.
    ///
    /// `password` is the **account** password/PIN gating history sync (the user enters it
    /// to authorize). Returns the new roster epoch.
    pub async fn authorize_link(
        &self,
        account: &Account,
        history: &mut History,
        req: &LinkRequest,
        password: &str,
    ) -> Result<u64> {
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();
        // No plaintext username travels in the request (an intercepted code must not reveal
        // who is linking). We don't need one to bind the account: the device record's
        // proof-of-possession is signed over THIS account's username hash, so a request made
        // for any other account fails `req.record.verify(&username_hash)` below.
        if req.device_id == PRIMARY_DEVICE_ID || !req.record.device_id_well_formed() {
            return Err(ClientError::Protocol("malformed device id".into()));
        }
        if req.record.device_id != req.device_id || !req.record.verify(&username_hash) {
            return Err(ClientError::Protocol(
                "device proof-of-possession invalid".into(),
            ));
        }
        let link_secret = csync::link_secret_from_b64(&req.link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;

        // Fetch our current full roster (need the existing devices' signed records to
        // re-publish); build the next epoch = existing devices + the new one.
        let (mut records, next_seq) = match self.fetch_own_roster(&username_hash).await? {
            Some(prev) => {
                let seq = prev.seq + 1;
                (prev.devices, seq)
            }
            None => (
                vec![account.device_record(&username_hash, PRIMARY_DEVICE_ID, now())],
                0,
            ),
        };
        if records.iter().any(|d| d.device_id == req.record.device_id) {
            return Err(ClientError::Protocol("device already linked".into()));
        }
        if records.len() + 1 > MAX_DEVICES {
            return Err(ClientError::Protocol("device limit reached".into()));
        }
        records.push(req.record.clone());
        let roster = account.kt_roster_entry(next_seq, records.clone(), now());
        self.publish_roster(&roster).await?;

        // Update our own multi-device state.
        let primary_key = account.ratchet_ref().identity_key();
        history.set_self_device(PRIMARY_DEVICE_ID, true);
        history.set_self_primary_key(&primary_key);
        history.set_self_roster_seq(next_seq);
        let rdevices: Vec<RosterDevice> = records
            .iter()
            .map(|d| RosterDevice {
                device_id: d.device_id.clone(),
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
            })
            .collect();
        // pin_roster is monotonic; our own publish never rolls back. The binding did
        // not change here — carry its pinned position forward.
        let bseq = history
            .pinned_roster(&username)
            .map(|p| p.binding_seq)
            .unwrap_or(0);
        let _ = history.pin_roster(&username, bseq, next_seq, &primary_key, rdevices);

        // Seal + upload history, then PUT the provisioning pointer under the link secret.
        let history_sync_id = self.export_history(history, password, &link_secret).await?;
        let prov = Provisioning {
            username: username.clone(),
            history_sync_id,
            primary_key,
        };
        let prov_json = serde_json::to_vec(&prov).expect("Provisioning serializes");
        let prov_blob = csync::seal_provisioning(&link_secret, &prov_json)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let resp = self
            .http
            .put(format!("{}/v1/sync/{}", self.base_url, req.provisioning_id))
            .body(prov_blob)
            .send()
            .await?;
        crate::ensure_ok(resp).await?;
        Ok(next_seq)
    }
    /// (New device) Complete linking after the primary authorized us: fetch the
    /// provisioning pointer + sealed history (decrypting with the account password/PIN +
    /// the link secret), import history, register our one-time keys on our device mailbox,
    /// and pin our own roster. `account` is this device's account (username already set).
    ///
    /// Returns the imported [`History`] (with this device's identity set). The `req` is the
    /// [`LinkRequest`] this device generated. Handles the "primary offline / blob not yet
    /// uploaded" case as a plain 404 the caller can retry.
    pub async fn complete_link(
        &self,
        account: &mut Account,
        req: &LinkRequest,
        password: &str,
    ) -> Result<LinkResult> {
        let link_secret = csync::link_secret_from_b64(&req.link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;

        // Provisioning pointer (404 = primary hasn't finished authorizing yet — retry).
        let resp = self
            .http
            .get(format!("{}/v1/sync/{}", self.base_url, req.provisioning_id))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Err(ClientError::Status(404));
        }
        let prov_blob = resp.error_for_status()?.bytes().await?;
        let prov_json = csync::open_provisioning(&link_secret, &prov_blob)
            .map_err(|_| ClientError::Crypto("provisioning decrypt failed".into()))?;
        let prov: Provisioning =
            serde_json::from_slice(&prov_json).map_err(|e| ClientError::Protocol(e.to_string()))?;

        // Sealed history (404 = expired past TTL — caller should request a re-export).
        let mut history = History::new();
        let hist_resp = self
            .http
            .get(format!(
                "{}/v1/sync/{}",
                self.base_url, prov.history_sync_id
            ))
            .send()
            .await?;
        let mut history_synced = false;
        if hist_resp.status().as_u16() != 404 {
            let hist_blob = hist_resp.error_for_status()?.bytes().await?;
            match csync::open_history(password, &link_secret, &hist_blob) {
                Ok(plain) => {
                    if let Some(imported) = History::import_plaintext(&plain) {
                        history.merge_from(&imported);
                    }
                    history_synced = true;
                }
                Err(_) => {
                    // Wrong password/PIN — surface clearly so the UI can re-prompt.
                    return Err(ClientError::Crypto(
                        "history decrypt failed (wrong password/PIN)".into(),
                    ));
                }
            }
        }

        // This device's identity + attribution. Pin our own roster so is_own_device works.
        history.set_self_device(&req.device_id, false);
        history.set_self_primary_key(&prov.primary_key);
        let _ = self
            .resolve_account_devices(&mut history, &prov.username)
            .await?;

        // Publish our one-time keys on our device mailbox so senders can reach us.
        self.replenish_device_keys(account, &prov.username, &req.device_id, 20)
            .await?;

        // Establish a session to the PRIMARY and send a no-op hello, so the primary gains a
        // session to us and can immediately forward legacy-sender messages (see
        // [`forward_inbound_sync`](Self::forward_inbound_sync)) without a network fetch.
        let primary_mailbox = IdentityHash::from_identifier(&prov.username)
            .as_str()
            .to_string();
        if self
            .ensure_device_session(account, &primary_mailbox, &prov.primary_key)
            .await
            .is_ok()
        {
            let hello = ChatPayload::SelfSeen {
                peer_key: String::new(),
                ids: Vec::new(),
            };
            if let Ok(env) = seal_payload_to(
                account,
                &primary_mailbox,
                &prov.primary_key,
                &hello,
                &random_msg_id(),
            ) {
                let _ = self.post_envelope(&env).await;
            }
        }
        Ok(LinkResult {
            history,
            history_synced,
        })
    }
    pub(crate) fn device_mailbox_from_hash(
        &self,
        username_hash: &str,
        device_id: &str,
    ) -> Result<String> {
        Ok(device_mailbox_hash(username_hash, device_id)
            .ok_or_else(|| ClientError::Protocol("bad device mailbox".into()))?
            .as_str()
            .to_string())
    }
}
