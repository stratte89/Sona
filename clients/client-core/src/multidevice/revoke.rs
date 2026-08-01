use super::*;

impl Client {
    /// Remove a device from our account: publish a roster epoch without it (revocation).
    /// The relay drops the device's mailbox directory record on publish, so its socket
    /// auth and any *new* inbound sessions stop at once; peers drop its session when they
    /// next resolve our roster. Only the primary can do this.
    pub async fn revoke_device(
        &self,
        account: &Account,
        history: &mut History,
        device_id: &str,
    ) -> Result<u64> {
        if device_id == PRIMARY_DEVICE_ID {
            return Err(ClientError::Protocol(
                "cannot revoke the primary device".into(),
            ));
        }
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();
        let prev = self
            .fetch_own_roster(&username_hash)
            .await?
            .ok_or_else(|| ClientError::Protocol("no roster to revoke from".into()))?;
        if !prev.devices.iter().any(|d| d.device_id == device_id) {
            return Err(ClientError::Protocol("no such device".into()));
        }
        let records: Vec<DeviceRecord> = prev
            .devices
            .into_iter()
            .filter(|d| d.device_id != device_id)
            .collect();
        let next_seq = prev.seq + 1;
        let roster = account.kt_roster_entry(next_seq, records.clone(), now());
        self.publish_roster(&roster).await?;

        let primary_key = account.ratchet_ref().identity_key();
        history.set_self_roster_seq(next_seq);
        let rdevices: Vec<RosterDevice> = records
            .iter()
            .map(|d| RosterDevice {
                device_id: d.device_id.clone(),
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
            })
            .collect();
        let bseq = history
            .pinned_roster(&username)
            .map(|p| p.binding_seq)
            .unwrap_or(0);
        let _ = history.pin_roster(&username, bseq, next_seq, &primary_key, rdevices);
        Ok(next_seq)
    }
    /// (Current primary) Offer to make `target_device_id` the account's primary. Sends
    /// the signed rotation + our demoted record E2E to that device and records the
    /// pending demotion; the caller should poll
    /// [`finish_primary_demotion`](Self::finish_primary_demotion). Returns the device id
    /// this device will hold after the transfer completes.
    pub async fn offer_primary_transfer(
        &self,
        account: &mut Account,
        history: &mut History,
        target_device_id: &str,
    ) -> Result<String> {
        if !history.is_primary_device() {
            return Err(ClientError::Protocol(
                "only the primary device can transfer primary ownership".into(),
            ));
        }
        if target_device_id == PRIMARY_DEVICE_ID {
            return Err(ClientError::Protocol(
                "target is already the primary".into(),
            ));
        }
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();

        // Current binding, verified — and it must actually be OUR keys (we are about to
        // authorize a rotation with them).
        let entry = self.fetch_verified_entry(&username_hash).await?;
        if entry.identity_key != account.ratchet_ref().identity_key()
            || entry.signing_key != account.ratchet_ref().signing_key()
        {
            return Err(ClientError::Protocol(
                "this device does not hold the KT-bound account keys".into(),
            ));
        }
        // The target's keys come from our own current roster — semantically validated
        // and rollback-checked, so a relay can't feed us a stale epoch to route the
        // primary role to a revoked device.
        let roster = self
            .fetch_own_roster(&username_hash)
            .await?
            .ok_or_else(|| ClientError::Protocol("no roster — link a device first".into()))?;
        if roster.validate_against(&entry).is_err() {
            return Err(ClientError::Protocol(
                "published roster is stale — try again shortly".into(),
            ));
        }
        if let Some(pinned) = history.pinned_roster(&username) {
            if roster.seq < pinned.seq {
                return Err(RosterRollback {
                    username,
                    pinned_seq: pinned.seq,
                    served_seq: roster.seq,
                }
                .into());
            }
        }
        let target = roster
            .devices
            .iter()
            .find(|d| d.device_id == target_device_id)
            .cloned()
            .ok_or_else(|| ClientError::Protocol("no such device".into()))?;

        // The rotation the target will publish: it chains from the current binding and
        // is useless to anyone not holding the target's private keys.
        let rotation = KtEntry::new_rotation(
            entry.seq + 1,
            username_hash.clone(),
            target.identity_key.clone(),
            target.signing_key.clone(),
            entry.signing_key.clone(),
            now(),
            false,
            |p| account.ratchet_ref().sign(p),
        );
        // Our post-transfer identity: the same keys under a fresh linked-device id,
        // proof-of-possession self-signed. Only the roster entry changes — sessions
        // peers hold to our identity key keep working across the transfer.
        let new_device_id = random_hex_id();
        let demoted = account.device_record(&username_hash, &new_device_id, now());

        let mailbox = self.device_mailbox_from_hash(&username_hash, target_device_id)?;
        self.ensure_device_session(account, &mailbox, &target.identity_key)
            .await?;
        let payload = ChatPayload::PrimaryTransfer {
            entry: rotation,
            demoted,
        };
        let env = seal_payload_to(
            account,
            &mailbox,
            &target.identity_key,
            &payload,
            &random_msg_id(),
        )?;
        self.post_envelope(&env).await?;

        history.set_pending_demotion(&new_device_id, target_device_id);
        Ok(new_device_id)
    }
    /// (Linked device) Accept a [`PrimaryTransferOffered`](crate::InboundEvent) offer:
    /// verify it promotes exactly this device, publish the rotation (with fresh one-time
    /// keys for the account mailbox we now own), publish the roster epoch naming us
    /// primary, and flip local state. Idempotent across partial failures — safe to
    /// retry until it returns `Ok`.
    ///
    /// The caller MUST have verified the offer's ratchet-authenticated sender is our own
    /// account's current primary, and gated this on the account password.
    pub async fn accept_primary_transfer(
        &self,
        account: &mut Account,
        history: &mut History,
        rotation: &KtEntry,
        demoted: &DeviceRecord,
    ) -> Result<u64> {
        if history.is_primary_device() {
            return Err(ClientError::Protocol(
                "this device is already the primary".into(),
            ));
        }
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();
        let my_idk = account.ratchet_ref().identity_key();
        let my_sgk = account.ratchet_ref().signing_key();
        let my_old_device_id = history.self_device_id();

        // The offer must promote exactly THIS device on THIS account and be
        // self-consistent — fail-closed before touching the network.
        if rotation.username_hash != username_hash
            || rotation.identity_key != my_idk
            || rotation.signing_key != my_sgk
            || !rotation.verify_signature()
        {
            return Err(ClientError::Protocol(
                "transfer offer does not promote this device".into(),
            ));
        }
        if demoted.device_id == PRIMARY_DEVICE_ID
            || !demoted.device_id_well_formed()
            || !demoted.verify(&username_hash)
        {
            return Err(ClientError::Protocol(
                "demoted device record invalid".into(),
            ));
        }

        let current = self.fetch_verified_entry(&username_hash).await?;
        let already_rotated = current.identity_key == my_idk && current.signing_key == my_sgk;

        // Our account's current full roster (signed records — we re-publish them).
        let prev = self
            .fetch_own_roster(&username_hash)
            .await?
            .ok_or_else(|| ClientError::Protocol("no roster to transfer within".into()))?;
        if let Some(pinned) = history.pinned_roster(&username) {
            if prev.seq < pinned.seq {
                return Err(RosterRollback {
                    username,
                    pinned_seq: pinned.seq,
                    served_seq: prev.seq,
                }
                .into());
            }
        }

        // Retry path: a previous run already published both the rotation and the
        // roster but died before persisting — just adopt the completed state.
        if already_rotated
            && prev
                .devices
                .iter()
                .any(|d| d.device_id == PRIMARY_DEVICE_ID && d.identity_key == my_idk)
        {
            self.adopt_primary_state(history, current.seq, &username, &my_idk, &prev);
            return Ok(prev.seq);
        }

        if !already_rotated {
            // The rotation must chain from the live binding, and the demoted record
            // must carry exactly the old primary's keys (a primary trying to smuggle a
            // *different* key in would break the PoP-vs-binding equality here).
            if rotation.prev_signing_key.as_deref() != Some(current.signing_key.as_str())
                || rotation.seq != current.seq + 1
            {
                return Err(ClientError::Protocol(
                    "transfer offer is stale — ask your primary to offer again".into(),
                ));
            }
            if demoted.identity_key != current.identity_key
                || demoted.signing_key != current.signing_key
                || !demoted.verify(&username_hash)
            {
                return Err(ClientError::Protocol(
                    "demoted device record invalid".into(),
                ));
            }
            if prev.validate_against(&current).is_err() {
                return Err(ClientError::Protocol(
                    "published roster is stale — try again shortly".into(),
                ));
            }
            // Publish the rotation, seeding the account-mailbox directory with our keys
            // and fresh one-time keys (the account mailbox is ours from here on).
            let one_time_keys = account.ratchet().generate_one_time_keys(20);
            let fallback_key = account.ratchet().generate_fallback_key();
            let resp = self
                .http
                .post(format!("{}/v1/register", self.base_url))
                .json(&serde_json::json!({
                    "entry": rotation,
                    "one_time_keys": one_time_keys,
                    "fallback_key": fallback_key,
                }))
                .send()
                .await?;
            crate::ensure_ok(resp).await?;
        }

        // Fresh roster epoch signed by us (now the account key): we become device "0",
        // the old primary keeps its keys under its demoted id, everyone else unchanged.
        let mut records = Vec::with_capacity(prev.devices.len());
        let mut replaced_self = false;
        let mut replaced_old_primary = false;
        for d in prev.devices {
            if d.device_id == my_old_device_id && d.identity_key == my_idk {
                records.push(account.device_record(&username_hash, PRIMARY_DEVICE_ID, now()));
                replaced_self = true;
            } else if d.device_id == PRIMARY_DEVICE_ID {
                records.push(demoted.clone());
                replaced_old_primary = true;
            } else {
                records.push(d);
            }
        }
        if !replaced_self || !replaced_old_primary {
            return Err(ClientError::Protocol(
                "roster no longer contains this device and the old primary".into(),
            ));
        }
        let next_seq = prev.seq + 1;
        let roster = account.kt_roster_entry(next_seq, records.clone(), now());
        self.publish_roster(&roster).await?;

        history.set_self_device(PRIMARY_DEVICE_ID, true);
        history.set_self_primary_key(&my_idk);
        history.set_self_roster_seq(next_seq);
        let rdevices: Vec<RosterDevice> = records
            .iter()
            .map(|d| RosterDevice {
                device_id: d.device_id.clone(),
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
            })
            .collect();
        let _ = history.pin_roster(&username, rotation.seq, next_seq, &my_idk, rdevices);
        Ok(next_seq)
    }
    pub(crate) fn adopt_primary_state(
        &self,
        history: &mut History,
        binding_seq: u64,
        username: &str,
        my_idk: &str,
        roster: &KtRosterEntry,
    ) {
        history.set_self_device(PRIMARY_DEVICE_ID, true);
        history.set_self_primary_key(my_idk);
        history.set_self_roster_seq(roster.seq);
        let rdevices: Vec<RosterDevice> = roster
            .devices
            .iter()
            .map(|d| RosterDevice {
                device_id: d.device_id.clone(),
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
            })
            .collect();
        let _ = history.pin_roster(username, binding_seq, roster.seq, my_idk, rdevices);
    }
    /// (Old primary) Check whether a pending primary transfer we offered has completed,
    /// and if so demote this device to its pre-minted linked identity. Returns `true`
    /// exactly once — when the demotion was applied (the caller must then re-subscribe
    /// on the new device mailbox and persist). `false` = still pending / nothing pending.
    ///
    /// This is a *poll*, not a notification: once the target publishes the rotation, the
    /// account mailbox (and its socket auth) belongs to the target, so nothing can be
    /// delivered to us until we move to our device mailbox.
    ///
    /// Callable with or without a recorded [`crate::history::PendingDemotion`]: the
    /// source of truth is the **KT log** (the binding moved away from our keys), never
    /// local state — a crash that lost the pending marker, or a second offer that
    /// overwrote it, must not wedge the device. Membership is matched by our identity
    /// key alone, which is sound: a roster record's proof-of-possession binds the device
    /// id and only this device can sign one for its key.
    pub async fn finish_primary_demotion(
        &self,
        account: &Account,
        history: &mut History,
    ) -> Result<bool> {
        let username = account.account_id().to_string();
        let username_hash = account.identity_hash().as_str().to_string();
        let entry = self.fetch_verified_entry(&username_hash).await?;
        if entry.identity_key == account.ratchet_ref().identity_key() {
            // We still hold the binding — the target hasn't accepted (yet). If the
            // offered target has since been revoked, the offer can never complete:
            // drop the stale pending marker so the caller stops polling for it.
            if let Some(p) = history.pending_demotion().cloned() {
                let target_gone = history.pinned_roster(&username).is_some_and(|pin| {
                    !pin.devices
                        .iter()
                        .any(|d| d.device_id == p.target_device_id)
                });
                if target_gone {
                    history.clear_pending_demotion();
                }
            }
            return Ok(false);
        }
        // The binding moved. Resolve the (verified, rollback-pinned) roster and find
        // ourselves under the linked-device record we pre-signed at offer time.
        let resolved = self.resolve_account_devices(history, &username).await?;
        let me = resolved
            .devices
            .iter()
            .find(|d| d.identity_key == account.ratchet_ref().identity_key())
            .cloned();
        match me {
            Some(d) => {
                history.set_self_device(&d.device_id, false);
                history.set_self_primary_key(&resolved.primary_key);
                if let Some(seq) = resolved.roster_seq {
                    history.set_self_roster_seq(seq);
                }
                history.clear_pending_demotion();
                Ok(true)
            }
            None => Err(ClientError::Protocol(
                "the account key rotated but this device is not in the new roster — \
                 it may have been removed from the account"
                    .into(),
            )),
        }
    }
    /// The relay claimed this device was revoked (a `revoked` frame / missing directory
    /// record). That claim is **server-asserted and unauthenticated** — verify it against
    /// the KT log before acting on it. A device whose mailbox died because it *moved*
    /// (promoted to primary, or demoted to a fresh linked id) is NOT revoked; local device
    /// state is fixed up here so the caller can simply re-subscribe.
    ///
    /// Fail-closed on verification/network errors (`Err`): the caller must treat those as
    /// inconclusive and retry — never as a confirmed revocation.
    pub async fn verify_device_revocation(
        &self,
        account: &Account,
        history: &mut History,
    ) -> Result<RevocationCheck> {
        let username = account.account_id().to_string();
        let my_idk = account.ratchet_ref().identity_key();
        // KT-verified binding + rollback-pinned roster; errors bubble (inconclusive).
        let resolved = self.resolve_account_devices(history, &username).await?;
        let me = resolved.devices.iter().find(|d| d.identity_key == my_idk);
        match me {
            Some(d) => {
                let is_primary = d.device_id == PRIMARY_DEVICE_ID;
                history.set_self_device(&d.device_id, is_primary);
                history.set_self_primary_key(&resolved.primary_key);
                if let Some(seq) = resolved.roster_seq {
                    history.set_self_roster_seq(seq);
                }
                history.set_revoked(false);
                Ok(RevocationCheck::StillActive)
            }
            None => Ok(RevocationCheck::Revoked),
        }
    }
}
