use crate::*;
use kt_log::CallKeyBinding;

/// This device's call-control mailbox, for the reply route a locked peer answers on.
/// Re-exported here so a shell does not have to depend on `protocol_types` directly.
pub fn call_mailbox_for(account_hash: &str, device_id: &str) -> Option<String> {
    protocol_types::call_mailbox_hash(account_hash, device_id).map(|hash| hash.as_str().to_string())
}

/// Most capsules one drain takes. Far above what any real call produces (an offer and a
/// terminal per device), and low enough that a flooded mailbox cannot be pulled into a
/// woken phone's memory in one go.
const MAX_CAPSULES_PER_DRAIN: usize = 64;

/// What one call-control mailbox drain actually did.
///
/// The capsule layer is the only delivery path a locked device has, and every way it can
/// come back empty used to look identical from the outside: an empty mailbox, a capsule
/// that would not decode, and a capsule refused by screening all produced the same
/// `Vec::new()`. Four rounds of physical-device testing were spent distinguishing those
/// (`internal/NOTES.md` §"Second device matrix", E-9), so the drain now says which happened.
///
/// Counts only, deliberately. This crate is a library and does no logging; the shell
/// decides what to record, and there is nothing here it could leak — no call id, no
/// username, no key material.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleDrainStats {
    /// Envelopes taken from the mailbox. Every one of them is already acknowledged to the
    /// relay by the time this is returned, which is exactly what E-13 is about.
    pub fetched: usize,
    /// Of those, the ones whose bytes were a well-formed capsule for this device.
    pub decoded: usize,
    /// Refused because no signing key could be placed for the capsule's signer — an
    /// unknown or blocked caller, or (the fault E-1 chased) a screening index that is
    /// empty or stale, which refuses *everyone*.
    pub refused_unplaceable: usize,
    /// Refused because the signature did not verify under the key we did place, or the
    /// capsule was not addressed to this device, or it had expired.
    pub refused_signature: usize,
}

impl CapsuleDrainStats {
    /// Capsules that survived both filters and are being acted on.
    pub fn accepted(&self) -> usize {
        self.decoded
            .saturating_sub(self.refused_unplaceable)
            .saturating_sub(self.refused_signature)
    }

    /// Did this drain throw away everything it took? The shape that produced a ring with
    /// no call state behind it, and the one worth a log line every time.
    pub fn dropped_everything(&self) -> bool {
        self.fetched > 0 && self.accepted() == 0
    }
}

/// One sealed-and-addressed capsule, ready to post. Prepared with a shell's session lock
/// held (minting and signing are local) and posted with it released.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CapsuleDelivery {
    /// The recipient account. With `binding.device_id`, it names the call-control mailbox.
    pub username: String,
    pub binding: CallKeyBinding,
    /// The encoded [`CallCapsule`](crate::callcapsule::CallCapsule); sealed to the
    /// binding's key at post time.
    pub plaintext: Vec<u8>,
    /// A fresh offer earns the ring wake; a terminal the urgent silent one.
    pub ring: bool,
    pub expires_at: u64,
}

/// The local half of [`Client::fetch_verified_call_key`]: check a fetched binding against
/// the **pinned, KT-verified roster** for `username`. Fail-closed at every step:
///
/// * a binding for a device that is not on the pinned roster, signed by the wrong device,
///   replayed from another account, or with a malformed key → `None`;
/// * a binding whose key is not a usable Curve25519 point → `None`.
///
/// `None` simply means "no capsule for this device" — the ordinary encrypted offer still
/// rings it once its vault is open.
pub fn verified_call_key_binding(
    pin: &crate::history::RosterPin,
    username: &str,
    device_id: &str,
    binding: CallKeyBinding,
) -> Option<CallKeyBinding> {
    let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
    if binding.device_id != device_id || !crypto_core::callkey::valid_call_key(&binding.call_key) {
        return None;
    }
    // The pin holds the device set we KT-verified; rebuild the roster shape the binding is
    // checked against from it, so a relay cannot serve a roster of its own choosing
    // alongside a matching binding.
    let roster = kt_log::KtRosterEntry {
        seq: pin.seq,
        username_hash: account_hash.clone(),
        devices: pin
            .devices
            .iter()
            .map(|device| kt_log::DeviceRecord {
                device_id: device.device_id.clone(),
                identity_key: device.identity_key.clone(),
                signing_key: device.signing_key.clone(),
                added_at: 0,
                signature: String::new(),
            })
            .collect(),
        timestamp: 0,
        signature: String::new(),
    };
    binding.verify(&account_hash, &roster).then_some(binding)
}

impl Client {
    /// Publish this device's **call-control key** so peers can seal incoming-call
    /// capsules to it.
    ///
    /// The binding is signed twice over, by design: by this device's roster Ed25519 key
    /// (inside [`CallKeyBinding`], which is what a *fetcher* verifies against the
    /// KT-verified roster) and again over a single-use relay challenge (which is what
    /// stops anyone else from writing this mailbox's shelf). `mailbox_hash` is this
    /// device's mailbox — the account hash for a primary, the device mailbox for a
    /// linked device — because that is the directory record holding our signing key.
    pub async fn publish_call_key(
        &self,
        account: &Account,
        mailbox_hash: &str,
        device_id: &str,
        call_key: &crypto_core::CallKey,
        created_at: u64,
    ) -> Result<CallKeyBinding> {
        let nonce = self.call_key_nonce(mailbox_hash).await?;
        let (binding, signature) = self.prepare_call_key_publication(
            account,
            mailbox_hash,
            device_id,
            call_key,
            created_at,
            &nonce,
        );
        self.post_call_key_publication(
            account.identity_hash().as_str(),
            mailbox_hash,
            &nonce,
            &binding,
            &signature,
        )
        .await?;
        Ok(binding)
    }

    /// A single-use publication challenge for `mailbox_hash`. Network only — a shell
    /// that must not hold its session lock across the relay calls this first.
    pub async fn call_key_nonce(&self, mailbox_hash: &str) -> Result<String> {
        self.fetch_nonce(mailbox_hash).await
    }

    /// Sign a call-key publication: the device-signed binding a fetcher verifies, plus
    /// the challenge signature that authorizes writing this mailbox's shelf. Local only
    /// (the account is borrowed just to sign), so it fits inside a short lock.
    pub fn prepare_call_key_publication(
        &self,
        account: &Account,
        mailbox_hash: &str,
        device_id: &str,
        call_key: &crypto_core::CallKey,
        created_at: u64,
        nonce: &str,
    ) -> (CallKeyBinding, String) {
        let username_hash = account.identity_hash().as_str().to_string();
        let public = call_key.public_b64();
        let binding = CallKeyBinding::new(
            &username_hash,
            device_id.to_string(),
            public.clone(),
            call_key.signing_key_b64(),
            created_at,
            |payload| account.ratchet_ref().sign(payload),
        );
        let msg = protocol_types::call_key_publish_signing_message(
            mailbox_hash,
            &public,
            created_at,
            nonce,
        );
        let signature = account.ratchet_ref().sign(&msg);
        (binding, signature)
    }

    /// Post an already-signed publication. Network only.
    /// `account_hash` is the account's username hash: the relay checks it against the
    /// mailbox and device id (so a device cannot publish into another account) and derives
    /// the call-control mailbox from it.
    pub async fn post_call_key_publication(
        &self,
        account_hash: &str,
        mailbox_hash: &str,
        nonce: &str,
        binding: &CallKeyBinding,
        signature: &str,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/v1/callkey", self.base_url))
            .json(&json!({
                "hash": mailbox_hash,
                "account_hash": account_hash,
                "nonce": nonce,
                "signature": signature,
                "binding": binding,
            }))
            .send()
            .await?;
        ensure_ok(resp).await
    }

    /// Fetch a device's published call-control binding, **verified against the pinned,
    /// KT-verified roster** for `username`. Fail-closed at every step:
    ///
    /// * no pinned roster for that account → `None` (we have not verified their devices,
    ///   so we cannot trust any call key for them);
    /// * a binding for a device that is not on the pinned roster, signed by the wrong
    ///   device, replayed from another account, or with a malformed key → `None`;
    /// * a binding whose key is not a usable Curve25519 point → `None`.
    ///
    /// `None` simply means "no capsule for this device" — the ordinary encrypted offer
    /// still rings it once its vault is open.
    pub async fn fetch_verified_call_key(
        &self,
        history: &History,
        username: &str,
        device_id: &str,
    ) -> Option<CallKeyBinding> {
        let pin = history.pinned_roster(username)?.clone();
        let binding = self.fetch_device_call_key(username, device_id).await?;
        verified_call_key_binding(&pin, username, device_id, binding)
    }

    /// The network half of [`fetch_verified_call_key`](Self::fetch_verified_call_key):
    /// whatever the relay holds on that device's shelf, still unverified. Split out so a
    /// shell can fetch with its session lock released and verify against the pin
    /// afterwards (see [`verified_call_key_binding`]).
    pub async fn fetch_device_call_key(
        &self,
        username: &str,
        device_id: &str,
    ) -> Option<CallKeyBinding> {
        let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
        let mailbox = self
            .device_mailbox_from_hash(&account_hash, device_id)
            .ok()?;
        self.fetch_call_key(&mailbox).await.ok()?
    }

    /// [`fetch_device_call_key`](Self::fetch_device_call_key) for a whole roster, run
    /// concurrently and returned in input order. One device's missing or unreachable
    /// shelf never delays the others.
    pub async fn fetch_device_call_keys(
        &self,
        username: &str,
        device_ids: &[String],
    ) -> Vec<Option<CallKeyBinding>> {
        use futures_util::{stream, StreamExt};

        stream::iter(device_ids.iter().cloned())
            .map(|device_id| async move { self.fetch_device_call_key(username, &device_id).await })
            .buffered(8)
            .collect()
            .await
    }

    /// Raw fetch of whatever the relay has on a mailbox's call-key shelf. Unverified —
    /// use [`fetch_verified_call_key`](Self::fetch_verified_call_key).
    async fn fetch_call_key(&self, mailbox_hash: &str) -> Result<Option<CallKeyBinding>> {
        let resp = self
            .http
            .get(format!("{}/v1/callkey/{mailbox_hash}", self.base_url))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json().await?))
    }
}

impl Client {
    /// Seal and deliver a [`CallCapsule`](crate::callcapsule::CallCapsule) to one
    /// device's call-control mailbox, signed by this device's roster key.
    ///
    /// The capsule rides *alongside* the ordinary encrypted offer, never instead of it:
    /// both name the same `call_instance_id`, so a device that gets both rings once, and
    /// a device whose vault is locked still gets this one.
    pub async fn send_call_capsule(
        &self,
        account: &Account,
        username: &str,
        binding: &CallKeyBinding,
        plan: crate::callcapsule::CapsulePlan,
    ) -> Result<crate::callcapsule::CallCapsule> {
        let ring = matches!(plan.kind, crate::callcapsule::CapsuleKind::Offer);
        let expires_at = plan.expires_at;
        let capsule = crate::callcapsule::CallCapsule::new(plan, |payload| {
            account.ratchet_ref().sign(payload)
        });
        if !capsule.well_formed() {
            return Err(ClientError::Protocol("malformed call capsule".into()));
        }
        self.post_call_capsule(username, binding, &capsule.encode(), ring, expires_at)
            .await?;
        Ok(capsule)
    }

    /// Post a prepared batch of capsules concurrently, attempting every target even when
    /// one fails, and returning results in input order.
    pub async fn post_call_capsules_concurrent(
        &self,
        capsules: &[CapsuleDelivery],
    ) -> Vec<Result<()>> {
        use futures_util::{stream, StreamExt};

        stream::iter(capsules.iter().cloned())
            .map(|capsule| async move {
                self.post_call_capsule(
                    &capsule.username,
                    &capsule.binding,
                    &capsule.plaintext,
                    capsule.ring,
                    capsule.expires_at,
                )
                .await
            })
            .buffered(8)
            .collect()
            .await
    }

    /// Drain this device's call-control mailbox and return only the capsules that are
    /// **for this device, fresh, and signed by a caller we can place**.
    ///
    /// `signing_key_for` maps a capsule to the key its signature must verify under — the
    /// pinned KT roster when unlocked, the approved-caller screening index when locked,
    /// and for a capsule signed by a locked sender, that device's published call-control
    /// key. It takes the whole capsule rather than a name pair because
    /// [`CapsuleSigner`](crate::callcapsule::CapsuleSigner) decides *which* key applies.
    /// Returning `None` refuses the capsule, which is what makes an unknown or blocked
    /// caller unable to ring the device.
    pub async fn drain_verified_capsules(
        &self,
        call_key: &crypto_core::CallKey,
        username: &str,
        device_id: &str,
        now: u64,
        signing_key_for: impl Fn(&crate::callcapsule::CallCapsule) -> Option<String>,
    ) -> Result<(Vec<crate::callcapsule::CallCapsule>, CapsuleDrainStats)> {
        let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
        self.drain_verified_capsules_by_hash(
            call_key,
            &account_hash,
            device_id,
            now,
            signing_key_for,
        )
        .await
    }

    /// [`drain_verified_capsules`](Self::drain_verified_capsules) addressed by account
    /// **hash** rather than username — the form a locked device uses, because the hash is
    /// what its call-control store carries and the username is sealed in the vault.
    pub async fn drain_verified_capsules_by_hash(
        &self,
        call_key: &crypto_core::CallKey,
        account_hash: &str,
        device_id: &str,
        now: u64,
        signing_key_for: impl Fn(&crate::callcapsule::CallCapsule) -> Option<String>,
    ) -> Result<(Vec<crate::callcapsule::CallCapsule>, CapsuleDrainStats)> {
        let raw = self
            .drain_call_mailbox_by_hash(call_key, account_hash, device_id)
            .await?;
        let mut stats = CapsuleDrainStats {
            fetched: raw.len(),
            ..Default::default()
        };
        let mut kept = Vec::with_capacity(raw.len());
        for bytes in raw {
            // Each filter is counted separately rather than chained, because "the mailbox
            // was empty", "the bytes were not a capsule" and "the signer could not be
            // placed" are three different faults with three different fixes, and they were
            // indistinguishable for the whole of the first two device matrices.
            let Some(capsule) = crate::callcapsule::CallCapsule::decode(&bytes) else {
                continue; // not counted in `decoded`: it never was a capsule
            };
            stats.decoded += 1;
            let Some(key) = signing_key_for(&capsule) else {
                stats.refused_unplaceable += 1;
                continue;
            };
            if !capsule.verify(device_id, &key, now) {
                stats.refused_signature += 1;
                continue;
            }
            kept.push(capsule);
        }
        Ok((kept, stats))
    }

    /// Deliver a capsule to a call-control mailbox named **directly**, rather than derived
    /// from an account name and a fetched binding.
    ///
    /// This is the reply route a **locked** device uses: the mailbox and the key both came
    /// out of the authenticated offer capsule it is answering, so it needs neither the
    /// account name (sealed in the vault) nor a relay fetch it could not verify. Nothing
    /// here is trusted for anything else — the recipient still checks the signature.
    pub async fn post_call_capsule_to(
        &self,
        call_mailbox: &str,
        call_key_b64: &str,
        plaintext: &[u8],
        expires_at: u64,
    ) -> Result<()> {
        let capsule = crypto_core::callkey::seal_capsule(call_key_b64, plaintext)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let envelope = Envelope {
            to: IdentityHash::from_hex(call_mailbox)
                .ok_or_else(|| ClientError::Protocol("bad call mailbox".into()))?,
            ciphertext: STANDARD_NO_PAD.encode(&capsule),
            kind: protocol_types::PayloadKind::CallCapsule,
            msg_id: random_msg_id(),
            expires_at: Some(expires_at),
            // A decline must stop a ring that is sounding right now: urgent, silent.
            wake: protocol_types::WakeClass::CallControl,
            raw_identifier: None,
        };
        self.post_envelope(&envelope).await
    }

    /// Deliver an opaque call capsule to one device's **call-control mailbox**.
    ///
    /// The capsule is sealed to that device's published call key, so the relay carries
    /// bytes it cannot read, addressed to a mailbox that is deliberately not the device's
    /// message mailbox. `ring` picks the wake class: a fresh offer earns the immediate
    /// ring wake, a cancellation/terminal the urgent silent one.
    pub async fn post_call_capsule(
        &self,
        username: &str,
        binding: &CallKeyBinding,
        plaintext: &[u8],
        ring: bool,
        expires_at: u64,
    ) -> Result<()> {
        let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
        let mailbox = protocol_types::call_mailbox_hash(&account_hash, &binding.device_id)
            .ok_or_else(|| ClientError::Protocol("bad call mailbox".into()))?;
        let capsule = crypto_core::callkey::seal_capsule(&binding.call_key, plaintext)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let envelope = Envelope {
            to: mailbox,
            ciphertext: STANDARD_NO_PAD.encode(&capsule),
            kind: protocol_types::PayloadKind::CallCapsule,
            msg_id: random_msg_id(),
            expires_at: Some(expires_at),
            wake: if ring {
                protocol_types::WakeClass::Call
            } else {
                protocol_types::WakeClass::CallControl
            },
            raw_identifier: None,
        };
        self.post_envelope(&envelope).await
    }

    /// Drain this device's call-control mailbox with the **call-control key alone** — no
    /// account, no vault. Returns the plaintext of every capsule that opened, oldest
    /// first, and acks each one out of the mailbox.
    ///
    /// A capsule that does not open (someone else's, corrupted, or sealed to a key we
    /// have rotated away from) is acked and dropped: leaving it would let one bad
    /// envelope wedge the mailbox behind it forever.
    pub async fn drain_call_mailbox(
        &self,
        call_key: &crypto_core::CallKey,
        username: &str,
        device_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let account_hash = IdentityHash::from_identifier(username).as_str().to_string();
        self.drain_call_mailbox_by_hash(call_key, &account_hash, device_id)
            .await
    }

    /// [`drain_call_mailbox`](Self::drain_call_mailbox) addressed by account hash. This is
    /// the whole reason the call-control store carries the hash: with the chat vault
    /// locked there is no account to derive it from, and without it the device cannot even
    /// find the mailbox its own capsules are waiting in.
    pub async fn drain_call_mailbox_by_hash(
        &self,
        call_key: &crypto_core::CallKey,
        account_hash: &str,
        device_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        use futures_util::{SinkExt, StreamExt};
        let mailbox = protocol_types::call_mailbox_hash(account_hash, device_id)
            .ok_or_else(|| ClientError::Protocol("bad call mailbox".into()))?
            .as_str()
            .to_string();
        let mut ws = self
            .open_authed_socket_signed(&mailbox, |nonce| call_key.sign(nonce))
            .await?;
        let mut out = Vec::new();
        let mut taken = 0usize;
        while let Some(frame) = ws.next().await {
            let tokio_tungstenite::tungstenite::Message::Text(text) =
                frame.map_err(|e| ClientError::Ws(e.to_string()))?
            else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            match value["type"].as_str() {
                Some("ready") => break,
                Some("auth_failed") => return Err(ClientError::AuthRejected),
                Some("revoked") => return Err(ClientError::DeviceRevoked),
                Some("message") => {}
                _ => continue,
            }
            let Ok(envelope) = serde_json::from_value::<Envelope>(value["envelope"].clone()) else {
                continue;
            };
            if envelope.kind == protocol_types::PayloadKind::CallCapsule {
                if let Some(plain) = STANDARD_NO_PAD
                    .decode(&envelope.ciphertext)
                    .ok()
                    .and_then(|capsule| call_key.open_capsule(&capsule))
                {
                    out.push(plain);
                }
            }
            let ack = json!({ "type": "ack", "msg_id": envelope.msg_id });
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                ack.to_string(),
            ))
            .await
            .map_err(|e| ClientError::Ws(e.to_string()))?;
            // Bounded per drain: a flooded mailbox must not be pulled into memory whole on
            // a phone that woke for one ring. Everything taken here is acked, so the next
            // wake continues where this one stopped.
            taken += 1;
            if taken >= MAX_CAPSULES_PER_DRAIN {
                break;
            }
        }
        let _ = ws.close(None).await;
        Ok(out)
    }
}
