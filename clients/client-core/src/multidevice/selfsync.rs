use super::*;

impl Client {
    /// Prepare a fan-out of a text message to `contact` across all its devices, plus a
    /// self-sync copy to the sender's own other devices. Establishes any missing sessions
    /// (roster-verified). The returned [`Fanout`] is not yet posted.
    pub async fn prepare_text_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        text: &str,
        reply: Option<ReplyRef>,
        forwarded: bool,
    ) -> Result<Fanout> {
        let my_username = account.account_id().to_string();
        let ts = now();
        // Carry the conversation's timer INSIDE every copy (Some(0) = off), so a copy
        // that outruns the Timer control message still expires exactly on time.
        let expire = Some(history.timer(&contact.identity_key).unwrap_or(0));
        let recipient_payload = ChatPayload::Text {
            body: text.to_string(),
            ts,
            from: my_username.clone(),
            reply: reply.clone(),
            expire_secs: expire,
            fwd: forwarded,
        };
        let self_of =
            |peer_key: String, peer_username: String, msg_id: String| ChatPayload::SelfText {
                peer_key,
                peer_username,
                msg_id,
                body: text.to_string(),
                ts,
                reply: reply.clone(),
                expire_secs: expire,
                fwd: forwarded,
            };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            Some(ts),
        )
        .await
    }
    /// Prepare a fan-out of an attachment reference across a contact's devices, with a
    /// self-sync copy to the sender's own devices.
    pub async fn prepare_attachment_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        attachment: AttachmentRef,
        forwarded: bool,
    ) -> Result<Fanout> {
        let my_username = account.account_id().to_string();
        let expire = Some(history.timer(&contact.identity_key).unwrap_or(0));
        let recipient_payload = ChatPayload::File {
            attachment: attachment.clone(),
            from: my_username,
            expire_secs: expire,
            fwd: forwarded,
        };
        let att = attachment.clone();
        let self_of =
            |peer_key: String, peer_username: String, msg_id: String| ChatPayload::SelfFile {
                peer_key,
                peer_username,
                msg_id,
                attachment: att.clone(),
                expire_secs: expire,
                fwd: forwarded,
            };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            Some(attachment.ts),
        )
        .await
    }
    /// Prepare a fan-out of a read (`seen`) receipt: sent to the contact's devices, and
    /// self-synced to the sender's own devices so every device clears the unread badge.
    pub async fn prepare_receipt_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        ids: Vec<String>,
    ) -> Result<Option<Fanout>> {
        if ids.is_empty() {
            return Ok(None);
        }
        let recipient_payload = ChatPayload::Receipt {
            ids: ids.clone(),
            seen: true,
        };
        let peer_ids = ids.clone();
        let self_of = move |peer_key: String, _pu: String, _mid: String| ChatPayload::SelfSeen {
            peer_key,
            ids: peer_ids.clone(),
        };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            None,
        )
        .await
        .map(Some)
    }
    /// Prepare a fan-out of a 1:1 emoji-reaction toggle: sent to the contact's devices, and
    /// self-synced to the sender's own devices so every device shows the reaction.
    pub async fn prepare_reaction_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        target_msg_id: String,
        emoji: String,
        add: bool,
    ) -> Result<Fanout> {
        let recipient_payload = ChatPayload::Reaction {
            target_msg_id: target_msg_id.clone(),
            emoji: emoji.clone(),
            add,
            ts: now(),
        };
        let self_of =
            move |peer_key: String, _pu: String, _mid: String| ChatPayload::SelfReaction {
                peer_key,
                target_msg_id: target_msg_id.clone(),
                emoji: emoji.clone(),
                add,
            };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            None,
        )
        .await
    }
    /// Prepare a fan-out of a 1:1 message-pin toggle: sent to the contact's devices, and
    /// self-synced to the sender's own devices so every device shows the same pins.
    pub async fn prepare_pin_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        msg_id: String,
        pin: bool,
    ) -> Result<Fanout> {
        let recipient_payload = ChatPayload::PinMsg {
            msg_id: msg_id.clone(),
            pin,
        };
        let self_of = move |peer_key: String, _pu: String, _mid: String| ChatPayload::SelfPinMsg {
            peer_key,
            msg_id: msg_id.clone(),
            pin,
        };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            None,
        )
        .await
    }
    /// Prepare a fan-out of a disappearing-timer change: sent to every one of the
    /// contact's devices (so all of them stamp the same `delete_at` on the messages that
    /// follow), and self-synced to the sender's own devices (so a timer set on one of our
    /// devices governs the copies every other device records too).
    pub async fn prepare_timer_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        secs: Option<u64>,
    ) -> Result<Fanout> {
        let recipient_payload = ChatPayload::Timer { secs };
        let self_of = move |peer_key: String, _pu: String, _mid: String| ChatPayload::SelfTimer {
            peer_key,
            secs,
        };
        self.prepare_fanout(
            account,
            history,
            contact,
            recipient_payload,
            Some(&self_of),
            None,
        )
        .await
    }
    /// Prepare an ephemeral typing fan-out: one sealed copy per recipient device we
    /// ALREADY share a session with. Deliberately cheap and network-free: typing fires
    /// every few seconds, so it never fetches rosters/bundles, never establishes a
    /// session, and never self-syncs (our own devices don't need our typing state).
    /// Uses the pinned (KT-verified) roster; an unpinned peer falls back to the primary
    /// session only. May return an empty list — the caller just skips posting.
    pub fn prepare_typing_fanout(
        &self,
        account: &mut Account,
        history: &History,
        contact: &Contact,
        typing: bool,
    ) -> Result<Vec<Envelope>> {
        self.prepare_ephemeral_fanout(
            account,
            history,
            &contact.username,
            &contact.identity_key,
            &ChatPayload::Typing { typing },
        )
    }
    /// Like [`prepare_typing_fanout`](Self::prepare_typing_fanout), for a group thread:
    /// one sealed `GroupTyping` copy per device (of every other member) we already share
    /// a session with. Network-free; may return an empty list.
    pub fn prepare_group_typing_fanout(
        &self,
        account: &mut Account,
        history: &History,
        group: &Group,
        typing: bool,
    ) -> Result<Vec<Envelope>> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupTyping {
            group_id: group.id.clone(),
            typing,
        };
        let mut out = Vec::new();
        for m in &group.members {
            if m.identity_key == me {
                continue;
            }
            out.extend(self.prepare_ephemeral_fanout(
                account,
                history,
                &m.username,
                &m.identity_key,
                &payload,
            )?);
        }
        Ok(out)
    }
    /// Session-gated, network-free fan-out of an ephemeral payload to one account's
    /// devices (see [`prepare_typing_fanout`](Self::prepare_typing_fanout) for the
    /// rationale). `fallback_key` addresses the primary when no roster is pinned.
    pub(crate) fn prepare_ephemeral_fanout(
        &self,
        account: &mut Account,
        history: &History,
        username: &str,
        fallback_key: &str,
        payload: &ChatPayload,
    ) -> Result<Vec<Envelope>> {
        let msg_id = random_msg_id();
        let rec_hash = IdentityHash::from_identifier(username).as_str().to_string();
        let targets: Vec<(String, String)> = match history.pinned_roster(username) {
            Some(pin) => pin
                .devices
                .iter()
                .filter_map(|d| {
                    let mailbox = device_mailbox_hash(&rec_hash, &d.device_id)?
                        .as_str()
                        .to_string();
                    Some((mailbox, d.identity_key.clone()))
                })
                .collect(),
            None => vec![(rec_hash.clone(), fallback_key.to_string())],
        };
        let mut out = Vec::new();
        for (mailbox, key) in targets {
            if !account.ratchet_ref().has_session(&key) {
                continue;
            }
            out.push(seal_payload_to(account, &mailbox, &key, payload, &msg_id)?);
        }
        Ok(out)
    }
    /// Core fan-out: seal `recipient_payload` to every recipient device (immediate) and, if
    /// `self_payload` is given, a per-copy self-sync payload to each of the sender's own
    /// other devices (deferred). All copies share one message id.
    #[allow(clippy::type_complexity)]
    pub(crate) async fn prepare_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        recipient_payload: ChatPayload,
        self_payload: Option<&(dyn Fn(String, String, String) -> ChatPayload + Send + Sync)>,
        sent_at: Option<u64>,
    ) -> Result<Fanout> {
        let my_username = account.account_id().to_string();
        let rec = self
            .resolve_account_devices(history, &contact.username)
            .await?;
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);

        let msg_id = random_msg_id();
        // `sent_at` MUST be the ts already stamped inside the payload when there is
        // one: a second `now()` here can land one second later, and then the sender's
        // local copy (recorded with the returned value) and every wire copy (recorded
        // with the payload ts) compute disappearing deadlines one second apart.
        let ts = sent_at.unwrap_or_else(now);
        let rec_hash = IdentityHash::from_identifier(&contact.username)
            .as_str()
            .to_string();

        let mut immediate = Vec::new();
        for d in &rec.devices {
            let mailbox = device_mailbox_hash(&rec_hash, &d.device_id)
                .ok_or_else(|| ClientError::Protocol("bad device mailbox".into()))?
                .as_str()
                .to_string();
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            immediate.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &recipient_payload,
                &msg_id,
            )?);
        }

        let mut deferred = Vec::new();
        if let Some(build_self) = self_payload {
            let my_hash = IdentityHash::from_identifier(&my_username)
                .as_str()
                .to_string();
            let my_device = history.self_device_id();
            for d in &me.devices {
                if d.device_id == my_device {
                    continue; // never fan out to ourselves
                }
                let mailbox = device_mailbox_hash(&my_hash, &d.device_id)
                    .ok_or_else(|| ClientError::Protocol("bad device mailbox".into()))?
                    .as_str()
                    .to_string();
                self.ensure_device_session(account, &mailbox, &d.identity_key)
                    .await?;
                let payload = build_self(
                    rec.primary_key.clone(),
                    contact.username.clone(),
                    msg_id.clone(),
                );
                deferred.push(seal_payload_to(
                    account,
                    &mailbox,
                    &d.identity_key,
                    &payload,
                    &msg_id,
                )?);
            }
        }

        Ok(Fanout {
            msg_id,
            sent_at: ts,
            immediate,
            deferred,
        })
    }
    /// Seal a self-sync of our own profile picture to each of our OTHER devices. The caller
    /// pushes these onto the durable outbox (so a change made offline still reaches every
    /// device on the next drain) and records the picture locally. No copy is sealed to this
    /// device. `avatar` is already sanitized by the caller (`History::set_my_avatar`).
    pub async fn prepare_profile_selfsync(
        &self,
        account: &mut Account,
        history: &mut History,
        avatar: Option<String>,
    ) -> Result<Vec<Envelope>> {
        let my_username = account.account_id().to_string();
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);
        let my_hash = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        let my_device = history.self_device_id();
        let msg_id = random_msg_id();
        let payload = ChatPayload::SelfProfile { avatar };
        let mut out = Vec::new();
        for d in &me.devices {
            if d.device_id == my_device {
                continue; // never sync to ourselves
            }
            let mailbox = device_mailbox_hash(&my_hash, &d.device_id)
                .ok_or_else(|| ClientError::Protocol("bad device mailbox".into()))?
                .as_str()
                .to_string();
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &payload,
                &msg_id,
            )?);
        }
        Ok(out)
    }
    /// Send a group message with **per-device fan-out**: to every device of every other
    /// member (resolved from each member's verified roster) AND to our own other devices
    /// (so all our devices show the sent message). All copies share one `msg_id` so every
    /// device dedups against the sender's locally recorded copy. Returns
    /// `(msg_id, sent_at)` — record the local copy with that exact `sent_at`, so its
    /// disappearing deadline matches every recipient's. A member with no roster is
    /// delivered single-device (their primary), preserving old behavior.
    pub async fn send_group_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        body: &str,
        reply: Option<crate::ReplyRef>,
        forwarded: bool,
    ) -> Result<(String, u64)> {
        let ts = now();
        // Carried group timer (Some(0) = off) — same anti-race rule as 1:1 messages.
        let payload = ChatPayload::GroupText {
            group_id: group.id.clone(),
            body: body.to_string(),
            ts,
            expire_secs: Some(history.group_timer(&group.id).unwrap_or(0)),
            reply,
            fwd: forwarded,
        };
        let msg_id = self
            .fan_group_payload(account, history, group, &payload)
            .await?;
        Ok((msg_id, ts))
    }
    /// Fan a group-message edit to every device of every member and our own other
    /// devices (recipients enforce ownership by stored-sender match).
    pub async fn send_group_edit_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        msg_id: &str,
        body: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupEdit {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
            body: body.to_string(),
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Fan a group "delete for everyone" to every device of every member and ours.
    pub async fn send_group_delete_msg_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        msg_id: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupDeleteMsg {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Fan a group rename to every device of every member and ours.
    pub async fn send_group_rename_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        name: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupRename {
            group_id: group.id.clone(),
            name: name.to_string(),
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Tell every device of every member (and our own other devices, which mark the
    /// group left) that we left the group.
    pub async fn send_group_leave_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
    ) -> Result<()> {
        let payload = ChatPayload::GroupLeave {
            group_id: group.id.clone(),
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Fan a group message-pin toggle to every device of every member and our own other
    /// devices (any member may pin — roster trust model).
    pub async fn send_group_pin_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        msg_id: &str,
        pin: bool,
    ) -> Result<()> {
        let payload = ChatPayload::GroupPinMsg {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
            pin,
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Seal a note-to-self text to each of our OTHER devices (the special
    /// [`crate::NOTE_TO_SELF_PEER`] conversation). Notes never touch a recipient — this
    /// self-sync is their only wire presence; single-device accounts get an empty list.
    /// Push the result onto the durable outbox like any other self-sync.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_note_text_selfsync(
        &self,
        account: &mut Account,
        history: &mut History,
        msg_id: &str,
        body: &str,
        ts: u64,
        reply: Option<ReplyRef>,
        forwarded: bool,
    ) -> Result<Vec<Envelope>> {
        // Carry the note timer at send time (same rule as 1:1 sends): the copy on our
        // other devices stamps the identical delete_at even if the SelfTimer control
        // message races behind.
        let expire_secs = Some(history.timer(crate::NOTE_TO_SELF_PEER).unwrap_or(0));
        let payload = ChatPayload::SelfText {
            peer_key: crate::NOTE_TO_SELF_PEER.to_string(),
            peer_username: String::new(),
            msg_id: msg_id.to_string(),
            body: body.to_string(),
            ts,
            reply,
            expire_secs,
            fwd: forwarded,
        };
        self.prepare_self_only(account, history, &payload, msg_id)
            .await
    }
    /// Self-sync a note-to-self disappearing-timer change to our own other devices
    /// (notes have no peer — the timer is pure self state, `SelfTimer` carries it).
    pub async fn prepare_note_timer_selfsync(
        &self,
        account: &mut Account,
        history: &mut History,
        secs: Option<u64>,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::SelfTimer {
            peer_key: crate::NOTE_TO_SELF_PEER.to_string(),
            secs,
        };
        self.prepare_self_only(account, history, &payload, &random_msg_id())
            .await
    }
    /// Seal a note-to-self attachment reference to each of our other devices (see
    /// [`prepare_note_text_selfsync`](Self::prepare_note_text_selfsync)).
    pub async fn prepare_note_file_selfsync(
        &self,
        account: &mut Account,
        history: &mut History,
        msg_id: &str,
        attachment: AttachmentRef,
        forwarded: bool,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::SelfFile {
            peer_key: crate::NOTE_TO_SELF_PEER.to_string(),
            peer_username: String::new(),
            msg_id: msg_id.to_string(),
            attachment,
            expire_secs: Some(history.timer(crate::NOTE_TO_SELF_PEER).unwrap_or(0)),
            fwd: forwarded,
        };
        self.prepare_self_only(account, history, &payload, msg_id)
            .await
    }
    /// One sealed copy of `payload` per own OTHER device (roster-resolved). The shared
    /// delivery shape of every pure self-sync (profile picture, notes).
    async fn prepare_self_only(
        &self,
        account: &mut Account,
        history: &mut History,
        payload: &ChatPayload,
        msg_id: &str,
    ) -> Result<Vec<Envelope>> {
        let my_username = account.account_id().to_string();
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);
        let my_hash = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        let my_device = history.self_device_id();
        let mut out = Vec::new();
        for d in &me.devices {
            if d.device_id == my_device {
                continue; // never sync to ourselves
            }
            let mailbox = self.device_mailbox_from_hash(&my_hash, &d.device_id)?;
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                payload,
                msg_id,
            )?);
        }
        Ok(out)
    }
    /// Fan a signed membership epoch (+ group meta) to every device of every member AND
    /// our own other devices — the multi-device variant of
    /// [`send_group_roster`](crate::Client::send_group_roster). For a removal, `group`
    /// must still carry the FULL old roster so the kicked member's devices learn too.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_group_roster_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        epoch: &kt_log::GroupEpoch,
        name: &str,
        timer_secs: Option<u64>,
        avatar: Option<String>,
    ) -> Result<()> {
        let payload = ChatPayload::GroupRoster {
            epoch: epoch.clone(),
            name: name.to_string(),
            disappearing_secs: Some(timer_secs.unwrap_or(0)),
            avatar,
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Fan an attachment out to every device of every other member AND our own other
    /// devices (they render it as ours via attribution). One uploaded blob, one shared
    /// msg_id; each copy's key travels only inside that pair's ratchet — the exact
    /// delivery shape of [`send_group_multi`](Self::send_group_multi).
    pub async fn send_group_file_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        attachment: crate::AttachmentRef,
        forwarded: bool,
    ) -> Result<(String, u64)> {
        let ts = attachment.ts;
        let payload = ChatPayload::GroupFile {
            group_id: group.id.clone(),
            attachment,
            ts,
            expire_secs: Some(history.group_timer(&group.id).unwrap_or(0)),
            fwd: forwarded,
        };
        let msg_id = self
            .fan_group_payload(account, history, group, &payload)
            .await?;
        Ok((msg_id, ts))
    }
    /// Fan a group disappearing-timer change out to every device of every other member
    /// AND our own other devices, so the whole group (and all our devices) agree on the
    /// timer. Same delivery shape as a group message.
    pub async fn send_group_timer_multi(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        secs: Option<u64>,
    ) -> Result<()> {
        let payload = ChatPayload::GroupTimer {
            group_id: group.id.clone(),
            secs,
        };
        self.fan_group_payload(account, history, group, &payload)
            .await
            .map(|_| ())
    }
    /// Shared per-device group fan-out: one sealed copy of `payload` to every device of
    /// every other member (roster-resolved, fail-closed) and to our own other devices.
    /// All copies share the returned `msg_id`.
    pub(crate) async fn fan_group_payload(
        &self,
        account: &mut Account,
        history: &mut History,
        group: &crate::Group,
        payload: &ChatPayload,
    ) -> Result<String> {
        let my_username = account.account_id().to_string();
        let msg_id = random_msg_id();

        // Every other member's devices.
        let others: Vec<String> = group
            .members
            .iter()
            .filter(|m| m.username != my_username)
            .map(|m| m.username.clone())
            .collect();
        for member_username in &others {
            let devs = self
                .resolve_account_devices(history, member_username)
                .await?;
            let hash = IdentityHash::from_identifier(member_username)
                .as_str()
                .to_string();
            for d in &devs.devices {
                let mailbox = self.device_mailbox_from_hash(&hash, &d.device_id)?;
                self.ensure_device_session(account, &mailbox, &d.identity_key)
                    .await?;
                let env = seal_payload_to(account, &mailbox, &d.identity_key, payload, &msg_id)?;
                self.post_envelope(&env).await?;
            }
        }

        // Our own other devices (they render it as ours via attribution).
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);
        if me.devices.len() > 1 {
            let my_hash = IdentityHash::from_identifier(&my_username)
                .as_str()
                .to_string();
            let my_device = history.self_device_id();
            for d in &me.devices {
                if d.device_id == my_device {
                    continue;
                }
                let mailbox = self.device_mailbox_from_hash(&my_hash, &d.device_id)?;
                self.ensure_device_session(account, &mailbox, &d.identity_key)
                    .await?;
                let env = seal_payload_to(account, &mailbox, &d.identity_key, payload, &msg_id)?;
                self.post_envelope(&env).await?;
            }
        }
        Ok(msg_id)
    }
    /// (Caller) Sealed copies of a call offer for every device of `contact` **except**
    /// the one already signaled directly (`contact.identity_key`). Empty when the
    /// contact is single-device.
    pub async fn extra_call_offer_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        call_id: &str,
        key_b64: &str,
    ) -> Result<Vec<Envelope>> {
        self.extra_call_offer_envelopes_full(account, history, contact, call_id, key_b64, "")
            .await
    }
    /// [`extra_call_offer_envelopes`](Self::extra_call_offer_envelopes) with a
    /// `reconnect_of` marker. Devices that were not in the dropped call ignore a
    /// reconnect offer entirely, so fanning it to the whole roster is safe — it is the
    /// only way to reach the in-call device when that device is a linked one.
    pub async fn extra_call_offer_envelopes_full(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        call_id: &str,
        key_b64: &str,
        reconnect_of: &str,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::CallOffer {
            call_id: call_id.to_string(),
            key_b64: key_b64.to_string(),
            ts: now(),
            from: account.account_id().to_string(),
            caps: crate::media::local_caps(),
            reconnect_of: reconnect_of.to_string(),
        };
        self.extra_signal_envelopes(account, history, contact, payload)
            .await
    }
    /// (Group caller/joiner) Sealed copies of a group-call pair-leg offer for every
    /// device of `contact` except the directly-signaled one — the same ticket to every
    /// device (only one of them answers and joins the two-member pair room, exactly as
    /// in a 1:1 ring-all). Same fail-open-safe roster rules as the 1:1 offer fan.
    #[allow(clippy::too_many_arguments)]
    pub async fn extra_group_call_offer_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        group_id: &str,
        call_instance: &str,
        call_id: &str,
        key_b64: &str,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::GroupCallOffer {
            group_id: group_id.to_string(),
            call_instance: call_instance.to_string(),
            call_id: call_id.to_string(),
            key_b64: key_b64.to_string(),
            ts: now(),
            from: account.account_id().to_string(),
        };
        self.extra_signal_envelopes(account, history, contact, payload)
            .await
    }
    /// (Group leaver/decliner) Sealed copies of a group-call leave/decline for every
    /// device of `contact` except the directly-signaled one.
    pub async fn extra_group_call_end_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        group_id: &str,
        call_instance: &str,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::GroupCallEnd {
            group_id: group_id.to_string(),
            call_instance: call_instance.to_string(),
        };
        self.extra_signal_envelopes(account, history, contact, payload)
            .await
    }
    /// (Caller) Sealed copies of a hangup/cancel for every device of `contact` except
    /// the directly-signaled one, so every ringing device stops. Idempotent per device.
    pub async fn extra_call_end_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        call_id: &str,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::CallEnd {
            call_id: call_id.to_string(),
        };
        self.extra_signal_envelopes(account, history, contact, payload)
            .await
    }
    /// (Callee) Sealed copies of an accept/decline for the caller's other devices. The
    /// direct 1:1 answer lands in the caller's ACCOUNT mailbox — which only the primary
    /// drains — so when the call came from a **linked** device, the fan copy on that
    /// device's own mailbox is the only answer it can ever receive.
    pub async fn extra_call_answer_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        call_id: &str,
        accept: bool,
        busy: bool,
    ) -> Result<Vec<Envelope>> {
        let payload = ChatPayload::CallAnswer {
            call_id: call_id.to_string(),
            accept,
            caps: crate::media::local_caps(),
            busy,
        };
        self.extra_signal_envelopes(account, history, contact, payload)
            .await
    }
    pub(crate) async fn extra_signal_envelopes(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
        payload: ChatPayload,
    ) -> Result<Vec<Envelope>> {
        let rec = self
            .resolve_account_devices(history, &contact.username)
            .await?;
        if rec.devices.len() <= 1 {
            return Ok(Vec::new());
        }
        let rec_hash = IdentityHash::from_identifier(&contact.username)
            .as_str()
            .to_string();
        let msg_id = random_msg_id();
        let mut out = Vec::new();
        for d in &rec.devices {
            // The direct 1:1 copy travels to the ACCOUNT mailbox, which only the
            // primary device drains — so the primary is the only device the direct
            // copy can reach, and only when it is also the key the copy was sealed to.
            // Every other device needs a fan copy on its own mailbox (in particular:
            // when `contact.identity_key` names a LINKED device — e.g. answering a call
            // placed from one — the direct copy is undrainable by anyone; the fan copy
            // is that device's only working delivery).
            if d.device_id == PRIMARY_DEVICE_ID && d.identity_key == contact.identity_key {
                continue;
            }
            let mailbox = self.device_mailbox_from_hash(&rec_hash, &d.device_id)?;
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &payload,
                &msg_id,
            )?);
        }
        Ok(out)
    }
    /// (Callee) Tell our OWN other devices this ring was answered/declined here, so they
    /// stop ringing. Posted immediately (a ring is already a simultaneous, relay-visible
    /// event — the answering device's call-room join happens at the same instant, so
    /// this adds no new correlation signal). Cheap no-op for single-device accounts.
    pub async fn call_handled_selfsync(
        &self,
        account: &mut Account,
        history: &mut History,
        call_id: &str,
    ) -> Result<Vec<Envelope>> {
        let my_username = account.account_id().to_string();
        if history.pinned_roster(&my_username).is_none() {
            return Ok(Vec::new()); // never linked a device — skip the network entirely
        }
        let me = self.resolve_account_devices(history, &my_username).await?;
        if me.devices.len() <= 1 {
            return Ok(Vec::new());
        }
        history.set_self_primary_key(&me.primary_key);
        let my_hash = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        let my_device = history.self_device_id();
        let payload = ChatPayload::SelfCallHandled {
            call_id: call_id.to_string(),
        };
        let msg_id = random_msg_id();
        let mut out = Vec::new();
        for d in &me.devices {
            if d.device_id == my_device {
                continue;
            }
            let mailbox = self.device_mailbox_from_hash(&my_hash, &d.device_id)?;
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &payload,
                &msg_id,
            )?);
        }
        Ok(out)
    }
    /// (Linked device) Ask our primary to re-export history because our transfer expired.
    /// Picks a fresh capability id + link secret, E2E-encrypts a [`ChatPayload::SyncRequest`]
    /// to the primary's mailbox (the relay never sees the link secret), and returns the
    /// `(provisioning_id, link_secret_b64)` to poll with [`poll_resync`](Self::poll_resync).
    pub async fn request_history_resync(
        &self,
        account: &mut Account,
        history: &mut History,
    ) -> Result<(String, String)> {
        let my_username = account.account_id().to_string();
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);
        let primary_mailbox = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        self.ensure_device_session(account, &primary_mailbox, &me.primary_key)
            .await?;

        let provisioning_id = random_hex_id();
        let link_secret = csync::generate_link_secret();
        let link_secret_b64 = csync::link_secret_b64(&link_secret);
        let payload = ChatPayload::SyncRequest {
            provisioning_id: provisioning_id.clone(),
            link_secret_b64: link_secret_b64.clone(),
        };
        let env = seal_payload_to(
            account,
            &primary_mailbox,
            &me.primary_key,
            &payload,
            &random_msg_id(),
        )?;
        self.post_envelope(&env).await?;
        Ok((provisioning_id, link_secret_b64))
    }
    /// (Linked device) Poll for a re-exported history blob at `provisioning_id`, decrypting
    /// with the account password + the link secret used in the request. `Ok(None)` = not
    /// ready yet (primary hasn't fulfilled) — retry later.
    pub async fn poll_resync(
        &self,
        provisioning_id: &str,
        link_secret_b64: &str,
        password: &str,
    ) -> Result<Option<History>> {
        let link_secret = csync::link_secret_from_b64(link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;
        let resp = self
            .http
            .get(format!("{}/v1/sync/{provisioning_id}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let blob = resp.error_for_status()?.bytes().await?;
        let plain = csync::open_history(password, &link_secret, &blob).map_err(|_| {
            ClientError::Crypto("history decrypt failed (wrong password/PIN)".into())
        })?;
        History::import_plaintext(&plain)
            .map(Some)
            .ok_or_else(|| ClientError::Protocol("malformed history".into()))
    }
    /// (Primary device) Fulfill a linked device's [`InboundEvent::SyncRequested`]: re-seal
    /// the current history under the account password + the requester's link secret and PUT
    /// it at the requested capability id. The caller MUST first confirm the request came
    /// from one of our own devices (`History::is_own_device` on the event's sender).
    pub async fn fulfill_resync(
        &self,
        history: &History,
        provisioning_id: &str,
        link_secret_b64: &str,
        password: &str,
    ) -> Result<()> {
        let link_secret = csync::link_secret_from_b64(link_secret_b64)
            .ok_or_else(|| ClientError::Protocol("bad link secret".into()))?;
        let blob = csync::seal_history(password, &link_secret, &history.export_plaintext())
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let resp = self
            .http
            .put(format!("{}/v1/sync/{provisioning_id}", self.base_url))
            .body(blob)
            .send()
            .await?;
        crate::ensure_ok(resp).await
    }
    /// Build forward envelopes for a legacy-sender inbound message **without any network**:
    /// targets only our linked devices we already hold a session with (the link-time hello
    /// establishes it). Lock-friendly for the delivery loop; misses only devices with no
    /// session yet, which pick the message up once a session exists. Idempotent by msg_id.
    pub fn forward_inbound_sync(
        &self,
        account: &mut Account,
        history: &History,
        event: &InboundEvent,
    ) -> Result<Vec<Envelope>> {
        if !history.is_primary_device() {
            return Ok(Vec::new());
        }
        let (from_key, from_username, msg_id, body, ts, reply, attachment, expire_secs) =
            match event {
                InboundEvent::Message {
                    sender_identity_key,
                    sender_username,
                    msg_id,
                    body,
                    sent_at,
                    reply,
                    expire_secs,
                    ..
                } => (
                    sender_identity_key.clone(),
                    sender_username.clone(),
                    msg_id.clone(),
                    body.clone(),
                    *sent_at,
                    reply.clone(),
                    None,
                    *expire_secs,
                ),
                InboundEvent::Attachment {
                    sender_identity_key,
                    sender_username,
                    msg_id,
                    attachment,
                    sent_at,
                    expire_secs,
                    ..
                } => (
                    sender_identity_key.clone(),
                    sender_username.clone(),
                    msg_id.clone(),
                    attachment.filename.clone(),
                    *sent_at,
                    None,
                    Some(attachment.clone()),
                    *expire_secs,
                ),
                _ => return Ok(Vec::new()),
            };
        let my_username = account.account_id().to_string();
        let Some(pin) = history.pinned_roster(&my_username) else {
            return Ok(Vec::new());
        };
        let devices = pin.devices.clone();
        let my_hash = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        let my_device = history.self_device_id();
        let payload = ChatPayload::ForwardIncoming {
            from_key,
            from_username,
            msg_id: msg_id.clone(),
            body,
            ts,
            reply,
            attachment,
            expire_secs,
        };
        let mut out = Vec::new();
        for d in &devices {
            if d.device_id == my_device || !account.ratchet_ref().has_session(&d.identity_key) {
                continue;
            }
            let mailbox = self.device_mailbox_from_hash(&my_hash, &d.device_id)?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &payload,
                &msg_id,
            )?);
        }
        Ok(out)
    }
    /// (Primary device) Forward a message that arrived from a **legacy** sender (one that
    /// only addressed our account mailbox) to our own linked devices, so they see it too.
    /// Returns envelopes to post (empty when we have no linked devices). Only meaningful on
    /// the primary; a linked device's account mailbox is never delivered to. Idempotent —
    /// the receiving device dedups by msg_id against any direct fan-out copy.
    pub async fn forward_inbound_to_devices(
        &self,
        account: &mut Account,
        history: &mut History,
        event: &InboundEvent,
    ) -> Result<Vec<Envelope>> {
        // Only the primary forwards, and only real timeline messages.
        if !history.is_primary_device() {
            return Ok(Vec::new());
        }
        let (from_key, from_username, msg_id, body, ts, reply, attachment, expire_secs) =
            match event {
                InboundEvent::Message {
                    sender_identity_key,
                    sender_username,
                    msg_id,
                    body,
                    sent_at,
                    reply,
                    expire_secs,
                    ..
                } => (
                    sender_identity_key.clone(),
                    sender_username.clone(),
                    msg_id.clone(),
                    body.clone(),
                    *sent_at,
                    reply.clone(),
                    None,
                    *expire_secs,
                ),
                InboundEvent::Attachment {
                    sender_identity_key,
                    sender_username,
                    msg_id,
                    attachment,
                    sent_at,
                    expire_secs,
                    ..
                } => (
                    sender_identity_key.clone(),
                    sender_username.clone(),
                    msg_id.clone(),
                    attachment.filename.clone(),
                    *sent_at,
                    None,
                    Some(attachment.clone()),
                    *expire_secs,
                ),
                _ => return Ok(Vec::new()),
            };

        let my_username = account.account_id().to_string();
        let me = self.resolve_account_devices(history, &my_username).await?;
        history.set_self_primary_key(&me.primary_key);
        if me.devices.len() <= 1 {
            return Ok(Vec::new());
        }
        let my_hash = IdentityHash::from_identifier(&my_username)
            .as_str()
            .to_string();
        let my_device = history.self_device_id();
        let payload = ChatPayload::ForwardIncoming {
            from_key,
            from_username,
            msg_id: msg_id.clone(),
            body,
            ts,
            reply,
            attachment,
            expire_secs,
        };
        let mut out = Vec::new();
        for d in &me.devices {
            if d.device_id == my_device {
                continue;
            }
            let mailbox = self.device_mailbox_from_hash(&my_hash, &d.device_id)?;
            self.ensure_device_session(account, &mailbox, &d.identity_key)
                .await?;
            out.push(seal_payload_to(
                account,
                &mailbox,
                &d.identity_key,
                &payload,
                &msg_id,
            )?);
        }
        Ok(out)
    }
    /// Seal the current history under the account password/PIN + link secret and upload it
    /// as an opaque blob. Returns the capability id.
    pub async fn export_history(
        &self,
        history: &History,
        password: &str,
        link_secret: &[u8; csync::LINK_SECRET_LEN],
    ) -> Result<String> {
        let plaintext = history.export_plaintext();
        let blob = csync::seal_history(password, link_secret, &plaintext)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        self.upload_sync_blob(blob).await
    }
    /// Download + decrypt a history blob by id. Merge with [`History::merge_from`].
    pub async fn import_history(
        &self,
        sync_id: &str,
        password: &str,
        link_secret: &[u8; csync::LINK_SECRET_LEN],
    ) -> Result<History> {
        let blob = self.download_sync_blob(sync_id).await?;
        let plain = csync::open_history(password, link_secret, &blob)
            .map_err(|_| ClientError::Crypto("history decrypt failed".into()))?;
        History::import_plaintext(&plain)
            .ok_or_else(|| ClientError::Protocol("malformed history".into()))
    }
}
