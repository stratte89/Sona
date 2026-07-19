use crate::*;

impl Client {
    /// Encrypt and relay a message to a contact. The envelope names only the recipient
    /// hash; the sender (and the message itself) are sealed inside the ciphertext.
    /// Returns the message id + timestamp so the caller can record it in local history
    /// with the exact values the recipient will see (needed for disappearing messages).
    pub async fn send(
        &self,
        account: &mut Account,
        contact: &Contact,
        plaintext: &str,
    ) -> Result<SentMessage> {
        let prepared = self.prepare_message(account, contact, plaintext)?;
        let (msg_id, sent_at) = (prepared.msg_id.clone(), prepared.sent_at);
        self.post_envelope(&prepared.envelope).await?;
        Ok(SentMessage { msg_id, sent_at })
    }
    /// Encrypt a text message for a contact without sending it (no network, no await
    /// points that matter). Post the returned envelope with [`Client::post_envelope`].
    /// Note the ratchet advances here — the caller should persist the account whether or
    /// not the post later succeeds.
    pub fn prepare_message(
        &self,
        account: &mut Account,
        contact: &Contact,
        plaintext: &str,
    ) -> Result<PreparedMessage> {
        self.prepare_message_replying(account, contact, plaintext, None, None, false)
    }
    /// Like [`prepare_message`](Self::prepare_message), optionally quoting another message.
    /// `expire_secs` is carried verbatim inside the message (wire encoding: `None` =
    /// don't carry a timer — the recipient falls back to its stored conversation timer;
    /// `Some(0)` = timer explicitly off; `Some(n)` = n seconds). A caller that knows the
    /// conversation timer should pass `Some(timer.unwrap_or(0))` so the recipient stamps
    /// the right delete time even when the message races ahead of the `Timer` control.
    /// `forwarded` marks the message as forwarded from another conversation (the
    /// recipient renders a "Forwarded" tag).
    pub fn prepare_message_replying(
        &self,
        account: &mut Account,
        contact: &Contact,
        plaintext: &str,
        reply: Option<ReplyRef>,
        expire_secs: Option<u64>,
        forwarded: bool,
    ) -> Result<PreparedMessage> {
        let ts = now();
        let payload = ChatPayload::Text {
            body: plaintext.to_string(),
            ts,
            from: account.account_id().to_string(),
            reply,
            expire_secs,
            fwd: forwarded,
        };
        let envelope = build_envelope(account, contact, &payload)?;
        let msg_id = envelope.msg_id.clone();
        Ok(PreparedMessage {
            envelope,
            msg_id,
            sent_at: ts,
        })
    }
    /// Encrypt a delivery/read receipt without sending it. `None` when `ids` is empty.
    pub fn prepare_receipt(
        &self,
        account: &mut Account,
        contact: &Contact,
        ids: Vec<String>,
        seen: bool,
    ) -> Result<Option<Envelope>> {
        if ids.is_empty() {
            return Ok(None);
        }
        build_envelope(account, contact, &ChatPayload::Receipt { ids, seen }).map(Some)
    }
    /// Relay a previously prepared envelope. Pure network — needs no account state, so a
    /// caller can do this outside any lock that guards the account.
    pub async fn post_envelope(&self, envelope: &Envelope) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .json(envelope)
            .send()
            .await?;
        ensure_ok(resp).await
    }
    /// Gossip transport: send our current Key Transparency tree head to a contact, so they
    /// can compare it against their own view and catch an equivocating server. Call this
    /// periodically (e.g. on connect); the recipient handles the [`InboundEvent::PeerHead`]
    /// by passing the head to [`compare_foreign_head`](Self::compare_foreign_head).
    pub async fn send_head(&self, account: &mut Account, contact: &Contact) -> Result<()> {
        let head = self.fetch_tree_head().await?;
        self.send_payload(account, contact, &ChatPayload::Gossip { head })
            .await
            .map(|_| ())
    }
    /// Edit one of our previously sent messages on the peer's side (pair with a local
    /// history edit). The recipient only applies it to messages we sent.
    pub async fn send_edit(
        &self,
        account: &mut Account,
        contact: &Contact,
        msg_id: &str,
        body: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::Edit {
                msg_id: msg_id.to_string(),
                body: body.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Pin (or unpin) a message in this 1:1 conversation on the peer's side (pair with
    /// [`History::set_msg_pinned`]). Either side may pin — shared metadata.
    pub async fn send_pin_msg(
        &self,
        account: &mut Account,
        contact: &Contact,
        msg_id: &str,
        pin: bool,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::PinMsg {
                msg_id: msg_id.to_string(),
                pin,
            },
        )
        .await
        .map(|_| ())
    }
    /// Delete one of our previously sent messages on the peer's side ("for everyone").
    pub async fn send_delete_msg(
        &self,
        account: &mut Account,
        contact: &Contact,
        msg_id: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::DeleteMsg {
                msg_id: msg_id.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Ask the peer to delete the conversation on their side too ("delete for both").
    /// The caller wipes its own local copy separately.
    pub async fn send_delete_chat(&self, account: &mut Account, contact: &Contact) -> Result<()> {
        self.send_payload(account, contact, &ChatPayload::DeleteChat {})
            .await
            .map(|_| ())
    }
    /// Toggle a 1:1 emoji reaction on the peer's side (pair with a local
    /// [`History::react`]). `add` sets it, `!add` removes it.
    pub async fn send_reaction(
        &self,
        account: &mut Account,
        contact: &Contact,
        target_msg_id: &str,
        emoji: &str,
        add: bool,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::Reaction {
                target_msg_id: target_msg_id.to_string(),
                emoji: emoji.to_string(),
                add,
                ts: now(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Send an ephemeral typing signal to a contact (`typing == false` = stopped). Never
    /// recorded in history on either side — pure UI state. Best-effort: the caller ignores
    /// failures (a lost typing frame is harmless).
    pub async fn send_typing(
        &self,
        account: &mut Account,
        contact: &Contact,
        typing: bool,
    ) -> Result<()> {
        self.send_payload(account, contact, &ChatPayload::Typing { typing })
            .await
            .map(|_| ())
    }
    /// Set (or clear, with `None`) the disappearing-messages timer for a conversation.
    /// Sends an end-to-end control message so the peer's client adopts the same timer —
    /// the setting is shared, and the server never learns it's on or what it is. The
    /// caller should also apply it to its own local history.
    pub async fn set_disappearing(
        &self,
        account: &mut Account,
        contact: &Contact,
        secs: Option<u64>,
    ) -> Result<()> {
        self.send_payload(account, contact, &ChatPayload::Timer { secs })
            .await
            .map(|_| ())
    }
    /// Send a delivery receipt for the peer's messages `ids`. `seen == false` = delivered,
    /// `true` = read. Encrypted end-to-end like any message; the server learns nothing.
    pub async fn send_receipt(
        &self,
        account: &mut Account,
        contact: &Contact,
        ids: Vec<String>,
        seen: bool,
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.send_payload(account, contact, &ChatPayload::Receipt { ids, seen })
            .await
            .map(|_| ())
    }
    /// Send an explicit chat request ("knock") to a contact: no content, the recipient's
    /// request gate surfaces a pending-request row. Multi-device shells should prefer
    /// [`prepare_knock_fanout`](Self::prepare_knock_fanout) so every recipient device
    /// shows the request.
    pub async fn send_knock(&self, account: &mut Account, contact: &Contact) -> Result<()> {
        let payload = ChatPayload::Knock {
            from: account.account_id().to_string(),
        };
        self.send_payload(account, contact, &payload)
            .await
            .map(|_| ())
    }
    /// Multi-device flavor of [`send_knock`](Self::send_knock): one sealed copy per
    /// recipient device (no self-sync — our own devices have nothing to show for it).
    pub async fn prepare_knock_fanout(
        &self,
        account: &mut Account,
        history: &mut History,
        contact: &Contact,
    ) -> Result<crate::multidevice::Fanout> {
        let payload = ChatPayload::Knock {
            from: account.account_id().to_string(),
        };
        self.prepare_fanout(account, history, contact, payload, None, None)
            .await
    }
    /// Encrypt a [`ChatPayload`] for a contact and relay it. Returns the envelope msg_id.
    pub(crate) async fn send_payload(
        &self,
        account: &mut Account,
        contact: &Contact,
        payload: &ChatPayload,
    ) -> Result<String> {
        let envelope = build_envelope(account, contact, payload)?;
        let msg_id = envelope.msg_id.clone();
        self.post_envelope(&envelope).await?;
        Ok(msg_id)
    }
}
