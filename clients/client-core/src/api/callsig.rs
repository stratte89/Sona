use crate::*;

fn require_signal_id(value: &str, field: &str) -> Result<()> {
    if callstate::valid_call_id(value) {
        Ok(())
    } else {
        Err(ClientError::Protocol(format!("invalid v2 {field}")))
    }
}

fn require_device_id(value: &str, field: &str) -> Result<()> {
    if callstate::valid_device_id(value) {
        Ok(())
    } else {
        Err(ClientError::Protocol(format!("invalid v2 {field}")))
    }
}

fn require_control_expiry(expires_at: u64) -> Result<()> {
    if callstate::valid_control_expiry(expires_at, now()) {
        Ok(())
    } else {
        Err(ClientError::Protocol("invalid v2 control expiry".into()))
    }
}

fn require_reply_mailbox(reply_to_mailbox: &str) -> Result<()> {
    if reply_to_mailbox.len() == 64
        && reply_to_mailbox
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ClientError::Protocol("invalid v2 reply mailbox".into()))
    }
}

fn targeted_signal_envelope(
    account: &mut Account,
    target_identity_key: &str,
    target_mailbox: &str,
    payload: &ChatPayload,
) -> Result<Envelope> {
    if target_identity_key.is_empty() {
        return Err(ClientError::Protocol(
            "invalid v2 target identity key".into(),
        ));
    }
    require_reply_mailbox(target_mailbox)?;
    seal_payload_to(
        account,
        target_mailbox,
        target_identity_key,
        payload,
        &random_msg_id(),
    )
}

impl Client {
    /// Encrypt one direct protocol-v2 offer without posting it. Preparing every device
    /// copy first lets shells launch the fanout together.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_offer_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_instance_id: &str,
        offer_id: &str,
        call_id: &str,
        key_b64: &str,
        created_at: u64,
        ring_expires_at: u64,
        expires_at: u64,
        caller_device_id: &str,
        resume_of: &str,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_device_id(caller_device_id, "caller device id")?;
        if !call::CallTicket::valid(call_id, key_b64)
            || (!resume_of.is_empty() && !callstate::valid_call_id(resume_of))
            || !callstate::valid_offer_deadline(created_at, ring_expires_at)
            || !callstate::valid_signal_deadline(created_at, expires_at)
            || !callstate::valid_control_expiry(expires_at, now())
            || ring_expires_at > expires_at
        {
            return Err(ClientError::Protocol("invalid v2 offer deadline".into()));
        }
        let reply_to_mailbox = self.device_mailbox(account.account_id(), caller_device_id)?;
        let payload = ChatPayload::CallOfferV2 {
            call_instance_id: call_instance_id.to_string(),
            offer_id: offer_id.to_string(),
            call_id: call_id.to_string(),
            key_b64: key_b64.to_string(),
            created_at,
            ring_expires_at,
            expires_at,
            from: account.account_id().to_string(),
            caller_device_id: caller_device_id.to_string(),
            reply_to_mailbox,
            caps: media::local_caps(),
            resume_of: resume_of.to_string(),
        };
        build_envelope(account, contact, &payload)
    }

    /// Send one protocol-v2 call offer. All device copies for a logical fanout must reuse
    /// these IDs and deadlines; the media room capability stays separate.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_call_offer_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_instance_id: &str,
        offer_id: &str,
        call_id: &str,
        key_b64: &str,
        created_at: u64,
        ring_expires_at: u64,
        expires_at: u64,
        caller_device_id: &str,
        resume_of: &str,
    ) -> Result<()> {
        let envelope = self.prepare_call_offer_v2(
            account,
            contact,
            call_instance_id,
            offer_id,
            call_id,
            key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            caller_device_id,
            resume_of,
        )?;
        self.post_envelope(&envelope).await
    }

    /// Prepare an answer claim addressed to the exact caller device mailbox authenticated
    /// by the offer, rather than broadcasting it across the caller account.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_answer_claim_v2_to_mailbox(
        &self,
        account: &mut Account,
        caller_identity_key: &str,
        caller_reply_to_mailbox: &str,
        call_instance_id: &str,
        offer_id: &str,
        claim_nonce: &str,
        answering_device_id: &str,
        reply_to_mailbox: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_signal_id(claim_nonce, "claim nonce")?;
        require_device_id(answering_device_id, "answering device id")?;
        require_reply_mailbox(reply_to_mailbox)?;
        require_control_expiry(expires_at)?;
        targeted_signal_envelope(
            account,
            caller_identity_key,
            caller_reply_to_mailbox,
            &ChatPayload::CallAnswerClaimV2 {
                call_instance_id: call_instance_id.to_string(),
                offer_id: offer_id.to_string(),
                claim_nonce: claim_nonce.to_string(),
                answering_device_id: answering_device_id.to_string(),
                reply_to_mailbox: reply_to_mailbox.to_string(),
                caps: media::local_caps(),
                expires_at,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_winner_v2_to_mailbox(
        &self,
        account: &mut Account,
        winner_identity_key: &str,
        winner_reply_to_mailbox: &str,
        call_instance_id: &str,
        offer_id: &str,
        claim_nonce: &str,
        winner_device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_signal_id(claim_nonce, "claim nonce")?;
        require_device_id(winner_device_id, "winner device id")?;
        require_control_expiry(expires_at)?;
        targeted_signal_envelope(
            account,
            winner_identity_key,
            winner_reply_to_mailbox,
            &ChatPayload::CallWinnerV2 {
                call_instance_id: call_instance_id.to_string(),
                offer_id: offer_id.to_string(),
                claim_nonce: claim_nonce.to_string(),
                winner_device_id: winner_device_id.to_string(),
                expires_at,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_busy_v2_to_mailbox(
        &self,
        account: &mut Account,
        caller_identity_key: &str,
        caller_reply_to_mailbox: &str,
        call_instance_id: &str,
        offer_id: &str,
        device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_device_id(device_id, "device id")?;
        require_control_expiry(expires_at)?;
        targeted_signal_envelope(
            account,
            caller_identity_key,
            caller_reply_to_mailbox,
            &ChatPayload::CallBusyV2 {
                call_instance_id: call_instance_id.to_string(),
                offer_id: offer_id.to_string(),
                device_id: device_id.to_string(),
                expires_at,
            },
        )
    }

    /// Send a final protocol-v2 outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_terminal_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_instance_id: &str,
        offer_id: &str,
        reason: callstate::CallTerminalReason,
        actor_device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_device_id(actor_device_id, "actor device id")?;
        require_control_expiry(expires_at)?;
        let from = account.account_id().to_string();
        build_envelope(
            account,
            contact,
            &ChatPayload::CallTerminalV2 {
                call_instance_id: call_instance_id.to_string(),
                offer_id: offer_id.to_string(),
                reason,
                from,
                actor_device_id: actor_device_id.to_string(),
                expires_at,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_call_terminal_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_instance_id: &str,
        offer_id: &str,
        reason: callstate::CallTerminalReason,
        actor_device_id: &str,
        expires_at: u64,
    ) -> Result<()> {
        let envelope = self.prepare_call_terminal_v2(
            account,
            contact,
            call_instance_id,
            offer_id,
            reason,
            actor_device_id,
            expires_at,
        )?;
        self.post_envelope(&envelope).await
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_call_terminal_v2_to_mailbox(
        &self,
        account: &mut Account,
        target_identity_key: &str,
        target_reply_to_mailbox: &str,
        call_instance_id: &str,
        offer_id: &str,
        reason: callstate::CallTerminalReason,
        actor_device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(offer_id, "offer id")?;
        require_device_id(actor_device_id, "actor device id")?;
        require_control_expiry(expires_at)?;
        let from = account.account_id().to_string();
        targeted_signal_envelope(
            account,
            target_identity_key,
            target_reply_to_mailbox,
            &ChatPayload::CallTerminalV2 {
                call_instance_id: call_instance_id.to_string(),
                offer_id: offer_id.to_string(),
                reason,
                from,
                actor_device_id: actor_device_id.to_string(),
                expires_at,
            },
        )
    }

    /// Offer one protocol-v2 group-call pair leg.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_group_call_offer_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        offer_id: &str,
        call_id: &str,
        key_b64: &str,
        created_at: u64,
        ring_expires_at: u64,
        expires_at: u64,
        caller_device_id: &str,
        coordinator_username: &str,
        coordinator_identity_key: &str,
        coordinator_device_id: &str,
        coordinator_reply_to_mailbox: &str,
        resume: bool,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(ring_id, "ring id")?;
        require_signal_id(offer_id, "offer id")?;
        require_device_id(caller_device_id, "caller device id")?;
        require_device_id(coordinator_device_id, "coordinator device id")?;
        require_reply_mailbox(coordinator_reply_to_mailbox)?;
        if coordinator_username.is_empty() || coordinator_identity_key.is_empty() {
            return Err(ClientError::Protocol("invalid v2 group coordinator".into()));
        }
        if !call::CallTicket::valid(call_id, key_b64)
            || !callstate::valid_offer_deadline(created_at, ring_expires_at)
            || !callstate::valid_signal_deadline(created_at, expires_at)
            || !callstate::valid_control_expiry(expires_at, now())
            || ring_expires_at > expires_at
        {
            return Err(ClientError::Protocol(
                "invalid v2 group offer deadline".into(),
            ));
        }
        let payload = ChatPayload::GroupCallOfferV2 {
            group_id: group_id.to_string(),
            call_instance_id: call_instance_id.to_string(),
            ring_id: ring_id.to_string(),
            offer_id: offer_id.to_string(),
            call_id: call_id.to_string(),
            key_b64: key_b64.to_string(),
            created_at,
            ring_expires_at,
            expires_at,
            from: account.account_id().to_string(),
            caller_device_id: caller_device_id.to_string(),
            coordinator_username: coordinator_username.to_string(),
            coordinator_identity_key: coordinator_identity_key.to_string(),
            coordinator_device_id: coordinator_device_id.to_string(),
            coordinator_reply_to_mailbox: coordinator_reply_to_mailbox.to_string(),
            resume,
        };
        build_envelope(account, contact, &payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_group_call_offer_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        offer_id: &str,
        call_id: &str,
        key_b64: &str,
        created_at: u64,
        ring_expires_at: u64,
        expires_at: u64,
        caller_device_id: &str,
        coordinator_username: &str,
        coordinator_identity_key: &str,
        coordinator_device_id: &str,
        coordinator_reply_to_mailbox: &str,
        resume: bool,
    ) -> Result<()> {
        let envelope = self.prepare_group_call_offer_v2(
            account,
            contact,
            group_id,
            call_instance_id,
            ring_id,
            offer_id,
            call_id,
            key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            caller_device_id,
            coordinator_username,
            coordinator_identity_key,
            coordinator_device_id,
            coordinator_reply_to_mailbox,
            resume,
        )?;
        self.post_envelope(&envelope).await
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_group_call_answer_claim_v2_to_mailbox(
        &self,
        account: &mut Account,
        coordinator_identity_key: &str,
        coordinator_reply_to_mailbox: &str,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        claim_nonce: &str,
        answering_device_id: &str,
        reply_to_mailbox: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(ring_id, "ring id")?;
        require_signal_id(claim_nonce, "claim nonce")?;
        require_device_id(answering_device_id, "answering device id")?;
        require_reply_mailbox(reply_to_mailbox)?;
        require_control_expiry(expires_at)?;
        targeted_signal_envelope(
            account,
            coordinator_identity_key,
            coordinator_reply_to_mailbox,
            &ChatPayload::GroupCallAnswerClaimV2 {
                group_id: group_id.to_string(),
                call_instance_id: call_instance_id.to_string(),
                ring_id: ring_id.to_string(),
                claim_nonce: claim_nonce.to_string(),
                answering_device_id: answering_device_id.to_string(),
                reply_to_mailbox: reply_to_mailbox.to_string(),
                expires_at,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_group_call_winner_v2_to_mailbox(
        &self,
        account: &mut Account,
        winner_identity_key: &str,
        winner_reply_to_mailbox: &str,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        claim_nonce: &str,
        winner_device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(ring_id, "ring id")?;
        require_signal_id(claim_nonce, "claim nonce")?;
        require_device_id(winner_device_id, "winner device id")?;
        require_control_expiry(expires_at)?;
        targeted_signal_envelope(
            account,
            winner_identity_key,
            winner_reply_to_mailbox,
            &ChatPayload::GroupCallWinnerV2 {
                group_id: group_id.to_string(),
                call_instance_id: call_instance_id.to_string(),
                ring_id: ring_id.to_string(),
                claim_nonce: claim_nonce.to_string(),
                winner_device_id: winner_device_id.to_string(),
                expires_at,
            },
        )
    }

    /// Send an explicit group-call terminal/leave outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_group_call_terminal_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        reason: callstate::CallTerminalReason,
        actor_device_id: &str,
        coordinator_username: &str,
        coordinator_identity_key: &str,
        coordinator_device_id: &str,
        expires_at: u64,
    ) -> Result<Envelope> {
        require_signal_id(call_instance_id, "call instance id")?;
        require_signal_id(ring_id, "ring id")?;
        require_device_id(actor_device_id, "actor device id")?;
        require_device_id(coordinator_device_id, "coordinator device id")?;
        if coordinator_username.is_empty() || coordinator_identity_key.is_empty() {
            return Err(ClientError::Protocol("invalid v2 group coordinator".into()));
        }
        require_control_expiry(expires_at)?;
        build_envelope(
            account,
            contact,
            &ChatPayload::GroupCallTerminalV2 {
                group_id: group_id.to_string(),
                call_instance_id: call_instance_id.to_string(),
                ring_id: ring_id.to_string(),
                reason,
                actor_device_id: actor_device_id.to_string(),
                coordinator_username: coordinator_username.to_string(),
                coordinator_identity_key: coordinator_identity_key.to_string(),
                coordinator_device_id: coordinator_device_id.to_string(),
                expires_at,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_group_call_terminal_v2(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance_id: &str,
        ring_id: &str,
        reason: callstate::CallTerminalReason,
        actor_device_id: &str,
        coordinator_username: &str,
        coordinator_identity_key: &str,
        coordinator_device_id: &str,
        expires_at: u64,
    ) -> Result<()> {
        let envelope = self.prepare_group_call_terminal_v2(
            account,
            contact,
            group_id,
            call_instance_id,
            ring_id,
            reason,
            actor_device_id,
            coordinator_username,
            coordinator_identity_key,
            coordinator_device_id,
            expires_at,
        )?;
        self.post_envelope(&envelope).await
    }
}
