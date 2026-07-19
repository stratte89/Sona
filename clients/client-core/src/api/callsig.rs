use crate::*;

impl Client {
    /// Ring a contact: send the call capability (room id + key) over the ratchet. Mint
    /// the ticket with [`call::CallTicket::mint`]; join the room before or right after
    /// sending so the callee finds you there.
    pub async fn send_call_offer(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_id: &str,
        key_b64: &str,
    ) -> Result<()> {
        self.send_call_offer_full(account, contact, call_id, key_b64, "")
            .await
    }
    /// [`send_call_offer`](Self::send_call_offer) with a `reconnect_of` marker: a
    /// non-empty value resumes that dropped call silently instead of ringing (see
    /// [`ChatPayload::CallOffer`]).
    pub async fn send_call_offer_full(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_id: &str,
        key_b64: &str,
        reconnect_of: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::CallOffer {
                call_id: call_id.to_string(),
                key_b64: key_b64.to_string(),
                ts: now(),
                from: account.account_id().to_string(),
                caps: media::local_caps(),
                reconnect_of: reconnect_of.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Answer a pending call offer (accept or decline).
    pub async fn send_call_answer(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_id: &str,
        accept: bool,
        busy: bool,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::CallAnswer {
                call_id: call_id.to_string(),
                accept,
                caps: media::local_caps(),
                busy,
            },
        )
        .await
        .map(|_| ())
    }
    /// Hang up / cancel a call (belt-and-suspenders next to leaving the room).
    pub async fn send_call_end(
        &self,
        account: &mut Account,
        contact: &Contact,
        call_id: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::CallEnd {
                call_id: call_id.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Offer one group-call pair leg to a member: the leg's relay-room capability and
    /// key, plus the instance id that names the call (see
    /// [`ChatPayload::GroupCallOffer`] for the mesh + glare design). Mint the ticket
    /// with [`call::CallTicket::mint`], one per pair, never reused.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_group_call_offer(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance: &str,
        call_id: &str,
        key_b64: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::GroupCallOffer {
                group_id: group_id.to_string(),
                call_instance: call_instance.to_string(),
                call_id: call_id.to_string(),
                key_b64: key_b64.to_string(),
                ts: now(),
                from: account.account_id().to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Tell a member we declined / left / cancelled group call `call_instance`.
    pub async fn send_group_call_end(
        &self,
        account: &mut Account,
        contact: &Contact,
        group_id: &str,
        call_instance: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::GroupCallEnd {
                group_id: group_id.to_string(),
                call_instance: call_instance.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
}
