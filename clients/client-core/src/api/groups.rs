use crate::*;

/// Convert a display [`GroupMember`] to the epoch's [`GroupMemberEntry`] (username +
/// account identity key — no per-member signing key is needed; the admin is located among
/// the members and its authority key travels in the epoch header).
fn member_entry(m: &GroupMember) -> GroupMemberEntry {
    GroupMemberEntry {
        username: m.username.clone(),
        identity_key: m.identity_key.clone(),
    }
}

impl Client {
    /// Create an **admin-model** group: we become the group's first admin, minting the
    /// genesis membership epoch (seq 0, self-signed by our account key) and fanning it out
    /// to every member as a [`ChatPayload::GroupRoster`]. Returns the group and the genesis
    /// epoch — the caller adopts it locally with
    /// [`History::adopt_group_epoch`](crate::History::adopt_group_epoch) and then
    /// [`History::set_group_name`](crate::History::set_group_name).
    pub async fn create_group(
        &self,
        account: &mut Account,
        name: &str,
        members: &[Contact],
    ) -> Result<(Group, GroupEpoch)> {
        let group_id = random_msg_id();
        let mut roster: Vec<GroupMember> = members
            .iter()
            .map(|c| GroupMember {
                username: c.username.clone(),
                identity_key: c.identity_key.clone(),
            })
            .collect();
        roster.push(GroupMember {
            username: account.account_id().to_string(),
            identity_key: account.ratchet_ref().identity_key(),
        });

        // Genesis epoch: we are the admin (our account Ed25519 signing key is the authority,
        // our Curve25519 identity key locates us among the members), self-signed.
        let epoch = GroupEpoch::genesis(
            group_id.clone(),
            roster.iter().map(member_entry).collect(),
            account.ratchet_ref().signing_key(),
            account.ratchet_ref().identity_key(),
            now(),
            |p| account.ratchet_ref().sign(p),
        );
        // A brand-new group starts with the timer off and no picture.
        self.send_group_roster(account, &roster, &epoch, name, Some(0), None)
            .await?;
        Ok((
            Group {
                id: group_id,
                name: name.to_string(),
                members: roster,
            },
            epoch,
        ))
    }
    /// Build a **successor** membership epoch keeping us as admin (add/remove a member).
    /// `admin` is our pinned admin state for the group; `new_members` is the intended full
    /// roster. Fails if we are not the current admin (only the admin can sign a valid epoch).
    pub fn group_membership_epoch(
        &self,
        account: &Account,
        admin: &GroupAdmin,
        group_id: &str,
        new_members: &[GroupMember],
    ) -> Result<GroupEpoch> {
        if admin.admin_identity_key != account.ratchet_ref().identity_key() {
            return Err(ClientError::Protocol(
                "only the group admin can change membership".into(),
            ));
        }
        Ok(GroupEpoch::next(
            admin.epoch_seq + 1,
            group_id.to_string(),
            new_members.iter().map(member_entry).collect(),
            admin.admin_key.clone(),
            admin.admin_identity_key.clone(),
            admin.admin_key.clone(), // signed by us, the current admin
            now(),
            |p| account.ratchet_ref().sign(p),
        ))
    }
    /// Build an **admin-transfer** epoch: hand the admin role to `new_admin` (a current
    /// member). Their account Ed25519 signing key is KT-resolved + verified against the
    /// binding for their username, so we cannot be tricked into naming a key that is not
    /// really theirs. Signed by us (the outgoing admin); after this, only the new admin can
    /// extend the chain.
    pub async fn group_transfer_epoch(
        &self,
        account: &mut Account,
        admin: &GroupAdmin,
        group_id: &str,
        members: &[GroupMember],
        new_admin: &GroupMember,
    ) -> Result<GroupEpoch> {
        if admin.admin_identity_key != account.ratchet_ref().identity_key() {
            return Err(ClientError::Protocol(
                "only the current admin can transfer the admin role".into(),
            ));
        }
        if !members
            .iter()
            .any(|m| m.identity_key == new_admin.identity_key)
        {
            return Err(ClientError::Protocol(
                "the new admin must be a current member".into(),
            ));
        }
        // KT-verify the new admin's account keys: fetch their current binding and confirm it
        // matches the identity key we hold for them, then take its signing key as the new
        // admin authority. A relay cannot substitute a key here without failing verification.
        let hash = IdentityHash::from_identifier(&new_admin.username)
            .as_str()
            .to_string();
        let entry = self.fetch_verified_entry(&hash).await?;
        if entry.identity_key != new_admin.identity_key {
            return Err(ClientError::KtVerification(
                crypto_core::kt::KtCheck::KeyMismatch,
            ));
        }
        Ok(GroupEpoch::next(
            admin.epoch_seq + 1,
            group_id.to_string(),
            members.iter().map(member_entry).collect(),
            entry.signing_key, // new admin authority (Ed25519, KT-verified)
            new_admin.identity_key.clone(), // new admin locator (Curve25519)
            admin.admin_key.clone(), // chains from — and is signed by — the old admin
            now(),
            |p| account.ratchet_ref().sign(p),
        ))
    }
    /// Fan a signed membership epoch (+ group meta) out to `recipients` over their 1:1
    /// sessions as [`ChatPayload::GroupRoster`]. For a removal, pass the FULL old roster
    /// (including the removed member) so they learn they were kicked.
    pub async fn send_group_roster(
        &self,
        account: &mut Account,
        recipients: &[GroupMember],
        epoch: &GroupEpoch,
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
        let me = account.ratchet_ref().identity_key();
        for member in recipients {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
    /// Send a message to a group by fanning it out to every other member over their 1:1
    /// session — establishing (KT-verified) any session we don't yet have. This is how any
    /// member can message the whole group without shared group keys.
    pub async fn send_group(&self, account: &mut Account, group: &Group, body: &str) -> Result<()> {
        self.send_group_timed(account, group, body, None, None, false)
            .await
    }
    /// [`send_group`](Self::send_group) carrying `expire_secs` verbatim inside the
    /// message (wire encoding as in [`prepare_message_replying`]: `None` = don't carry,
    /// `Some(0)` = off, `Some(n)` = n seconds) and an optional quoted-reply reference.
    /// A caller that knows the group timer should pass `Some(timer.unwrap_or(0))`.
    pub async fn send_group_timed(
        &self,
        account: &mut Account,
        group: &Group,
        body: &str,
        expire_secs: Option<u64>,
        reply: Option<crate::ReplyRef>,
        forwarded: bool,
    ) -> Result<()> {
        let ts = now();
        let payload = ChatPayload::GroupText {
            group_id: group.id.clone(),
            body: body.to_string(),
            ts,
            expire_secs,
            reply,
            fwd: forwarded,
        };
        self.fan_group(account, group, &payload).await
    }
    /// Fan one payload out pairwise to every other member (the single-device delivery
    /// shape shared by every group send/control message in this file).
    async fn fan_group(
        &self,
        account: &mut Account,
        group: &Group,
        payload: &ChatPayload,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, payload).await?;
        }
        Ok(())
    }
    /// Edit one of OUR OWN group messages for everyone (recipients enforce ownership by
    /// matching the stored sender). Pair with [`History::edit_group_local`].
    pub async fn send_group_edit(
        &self,
        account: &mut Account,
        group: &Group,
        msg_id: &str,
        body: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupEdit {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
            body: body.to_string(),
        };
        self.fan_group(account, group, &payload).await
    }
    /// Delete one of OUR OWN group messages for everyone (recipients enforce ownership).
    pub async fn send_group_delete_msg(
        &self,
        account: &mut Account,
        group: &Group,
        msg_id: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupDeleteMsg {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
        };
        self.fan_group(account, group, &payload).await
    }
    /// Rename the group for everyone (any member may — same trust model as the roster).
    pub async fn send_group_rename(
        &self,
        account: &mut Account,
        group: &Group,
        name: &str,
    ) -> Result<()> {
        let payload = ChatPayload::GroupRename {
            group_id: group.id.clone(),
            name: name.to_string(),
        };
        self.fan_group(account, group, &payload).await
    }
    /// Tell every member we left the group (their clients drop us from the roster).
    pub async fn send_group_leave(&self, account: &mut Account, group: &Group) -> Result<()> {
        let payload = ChatPayload::GroupLeave {
            group_id: group.id.clone(),
        };
        self.fan_group(account, group, &payload).await
    }
    /// Pin (or unpin) a group message for everyone (any member may — roster trust model).
    pub async fn send_group_pin(
        &self,
        account: &mut Account,
        group: &Group,
        msg_id: &str,
        pin: bool,
    ) -> Result<()> {
        let payload = ChatPayload::GroupPinMsg {
            group_id: group.id.clone(),
            msg_id: msg_id.to_string(),
            pin,
        };
        self.fan_group(account, group, &payload).await
    }
    /// Fan an attachment reference out pairwise to every other member (legacy
    /// single-device path; the multi-device shell uses
    /// [`send_group_file_multi`](Self::send_group_file_multi)). The blob was uploaded
    /// once ([`upload_attachment`](Self::upload_attachment)); every member receives the
    /// same reference, each copy sealed under that pair's ratchet.
    pub async fn send_group_file(
        &self,
        account: &mut Account,
        group: &Group,
        attachment: AttachmentRef,
        expire_secs: Option<u64>,
        forwarded: bool,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupFile {
            group_id: group.id.clone(),
            attachment,
            ts: now(),
            expire_secs,
            fwd: forwarded,
        };
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
    /// Fan a group disappearing-timer change out pairwise to every other member (legacy
    /// single-device path; the multi-device shell uses
    /// [`send_group_timer_multi`](Self::send_group_timer_multi)).
    pub async fn send_group_timer(
        &self,
        account: &mut Account,
        group: &Group,
        secs: Option<u64>,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupTimer {
            group_id: group.id.clone(),
            secs,
        };
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
    /// Resolve a group member to a sendable [`Contact`]: reuse an existing session, or
    /// establish one (KT-verified) from the username.
    pub async fn member_contact(
        &self,
        account: &mut Account,
        member: &GroupMember,
    ) -> Result<Contact> {
        let me = account.ratchet_ref().identity_key();
        if account.ratchet_ref().has_session(&member.identity_key) {
            Ok(Contact {
                username: member.username.clone(),
                identity_hash: IdentityHash::from_identifier(&member.username)
                    .as_str()
                    .to_string(),
                identity_key: member.identity_key.clone(),
                safety_number: safety_number(&me, &member.identity_key),
            })
        } else {
            self.add_contact(account, &member.username).await
        }
    }
    /// Toggle a group emoji reaction, fanned out over every other member's 1:1 session
    /// (same transport as [`send_group`](Self::send_group)).
    pub async fn send_group_reaction(
        &self,
        account: &mut Account,
        group: &Group,
        target_msg_id: &str,
        emoji: &str,
        add: bool,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupReaction {
            group_id: group.id.clone(),
            target_msg_id: target_msg_id.to_string(),
            emoji: emoji.to_string(),
            add,
            ts: now(),
        };
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
    /// Ephemeral group typing signal, fanned out over each other member's 1:1 session.
    pub async fn send_group_typing(
        &self,
        account: &mut Account,
        group: &Group,
        typing: bool,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupTyping {
            group_id: group.id.clone(),
            typing,
        };
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
    /// Tell a contact (over the existing E2E session) that we changed our username, so
    /// their client re-pins us under the new name. Call after the new name is registered
    /// in the KT log; recipients apply it via [`History::rename_contact`].
    pub async fn send_rename(
        &self,
        account: &mut Account,
        contact: &Contact,
        new_username: &str,
    ) -> Result<()> {
        self.send_payload(
            account,
            contact,
            &ChatPayload::Rename {
                new_username: new_username.to_string(),
            },
        )
        .await
        .map(|_| ())
    }
    /// Tell one contact our profile picture changed (`avatar == None` clears it). Broadcast
    /// per-contact over the existing E2E session — the caller loops its address book, exactly
    /// like [`send_rename`](Self::send_rename). Recipients bound + format-check the value.
    pub async fn send_profile(
        &self,
        account: &mut Account,
        contact: &Contact,
        avatar: Option<String>,
    ) -> Result<()> {
        self.send_payload(account, contact, &ChatPayload::Profile { avatar })
            .await
            .map(|_| ())
    }
    /// Fan a group picture change out pairwise to every other member (`avatar == None`
    /// clears it). Same transport + trust model as [`send_group_timer`](Self::send_group_timer).
    pub async fn send_group_avatar(
        &self,
        account: &mut Account,
        group: &Group,
        avatar: Option<String>,
    ) -> Result<()> {
        let me = account.ratchet_ref().identity_key();
        let payload = ChatPayload::GroupAvatar {
            group_id: group.id.clone(),
            avatar,
        };
        for member in &group.members {
            if member.identity_key == me {
                continue;
            }
            let contact = self.member_contact(account, member).await?;
            self.send_payload(account, &contact, &payload).await?;
        }
        Ok(())
    }
}
