use crate::{Client, GroupCoordinator, History, Session};

#[allow(clippy::too_many_arguments)]
pub(super) fn valid_offer_shape(
    ids: &[&str],
    call_id: &str,
    key_b64: &str,
    created_at: u64,
    ring_expires_at: u64,
    expires_at: u64,
    now: u64,
) -> bool {
    ids.iter()
        .all(|id| client_core::callstate::valid_call_id(id))
        && client_core::call::CallTicket::valid(call_id, key_b64)
        && client_core::callstate::valid_offer_deadline(created_at, ring_expires_at)
        && client_core::callstate::valid_signal_deadline(created_at, expires_at)
        && client_core::callstate::valid_control_expiry(expires_at, now)
        && ring_expires_at <= expires_at
}

/// Bind an encrypted device-id claim to the ratchet-authenticated sender key and the
/// locally pinned, KT-verified roster. A never-linked account has only primary device
/// `"0"`; linked IDs are never accepted without a roster entry.
pub(super) fn verified_sender_device(
    history: &History,
    username: &str,
    sender_identity_key: &str,
    device_id: &str,
) -> bool {
    if username.is_empty() || !client_core::callstate::valid_device_id(device_id) {
        return false;
    }
    match history.pinned_roster(username) {
        Some(roster) => roster.devices.iter().any(|device| {
            device.device_id == device_id && device.identity_key == sender_identity_key
        }),
        None => {
            device_id == client_core::PRIMARY_DEVICE_ID
                && history.attribute_device(sender_identity_key) == sender_identity_key
        }
    }
}

pub(super) fn verified_sender_route(
    client: &Client,
    history: &History,
    username: &str,
    identity_key: &str,
    device_id: &str,
    reply_to_mailbox: &str,
) -> bool {
    verified_sender_device(history, username, identity_key, device_id)
        && client.device_mailbox(username, device_id).ok().as_deref() == Some(reply_to_mailbox)
}

pub(super) fn same_peer(history: &History, left_device_key: &str, right_device_key: &str) -> bool {
    history.attribute_device(left_device_key) == history.attribute_device(right_device_key)
}

pub(super) fn verified_group_coordinator(
    client: &Client,
    history: &History,
    group: &client_core::history::GroupRecord,
    username: &str,
    identity_key: &str,
    device_id: &str,
    reply_to_mailbox: &str,
) -> bool {
    let account_key = history.attribute_device(identity_key);
    group.members.iter().any(|member| {
        member.username == username
            && (member.identity_key == account_key || member.identity_key == identity_key)
    }) && verified_sender_route(
        client,
        history,
        username,
        identity_key,
        device_id,
        reply_to_mailbox,
    )
}

pub(super) fn verified_group_member(
    history: &History,
    group: &client_core::history::GroupRecord,
    identity_key: &str,
) -> bool {
    let account_key = history.attribute_device(identity_key);
    group
        .members
        .iter()
        .any(|member| member.identity_key == account_key || member.identity_key == identity_key)
}

pub(super) fn local_group_coordinator(session: &Session, coordinator: &GroupCoordinator) -> bool {
    session.account.as_ref().is_some_and(|account| {
        coordinator.identity_key == account.ratchet_ref().identity_key()
            && coordinator.device_id == session.history.self_device_id()
    })
}
