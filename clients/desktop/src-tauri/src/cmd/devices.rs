use crate::*;

/// Self-audit: confirm the KT log still binds our username to our real keys (catches a
/// rogue entry published under our name). Returns a short verdict string for the UI.
#[tauri::command]
pub async fn audit_own_key(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let account = s.account.as_ref().ok_or("locked")?;
    use client_core::AuditOutcome;
    let verdict = match client
        .audit_own_key(account, &s.history)
        .await
        .map_err(|e| e.to_string())?
    {
        AuditOutcome::Ok => "ok".into(),
        AuditOutcome::RogueKey {
            published_identity_key,
        } => format!("rogue:{published_identity_key}"),
        AuditOutcome::NotRegistered => "not_registered".into(),
    };
    Ok(verdict)
}

/// (New device) Begin linking to an existing account: create this device's local account +
/// vault, mint the link request, and return the QR/short-code JSON to show the primary. The
/// account is held pending until [`complete_link_cmd`] runs. `password` is the account
/// password (used for this device's vault AND to decrypt the synced history).
#[tauri::command]
pub async fn link_start(
    state: tauri::State<'_, AppState>,
    username: String,
    password: String,
) -> Result<String, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("enter your account username".into());
    }
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    if !detect_capabilities(&client).await {
        return Err("this relay does not support multi-device".into());
    }
    // Fail a wrong password BEFORE any QR exists. On a relink (revoked device) or a
    // lock-screen link this install still holds a vault, so the entered password must
    // open it — otherwise a typo only surfaces at complete-link, after the primary has
    // already scanned the code and published a roster epoch for a device that can never
    // finish. A fresh install has nothing local to check against; there the only proof
    // of the password remains decrypting the synced history at complete-link.
    if let Ok(blob) = std::fs::read(s.vault_path()) {
        match unlock_bound(&password, device_key().as_ref(), &blob) {
            Ok(acct) if acct.account_id() == username => {}
            Ok(acct) => {
                return Err(format!(
                    "this device belongs to \"{}\" — enter that username, or clear the app data to link a different account",
                    acct.account_id()
                ));
            }
            Err(_) => return Err("wrong password".into()),
        }
    }
    // A fresh Olm identity for THIS device (its own keys — never the account keys).
    let (account, _vault) =
        create_account_with_username_bound(&username, &password, device_key_or_create().as_ref())
            .map_err(|e| e.to_string())?;
    let mut req = client.create_link_request(&account);
    // Hardware attestation (Android): mint a chain bound to this request and park it on
    // the relay BEFORE the QR exists — the QR carries only the capability id. Both the
    // Keystore mint and a failed upload degrade to "no attestation", never to a failed
    // link: the verdict is advisory and desktop linkers never have one either.
    let challenge =
        client_core::attest::link_attest_challenge(&req.device_id, &req.record.identity_key);
    let chain = tokio::task::spawn_blocking(move || crate::hw_attest::chain(&challenge))
        .await
        .ok()
        .flatten();
    if let Some(chain) = chain {
        if let Err(e) = client.attach_link_attestation(&mut req, &chain).await {
            eprintln!("[hw-attest] upload failed, linking without attestation: {e}");
        }
    }
    let qr = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    s.multi_device = true;
    s.pending_link = Some((account, req));
    Ok(qr)
}

/// (Primary) Check a scanned link request's hardware attestation, if it carries one.
/// Fetches the sealed chain from the relay and verifies it against the pinned Google
/// attestation roots + this request's challenge binding. Advisory UI input for the
/// authorize dialog — never called on the authorize path itself, so a slow relay fetch
/// can't block the ceremony.
#[tauri::command]
pub async fn attest_verdict(
    state: tauri::State<'_, AppState>,
    link_request: String,
) -> Result<AttestView, String> {
    use client_core::attest::{BootState, SecurityLevel};
    let req: LinkRequest = serde_json::from_str(link_request.trim())
        .map_err(|_| "unreadable link code".to_string())?;
    let client = {
        let s = state.inner.lock().await;
        s.client.clone().ok_or("not configured")?
    };
    let chain = match client.fetch_link_attestation(&req).await {
        Ok(None) => {
            return Ok(AttestView {
                status: "absent".into(),
                detail: String::new(),
            })
        }
        Ok(Some(chain)) => chain,
        Err(e) => {
            return Ok(AttestView {
                status: "unavailable".into(),
                detail: e.to_string(),
            })
        }
    };
    match client_core::Client::verify_link_attestation(&req, &chain) {
        Ok(a) => {
            let hw = match a.security_level {
                SecurityLevel::StrongBox => "secure element (StrongBox)",
                _ => "trusted environment (TEE)",
            };
            let boot = match (a.boot_state, a.device_locked) {
                (Some(BootState::Verified), _) => ", stock OS verified boot",
                (Some(BootState::SelfSigned), Some(true)) => ", locked bootloader (custom OS)",
                (Some(BootState::SelfSigned), _) => ", custom OS",
                (Some(BootState::Unverified), _) => ", UNLOCKED bootloader",
                (Some(BootState::Failed), _) => ", boot verification FAILED",
                (None, _) => "",
            };
            Ok(AttestView {
                status: "verified".into(),
                detail: format!("{hw}{boot}"),
            })
        }
        Err(e) => Ok(AttestView {
            status: "failed".into(),
            detail: e.to_string(),
        }),
    }
}

/// (Primary device, unlocked) Authorize a scanned link request: publish the new roster
/// epoch, seal+upload history under the account password + link secret, and PUT the
/// provisioning pointer. Returns the new roster epoch.
#[tauri::command]
pub async fn authorize_device(
    state: tauri::State<'_, AppState>,
    link_request: String,
    account_password: String,
) -> Result<u64, String> {
    let req: LinkRequest = serde_json::from_str(link_request.trim())
        .map_err(|_| "unreadable link code".to_string())?;
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    // Re-verify the account password opens the vault before authorizing (the ceremony gate).
    password_opens_vault(&s, &account_password)?;
    let sess = &mut *s;
    let account = sess.account.as_ref().ok_or("locked")?;
    // Establishing sessions during fan-out needs &mut; authorize itself only signs, so a
    // shared borrow is fine here — clone what we need, then call.
    let seq = client
        .authorize_link(account, &mut sess.history, &req, &account_password)
        .await
        .map_err(|e| e.to_string())?;
    s.multi_device = true;
    s.persist()?;
    Ok(seq)
}

/// (New device) Complete linking after the primary authorized us: fetch + decrypt the
/// synced history (with the account password + our retained link secret), adopt this
/// device's identity, persist, and start delivery.
#[tauri::command]
pub async fn complete_link_cmd(
    state: tauri::State<'_, AppState>,
    account_password: String,
) -> Result<LinkCompleteView, String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let (mut account, req) = s
        .pending_link
        .take()
        .ok_or("no linking in progress — scan the code on your primary device first")?;
    let result = match client
        .complete_link(&mut account, &req, &account_password)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // Keep the pending link so the user can retry (e.g. primary not done yet, or a
            // mistyped password).
            s.pending_link = Some((account, req));
            return Err(e.to_string());
        }
    };
    let id = account.account_id().to_string();
    s.account = Some(account);
    s.history = result.history;
    s.multi_device = true;
    s.persist()?;
    spawn_subscriber(&state.inner, &mut s);
    Ok(LinkCompleteView {
        account_id: id,
        history_synced: result.history_synced,
    })
}

/// (Linked device) Ask the primary to re-export history (transfer expired). Returns the
/// `(provisioning_id, link_secret_b64)` the UI holds to poll with [`poll_resync_cmd`].
#[tauri::command]
pub async fn request_resync(state: tauri::State<'_, AppState>) -> Result<(String, String), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    let out = client
        .request_history_resync(account, &mut sess.history)
        .await
        .map_err(|e| e.to_string())?;
    s.persist()?;
    Ok(out)
}

/// (Linked device) Poll for a re-exported history blob and, if present, import + merge it.
/// Returns true when history was imported.
#[tauri::command]
pub async fn poll_resync_cmd(
    state: tauri::State<'_, AppState>,
    provisioning_id: String,
    link_secret_b64: String,
    account_password: String,
) -> Result<bool, String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    match client
        .poll_resync(&provisioning_id, &link_secret_b64, &account_password)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(imported) => {
            s.history.merge_from(&imported);
            s.persist()?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// (Primary device) Fulfill a linked device's history re-export request. Called after the
/// UI prompt confirms the account password. The `sender_key` must be one of our own
/// devices (checked here before re-sealing anything).
#[tauri::command]
pub async fn fulfill_resync_cmd(
    state: tauri::State<'_, AppState>,
    sender_key: String,
    provisioning_id: String,
    link_secret_b64: String,
    account_password: String,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    password_opens_vault(&s, &account_password)?;
    if !s.history.is_own_device(&sender_key) {
        return Err("re-export request is not from one of your devices".into());
    }
    client
        .fulfill_resync(
            &s.history,
            &provisioning_id,
            &link_secret_b64,
            &account_password,
        )
        .await
        .map_err(|e| e.to_string())
}

/// List this account's devices (from the locally pinned roster). Empty ⇒ single-device.
#[tauri::command]
pub async fn list_devices(state: tauri::State<'_, AppState>) -> Result<Vec<DeviceView>, String> {
    let s = state.inner.lock().await;
    let account = s.account.as_ref().ok_or("locked")?;
    let this = s.history.self_device_id();
    let Some(pin) = s.history.pinned_roster(account.account_id()) else {
        return Ok(Vec::new());
    };
    Ok(pin
        .devices
        .iter()
        .map(|d| DeviceView {
            device_id: d.device_id.clone(),
            is_this_device: d.device_id == this,
            is_primary: d.device_id == "0",
        })
        .collect())
}

/// (Primary device) Revoke a linked device: publish a roster epoch without it. Returns the
/// new epoch.
#[tauri::command]
pub async fn revoke_device(
    state: tauri::State<'_, AppState>,
    device_id: String,
) -> Result<u64, String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let sess = &mut *s;
    let account = sess.account.as_ref().ok_or("locked")?;
    let seq = client
        .revoke_device(account, &mut sess.history, device_id.trim())
        .await
        .map_err(|e| e.to_string())?;
    s.persist()?;
    Ok(seq)
}

/// Self-audit our own account's device roster for a device we never enrolled (a rogue
/// enrollment). Returns "single_device", "ok:N", or "rogue:id1,id2".
#[tauri::command]
pub async fn audit_devices(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let account = s.account.as_ref().ok_or("locked")?;
    let verdict = match client
        .audit_own_roster(account, &s.history)
        .await
        .map_err(|e| e.to_string())?
    {
        RosterAudit::SingleDevice => "single_device".into(),
        RosterAudit::Ok { devices, .. } => format!("ok:{devices}"),
        RosterAudit::UnknownDevices {
            unknown_device_ids, ..
        } => format!("rogue:{}", unknown_device_ids.join(",")),
    };
    Ok(verdict)
}

/// (Primary device) Offer primary ownership to a linked device. Gated on the account
/// password (the same ceremony as authorizing a device). The transfer completes only
/// when the target accepts with ITS password; until then this device stays the primary.
#[tauri::command]
pub async fn transfer_primary(
    state: tauri::State<'_, AppState>,
    device_id: String,
    account_password: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    password_opens_vault(&s, &account_password)?;
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    client
        .offer_primary_transfer(account, &mut sess.history, device_id.trim())
        .await
        .map_err(|e| e.to_string())?;
    s.persist()?;
    Ok(())
}

/// (Linked device) Accept the pending primary-transfer offer: publish the rotation +
/// the new roster, become the primary, and re-subscribe on the account mailbox. Gated on
/// the account password. On failure the offer is kept so the user can retry.
#[tauri::command]
pub async fn accept_primary_cmd(
    state: tauri::State<'_, AppState>,
    account_password: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    password_opens_vault(&s, &account_password)?;
    let pending = s
        .history
        .pending_promotion()
        .cloned()
        .ok_or("no primary transfer is pending on this device")?;
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    // The pending offer stays in history on failure, so the user can retry (the accept
    // is idempotent across partial completion).
    client
        .accept_primary_transfer(account, &mut sess.history, &pending.entry, &pending.demoted)
        .await
        .map_err(|e| e.to_string())?;
    s.history.clear_pending_promotion();
    s.persist()?;
    // This device now owns the account mailbox — switch the delivery loop over.
    spawn_subscriber(&state.inner, &mut s);
    Ok(())
}

/// (Old primary) Poll whether an offered primary transfer completed; if so, demote this
/// device to its linked identity and re-subscribe on its device mailbox. Returns
/// "none" (nothing pending), "pending", or "demoted". Cheap when nothing is pending.
#[tauri::command]
pub async fn check_transfer_cmd(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut s = state.inner.lock().await;
    // A recorded pending transfer polls. Beyond that, any multi-device primary
    // reconciles against the KT log — a crash that lost the pending marker after the
    // offer went out must not leave a device that thinks it is primary while the
    // binding (and the account mailbox) already moved. Single-device accounts
    // (no roster ever published) skip the network entirely.
    let multi_device_primary =
        s.history.is_primary_device() && s.history.self_roster_seq().is_some();
    if s.history.pending_demotion().is_none() && !multi_device_primary {
        return Ok("none".into());
    }
    let client = s.client.clone().ok_or("not configured")?;
    let sess = &mut *s;
    let account = sess.account.as_ref().ok_or("locked")?;
    let demoted = client
        .finish_primary_demotion(account, &mut sess.history)
        .await
        .map_err(|e| e.to_string())?;
    if !demoted {
        return Ok("pending".into());
    }
    // Stock our new device mailbox with one-time keys right away (best-effort; the
    // unlock path also does this) so peers can start sessions without waiting.
    {
        let sess = &mut *s;
        if let Some(account) = sess.account.as_mut() {
            let username = account.account_id().to_string();
            let device_id = sess.history.self_device_id();
            let _ = client
                .replenish_device_keys(account, &username, &device_id, 20)
                .await;
        }
    }
    s.persist()?;
    spawn_subscriber(&state.inner, &mut s);
    Ok("demoted".into())
}

/// Nudge the UI to reload from local history (pull-to-refresh). Live delivery is push-based
/// via the subscription, so this is just a manual repaint.
#[tauri::command]
pub async fn poll_now() -> Result<(), String> {
    eng().emit("sync", ());
    Ok(())
}
