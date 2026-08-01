use crate::*;

/// Repair a conversation that has gone one-way silent: drop our ratchet sessions with
/// every device of this contact so the next message performs a fresh handshake.
///
/// A desynced session cannot self-heal. We keep encrypting to it happily while the peer's
/// decrypt yields `NoSession` and drops the message — both ends still show "connected", so
/// it is indistinguishable from nobody writing. A non-prekey message carries no cleartext
/// sender, so the peer cannot even tell us which session to reset: the repair has to be
/// driven from this side. Their copy is untouched — they bootstrap a new inbound session
/// from our next pre-key message. Records a system chip so the repair is visible in the
/// transcript. Returns how many device sessions were dropped (0 is equally fine: nothing
/// was established in the first place).
/// Automatic half of the session repair, run before every 1:1 send.
///
/// If our recent sends to `peer` were never acknowledged we are almost certainly
/// encrypting into a session they can no longer open — invisible to us, and it never
/// recovers on its own (`ensure_device_session` reuses whatever already exists). Dropping
/// ours makes the message we are about to send a fresh handshake, which they bootstrap
/// automatically, so a broken conversation heals on the next thing the user types.
///
/// The decision is made entirely from LOCAL state and is rate-limited
/// ([`History::session_looks_dead`]), so nothing remote — a peer, or the relay — can
/// provoke a reset. That is deliberate: the obvious alternative (the receiver asking peers
/// to reset when it sees undecryptable traffic) is exploitable, because anyone can post
/// junk ciphertext into a mailbox and the resulting burst of requests would enumerate that
/// user's contacts. A false positive here costs exactly one extra handshake and loses
/// nothing — the peer keeps their existing sessions alongside the new one.
///
/// Best-effort: a failure must never block the send.
pub(crate) async fn auto_reset_if_dead(
    s: &mut Session,
    client: &Arc<Client>,
    username: &str,
    peer: &str,
) {
    if !s.history.session_looks_dead(peer, now_secs()) {
        return;
    }
    let Some(account) = s.account.as_mut() else {
        return;
    };
    match client
        .reset_sessions_with(account, &mut s.history, username, peer)
        .await
    {
        Ok(_) => {
            s.history.mark_session_reset(peer, now_secs());
            s.history
                .record_system(peer, "Secure session reset automatically", now_secs());
            let _ = s.persist();
        }
        Err(e) => crate::diag!("client: auto session reset failed: {e}"),
    }
}

#[tauri::command]
pub async fn reset_secure_session(
    state: tauri::State<'_, AppState>,
    username: String,
    peer: String,
) -> Result<usize, String> {
    let mut s = state.inner.lock().await;
    let client = s.client.clone().ok_or("not configured")?;
    let sess = &mut *s;
    let account = sess.account.as_mut().ok_or("locked")?;
    let dropped = client
        .reset_sessions_with(account, &mut sess.history, username.trim(), peer.trim())
        .await
        .map_err(|e| e.to_string())?;
    sess.history
        .record_system(peer.trim(), "Secure session reset", now_secs());
    sess.persist()?;
    Ok(dropped)
}

#[tauri::command]
pub async fn security_status(state: tauri::State<'_, AppState>) -> Result<SecurityView, String> {
    let os_auth = match bio::availability_async().await {
        bio::OsAuth::Biometric => "biometric",
        bio::OsAuth::CredentialOnly => "credential",
        bio::OsAuth::None => "none",
    };
    let s = state.inner.lock().await;
    Ok(SecurityView {
        pin_set: s.quick_pin_path().exists(),
        pin_attempts_left: MAX_PIN_ATTEMPTS.saturating_sub(s.prefs.pin_attempts),
        auto_unlock: s.prefs.auto_unlock && s.quick_auto_path().exists(),
        bio_enabled: s.prefs.bio_enabled && s.quick_bio_path().exists(),
        bio_available: os_auth == "biometric",
        os_auth,
        device_key_available: device_key().is_some(),
        lock_after_secs: s.prefs.lock_after_secs,
        pin_reminder_every: s.prefs.pin_reminder_every,
        ceremony_min_pin_len: quick::CEREMONY_MIN_PIN_LEN,
    })
}

/// Live PIN-policy check for the set-PIN form.
#[tauri::command]
pub fn pin_strength(pin: String) -> serde_json::Value {
    let r = quick::check_pin(&pin);
    serde_json::json!({
        "acceptable": r.acceptable,
        "problems": r.problems,
        "ceremony_grade": r.ceremony_grade,
    })
}

/// Verify the vault password without changing any state (ceremony step 1, and the gate
/// for enabling any quick-unlock method). Argon2 runs once — intentionally not free.
pub(crate) fn password_opens_vault(s: &Session, password: &str) -> Result<(), String> {
    let blob = std::fs::read(s.vault_path()).map_err(|_| "no vault on this device")?;
    unlock_bound(password, device_key().as_ref(), &blob)
        .map(|_| ())
        .map_err(|_| "wrong password".to_string())
}

#[tauri::command]
pub async fn verify_password(
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let s = state.inner.lock().await;
    password_opens_vault(&s, &password)
}

/// Check a PIN against the wrapped blob, counting failures: [`MAX_PIN_ATTEMPTS`] wrong
/// entries wipe the blob (password becomes the only way in). Success resets the counter
/// and returns the unwrapped seal key.
pub(crate) fn check_pin_counting(s: &mut Session, pin: &str) -> Result<SealKey, String> {
    let path = s.quick_pin_path();
    let blob = std::fs::read(&path)
        .map_err(|_| "no unlock PIN is set — add one in Settings → Security")?;
    let dk = device_key().ok_or("OS key store unavailable — use your password")?;
    match quick::unwrap_seal_key_pin(pin, &dk, &blob) {
        Ok(key) => {
            if s.prefs.pin_attempts != 0 {
                s.prefs.pin_attempts = 0;
                let _ = s.save_prefs();
            }
            Ok(key)
        }
        Err(_) => {
            s.prefs.pin_attempts += 1;
            if s.prefs.pin_attempts >= MAX_PIN_ATTEMPTS {
                // Wipe: the PIN path is gone; the password (full Argon2 + device key)
                // remains. This is what makes an on-device guessing loop pointless.
                let _ = std::fs::remove_file(&path);
                s.prefs.pin_attempts = 0;
                let _ = s.save_prefs();
                return Err("too many wrong PINs — PIN unlock disabled, use your password".into());
            }
            let left = MAX_PIN_ATTEMPTS - s.prefs.pin_attempts;
            let _ = s.save_prefs();
            Err(format!("wrong PIN — {left} attempts left"))
        }
    }
}

/// Set (or replace) the unlock PIN. Requires the password: a snatched *unlocked* device
/// must not be enough to plant a new PIN for later re-entry.
#[tauri::command]
pub async fn set_pin(
    state: tauri::State<'_, AppState>,
    password: String,
    pin: String,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let account = s.account.as_ref().ok_or("locked")?;
    let strength = quick::check_pin(&pin);
    if !strength.acceptable {
        return Err(format!("PIN needs: {}", strength.problems.join(", ")));
    }
    let dk = device_key()
        .ok_or("no OS key store on this device — PIN unlock can't be enabled safely")?;
    let seal = SealKey::from_bytes(&account.seal_key_bytes()).map_err(|e| e.to_string())?;
    password_opens_vault(&s, &password)?;
    let blob = quick::wrap_seal_key_pin(&seal, &pin, &dk).map_err(|e| e.to_string())?;
    std::fs::write(s.quick_pin_path(), blob).map_err(|e| e.to_string())?;
    s.prefs.pin_attempts = 0;
    s.save_prefs()
}

#[tauri::command]
pub async fn disable_pin(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    let _ = std::fs::remove_file(s.quick_pin_path());
    s.prefs.pin_attempts = 0;
    s.save_prefs()
}

/// Unlock with the PIN (device key + attempt counter enforced — see `crypto_core::quick`).
#[tauri::command]
pub async fn unlock_pin(state: tauri::State<'_, AppState>, pin: String) -> Result<String, String> {
    let mut s = state.inner.lock().await;
    let seal = check_pin_counting(&mut s, &pin)?;
    let blob = std::fs::read(s.vault_path()).map_err(|_| "no vault on this device")?;
    let account = unlock_with_seal_key(&seal.to_bytes(), &blob).map_err(|e| e.to_string())?;
    finish_unlock(&state.inner, &mut s, account).await
}

/// Re-verify the PIN while unlocked (periodic reminder). Success resets the reminder
/// counter; failures count against the same attempt limit as the lock screen.
#[tauri::command]
pub async fn verify_pin(state: tauri::State<'_, AppState>, pin: String) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    check_pin_counting(&mut s, &pin)?;
    s.prefs.opens_since_pin_check = 0;
    s.save_prefs()
}

/// Authorize turning a quick-unlock method **on**. Either knowledge factor does it: the
/// vault password, or the unlock PIN when one is set. Both already open the vault on their
/// own, so neither weakens the gate; what must never be enough is bare possession of an
/// *unlocked* session, or a snatched phone could be given a new way back in. PIN failures
/// count against the same attempt limit as the lock screen (see [`check_pin_counting`] —
/// `MAX_PIN_ATTEMPTS` wrong entries wipe the PIN blob).
pub(crate) fn authorize_quick_enable(
    s: &mut Session,
    password: Option<&str>,
    pin: Option<&str>,
) -> Result<(), String> {
    let pin = pin.filter(|p| !p.is_empty());
    let password = password.filter(|p| !p.is_empty());
    match (pin, password) {
        (Some(pin), _) => check_pin_counting(s, pin).map(|_| ()),
        (None, Some(password)) => password_opens_vault(s, password),
        (None, None) => Err("your password or unlock PIN is required".into()),
    }
}

/// Toggle auto-unlock (open the vault at startup with no prompt). The seal key is
/// wrapped under the OS-keyring/Keystore device key alone — possession of the unlocked
/// OS session becomes the gate; the blob is useless off-device. Password *or* PIN required
/// to enable, for the same reason as [`set_pin`].
#[tauri::command]
pub async fn set_auto_unlock(
    state: tauri::State<'_, AppState>,
    password: Option<String>,
    pin: Option<String>,
    enable: bool,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if enable {
        // Mutually exclusive with fingerprint unlock: silent auto-unlock would make the
        // biometric gate decorative (the same vault opens with no auth at all).
        if s.prefs.bio_enabled && s.quick_bio_path().exists() {
            return Err(
                "fingerprint unlock is on — turn it off first; only one of auto-unlock and fingerprint unlock can be enabled".into(),
            );
        }
        if s.account.is_none() {
            return Err("locked".into());
        }
        let dk = device_key()
            .ok_or("no OS key store on this device — auto-unlock can't be enabled safely")?;
        authorize_quick_enable(&mut s, password.as_deref(), pin.as_deref())?;
        let account = s.account.as_ref().ok_or("locked")?;
        let seal = SealKey::from_bytes(&account.seal_key_bytes()).map_err(|e| e.to_string())?;
        let blob = quick::wrap_seal_key_auto(&seal, &dk).map_err(|e| e.to_string())?;
        std::fs::write(s.quick_auto_path(), blob).map_err(|e| e.to_string())?;
        s.prefs.auto_unlock = true;
    } else {
        let _ = std::fs::remove_file(s.quick_auto_path());
        s.prefs.auto_unlock = false;
    }
    s.save_prefs()
}

/// Startup path when auto-unlock is on. `Ok(None)` = not enabled / not possible (fall
/// through to the lock screen); a stale blob (e.g. after a password change on another
/// path) disables itself.
#[tauri::command]
pub async fn try_auto_unlock(state: tauri::State<'_, AppState>) -> Result<Option<String>, String> {
    let mut s = state.inner.lock().await;
    if s.account.is_some() {
        return Ok(s.account.as_ref().map(|a| a.account_id().to_string()));
    }
    let Some(account) = attempt_auto_unlock(&mut s) else {
        return Ok(None);
    };
    finish_unlock(&state.inner, &mut s, account).await.map(Some)
}

/// The silent auto-unlock attempt itself, shared by the startup command above and the
/// headless entry points (sticky restart, boot, push wake — docs/NOTIFICATIONS.md §4.4). No prompt,
/// no biometric: the `quick_auto.bin` blob variant is wrapped by the Keystore device
/// key alone (Signal's at-rest model). A stale/corrupt blob disables itself so the
/// user falls back to the interactive unlock instead of looping.
pub(crate) fn attempt_auto_unlock(s: &mut Session) -> Option<Account> {
    if !s.prefs.auto_unlock {
        return None;
    }
    // Exclusivity guard for pre-existing state where both ended up on: the lock screen
    // (with its fingerprint prompt) wins over silent auto-unlock.
    if s.prefs.bio_enabled && s.quick_bio_path().exists() {
        return None;
    }
    let blob = std::fs::read(s.quick_auto_path()).ok()?;
    let dk = device_key()?;
    let Ok(seal) = quick::unwrap_seal_key_auto(&dk, &blob) else {
        // Stale (seal key rotated) or corrupt: drop it, fall back to interactive unlock.
        let _ = std::fs::remove_file(s.quick_auto_path());
        s.prefs.auto_unlock = false;
        let _ = s.save_prefs();
        return None;
    };
    let vault_blob = std::fs::read(s.vault_path()).ok()?;
    match unlock_with_seal_key(&seal.to_bytes(), &vault_blob) {
        Ok(account) => Some(account),
        Err(_) => {
            let _ = std::fs::remove_file(s.quick_auto_path());
            s.prefs.auto_unlock = false;
            let _ = s.save_prefs();
            None
        }
    }
}

/// Enable biometric (fingerprint) unlock — Android only. The seal key is wrapped by a
/// non-exportable Keystore key requiring a BIOMETRIC_STRONG auth per use; enabling
/// prompts for a fingerprint (the wrap itself is auth-gated). Password *or* PIN required,
/// as with every quick-unlock enable (see [`authorize_quick_enable`]).
#[tauri::command]
pub async fn set_bio_unlock(
    state: tauri::State<'_, AppState>,
    password: Option<String>,
    pin: Option<String>,
    enable: bool,
) -> Result<(), String> {
    if !enable {
        let mut s = state.inner.lock().await;
        let _ = std::fs::remove_file(s.quick_bio_path());
        s.prefs.bio_enabled = false;
        return s.save_prefs();
    }
    // Verify + export under the lock, run the (slow, user-facing) prompt without it.
    let (seal_bytes, bio_path) = {
        let mut s = state.inner.lock().await;
        // Mutually exclusive with auto-unlock (see `set_auto_unlock`).
        if s.prefs.auto_unlock && s.quick_auto_path().exists() {
            return Err(
                "auto-unlock is on — turn it off first; only one of auto-unlock and fingerprint unlock can be enabled".into(),
            );
        }
        if s.account.is_none() {
            return Err("locked".into());
        }
        authorize_quick_enable(&mut s, password.as_deref(), pin.as_deref())?;
        let account = s.account.as_ref().ok_or("locked")?;
        (account.seal_key_bytes().to_vec(), s.quick_bio_path())
    };
    let blob = bio::enroll_async(seal_bytes).await?;
    std::fs::write(&bio_path, blob).map_err(|e| e.to_string())?;
    let mut s = state.inner.lock().await;
    s.prefs.bio_enabled = true;
    s.save_prefs()
}

/// Unlock with a fingerprint (Android). The Keystore key gates the unwrap; a new
/// fingerprint enrollment invalidates it (then this fails and the UI falls back).
#[tauri::command]
pub async fn unlock_bio(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let bio_path = {
        let s = state.inner.lock().await;
        s.quick_bio_path()
    };
    let blob = std::fs::read(&bio_path).map_err(|_| "biometric unlock is not set up")?;
    let seal_bytes = zeroize::Zeroizing::new(bio::unwrap_async(blob).await?);
    let mut s = state.inner.lock().await;
    let vault_blob = std::fs::read(s.vault_path()).map_err(|_| "no vault on this device")?;
    let account = unlock_with_seal_key(&seal_bytes, &vault_blob).map_err(|e| e.to_string())?;
    finish_unlock(&state.inner, &mut s, account).await
}

/// Ceremony step 2 (Android): fingerprint, or the device credential when no fingerprint
/// is enrolled, or an automatic pass when the device has neither (per spec). Records the
/// pass; [`ceremony_gate`] requires it to be recent. Desktop: automatic pass.
#[tauri::command]
pub async fn os_presence_check(state: tauri::State<'_, AppState>) -> Result<&'static str, String> {
    let verified = bio::presence_check_async().await?;
    let mut s = state.inner.lock().await;
    s.last_presence_ok = Some(std::time::Instant::now());
    Ok(if verified { "checked" } else { "skipped" })
}

/// The full gate for account-changing ceremonies, re-verified atomically at the final
/// step (the UI walks the user through the same order, but the UI is not trusted):
/// 1. current password opens the vault;
/// 2. a recent OS presence check (Android; desktop has no OS step);
/// 3. the app PIN — which must exist and be ceremony-grade (≥ 6 chars).
pub(crate) fn ceremony_gate(
    s: &mut Session,
    current_password: &str,
    pin: &str,
) -> Result<(), String> {
    password_opens_vault(s, current_password)?;
    if cfg!(target_os = "android") {
        match s.last_presence_ok {
            Some(t) if t.elapsed().as_secs() < PRESENCE_WINDOW_SECS => {}
            _ => {
                return Err("OS verification missing or expired — redo the fingerprint step".into())
            }
        }
    }
    if !s.quick_pin_path().exists() {
        return Err(format!(
            "account changes require an unlock PIN of {}+ characters — set one in Settings → Security first",
            quick::CEREMONY_MIN_PIN_LEN
        ));
    }
    if pin.chars().count() < quick::CEREMONY_MIN_PIN_LEN {
        return Err(format!(
            "account changes require a PIN of {}+ characters — lengthen your PIN first",
            quick::CEREMONY_MIN_PIN_LEN
        ));
    }
    check_pin_counting(s, pin).map(|_| ())
}

/// Change the vault password. Full ceremony, then: re-key the vault (fresh Argon2 seal
/// key), re-wrap the PIN and auto-unlock blobs under the new seal key, and drop the
/// biometric blob (its Keystore wrap covers the old key; re-enable prompts afresh).
/// Returns `true` when biometric unlock was disabled and needs re-enabling.
#[tauri::command]
pub async fn change_password(
    state: tauri::State<'_, AppState>,
    current_password: String,
    pin: String,
    new_password: String,
) -> Result<bool, String> {
    let mut s = state.inner.lock().await;
    s.account.as_ref().ok_or("locked")?;
    ceremony_gate(&mut s, &current_password, &pin)?;
    let dk = device_key();
    let account = s.account.as_mut().ok_or("locked")?;
    let new_blob = account
        .rekey(&new_password, dk.as_ref())
        .map_err(|e| e.to_string())?;
    std::fs::write(s.vault_path(), new_blob).map_err(|e| e.to_string())?;

    // Every quick-unlock blob wrapped the OLD seal key — rotate them now.
    let account = s.account.as_ref().ok_or("locked")?;
    let seal = SealKey::from_bytes(&account.seal_key_bytes()).map_err(|e| e.to_string())?;
    if s.quick_pin_path().exists() {
        if let Some(dk) = dk.as_ref() {
            // The ceremony just verified this PIN, so re-wrapping with it is safe.
            let blob = quick::wrap_seal_key_pin(&seal, &pin, dk).map_err(|e| e.to_string())?;
            std::fs::write(s.quick_pin_path(), blob).map_err(|e| e.to_string())?;
        } else {
            let _ = std::fs::remove_file(s.quick_pin_path());
        }
    }
    if s.prefs.auto_unlock {
        match dk.as_ref() {
            Some(dk) => {
                let blob = quick::wrap_seal_key_auto(&seal, dk).map_err(|e| e.to_string())?;
                std::fs::write(s.quick_auto_path(), blob).map_err(|e| e.to_string())?;
            }
            None => {
                let _ = std::fs::remove_file(s.quick_auto_path());
                s.prefs.auto_unlock = false;
            }
        }
    }
    let bio_dropped = s.prefs.bio_enabled;
    if bio_dropped {
        let _ = std::fs::remove_file(s.quick_bio_path());
        s.prefs.bio_enabled = false;
    }
    let _ = s.save_prefs();
    s.persist()?;
    Ok(bio_dropped)
}

/// Change the username. Full ceremony, then: swap the account id, publish a fresh KT
/// claim + registration under the new name (the relay's first-come rule rejects taken
/// names — we revert on failure), record the old name (its mailbox keeps being drained),
/// and tell every contact over the existing E2E sessions so their address books follow.
#[tauri::command]
pub async fn change_username(
    state: tauri::State<'_, AppState>,
    current_password: String,
    pin: String,
    new_username: String,
    confirm_unlink: bool,
) -> Result<String, String> {
    let new_username = new_username.trim().to_string();
    let mut s = state.inner.lock().await;
    s.account.as_ref().ok_or("locked")?;
    ceremony_gate(&mut s, &current_password, &pin)?;
    let client = s.client.clone().ok_or("not configured")?;

    // Product limit: at most MAX_RENAMES_PER_WEEK changes per rolling week (the relay
    // additionally backstops the release side per signing key).
    {
        let (used, next_free) = s.history.renames_in_window(now_secs());
        if used >= client_core::history::MAX_RENAMES_PER_WEEK {
            let wait = next_free
                .map(|t| t.saturating_sub(now_secs()))
                .unwrap_or(0)
                .max(1);
            return Err(format!(
                "username-change limit reached ({} per week) — next change possible in ~{}",
                client_core::history::MAX_RENAMES_PER_WEEK,
                human_duration(wait)
            ));
        }
    }

    // Contacts to notify (skip blocked): gathered before mutating anything.
    let notify: Vec<(String, String)> = s
        .history
        .contacts()
        .into_iter()
        .filter(|(_, p)| !p.blocked)
        .map(|(u, p)| (u, p.identity_key))
        .collect();

    // Renaming is a single-device ceremony: device rosters and device mailboxes are
    // derived from the username hash, and linked devices cannot re-sign their roster
    // records for the new hash from here. Non-primary devices are refused outright;
    // linked devices are unlinked first — but only with the user's explicit,
    // count-aware confirmation from the UI dialog.
    if !s.history.is_primary_device() {
        return Err("only the primary device can change the username".into());
    }
    // A primary transfer in flight means the primary role itself is moving — renaming
    // under it invites split-brain. Finish (or let it lapse) first.
    if s.history.pending_demotion().is_some() || s.history.pending_promotion().is_some() {
        return Err("a primary transfer is in progress — finish it before renaming".into());
    }
    {
        let sess = &mut *s;
        let account = sess.account.as_ref().ok_or("locked")?;
        let username = account.account_id().to_string();
        let me = client
            .resolve_account_devices(&mut sess.history, &username)
            .await
            .map_err(|e| e.to_string())?;
        let linked: Vec<String> = me
            .devices
            .iter()
            .filter(|d| d.device_id != client_core::PRIMARY_DEVICE_ID)
            .map(|d| d.device_id.clone())
            .collect();
        if !linked.is_empty() {
            if !confirm_unlink {
                // Structured refusal the UI turns into an "are you sure" dialog.
                return Err(format!("confirm_unlink:{}", linked.len()));
            }
            // Confirmed: revoke every linked device (each gets kicked onto the relink
            // screen), then re-verify the roster really is primary-only before the
            // point of no return.
            for device_id in &linked {
                client
                    .revoke_device(account, &mut sess.history, device_id)
                    .await
                    .map_err(|e| format!("could not unlink device: {e}"))?;
            }
            let me = client
                .resolve_account_devices(&mut sess.history, &username)
                .await
                .map_err(|e| e.to_string())?;
            if me.devices.len() > 1 {
                return Err("a device is still linked — try again".into());
            }
        }
    }

    let account = s.account.as_mut().ok_or("locked")?;
    let old_username = account.account_id().to_string();
    if new_username == old_username {
        return Err("that is already your username".into());
    }
    account.rename(&new_username).map_err(|e| e.to_string())?;
    // Registration appends the KT claim for the new name; a taken name (or any relay
    // refusal) fails the whole ceremony and we revert to the old identity.
    if let Err(e) = client.register(account, 20).await {
        let _ = account.rename(&old_username);
        s.persist()?; // the ratchet minted keys during the attempt — keep state coherent
        return Err(format!("could not claim that username: {e}"));
    }

    // Point of no return: new name registered. Old mailbox stays ours (same keys) and
    // keeps draining; the release starts the 7-day clock after which the old name
    // becomes claimable by anyone (we can take it back any time before that).
    let release_failed = client
        .release_username(account, &old_username)
        .await
        .is_err();
    s.history.note_own_rename(&old_username, &new_username);
    s.history.note_rename_time(now_secs());
    let account = s.account.as_mut().ok_or("locked")?;
    let mut failed = 0usize;
    for (username, key) in &notify {
        if !account.ratchet_ref().has_session(key) {
            continue; // they'll learn the new name from the next message's `from` field
        }
        let contact = contact_for(username, key);
        if client
            .send_rename(account, &contact, &new_username)
            .await
            .is_err()
        {
            failed += 1;
        }
    }
    s.persist()?;
    // Re-subscribe: main loop moves to the new hash; the old name joins the alias drains.
    spawn_subscriber(&state.inner, &mut s);
    let mut notes = Vec::new();
    if failed > 0 {
        notes.push(format!(
            "{failed} contact notice(s) failed — they'll still see the new name on your next message"
        ));
    }
    if release_failed {
        notes.push(format!(
            "'{old_username}' could not be released and stays reserved to you"
        ));
    }
    if notes.is_empty() {
        Ok(new_username)
    } else {
        Ok(format!("{new_username} ({})", notes.join("; ")))
    }
}

/// Wipe every trace of the account from this device: sealed vault, sealed history,
/// every quick-unlock blob, and the prefs (reset to defaults — they may reference the
/// dead push endpoint / unlock blobs). The relay config stays: it is the pinned trust
/// anchor for the relay itself, not for any account, and the user lands on the
/// account-creation screen for the same relay.
fn wipe_local_account(s: &mut Session) {
    // Stop delivery first — a live subscriber must not observe (and react to) the
    // account state being torn down under it.
    if let Some(stop) = s.stop.take() {
        let _ = stop.send(true);
    }
    delivery_service::set_background_delivery(false);
    let _ = std::fs::remove_file(s.vault_path());
    let _ = std::fs::remove_file(s.history_path());
    let _ = std::fs::remove_file(s.quick_pin_path());
    let _ = std::fs::remove_file(s.quick_auto_path());
    let _ = std::fs::remove_file(s.quick_bio_path());
    // The call-control identity is not in the vault, so it needs its own erasure.
    wipe_call_identity(s);
    s.prefs = Prefs::default();
    let _ = s.save_prefs();
    // `Account` zeroizes its secrets on drop.
    s.account = None;
    s.history = History::new();
    // Every presentation handle this account handed the platform comes back: an account
    // that no longer exists must not leave a system call the user cannot end.
    for ring_handle in eng().system_calls() {
        eng().end_system_call(&ring_handle, telecom::cause::LOCAL);
    }
    s.call = None;
    s.incoming = None;
    s.claiming = None;
    s.reconnect = None;
    s.call_bindings.clear();
    s.group_call = None;
    s.group_incoming = None;
    s.group_claiming = None;
    s.pending_link = None;
    s.last_presence_ok = None;
}

/// Delete the account. **Primary device only**, and the full account-change ceremony —
/// the same triple gate as a username/password change (password → OS presence → PIN),
/// re-verified atomically here, plus a typed username confirmation the backend checks
/// itself (the UI is not trusted).
///
/// Order of operations, chosen so every failure leaves a *usable* account:
/// 1. unlink every linked device (KT roster shrinks to primary-only, so each lands on
///    its lockout screen through the verified revocation path — never a retry loop);
/// 2. release the current and all former usernames in the KT log (signed entries; the
///    names become claimable after the grace period). Best-effort: a refused release
///    (e.g. the weekly release budget) is reported, not fatal — that name simply stays
///    reserved forever;
/// 3. the relay-side deletion (challenge-signed): directory records, device mailboxes,
///    queued ciphertext, push subscriptions — the point of no return;
/// 4. the local wipe (vault, history, unlock blobs, prefs).
///
/// The KT log keeps its entries — it is append-only and public by design; the release
/// entries are what unbind the names.
#[tauri::command]
pub async fn delete_account(
    state: tauri::State<'_, AppState>,
    current_password: String,
    pin: String,
    confirm_username: String,
) -> Result<String, String> {
    let mut s = state.inner.lock().await;
    s.account.as_ref().ok_or("locked")?;
    ceremony_gate(&mut s, &current_password, &pin)?;
    let client = s.client.clone().ok_or("not configured")?;

    let username = s
        .account
        .as_ref()
        .map(|a| a.account_id().to_string())
        .ok_or("locked")?;
    if confirm_username.trim() != username {
        return Err("username confirmation does not match".into());
    }
    if !s.history.is_primary_device() {
        return Err("only the primary device can delete the account".into());
    }
    if s.history.pending_demotion().is_some() || s.history.pending_promotion().is_some() {
        return Err("a primary transfer is in progress — finish it before deleting".into());
    }

    // 1. Unlink every linked device. Abort on failure: a device left both linked in the
    // KT roster and cut off by the relay deletion would loop on an inconclusive
    // revocation check instead of landing on its lockout screen.
    if s.multi_device {
        let sess = &mut *s;
        let account = sess.account.as_ref().ok_or("locked")?;
        let me = client
            .resolve_account_devices(&mut sess.history, &username)
            .await
            .map_err(|e| e.to_string())?;
        let linked: Vec<String> = me
            .devices
            .iter()
            .filter(|d| d.device_id != client_core::PRIMARY_DEVICE_ID)
            .map(|d| d.device_id.clone())
            .collect();
        for device_id in &linked {
            client
                .revoke_device(account, &mut sess.history, device_id)
                .await
                .map_err(|e| format!("could not unlink device: {e}"))?;
        }
    }

    // 2. Release the names (current first, then former ones still draining). A refused
    // release is a note, never a blocker — the deletion below still cuts the account.
    let mut notes = Vec::new();
    {
        let account = s.account.as_ref().ok_or("locked")?;
        let mut names = vec![username.clone()];
        names.extend(s.history.previous_usernames().iter().cloned());
        for name in names {
            if client.release_username(account, &name).await.is_err() {
                notes.push(format!(
                    "'{name}' could not be released and stays reserved forever"
                ));
            }
        }
    }

    // 3. Point of no return: the relay forgets the account. On failure everything so
    // far is recoverable (released names reclaim on re-registration), so surface it.
    {
        let account = s.account.as_ref().ok_or("locked")?;
        let previous = s.history.previous_usernames().to_vec();
        client
            .delete_account(account, &previous)
            .await
            .map_err(|e| format!("relay deletion failed — nothing was wiped: {e}"))?;
    }

    // 4. This device forgets the account.
    wipe_local_account(&mut s);

    Ok(if notes.is_empty() {
        String::new()
    } else {
        notes.join("; ")
    })
}

/// Auto-lock timer (`None` = disabled). Enforced by the UI's idle tracker calling `lock`.
#[tauri::command]
pub async fn set_lock_after(
    state: tauri::State<'_, AppState>,
    secs: Option<u64>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.prefs.lock_after_secs = secs.filter(|s| *s > 0);
    s.save_prefs()
}

/// PIN reminder cadence (`None` = off): re-ask for the PIN every Nth app open.
#[tauri::command]
pub async fn set_pin_reminder(
    state: tauri::State<'_, AppState>,
    every: Option<u32>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    s.prefs.pin_reminder_every = every.filter(|e| *e > 0);
    s.prefs.opens_since_pin_check = 0;
    s.save_prefs()
}

/// Called once per app launch. Returns whether this open should show the PIN reminder
/// (PIN set + reminders on + counter reached). The counter resets on a correct
/// [`verify_pin`], not here — dismissing the reminder doesn't silence the next one.
#[tauri::command]
pub async fn note_app_open(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let mut s = state.inner.lock().await;
    s.prefs.opens_since_pin_check = s.prefs.opens_since_pin_check.saturating_add(1);
    let _ = s.save_prefs();
    Ok(match s.prefs.pin_reminder_every {
        Some(every) if s.quick_pin_path().exists() => s.prefs.opens_since_pin_check >= every,
        _ => false,
    })
}

#[tauri::command]
pub async fn privacy_prefs(state: tauri::State<'_, AppState>) -> Result<PrivacyView, String> {
    let s = state.inner.lock().await;
    Ok(PrivacyView {
        send_typing: s.prefs.send_typing,
        send_receipts: s.prefs.send_receipts,
        notif_level: s.prefs.notif_level.clone(),
        call_retention_secs: call_retention_secs(&s),
        require_unlock_to_answer: s.prefs.require_unlock_to_answer,
    })
}

/// Update a Privacy setting. Any argument left `None` is unchanged. `notif_level` accepts
/// `"sender_message"` | `"sender"` | `"generic"`; `call_retention_secs` accepts one of
/// [`CALL_RETENTION_CHOICES`] and takes effect immediately — shortening it cleans the
/// call-control store now rather than at the next call.
#[tauri::command]
pub async fn set_privacy(
    state: tauri::State<'_, AppState>,
    send_typing: Option<bool>,
    send_receipts: Option<bool>,
    notif_level: Option<String>,
    call_retention_secs: Option<u64>,
    require_unlock_to_answer: Option<bool>,
) -> Result<(), String> {
    let mut s = state.inner.lock().await;
    if let Some(v) = send_typing {
        s.prefs.send_typing = v;
    }
    if let Some(v) = send_receipts {
        s.prefs.send_receipts = v;
    }
    if let Some(v) = notif_level {
        if matches!(v.as_str(), "sender_message" | "sender" | "generic") {
            s.prefs.notif_level = v;
        }
    }
    if let Some(v) = require_unlock_to_answer {
        // §8: changing it at all needs an open vault. It decides who may answer this
        // device's calls, and a setting the locked call subsystem could reach would be a
        // way around the very boundary that subsystem is scoped by.
        if s.account.is_none() {
            return Err("unlock first".into());
        }
        // Turning it OFF weakens who may answer this device's calls, so it costs an OS
        // presence check — the same gate the account ceremonies use. Turning it ON only
        // ever adds a requirement, so it is free.
        if !v && s.prefs.require_unlock_to_answer {
            let recent = matches!(s.last_presence_ok, Some(t)
                if t.elapsed().as_secs() < PRESENCE_WINDOW_SECS);
            if cfg!(target_os = "android") && !recent {
                return Err("verify it's you first — then turn this off".into());
            }
        }
        s.prefs.require_unlock_to_answer = v;
    }
    if let Some(v) = call_retention_secs {
        if CALL_RETENTION_CHOICES.contains(&v) {
            s.prefs.call_retention_secs = v;
            apply_call_retention(&mut s);
        }
    }
    s.save_prefs()
}
