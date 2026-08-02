use super::*;

// ─────────────────────────── REST: register ───────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// The Key Transparency entry binding this username to its keys. Self-authenticating:
    /// the server validates its signature + continuity chain when appending to the log.
    pub entry: KtEntry,
    /// One-time keys (base64) to seed the bundle store for this identity.
    pub one_time_keys: Vec<String>,
    /// Reusable last-resort pre-key (base64), served when one-time keys run out.
    #[serde(default)]
    pub fallback_key: Option<String>,
}

pub(crate) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Registration appends to the permanent, public KT log (a free anonymous first-claim),
    // so it is the most abusable endpoint. Rate-limit it per client on the stricter
    // auth budget, fail-closed on a missing trusted client address in prod (M-3, L-7).
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let hash = req.entry.username_hash.clone();
    if IdentityHash::from_hex(&hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed username_hash").into_response();
    }
    let identity_key = req.entry.identity_key.clone();
    let signing_key = req.entry.signing_key.clone();
    let released = req.entry.released;
    let entry_for_db = req.entry.clone();

    // The release-grace rule compares SIGNED timestamps, so a future-dated entry would
    // let its author pre-shorten (or pre-position) a takeover window. Refuse anything
    // ahead of our clock beyond ordinary skew.
    if req.entry.timestamp > now() + 600 {
        return (StatusCode::BAD_REQUEST, "entry timestamp in the future").into_response();
    }

    let mut inner = state.inner.lock().unwrap();
    if !inner.auth_rate.check(&format!("register:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    // Permanent-growth backstop on top of the per-minute limiter (SP-11): every accepted
    // leaf is replayed and re-verified at every boot, so a per-minute rate cannot bound
    // what only ever grows.
    if !inner.kt_growth_rate.check(&format!("kt:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    // Username-change backstop: a release is the rename's signature move, so cap
    // releases per key and rolling week. Budget is keyed by the key that SIGNED the
    // entry (the authorizing/previous key) and the signature is verified before any
    // budget is consumed — both are needed, or anyone could burn a victim's allowance
    // by naming the victim's key in a forged release. The client enforces the same
    // product limit locally — this stops a modified client from spamming the public
    // log. A refused release leaves no log entry.
    if released {
        if !entry_for_db.verify_signature() {
            return (StatusCode::UNAUTHORIZED, "bad entry signature").into_response();
        }
        let signer = entry_for_db
            .prev_signing_key
            .as_deref()
            .unwrap_or(signing_key.as_str());
        if !inner.rename_rate.check(&format!("rename:{signer}"), now()) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "username-change limit reached (5 per week)",
            )
                .into_response();
        }
    }
    // Invite-code gate: when configured, a BRAND-NEW claim (a name with no chain
    // history) must present an unused single-use code. Rotations, renames, releases,
    // and takeovers of released names ride an existing chain and are authorized by
    // signatures, so they are never gated — existing users can't be locked out by an
    // exhausted code list. This bounds anonymous permanent KT-log growth: without it,
    // registration is a free first-claim for anyone who can reach the relay.
    let fresh_claim = inner.kt.latest_index_for(&hash).is_none();
    let mut consume_invite: Option<String> = None;
    if fresh_claim && !state.config.registration_code_hashes.is_empty() {
        let digest = headers
            .get("x-sona-invite")
            .and_then(|v| v.to_str().ok())
            .map(|c| hex::encode(crate::access::token_digest(c.trim())));
        match digest {
            Some(d) if state.config.registration_code_hashes.contains(&d) => {
                // Fail closed on a DB error: better to refuse a signup than double-spend.
                let used = match &inner.db {
                    Some(db) => db.invite_used(&d).unwrap_or(true),
                    None => inner.used_invites.contains(&d),
                };
                if used {
                    return (StatusCode::FORBIDDEN, "invite code already used").into_response();
                }
                consume_invite = Some(d);
            }
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    "registration requires an invite code",
                )
                    .into_response();
            }
        }
    }
    // Append to the Key Transparency log. This is the single source of truth for the
    // binding: it validates the signature and the rotation-continuity chain (including
    // release/takeover rules). A forged or hijacking entry is rejected here, fail-closed.
    match inner.kt.append(req.entry) {
        Ok(_) => {}
        Err(kt_log::AppendError::BadSignature) => {
            return (StatusCode::UNAUTHORIZED, "bad entry signature").into_response();
        }
        Err(kt_log::AppendError::BrokenChain(why)) => {
            return (
                StatusCode::CONFLICT,
                format!("key continuity broken: {why}"),
            )
                .into_response();
        }
        // append() never yields a roster error, but the enum is shared — fail closed.
        Err(kt_log::AppendError::Roster(_)) => {
            return (StatusCode::BAD_REQUEST, "not a binding entry").into_response();
        }
    }

    // The claim is in the log — burn its invite code now (never on a failed attempt, so
    // a typo'd registration doesn't waste the code).
    if let Some(d) = consume_invite {
        match &inner.db {
            Some(db) => {
                let _ = db.consume_invite(&d);
            }
            None => {
                inner.used_invites.insert(d);
            }
        }
    }

    if let Some(db) = &inner.db {
        let _ = db.append_kt_entry(&entry_for_db);
    }
    // A release changes only the log: the owner keeps the mailbox (and its one-time-key
    // stock) through the grace period, so peers who missed the rename can still reach
    // them and start sessions.
    if released {
        return StatusCode::OK.into_response();
    }

    // The KT append succeeded, so the binding is valid (a first claim, a properly
    // authorized rotation, or a post-grace takeover of a released name). Reflect the
    // current keys + fresh one-time keys in the directory the bundle endpoint serves.
    let Inner {
        directory,
        db,
        live,
        ..
    } = &mut *inner;
    // Ownership moved (takeover, or any rotation to a new signing key): the previous
    // holder's live sockets on this mailbox must not keep draining the new holder's
    // traffic. Close them; their next auth verifies against the new directory record.
    if let Some(prev) = directory.get(&hash) {
        if prev.signing_key != signing_key {
            live.remove(&hash);
        }
    }
    let dir_entry = DirectoryEntry {
        identity_key,
        signing_key,
        one_time_keys: req.one_time_keys.into_iter().collect(),
        fallback_key: req.fallback_key,
    };
    directory.insert(hash.clone(), dir_entry.clone());

    // Write through to durable storage (the KT entry is public; the directory is public
    // key material). Persistence failure is logged, not fatal to the request.
    if let Some(db) = db {
        let _ = db.upsert_directory(&hash, &dir_entry);
    }
    StatusCode::OK.into_response()
}

// ─────────────────────────── REST: account deletion ───────────────────────────

/// Defensive ceiling on alias mailboxes deletable in one request. The client keeps at
/// most 5 former usernames; anything past this is a malformed/hostile request.
const MAX_DELETE_ALIASES: usize = 16;

#[derive(Deserialize)]
pub struct AccountDeleteRequest {
    /// The account mailbox (current username hash).
    pub hash: String,
    /// Former-username mailboxes to delete along with it. Each is honored only if its
    /// directory record carries the SAME signing key as the account — the signature
    /// can never widen the deletion to someone else's mailbox.
    #[serde(default)]
    pub alias_hashes: Vec<String>,
    /// Single-use nonce from `GET /v1/challenge` for `hash`.
    pub nonce: String,
    /// Ed25519 over [`protocol_types::account_delete_signing_message`].
    pub signature: String,
}

/// Delete an account from the relay: the directory records (account, device mailboxes,
/// owned aliases), every queued message for those mailboxes, their push subscriptions,
/// and their live sockets (kicked with a terminal `revoked` frame). Authorized by a
/// challenge signature from the account's registered signing key — the same key that
/// authenticates every mailbox drain, so only the account holder (in practice: the
/// primary device, the only holder of that key) can do this.
///
/// The Key Transparency log is deliberately NOT touched: it is append-only and public
/// by design. The client unbinds the username separately with a signed release entry,
/// which starts the normal grace-then-claimable clock.
pub(crate) async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AccountDeleteRequest>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    if IdentityHash::from_hex(&req.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    if req.alias_hashes.len() > MAX_DELETE_ALIASES
        || req
            .alias_hashes
            .iter()
            .any(|a| IdentityHash::from_hex(a).is_none())
    {
        return (StatusCode::BAD_REQUEST, "malformed alias hashes").into_response();
    }
    let msg =
        protocol_types::account_delete_signing_message(&req.hash, &req.alias_hashes, &req.nonce);

    let mut inner = state.inner.lock().unwrap();
    // Same strict budget as the other account-shaped endpoints.
    if !inner.auth_rate.check(&format!("delete:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    if let Err(err) = super::push::consume_and_verify(
        &mut inner,
        &req.hash,
        &req.nonce,
        &msg,
        &req.signature,
        now(),
    ) {
        return err.into_response();
    }
    // The signer's key, captured before anything is removed — the alias ownership check
    // compares against it.
    let account_signing_key = match inner.directory.get(&req.hash) {
        Some(e) => e.signing_key.clone(),
        None => return (StatusCode::NOT_FOUND, "no such identity").into_response(),
    };

    // Everything this signature is allowed to take down:
    // the account mailbox, its device mailboxes (from the latest published roster),
    // and each claimed alias whose directory record carries the same signing key.
    let mut mailboxes = vec![req.hash.clone()];
    // Every device's message mailbox AND its call-control mailbox: the latter has its own
    // directory record (keyed by the call-control key), so deleting the account must take
    // it down too — the primary's included.
    if let Some(mb) = protocol_types::call_mailbox_hash(&req.hash, kt_log::PRIMARY_DEVICE_ID) {
        mailboxes.push(mb.as_str().to_string());
    }
    if let Some(roster) = inner.kt.latest_roster_for(&req.hash) {
        for d in &roster.devices {
            if let Some(mb) = protocol_types::call_mailbox_hash(&req.hash, &d.device_id) {
                mailboxes.push(mb.as_str().to_string());
            }
            if d.device_id == kt_log::PRIMARY_DEVICE_ID {
                continue;
            }
            if let Some(mb) = protocol_types::device_mailbox_hash(&req.hash, &d.device_id) {
                mailboxes.push(mb.as_str().to_string());
            }
        }
    }
    for alias in &req.alias_hashes {
        let owned = inner
            .directory
            .get(alias)
            .is_some_and(|e| e.signing_key == account_signing_key);
        if owned {
            mailboxes.push(alias.clone());
        }
    }

    let Inner {
        directory,
        store,
        live,
        push,
        call_keys,
        db,
        ..
    } = &mut *inner;
    for mb in &mailboxes {
        directory.remove(mb);
        push.remove(mb);
        call_keys.remove(mb);
        store.purge(mb);
        // Live sockets get the terminal frame first (so a connected device lands on
        // its lockout screen instead of a silent reconnect loop), then the channel
        // drops, which closes the socket.
        if let Some(senders) = live.remove(mb) {
            if let Ok(frame) = serde_json::to_string(&ServerFrame::Revoked) {
                for s in senders {
                    let _ = s.send(frame.clone());
                }
            }
        }
        if let Some(db) = db {
            let _ = db.delete_directory(mb);
            let _ = db.delete_push(mb);
            let _ = db.delete_call_key(mb);
            let _ = db.delete_messages_for(mb);
        }
    }
    StatusCode::OK.into_response()
}

// ─────────────────────────── REST: challenge ───────────────────────────

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub hash: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

pub(crate) async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ChallengeQuery>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    if IdentityHash::from_hex(&q.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let nonce = {
        let mut inner = state.inner.lock().unwrap();
        // Rate-limit challenge issuance per client so `/challenge` can't be used to grow
        // the nonce map (backstopped by expiry pruning + cap in `ChallengeStore`) (M-3).
        if !inner.auth_rate.check(&format!("challenge:{key}"), now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
        inner.challenges.issue(&q.hash, now())
    };
    (StatusCode::OK, Json(ChallengeResponse { nonce })).into_response()
}

/// What optional protocol surfaces this relay supports. Old relays 404 here; clients
/// must treat that as "none" and stay on the single-device path.
pub(crate) async fn capabilities(State(state): State<AppState>) -> Response {
    let mut caps = vec![
        protocol_types::CAP_MULTI_DEVICE,
        protocol_types::CAP_HISTORY_SYNC,
        protocol_types::CAP_PUSH_WEBHOOK,
    ];
    if state.config.giphy_key.is_some() {
        caps.push(protocol_types::CAP_GIF_SEARCH);
    }
    if state.fcm.is_some() {
        caps.push(protocol_types::CAP_PUSH_FCM);
    }
    if !state.config.registration_code_hashes.is_empty() {
        caps.push(protocol_types::CAP_INVITE_REGISTER);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "capabilities": caps })),
    )
        .into_response()
}
