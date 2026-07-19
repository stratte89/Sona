use super::*;

// ─────────────────────────── REST: fetch bundle ───────────────────────────

pub(crate) async fn fetch_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    // Rate-limited: each fetch may CONSUME a one-time key, so an unmetered loop drains
    // a victim's fresh-key stock down to the (reusable) fallback for free.
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&format!("bundle:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    // Disjoint borrows of the directory and the db field through one guard.
    let Inner { directory, db, .. } = &mut *inner;
    let Some(entry) = directory.get_mut(&hash) else {
        return (StatusCode::NOT_FOUND, "no such identity").into_response();
    };
    // Prefer a fresh one-time key. If exhausted, serve the reusable fallback key so a
    // session can still start (this is what stops a one-time-key-drain DoS). Only if
    // there is neither do we refuse.
    let consumed_otk = entry.one_time_keys.pop_front();
    let one_time_key = match consumed_otk.clone().or_else(|| entry.fallback_key.clone()) {
        Some(k) => k,
        None => return (StatusCode::CONFLICT, "no keys available").into_response(),
    };
    let bundle = PreKeyBundle {
        identity_key: entry.identity_key.clone(),
        signing_key: entry.signing_key.clone(),
        one_time_key,
    };
    // Persist only if we actually consumed a one-time key (fallback is not consumed).
    if consumed_otk.is_some() {
        if let Some(db) = db {
            let _ = db.upsert_directory(&hash, entry);
        }
    }
    (StatusCode::OK, Json(bundle)).into_response()
}

// ─────────────────────────── REST: one-time key replenishment ───────────────────────────

/// Upper bound on stored one-time keys per user — caps storage and replay growth.
pub const MAX_ONE_TIME_KEYS: usize = 100;

#[derive(Deserialize)]
pub struct OneTimeKeysRequest {
    pub identity_hash: String,
    pub one_time_keys: Vec<String>,
    /// Ed25519 signature over `one_time_keys_signing_message(hash, keys)`, by the
    /// account's registered signing key — proves the uploader owns this identity.
    pub signature: String,
}

/// Add one-time keys to an existing identity (so others can keep starting sessions with
/// it after its initial batch is consumed). Authenticated by the account's signing key.
pub(crate) async fn upload_one_time_keys(
    State(state): State<AppState>,
    Json(req): Json<OneTimeKeysRequest>,
) -> Response {
    if IdentityHash::from_hex(&req.identity_hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let mut inner = state.inner.lock().unwrap();
    let Inner { directory, db, .. } = &mut *inner;
    let Some(entry) = directory.get_mut(&req.identity_hash) else {
        return (StatusCode::NOT_FOUND, "no such identity").into_response();
    };
    let msg = protocol_types::one_time_keys_signing_message(&req.identity_hash, &req.one_time_keys);
    if !auth::verify(&entry.signing_key, &msg, &req.signature) {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }
    // Dedup against existing keys and cap the stored set.
    for k in req.one_time_keys {
        if entry.one_time_keys.len() >= MAX_ONE_TIME_KEYS {
            break;
        }
        if !entry.one_time_keys.contains(&k) {
            entry.one_time_keys.push_back(k);
        }
    }
    if let Some(db) = db {
        let _ = db.upsert_directory(&req.identity_hash, entry);
    }
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct CountResponse {
    remaining: usize,
}

/// How many one-time keys an identity has left (so its client knows when to replenish).
pub(crate) async fn one_time_key_count(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let mut inner = state.inner.lock().unwrap();
    // Shares the bundle-surface bucket: both are cheap directory reads by the same actors.
    if !inner.rate.check(&format!("bundle:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    match inner.directory.get(&hash) {
        Some(e) => (
            StatusCode::OK,
            Json(CountResponse {
                remaining: e.one_time_keys.len(),
            }),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such identity").into_response(),
    }
}
