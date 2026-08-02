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
    let t = now();
    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&format!("bundle:{key}"), t) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    // Disjoint borrows of the directory, the drain floor, and the db field through one
    // guard.
    let Inner {
        directory,
        db,
        otk_drain_rate,
        ..
    } = &mut *inner;
    let Some(entry) = directory.get_mut(&hash) else {
        return (StatusCode::NOT_FOUND, "no such identity").into_response();
    };
    // Per-RECIPIENT floor on the drain rate (SP-10). The `bundle:{key}` limit above is per
    // *client*, so it bounds one address and does nothing about a drain spread over many;
    // this bounds what one mailbox can lose, whoever asks. It engages only inside the
    // reserve band, so the common case is untouched — no metering, no new bucket, and no
    // observable difference — and a legitimate burst (every device of a busy group fetching
    // a newly-registered member's bundle) still gets fresh keys.
    //
    // Over the floor we serve the fallback key **instead of consuming a fresh one**: the
    // same answer the endpoint already gives a fully-drained mailbox, so a session still
    // starts and nothing fails. That is the whole reason this is the option that was
    // chosen over rotating the fallback key — it has no message-loss failure mode.
    //
    // Two conditions keep the floor from ever *causing* the harm it prevents:
    //   * an account with no fallback key is never metered — holding a fresh key back
    //     there would mean `409 no keys available`, i.e. nobody can start a session with
    //     that user at all, which is strictly worse than the drain;
    //   * an already-empty stock is never metered — those fetches consume nothing, and
    //     charging them would spend the window's budget on nothing and leave the mailbox
    //     metered-out the instant its owner replenishes.
    let metered = !entry.one_time_keys.is_empty()
        && entry.one_time_keys.len() <= OTK_DRAIN_RESERVE
        && entry.fallback_key.is_some();
    let may_consume = !metered || otk_drain_rate.check(&format!("otkdrain:{hash}"), t);
    // Prefer a fresh one-time key. If exhausted (or held back by the floor), serve the
    // reusable fallback key so a session can still start (this is what stops a
    // one-time-key-drain DoS). Only if there is neither do we refuse.
    let consumed_otk = if may_consume {
        entry.one_time_keys.pop_front()
    } else {
        None
    };
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

/// Fresh-key stock at or below which `/v1/bundle/{hash}` hand-outs are metered **per
/// recipient mailbox** (SP-10, second half). Above it nothing is metered.
///
/// ## What this defends
///
/// Every `/v1/bundle` fetch consumes one one-time key, and the endpoint is
/// unauthenticated by design with a publicly computable address. Drain a victim's stock
/// and every session started afterwards falls back to the single **reusable** fallback
/// pre-key, which is never consumed — so a later compromise of that one key exposes the
/// initiating message of every session established while it was current. The existing
/// `bundle:{key}` limit is per *client*: it bounds one address to 60/min (≈100 keys in two
/// minutes) and does nothing at all about a drain spread across many addresses.
///
/// The alternative fix — rotating the fallback key — was rejected, and this constant is
/// why it stays rejected. `vodozemac` keeps exactly two fallback keys (current and
/// previous), a queued pre-key message may sit in a mailbox for `MAX_MESSAGE_TTL_SECS`
/// (30 days) and in a *sender's* count-bounded outbox indefinitely, and Sona has no
/// session-recovery path: an undecryptable frame becomes `Decoded::Ignore` and is acked
/// out of the mailbox permanently while the sender already saw `202`. A rotation that
/// outran that window would be silent, unrecoverable message loss. Bounding the drain
/// touches no key material and has no such failure mode.
///
/// ## Sizing
///
/// The band must stay **above the client's replenish batch** (20, `replenish_own_keys`) or
/// it would never engage for a victim under sustained drain: a topped-up stock would sit
/// outside the band and be drainable at the per-client rate all over again. 32 keeps a
/// full top-up inside the metered region while leaving the first two thirds of a fresh
/// 100-key stock unmetered.
///
/// ## Residual, deliberately
///
/// This bounds the *total* drain, not the race for any individual key. Under a sustained
/// distributed drain an attacker still takes each window's tokens as they refill, so new
/// sessions started during the attack use the fallback key — exactly what happens today.
/// What changes is that the stock is no longer *destroyed*: walking the band takes hours
/// instead of seconds, the drain must be sustained forever rather than run once and
/// forgotten, an offline victim cannot be emptied while they are away, and service returns
/// to fresh keys the moment the drain stops. It also cannot be closed further at this
/// layer — sealed sender means the relay cannot tell an attacker's fetch from a real
/// first contact, so any budget it can enforce is per recipient and blind to who spends it.
pub const OTK_DRAIN_RESERVE: usize = 32;

/// Fresh one-time keys one mailbox may hand out per [`OTK_DRAIN_WINDOW_SECS`] while its
/// stock is inside the [`OTK_DRAIN_RESERVE`] band — 12/hour.
///
/// Above any real first-contact rate for a user whose stock is already low, and far below
/// the ~3000/hour a single address could take before. The window is short so the budget
/// cannot be hoarded and spent in one burst at a window boundary.
pub const OTK_DRAIN_PER_WINDOW: u32 = 2;

/// Window for [`OTK_DRAIN_PER_WINDOW`].
pub const OTK_DRAIN_WINDOW_SECS: u64 = 600;

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
    headers: HeaderMap,
    Json(req): Json<OneTimeKeysRequest>,
) -> Response {
    // Gated BEFORE the signature verify (SP-19). This was the only handler in the `core`
    // router with neither a trusted-client gate nor a rate limit, and it is not
    // nonce-gated either — so an unauthenticated loop could spend a directory lookup plus
    // an Ed25519 verify over a body up to 64 KiB *while holding the global state mutex*,
    // serializing the whole relay behind it. Storage growth was already bounded
    // (MAX_ONE_TIME_KEYS, dedup); the cost was CPU and lock pressure. Both checks are
    // cheap and pre-verify, so a flood is now rejected before it costs anything.
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    if IdentityHash::from_hex(&req.identity_hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let mut inner = state.inner.lock().unwrap();
    // Same bucket convention as the rest of the key surface (`bundle:{key}`).
    if !inner.rate.check(&format!("otk:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
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

/// At or below this many remaining one-time keys, a client should top up. The exact
/// count is never published (SP-10) — only which side of this line it falls on.
pub const OTK_LOW_WATERMARK: usize = 10;

#[derive(Serialize)]
struct CountResponse {
    /// Coarse bucket: `plenty` / `low` / `none`. **Never an exact count.**
    ///
    /// This endpoint is unauthenticated and the mailbox hash is publicly computable, and
    /// each *new inbound session* consumes exactly one key — so an exact remaining count
    /// was a precise, third-party-readable signal of when a user is first contacted by
    /// someone new (SP-10). Polling a list of usernames turned it into a first-contact
    /// activity feed for the whole user base, against a design whose headline property is
    /// that even the server should not learn who talks to whom. A bucket still tells the
    /// owner what it needs ("top up or not") while a watcher learns only that a user
    /// crossed the watermark, which takes many sessions rather than one.
    level: &'static str,
    /// [`OTK_LOW_WATERMARK`] — the line `level` is computed against. A server constant,
    /// identical for every user, so publishing it leaks nothing. Clients need it to pick
    /// a top-up size that actually clears the line; without it a client whose target sits
    /// below the watermark would upload on every replenish cycle forever.
    low_watermark: usize,
}

/// Whether an identity still has fresh one-time keys, as a coarse bucket (see
/// [`CountResponse::level`]).
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
        Some(e) => {
            let level = match e.one_time_keys.len() {
                0 => "none",
                n if n <= OTK_LOW_WATERMARK => "low",
                _ => "plenty",
            };
            (
                StatusCode::OK,
                Json(CountResponse {
                    level,
                    low_watermark: OTK_LOW_WATERMARK,
                }),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such identity").into_response(),
    }
}
