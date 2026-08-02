use super::*;

// ─────────────────────────── Key Transparency ───────────────────────────

#[derive(Serialize)]
struct PubkeyResponse {
    /// Base64 Ed25519 key clients pin to trust this log. SHOWN HERE FOR BOOTSTRAP ONLY;
    /// a real deployment distributes the pin out-of-band so a malicious server can't
    /// just hand out its own key.
    pubkey: String,
}

pub(crate) async fn kt_pubkey(State(state): State<AppState>) -> Response {
    let pubkey = state.inner.lock().unwrap().kt.verifying_key_b64();
    (StatusCode::OK, Json(PubkeyResponse { pubkey })).into_response()
}

pub(crate) async fn kt_sth(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(denied) = metered(&headers, &state, "kt") {
        return denied;
    }
    let sth = state.inner.lock().unwrap().kt.sth(now());
    (StatusCode::OK, Json(sth)).into_response()
}

#[derive(Serialize)]
struct KtProofResponse {
    entry: KtEntry,
    index: u64,
    /// Base64 RFC 6962 inclusion proof (decode with `kt_log::inclusion_from_b64`).
    proof_b64: String,
    sth: SignedTreeHead,
}

/// The latest binding for a username plus a proof it is in the log, and the head to
/// verify the proof against. The client checks the proof itself — it never trusts that
/// this entry is genuine just because the server returned it.
pub(crate) async fn kt_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if let Some(denied) = metered(&headers, &state, "kt") {
        return denied;
    }
    let inner = state.inner.lock().unwrap();
    let Some(index) = inner.kt.latest_index_for(&hash) else {
        return (StatusCode::NOT_FOUND, "no key transparency entry").into_response();
    };
    let Some((entry, proof)) = inner.kt.inclusion(index) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "proof unavailable").into_response();
    };
    let sth = inner.kt.sth(now());
    (
        StatusCode::OK,
        Json(KtProofResponse {
            entry,
            index: index as u64,
            proof_b64: kt_log::inclusion_to_b64(&proof),
            sth,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    /// Size of the older tree head the client already trusts.
    pub from: usize,
}

#[derive(Serialize)]
struct ConsistencyResponse {
    /// Base64 RFC 6962 consistency proof (decode with `kt_log::consistency_from_b64`).
    proof_b64: String,
    sth: SignedTreeHead,
}

/// A proof that the current log is an append-only extension of an earlier size the
/// client saw — so the client can confirm no past binding was rewritten.
pub(crate) async fn kt_consistency(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsistencyQuery>,
) -> Response {
    if let Some(denied) = metered(&headers, &state, "kt") {
        return denied;
    }
    let inner = state.inner.lock().unwrap();
    let Some(proof) = inner.kt.consistency(q.from) else {
        return (StatusCode::BAD_REQUEST, "from exceeds current size").into_response();
    };
    let sth = inner.kt.sth(now());
    (
        StatusCode::OK,
        Json(ConsistencyResponse {
            proof_b64: kt_log::consistency_to_b64(&proof),
            sth,
        }),
    )
        .into_response()
}

// ─────────────────────────── Multi-device: capabilities + roster + sync ──────────────

/// Publish a device-roster epoch. Self-authenticating like `/register`: the KT log
/// validates the account signature, every device proof-of-possession, and epoch
/// continuity before appending — the relay cannot forge or reorder rosters, it can only
/// refuse (which is detectable, like any withholding). On success the relay mirrors the
/// roster into the directory: every linked device gets a mailbox record (so it can
/// upload one-time keys and authenticate its delivery socket), and devices dropped from
/// the roster lose theirs (revocation cuts off new sessions and socket auth at once).
pub(crate) async fn publish_roster(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(roster): Json<KtRosterEntry>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let hash = roster.username_hash.clone();
    if IdentityHash::from_hex(&hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed username_hash").into_response();
    }

    let mut inner = state.inner.lock().unwrap();
    // Roster appends grow the permanent public log — same strict budget as /register,
    // and the same permanent-growth backstop (SP-11).
    if !inner.auth_rate.check(&format!("roster:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    if !inner.kt_growth_rate.check(&format!("kt:{key}"), now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }

    // Device set of the previous epoch (id + key), to diff for directory add/remove.
    let previous: Vec<(String, String)> = inner
        .kt
        .latest_roster_for(&hash)
        .map(|r| {
            r.devices
                .iter()
                .map(|d| (d.device_id.clone(), d.identity_key.clone()))
                .collect()
        })
        .unwrap_or_default();

    let accepted = roster.clone();
    match inner.kt.append_roster(roster) {
        Ok(_) => {}
        Err(kt_log::AppendError::Roster(e)) => {
            return (StatusCode::UNAUTHORIZED, format!("roster rejected: {e}")).into_response();
        }
        Err(kt_log::AppendError::BadSignature) => {
            return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
        }
        Err(kt_log::AppendError::BrokenChain(why)) => {
            return (StatusCode::CONFLICT, format!("roster continuity: {why}")).into_response();
        }
    }

    // Mirror into the directory. Linked devices get (or keep) a mailbox record keyed by
    // their derived mailbox hash; the primary keeps the legacy account record untouched.
    let Inner {
        directory,
        db,
        push,
        live,
        call_keys,
        ..
    } = &mut *inner;
    for d in &accepted.devices {
        if d.device_id == kt_log::PRIMARY_DEVICE_ID {
            continue;
        }
        let Some(mailbox) = protocol_types::device_mailbox_hash(&hash, &d.device_id) else {
            continue; // device ids were validated on append; defensive only
        };
        let mailbox = mailbox.as_str().to_string();
        let keep = directory
            .get(&mailbox)
            .map(|e| e.identity_key == d.identity_key && e.signing_key == d.signing_key)
            .unwrap_or(false);
        if !keep {
            let entry = DirectoryEntry {
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
                one_time_keys: Default::default(),
                fallback_key: None,
            };
            if let Some(db) = db {
                let _ = db.upsert_directory(&mailbox, &entry);
            }
            directory.insert(mailbox, entry);
        }
    }
    // Revoke removed devices: drop their directory records (kills socket auth and new
    // sessions) and any push subscription. Queued ciphertext drains via its TTL.
    // A device whose id vanished but whose KEY is still in the roster was not revoked —
    // it moved (primary transfer re-ids the two devices involved): its dead mailbox is
    // still cleaned up, but it is not told `revoked` (the client re-subscribes on its
    // new mailbox; a terminal kick here would lock a healthy device out).
    let current_ids: std::collections::HashSet<&str> = accepted
        .devices
        .iter()
        .map(|d| d.device_id.as_str())
        .collect();
    let current_keys: std::collections::HashSet<&str> = accepted
        .devices
        .iter()
        .map(|d| d.identity_key.as_str())
        .collect();
    for (dropped, key) in previous.iter().filter(|(id, _)| {
        id.as_str() != kt_log::PRIMARY_DEVICE_ID && !current_ids.contains(id.as_str())
    }) {
        if let Some(mailbox) = protocol_types::device_mailbox_hash(&hash, dropped) {
            let mailbox = mailbox.as_str().to_string();
            directory.remove(&mailbox);
            push.remove(&mailbox);
            // A revoked device's call-control key goes with it: no capsule may be sealed
            // to a device the account no longer recognizes, and its call-control mailbox
            // stops authenticating.
            call_keys.remove(&mailbox);
            let call_mailbox =
                protocol_types::call_mailbox_hash(&hash, dropped).map(|h| h.as_str().to_string());
            if let Some(call_mailbox) = &call_mailbox {
                directory.remove(call_mailbox);
            }
            if let Some(db) = db {
                let _ = db.delete_directory(&mailbox);
                let _ = db.delete_push(&mailbox);
                let _ = db.delete_call_key(&mailbox);
                if let Some(call_mailbox) = &call_mailbox {
                    let _ = db.delete_directory(call_mailbox);
                }
            }
            // Drop the mailbox's live channels — the forward task ends, which closes
            // the socket. A truly revoked device is told why first; reconnects land on
            // the removed directory record and get `Revoked` at auth.
            if let Some(senders) = live.remove(&mailbox) {
                let moved = current_keys.contains(key.as_str());
                if !moved {
                    if let Ok(frame) = serde_json::to_string(&ServerFrame::Revoked) {
                        for s in senders {
                            let _ = s.send(frame.clone());
                        }
                    }
                }
            }
        }
    }

    if let Some(db) = db {
        let _ = db.append_kt_roster(&accepted);
    }
    StatusCode::OK.into_response()
}

#[derive(Serialize)]
struct KtRosterResponse {
    roster: KtRosterEntry,
    index: u64,
    /// Base64 RFC 6962 inclusion proof over the roster leaf.
    proof_b64: String,
    sth: SignedTreeHead,
}

/// The latest device roster for an account plus its inclusion proof. The client must
/// verify the proof AND validate the roster against the account's KT-verified binding
/// (`KtRosterEntry::validate_against`) — never trust the list because the server served
/// it. 404 = the account has never published a roster (single-device account).
pub(crate) async fn kt_roster(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if let Some(denied) = metered(&headers, &state, "kt") {
        return denied;
    }
    let inner = state.inner.lock().unwrap();
    let Some(index) = inner.kt.latest_roster_index_for(&hash) else {
        return (StatusCode::NOT_FOUND, "no device roster").into_response();
    };
    let Some((roster, proof)) = inner.kt.roster_inclusion(index) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "proof unavailable").into_response();
    };
    let sth = inner.kt.sth(now());
    (
        StatusCode::OK,
        Json(KtRosterResponse {
            roster,
            index: index as u64,
            proof_b64: kt_log::inclusion_to_b64(&proof),
            sth,
        }),
    )
        .into_response()
}

// ─────────────────────── Per-user leaf enumeration (owner-gated) ───────────────────────

#[derive(Deserialize)]
pub struct KtLeavesRequest {
    pub hash: String,
    pub nonce: String,
    /// Ed25519 over [`protocol_types::kt_leaves_signing_message`].
    pub signature: String,
}

/// One leaf under a username, with its proof of inclusion in the current tree.
#[derive(Serialize)]
struct KtLeaf {
    index: u64,
    /// `"binding"` or `"roster"` — which record kind this leaf is.
    kind: &'static str,
    /// The record itself, so the owner can check it against what it actually signed.
    record: serde_json::Value,
    /// Base64 RFC 6962 inclusion proof against `sth`.
    proof_b64: String,
}

#[derive(Serialize)]
struct KtLeavesResponse {
    leaves: Vec<KtLeaf>,
    sth: SignedTreeHead,
}

/// **Every** leaf under one username, each with an inclusion proof against the current
/// head — the primitive SP-13 needs.
///
/// `sona-auditor` verifies exactly two things: the STH is signed by the pinned key, and
/// each growth step carries a valid consistency proof. That catches a *rewritten* log. It
/// does not catch a log that grows correctly while containing an entry the named account
/// never authorized, and the account's own `audit_devices` asks the relay for its current
/// roster — so a two-faced relay can serve the victim the pre-injection epoch and everyone
/// else the injected one, and every check stays green. `ARCHITECTURE.md` §4 promises "B's
/// own client will see 'there's a key for B that B never published'"; without leaf
/// enumeration, nothing could.
///
/// **Owner-gated deliberately.** "All leaves for this username", served to anyone, would
/// be a fresh activity-enumeration oracle stacked on an already-reversible mailbox hash
/// (SP-04) — who registered, when, how often they rotate, how many devices they have. So
/// it is challenge-signed by the account's own key, exactly like push register/unregister.
/// Independent auditors keep the aggregate consistency view they already have.
///
/// This is a detection net, not a fix: it exists so an injected-but-validly-signed leaf
/// becomes *visible* to its victim. Making the injection impossible in the first place is
/// SP-01, which is closed.
pub(crate) async fn kt_leaves(
    State(state): State<AppState>,
    Json(req): Json<KtLeavesRequest>,
) -> Response {
    if IdentityHash::from_hex(&req.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let msg = protocol_types::kt_leaves_signing_message(&req.hash, &req.nonce);
    let mut inner = state.inner.lock().unwrap();
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
    let sth = inner.kt.sth(now());
    let mut leaves = Vec::new();
    for index in inner.kt.all_indices_for(&req.hash) {
        // Each leaf carries its own proof against the SAME head, so a relay that omits
        // one cannot also produce a consistent head — the omission is what the owner is
        // looking for, and hiding it costs the relay a detectable equivocation.
        let (kind, record, proof) = match inner.kt.record(index) {
            Some(kt_log::KtRecord::Binding(e)) => (
                "binding",
                serde_json::to_value(e).unwrap_or(serde_json::Value::Null),
                inner.kt.inclusion(index).map(|(_, p)| p),
            ),
            Some(kt_log::KtRecord::Roster(r)) => (
                "roster",
                serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
                inner.kt.roster_inclusion(index).map(|(_, p)| p),
            ),
            None => continue,
        };
        let Some(proof) = proof else { continue };
        leaves.push(KtLeaf {
            index: index as u64,
            kind,
            record,
            proof_b64: kt_log::inclusion_to_b64(&proof),
        });
    }
    (StatusCode::OK, Json(KtLeavesResponse { leaves, sth })).into_response()
}
