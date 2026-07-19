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

pub(crate) async fn kt_sth(State(state): State<AppState>) -> Response {
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
pub(crate) async fn kt_proof(State(state): State<AppState>, Path(hash): Path<String>) -> Response {
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
    Query(q): Query<ConsistencyQuery>,
) -> Response {
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
    // Roster appends grow the permanent public log — same strict budget as /register.
    if !inner.auth_rate.check(&format!("roster:{key}"), now()) {
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
            if let Some(db) = db {
                let _ = db.delete_directory(&mailbox);
                let _ = db.delete_push(&mailbox);
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
pub(crate) async fn kt_roster(State(state): State<AppState>, Path(hash): Path<String>) -> Response {
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
