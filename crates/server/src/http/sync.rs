use super::*;

/// Max history-sync blob (client ciphertext, already bucket-padded). 32 MiB.
pub const MAX_SYNC_BLOB_BYTES: usize = 32 * 1024 * 1024;
/// How long an undownloaded history-sync blob is retained: long enough for the "new
/// device finishes setup later / offline" case, short enough not to become a backup
/// hosting service. The uploader can always re-upload.
const SYNC_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Serialize)]
struct SyncUploadResponse {
    sync_id: String,
}

/// Store an opaque history-sync blob. The blob is sealed client-side under the account
/// password/PIN *and* a link secret the relay never sees (`crypto_core::sync`), and is
/// addressed by a random capability id — deliberately unauthenticated (like `/blobs`
/// and call rooms), so the relay cannot link a blob to an account. The id travels to
/// the new device over the device-linking channel.
pub(crate) async fn upload_sync_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let t = now();
    let id = blobs::random_blob_id();
    let expires = t + SYNC_TTL_SECS;

    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&format!("sync:{key}"), t) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    if !inner.upload_bytes.charge(&key, body.len() as u64, t) {
        return (StatusCode::TOO_MANY_REQUESTS, "upload byte budget exceeded").into_response();
    }
    if blobs::storage_rationed(&mut inner, &state.config, &key, body.len(), t) {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "relay storage nearly full — per-client reserve exceeded",
        )
            .into_response();
    }
    if blobs::storage_full(&inner, &state.config, body.len()) {
        return (StatusCode::INSUFFICIENT_STORAGE, "relay storage full").into_response();
    }
    match &inner.db {
        Some(db) => {
            if db.insert_sync(&id, &body, expires).is_err() {
                return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
            }
        }
        None => {
            inner
                .sync_blobs
                .insert(id.clone(), (body.to_vec(), expires));
        }
    }
    (StatusCode::OK, Json(SyncUploadResponse { sync_id: id })).into_response()
}

/// Store a history-sync/provisioning blob at a **caller-chosen** capability id (32 hex
/// chars). Used for device-linking provisioning, where the new device picks the id and
/// hands it to the primary over the QR/link channel; the primary PUTs the (opaque,
/// link-secret-sealed) provisioning blob there and the new device GETs it. `PUT` (not the
/// random-id `POST`) so both sides agree on the address without a round trip. Rejects a
/// non-hex id and refuses to overwrite an existing id (random 128-bit ids don't collide,
/// so a hit means a replay attempt).
pub(crate) async fn put_sync_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "malformed id").into_response();
    }
    let t = now();
    let expires = t + SYNC_TTL_SECS;
    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&format!("syncput:{key}"), t) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    if !inner.upload_bytes.charge(&key, body.len() as u64, t) {
        return (StatusCode::TOO_MANY_REQUESTS, "upload byte budget exceeded").into_response();
    }
    if blobs::storage_rationed(&mut inner, &state.config, &key, body.len(), t) {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "relay storage nearly full — per-client reserve exceeded",
        )
            .into_response();
    }
    if blobs::storage_full(&inner, &state.config, body.len()) {
        return (StatusCode::INSUFFICIENT_STORAGE, "relay storage full").into_response();
    }
    // Refuse overwrite (idempotency + anti-clobber): first writer wins.
    let exists = match &inner.db {
        Some(db) => db.get_sync(&id, t).ok().flatten().is_some(),
        None => inner.sync_blobs.contains_key(&id),
    };
    if exists {
        return (StatusCode::CONFLICT, "id already in use").into_response();
    }
    match &inner.db {
        Some(db) => {
            if db.insert_sync(&id, &body, expires).is_err() {
                return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
            }
        }
        None => {
            inner.sync_blobs.insert(id, (body.to_vec(), expires));
        }
    }
    StatusCode::OK.into_response()
}

/// Fetch a history-sync blob by capability id (opaque ciphertext). 404 if absent or
/// expired. Rate- and byte-limited like `/v1/blobs/{id}` (same egress-drain shape).
pub(crate) async fn download_sync_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let t = now();
    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&format!("dl:{key}"), t) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let data = match &inner.db {
        Some(db) => db.get_sync(&id, t).ok().flatten(),
        None => {
            if let Some((_, exp)) = inner.sync_blobs.get(&id) {
                if *exp <= t {
                    inner.sync_blobs.remove(&id);
                }
            }
            inner.sync_blobs.get(&id).map(|(d, _)| d.clone())
        }
    };
    match data {
        Some(bytes) => {
            if !inner.download_bytes.charge(&key, bytes.len() as u64, t) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "download byte budget exceeded",
                )
                    .into_response();
            }
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such sync blob").into_response(),
    }
}
