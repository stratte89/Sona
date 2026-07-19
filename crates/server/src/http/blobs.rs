use super::*;

// ─────────────────────────── Attachment blobs ───────────────────────────

/// Max attachment blob size (the client ciphertext). 10 MiB.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;
/// How long an undownloaded blob is retained.
const BLOB_TTL_SECS: u64 = 30 * 24 * 3600;

#[derive(Serialize)]
struct BlobUploadResponse {
    blob_id: String,
}

/// Would adding `add` bytes to the object stores (attachments + sync blobs) exceed the
/// global ceiling? The per-client budgets bound one address; this bounds the SUM, so
/// spreading uploads across many addresses still can't fill the disk. Fail-closed: a
/// storage-size query error counts as full.
pub(crate) fn storage_full(inner: &Inner, config: &crate::state::Config, add: usize) -> bool {
    let used = match &inner.db {
        Some(db) => db.storage_bytes().unwrap_or(u64::MAX),
        None => {
            inner
                .blobs
                .values()
                .map(|(d, _)| d.len() as u64)
                .sum::<u64>()
                + inner
                    .sync_blobs
                    .values()
                    .map(|(d, _)| d.len() as u64)
                    .sum::<u64>()
        }
    };
    used.saturating_add(add as u64) > config.max_storage_bytes
}

/// Store an opaque attachment blob (already encrypted end-to-end by the sender with a key
/// only the recipient learns, in-band). The server never sees the plaintext or the key —
/// it holds ciphertext addressed by a random id. Sealed-sender: uploads aren't attributed.
pub(crate) async fn upload_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    let t = now();
    let id = random_blob_id();
    let expires = Some(t + BLOB_TTL_SECS);

    let mut inner = state.inner.lock().unwrap();
    if !inner.rate.check(&key, t) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    // Request counts alone don't bound disk growth (60/min × 10 MiB is a multi-GiB/hour
    // fill) — the byte budget does.
    if !inner.upload_bytes.charge(&key, body.len() as u64, t) {
        return (StatusCode::TOO_MANY_REQUESTS, "upload byte budget exceeded").into_response();
    }
    if storage_full(&inner, &state.config, body.len()) {
        return (StatusCode::INSUFFICIENT_STORAGE, "relay storage full").into_response();
    }
    match &inner.db {
        Some(db) => {
            if db.insert_blob(&id, &body, expires).is_err() {
                return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
            }
        }
        None => {
            inner.blobs.insert(id.clone(), (body.to_vec(), expires));
        }
    }
    (StatusCode::OK, Json(BlobUploadResponse { blob_id: id })).into_response()
}

/// Fetch an attachment blob by id (opaque ciphertext). 404 if absent or expired.
/// Rate- and byte-limited: an unmetered download path is free egress amplification
/// (upload one max-size blob, hammer GETs).
pub(crate) async fn download_blob(
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
        Some(db) => db.get_blob(&id, t).ok().flatten(),
        None => {
            // Prune-on-read for the in-memory path.
            if let Some((_, Some(exp))) = inner.blobs.get(&id) {
                if *exp <= t {
                    inner.blobs.remove(&id);
                }
            }
            inner.blobs.get(&id).map(|(d, _)| d.clone())
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
        None => (StatusCode::NOT_FOUND, "no such blob").into_response(),
    }
}

pub(crate) fn random_blob_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
