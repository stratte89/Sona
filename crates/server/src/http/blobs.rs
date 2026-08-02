use super::*;

// ─────────────────────────── Attachment blobs ───────────────────────────

/// Max attachment blob size (the client ciphertext). 10 MiB.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

#[derive(Serialize)]
struct BlobUploadResponse {
    blob_id: String,
}

/// Fraction of the global storage ceiling above which uploads are rationed per client
/// rather than served first-come-first-served (SP-11), as (numerator, denominator).
pub(crate) const STORAGE_PRESSURE: (u64, u64) = (9, 10);

/// Per-client window allowance once the pool is under pressure. Deliberately above one
/// full history sync (`MAX_SYNC_BLOB_BYTES`, 32 MiB) so device linking — the operation
/// that breaks most visibly and most permanently — still completes on a nearly-full
/// relay. Below the normal `UPLOAD_BYTES_PER_WINDOW`, which is the point.
pub const STORAGE_RESERVE_PER_CLIENT: u64 = 64 * 1024 * 1024;

/// Bytes currently held across the object stores (attachments + sync blobs).
/// Fail-closed: a storage-size query error reports the ceiling, i.e. "full".
fn storage_used(inner: &Inner) -> u64 {
    match &inner.db {
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
    }
}

/// Would adding `add` bytes exceed the global ceiling? The per-client budgets bound one
/// address; this bounds the SUM, so spreading uploads across many addresses still can't
/// fill the disk. Fail-closed.
pub(crate) fn storage_full(inner: &Inner, config: &crate::state::Config, add: usize) -> bool {
    storage_used(inner).saturating_add(add as u64) > config.max_storage_bytes
}

/// Ration the **last slice** of the shared pool per client (SP-11).
///
/// The global ceiling alone made object storage a resource one actor could exhaust for
/// everyone: sealed-sender uploads cannot be attributed to anyone, so there is no early
/// reclamation, and once full every user loses attachments *and* device linking until
/// blobs age out — up to `BLOB_TTL_DAYS`, 30 days. Filling it took only ~40 client
/// windows, i.e. one address for a few hours or forty at once.
///
/// Below the pressure line nothing changes. Above it, an individual client gets a bounded
/// slice per window instead of whatever is left, so the tail of the pool is shared rather
/// than claimed. `true` = refuse this upload.
///
/// This does not make the ceiling unreachable — a wide enough botnet still fills it —
/// but it removes the cheap single-actor version and keeps a nearly-full relay usable
/// for everyone else.
pub(crate) fn storage_rationed(
    inner: &mut Inner,
    config: &crate::state::Config,
    key: &str,
    add: usize,
    t: u64,
) -> bool {
    let (num, den) = STORAGE_PRESSURE;
    let line = config.max_storage_bytes / den * num;
    if storage_used(inner) < line {
        return false;
    }
    !inner.storage_reserve.charge(key, add as u64, t)
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
    // Hard retention cap (BLOB_TTL_DAYS): the only server-side deletion for
    // attachments — see the Config field docs for why chat state can't drive it.
    let expires = Some(t + state.config.blob_ttl_secs);

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
    // Near the ceiling the remaining pool is rationed per client (SP-11) so one actor
    // cannot claim the tail and wedge attachments + device linking for everyone.
    if storage_rationed(&mut inner, &state.config, &key, body.len(), t) {
        return (
            StatusCode::INSUFFICIENT_STORAGE,
            "relay storage nearly full — per-client reserve exceeded",
        )
            .into_response();
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
