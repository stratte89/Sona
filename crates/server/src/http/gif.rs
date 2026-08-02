use super::*;

// ─────────────────────────── REST: GIF privacy proxy ───────────────────────────
//
// GIF search normally leaks the user's IP + query straight to the provider (Giphy).
// The relay therefore proxies BOTH the search and the media bytes: the provider only
// ever sees the relay. The client turns a chosen GIF into an ordinary end-to-end
// encrypted attachment, so the recipient never contacts the provider at all (the
// Signal model). Enabled by `GIPHY_API_KEY`; advertised as `CAP_GIF_SEARCH`.

/// Longest accepted search query (chars) — bounds the upstream URL.
const GIF_QUERY_MAX: usize = 100;
/// Media cap: a proxied GIF larger than this is refused (bounds relay bandwidth and
/// matches the client attachment limit).
const GIF_MEDIA_MAX: usize = 10 * 1024 * 1024;

/// Hosts the media proxy may fetch from. This endpoint is a server-side fetch of a
/// client-supplied URL — SSRF surface — so it is a strict https-only allowlist and
/// everything else is refused outright (same posture as `acceptable_push_endpoint`).
/// Giphy serves media from `i.giphy.com`, `media.giphy.com`, and the numbered shards
/// `media0.giphy.com` … `media9.giphy.com`.
fn gif_media_host_ok(host: &str) -> bool {
    if host == "i.giphy.com" || host == "media.giphy.com" {
        return true;
    }
    host.strip_prefix("media")
        .and_then(|rest| rest.strip_suffix(".giphy.com"))
        .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
}

/// Media types the proxy may echo back, as an exact allowlist rather than an
/// `image/`/`video/` prefix test (SP-21). A prefix test passed `image/svg+xml` straight
/// through, and SVG is a script-bearing document, not a raster image — served
/// same-origin from the relay's own domain, with only the (strict) upstream host
/// allowlist standing between "GIF proxy" and "arbitrary attacker-controlled response
/// with an attacker-influenced Content-Type". Not exploitable as written — the client
/// relabels the bytes as a local `data:image/gif` inside an `<img>` — but this is the
/// layer that should not have to depend on that. Matching by exact subtype means a new
/// SVG-ish media type cannot quietly undo the fix.
const ALLOWED_MEDIA_TYPES: &[&str] = &[
    "image/gif",
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/avif",
    "video/mp4",
    "video/webm",
];

/// Constrain an upstream `Content-Type` to [`ALLOWED_MEDIA_TYPES`], defaulting to
/// `image/gif`. Parameters (`; charset=…`) are stripped and case normalized first.
fn proxy_content_type(upstream: Option<&str>) -> String {
    upstream
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|ct| ALLOWED_MEDIA_TYPES.contains(&ct.as_str()))
        .unwrap_or_else(|| "image/gif".to_string())
}

/// Shared client for provider calls: no redirects (an allowlisted host redirecting
/// elsewhere would reopen SSRF), tight timeout.
fn gif_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client")
    })
}

#[derive(Deserialize)]
pub struct GifSearchParams {
    pub q: String,
    /// Pagination cursor from a previous response's `next` (Giphy result offset).
    #[serde(default)]
    pub pos: Option<String>,
}

/// Results per search page (also the `next` cursor stride).
const GIF_PAGE: u64 = 24;

/// Slim one provider result down to exactly what the client needs: proxyable URLs and
/// dimensions. Nothing else from the provider passes through unfiltered.
fn slim_gif(r: &serde_json::Value) -> Option<serde_json::Value> {
    let orig = &r["images"]["original"];
    let gif = orig["url"].as_str()?;
    let tiny = r["images"]["fixed_width"]["url"].as_str().unwrap_or(gif);
    let dim = |k: &str| {
        orig[k]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    };
    Some(serde_json::json!({
        "url": gif, "preview": tiny, "width": dim("width"), "height": dim("height"),
    }))
}

// ── Trending: relay-side pre-load ───────────────────────────────────────────────
// The GIF tab opens onto suggestions before the user types anything. The relay keeps
// ONE cached copy of the provider's trending page (warmed at boot, refreshed on demand
// after the TTL) and serves every client from it — suggestions are instant, and the
// provider sees one fetch per TTL instead of one per user.

/// How long a cached trending page stays fresh.
const GIF_TRENDING_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

fn trending_cache() -> &'static tokio::sync::Mutex<Option<(std::time::Instant, serde_json::Value)>>
{
    static CACHE: std::sync::OnceLock<
        tokio::sync::Mutex<Option<(std::time::Instant, serde_json::Value)>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// Fetch + shape the provider's trending page. `None` on any provider failure — the
/// caller decides whether that is a warm-miss (serve stale/empty) or a 502.
async fn fetch_trending(api_key: &str) -> Option<serde_json::Value> {
    let limit = GIF_PAGE.to_string();
    let v: serde_json::Value = gif_client()
        .get("https://api.giphy.com/v1/gifs/trending")
        .query(&[
            ("api_key", api_key),
            ("limit", limit.as_str()),
            ("rating", "pg-13"),
        ])
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    let results: Vec<serde_json::Value> = v["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(slim_gif)
        .collect();
    if results.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "results": results, "next": "" }))
}

/// Boot-time warm: fill the trending cache so the first client to open the GIF tab is
/// served instantly. Spawned from main when the proxy is enabled; failures are silent
/// (the on-demand path retries).
pub async fn warm_gif_trending(state: AppState) {
    let Some(api_key) = state.config.giphy_key.clone() else {
        return;
    };
    if let Some(page) = fetch_trending(&api_key).await {
        *trending_cache().lock().await = Some((std::time::Instant::now(), page));
    }
}

pub(crate) async fn gif_trending(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(api_key) = state.config.giphy_key.clone() else {
        return (StatusCode::NOT_FOUND, "gif search not enabled").into_response();
    };
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    {
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&format!("gif:{key}"), now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    // Single-flight refresh: the mutex is held across the provider fetch, so a stampede
    // of clients after the TTL costs one upstream request — everyone else waits on the
    // lock and reads the fresh copy.
    let mut cache = trending_cache().lock().await;
    if let Some((at, page)) = cache.as_ref() {
        if at.elapsed() < GIF_TRENDING_TTL {
            return Json(page.clone()).into_response();
        }
    }
    match fetch_trending(&api_key).await {
        Some(page) => {
            *cache = Some((std::time::Instant::now(), page.clone()));
            Json(page).into_response()
        }
        // Provider down: a stale page beats an error — suggestions are best-effort.
        None => match cache.as_ref() {
            Some((_, page)) => Json(page.clone()).into_response(),
            None => (StatusCode::BAD_GATEWAY, "gif provider unreachable").into_response(),
        },
    }
}

pub(crate) async fn gif_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<GifSearchParams>,
) -> Response {
    let Some(api_key) = state.config.giphy_key.clone() else {
        return (StatusCode::NOT_FOUND, "gif search not enabled").into_response();
    };
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    {
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&format!("gif:{key}"), now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    let q: String = p.q.trim().chars().take(GIF_QUERY_MAX).collect();
    if q.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty query").into_response();
    }
    let offset = p
        .pos
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let limit = GIF_PAGE.to_string();
    let offset_s = offset.to_string();
    let req = gif_client()
        .get("https://api.giphy.com/v1/gifs/search")
        .query(&[
            ("api_key", api_key.as_str()),
            ("q", q.as_str()),
            ("limit", limit.as_str()),
            ("offset", offset_s.as_str()),
            ("rating", "pg-13"),
        ]);
    let v: serde_json::Value = match req.send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => match resp.bytes().await.map(|b| serde_json::from_slice(&b)) {
                Ok(Ok(v)) => v,
                _ => return (StatusCode::BAD_GATEWAY, "bad provider response").into_response(),
            },
            Err(_) => return (StatusCode::BAD_GATEWAY, "gif provider error").into_response(),
        },
        Err(_) => return (StatusCode::BAD_GATEWAY, "gif provider unreachable").into_response(),
    };
    // Slim + re-shape: only allowlist-proxyable URLs and dimensions reach the client —
    // nothing from the provider passes through unfiltered.
    let results: Vec<serde_json::Value> = v["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(slim_gif)
        .collect();
    // `next` = the offset of the following page; empty when this page was the last.
    let next = if results.len() as u64 == GIF_PAGE {
        (offset + GIF_PAGE).to_string()
    } else {
        String::new()
    };
    Json(serde_json::json!({ "results": results, "next": next })).into_response()
}

#[derive(Deserialize)]
pub struct GifProxyParams {
    pub url: String,
}

pub(crate) async fn gif_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<GifProxyParams>,
) -> Response {
    if state.config.giphy_key.is_none() {
        return (StatusCode::NOT_FOUND, "gif search not enabled").into_response();
    }
    let Some(key) = client_key(&headers, &state) else {
        return (StatusCode::FORBIDDEN, "no trusted client address").into_response();
    };
    {
        let mut inner = state.inner.lock().unwrap();
        if !inner.rate.check(&format!("gif:{key}"), now()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
        }
    }
    // SSRF gate: https, allowlisted host, default port, no credentials in the URL.
    let Ok(url) = reqwest::Url::parse(&p.url) else {
        return (StatusCode::BAD_REQUEST, "malformed url").into_response();
    };
    let host_ok = url.host_str().is_some_and(gif_media_host_ok);
    if url.scheme() != "https"
        || !host_ok
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return (StatusCode::FORBIDDEN, "url not allowed").into_response();
    }
    let mut resp = match gif_client().get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return (StatusCode::BAD_GATEWAY, "gif media unreachable").into_response(),
    };
    if resp
        .content_length()
        .is_some_and(|l| l > GIF_MEDIA_MAX as u64)
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, "gif too large").into_response();
    }
    let content_type = proxy_content_type(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    );
    // Read capped even when Content-Length lied.
    let mut out: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > GIF_MEDIA_MAX {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "gif too large").into_response();
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return (StatusCode::BAD_GATEWAY, "gif media read failed").into_response(),
        }
    }
    // `nosniff` so a browser cannot second-guess the type we just constrained, and an
    // attachment disposition so nothing here is ever treated as a navigable document.
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CONTENT_DISPOSITION, "attachment".to_string()),
        ],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::gif_media_host_ok;

    /// SP-21: the proxy used to echo any upstream `Content-Type` starting `image/` or
    /// `video/` — which includes `image/svg+xml`, a script-bearing document rather than
    /// a raster image, served same-origin from the relay's own domain. Allowlisted by
    /// exact subtype now; real GIF/video types must keep working.
    #[test]
    fn proxied_content_types_are_an_exact_raster_video_allowlist() {
        for good in [
            "image/gif",
            "image/png",
            "image/jpeg",
            "image/webp",
            "image/avif",
            "video/mp4",
            "video/webm",
        ] {
            assert_eq!(super::proxy_content_type(Some(good)), good);
        }
        // Parameters are stripped and case normalized before matching.
        assert_eq!(
            super::proxy_content_type(Some("IMAGE/GIF; charset=binary")),
            "image/gif"
        );
        // Anything else — script-bearing, novel, or absent — falls back to image/gif.
        for bad in [
            "image/svg+xml",
            "image/svg",
            "text/html",
            "application/javascript",
            "video/x-anything",
            "image/",
        ] {
            assert_eq!(super::proxy_content_type(Some(bad)), "image/gif");
        }
        assert_eq!(super::proxy_content_type(None), "image/gif");
    }

    #[test]
    fn gif_media_allowlist_is_strict() {
        // Giphy media hosts pass.
        assert!(gif_media_host_ok("i.giphy.com"));
        assert!(gif_media_host_ok("media.giphy.com"));
        assert!(gif_media_host_ok("media0.giphy.com"));
        assert!(gif_media_host_ok("media9.giphy.com"));
        // Everything else is refused — including lookalikes and multi-digit shards
        // (SSRF surface: this list must never loosen by accident).
        assert!(!gif_media_host_ok("media10.giphy.com"));
        assert!(!gif_media_host_ok("mediaX.giphy.com"));
        assert!(!gif_media_host_ok("giphy.com"));
        assert!(!gif_media_host_ok("evil.com"));
        assert!(!gif_media_host_ok("media.giphy.com.evil.com"));
        assert!(!gif_media_host_ok("imedia.giphy.com"));
        assert!(!gif_media_host_ok(""));
    }
}
