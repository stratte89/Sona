use super::*;

#[derive(Deserialize)]
pub struct PushRegisterRequest {
    pub hash: String,
    pub endpoint: String,
    /// Single-use nonce from `GET /v1/challenge`.
    pub nonce: String,
    /// Ed25519 over [`protocol_types::push_register_signing_message`].
    pub signature: String,
}

#[derive(Deserialize)]
pub struct PushUnregisterRequest {
    pub hash: String,
    pub nonce: String,
    /// Ed25519 over [`protocol_types::push_unregister_signing_message`].
    pub signature: String,
}

/// Clock skew tolerated on a published call-key mint time.
const CALL_KEY_SKEW_SECS: u64 = 300;

/// Shared HTTP client for wake POSTs: no redirects (a push endpoint has no business
/// redirecting, and following one widens SSRF), tight timeout.
pub(crate) fn push_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(WAKE_TIMEOUT_SECS))
            .build()
            .expect("reqwest client builds")
    })
}

/// Is this URL acceptable as a push endpoint? In production: HTTPS only, and obvious
/// SSRF targets (loopback/private/link-local IP literals, `localhost`) are refused —
/// the relay must not be turnable into a probe of its own network. (DNS-rebinding via
/// a hostname that *resolves* privately is documented residual risk; run the relay
/// network-isolated, as the provided container/systemd setups do.)
///
/// `fcm:<registration_token>` endpoints are a separate scheme branch: accepted only
/// when the relay is FCM-configured (`fcm_enabled`), and they NEVER touch the generic
/// URL fetcher — the token goes to Google's fixed v1 endpoint, so the SSRF posture of
/// the webhook path is untouched.
fn acceptable_push_endpoint(endpoint: &str, prod: bool, fcm_enabled: bool) -> bool {
    if let Some(token) = endpoint.strip_prefix("fcm:") {
        return fcm_enabled && acceptable_fcm_token(token);
    }
    if endpoint.len() > 2048 {
        return false;
    }
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    match url.scheme() {
        "https" => {}
        "http" if !prod => {}
        _ => return false,
    }
    if prod {
        match url.host() {
            Some(url::Host::Ipv4(ip)) => {
                if forbidden_v4(ip) {
                    return false;
                }
            }
            Some(url::Host::Ipv6(ip)) => {
                if forbidden_v6(ip) {
                    return false;
                }
            }
            Some(url::Host::Domain(d)) => {
                if d.eq_ignore_ascii_case("localhost") {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

/// Sanity-shape an FCM registration token: printable ASCII, no whitespace, bounded
/// length. Tokens are opaque to us — this only blocks garbage and header-injection
/// shapes before the token is echoed into an authenticated Google API call.
fn acceptable_fcm_token(token: &str) -> bool {
    (16..=4096).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic())
}

/// Reject an IPv4 literal that points at loopback/private/link-local/unspecified space,
/// plus the whole 100.64.0.0/10 (CGNAT) and 192.0.0.0/24 (IETF protocol assignments)
/// ranges that `is_private()` misses.
fn forbidden_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
}

/// Reject an IPv6 literal. Crucially, canonicalize any IPv4-mapped/-compatible,
/// NAT64 (64:ff9b::/96), or 6to4 (2002::/16) form to the embedded IPv4 first and apply
/// [`forbidden_v4`] — otherwise `::ffff:169.254.169.254` and friends slip past the
/// v6-only checks and a dual-stack host connects them to the internal target.
fn forbidden_v6(ip: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return forbidden_v4(v4);
    }
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || (seg[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (seg[0] & 0xff00) == 0xff00 // multicast ff00::/8
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation 2001:db8::/32
}

/// Extract an embedded IPv4 address from IPv4-mapped (`::ffff:0:0/96`),
/// IPv4-compatible (`::/96`), NAT64 (`64:ff9b::/96`), or 6to4 (`2002::/16`) forms.
fn embedded_v4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4); // ::ffff:a.b.c.d
    }
    let seg = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 — embedded IPv4 in the low 32 bits.
    if seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
    {
        return Some(std::net::Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    // 6to4 2002::/16 — embedded IPv4 in segments 1..=2.
    if seg[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        ));
    }
    // IPv4-compatible ::a.b.c.d (deprecated but still routable on some stacks). Excludes
    // ::1 and :: which the caller handles as loopback/unspecified.
    if seg[..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && (seg[7] == 0 || seg[7] == 1)) {
        return Some(std::net::Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    None
}

/// Consume the single-use nonce and verify the signature against the identity's
/// registered signing key. Nonce is consumed *first*, so a failed attempt still burns it.
pub(crate) fn consume_and_verify(
    inner: &mut Inner,
    hash: &str,
    nonce: &str,
    message: &[u8],
    signature: &str,
    t: u64,
) -> Result<(), (StatusCode, &'static str)> {
    if !inner.challenges.consume(hash, nonce, t) {
        return Err((StatusCode::UNAUTHORIZED, "bad or expired nonce"));
    }
    let Some(entry) = inner.directory.get(hash) else {
        return Err((StatusCode::NOT_FOUND, "no such identity"));
    };
    if !auth::verify(&entry.signing_key, message, signature) {
        return Err((StatusCode::UNAUTHORIZED, "bad signature"));
    }
    Ok(())
}

pub(crate) async fn push_register(
    State(state): State<AppState>,
    Json(req): Json<PushRegisterRequest>,
) -> Response {
    if IdentityHash::from_hex(&req.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    if !acceptable_push_endpoint(&req.endpoint, state.config.prod, state.fcm.is_some()) {
        return (StatusCode::BAD_REQUEST, "unacceptable endpoint").into_response();
    }
    let msg = protocol_types::push_register_signing_message(&req.hash, &req.endpoint, &req.nonce);
    let mut inner = state.inner.lock().unwrap();
    if let Err(err) = consume_and_verify(
        &mut inner,
        &req.hash,
        &req.nonce,
        &msg,
        &req.signature,
        now(),
    ) {
        return err.into_response();
    }
    inner.push.insert(
        req.hash.clone(),
        PushSub {
            endpoint: req.endpoint.clone(),
            ..PushSub::default()
        },
    );
    if let Some(db) = &inner.db {
        let _ = db.upsert_push(&req.hash, &req.endpoint);
    }
    StatusCode::OK.into_response()
}

pub(crate) async fn push_unregister(
    State(state): State<AppState>,
    Json(req): Json<PushUnregisterRequest>,
) -> Response {
    if IdentityHash::from_hex(&req.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let msg = protocol_types::push_unregister_signing_message(&req.hash, &req.nonce);
    let mut inner = state.inner.lock().unwrap();
    if let Err(err) = consume_and_verify(
        &mut inner,
        &req.hash,
        &req.nonce,
        &msg,
        &req.signature,
        now(),
    ) {
        return err.into_response();
    }
    inner.push.remove(&req.hash);
    if let Some(db) = &inner.db {
        let _ = db.delete_push(&req.hash);
    }
    StatusCode::OK.into_response()
}

// ─────────────────────── Call-control key bindings ───────────────────────
// A device publishes the Curve25519 key that incoming-call capsules are sealed to, so a
// locked phone can be rung without opening its chat vault. The relay is a dumb, bounded
// shelf here: the binding is signed by the device's own roster key and every fetcher
// re-verifies it against the KT roster, so the relay can neither mint a key nor point a
// caller at one of its own. All it enforces is *who may write this shelf*.

#[derive(Deserialize)]
pub struct CallKeyPublishRequest {
    /// Mailbox hash of the publishing device (the account hash for the primary).
    pub hash: String,
    /// The account's username hash. Checked against `hash` + the binding's device id, so
    /// it cannot name an account this device does not belong to — and it is what the
    /// call-control mailbox is derived from.
    pub account_hash: String,
    /// Single-use nonce from `GET /v1/challenge`.
    pub nonce: String,
    /// Ed25519 over [`protocol_types::call_key_publish_signing_message`], by the same
    /// device key the directory holds for `hash`.
    pub signature: String,
    pub binding: kt_log::CallKeyBinding,
}

pub(crate) async fn publish_call_key(
    State(state): State<AppState>,
    Json(req): Json<CallKeyPublishRequest>,
) -> Response {
    if IdentityHash::from_hex(&req.hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    if !req.binding.well_formed() {
        return (StatusCode::BAD_REQUEST, "malformed binding").into_response();
    }
    // The publisher's mailbox must really be this account's mailbox for this device.
    let derived = protocol_types::device_mailbox_hash(&req.account_hash, &req.binding.device_id);
    if derived.map(|h| h.as_str().to_string()).as_deref() != Some(req.hash.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            "mailbox does not match the account",
        )
            .into_response();
    }
    let Some(call_mailbox) =
        protocol_types::call_mailbox_hash(&req.account_hash, &req.binding.device_id)
    else {
        return (StatusCode::BAD_REQUEST, "malformed account hash").into_response();
    };
    let call_mailbox = call_mailbox.as_str().to_string();
    // A key minted far in the future would out-rank every later honest publication for
    // that device (`supersedes` is time-ordered), so refuse one outright.
    let t = now();
    if req.binding.created_at > t.saturating_add(CALL_KEY_SKEW_SECS) {
        return (StatusCode::BAD_REQUEST, "binding is from the future").into_response();
    }
    let msg = protocol_types::call_key_publish_signing_message(
        &req.hash,
        &req.binding.call_key,
        req.binding.created_at,
        &req.nonce,
    );
    let mut inner = state.inner.lock().unwrap();
    if let Err(err) = consume_and_verify(&mut inner, &req.hash, &req.nonce, &msg, &req.signature, t)
    {
        return err.into_response();
    }
    // Monotonic per mailbox: a replayed older publication must not displace the key the
    // device is actually listening with.
    if inner
        .call_keys
        .get(&req.hash)
        .is_some_and(|current| !req.binding.supersedes(current) && *current != req.binding)
    {
        return (StatusCode::CONFLICT, "a newer call key is published").into_response();
    }
    // Give the device's call-control mailbox a directory record of its own, keyed by the
    // published Ed25519 half. That is what lets a **locked** device authenticate a
    // subscription to it: its account signing key is sealed in the vault, and the whole
    // point of the capsule path is that it works without opening it. The record carries
    // no one-time keys — nothing establishes a ratchet session there.
    let entry = DirectoryEntry {
        identity_key: req.binding.call_key.clone(),
        signing_key: req.binding.call_signing_key.clone(),
        one_time_keys: Default::default(),
        fallback_key: None,
    };
    if let Some(db) = &inner.db {
        if let Ok(json) = serde_json::to_string(&req.binding) {
            let _ = db.upsert_call_key(&req.hash, &json);
        }
        let _ = db.upsert_directory(&call_mailbox, &entry);
    }
    inner.directory.insert(call_mailbox, entry);
    inner.call_keys.insert(req.hash.clone(), req.binding);
    StatusCode::OK.into_response()
}

/// Serve a device's published call-control binding. Public, like a prekey bundle — the
/// fetcher's KT-roster verification is what makes it trustworthy.
pub(crate) async fn fetch_call_key(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Response {
    if IdentityHash::from_hex(&hash).is_none() {
        return (StatusCode::BAD_REQUEST, "malformed hash").into_response();
    }
    let inner = state.inner.lock().unwrap();
    match inner.call_keys.get(&hash) {
        Some(binding) => Json(binding.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no call key published").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::acceptable_push_endpoint as accept_full;
    use crate::http::msg::claim_wake;
    use crate::state::{Config, PushSub};
    use protocol_types::WakeClass;

    /// Legacy-signature shim: the webhook policy is FCM-independent.
    fn acceptable_push_endpoint(endpoint: &str, prod: bool) -> bool {
        assert_eq!(
            accept_full(endpoint, prod, false),
            accept_full(endpoint, prod, true),
            "webhook policy must not depend on FCM config"
        );
        accept_full(endpoint, prod, false)
    }

    #[test]
    fn fcm_endpoints_gated_on_config() {
        let token = "e".repeat(64);
        let ep = format!("fcm:{token}");
        // Refused outright when the relay has no FCM service account.
        assert!(!accept_full(&ep, true, false));
        assert!(!accept_full(&ep, false, false));
        // Accepted (prod or dev) when configured.
        assert!(accept_full(&ep, true, true));
        assert!(accept_full(&ep, false, true));
        // Garbage token shapes are refused even when configured.
        assert!(!accept_full("fcm:", true, true));
        assert!(!accept_full("fcm:short", true, true));
        assert!(!accept_full(&format!("fcm:{} x", token), true, true)); // whitespace
        assert!(!accept_full(
            &format!("fcm:{}", "e".repeat(5000)),
            true,
            true
        ));
        // The fcm scheme never reaches the URL logic — an fcm-prefixed URL is a token.
        assert!(!accept_full("fcm:https://127.0.0.1/\n", true, true));
    }

    #[test]
    fn wake_policy_per_class() {
        let config = Config {
            wake_debounce_secs: 30,
            call_wake_min_secs: 2,
            control_wake_min_secs: 1,
            ..Config::default()
        };
        let mut sub = PushSub {
            endpoint: "https://push.example/up".into(),
            ..PushSub::default()
        };

        // None never wakes.
        assert!(claim_wake(&mut sub, WakeClass::None, 1000, &config).is_none());

        // Normal: first fires, burst inside the window is debounced, after it fires.
        assert!(claim_wake(&mut sub, WakeClass::Normal, 1000, &config).is_some());
        assert!(claim_wake(&mut sub, WakeClass::Normal, 1010, &config).is_none());
        assert!(claim_wake(&mut sub, WakeClass::Normal, 1030, &config).is_some());

        // Call bypasses the message debounce entirely (fires right inside the
        // 30 s normal window)…
        assert!(claim_wake(&mut sub, WakeClass::Call, 1031, &config).is_some());
        // …but has its own 2 s anti-flood interval.
        assert!(claim_wake(&mut sub, WakeClass::Call, 1032, &config).is_none());
        assert!(claim_wake(&mut sub, WakeClass::Call, 1033, &config).is_some());
        // Terminal controls use a bucket of their own, so a ring-offer debounce can never
        // swallow the one instruction capable of stopping an already-presented Android
        // ring, and one call's worth of controls all get through together.
        for _ in 0..crate::http::msg::CONTROL_WAKE_BURST {
            assert!(claim_wake(&mut sub, WakeClass::CallControl, 1033, &config).is_some());
        }
        // …but the bucket is bounded, or one sender could drive an unbounded stream of
        // silent high-priority wakes at a device whose user sees only battery drain (A-15).
        assert!(claim_wake(&mut sub, WakeClass::CallControl, 1033, &config).is_none());
        // It refills at the configured rate rather than staying shut.
        assert!(claim_wake(&mut sub, WakeClass::CallControl, 1034, &config).is_some());
        assert!(claim_wake(&mut sub, WakeClass::CallControl, 1034, &config).is_none());
        // And a call wake does not consume the normal debounce slot.
        assert!(claim_wake(&mut sub, WakeClass::Normal, 1060, &config).is_some());
    }
    #[test]
    fn push_endpoint_policy() {
        // Dev mode: http allowed (local testing), garbage refused.
        assert!(acceptable_push_endpoint(
            "http://127.0.0.1:9/up?token=x",
            false
        ));
        assert!(acceptable_push_endpoint(
            "https://push.example.org/up",
            false
        ));
        assert!(!acceptable_push_endpoint("not a url", false));
        assert!(!acceptable_push_endpoint(
            "ftp://push.example.org/up",
            false
        ));

        // Prod: https only, no loopback/private/link-local/localhost targets.
        assert!(acceptable_push_endpoint("https://ntfy.sh/mytopic", true));
        assert!(!acceptable_push_endpoint(
            "http://push.example.org/up",
            true
        ));
        assert!(!acceptable_push_endpoint("https://127.0.0.1/up", true));
        assert!(!acceptable_push_endpoint("https://10.0.0.5/up", true));
        assert!(!acceptable_push_endpoint("https://192.168.1.10/up", true));
        assert!(!acceptable_push_endpoint(
            "https://169.254.169.254/latest/meta-data",
            true
        ));
        assert!(!acceptable_push_endpoint("https://[::1]/up", true));
        assert!(!acceptable_push_endpoint("https://[fe80::1]/up", true));
        assert!(!acceptable_push_endpoint("https://[fc00::1]/up", true));
        assert!(!acceptable_push_endpoint("https://localhost/up", true));
        assert!(!acceptable_push_endpoint("https://LOCALHOST/up", true));

        // H-1 regression: IPv4-mapped / embedded-IPv6 forms of internal targets must be
        // canonicalized and rejected — they used to slip past the v6-only checks.
        assert!(!acceptable_push_endpoint(
            "https://[::ffff:127.0.0.1]/up",
            true
        ));
        assert!(!acceptable_push_endpoint(
            "https://[::ffff:169.254.169.254]/latest/meta-data",
            true
        ));
        assert!(!acceptable_push_endpoint(
            "https://[::ffff:10.0.0.5]/up",
            true
        ));
        assert!(!acceptable_push_endpoint("https://[::ffff:a00:5]/up", true)); // hex form of 10.0.0.5
        assert!(!acceptable_push_endpoint("https://[::127.0.0.1]/up", true)); // IPv4-compatible
        assert!(!acceptable_push_endpoint(
            "https://[64:ff9b::a9fe:a9fe]/up", // NAT64-embedded 169.254.169.254
            true
        ));
        assert!(!acceptable_push_endpoint(
            "https://[2002:a00:5::]/up", // 6to4-embedded 10.0.0.5
            true
        ));
        // CGNAT + protocol-assignment IPv4 ranges is_private() misses.
        assert!(!acceptable_push_endpoint("https://100.64.0.1/up", true));
        // A genuine public IPv6 push host is still accepted.
        assert!(acceptable_push_endpoint(
            "https://[2606:4700:4700::1111]/up",
            true
        ));

        // Length cap.
        let long = format!("https://push.example.org/{}", "x".repeat(3000));
        assert!(!acceptable_push_endpoint(&long, true));
    }
}
