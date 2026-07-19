//! FCM wake adapter — the relay side of `fcm:<token>` push endpoints.
//!
//! The webhook path (any HTTPS URL, the UnifiedPush shape) stays exactly as it is in
//! `http.rs`; this module adds a second endpoint form the relay understands natively.
//! It speaks the FCM HTTP v1 API directly — OAuth2 service-account JWT (RS256) minted
//! here, no Google SDK — and sends **data-only, content-free** messages: the payload is
//! a constant `{"t":"m"}` or `{"t":"c"}` (message / call wake class). Google learns the
//! wake class and timing, nothing else — strictly less than Signal, which ships the
//! sealed envelope bytes *through* FCM.
//!
//! Error posture: wakes are cheap and fire-and-forget. `UNREGISTERED`/dead-token
//! responses tell the caller to delete the push row (the device re-registers via
//! `onNewToken` on its next start); anything transient is dropped — the next envelope
//! re-fires.

use protocol_types::WakeClass;

/// OAuth scope FCM v1 requires.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// How long a minted access token is reused. Google issues 3600 s tokens; refreshing at
/// 55 min leaves comfortable slack.
const TOKEN_REUSE_SECS: u64 = 55 * 60;
/// Outbound HTTP timeout — a slow Google endpoint must not pile up wake tasks.
const HTTP_TIMEOUT_SECS: u64 = 10;

/// What became of one wake attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    Sent,
    /// The registration token is dead (`UNREGISTERED` / unrecoverably invalid) — the
    /// caller should delete the push row so the relay stops trying (self-heal).
    DeadToken,
    /// Transient failure (auth hiccup, 429/5xx, network). Dropped; wakes are cheap.
    Transient,
}

/// A configured FCM sender: service-account credentials + a cached access token.
pub struct FcmSender {
    project_id: String,
    client_email: String,
    token_uri: String,
    signing_key: ring::rsa::KeyPair,
    http: reqwest::Client,
    /// (bearer token, expires_at unix secs).
    cached: tokio::sync::Mutex<Option<(String, u64)>>,
    /// Overrides the FCM send URL in tests (mock endpoint).
    send_url_override: Option<String>,
}

/// Extract the PKCS#8 DER from a `-----BEGIN PRIVATE KEY-----` PEM (the shape Google
/// service-account JSONs carry). No PEM crate needed for this one fixed format.
fn pkcs8_der_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    STANDARD
        .decode(body.trim())
        .map_err(|e| format!("service account private key PEM: {e}"))
}

impl FcmSender {
    /// Build from a Google service-account JSON (the file's verbatim contents). The
    /// project id comes from the JSON unless `project_override` is set.
    pub fn from_service_account_json(
        json: &str,
        project_override: Option<String>,
    ) -> Result<Self, String> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("service account JSON: {e}"))?;
        let field = |k: &str| {
            v[k].as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("service account JSON missing `{k}`"))
        };
        let project_id = match project_override {
            Some(p) => p,
            None => field("project_id")?,
        };
        let client_email = field("client_email")?;
        let token_uri = v["token_uri"]
            .as_str()
            .unwrap_or("https://oauth2.googleapis.com/token")
            .to_string();
        let der = pkcs8_der_from_pem(&field("private_key")?)?;
        let key = ring::rsa::KeyPair::from_pkcs8(&der)
            .map_err(|e| format!("service account private key: {e}"))?;
        Ok(Self {
            project_id,
            client_email,
            token_uri,
            signing_key: key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()
                .map_err(|e| format!("http client: {e}"))?,
            cached: tokio::sync::Mutex::new(None),
            send_url_override: None,
        })
    }

    /// Test hook: send wakes to a mock endpoint instead of Google.
    pub fn with_send_url(mut self, url: String) -> Self {
        self.send_url_override = Some(url);
        self
    }

    /// Base64url (no pad) — the JWT alphabet.
    fn b64url(data: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Mint the RS256 service-account JWT for the OAuth token exchange (ring, constant-time).
    fn assertion(&self, now: u64) -> String {
        let header = Self::b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = Self::b64url(
            serde_json::json!({
                "iss": self.client_email,
                "scope": FCM_SCOPE,
                "aud": self.token_uri,
                "iat": now,
                "exp": now + 3600,
            })
            .to_string()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0u8; self.signing_key.public().modulus_len()];
        // Constant-time RS256 (ring) — see the Cargo.toml note on RUSTSEC-2023-0071.
        self.signing_key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut sig,
            )
            .expect("RS256 signing with a validated key cannot fail");
        format!("{signing_input}.{}", Self::b64url(&sig))
    }

    /// A valid bearer token — cached, refreshed via the OAuth2 JWT grant when stale.
    async fn bearer(&self) -> Result<String, String> {
        let now = crate::state::now();
        let mut cached = self.cached.lock().await;
        if let Some((token, exp)) = cached.as_ref() {
            if *exp > now {
                return Ok(token.clone());
            }
        }
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &self.assertion(now)),
            ])
            .send()
            .await
            .map_err(|e| format!("token exchange: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("token exchange status {}", resp.status()));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("token response: {e}"))?;
        let token = v["access_token"]
            .as_str()
            .ok_or("token response missing access_token")?
            .to_string();
        *cached = Some((token.clone(), now + TOKEN_REUSE_SECS));
        Ok(token)
    }

    /// Fire one content-free wake at `token`. Data-only, high priority for both classes
    /// (every wake produces a user-visible result, which is what Android's high-priority
    /// budget wants); calls get a 60 s TTL so a stale offer push dies in transit instead
    /// of ringing a phone that was off — the drain then surfaces "Missed call" from the
    /// mailbox. Never a `notification:` payload — display stays local, post-decrypt.
    pub async fn wake(&self, token: &str, class: WakeClass) -> WakeOutcome {
        let (t, ttl) = match class {
            WakeClass::Call => ("c", "60s"),
            _ => ("m", "86400s"),
        };
        let bearer = match self.bearer().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[fcm] {e}");
                return WakeOutcome::Transient;
            }
        };
        let url = match &self.send_url_override {
            Some(u) => u.clone(),
            None => format!(
                "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                self.project_id
            ),
        };
        let body = serde_json::json!({
            "message": {
                "token": token,
                "data": { "t": t },
                "android": { "priority": "HIGH", "ttl": ttl, "collapse_key": "wake" },
            }
        });
        match self
            .http
            .post(url)
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    return WakeOutcome::Sent;
                }
                let text = resp.text().await.unwrap_or_default();
                // v1 signals a dead registration as 404 UNREGISTERED (or 400
                // INVALID_ARGUMENT for a malformed token). Both are permanent for
                // this token — purge the row; the device re-registers on next open.
                if status == 404
                    || text.contains("UNREGISTERED")
                    || (status == 400 && text.contains("INVALID_ARGUMENT"))
                {
                    return WakeOutcome::DeadToken;
                }
                eprintln!("[fcm] send status {status}");
                WakeOutcome::Transient
            }
            Err(e) => {
                eprintln!("[fcm] send: {e}");
                WakeOutcome::Transient
            }
        }
    }
}
