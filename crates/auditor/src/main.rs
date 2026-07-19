//! `sona-auditor` — standalone Key Transparency witness daemon.
//!
//! Point it at a relay and let it run (ideally on a different machine than the relay,
//! by a different party — that independence is what makes equivocation detectable):
//!
//! ```sh
//! SONA_RELAY_URL=https://relay.example.org sona-auditor
//! ```
//!
//! Environment:
//! * `SONA_RELAY_URL`          — relay base URL (required).
//! * `SONA_KT_PUBKEY`          — base64 Ed25519 KT key to pin. If unset, the key is
//!   fetched once on first run (trust-on-first-use) and pinned in the state file
//!   forever after.
//! * `SONA_ACCESS_TOKEN`       — shared access token for a private relay
//!   (`ACCESS_MODE=token/stealth`). Without it such a relay answers 401/404 and the
//!   log cannot be witnessed — a private relay still needs its auditors.
//! * `AUDITOR_STATE`           — witness state file (default `./sona-auditor.json`).
//! * `AUDITOR_INTERVAL_SECS`   — poll interval (default 300; `0` = observe once, exit).
//!
//! Exit codes (single-shot mode): 0 honest, 2 ALARM. In loop mode an alarm is written
//! to `<state>.alarm-<timestamp>.json` (both signed heads + failed proof — everything a
//! third party needs to verify the misbehavior) and the process keeps witnessing.

use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use auditor::{observe_once, Outcome, Witness};
use serde::Deserialize;

#[derive(Deserialize)]
struct PubkeyResponse {
    pubkey: String,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_witness(path: &Path, pinned_env: Option<String>) -> Option<Witness> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let w: Witness = serde_json::from_slice(&bytes)
                .map_err(|e| {
                    eprintln!("error: corrupt state file {}: {e}", path.display());
                    exit(1);
                })
                .unwrap();
            // A pinned key from the environment must match the one already on disk —
            // silently switching pins would defeat the whole point of witnessing.
            if let Some(pin) = pinned_env {
                if pin != w.pinned_key_b64 {
                    eprintln!(
                        "error: SONA_KT_PUBKEY differs from the key pinned in {} — refusing",
                        path.display()
                    );
                    exit(1);
                }
            }
            Some(w)
        }
        Err(_) => pinned_env.map(Witness::new),
    }
}

fn save(path: &Path, witness: &Witness) {
    let json = serde_json::to_vec_pretty(witness).expect("witness serializes");
    if let Err(e) = std::fs::write(path, json) {
        eprintln!(
            "error: cannot persist witness state to {}: {e}",
            path.display()
        );
        exit(1);
    }
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status().as_u16()));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let base = env("SONA_RELAY_URL").unwrap_or_else(|| {
        eprintln!("error: SONA_RELAY_URL is required");
        exit(1);
    });
    let base = base.trim_end_matches('/').to_string();
    let state_path = PathBuf::from(env("AUDITOR_STATE").unwrap_or("sona-auditor.json".into()));
    let interval: u64 = env("AUDITOR_INTERVAL_SECS")
        .map(|v| v.parse().expect("AUDITOR_INTERVAL_SECS must be a number"))
        .unwrap_or(300);

    // Private relay support: attach the shared access token to every request (the
    // relay's gate covers the KT endpoints too). Marked sensitive so logging layers
    // redact it.
    let client = match env("SONA_ACCESS_TOKEN") {
        Some(token) => {
            let mut headers = reqwest::header::HeaderMap::new();
            let mut v = reqwest::header::HeaderValue::from_str(token.trim()).unwrap_or_else(|_| {
                eprintln!("error: SONA_ACCESS_TOKEN contains invalid header characters");
                exit(1);
            });
            v.set_sensitive(true);
            headers.insert("x-sona-access", v);
            reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .expect("reqwest client builds")
        }
        None => reqwest::Client::new(),
    };

    // Pin the KT key: from env, from the existing state file, or (last resort) TOFU.
    let mut witness = match load_witness(&state_path, env("SONA_KT_PUBKEY")) {
        Some(w) => w,
        None => {
            let key: PubkeyResponse = fetch_json(&client, &format!("{base}/v1/kt/pubkey"))
                .await
                .unwrap_or_else(|e| {
                    eprintln!("error: cannot fetch KT key to pin: {e}");
                    exit(1);
                });
            println!("pinned KT key (trust-on-first-use): {}", key.pubkey);
            Witness::new(key.pubkey)
        }
    };
    save(&state_path, &witness);

    loop {
        match observe_once(&client, &base, &mut witness).await {
            Ok(Outcome::Alarm(alarm)) => {
                let evidence = state_path.with_extension(format!("alarm-{}.json", now()));
                let json = serde_json::to_vec_pretty(&alarm).expect("alarm serializes");
                let _ = std::fs::write(&evidence, json);
                eprintln!(
                    "ALARM [{:?}]: the relay's Key Transparency log violated append-only \
                     consistency. Evidence written to {} — do not trust key lookups from \
                     this relay until resolved.",
                    alarm.kind,
                    evidence.display()
                );
                if interval == 0 {
                    exit(2);
                }
            }
            Ok(outcome) => {
                save(&state_path, &witness);
                match outcome {
                    Outcome::FirstHead => println!(
                        "baseline pinned: size {}",
                        witness.last.as_ref().map(|h| h.tree_size).unwrap_or(0)
                    ),
                    Outcome::Extended { from, to } => {
                        println!("log grew {from} → {to}: append-only consistency verified")
                    }
                    Outcome::Unchanged => println!("log unchanged: head matches"),
                    Outcome::Alarm(_) => unreachable!(),
                }
                if interval == 0 {
                    exit(0);
                }
            }
            Err(e) => {
                eprintln!("transport error (will retry): {e}");
                if interval == 0 {
                    exit(1);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
