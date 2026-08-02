//! Relay access control: discoverability tiers + optional IP allowlist.
//!
//! A self-hoster may not want their relay discoverable or usable by strangers — if the
//! endpoint shapes are public (this repo is), scrapers can fingerprint relays and probe
//! them for vulnerabilities. `ACCESS_MODE` picks the posture:
//!
//! * **open** (default) — today's behavior: anyone may use the relay.
//! * **token** — every request must carry the shared access token in `x-sona-access`.
//!   Wrong/missing token → `401`. The relay is visible but unusable without the token.
//! * **stealth** — token required AND every rejected request gets a bare, uniform `404`
//!   with an empty body — exactly what this server answers for any unknown path — so a
//!   scanner cannot distinguish the relay from a web server with nothing on it.
//!
//! The gate runs as the **outermost** middleware, before routing and body parsing: a
//! future bug in any handler, JSON shape, or the KT log is unreachable without the
//! token. That containment is the main point, not the secrecy itself.
//!
//! ## Why ONE shared token and not per-user credentials
//!
//! Sealed sender is the relay's core privacy property: `POST /v1/messages` is
//! deliberately unauthenticated so the server cannot learn who talks to whom. A
//! per-user credential on every request would attribute every send and destroy that
//! anonymity set. One shared token keeps all members mutually indistinguishable.
//! Trade-off accepted: evicting a member means rotating the token (the env var takes a
//! comma-separated list precisely so rotation can overlap).
//!
//! ## IP allowlist (`IP_ALLOWLIST`)
//!
//! Independent of the mode, OFF unless set: a comma-separated CIDR list checked against
//! the reverse proxy's `X-Real-IP`. Fail-closed in production when the header is
//! missing (same rule as the rate limiter). Practical mainly for VPN / static-IP
//! deployments — roaming phones change addresses constantly.

use std::net::IpAddr;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::{AppState, Config};

/// Header carrying the shared relay-access token.
pub const ACCESS_HEADER: &str = "x-sona-access";

/// Discoverability tier. See the module docs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AccessMode {
    #[default]
    Open,
    Token,
    Stealth,
}

impl AccessMode {
    /// Parse the `ACCESS_MODE` env value. `None` = unrecognized (caller fails closed).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "open" => Some(Self::Open),
            "token" => Some(Self::Token),
            "stealth" => Some(Self::Stealth),
            _ => None,
        }
    }
}

/// SHA-256 of an access token. Config holds digests, never the tokens themselves, and
/// the gate compares digests — equality on fixed-width hashes leaks no usable timing
/// about the token (recovering a token from digest-prefix timing is a preimage attack).
pub fn token_digest(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).into()
}

/// One IP allowlist entry: a single address (`1.2.3.4`, `fd00::1`) or a CIDR block
/// (`10.0.0.0/8`, `fd00::/8`).
#[derive(Clone, Copy, Debug)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr[/prefix]`. `None` on malformed input or an out-of-range prefix —
    /// the caller must refuse to start rather than silently narrow the list.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_s {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// Does this block contain `ip`? Cross-family never matches (the caller
    /// canonicalizes IPv4-mapped IPv6 to IPv4 first).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// The raw client address from the trusted reverse proxy, for CIDR matching. Same trust
/// model as [`crate::http`]'s `client_key`, but unhashed — the allowlist needs the real
/// address. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is canonicalized so a v4 allowlist
/// entry matches however the proxy renders the address.
fn raw_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let ip: IpAddr = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())?
        .trim()
        .parse()
        .ok()?;
    Some(canonical_ip(ip))
}

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) down to its v4 form, so a
/// v4 allowlist entry matches however the address was rendered — and so a `::ffff:` form
/// cannot slip past the allowlist.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 => v4,
    }
}

/// Whether `ip` is admitted by the configured allowlist. An empty allowlist is "off",
/// admitting everything.
///
/// Exposed for the QUIC media endpoint (SP-14), which never traverses the axum `gate`
/// middleware, so `ACCESS_MODE=open` + `IP_ALLOWLIST=…` — the documented "only these
/// addresses may use the relay" posture — left udp/4443 answering anyone. QUIC is
/// published straight to clients and always has a real peer address, so it passes
/// `conn.remote_address()` here rather than reading any proxy header, and there is no
/// dev bypass to reintroduce.
pub fn ip_allowed(config: &Config, ip: IpAddr) -> bool {
    config.ip_allowlist.is_empty()
        || config
            .ip_allowlist
            .iter()
            .any(|c| c.contains(canonical_ip(ip)))
}

/// The deny response for this mode. Stealth is a bare `404` with an empty body —
/// byte-identical to this server's answer for any unknown path — for BOTH failure
/// kinds, so probes learn nothing (a distinct "bad address" vs "bad token" answer
/// would itself be a fingerprint).
fn deny(mode: AccessMode, status: StatusCode, reason: &'static str) -> Response {
    match mode {
        AccessMode::Stealth => StatusCode::NOT_FOUND.into_response(),
        _ => (status, reason).into_response(),
    }
}

/// Pure decision function (unit-testable without a running server). `None` = admitted.
pub fn check(config: &Config, headers: &HeaderMap) -> Option<Response> {
    if !config.ip_allowlist.is_empty() {
        let ok = match raw_client_ip(headers) {
            Some(ip) => config.ip_allowlist.iter().any(|c| c.contains(ip)),
            // No trusted proxy address: fail closed in prod, allow in dev (no proxy
            // exists there) — mirrors `client_key`.
            None => !config.prod,
        };
        if !ok {
            return Some(deny(
                config.access_mode,
                StatusCode::FORBIDDEN,
                "address not allowed",
            ));
        }
    }
    match config.access_mode {
        AccessMode::Open => None,
        AccessMode::Token | AccessMode::Stealth => {
            let presented = headers
                .get(ACCESS_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(token_digest);
            let ok = presented.is_some_and(|d| config.access_token_hashes.contains(&d));
            if ok {
                None
            } else {
                Some(deny(
                    config.access_mode,
                    StatusCode::UNAUTHORIZED,
                    "access token required",
                ))
            }
        }
    }
}

/// The middleware: applied outermost in [`crate::http::app`], so it also covers the
/// WebSocket upgrades (native clients attach the header on the upgrade request).
pub async fn gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(denied) = check(&state.config, req.headers()) {
        return denied;
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_and_contains() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.1.2.3".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        // Bare address = /32.
        let host = Cidr::parse("192.168.1.5").unwrap();
        assert!(host.contains("192.168.1.5".parse().unwrap()));
        assert!(!host.contains("192.168.1.6".parse().unwrap()));
        // v6 block; cross-family never matches.
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        // /0 matches everything in-family.
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("203.0.113.9".parse().unwrap()));
        // Malformed inputs refuse to parse (caller fails closed).
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
        assert!(Cidr::parse("10.0.0.0/x").is_none());
    }

    #[test]
    fn mapped_v4_matches_v4_allowlist() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "::ffff:10.1.2.3".parse().unwrap());
        let ip = raw_client_ip(&headers).unwrap();
        assert!(net.contains(ip));
    }

    #[test]
    fn access_mode_parses() {
        assert_eq!(AccessMode::parse("open"), Some(AccessMode::Open));
        assert_eq!(AccessMode::parse(""), Some(AccessMode::Open));
        assert_eq!(AccessMode::parse("Token"), Some(AccessMode::Token));
        assert_eq!(AccessMode::parse("STEALTH"), Some(AccessMode::Stealth));
        assert_eq!(AccessMode::parse("bogus"), None);
    }
}
