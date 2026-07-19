//! QUIC transport for call media — the client side of the relay's `quic` module.
//!
//! Why: WebSocket media rides TCP, where one lost packet stalls everything behind it
//! (head-of-line blocking) — the worst failure mode for a live call. Over QUIC:
//!
//! * voice + screen-audio frames are **unreliable datagrams**: a lost frame is 20 ms
//!   of silence, never a stall;
//! * each encoded video frame's cells travel on **their own short reliable stream**:
//!   a retransmit delays only that frame, and the H.264 reference chain never breaks;
//! * room control (`joined` / `peer_joined` / `peer_left`) is newline-framed JSON on
//!   one bidirectional stream — reliable for the life of the call. A dissolved room
//!   may also arrive as the connection-close *reason* (`peer_left`), which QUIC
//!   delivers atomically even when the control line didn't flush first.
//!
//! Trust: QUIC mandates TLS, but the relay's certificate is a boot-time self-signed
//! one. The client fetches `{port, cert_sha256}` from `GET /v1/call/quic` over the
//! HTTPS channel it already trusts, then pins the **exact certificate hash** for the
//! QUIC handshake. The TLS layer is transport armor only — media above it is
//! end-to-end encrypted and the relay is blind either way (see `docs/PROTOCOL.md`).
//!
//! Failure anywhere here (UDP blocked, old relay, timeout) is silent: the caller
//! falls back to the WebSocket path. Latency is a bonus, never a requirement.

use std::sync::Arc;

use protocol_types::quicwire::{frame_cells, parse_cells, ALPN, MAX_STREAM_GROUP_BYTES};
use sha2::{Digest, Sha256};

use crate::call::CallWireEvent;
use crate::{ClientError, Result};

/// How long the whole QUIC attempt may take before the WebSocket fallback wins.
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Trust exactly one certificate, identified by the SHA-256 of its DER encoding (the
/// hash arrives over the already-authenticated HTTPS channel). Signatures are still
/// verified — the pin binds the key, the handshake proves possession of it.
#[derive(Debug)]
struct PinnedCert {
    sha256: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.sha256 {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// One QUIC call leg: the connection (for sending) plus a unified event queue fed by
/// background pump tasks (control lines, datagrams, incoming streams). The pumps keep
/// `next_event` cancel-safe — dropping its future loses nothing.
pub(crate) struct QuicMedia {
    conn: quinn::Connection,
    events: tokio::sync::mpsc::UnboundedReceiver<CallWireEvent>,
    /// Keeps the endpoint (and its UDP socket) alive for the call's lifetime.
    _endpoint: quinn::Endpoint,
}

impl QuicMedia {
    /// Connect, join the room, and start the receive pumps. `access_token` rides after
    /// the call id when set — a token-mode relay refuses the join without it (an open
    /// relay never reads the extra line, so sending it is always safe).
    pub(crate) async fn connect(
        addr: std::net::SocketAddr,
        server_name: &str,
        cert_sha256: [u8; 32],
        call_id: &str,
        access_token: Option<&str>,
    ) -> Result<QuicMedia> {
        let err = |e: String| ClientError::Ws(format!("quic: {e}"));

        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert {
                sha256: cert_sha256,
            }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| err(e.to_string()))?,
        ));
        let bind: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("addr")
        } else {
            "[::]:0".parse().expect("addr")
        };
        let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| err(e.to_string()))?;
        endpoint.set_default_client_config(cfg);

        let conn = endpoint
            .connect(addr, server_name)
            .map_err(|e| err(e.to_string()))?
            .await
            .map_err(|e| err(e.to_string()))?;

        // Join: our first bidi stream carries the call id (+ the access token line on a
        // private relay); the server talks back in newline-framed JSON for the rest of
        // the call.
        let (mut ctrl_tx, ctrl_rx) = conn.open_bi().await.map_err(|e| err(e.to_string()))?;
        let mut join = call_id.as_bytes().to_vec();
        if let Some(token) = access_token.map(str::trim).filter(|t| !t.is_empty()) {
            join.extend_from_slice(token.as_bytes());
            join.push(b'\n');
        }
        ctrl_tx
            .write_all(&join)
            .await
            .map_err(|e| err(e.to_string()))?;

        let (ev_tx, events) = tokio::sync::mpsc::unbounded_channel();

        // ── Control pump: JSON lines → events; close reason `peer_left` → PeerLeft. ──
        {
            let ev_tx = ev_tx.clone();
            let conn = conn.clone();
            let mut ctrl_rx = ctrl_rx;
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match ctrl_rx.read_exact(&mut byte).await {
                        Ok(()) => {}
                        Err(_) => {
                            // Stream/connection gone. A room dissolved by the peer
                            // hanging up closes with reason "peer_left" — surface it
                            // as the event the engine expects, then end the session.
                            if let Some(quinn::ConnectionError::ApplicationClosed(ac)) =
                                conn.close_reason()
                            {
                                if ac.reason.as_ref() == b"peer_left" {
                                    let _ = ev_tx.send(CallWireEvent::PeerLeft);
                                }
                            }
                            let _ = ev_tx.send(CallWireEvent::Closed);
                            return;
                        }
                    }
                    if byte[0] != b'\n' {
                        line.push(byte[0]);
                        continue;
                    }
                    let v: serde_json::Value = match serde_json::from_slice(&line) {
                        Ok(v) => v,
                        Err(_) => {
                            line.clear();
                            continue;
                        }
                    };
                    line.clear();
                    let ev = match v["type"].as_str() {
                        Some("joined") => Some(CallWireEvent::Joined {
                            peers: v["peers"].as_u64().unwrap_or(1) as u8,
                            media: v["media"].as_u64().unwrap_or(1) as u8,
                        }),
                        Some("peer_joined") => Some(CallWireEvent::PeerJoined),
                        Some("peer_left") => Some(CallWireEvent::PeerLeft),
                        _ => None,
                    };
                    if let Some(ev) = ev {
                        if ev_tx.send(ev).is_err() {
                            return;
                        }
                    }
                }
            });
        }

        // ── Datagram pump: each datagram is one loss-tolerant media frame. ──
        {
            let ev_tx = ev_tx.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Ok(b) = conn.read_datagram().await {
                    if ev_tx.send(CallWireEvent::Frame(b.to_vec())).is_err() {
                        return;
                    }
                }
            });
        }

        // ── Stream pump: each incoming uni stream is one reliable cell group. ──
        {
            let ev_tx = ev_tx.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                while let Ok(mut s) = conn.accept_uni().await {
                    let ev_tx = ev_tx.clone();
                    tokio::spawn(async move {
                        let Ok(group) = s.read_to_end(MAX_STREAM_GROUP_BYTES).await else {
                            return;
                        };
                        let Some(cells) = parse_cells(&group) else {
                            return; // malformed — drop the group, not the call
                        };
                        for cell in cells {
                            if ev_tx.send(CallWireEvent::Frame(cell)).is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        }

        Ok(QuicMedia {
            conn,
            events,
            _endpoint: endpoint,
        })
    }

    /// Loss-tolerant send (voice / screen audio). Dropped frames are fine; a dead
    /// connection is not — that's the only error surfaced.
    pub(crate) fn send_lossy(&self, frame: Vec<u8>) -> Result<()> {
        match self.conn.send_datagram(frame.into()) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::ConnectionLost(e)) => {
                Err(ClientError::Ws(format!("quic: {e}")))
            }
            Err(_) => Ok(()), // too large / not supported: drop, engine cadence continues
        }
    }

    /// Reliable group send (one video frame's cells, or a control cell): one short
    /// unidirectional stream.
    pub(crate) async fn send_cells(&self, cells: Vec<Vec<u8>>) -> Result<()> {
        let mut s = self
            .conn
            .open_uni()
            .await
            .map_err(|e| ClientError::Ws(format!("quic: {e}")))?;
        s.write_all(&frame_cells(&cells))
            .await
            .map_err(|e| ClientError::Ws(format!("quic: {e}")))?;
        let _ = s.finish();
        Ok(())
    }

    /// Next room/media event. Cancel-safe (pumps own the sockets).
    pub(crate) async fn next_event(&mut self) -> CallWireEvent {
        self.events.recv().await.unwrap_or(CallWireEvent::Closed)
    }

    pub(crate) fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }
}
