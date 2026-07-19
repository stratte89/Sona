//! QUIC media-relay integration: real UDP endpoint, real quinn clients, and a mixed
//! WebSocket+QUIC room. The relay must pair members across transports, keep the
//! datagram/stream framing rules straight, and enforce the same abuse bounds.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use server::quic::{frame_cells, parse_cells, ALPN};
use server::{app, AppState};
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::Message as Ws;

const CALL_ID: &str = "fedcba9876543210fedcba9876543210";

/// Certificate pinning by exact hash — the same trust model the real client uses
/// (the hash arrives over the already-trusted HTTPS channel).
#[derive(Debug)]
struct PinnedCert {
    sha256: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

/// Relay with both transports: returns (ws base url, quic addr, cert hash).
async fn spawn_relay() -> (String, std::net::SocketAddr, Vec<u8>) {
    let state = AppState::default();
    let info = server::quic::start(state.clone(), 0).expect("quic endpoint");
    *state.quic.lock().unwrap() = Some(info.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state).into_make_service())
            .await
            .unwrap();
    });

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let hash = STANDARD_NO_PAD.decode(&info.cert_sha256_b64).unwrap();
    let quic_addr = std::net::SocketAddr::from(([127, 0, 0, 1], info.port));
    (format!("ws://{addr}"), quic_addr, hash)
}

struct QuicLeg {
    conn: quinn::Connection,
    ctrl: quinn::RecvStream,
    _ep: quinn::Endpoint,
}

async fn quic_join(addr: std::net::SocketAddr, cert_hash: &[u8], call_id: &str) -> QuicLeg {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert {
            sha256: cert_hash.to_vec(),
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cfg);
    let conn = ep.connect(addr, "sona-relay").unwrap().await.unwrap();
    let (mut tx, ctrl) = conn.open_bi().await.unwrap();
    tx.write_all(call_id.as_bytes()).await.unwrap();
    QuicLeg {
        conn,
        ctrl,
        _ep: ep,
    }
}

/// Next room event with a loud timeout: either a control line, or — for a dissolved
/// room — the connection-close reason (the server closes with `peer_left` so the
/// notice can't be lost to an unflushed stream write).
async fn next_line(ctrl: &mut quinn::RecvStream) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match ctrl.read_exact(&mut byte).await {
                Ok(()) => {}
                Err(e) => return format!("<closed: {e:?}>"),
            }
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
            line.push(byte[0]);
        }
    })
    .await
    .expect("timed out waiting for a control line")
}

#[tokio::test]
async fn quic_members_pair_datagrams_and_streams_flow() {
    let (_ws, addr, hash) = spawn_relay().await;

    let mut a = quic_join(addr, &hash, CALL_ID).await;
    let joined = next_line(&mut a.ctrl).await;
    assert!(joined.contains(r#""peers":1"#) && joined.contains(r#""media":2"#));

    let mut b = quic_join(addr, &hash, CALL_ID).await;
    assert!(next_line(&mut b.ctrl).await.contains(r#""peers":2"#));
    assert!(next_line(&mut a.ctrl).await.contains("peer_joined"));

    // Voice-shaped datagram (first byte 0) crosses as a datagram.
    let voice = vec![0u8; 280];
    a.conn.send_datagram(voice.clone().into()).unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), b.conn.read_datagram())
        .await
        .expect("datagram in time")
        .unwrap();
    assert_eq!(got.as_ref(), &voice[..]);

    // A video frame's cells (track byte 1) cross as one uni stream, grouped.
    let cells = vec![vec![1u8; 1049], vec![1u8; 500]];
    let mut s = a.conn.open_uni().await.unwrap();
    s.write_all(&frame_cells(&cells)).await.unwrap();
    s.finish().unwrap();
    let mut incoming = tokio::time::timeout(std::time::Duration::from_secs(5), b.conn.accept_uni())
        .await
        .expect("stream in time")
        .unwrap();
    let group = incoming.read_to_end(1 << 20).await.unwrap();
    assert_eq!(parse_cells(&group).unwrap(), cells);

    // Hangup: closing the connection dissolves the room; the peer hears peer_left.
    a.conn.close(0u32.into(), b"bye");
    assert!(next_line(&mut b.ctrl).await.contains("peer_left"));
}

#[tokio::test]
async fn mixed_ws_and_quic_members_bridge_both_framings() {
    let (base, addr, hash) = spawn_relay().await;

    // WS member first…
    let (mut w, _) = tokio_tungstenite::connect_async(format!("{base}/v1/call/{CALL_ID}"))
        .await
        .unwrap();
    // consume "joined"
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), w.next())
        .await
        .unwrap();

    // …QUIC member second.
    let mut q = quic_join(addr, &hash, CALL_ID).await;
    assert!(next_line(&mut q.ctrl).await.contains(r#""peers":2"#));

    // WS voice binary → QUIC datagram.
    w.send(Ws::Binary(vec![0u8; 280])).await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), q.conn.read_datagram())
        .await
        .expect("datagram in time")
        .unwrap();
    assert_eq!(got.len(), 280);

    // WS video cell (16 KiB-class, track byte 1) → QUIC uni stream.
    let big_cell = vec![1u8; 16 * 1024];
    w.send(Ws::Binary(big_cell.clone())).await.unwrap();
    let mut incoming = tokio::time::timeout(std::time::Duration::from_secs(5), q.conn.accept_uni())
        .await
        .expect("stream in time")
        .unwrap();
    let group = incoming.read_to_end(1 << 20).await.unwrap();
    assert_eq!(parse_cells(&group).unwrap(), vec![big_cell]);

    // QUIC datagram → WS binary.
    q.conn.send_datagram(vec![3u8; 281].into()).unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match w.next().await.expect("ws open").expect("frame ok") {
                Ws::Binary(b) => return b.to_vec(),
                _ => continue,
            }
        }
    })
    .await
    .expect("ws binary in time");
    assert_eq!(got.len(), 281);

    // QUIC stream group of 3 cells → three separate WS binaries.
    let cells = vec![vec![15u8; 153], vec![2u8; 1049], vec![2u8; 400]];
    let mut s = q.conn.open_uni().await.unwrap();
    s.write_all(&frame_cells(&cells)).await.unwrap();
    s.finish().unwrap();
    for want in &cells {
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match w.next().await.expect("ws open").expect("frame ok") {
                    Ws::Binary(b) => return b.to_vec(),
                    _ => continue,
                }
            }
        })
        .await
        .expect("ws binary in time");
        assert_eq!(&got, want);
    }
}

#[tokio::test]
async fn quic_rejects_bad_ids_and_non_lossy_datagrams() {
    let (_ws, addr, hash) = spawn_relay().await;

    // Bad call id: connection is closed without a joined line.
    let mut bad = quic_join(addr, &hash, "not-a-valid-id-not-a-valid-id-xx").await;
    let ev = next_line(&mut bad.ctrl).await;
    assert!(ev.contains("<closed:"), "bad id must close, got {ev}");
    assert!(!ev.contains("joined"));

    // Video-track bytes in a datagram = protocol violation → sender dropped.
    let mut a = quic_join(addr, &hash, CALL_ID).await;
    let _ = next_line(&mut a.ctrl).await;
    let mut b = quic_join(addr, &hash, CALL_ID).await;
    let _ = next_line(&mut b.ctrl).await;
    let _ = next_line(&mut a.ctrl).await; // peer_joined

    a.conn.send_datagram(vec![1u8; 100].into()).unwrap();
    assert!(next_line(&mut b.ctrl).await.contains("peer_left"));
}

/// Token-mode relay: the QUIC join must carry the shared access token (newline line
/// after the 32-byte id) — without it the port was the one hole in the token perimeter.
#[tokio::test]
async fn quic_join_requires_access_token_in_token_mode() {
    let config = server::Config {
        access_mode: server::access::AccessMode::Token,
        access_token_hashes: vec![server::access::token_digest("quic-gate-token-1")],
        ..server::Config::default()
    };
    let state = AppState::new(config);
    let info = server::quic::start(state.clone(), 0).expect("quic endpoint");
    let quic_addr = std::net::SocketAddr::from(([127, 0, 0, 1], info.port));
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    let hash = STANDARD_NO_PAD.decode(&info.cert_sha256_b64).unwrap();

    // Bare join (old-style, id only): refused before the room is touched.
    let mut bare = quic_join(quic_addr, &hash, CALL_ID).await;
    let line = next_line(&mut bare.ctrl).await;
    assert!(line.starts_with("<closed"), "expected refusal, got {line}");

    // Wrong token: same refusal.
    let mut wrong = quic_join_token(quic_addr, &hash, CALL_ID, Some("nope-nope")).await;
    let line = next_line(&mut wrong.ctrl).await;
    assert!(line.starts_with("<closed"), "expected refusal, got {line}");

    // Right token: joined like normal.
    let mut ok = quic_join_token(quic_addr, &hash, CALL_ID, Some("quic-gate-token-1")).await;
    let line = next_line(&mut ok.ctrl).await;
    assert!(line.contains("joined"), "expected join, got {line}");
}

async fn quic_join_token(
    addr: std::net::SocketAddr,
    cert_hash: &[u8],
    call_id: &str,
    token: Option<&str>,
) -> QuicLeg {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert {
            sha256: cert_hash.to_vec(),
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cfg);
    let conn = ep.connect(addr, "sona-relay").unwrap().await.unwrap();
    let (mut tx, ctrl) = conn.open_bi().await.unwrap();
    let mut join = call_id.as_bytes().to_vec();
    if let Some(t) = token {
        join.extend_from_slice(t.as_bytes());
        join.push(b'\n');
    }
    tx.write_all(&join).await.unwrap();
    QuicLeg {
        conn,
        ctrl,
        _ep: ep,
    }
}
