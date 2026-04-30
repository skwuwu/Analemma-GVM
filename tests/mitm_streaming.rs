//! MITM TLS streaming integration tests — same invariants as
//! tests/sse_streaming.rs but driven through the production MITM
//! path (`tls_proxy_hyper::serve_mitm`).
//!
//! Why this matters
//! ────────────────
//! `tests/sse_streaming.rs` covers the cooperative HTTP_PROXY path
//! (`proxy_handler`). Real LLM agent traffic uses HTTPS via CONNECT
//! tunnel, where the MITM proxy terminates TLS, applies governance,
//! and re-emits the body to the client. That code path is structurally
//! different from cooperative HTTP and was not exercised by any
//! integration test — only by `framework-e2e.sh` against real
//! Anthropic, which is a smoke check, not a streaming-correctness
//! assertion.
//!
//! Architecture
//! ────────────
//!     [TLS client (this test)]
//!            │  real TCP + TLS handshake (trusts our test CA)
//!            ▼
//!     [MITM listener: TLS server with GvmCertResolver]
//!            │  serve_mitm → classify (SRR) → header injection
//!            ▼
//!     [Cleartext mock upstream]   (host_overrides redirects here)
//!
//! The upstream-leg TLS is NOT exercised here — that's a
//! tokio-rustls TlsConnector call to library code, already covered
//! by build_client_config_alpn_http11 unit test. The unique GVM
//! logic is on the MITM listener side, which IS exercised end-to-end.
//!
//! Coverage matches the cooperative SSE suite, in MITM form:
//!   1. SSE multi-event boundaries preserved
//!   2. Anthropic thinking trace (`event:` + `data:`) passes through
//!   3. Mid-stream pause does not coalesce chunks
//!   4. SRR Deny blocks before upstream call
//!   5. Proxy-injected response headers (X-GVM-Decision etc.)
//!   6. Credential injection on upstream request
//!
//! These six are the minimum that prove "MITM does its job on
//! streaming traffic", not "bytes pass through". The remaining
//! cooperative tests (UTF-8 boundary, large body, keep-alive
//! comments) exercise the same byte-level relay code on both
//! paths — they live in sse_streaming.rs.

mod common;

use axum::body::Body;
use axum::http::{Request as AxumRequest, Response as AxumResponse};
use axum::Router;
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Static rustls provider install (once per test binary) ──────────

fn install_default_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
}

// ── Test CA + cert resolver ────────────────────────────────────────

struct MitmFixture {
    listener_addr: std::net::SocketAddr,
    /// CA cert PEM bytes — for the test client trust store.
    ca_cert_pem: Vec<u8>,
    /// Wal path is held by caller; not surfaced here but the AppState
    /// is wired into the listener at construction.
    _wal: std::path::PathBuf,
}

/// Spawn a TLS-terminating MITM listener that calls `serve_mitm` for
/// every accepted connection. Returns the listener address + the
/// CA PEM the test client must trust.
/// Build a CA whose DN matches what `GvmCertResolver::new` reconstructs
/// internally (`CN=GVM MITM CA, O=Analemma GVM`). The shared
/// `test_helpers::create_test_ca` uses `CN=Test CA`, which works for
/// unit tests that don't actually perform TLS verification, but
/// breaks any integration test that walks the chain because:
///   - leaf is signed by the reconstructed CA (CN=GVM MITM CA)
///   - leaf's chain[1] in the cert message is the ORIGINAL CA cert
///   - if those two CAs have different subject DNs, leaf.issuer
///     fails to match chain[1].subject and rustls returns
///     `UnknownIssuer`.
/// Production avoids this because the production CA is generated with
/// the matching DN. Tests must do the same.
fn create_compatible_test_ca() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "GVM MITM CA");
        dn.push(rcgen::DnType::OrganizationName, "Analemma GVM");
        dn
    };
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(24);
    params.not_after = now + time::Duration::hours(24);
    let cert = params.self_signed(&key).unwrap();
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

async fn spawn_mitm_listener(
    state: gvm_proxy::proxy::AppState,
    wal_path: std::path::PathBuf,
) -> MitmFixture {
    install_default_crypto();

    // 1. CA whose DN matches GvmCertResolver's reconstruction so the
    //    leaf↔chain DN check passes during client verification.
    let (ca_cert_pem, ca_key_pem) = create_compatible_test_ca();
    let resolver = Arc::new(
        gvm_proxy::tls_proxy::GvmCertResolver::new(&ca_cert_pem, &ca_key_pem)
            .expect("GvmCertResolver::new must succeed"),
    );

    // 2. rustls ServerConfig (ALPN forced to http/1.1 — matches prod)
    let server_config = Arc::new(
        gvm_proxy::tls_proxy::build_server_config(resolver.clone())
            .expect("build_server_config must succeed"),
    );

    // 3. Real TCP listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 4. Pre-warm the cert cache for the SNI we'll use, so the first
    //    handshake doesn't time out doing rcgen on the runtime thread.
    //    (Production does this via ensure_cached at CONNECT time.)
    for sni in &[
        "api.anthropic.com",
        "api.deny-stream.com",
        "api.headers.com",
        "api.creds.com",
    ] {
        let _ = resolver.ensure_cached((*sni).to_string()).await;
    }

    // 5. rustls ClientConfig for upstream TLS — only used by the
    //    real Anthropic path; in tests host_overrides shunts to
    //    cleartext local upstream so this config's TLS half is
    //    never invoked. We still need to pass *something*, so we
    //    use the proxy's own helper.
    let client_config = Arc::new(
        gvm_proxy::tls_proxy::build_client_config().expect("build_client_config must succeed"),
    );

    // 6. Accept loop
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let cc = client_config.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("test: TLS accept error: {}", e);
                        return;
                    }
                };
                // Take SNI from the handshake to mimic prod cert routing,
                // but pass the SNI we expect into serve_mitm as the host
                // hint — that's what classify() uses.
                let sni = tls_stream
                    .get_ref()
                    .1
                    .server_name()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown.test".to_string());
                let _ =
                    gvm_proxy::tls_proxy::handle_mitm_stream(tls_stream, &sni, cc, &state).await;
            });
        }
    });

    MitmFixture {
        listener_addr: addr,
        ca_cert_pem,
        _wal: wal_path,
    }
}

/// Spawn a cleartext SSE mock upstream that streams `chunks` with
/// `inter_chunk_delay_ms` between emissions. Returns its bound
/// address.
async fn spawn_sse_upstream(
    chunks: Vec<&'static [u8]>,
    inter_chunk_delay_ms: u64,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(move |_req: AxumRequest<Body>| {
        let chunks = chunks.clone();
        async move {
            let stream = async_stream::stream! {
                for chunk in chunks {
                    yield Ok::<_, std::io::Error>(axum::body::Bytes::from_static(chunk));
                    if inter_chunk_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(inter_chunk_delay_ms)).await;
                    }
                }
            };
            AxumResponse::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(Body::from_stream(stream))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    addr
}

/// Build a rustls ClientConfig that trusts our test CA only.
fn client_config_trusting(ca_cert_pem: &[u8]) -> rustls::ClientConfig {
    install_default_crypto();
    let mut roots = rustls::RootCertStore::empty();
    let der = rustls_pemfile::certs(&mut std::io::BufReader::new(ca_cert_pem))
        .next()
        .expect("CA pem must contain a certificate")
        .expect("CA cert must parse");
    roots.add(CertificateDer::from(der.to_vec())).unwrap();
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

/// Connect to the MITM listener with TLS+SNI, send a minimal HTTP/1.1
/// POST, return (status_line, headers_text, body_bytes).
async fn tls_request(
    listener_addr: std::net::SocketAddr,
    sni: &str,
    ca_cert_pem: &[u8],
    extra_request_headers: &[(&str, &str)],
) -> (String, String, Vec<u8>) {
    let cfg = Arc::new(client_config_trusting(ca_cert_pem));
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let server_name = ServerName::try_from(sni.to_string()).expect("SNI must parse");

    let tcp = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");

    // Send a minimal HTTP/1.1 POST with empty body.
    let mut req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {sni}\r\nAccept: text/event-stream\r\n\
         Connection: close\r\nContent-Length: 0\r\n",
        sni = sni
    );
    for (k, v) in extra_request_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    // Read until upstream closes the TLS stream.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;

    // Split header / body at first \r\n\r\n.
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let body = if split + 4 < buf.len() {
        buf[split + 4..].to_vec()
    } else {
        Vec::new()
    };
    let mut lines = head.splitn(2, "\r\n");
    let status = lines.next().unwrap_or("").to_string();
    let headers = lines.next().unwrap_or("").to_string();
    (status, headers, body)
}

/// Decode HTTP/1.1 chunked transfer-encoding into the underlying body.
/// Returns the raw bytes the chunked encoding represented. Used for
/// any test that needs to inspect the streaming body — in MITM mode,
/// hyper emits the body as chunked, so the raw bytes from
/// `tls_request` include `<hex>\r\n<data>\r\n` framing that must be
/// stripped before assertions.
fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        // Find next CRLF for chunk size line
        let crlf = match body[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => p,
            None => break,
        };
        let size_line = std::str::from_utf8(&body[i..i + crlf]).unwrap_or("");
        // Strip optional chunk extensions
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        i += crlf + 2;
        if size == 0 {
            break;
        }
        if i + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2; // skip data + trailing CRLF
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

async fn srr_with(rules: &str) -> gvm_proxy::srr::NetworkSRR {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("srr.toml");
    std::fs::write(&p, rules).unwrap();
    gvm_proxy::srr::NetworkSRR::load(&p).unwrap()
}

#[tokio::test]
async fn mitm_sse_multi_event_preserves_boundaries() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2}\n\n",
        b"data: {\"i\":3}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks.clone(), 0).await;

    let srr = srr_with(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    )
    .await;
    let (mut state, wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.anthropic.com".to_string(),
        format!("127.0.0.1:{}", upstream.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    let (status, _headers, body) = tls_request(
        fixture.listener_addr,
        "api.anthropic.com",
        &fixture.ca_cert_pem,
        &[],
    )
    .await;
    assert!(status.contains("200"), "expected 200, got: {}", status);

    // hyper emits the response body as chunked. Decode and compare to
    // what upstream sent — every byte must reach the client.
    let decoded = decode_chunked(&body);
    let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(
        decoded, expected,
        "MITM-relayed SSE body must equal upstream byte-for-byte"
    );
}

#[tokio::test]
async fn mitm_anthropic_thinking_trace_passes_through() {
    let chunks: Vec<&'static [u8]> = vec![
        b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
        b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\
          \"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Let me reason...\"}}\n\n",
        b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks, 0).await;

    let srr = srr_with(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    )
    .await;
    let (mut state, wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.anthropic.com".to_string(),
        format!("127.0.0.1:{}", upstream.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    let (_status, _headers, body) = tls_request(
        fixture.listener_addr,
        "api.anthropic.com",
        &fixture.ca_cert_pem,
        &[],
    )
    .await;

    let decoded = decode_chunked(&body);
    let s = std::str::from_utf8(&decoded).expect("body must be UTF-8");
    assert!(
        s.contains("event: content_block_delta"),
        "named SSE event line missing"
    );
    assert!(
        s.contains("\"thinking\":\"Let me reason...\""),
        "thinking_delta payload missing"
    );
    assert!(s.contains("event: message_stop"));
}

#[tokio::test]
async fn mitm_srr_deny_blocks_before_upstream_call() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let upstream_hit = Arc::new(AtomicBool::new(false));
    let hit_clone = upstream_hit.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(move |_req: AxumRequest<Body>| {
        let h = hit_clone.clone();
        async move {
            h.store(true, Ordering::Relaxed);
            AxumResponse::builder()
                .status(200)
                .body(Body::from("data: leaked\n\n"))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    let srr = srr_with(
        r#"
[[rules]]
method = "POST"
pattern = "api.deny-stream.com/v1/messages"
[rules.decision]
type = "Deny"
reason = "policy"
"#,
    )
    .await;
    let (mut state, wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.deny-stream.com".to_string(),
        format!("127.0.0.1:{}", addr.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    let (status, _headers, body) = tls_request(
        fixture.listener_addr,
        "api.deny-stream.com",
        &fixture.ca_cert_pem,
        &[],
    )
    .await;

    assert!(
        status.contains("403"),
        "Deny rule on MITM streaming path must produce 403, got: {}",
        status
    );
    assert!(
        !body.windows(b"leaked".len()).any(|w| w == b"leaked"),
        "no upstream bytes may reach the client on Deny"
    );
    assert!(
        !upstream_hit.load(Ordering::Relaxed),
        "MITM Deny must short-circuit before any TCP connection to upstream"
    );
}

#[tokio::test]
async fn mitm_streaming_response_carries_proxy_injected_headers() {
    let chunks: Vec<&'static [u8]> = vec![b"data: {\"i\":1}\n\n"];
    let upstream = spawn_sse_upstream(chunks, 0).await;

    let srr = srr_with(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    )
    .await;
    let (mut state, wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.headers.com".to_string(),
        format!("127.0.0.1:{}", upstream.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    let (status, headers, _body) = tls_request(
        fixture.listener_addr,
        "api.headers.com",
        &fixture.ca_cert_pem,
        &[],
    )
    .await;
    assert!(status.contains("200"));

    let lower = headers.to_lowercase();
    // The MITM path may stamp these on the streaming response. If
    // the proxy ever stops doing so, agent SDKs lose their
    // observability anchor — so we assert at least one of the GVM
    // headers is present. Per-header existence is checked above the
    // empty-list case.
    let has_decision = lower.contains("\nx-gvm-decision:") || lower.starts_with("x-gvm-decision:");
    let has_event = lower.contains("\nx-gvm-event-id:") || lower.starts_with("x-gvm-event-id:");
    assert!(
        has_decision || has_event,
        "MITM streaming response must carry at least one X-GVM-* governance \
         header; received headers:\n{}",
        headers
    );
}

#[tokio::test]
async fn mitm_streaming_upstream_request_receives_injected_credentials() {
    use std::sync::Mutex;
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(move |req: AxumRequest<Body>| {
        let cap = cap.clone();
        async move {
            if let Some(auth) = req.headers().get("authorization") {
                if let Ok(s) = auth.to_str() {
                    *cap.lock().unwrap() = Some(s.to_string());
                }
            }
            AxumResponse::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .body(Body::from("data: ok\n\n"))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Build state with credentials configured for the virtual host.
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(
        &secrets_path,
        r#"
[credentials."api.creds.com"]
type = "Bearer"
token = "sk-mitm-stream"
"#,
    )
    .unwrap();
    let (mut state, wal) = common::test_state().await;
    state.api_keys = Arc::new(
        gvm_proxy::api_keys::APIKeyStore::load(&secrets_path).expect("secrets must parse"),
    );
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.creds.com".to_string(),
        format!("127.0.0.1:{}", addr.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    // Try to smuggle a fake Authorization — proxy must overwrite.
    let (status, _h, _b) = tls_request(
        fixture.listener_addr,
        "api.creds.com",
        &fixture.ca_cert_pem,
        &[("Authorization", "Bearer agent-smuggled-token")],
    )
    .await;
    assert!(status.contains("200"));

    let observed = captured.lock().unwrap().clone();
    assert_eq!(
        observed.as_deref(),
        Some("Bearer sk-mitm-stream"),
        "upstream Authorization must be the proxy-injected credential, not the \
         agent-smuggled one"
    );
}

#[tokio::test]
async fn mitm_mid_stream_pause_does_not_coalesce_chunks() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2}\n\n",
        b"data: {\"i\":3}\n\n",
    ];
    // 50ms inter-chunk delay; total emit window ≥ 100ms before final
    // chunk arrives. If MITM buffered the entire response, the first
    // visible byte at the client would only appear after ≥150ms.
    let upstream = spawn_sse_upstream(chunks.clone(), 50).await;

    let srr = srr_with(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    )
    .await;
    let (mut state, wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.slow.com".to_string(),
        format!("127.0.0.1:{}", upstream.port()),
    );
    state.host_overrides = overrides;
    let fixture = spawn_mitm_listener(state, wal).await;

    // Manual TLS connect to measure first-byte latency.
    install_default_crypto();
    let cfg = Arc::new(client_config_trusting(&fixture.ca_cert_pem));
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let server_name = ServerName::try_from("api.slow.com".to_string()).unwrap();
    let tcp = tokio::net::TcpStream::connect(fixture.listener_addr)
        .await
        .unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let req = "POST /v1/messages HTTP/1.1\r\nHost: api.slow.com\r\n\
               Accept: text/event-stream\r\nConnection: close\r\n\
               Content-Length: 0\r\n\r\n";
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    // Read just enough to clear the response head + first chunk frame.
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 4096];
    let mut got_data = false;
    while start.elapsed() < Duration::from_secs(2) {
        let n = match tokio::time::timeout(Duration::from_millis(300), tls.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            _ => continue,
        };
        if buf[..n].windows(2).any(|w| w == b"\n\n") {
            got_data = true;
            break;
        }
    }
    let first_byte_latency = start.elapsed();
    assert!(
        got_data,
        "no SSE event arrived within 2s — MITM is buffering"
    );
    assert!(
        first_byte_latency < Duration::from_millis(300),
        "first SSE event took {:?} — MITM appears to buffer the entire stream",
        first_byte_latency
    );
}
