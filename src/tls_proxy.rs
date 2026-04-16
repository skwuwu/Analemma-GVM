//! Transparent MITM TLS proxy for sandbox environments.
//!
//! Terminates TLS from the agent, inspects the plaintext HTTP request
//! (method, path, headers, body), applies SRR policy, injects API keys,
//! then re-encrypts and forwards to the upstream server.
//!
//! Key design decisions:
//! - ALPN forced to `http/1.1` (no HTTP/2 binary frame parsing needed)
//! - SNI extracted from ClientHello for dynamic cert generation
//! - SO_ORIGINAL_DST fallback when SNI is absent (direct IP access)
//! - ECDSA P-256 leaf certs cached per domain (~0.1ms cold, 0ns warm)
//! - httparse zero-copy parsing with Status::Partial state machine

use anyhow::{Context, Result};
use moka::sync::Cache;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// TLS proxy configuration.
pub struct TlsProxyConfig {
    /// CA certificate PEM (for signing leaf certs).
    pub ca_cert_pem: Vec<u8>,
    /// CA private key PEM.
    pub ca_key_pem: Vec<u8>,
}

/// Maximum number of cached leaf certificates.
/// Prevents memory exhaustion from SNI cache poisoning attacks
/// (e.g., agent requesting 1.evil.com, 2.evil.com, ..., N.evil.com).
const MAX_CERT_CACHE_SIZE: u64 = 10_000;

/// Time-to-idle for cached certificates. Unused certs are evicted after this.
const CERT_CACHE_TTI_SECS: u64 = 3600;

/// Time-to-live for cached certificates. Certs are regenerated after this,
/// regardless of usage. Must be shorter than cert validity (24h) to ensure
/// certs are refreshed before expiry. 23h = 1 hour safety margin.
const CERT_CACHE_TTL_SECS: u64 = 23 * 3600;

/// Dynamic certificate resolver — generates per-domain leaf certs on demand.
pub struct GvmCertResolver {
    /// CA certificate for signing.
    ca_cert: rcgen::Certificate,
    /// CA certificate DER (included in TLS chain so clients can verify).
    ca_cert_der: Vec<u8>,
    /// CA key pair.
    ca_key: KeyPair,
    /// Per-domain leaf cert cache with bounded capacity and TTI eviction.
    /// Prevents SNI cache poisoning: an attacker requesting unlimited unique
    /// domains cannot exhaust host memory — moka evicts LRU entries at capacity.
    cache: Cache<String, Arc<CertifiedKey>>,
}

impl std::fmt::Debug for GvmCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GvmCertResolver")
            .field("cached_domains", &self.cache.entry_count())
            .finish()
    }
}

impl GvmCertResolver {
    /// Create a resolver from CA key PEM bytes.
    ///
    /// `ca_cert_pem` is the original CA certificate (served via /gvm/ca.pem and
    /// injected into the sandbox trust store). Its DER is included in the TLS
    /// cert chain so clients can verify: leaf → original CA → trust store.
    ///
    /// The signing key is extracted from `ca_key_pem` and used to sign leaf certs
    /// via a reconstructed rcgen Certificate (necessary because rcgen cannot parse
    /// PEM back to Certificate). Both the original and reconstructed certs share
    /// the same key, so signatures are valid against either.
    pub fn new(ca_cert_pem: &[u8], ca_key_pem: &[u8]) -> Result<Self> {
        let ca_key_str = std::str::from_utf8(ca_key_pem).context("CA key not valid UTF-8")?;

        let ca_key = KeyPair::from_pem(ca_key_str).context("Failed to parse CA key PEM")?;

        // Extract original CA cert DER from PEM (for inclusion in TLS chain).
        // This is the cert clients have in their trust store, so it must be in the chain.
        let original_ca_der = rustls_pemfile::certs(&mut &ca_cert_pem[..])
            .next()
            .ok_or_else(|| anyhow::anyhow!("No certificate found in CA PEM"))?
            .context("Failed to parse CA cert PEM")?
            .to_vec();

        // Reconstruct CA cert from key (self-signed)
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // DN must match ca.rs exactly. Mismatch causes "unable to get
        // local issuer certificate" — leaf issuer DN ≠ chain CA subject DN.
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "GVM MITM CA");
            dn.push(DnType::OrganizationName, "Analemma GVM");
            dn
        };
        // Backdate not_before for clock drift tolerance
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(24);
        params.not_after = now + time::Duration::hours(24);
        let ca_cert = params
            .self_signed(&ca_key)
            .context("Failed to reconstruct CA cert")?;

        Ok(Self {
            ca_cert,
            ca_cert_der: original_ca_der,
            ca_key,
            cache: Cache::builder()
                .max_capacity(MAX_CERT_CACHE_SIZE)
                .time_to_idle(Duration::from_secs(CERT_CACHE_TTI_SECS))
                .time_to_live(Duration::from_secs(CERT_CACHE_TTL_SECS))
                .build(),
        })
    }

    /// Issue a leaf cert for the given domain. Caches the result.
    fn issue_and_cache(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // Check cache first (moka handles TTI refresh on access)
        if let Some(cached) = self.cache.get(domain) {
            return Some(cached);
        }

        // Generate ECDSA P-256 leaf cert (~0.1ms)
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).ok()?;

        let mut params = CertificateParams::new(vec![domain.to_string()]).ok()?;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, domain);
            dn
        };
        // Backdate leaf cert for clock drift tolerance
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(24);
        params.not_after = now + time::Duration::hours(24);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .ok()?;

        // Convert to rustls types.
        // Include both leaf cert and CA cert in the chain so clients can verify
        // the full chain even when the trust store has the original CA cert
        // (which shares the same key but different serial/validity).
        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = CertificateDer::from(self.ca_cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).ok()?;

        let certified_key = CertifiedKey::new(vec![cert_der, ca_der], signing_key);
        let arc_key = Arc::new(certified_key);

        self.cache.insert(domain.to_string(), arc_key.clone());
        tracing::debug!(domain, "Leaf certificate generated and cached");

        Some(arc_key)
    }
}

impl GvmCertResolver {
    /// Flush pending moka tasks and return the number of cached certs.
    /// Used by tests to verify cache state after concurrent operations.
    pub fn sync_and_count(&self) -> u64 {
        self.cache.run_pending_tasks();
        self.cache.entry_count()
    }

    /// Pre-warm the cert cache for a domain on a blocking thread.
    ///
    /// Called BEFORE TLS handshake so that `resolve()` hits cache (0ns)
    /// and never blocks the tokio runtime with CPU-bound keygen.
    /// This is the fix for the cooperative scheduling starvation issue:
    /// without this, 50 concurrent new-domain TLS handshakes would block
    /// all tokio worker threads for the duration of cert generation.
    pub async fn ensure_cached(self: &Arc<Self>, domain: String) -> Option<Arc<CertifiedKey>> {
        // Fast path: already cached
        if let Some(cached) = self.cache.get(&domain) {
            return Some(cached);
        }

        // Slow path: offload CPU-bound keygen to blocking thread pool
        let resolver = Arc::clone(self);
        tokio::task::spawn_blocking(move || resolver.issue_and_cache(&domain))
            .await
            .ok()?
    }
}

impl ResolvesServerCert for GvmCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name()?;
        // After ensure_cached(), this is always a cache hit (0ns).
        // If somehow called without pre-warming, falls back to sync generation
        // to maintain correctness (at the cost of blocking the runtime).
        self.issue_and_cache(domain)
    }
}

/// Build a rustls ServerConfig for the MITM proxy (agent-facing).
///
/// Forces ALPN to HTTP/1.1 to avoid HTTP/2 binary frame parsing.
pub fn build_server_config(resolver: Arc<GvmCertResolver>) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Force HTTP/1.1 — prevent h2 negotiation
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// Build a rustls ClientConfig for upstream connections (proxy → server).
///
/// Uses system root CAs. Forces ALPN to HTTP/1.1.
pub fn build_client_config() -> Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Force HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// Maximum time to read a complete HTTP request header.
/// Defends against Slowloris: attacker sending 1 byte/sec is disconnected.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Parse an HTTP request from a TLS-decrypted byte stream.
///
/// Handles Status::Partial by looping and accumulating bytes.
/// Returns method, path, host, and body slice.
///
/// Security:
/// - 30s timeout against Slowloris (attacker trickling bytes)
/// - Rejects Content-Length + Transfer-Encoding conflict (RFC 7230 §3.3.3)
/// - Rejects duplicate Content-Length headers with differing values
pub async fn read_http_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<HttpRequest> {
    tokio::time::timeout(REQUEST_READ_TIMEOUT, read_http_request_inner(stream))
        .await
        .map_err(|_| anyhow::anyhow!("HTTP request read timed out (Slowloris defense)"))?
}

async fn read_http_request_inner<S: AsyncRead + Unpin>(stream: &mut S) -> Result<HttpRequest> {
    let mut buf = Vec::with_capacity(8192);
    let mut total = 0;
    const MAX_HEADER: usize = 64 * 1024; // 64KB header limit

    loop {
        buf.resize(total + 4096, 0);
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            anyhow::bail!("Connection closed before headers complete");
        }
        total += n;
        buf.truncate(total);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(body_offset)) => {
                let method = req.method.unwrap_or("GET").to_string();
                let path = req.path.unwrap_or("/").to_string();
                let host = headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .unwrap_or("")
                    .to_string();

                // ── HTTP Request Smuggling defense (RFC 7230 §3.3.3) ──
                // Reject requests with both Content-Length and Transfer-Encoding.
                // A desync between our parser (httparse) and the upstream server's
                // parser on where the request body ends could let an attacker
                // smuggle a second request inside the body of the first.
                let has_te = headers
                    .iter()
                    .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
                let cl_values: Vec<&[u8]> = headers
                    .iter()
                    .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .map(|h| h.value)
                    .collect();

                if has_te && !cl_values.is_empty() {
                    anyhow::bail!(
                        "Rejected: both Content-Length and Transfer-Encoding present \
                         (request smuggling attempt)"
                    );
                }

                // Reject duplicate Content-Length with differing values
                if cl_values.len() > 1 {
                    let first = cl_values[0];
                    if cl_values.iter().skip(1).any(|v| *v != first) {
                        anyhow::bail!(
                            "Rejected: multiple Content-Length headers with different values"
                        );
                    }
                }

                // Collect all headers for forwarding
                let header_pairs: Vec<(String, Vec<u8>)> = headers
                    .iter()
                    .filter(|h| h.name != httparse::EMPTY_HEADER.name)
                    .map(|h| (h.name.to_string(), h.value.to_vec()))
                    .collect();

                // Read remaining body based on Content-Length.
                // After header parsing, buf[body_offset..] contains whatever body
                // bytes arrived with the header read. If Content-Length indicates more,
                // keep reading until we have the full body.
                let content_length: usize = cl_values
                    .first()
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);

                let mut body = buf[body_offset..].to_vec();
                let raw_head = buf[..body_offset].to_vec();

                if content_length > 0 && body.len() < content_length {
                    let remaining = content_length - body.len();
                    // Cap to prevent OOM (64KB body limit for MITM inspection)
                    let cap = remaining.min(64 * 1024);
                    let mut rest = vec![0u8; cap];
                    let mut read_so_far = 0;
                    while read_so_far < cap {
                        let n = stream.read(&mut rest[read_so_far..]).await?;
                        if n == 0 {
                            break; // upstream closed
                        }
                        read_so_far += n;
                    }
                    body.extend_from_slice(&rest[..read_so_far]);
                }

                return Ok(HttpRequest {
                    method,
                    path,
                    host,
                    headers: header_pairs,
                    body,
                    raw_head,
                });
            }
            Ok(httparse::Status::Partial) => {
                if total > MAX_HEADER {
                    anyhow::bail!("HTTP header exceeds 64KB limit");
                }
                continue; // read more bytes
            }
            Err(e) => anyhow::bail!("HTTP parse error: {}", e),
        }
    }
}

/// Auth-related header names that must be stripped before credential injection.
/// Matches the same set as api_keys.rs to prevent credential smuggling.
const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "apikey",
    "x-auth-token",
    "x-api-token",
    "x-signature",
    "x-hmac",
    "x-credentials",
];

/// Check if a byte slice contains characters that would enable HTTP header injection.
/// CR (\r), LF (\n), and NUL (\0) in header values allow response splitting attacks.
#[inline]
fn contains_header_injection_chars(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|&b| b == b'\r' || b == b'\n' || b == b'\0')
}

/// Parsed HTTP request from decrypted TLS stream.
#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    /// Raw header bytes for forwarding (if no modification needed).
    pub raw_head: Vec<u8>,
}

impl HttpRequest {
    /// Strip agent-supplied auth headers and inject proxy credentials.
    ///
    /// This is the MITM equivalent of `api_keys.rs::inject()` for the HTTP proxy path.
    /// After injection, `raw_head` is rebuilt from the modified headers.
    ///
    /// Returns true if credentials were injected, false if no credential was configured
    /// for this host (passthrough mode).
    pub fn inject_credentials(&mut self, api_keys: &crate::api_keys::APIKeyStore) -> bool {
        let credential = match api_keys.get_credential(&self.host) {
            Some(c) => c,
            None => return false,
        };

        // Strip all agent-supplied auth headers (prevent credential smuggling)
        self.headers
            .retain(|(name, _)| !AUTH_HEADERS.contains(&name.to_ascii_lowercase().as_str()));

        // Inject the configured credential
        // Safety: validate all header values against CRLF injection before inserting
        // as raw bytes. The HTTP proxy path uses HeaderValue::from_str() which rejects
        // non-visible ASCII, but the MITM path writes raw bytes into rebuild_raw_head().
        // A \r\n in a header value would cause HTTP response splitting.
        match credential {
            crate::api_keys::Credential::Bearer { token } => {
                let value = format!("Bearer {}", token);
                if contains_header_injection_chars(value.as_bytes()) {
                    tracing::error!(
                        host = %self.host,
                        "Credential contains illegal characters (CR/LF/NUL) — rejecting injection to prevent HTTP response splitting"
                    );
                    return false;
                }
                self.headers
                    .push(("Authorization".to_string(), value.into_bytes()));
            }
            crate::api_keys::Credential::OAuth2 { access_token, .. } => {
                let value = format!("Bearer {}", access_token);
                if contains_header_injection_chars(value.as_bytes()) {
                    tracing::error!(
                        host = %self.host,
                        "OAuth2 credential contains illegal characters (CR/LF/NUL) — rejecting injection"
                    );
                    return false;
                }
                self.headers
                    .push(("Authorization".to_string(), value.into_bytes()));
            }
            crate::api_keys::Credential::ApiKey { header, value } => {
                if contains_header_injection_chars(header.as_bytes())
                    || contains_header_injection_chars(value.as_bytes())
                {
                    tracing::error!(
                        host = %self.host,
                        "ApiKey credential contains illegal characters (CR/LF/NUL) — rejecting injection"
                    );
                    return false;
                }
                self.headers
                    .push((header.clone(), value.clone().into_bytes()));
            }
        }

        // Rebuild raw_head from modified headers
        self.rebuild_raw_head();
        true
    }

    /// Reconstruct `raw_head` from method, path, and current headers.
    fn rebuild_raw_head(&mut self) {
        let mut head = Vec::with_capacity(self.raw_head.len() + 256);
        // Request line
        head.extend_from_slice(self.method.as_bytes());
        head.push(b' ');
        head.extend_from_slice(self.path.as_bytes());
        head.extend_from_slice(b" HTTP/1.1\r\n");
        // Headers
        for (name, value) in &self.headers {
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value);
            head.extend_from_slice(b"\r\n");
        }
        // End of headers
        head.extend_from_slice(b"\r\n");
        self.raw_head = head;
    }
}

/// Handle a MITM TLS stream: read plaintext HTTP, apply SRR, forward to upstream.
///
/// Write an enforcement event (Deny/RequireApproval) to WAL.
/// Every blocked or rate-limited request must appear in the audit trail.
pub async fn append_enforcement_event(
    ledger: &std::sync::Arc<crate::ledger::Ledger>,
    classify_output: &crate::enforcement::ClassifyOutput,
    host: &str,
    req: &HttpRequest,
    decision_str: &str,
    status_code: Option<u16>,
    default_caution: bool,
) {
    let event = gvm_types::GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: classify_output.agent_id.clone(),
        tenant_id: None,
        session_id: host.to_string(),
        timestamp: chrono::Utc::now(),
        operation: format!("{} {}", req.method, req.path),
        resource: gvm_types::ResourceDescriptor {
            service: host.to_string(),
            identifier: Some(req.path.clone()),
            tier: gvm_types::ResourceTier::External,
            sensitivity: gvm_types::Sensitivity::Medium,
        },
        context: std::collections::HashMap::new(),
        transport: Some(gvm_types::TransportInfo {
            method: req.method.clone(),
            host: host.to_string(),
            path: req.path.clone(),
            status_code,
        }),
        decision: decision_str.to_string(),
        decision_source: format!("{:?}", classify_output.classification.source),
        matched_rule_id: classify_output.classification.matched_rule_id.clone(),
        enforcement_point: "mitm".to_string(),
        status: if decision_str.contains("Deny") {
            gvm_types::EventStatus::Failed {
                reason: format!("Denied: {}", decision_str),
            }
        } else {
            gvm_types::EventStatus::Confirmed
        },
        payload: gvm_types::PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution,
        config_integrity_ref: None,
    };
    if let Err(e) = ledger.append_durable(&event).await {
        tracing::error!(error = %e, decision = %decision_str, "MITM: enforcement WAL append FAILED");
    }
}

/// Shared between the port-8443 TLS listener and the CONNECT handler.
/// `S` can be `TcpStream` (DNAT path) or `TokioIo<Upgraded>` (CONNECT path).
///
/// Delegates to hyper-based handler for proper HTTP/1.1 framing.
/// hyper manages chunked encoding, content-length, keep-alive, and SSE streaming.
pub async fn handle_mitm_stream<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    tls_stream: tokio_rustls::server::TlsStream<S>,
    host_hint: &str,
    client_config: std::sync::Arc<rustls::ClientConfig>,
    state: &crate::proxy::AppState,
) -> Result<()> {
    crate::tls_proxy_hyper::serve_mitm(
        tls_stream,
        host_hint.to_string(),
        client_config,
        state.clone(),
    )
    .await
}

/// Legacy handle_mitm_stream — custom HTTP parser + relay.
/// Kept for reference. All MITM traffic now goes through hyper (above).
#[allow(dead_code)]
async fn handle_mitm_stream_legacy<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut tls_stream: tokio_rustls::server::TlsStream<S>,
    host_hint: &str,
    client_config: std::sync::Arc<rustls::ClientConfig>,
    state: &crate::proxy::AppState,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // HTTP/1.1 keep-alive loop: handle multiple requests on the same TLS connection.
    // OpenClaw and other agent frameworks reuse connections for multi-turn LLM calls
    // (assistant → tool_use → tool_result → assistant). Without this loop, the second
    // request on a keep-alive connection hangs forever (agent timeout).
    //
    // The loop exits when:
    // - Client closes the connection (read returns 0 / EOF)
    // - Read timeout expires (300s idle = client done sending)
    // - Connection: close header is present
    // - An error occurs
    //
    // 300s idle timeout covers the agent work cycle: LLM response (~20s) → tool
    // execution (30-120s) → next LLM request. 30s was too short — sub-agents that
    // process results before sending the next request hit the timeout, causing
    // "Connection error" on the reused keep-alive connection.
    //
    // Slowloris defense is separate: read_http_request() has its own timeout for
    // slow header delivery. This idle timeout only applies to already-authenticated
    // TLS connections between requests.
    loop {
        // 1. Read next HTTP request (with idle timeout for keep-alive)
        let req = match tokio::time::timeout(
            std::time::Duration::from_secs(300),
            read_http_request(&mut tls_stream),
        )
        .await
        {
            Ok(Ok(req)) => req,
            Ok(Err(_)) => break, // Parse error or connection closed
            Err(_) => break,     // 30s idle timeout — client done
        };

        let host = if req.host.is_empty() {
            host_hint.to_string()
        } else {
            req.host.clone()
        };

        let connection_close = req.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("connection")
                && std::str::from_utf8(v)
                    .unwrap_or("")
                    .eq_ignore_ascii_case("close")
        });

        tracing::info!(
            method = %req.method,
            host = %host,
            path = %req.path,
            "MITM: inspecting HTTPS request"
        );

        // 1.5. Circuit breaker: if WAL is failing, reject non-Allow requests early.
        // Without this, MITM continues accepting traffic when audit is broken,
        // violating the fail-close principle.
        const CIRCUIT_BREAKER_THRESHOLD: u64 = 5;
        let wal_failures = state.ledger.primary_failure_count();
        if wal_failures >= CIRCUIT_BREAKER_THRESHOLD {
            tracing::error!(
                failures = wal_failures,
                "MITM: circuit breaker OPEN — WAL failures exceed threshold, rejecting request"
            );
            let body_str = format!(
                r#"{{"blocked":true,"decision":"CircuitBreakerOpen","reason":"Audit subsystem degraded ({} consecutive WAL failures). Request rejected for safety.","retry_after_seconds":30}}"#,
                wal_failures
            );
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 30\r\nConnection: close\r\n\r\n{}",
                body_str.len(), body_str
            );
            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.flush().await?;
            break;
        }

        // 2. Unified classification (SRR via enforcement::classify).
        // This ensures MITM path has the same enforcement logic as proxy_handler.
        let body_ref = if req.body.is_empty() {
            None
        } else {
            Some(req.body.as_slice())
        };
        let classify_input = crate::enforcement::ClassifyInput {
            method: &req.method,
            host: &host,
            path: &req.path,
            body: body_ref,
            gvm_headers: None, // MITM traffic has no SDK headers
        };
        let classify_output = match crate::enforcement::classify(state, &classify_input) {
            Ok(o) => o,
            Err(err_msg) => {
                tracing::error!(error = %err_msg, "MITM classification failed — denying (fail-close)");
                let body_str = r#"{"blocked":true,"decision":"Deny","reason":"Internal governance error (fail-close)"}"#;
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_str.len(), body_str
                );
                tls_stream.write_all(response.as_bytes()).await?;
                tls_stream.flush().await?;
                // Best-effort WAL record for classification failure.
                // classify_output is unavailable, construct minimal event.
                let fail_event = gvm_types::GVMEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    trace_id: uuid::Uuid::new_v4().to_string(),
                    parent_event_id: None,
                    agent_id: "unknown".to_string(),
                    tenant_id: None,
                    session_id: host.clone(),
                    timestamp: chrono::Utc::now(),
                    operation: format!("{} {}", req.method, req.path),
                    resource: gvm_types::ResourceDescriptor {
                        service: host.clone(),
                        identifier: Some(req.path.clone()),
                        tier: gvm_types::ResourceTier::External,
                        sensitivity: gvm_types::Sensitivity::Medium,
                    },
                    context: std::collections::HashMap::new(),
                    transport: Some(gvm_types::TransportInfo {
                        method: req.method.clone(),
                        host: host.clone(),
                        path: req.path.clone(),
                        status_code: Some(500),
                    }),
                    decision: format!("Deny (classification error: {})", err_msg),
                    decision_source: "fail-close".to_string(),
                    matched_rule_id: None,
                    enforcement_point: "mitm".to_string(),
                    status: gvm_types::EventStatus::Confirmed,
                    payload: gvm_types::PayloadDescriptor::default(),
                    nats_sequence: None,
                    event_hash: None,
                    llm_trace: None,
                    default_caution: false,
                    config_integrity_ref: None,
                };
                let _ = state.ledger.append_durable(&fail_event).await;
                break;
            }
        };

        let decision = &classify_output.classification.decision;
        let is_default_caution = classify_output.is_default_caution;
        tracing::info!(decision = ?decision, host = %host, path = %req.path, "MITM: SRR decision");

        // 3. Enforce decision
        match decision {
            gvm_types::EnforcementDecision::Deny { reason } => {
                let event_id = uuid::Uuid::new_v4().to_string();
                let trace_id = uuid::Uuid::new_v4().to_string();
                let body = serde_json::json!({
                    "blocked": true,
                    "decision": "Deny",
                    "reason": reason,
                    "event_id": event_id,
                    "trace_id": trace_id,
                    "method": req.method,
                    "host": host,
                    "path": req.path,
                    "next_action": format!(
                        "Blocked by SRR rule. To allow: add an Allow rule for {} {} in config/srr_network.toml and run POST /gvm/reload.",
                        req.method, host
                    ),
                    "matched_rule": classify_output.classification.matched_rule_id.as_deref().unwrap_or(""),
                });
                let body_str = body.to_string();
                // Keep-alive after Deny: allow agent to retry on the same connection.
                // Previously Connection: close forced a new CONNECT tunnel per deny,
                // triggering intermittent TLS handshake eof on reconnect. With keep-alive,
                // the agent's next request (e.g., fallback URL or LLM call) uses the
                // same TLS session — no handshake overhead, no reconnect failures.
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body_str.len(), body_str
                );
                tls_stream.write_all(response.as_bytes()).await?;
                tls_stream.flush().await?;
                tracing::warn!(host = %host, path = %req.path, reason = %reason, "MITM: request DENIED");

                // Record Deny in WAL — blocked requests MUST appear in audit trail.
                append_enforcement_event(
                    &state.ledger,
                    &classify_output,
                    &host,
                    &req,
                    &format!("Deny {{ reason: {:?} }}", reason),
                    Some(403),
                    false,
                )
                .await;

                continue; // Keep-alive: allow next request on same connection
            }
            gvm_types::EnforcementDecision::Delay { milliseconds } => {
                tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
            }
            gvm_types::EnforcementDecision::RequireApproval { .. } => {
                // IC-3 on MITM path: cannot hold TLS stream for approval without
                // blocking the keep-alive loop. Treat as Deny with explanation.
                tracing::warn!(host = %host, path = %req.path, "MITM: IC-3 RequireApproval → Deny (approval not supported on MITM path)");
                let body_str = r#"{"blocked":true,"decision":"RequireApproval","reason":"IC-3 approval not supported on MITM TLS path. Use cooperative mode with SDK for IC-3."}"#;
                let response = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_str.len(), body_str
                );
                tls_stream.write_all(response.as_bytes()).await?;
                tls_stream.flush().await?;
                append_enforcement_event(
                    &state.ledger,
                    &classify_output,
                    &host,
                    &req,
                    "RequireApproval (→ Deny on MITM)",
                    Some(403),
                    false,
                )
                .await;
                break;
            }
            _ => {} // Allow, AuditOnly — pass through
        }

        // 3.2. WebSocket Upgrade: if the request has Connection: Upgrade + Upgrade: websocket,
        // SRR check was already done above. If allowed, relay the upgrade to upstream and switch
        // to bidirectional blind relay (same as CONNECT). WebSocket frame content is not inspected
        // — only the initial handshake host/path is governed.
        let is_websocket_upgrade = req.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("upgrade")
                && std::str::from_utf8(v)
                    .unwrap_or("")
                    .eq_ignore_ascii_case("websocket")
        });

        if is_websocket_upgrade {
            tracing::info!(
                host = %host,
                path = %req.path,
                "MITM: WebSocket Upgrade detected — switching to bidirectional relay"
            );

            // WAL audit for the upgrade request
            {
                let event_id = uuid::Uuid::new_v4().to_string();
                let trace_id = uuid::Uuid::new_v4().to_string();
                let decision_str = format!("{:?}", classify_output.classification.decision);
                let source_str = format!("{:?}", classify_output.classification.source);
                let event = gvm_types::GVMEvent {
                    event_id,
                    trace_id,
                    parent_event_id: None,
                    agent_id: classify_output.agent_id.clone(),
                    tenant_id: None,
                    session_id: host.clone(),
                    timestamp: chrono::Utc::now(),
                    operation: format!("WS-UPGRADE {} {}", req.method, req.path),
                    resource: gvm_types::ResourceDescriptor {
                        service: host.clone(),
                        identifier: Some(req.path.clone()),
                        tier: gvm_types::ResourceTier::External,
                        sensitivity: gvm_types::Sensitivity::Medium,
                    },
                    context: std::collections::HashMap::new(),
                    transport: Some(gvm_types::TransportInfo {
                        method: req.method.clone(),
                        host: host.clone(),
                        path: req.path.clone(),
                        status_code: None,
                    }),
                    decision: decision_str,
                    decision_source: source_str,
                    matched_rule_id: classify_output.classification.matched_rule_id.clone(),
                    enforcement_point: "mitm-ws-upgrade".to_string(),
                    status: gvm_types::EventStatus::Pending,
                    payload: gvm_types::PayloadDescriptor::default(),
                    nats_sequence: None,
                    event_hash: None,
                    llm_trace: None,
                    default_caution: is_default_caution,
                    config_integrity_ref: None,
                };
                state.ledger.append_durable(&event).await.ok();
            }

            // Connect to upstream and forward the original upgrade request
            let upstream_host_str = host.split(':').next().unwrap_or(&host);
            let connector = tokio_rustls::TlsConnector::from(client_config.clone());
            let upstream_addr = format!("{}:443", upstream_host_str);
            let upstream_tcp = match tokio::net::TcpStream::connect(&upstream_addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "MITM WebSocket: upstream connect failed"
                    );
                    break;
                }
            };
            let server_name =
                match rustls::pki_types::ServerName::try_from(upstream_host_str.to_string()) {
                    Ok(sn) => sn,
                    Err(_) => break,
                };
            let mut upstream_tls = match connector.connect(server_name, upstream_tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "MITM WebSocket: upstream TLS failed"
                    );
                    break;
                }
            };

            // Send original request (with Upgrade headers intact)
            use tokio::io::AsyncWriteExt;
            upstream_tls.write_all(&req.raw_head).await?;
            if !req.body.is_empty() {
                upstream_tls.write_all(&req.body).await?;
            }

            // Bidirectional relay (same as CONNECT blind_relay)
            let (mut client_read, mut client_write) = tokio::io::split(tls_stream);
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);
            let c2u = tokio::io::copy(&mut client_read, &mut upstream_write);
            let u2c = tokio::io::copy(&mut upstream_read, &mut client_write);
            tokio::select! {
                _ = c2u => {}
                _ = u2c => {}
            }

            tracing::info!(
                host = %host,
                "MITM WebSocket: relay closed"
            );
            return Ok(());
        }

        // 3.5. WAL audit record for MITM-inspected requests (sandbox observability).
        // Without this, gvm watch --sandbox sees no events because MITM-intercepted
        // traffic bypasses proxy_handler (which writes WAL). CONNECT tunnel setup
        // IS logged by proxy_handler, but individual L7 requests inside the tunnel
        // are only visible here.
        {
            let event_id = uuid::Uuid::new_v4().to_string();
            let trace_id = uuid::Uuid::new_v4().to_string();
            let decision_str = format!("{:?}", classify_output.classification.decision);
            let source_str = format!("{:?}", classify_output.classification.source);
            let event = gvm_types::GVMEvent {
                event_id,
                trace_id,
                parent_event_id: None,
                agent_id: classify_output.agent_id.clone(),
                tenant_id: None,
                session_id: host.clone(),
                timestamp: chrono::Utc::now(),
                operation: format!("{} {}", req.method, req.path),
                resource: gvm_types::ResourceDescriptor {
                    service: host.clone(),
                    identifier: Some(req.path.clone()),
                    tier: gvm_types::ResourceTier::External,
                    sensitivity: gvm_types::Sensitivity::Medium,
                },
                context: std::collections::HashMap::new(),
                transport: Some(gvm_types::TransportInfo {
                    method: req.method.clone(),
                    host: host.clone(),
                    path: req.path.clone(),
                    status_code: None,
                }),
                decision: decision_str,
                decision_source: source_str,
                matched_rule_id: classify_output.classification.matched_rule_id.clone(),
                enforcement_point: "mitm".to_string(),
                status: gvm_types::EventStatus::Pending,
                payload: gvm_types::PayloadDescriptor::default(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: is_default_caution,
                config_integrity_ref: None,
            };
            match state.ledger.append_durable(&event).await {
                Ok(()) => tracing::info!(host = %host, path = %req.path, "MITM WAL event recorded"),
                Err(e) => tracing::error!(error = %e, "MITM WAL append FAILED"),
            }
        }

        // 4. API key injection
        let mut req = req;
        if req.inject_credentials(&state.api_keys) {
            tracing::info!(host = %host, "MITM: API key injected for upstream");
        }

        // Preserve the original Connection header. Previously we forced Connection: close
        // to ensure upstream closes after response, but this breaks SSE (Server-Sent Events)
        // streaming — upstream closes the connection after the first chunk, killing the stream.
        // Anthropic API /v1/messages with stream:true uses chunked SSE that requires the
        // connection to stay open. The relay loop already handles EOF from upstream (read returns 0)
        // and has a 30s idle timeout, so keep-alive connections will terminate naturally.
        req.rebuild_raw_head();

        // 5. Connect to upstream and relay (new connection per request)
        let upstream_host = host.split(':').next().unwrap_or(&host);
        let override_addr = state.host_overrides.get(upstream_host);

        let relay_result = if let Some(local_addr) = override_addr {
            let addr = if local_addr.contains(':') {
                local_addr.clone()
            } else {
                format!("{}:80", local_addr)
            };
            relay_http(&mut tls_stream, &addr, &req).await
        } else {
            relay_tls(&mut tls_stream, upstream_host, &client_config, &req).await
        };

        if let Err(e) = relay_result {
            tracing::warn!(error = %e, host = %host, path = %req.path, "MITM: upstream relay failed");
            // Record relay failure in WAL — without this, failed requests
            // disappear from the audit trail (violates fail-close observability).
            let fail_event = gvm_types::GVMEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                trace_id: uuid::Uuid::new_v4().to_string(),
                parent_event_id: None,
                agent_id: classify_output.agent_id.clone(),
                tenant_id: None,
                session_id: host.clone(),
                timestamp: chrono::Utc::now(),
                operation: format!("{} {}", req.method, req.path),
                resource: gvm_types::ResourceDescriptor {
                    service: host.clone(),
                    identifier: Some(req.path.clone()),
                    tier: gvm_types::ResourceTier::External,
                    sensitivity: gvm_types::Sensitivity::Medium,
                },
                context: std::collections::HashMap::new(),
                transport: Some(gvm_types::TransportInfo {
                    method: req.method.clone(),
                    host: host.clone(),
                    path: req.path.clone(),
                    status_code: None,
                }),
                decision: format!("{:?}", classify_output.classification.decision),
                decision_source: format!("{:?}", classify_output.classification.source),
                matched_rule_id: classify_output.classification.matched_rule_id.clone(),
                enforcement_point: "mitm".to_string(),
                status: gvm_types::EventStatus::Failed {
                    reason: format!("Upstream relay failed: {}", e),
                },
                payload: gvm_types::PayloadDescriptor::default(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: is_default_caution,
                config_integrity_ref: None,
            };
            state.ledger.append_durable(&fail_event).await.ok();
            break;
        }

        if connection_close {
            break;
        }
    }

    tls_stream.shutdown().await.ok();
    Ok(())
}

/// Relay a single request/response to an upstream HTTP server (dev mode).
async fn relay_http<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    tls_stream: &mut tokio_rustls::server::TlsStream<S>,
    addr: &str,
    req: &HttpRequest,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut upstream = tokio::net::TcpStream::connect(addr)
        .await
        .context("MITM: failed to connect to dev override")?;

    upstream.write_all(&req.raw_head).await?;
    if !req.body.is_empty() {
        upstream.write_all(&req.body).await?;
    }

    let mut buf = vec![0u8; 8192];
    loop {
        let n = upstream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        tls_stream.write_all(&buf[..n]).await?;
        tls_stream.flush().await?;
    }
    Ok(())
}

/// Relay a single request/response to an upstream TLS server (production).
async fn relay_tls<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    tls_stream: &mut tokio_rustls::server::TlsStream<S>,
    upstream_host: &str,
    client_config: &std::sync::Arc<rustls::ClientConfig>,
    req: &HttpRequest,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let connector = tokio_rustls::TlsConnector::from(client_config.clone());
    let upstream_addr = format!("{}:443", upstream_host);

    let upstream_tcp = tokio::net::TcpStream::connect(&upstream_addr)
        .await
        .context("MITM: failed to connect to upstream")?;
    let server_name = rustls::pki_types::ServerName::try_from(upstream_host.to_string())
        .map_err(|e| anyhow::anyhow!("MITM: invalid server name: {}", e))?;
    let mut upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .context("MITM: upstream TLS handshake failed")?;

    upstream_tls.write_all(&req.raw_head).await?;
    if !req.body.is_empty() {
        upstream_tls.write_all(&req.body).await?;
    }

    // Relay upstream response to client, respecting HTTP/1.1 message framing.
    //
    // We must parse the response to detect where it ends, because the upstream
    // may keep the TCP connection alive (HTTP/1.1 keep-alive). Without framing
    // awareness, read() blocks indefinitely waiting for EOF that never comes.
    // This caused Telegram long-poll getUpdates to stall: the 30s poll response
    // arrived but relay_tls never returned because upstream kept the connection open.
    let mut buf = vec![0u8; 32768];
    let mut total_relayed: usize = 0;

    // Phase 1: Read and relay response headers
    let mut header_buf = Vec::with_capacity(8192);
    let content_length: Option<usize>;
    let is_chunked: bool;
    loop {
        let n = match upstream_tls.read(&mut buf).await {
            Ok(0) => {
                // EOF before headers complete — relay what we have
                if !header_buf.is_empty() {
                    tls_stream.write_all(&header_buf).await?;
                    tls_stream.flush().await?;
                }
                return Ok(());
            }
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "MITM: upstream read error during headers");
                return Ok(());
            }
        };
        header_buf.extend_from_slice(&buf[..n]);

        // Check for end of headers (\r\n\r\n)
        if let Some(header_end) = find_header_end(&header_buf) {
            let headers_slice = &header_buf[..header_end];
            content_length = parse_content_length(headers_slice);
            is_chunked = is_transfer_encoding_chunked(headers_slice);

            // Relay entire header_buf (headers + any body bytes already read)
            tls_stream.write_all(&header_buf).await?;
            tls_stream.flush().await?;
            total_relayed += header_buf.len();

            // Calculate how many body bytes we already have
            let body_bytes_read = header_buf.len() - header_end;

            // HTTP response framing — transport layer only, no Content-Type dispatch.
            // Chunked encoding wraps ALL content types (SSE, HTML, JSON, gzip).
            // The chunked parser reads chunk-size + data structurally, so body content
            // (including SSE events, gzip bytes, or accidental patterns) is irrelevant.
            // Priority: Content-Length > Transfer-Encoding: chunked > EOF.
            if let Some(cl) = content_length {
                let remaining = cl.saturating_sub(body_bytes_read);
                relay_exact_bytes(&mut upstream_tls, tls_stream, remaining, &mut total_relayed)
                    .await?;
            } else if is_chunked {
                relay_chunked(
                    &mut upstream_tls,
                    tls_stream,
                    &header_buf[header_end..],
                    &mut total_relayed,
                )
                .await?;
            } else {
                relay_until_eof(&mut upstream_tls, tls_stream, &mut total_relayed).await?;
            }
            // Final flush: ensure all response bytes reach client before
            // keep-alive loop reads the next request.
            tls_stream.flush().await?;
            break;
        }

        // Headers too large (> 64KB) — abort
        if header_buf.len() > 65536 {
            tls_stream.write_all(&header_buf).await?;
            tls_stream.flush().await?;
            return Ok(());
        }
    }

    if total_relayed > 0 {
        tracing::debug!(bytes = total_relayed, host = %upstream_host, "MITM: relay complete");
    }
    Ok(())
}

/// Find the end of HTTP headers (position after \r\n\r\n).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse Content-Length from raw HTTP headers.
fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        if let Some(val) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            return val.trim().parse().ok();
        }
        // Case-insensitive match for other capitalizations
        if line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:") {
            return line[15..].trim().parse().ok();
        }
    }
    None
}

/// Check if Transfer-Encoding is chunked.
fn is_transfer_encoding_chunked(headers: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(headers) else {
        return false;
    };
    for line in s.lines() {
        if line.len() > 18 && line[..18].eq_ignore_ascii_case("transfer-encoding:") {
            return line[18..].trim().eq_ignore_ascii_case("chunked");
        }
    }
    false
}

/// Relay exactly `remaining` bytes from upstream to client.
async fn relay_exact_bytes<R, W>(
    upstream: &mut R,
    client: &mut W,
    mut remaining: usize,
    total: &mut usize,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 32768];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = match upstream.read(&mut buf[..to_read]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "MITM: upstream read error during body relay");
                break;
            }
        };
        client.write_all(&buf[..n]).await?;
        client.flush().await?;
        remaining -= n;
        *total += n;
    }
    Ok(())
}

/// Relay chunked transfer encoding with proper framing.
///
/// State-based parser: reads chunk-size line → data → CRLF → repeat.
/// All bytes (chunk headers + data) are relayed verbatim to client.
/// Body is never decoded — only chunk boundaries are tracked.
///
/// `initial_body` contains body bytes already read with the headers.
async fn relay_chunked<R, W>(
    upstream: &mut R,
    client: &mut W,
    initial_body: &[u8],
    total: &mut usize,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut pending = Vec::from(initial_body);
    let mut raw_buf = vec![0u8; 32768];

    loop {
        // 1. Read chunk size line (hex + optional extensions + CRLF)
        let size_line =
            relay_read_line(upstream, &mut pending, &mut raw_buf, client, total).await?;
        let size_str = std::str::from_utf8(&size_line)
            .unwrap_or("0")
            .trim()
            .split(';')
            .next()
            .unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);

        // 2. Final chunk
        if chunk_size == 0 {
            // Read trailing \r\n after "0\r\n"
            let _ = relay_read_line(upstream, &mut pending, &mut raw_buf, client, total).await;
            // Ensure all bytes (including the final SSE events in the last data
            // chunk) are flushed to client before returning to the keep-alive loop.
            // Without this, the client may not receive message_stop before the
            // next response's message_start arrives on the same connection.
            client.flush().await?;
            break;
        }

        // 3. Relay exactly chunk_size bytes + trailing \r\n
        let mut remaining = chunk_size + 2;

        // Drain pending first
        if !pending.is_empty() {
            let drain = remaining.min(pending.len());
            client.write_all(&pending[..drain]).await?;
            client.flush().await?;
            *total += drain;
            remaining -= drain;
            pending = pending[drain..].to_vec();
        }

        // Read rest from upstream
        while remaining > 0 {
            let to_read = remaining.min(raw_buf.len());
            let n = match upstream.read(&mut raw_buf[..to_read]).await {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(error = %e, "MITM: chunked data read error");
                    return Ok(());
                }
            };
            client.write_all(&raw_buf[..n]).await?;
            client.flush().await?;
            *total += n;
            remaining -= n;
        }
    }
    Ok(())
}

/// Read one line (up to \r\n) from pending + upstream, relaying all bytes.
async fn relay_read_line<R, W>(
    upstream: &mut R,
    pending: &mut Vec<u8>,
    raw_buf: &mut [u8],
    client: &mut W,
    total: &mut usize,
) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut line = Vec::new();
    loop {
        if let Some(pos) = pending.windows(2).position(|w| w == b"\r\n") {
            let end = pos + 2;
            line.extend_from_slice(&pending[..pos]);
            client.write_all(&pending[..end]).await?;
            client.flush().await?;
            *total += end;
            *pending = pending[end..].to_vec();
            return Ok(line);
        }
        if !pending.is_empty() {
            line.extend_from_slice(pending);
            client.write_all(pending).await?;
            client.flush().await?;
            *total += pending.len();
            pending.clear();
        }
        let n = match upstream.read(raw_buf).await {
            Ok(0) => return Ok(line),
            Ok(n) => n,
            Err(_) => return Ok(line),
        };
        pending.extend_from_slice(&raw_buf[..n]);
    }
}

/// Relay until EOF (for responses without Content-Length or chunked).
async fn relay_until_eof<R, W>(upstream: &mut R, client: &mut W, total: &mut usize) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 32768];
    loop {
        let n = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "MITM: upstream read error during EOF relay");
                break;
            }
        };
        client.write_all(&buf[..n]).await?;
        client.flush().await?;
        *total += n;
    }
    Ok(())
}

/// Resolve the original destination when SNI is absent.
///
/// Uses SO_ORIGINAL_DST on the accepted socket to recover the
/// pre-DNAT destination (set by iptables -j DNAT in sandbox).
#[cfg(target_os = "linux")]
pub fn get_original_dst(fd: std::os::fd::RawFd) -> Option<std::net::SocketAddr> {
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddrV4};

    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // SO_ORIGINAL_DST = 80
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(std::net::SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_original_dst(_fd: i32) -> Option<std::net::SocketAddr> {
    None
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello without
/// consuming the stream. Peeks at the first bytes of the TCP stream to
/// parse the TLS record header and ClientHello extension.
///
/// Returns `None` if SNI cannot be extracted (non-TLS, missing extension, etc).
/// The peeked bytes remain in the socket buffer for the actual TLS handshake.
pub async fn peek_sni(stream: &tokio::net::TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024]; // ClientHello is typically < 512 bytes
    let n = stream.peek(&mut buf).await.ok()?;
    if n < 5 {
        return None;
    }

    // TLS record: type(1) + version(2) + length(2) + payload
    if buf[0] != 0x16 {
        return None; // Not a TLS Handshake
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let available = n.min(5 + record_len);
    if available < 43 {
        return None; // Too short for ClientHello
    }

    // Handshake header: type(1) + length(3)
    let hs = &buf[5..available];
    if hs[0] != 0x01 {
        return None; // Not ClientHello
    }

    // Skip: handshake header(4) + client_version(2) + random(32) = 38 bytes
    let mut pos = 38;
    if pos >= hs.len() {
        return None;
    }

    // Session ID (variable)
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > hs.len() {
        return None;
    }

    // Cipher suites (variable)
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > hs.len() {
        return None;
    }

    // Compression methods (variable)
    let comp_len = hs[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > hs.len() {
        return None;
    }

    // Extensions length
    let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(hs.len());

    // Scan extensions for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && pos + ext_data_len <= ext_end {
            // SNI extension: list_len(2) + type(1) + name_len(2) + name
            if ext_data_len >= 5 {
                let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= ext_end {
                    return std::str::from_utf8(&hs[name_start..name_start + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
            return None;
        }
        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_resolver_generates_and_caches() {
        let ca = crate::tls_proxy::test_helpers::create_test_ca();
        let resolver = GvmCertResolver::new(&ca.0, &ca.1).unwrap();

        // First call: cache miss → generate
        let key1 = resolver.issue_and_cache("api.github.com");
        assert!(key1.is_some());

        // Second call: cache hit
        let key2 = resolver.issue_and_cache("api.github.com");
        assert!(key2.is_some());

        // Different domain: new cert
        let key3 = resolver.issue_and_cache("api.anthropic.com");
        assert!(key3.is_some());

        // moka defers bookkeeping; flush pending tasks before checking count.
        resolver.cache.run_pending_tasks();
        assert_eq!(resolver.cache.entry_count(), 2);
    }

    #[test]
    fn alpn_forced_to_http11() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let ca = test_helpers::create_test_ca();
        let resolver = Arc::new(GvmCertResolver::new(&ca.0, &ca.1).unwrap());
        let config = build_server_config(resolver).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn client_config_alpn_http11() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let config = build_client_config().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn parse_complete_request() {
        let raw = b"GET /repos/test HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw.to_vec());

        // Use tokio::io::BufReader to make Cursor async-compatible
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let req = read_http_request(&mut reader).await.unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/repos/test");
        assert_eq!(req.host, "api.github.com");
        assert!(req.body.is_empty());
    }

    #[tokio::test]
    async fn parse_request_with_body() {
        let raw = b"POST /api/send HTTP/1.1\r\nHost: slack.com\r\nContent-Length: 13\r\n\r\n{\"text\":\"hi\"}";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let req = read_http_request(&mut reader).await.unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/send");
        assert_eq!(req.host, "slack.com");
        assert_eq!(req.body, b"{\"text\":\"hi\"}");
    }

    // ── CRLF injection defense tests ──

    #[test]
    fn contains_header_injection_chars_detects_cr() {
        assert!(contains_header_injection_chars(b"Bearer tok\r\nEvil: yes"));
    }

    #[test]
    fn contains_header_injection_chars_detects_lf() {
        assert!(contains_header_injection_chars(b"Bearer tok\nEvil: yes"));
    }

    #[test]
    fn contains_header_injection_chars_detects_nul() {
        assert!(contains_header_injection_chars(b"Bearer tok\0rest"));
    }

    #[test]
    fn contains_header_injection_chars_allows_clean_value() {
        assert!(!contains_header_injection_chars(b"Bearer sk-abc123XYZ"));
    }

    #[test]
    fn inject_credentials_rejects_bearer_with_crlf() {
        use crate::api_keys::{APIKeyStore, Credential};
        use std::collections::HashMap;

        // Build a store with a malicious Bearer token containing CRLF
        let mut credentials = HashMap::new();
        credentials.insert(
            "evil.com".to_string(),
            Credential::Bearer {
                token: "sk-good\r\nX-Injected: pwned".to_string(),
            },
        );
        let store = APIKeyStore::from_map(credentials);

        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/v1/chat".to_string(),
            host: "evil.com".to_string(),
            headers: vec![],
            body: vec![],
            raw_head: b"GET /v1/chat HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec(),
        };

        // inject_credentials must return false (rejected) and NOT inject the header
        let injected = req.inject_credentials(&store);
        assert!(!injected, "CRLF-tainted credential must be rejected");
        assert!(
            req.headers.is_empty(),
            "No headers should be added when credential is rejected"
        );
    }

    #[test]
    fn inject_credentials_rejects_apikey_with_crlf_in_value() {
        use crate::api_keys::{APIKeyStore, Credential};
        use std::collections::HashMap;

        let mut credentials = HashMap::new();
        credentials.insert(
            "evil.com".to_string(),
            Credential::ApiKey {
                header: "X-Api-Key".to_string(),
                value: "good-key\r\nX-Injected: pwned".to_string(),
            },
        );
        let store = APIKeyStore::from_map(credentials);

        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/api".to_string(),
            host: "evil.com".to_string(),
            headers: vec![],
            body: vec![],
            raw_head: b"GET /api HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec(),
        };

        let injected = req.inject_credentials(&store);
        assert!(!injected, "CRLF-tainted ApiKey value must be rejected");
    }

    #[test]
    fn inject_credentials_rejects_apikey_with_crlf_in_header_name() {
        use crate::api_keys::{APIKeyStore, Credential};
        use std::collections::HashMap;

        let mut credentials = HashMap::new();
        credentials.insert(
            "evil.com".to_string(),
            Credential::ApiKey {
                header: "X-Api-Key\r\nX-Injected".to_string(),
                value: "good-value".to_string(),
            },
        );
        let store = APIKeyStore::from_map(credentials);

        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/api".to_string(),
            host: "evil.com".to_string(),
            headers: vec![],
            body: vec![],
            raw_head: b"GET /api HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec(),
        };

        let injected = req.inject_credentials(&store);
        assert!(
            !injected,
            "CRLF-tainted ApiKey header name must be rejected"
        );
    }

    #[test]
    fn inject_credentials_accepts_clean_bearer() {
        use crate::api_keys::{APIKeyStore, Credential};
        use std::collections::HashMap;

        let mut credentials = HashMap::new();
        credentials.insert(
            "api.openai.com".to_string(),
            Credential::Bearer {
                token: "sk-proj-abc123".to_string(),
            },
        );
        let store = APIKeyStore::from_map(credentials);

        let mut req = HttpRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            host: "api.openai.com".to_string(),
            headers: vec![],
            body: vec![],
            raw_head: b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"
                .to_vec(),
        };

        let injected = req.inject_credentials(&store);
        assert!(injected, "Clean credential must be accepted");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "Authorization");
        assert_eq!(req.headers[0].1, b"Bearer sk-proj-abc123");
    }
}

/// Test helpers (not public API).
#[doc(hidden)]
pub mod test_helpers {
    use super::*;

    /// Create a test CA for unit tests. Returns (cert_pem, key_pem).
    ///
    /// Generates a standalone CA (not via EphemeralCA) because EphemeralCA
    /// doesn't expose the private key PEM needed by GvmCertResolver.
    pub fn create_test_ca() -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "Test CA");
            dn
        };
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }
}
