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

    /// Build a resolver from a per-sandbox CA (CA-4 routing).
    ///
    /// Equivalent to [`GvmCertResolver::new`] but takes a borrowed
    /// [`gvm_sandbox::ca::SandboxCA`] directly instead of separate cert
    /// and key PEM bytes. The cert PEM is copied; the key PEM is moved
    /// into the resolver's signing material via the same rcgen path.
    ///
    /// Each sandbox gets its own resolver instance — the leaf cache
    /// is per-resolver, so a leaf signed by sandbox A's CA is never
    /// reused for sandbox B's TLS handshake (which wouldn't validate
    /// anyway, since B's trust store carries B's CA cert, not A's).
    pub fn from_sandbox_ca(ca: &gvm_sandbox::ca::SandboxCA) -> Result<Self> {
        Self::new(ca.ca_cert_pem(), &ca.ca_key_pem())
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
        operation_descriptor: Some(crate::operation::http(&req.method, &req.path)),
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

    // ── Cert cache attack resistance + concurrency ─────────────────
    //
    // These tests cover the actual purpose of GvmCertResolver — not
    // "issue_and_cache returns Some" (already covered by
    // cert_resolver_generates_and_caches above) but the security and
    // correctness invariants the cache exists to provide:
    //
    //   1. SNI cache poisoning: an attacker who can request unlimited
    //      unique SNI values must NOT be able to grow the cert cache
    //      unbounded. Moka's TinyLFU eviction caps live entries at
    //      MAX_CERT_CACHE_SIZE.
    //
    //   2. Cache hit semantics: a second issue for the same domain
    //      must return the SAME Arc<CertifiedKey> as the first call —
    //      not a freshly generated cert with a different key. If this
    //      ever regresses, every TLS handshake re-pays the rcgen cost
    //      (~0.1ms × handshake_rate) and clients may see cert rotation
    //      they shouldn't.
    //
    //   3. Concurrent generation: simultaneous requests for the same
    //      new domain must all succeed without deadlock and must
    //      converge on equivalent cert chains (same chain length,
    //      same CA in second slot).
    //
    //   4. Concurrent issuance for many distinct domains must not
    //      deadlock or panic — moka's lock-free reads + striped write
    //      locks have to handle the worst case proxies see in
    //      production (50+ concurrent unseen SNI values).

    #[test]
    fn cert_cache_bounded_under_sni_attack() {
        let ca = test_helpers::create_test_ca();
        let resolver = GvmCertResolver::new(&ca.0, &ca.1).unwrap();

        // 12,000 unique domains — well above the 10,000 cap. Each
        // generates a real ECDSA P-256 leaf cert (~0.1ms each), so
        // this test takes ~1.5s on a typical CI runner. The point
        // is to verify the bound holds, not raw throughput.
        let n_attack: u64 = 12_000;
        for i in 0..n_attack {
            let domain = format!("evil-{}.attacker.example", i);
            assert!(
                resolver.issue_and_cache(&domain).is_some(),
                "issue_and_cache must not fail under SNI flood"
            );
        }

        // Flush moka's pending eviction tasks so entry_count() reflects
        // the steady-state size (TinyLFU eviction is async).
        let live = resolver.sync_and_count();
        assert!(
            live <= MAX_CERT_CACHE_SIZE,
            "SNI attack grew cache beyond cap: live={} max={}",
            live,
            MAX_CERT_CACHE_SIZE
        );
        // And ALSO non-trivially populated — if `live` were 0 the
        // test would pass vacuously but the attacker won.
        assert!(
            live > MAX_CERT_CACHE_SIZE / 2,
            "cache mysteriously empty after {} inserts (live={})",
            n_attack,
            live
        );
    }

    #[test]
    fn cert_cache_hit_returns_same_underlying_cert() {
        let ca = test_helpers::create_test_ca();
        let resolver = GvmCertResolver::new(&ca.0, &ca.1).unwrap();

        let first = resolver.issue_and_cache("api.openai.com").unwrap();
        let second = resolver.issue_and_cache("api.openai.com").unwrap();

        // The point: cache HIT must return a clone of the SAME
        // CertifiedKey, not a regenerated one. Compare by Arc
        // pointer-equality first (cheapest) and fall back to
        // cert-chain bytes if Arc pointers differ (which can
        // happen if a future refactor introduces a wrapping layer).
        assert!(
            Arc::ptr_eq(&first, &second),
            "cache hit produced a different Arc — leaf cert was \
             unexpectedly regenerated"
        );

        // Belt-and-suspenders: chain bytes must match too.
        assert_eq!(
            first.cert.len(),
            second.cert.len(),
            "chain length differs across cache hit"
        );
        for (a, b) in first.cert.iter().zip(second.cert.iter()) {
            assert_eq!(
                a.as_ref(),
                b.as_ref(),
                "chain DER bytes differ across cache hit"
            );
        }
    }

    #[test]
    fn cert_cache_chain_includes_ca_for_client_verification() {
        // The leaf cert chain MUST include the CA cert as the second
        // entry so clients verifying the chain can walk leaf → CA
        // → trust-store. If the chain only had the leaf, verifiers
        // that do not preload the original CA in their trust store
        // would reject the connection.
        let ca = test_helpers::create_test_ca();
        let resolver = GvmCertResolver::new(&ca.0, &ca.1).unwrap();
        let key = resolver.issue_and_cache("api.openai.com").unwrap();

        assert_eq!(
            key.cert.len(),
            2,
            "leaf cert chain must contain [leaf, ca], got {} entries",
            key.cert.len()
        );

        // Second entry must be the original CA cert DER (we extracted
        // it in GvmCertResolver::new from the input pem).
        assert!(!key.cert[0].as_ref().is_empty(), "leaf DER is empty");
        assert!(
            !key.cert[1].as_ref().is_empty(),
            "CA DER (chain slot 1) is empty"
        );
        assert_ne!(
            key.cert[0].as_ref(),
            key.cert[1].as_ref(),
            "leaf and CA DER are identical — chain is degenerate"
        );
    }

    #[test]
    fn cert_cache_concurrent_distinct_domains_no_deadlock_no_panic() {
        use std::thread;

        let ca = test_helpers::create_test_ca();
        let resolver = Arc::new(GvmCertResolver::new(&ca.0, &ca.1).unwrap());

        // 32 threads × 32 distinct domains each = 1024 generations.
        // Far above the realistic concurrent-handshake count, but
        // small enough to keep the test under a few seconds.
        let mut handles = Vec::new();
        for thread_id in 0..32u32 {
            let r = Arc::clone(&resolver);
            handles.push(thread::spawn(move || {
                for i in 0..32u32 {
                    let d = format!("t{}-d{}.example", thread_id, i);
                    let key = r.issue_and_cache(&d).expect("must succeed");
                    assert_eq!(
                        key.cert.len(),
                        2,
                        "concurrent generation produced wrong chain length"
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        // After all threads finish, the cache must have at least one
        // entry and at most MAX_CERT_CACHE_SIZE. Anything outside that
        // band means eviction is broken.
        let live = resolver.sync_and_count();
        assert!(live > 0, "cache empty after 1024 concurrent generations");
        assert!(
            live <= MAX_CERT_CACHE_SIZE,
            "cache grew beyond cap during concurrent issuance: {}",
            live
        );
    }

    #[test]
    fn cert_cache_concurrent_same_domain_all_threads_succeed() {
        // 32 threads request the SAME domain at roughly the same
        // time. Each must get a valid cert; the cache itself must
        // converge on a single cached entry (or close to it — moka
        // doesn't guarantee single-flight on writes, only on reads,
        // so multiple threads MAY each generate independently in the
        // worst case; the contract is "no deadlock + every thread
        // gets a working cert").
        use std::sync::Barrier;
        use std::thread;

        let ca = test_helpers::create_test_ca();
        let resolver = Arc::new(GvmCertResolver::new(&ca.0, &ca.1).unwrap());
        let barrier = Arc::new(Barrier::new(32));

        let mut handles = Vec::new();
        for _ in 0..32u32 {
            let r = Arc::clone(&resolver);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                let key = r.issue_and_cache("api.contended.com").unwrap();
                assert_eq!(key.cert.len(), 2);
                key
            }));
        }
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every thread must have gotten a valid 2-entry chain.
        for k in &keys {
            assert_eq!(k.cert.len(), 2);
        }

        // Steady-state: cache contains the entry exactly once.
        let live = resolver.sync_and_count();
        assert!(
            (1..=2).contains(&live),
            "expected 1 (single-flight) or 2 (race winner overwrote loser) \
             entries for one domain, got {}",
            live
        );
    }

    // ── rebuild_raw_head() ──
    //
    // Tests for the legacy HTTP-parsing helpers (find_header_end,
    // parse_content_length, is_transfer_encoding_chunked) were
    // removed alongside the helpers themselves when
    // handle_mitm_stream_legacy was deleted. All MITM traffic now
    // goes through hyper, which handles HTTP framing internally.

    #[test]
    fn rebuild_raw_head_produces_valid_http() {
        let mut req = HttpRequest {
            method: "POST".to_string(),
            path: "/v1/chat".to_string(),
            host: "api.openai.com".to_string(),
            headers: vec![
                ("Host".to_string(), b"api.openai.com".to_vec()),
                ("Content-Length".to_string(), b"13".to_vec()),
            ],
            body: b"{\"text\":\"hi\"}".to_vec(),
            raw_head: vec![], // will be rebuilt
        };

        req.rebuild_raw_head();

        let raw = String::from_utf8(req.raw_head.clone()).unwrap();
        assert!(raw.starts_with("POST /v1/chat HTTP/1.1\r\n"));
        assert!(raw.contains("Host: api.openai.com\r\n"));
        assert!(raw.contains("Content-Length: 13\r\n"));
        assert!(raw.ends_with("\r\n\r\n"));
    }

    #[test]
    fn rebuild_raw_head_empty_headers() {
        let mut req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            host: String::new(),
            headers: vec![],
            body: vec![],
            raw_head: vec![],
        };

        req.rebuild_raw_head();

        let raw = String::from_utf8(req.raw_head.clone()).unwrap();
        assert_eq!(raw, "GET / HTTP/1.1\r\n\r\n");
    }

    // ── read_http_request smuggling defense ──

    #[tokio::test]
    async fn parse_rejects_cl_and_te_conflict() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let result = read_http_request(&mut reader).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("smuggling"),
            "error should mention smuggling: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn parse_rejects_duplicate_cl_with_different_values() {
        let raw =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let result = read_http_request(&mut reader).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Content-Length"),
            "error should mention Content-Length: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn parse_accepts_duplicate_cl_with_same_value() {
        let raw =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let result = read_http_request(&mut reader).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().body, b"hello");
    }

    #[tokio::test]
    async fn parse_empty_stream_returns_error() {
        let raw: &[u8] = b"";
        let mut cursor = std::io::Cursor::new(raw.to_vec());
        let mut reader = tokio::io::BufReader::new(&mut cursor);
        let result = read_http_request(&mut reader).await;
        assert!(result.is_err());
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
