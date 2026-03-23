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
use dashmap::DashMap;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// TLS proxy configuration.
pub struct TlsProxyConfig {
    /// CA certificate PEM (for signing leaf certs).
    pub ca_cert_pem: Vec<u8>,
    /// CA private key PEM.
    pub ca_key_pem: Vec<u8>,
}

/// Dynamic certificate resolver — generates per-domain leaf certs on demand.
pub struct GvmCertResolver {
    /// CA certificate for signing.
    ca_cert: rcgen::Certificate,
    /// CA key pair.
    ca_key: KeyPair,
    /// Per-domain leaf cert cache (domain → CertifiedKey).
    cache: DashMap<String, Arc<CertifiedKey>>,
}

impl std::fmt::Debug for GvmCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GvmCertResolver")
            .field("cached_domains", &self.cache.len())
            .finish()
    }
}

impl GvmCertResolver {
    /// Create a resolver from CA PEM bytes.
    pub fn new(ca_cert_pem: &[u8], ca_key_pem: &[u8]) -> Result<Self> {
        let ca_key_str = std::str::from_utf8(ca_key_pem).context("CA key not valid UTF-8")?;

        let ca_key = KeyPair::from_pem(ca_key_str).context("Failed to parse CA key PEM")?;

        // Reconstruct CA cert from key (self-signed)
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "GVM Ephemeral CA");
            dn
        };
        let ca_cert = params
            .self_signed(&ca_key)
            .context("Failed to reconstruct CA cert")?;

        Ok(Self {
            ca_cert,
            ca_key,
            cache: DashMap::new(),
        })
    }

    /// Issue a leaf cert for the given domain. Caches the result.
    fn issue_and_cache(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // Check cache first
        if let Some(cached) = self.cache.get(domain) {
            return Some(cached.clone());
        }

        // Generate ECDSA P-256 leaf cert (~0.1ms)
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).ok()?;

        let mut params = CertificateParams::new(vec![domain.to_string()]).ok()?;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, domain);
            dn
        };

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .ok()?;

        // Convert to rustls types
        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der).ok()?;

        let certified_key = CertifiedKey::new(vec![cert_der], signing_key);
        let arc_key = Arc::new(certified_key);

        self.cache.insert(domain.to_string(), arc_key.clone());
        tracing::debug!(domain, "Leaf certificate generated and cached");

        Some(arc_key)
    }
}

impl ResolvesServerCert for GvmCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name()?;
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

/// Parse an HTTP request from a TLS-decrypted byte stream.
///
/// Handles Status::Partial by looping and accumulating bytes.
/// Returns method, path, host, and body slice.
pub async fn read_http_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<HttpRequest> {
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

                // Collect all headers for forwarding
                let header_pairs: Vec<(String, Vec<u8>)> = headers
                    .iter()
                    .filter(|h| h.name != httparse::EMPTY_HEADER.name)
                    .map(|h| (h.name.to_string(), h.value.to_vec()))
                    .collect();

                let body = buf[body_offset..].to_vec();

                return Ok(HttpRequest {
                    method,
                    path,
                    host,
                    headers: header_pairs,
                    body,
                    raw_head: buf[..body_offset].to_vec(),
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

/// Parsed HTTP request from decrypted TLS stream.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    /// Raw header bytes for forwarding (if no modification needed).
    pub raw_head: Vec<u8>,
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
            &mut addr as *mut _ as *mut libc::c_void,
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

        assert_eq!(resolver.cache.len(), 2);
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
}

/// Test helpers (not public API).
#[doc(hidden)]
pub mod test_helpers {
    use super::*;

    /// Create a test CA for unit tests. Returns (cert_pem, key_pem).
    pub fn create_test_ca() -> (Vec<u8>, Vec<u8>) {
        let ca = gvm_sandbox::ca::EphemeralCA::generate().unwrap();
        let cert_pem = ca.ca_cert_pem().to_vec();
        // We need to also get the key — but EphemeralCA doesn't expose it.
        // For tests, generate a standalone CA directly.
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
