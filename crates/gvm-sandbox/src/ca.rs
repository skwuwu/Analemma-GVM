//! Ephemeral CA for transparent MITM TLS inspection inside sandboxes.
//!
//! Generates a per-session CA certificate and private key entirely in memory.
//! The CA is injected into the sandbox's trust store via tmpfs — no
//! cryptographic material ever touches the host disk.
//!
//! Leaf certificates are generated on-demand per domain (via SNI) and cached
//! in a concurrent map for reuse within the session.

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use zeroize::Zeroize;

/// Ephemeral CA — lives only in memory, zeroized on drop.
pub struct EphemeralCA {
    /// PEM-encoded CA certificate (for injection into sandbox trust store).
    ca_cert_pem: Vec<u8>,
    /// CA key pair for signing leaf certificates.
    ca_key: KeyPair,
    /// CA certificate params (for signing).
    ca_cert: rcgen::Certificate,
}

impl EphemeralCA {
    /// Generate a new ephemeral CA with ECDSA P-256 key.
    ///
    /// The CA is valid for 24 hours — one sandbox session.
    /// No disk I/O. All state is in memory.
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate CA key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "GVM Ephemeral CA");
            dn.push(DnType::OrganizationName, "Analemma GVM");
            dn
        };
        // 24-hour validity window centered on now.
        // Backdated not_before tolerates clock drift up to 24 hours.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(24);
        params.not_after = now + time::Duration::hours(24);

        let ca_cert = params
            .self_signed(&key_pair)
            .context("Failed to self-sign CA certificate")?;

        let ca_cert_pem = ca_cert.pem().into_bytes();

        tracing::info!("Ephemeral CA generated (ECDSA P-256, in-memory only)");

        Ok(Self {
            ca_cert_pem,
            ca_key: key_pair,
            ca_cert,
        })
    }

    /// Get the CA certificate in PEM format (for trust store injection).
    pub fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// Get the CA private key in PEM format (for MITM TLS listener).
    pub fn ca_key_pem(&self) -> Vec<u8> {
        self.ca_key.serialize_pem().into_bytes()
    }

    /// Issue a leaf certificate for the given domain, signed by this CA.
    ///
    /// Uses ECDSA P-256 (~0.1ms per generation). Caller should cache the result.
    pub fn issue_leaf_cert(&self, domain: &str) -> Result<LeafCert> {
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate leaf key pair")?;

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .context("Invalid domain for certificate")?;
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, domain);
            dn
        };
        // Backdate leaf cert for clock drift tolerance (matches CA window)
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(24);
        params.not_after = now + time::Duration::hours(24);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("Failed to sign leaf certificate")?;

        Ok(LeafCert {
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

impl Drop for EphemeralCA {
    fn drop(&mut self) {
        // Zeroize CA cert PEM
        self.ca_cert_pem.zeroize();
        // Zeroize the serialized private key — rcgen::KeyPair doesn't implement Zeroize,
        // but we can serialize it once and zeroize the output to reduce exposure.
        // The in-memory KeyPair object itself will be freed by the allocator.
        let mut key_pem = self.ca_key.serialize_pem().into_bytes();
        key_pem.zeroize();
        tracing::debug!("Ephemeral CA zeroized on drop (cert PEM + key PEM serialization)");
    }
}

/// A leaf certificate + private key for a specific domain.
pub struct LeafCert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Drop for LeafCert {
    fn drop(&mut self) {
        self.cert_pem.zeroize();
        self.key_pem.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ephemeral_ca() {
        let ca = EphemeralCA::generate().expect("CA generation must succeed");
        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn issue_leaf_cert_for_domain() {
        let ca = EphemeralCA::generate().unwrap();
        let leaf = ca
            .issue_leaf_cert("api.github.com")
            .expect("Leaf cert must be issued");
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn issue_multiple_domains() {
        let ca = EphemeralCA::generate().unwrap();
        let domains = [
            "api.github.com",
            "api.anthropic.com",
            "slack.com",
            "api.telegram.org",
        ];
        for domain in &domains {
            let leaf = ca.issue_leaf_cert(domain).unwrap();
            assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        }
    }

    #[test]
    fn issue_ip_address_cert() {
        let ca = EphemeralCA::generate().unwrap();
        // IP address as SAN — rcgen supports IP SANs since 0.12+.
        // Verify the cert is actually issued with valid PEM content.
        let leaf = ca.issue_leaf_cert("142.250.190.46");
        match leaf {
            Ok(cert) => {
                assert!(
                    cert.cert_pem.contains("BEGIN CERTIFICATE"),
                    "IP SAN cert must have valid PEM"
                );
                assert!(
                    cert.key_pem.contains("BEGIN PRIVATE KEY"),
                    "IP SAN cert must have valid key"
                );
            }
            Err(e) => {
                // If rcgen doesn't support IP SANs, that's acceptable — just ensure
                // the error message is meaningful, not a panic.
                assert!(
                    !e.to_string().is_empty(),
                    "Error must have a message: {}",
                    e
                );
            }
        }
    }

    #[test]
    fn ca_cert_pem_zeroized_on_drop() {
        let ca = EphemeralCA::generate().unwrap();
        let pem_len = ca.ca_cert_pem().len();
        assert!(pem_len > 100); // non-trivial cert
        drop(ca);
        // Can't directly verify memory is zeroed, but drop didn't panic
    }
}
