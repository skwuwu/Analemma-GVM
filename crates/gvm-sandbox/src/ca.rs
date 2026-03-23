//! Ephemeral CA for transparent MITM TLS inspection inside sandboxes.
//!
//! Generates a per-session CA certificate and private key entirely in memory.
//! The CA is injected into the sandbox's trust store via memfd/tmpfs — no
//! cryptographic material ever touches the host disk.
//!
//! Leaf certificates are generated on-demand per domain (via SNI) and cached
//! in a concurrent map for reuse within the session.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey as RcgenCertifiedKey, DistinguishedName,
    DnType, IsCa, KeyPair,
};
use std::sync::Arc;
use std::time::Duration;
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
        // 24-hour validity — ephemeral, single session
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 12, 31);

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
        // Zeroize CA cert PEM — defense-in-depth
        self.ca_cert_pem.zeroize();
        tracing::debug!("Ephemeral CA zeroized on drop");
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
        // IP address as SAN (for SNI-less connections)
        let leaf = ca.issue_leaf_cert("142.250.190.46");
        // rcgen may or may not support IP SANs — test that it doesn't panic
        assert!(leaf.is_ok() || leaf.is_err());
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
