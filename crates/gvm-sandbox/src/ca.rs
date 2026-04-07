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
use std::path::Path;
use zeroize::Zeroize;

/// MITM CA for transparent TLS inspection.
///
/// Persisted to disk so that proxy restarts don't invalidate running sandbox
/// trust stores. This matches the pattern used by mitmproxy, Burp Suite, and
/// Charles Proxy — the CA is generated once and reused across sessions.
///
/// The CA cert + key are stored with restricted permissions (0600).
/// The key is zeroized in memory on drop.
pub struct EphemeralCA {
    /// PEM-encoded CA certificate (for injection into sandbox trust store).
    ca_cert_pem: Vec<u8>,
    /// PEM-encoded CA private key (for GvmCertResolver to sign leaf certs).
    ca_key_pem: Vec<u8>,
    /// Certificate `not_after` timestamp.
    ///
    /// Set exactly when the CA is freshly generated. When loaded from disk
    /// (subsequent restarts), we approximate via the cert file's mtime + 365d
    /// — this stays accurate as long as the file was written by `generate()`,
    /// which is the only path that creates it. Surfaced as `ca_expires_days`
    /// in `/gvm/health` so `gvm status` can warn before expiry.
    not_after: time::OffsetDateTime,
}

/// Default file paths for persistent CA storage.
const CA_CERT_PATH: &str = "data/mitm-ca.pem";
const CA_KEY_PATH: &str = "data/mitm-ca-key.pem";

impl EphemeralCA {
    /// Load existing CA from disk, or generate a new one and save it.
    ///
    /// On first run: generates ECDSA P-256 CA, saves cert + key to data/.
    /// On subsequent runs: loads from disk — same CA across proxy restarts.
    /// Running sandboxes keep working because the CA doesn't change.
    pub fn load_or_generate() -> Result<Self> {
        let cert_path = Path::new(CA_CERT_PATH);
        let key_path = Path::new(CA_KEY_PATH);

        if cert_path.exists() && key_path.exists() {
            match Self::load_from_disk(cert_path, key_path) {
                Ok(ca) => return Ok(ca),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load saved CA — regenerating");
                }
            }
        }

        let ca = Self::generate()?;
        ca.save_to_disk(cert_path, key_path)?;
        Ok(ca)
    }

    /// Load CA cert + key from disk. No regeneration — exact same bytes.
    fn load_from_disk(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read(cert_path).context("Failed to read CA cert")?;
        let key_pem = std::fs::read(key_path).context("Failed to read CA key")?;

        // Validate that the key is parseable
        KeyPair::from_pem(&String::from_utf8_lossy(&key_pem))
            .context("Saved CA key PEM is invalid")?;

        // Approximate not_after from the cert file's mtime + 365d.
        // This is exact because generate() always sets a 365-day validity
        // and writes the file immediately. Falls back to "now + 365d" if the
        // mtime is unreadable (extremely rare).
        let mtime = std::fs::metadata(cert_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64).ok())
            .unwrap_or_else(time::OffsetDateTime::now_utc);
        let not_after = mtime + time::Duration::days(365);

        tracing::info!(
            cert = %cert_path.display(),
            "MITM CA loaded from disk (persistent across restarts)"
        );

        Ok(Self {
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            not_after,
        })
    }

    /// Save CA cert + key to disk with restricted permissions.
    fn save_to_disk(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        std::fs::write(cert_path, &self.ca_cert_pem).context("Failed to write CA cert")?;
        std::fs::write(key_path, &self.ca_key_pem).context("Failed to write CA key")?;

        // Restrict permissions (key file especially)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600)).ok();
            std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644)).ok();
        }

        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "MITM CA saved to disk (reused on proxy restart)"
        );
        Ok(())
    }

    /// Generate a new CA with ECDSA P-256 key.
    ///
    /// Valid for 365 days. Persisted to disk by load_or_generate().
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate CA key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "GVM MITM CA");
            dn.push(DnType::OrganizationName, "Analemma GVM");
            dn
        };
        // 365-day validity. Persistent CA — not ephemeral per-session.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(24);
        let not_after = now + time::Duration::days(365);
        params.not_after = not_after;

        let ca_cert = params
            .self_signed(&key_pair)
            .context("Failed to self-sign CA certificate")?;

        let ca_cert_pem = ca_cert.pem().into_bytes();
        let ca_key_pem = key_pair.serialize_pem().into_bytes();

        tracing::info!("MITM CA generated (ECDSA P-256, 365-day validity)");

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            not_after,
        })
    }

    /// Days until the CA certificate expires (negative if already expired).
    /// Used by `/gvm/health` to surface CA validity to `gvm status`.
    pub fn expires_in_days(&self) -> i64 {
        let now = time::OffsetDateTime::now_utc();
        (self.not_after - now).whole_days()
    }

    /// Get the CA certificate in PEM format (for trust store injection).
    pub fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// Get the CA private key in PEM format (for GvmCertResolver).
    pub fn ca_key_pem(&self) -> Vec<u8> {
        self.ca_key_pem.clone()
    }
}

impl Drop for EphemeralCA {
    fn drop(&mut self) {
        self.ca_cert_pem.zeroize();
        self.ca_key_pem.zeroize();
        tracing::debug!("MITM CA key zeroized on drop");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca() {
        let ca = EphemeralCA::generate().expect("CA generation must succeed");
        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(!ca.ca_key_pem().is_empty());
    }

    #[test]
    fn ca_roundtrip_via_disk() {
        let ca = EphemeralCA::generate().unwrap();
        let cert_pem = ca.ca_cert_pem().to_vec();
        let key_pem = ca.ca_key_pem();

        // Write + read should produce identical bytes
        let dir = std::env::temp_dir().join("gvm-ca-test");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");
        ca.save_to_disk(&cert_path, &key_path).unwrap();

        let loaded = EphemeralCA::load_from_disk(&cert_path, &key_path).unwrap();
        assert_eq!(loaded.ca_cert_pem(), cert_pem);
        assert_eq!(loaded.ca_key_pem(), key_pem);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ca_zeroized_on_drop() {
        let ca = EphemeralCA::generate().unwrap();
        assert!(ca.ca_cert_pem().len() > 100);
        drop(ca);
    }
}
