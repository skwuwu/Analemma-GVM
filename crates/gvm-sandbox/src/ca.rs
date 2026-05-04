//! MITM CA management for transparent TLS inspection inside sandboxes.
//!
//! Two CA models coexist during the v0.5 → v0.6 migration:
//!
//! 1. **`EphemeralCA` (legacy, this module's original type)** — persistent,
//!    single CA shared by every sandbox. Stored at `data/mitm-ca.pem` +
//!    `data/mitm-ca-key.pem` with 0600 permissions. Reused across proxy
//!    restarts so running sandboxes keep TLS trust. **The name "Ephemeral"
//!    is historical — the keypair is on host disk.** All sandboxes share
//!    the same private key, so a key compromise affects every sandbox.
//!
//! 2. **`SandboxCA` + `CARegistry` (new, RAM-only, per-sandbox)** — each
//!    sandbox launch generates its own CA, held in proxy memory only,
//!    zeroized on sandbox exit. Bound to the audit chain via a
//!    `gvm.sandbox.launch` event whose `parent_event_id` is the chain
//!    root for every subsequent enforcement decision in that sandbox.
//!    See [`SandboxCA`] / [`CARegistry`].
//!
//! Migration plan: CA-1 (this docfix) → CA-2 (introduce SandboxCA, dual
//! emit sandbox_launch events) → CA-4 (MITM resolver routes by
//! sandbox_id) → CA-5 (delete `data/mitm-ca-key.pem`, drop EphemeralCA).
//!
//! Leaf certificates are generated on-demand per domain (via SNI) and
//! cached in a concurrent map. Both CA models cache leaves; the new
//! model caches per-sandbox so that one sandbox's domain cache does not
//! grant another sandbox the matching leaf.

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroize;

/// **Legacy single-CA model — persistent on host disk, shared across sandboxes.**
///
/// Persisted to disk so that proxy restarts don't invalidate running sandbox
/// trust stores. Matches the pattern used by mitmproxy, Burp Suite, and
/// Charles Proxy — one CA, reused across sessions. Will be removed at
/// CA-5 in favor of [`SandboxCA`].
///
/// The CA cert + key are stored with restricted permissions (0600).
/// The key is zeroized in memory on drop, but the disk copy survives
/// process exit — that is the property the new model fixes.
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

// ─── New per-sandbox model (CA-2) ─────────────────────────────────────────
//
// `SandboxCA` is the replacement for `EphemeralCA`. The proxy holds one
// `SandboxCA` per active sandbox in `CARegistry`, hands the cert PEM to
// the sandbox at launch (via the launch API, never via the legacy
// `GET /gvm/ca.pem`), and drops it on sandbox exit. The private key
// never reaches host disk; the only on-disk copy is the cert PEM
// inside the sandbox's tmpfs trust store, which is destroyed with the
// mount namespace on sandbox exit.
//
// Cryptographic identity is the SHA-256 of the DER-encoded
// SubjectPublicKeyInfo (a.k.a. "SPKI hash"). This is the value bound
// into the audit chain by the sandbox launch event so any later
// `verify_proof` walker can prove a given enforcement decision was
// made under a specific cryptographic root.

const SANDBOX_CA_DEFAULT_LIFETIME_HOURS: i64 = 8;

/// **Per-sandbox MITM CA — RAM-only, unique per launch.**
///
/// Replaces [`EphemeralCA`] (CA-2 → CA-5 migration). Properties:
///
/// - **RAM-only**: cert PEM + key PEM never written to host disk by this
///   module. The cert is delivered to the sandbox via the launch API and
///   then injected into the sandbox's tmpfs trust store (which lives in
///   the sandbox's mount namespace and is destroyed on exit). The key
///   stays only in proxy memory and is `zeroize()`d on `Drop`.
/// - **Per-sandbox**: each call to [`SandboxCA::generate_for_sandbox`]
///   produces a fresh keypair. A compromise of one sandbox's CA does
///   not affect other sandboxes' TLS trust.
/// - **Identity-bound**: [`SandboxCA::pubkey_hash`] returns the SHA-256
///   of the DER-encoded SPKI. This is the value embedded in the
///   `gvm.sandbox.launch` event's `context.ca_pubkey_hash` so every
///   later enforcement event in this sandbox traces back, via
///   `parent_event_id`, to a Merkle-anchored cryptographic root.
/// - **Bounded lifetime**: validity defaults to 8 hours (vs the 365 days
///   of the legacy CA), reflecting that this CA cannot outlive the
///   sandbox. Long-running sandboxes must request a refresh via the
///   launch API rather than depending on cert longevity.
pub struct SandboxCA {
    /// Sandbox identifier this CA was provisioned for. Used by
    /// [`CARegistry`] for lookups and by audit logs for correlation.
    sandbox_id: String,
    /// PEM-encoded CA certificate. Public — safe to expose via launch API.
    ca_cert_pem: Vec<u8>,
    /// PEM-encoded CA private key. RAM-only; zeroized on `Drop`.
    /// Stored as plain `Vec<u8>` rather than `secrecy::SecretBox` because
    /// `rcgen::KeyPair::from_pem` consumes a `&str`; wrapping later if
    /// the codebase adopts `secrecy` workspace-wide is straightforward.
    ca_key_pem: Vec<u8>,
    /// SHA-256 of the DER-encoded SubjectPublicKeyInfo. Computed once
    /// at generation; constant for the lifetime of this CA.
    pubkey_hash: [u8; 32],
    /// Validity end time. Set to `now + SANDBOX_CA_DEFAULT_LIFETIME_HOURS`.
    not_after: time::OffsetDateTime,
}

impl SandboxCA {
    /// Generate a new RAM-only CA for `sandbox_id`. Validity:
    /// `SANDBOX_CA_DEFAULT_LIFETIME_HOURS` from now.
    ///
    /// The key never reaches disk. The caller is responsible for
    /// extracting [`SandboxCA::ca_cert_pem`] for the sandbox's trust
    /// store and storing the `SandboxCA` itself in [`CARegistry`].
    pub fn generate_for_sandbox(sandbox_id: impl Into<String>) -> Result<Self> {
        let sandbox_id = sandbox_id.into();

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate per-sandbox CA key pair")?;

        // Cache the SPKI DER bytes BEFORE we move `key_pair` into
        // `self_signed`. `subject_public_key_info()` returns the
        // SPKI in the canonical DER form used by RFC 5280 — exactly
        // what we want to hash for the cryptographic identity.
        let spki_der = key_pair.public_key_der();
        let pubkey_hash: [u8; 32] = Sha256::digest(&spki_der).into();

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            // CN includes the sandbox_id so an operator inspecting the
            // cert (e.g. via `openssl x509 -in /etc/ssl/certs/gvm-ca.crt`
            // inside the sandbox) can immediately tell which CA they
            // are looking at and that it is per-sandbox, not shared.
            dn.push(
                DnType::CommonName,
                format!("GVM Sandbox CA ({})", sandbox_id),
            );
            dn.push(DnType::OrganizationName, "Analemma GVM");
            dn
        };
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5); // small clock skew tolerance
        let not_after = now + time::Duration::hours(SANDBOX_CA_DEFAULT_LIFETIME_HOURS);
        params.not_after = not_after;

        let ca_cert = params
            .self_signed(&key_pair)
            .context("Failed to self-sign per-sandbox CA certificate")?;

        let ca_cert_pem = ca_cert.pem().into_bytes();
        let ca_key_pem = key_pair.serialize_pem().into_bytes();

        tracing::info!(
            sandbox = %sandbox_id,
            pubkey_hash = %hex::encode(pubkey_hash),
            valid_for_hours = SANDBOX_CA_DEFAULT_LIFETIME_HOURS,
            "Per-sandbox MITM CA provisioned (RAM-only, ECDSA P-256)"
        );

        Ok(Self {
            sandbox_id,
            ca_cert_pem,
            ca_key_pem,
            pubkey_hash,
            not_after,
        })
    }

    /// Sandbox this CA belongs to.
    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    /// CA certificate PEM. Safe to log or expose via API.
    pub fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// CA private key PEM. **Sensitive** — only the `GvmCertResolver`
    /// for this sandbox should consume this. Returned as a clone so
    /// that the original buffer in `self` continues to be zeroized
    /// on `Drop` regardless of caller behavior.
    pub fn ca_key_pem(&self) -> Vec<u8> {
        self.ca_key_pem.clone()
    }

    /// SHA-256 of DER-encoded SPKI. The cryptographic identity bound
    /// into the audit chain by the sandbox launch event.
    pub fn pubkey_hash(&self) -> [u8; 32] {
        self.pubkey_hash
    }

    /// Hex form of [`SandboxCA::pubkey_hash`] (lowercase, no `0x`
    /// prefix). Suitable for embedding in audit event context maps
    /// or log lines.
    pub fn pubkey_hash_hex(&self) -> String {
        hex::encode(self.pubkey_hash)
    }

    /// Validity end time. After this point the CA must be re-provisioned.
    pub fn not_after(&self) -> time::OffsetDateTime {
        self.not_after
    }

    /// Hours until expiry (negative if already expired).
    pub fn expires_in_hours(&self) -> i64 {
        (self.not_after - time::OffsetDateTime::now_utc()).whole_hours()
    }
}

impl Drop for SandboxCA {
    fn drop(&mut self) {
        self.ca_key_pem.zeroize();
        self.ca_cert_pem.zeroize();
        // pubkey_hash is just a 32-byte digest of public material — no
        // need to zeroize, but emit an audit-relevant trace so a chain
        // walker correlating WAL events with proxy logs can see when
        // the CA was retired.
        tracing::info!(
            sandbox = %self.sandbox_id,
            pubkey_hash = %hex::encode(self.pubkey_hash),
            "Per-sandbox MITM CA retired (zeroized)"
        );
    }
}

/// In-memory registry of active per-sandbox CAs.
///
/// One CA per sandbox lifetime. Lookups happen on every MITM TLS
/// handshake (via `peer_addr → sandbox_id` resolution upstream of
/// this registry), so the data structure must be cheap to read
/// concurrently — hence `DashMap`.
///
/// The registry holds `Arc<SandboxCA>` so that a TLS handshake in
/// progress for sandbox X cannot have its CA buffer freed by a
/// concurrent `revoke(X)`. The buffer is dropped (and zeroized)
/// only after the last `Arc` clone is released — typically once
/// the in-flight handshake completes.
pub struct CARegistry {
    by_sandbox: dashmap::DashMap<String, Arc<SandboxCA>>,
}

impl CARegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            by_sandbox: dashmap::DashMap::new(),
        }
    }

    /// Provision a CA for `sandbox_id`. Returns the inserted `Arc`.
    ///
    /// If a CA already exists for this sandbox_id, it is replaced
    /// and the previous one's `Arc` is dropped — its in-flight TLS
    /// handshakes (if any) keep their references and finish with
    /// the old CA, but new handshakes use the new one. This is the
    /// "rotate" pathway for long-lived sandboxes.
    ///
    /// **Note**: this method does NOT emit the
    /// `gvm.sandbox.launch` audit event. The caller (sandbox launch
    /// orchestrator in the proxy crate) is responsible for that
    /// because only the orchestrator has access to the [`Ledger`]
    /// and the surrounding launch context (agent_id, mode, etc.).
    /// See `crate::operation::sandbox_launch` in `gvm-proxy` for
    /// the descriptor builder.
    ///
    /// [`Ledger`]: ../../../gvm_proxy/ledger/struct.Ledger.html
    pub fn provision(&self, sandbox_id: impl Into<String>) -> Result<Arc<SandboxCA>> {
        let sandbox_id = sandbox_id.into();
        let ca = Arc::new(SandboxCA::generate_for_sandbox(sandbox_id.clone())?);
        self.by_sandbox.insert(sandbox_id, ca.clone());
        Ok(ca)
    }

    /// Look up the CA for `sandbox_id`. Returns `None` if the
    /// sandbox has been revoked or never provisioned. Hot path —
    /// called on every MITM handshake.
    pub fn lookup(&self, sandbox_id: &str) -> Option<Arc<SandboxCA>> {
        self.by_sandbox.get(sandbox_id).map(|r| Arc::clone(&r))
    }

    /// Revoke and drop the CA for `sandbox_id`. The dropped CA's
    /// `Drop` impl zeroizes the key buffer once the last `Arc`
    /// reference is released. In-flight handshakes are not
    /// interrupted; new handshakes for this sandbox will fail
    /// `lookup()` and the MITM path is expected to fall back to
    /// blind relay or refuse the connection (per the visibility-tier
    /// policy designed in CA-4).
    pub fn revoke(&self, sandbox_id: &str) {
        if self.by_sandbox.remove(sandbox_id).is_some() {
            tracing::info!(sandbox = %sandbox_id, "MITM CA revoked");
        }
    }

    /// Number of active CAs (= active sandboxes with MITM on). Used by
    /// `gvm status` / `/gvm/health` to surface registry size.
    pub fn active_count(&self) -> usize {
        self.by_sandbox.len()
    }

    /// Snapshot of all currently-active sandbox IDs and their CA
    /// fingerprints. Intended for `gvm sandbox list` / debug
    /// inspection. Returns owned `String`s so the caller does not
    /// hold any DashMap shard locks.
    pub fn snapshot(&self) -> Vec<(String, String, time::OffsetDateTime)> {
        self.by_sandbox
            .iter()
            .map(|r| {
                let ca = r.value();
                (
                    ca.sandbox_id().to_string(),
                    ca.pubkey_hash_hex(),
                    ca.not_after(),
                )
            })
            .collect()
    }
}

impl Default for CARegistry {
    fn default() -> Self {
        Self::new()
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
        // Verify Drop actually wrote zeros over the CA bytes. We use
        // `ca_cert_pem()` because it returns `&[u8]` pointing into the
        // private field — `ca_key_pem()` returns a *clone*, so its
        // pointer would not survive `drop(ca)` and we'd be reading
        // from a separately-allocated heap region that Drop never
        // touches. The cert and key buffers share the same Drop impl
        // (both are `zeroize()`d), so testing the cert proves the
        // zeroize call ran.
        let ca = EphemeralCA::generate().expect("CA generation must succeed");
        let cert = ca.ca_cert_pem();
        assert!(cert.len() > 100);

        // Snapshot original cert bytes (first 64) for post-drop comparison.
        let mut original = [0u8; 64];
        let copy_len = original.len().min(cert.len());
        original[..copy_len].copy_from_slice(&cert[..copy_len]);

        // Capture the pointer to the live heap buffer in `ca`.
        let key_ptr: *const u8 = cert.as_ptr();

        drop(ca);

        // SAFETY: read_volatile through dangling pointer post-drop. The
        // allocation may have been recycled — in that case we read
        // unrelated bytes which still won't match `original`. The test
        // fails only if the original key bytes survive — which proves
        // Drop did NOT zero.
        let observed: [u8; 64] = unsafe {
            let mut buf = [0u8; 64];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = std::ptr::read_volatile(key_ptr.add(i));
            }
            buf
        };

        assert_ne!(
            observed,
            original,
            "CA cert heap buffer still holds the original PEM bytes \
             after drop — Drop did not zeroize. \
             original_prefix={:02x?}",
            &original[..8],
        );
    }

    // ─── SandboxCA / CARegistry (CA-2) ─────────────────────────────────

    #[test]
    fn sandbox_ca_generates_valid_pem_and_pubkey_hash() {
        let ca = SandboxCA::generate_for_sandbox("sb-test-001")
            .expect("per-sandbox CA generation must succeed");

        assert_eq!(ca.sandbox_id(), "sb-test-001");
        assert!(ca.ca_cert_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(!ca.ca_key_pem().is_empty());

        // pubkey_hash is 32 bytes, hex form is 64 chars and not all zeros.
        let hex = ca.pubkey_hash_hex();
        assert_eq!(hex.len(), 64, "SHA-256 hex is 64 chars");
        assert_ne!(
            hex,
            "0".repeat(64),
            "pubkey hash must not be the zero hash (real key was generated)"
        );
    }

    #[test]
    fn sandbox_ca_pubkey_hash_is_unique_per_generation() {
        // Two CAs for the same sandbox_id must still produce
        // different pubkey hashes — the keypair is fresh each time.
        let ca1 = SandboxCA::generate_for_sandbox("sb-xyz").unwrap();
        let ca2 = SandboxCA::generate_for_sandbox("sb-xyz").unwrap();
        assert_ne!(
            ca1.pubkey_hash(),
            ca2.pubkey_hash(),
            "fresh keypair per generation — hashes must differ"
        );
    }

    #[test]
    fn sandbox_ca_pubkey_hash_is_deterministic_per_instance() {
        // Same `SandboxCA` instance always returns the same hash —
        // it is computed once at generation, not on every call.
        let ca = SandboxCA::generate_for_sandbox("sb-det").unwrap();
        let h1 = ca.pubkey_hash();
        let h2 = ca.pubkey_hash();
        assert_eq!(h1, h2);
        assert_eq!(ca.pubkey_hash_hex(), hex::encode(h1));
    }

    #[test]
    fn sandbox_ca_validity_is_short() {
        let ca = SandboxCA::generate_for_sandbox("sb-life").unwrap();
        let hours = ca.expires_in_hours();
        // 8h default minus a tiny rounding/processing delta.
        assert!(
            (7..=8).contains(&hours),
            "expected ~8h validity, got {} hours",
            hours
        );
    }

    #[test]
    fn ca_registry_provision_and_lookup() {
        let registry = CARegistry::new();
        assert_eq!(registry.active_count(), 0);

        let ca_a = registry.provision("sb-A").unwrap();
        let ca_b = registry.provision("sb-B").unwrap();
        assert_eq!(registry.active_count(), 2);

        // Distinct sandboxes → distinct CAs (different pubkey hashes).
        assert_ne!(ca_a.pubkey_hash(), ca_b.pubkey_hash());

        // Lookup returns the same Arc-pointed CA.
        let looked_up = registry.lookup("sb-A").expect("present");
        assert_eq!(looked_up.pubkey_hash(), ca_a.pubkey_hash());

        // Miss returns None.
        assert!(registry.lookup("sb-nonexistent").is_none());
    }

    #[test]
    fn ca_registry_revoke_drops_entry() {
        let registry = CARegistry::new();
        let _ca = registry.provision("sb-tmp").unwrap();
        assert!(registry.lookup("sb-tmp").is_some());

        registry.revoke("sb-tmp");
        assert!(registry.lookup("sb-tmp").is_none());
        assert_eq!(registry.active_count(), 0);

        // Revoking a non-existent entry is a no-op.
        registry.revoke("sb-was-never-here");
    }

    #[test]
    fn ca_registry_provision_replaces_existing() {
        // Re-provisioning the same sandbox_id replaces the CA.
        // In-flight callers holding the old Arc are unaffected
        // (they keep their reference) but new lookups get the new one.
        let registry = CARegistry::new();
        let old = registry.provision("sb-rotate").unwrap();
        let old_hash = old.pubkey_hash();

        let new = registry.provision("sb-rotate").unwrap();
        let new_hash = new.pubkey_hash();
        assert_ne!(old_hash, new_hash, "rotation must produce a new keypair");

        // Lookup returns the new one.
        let looked_up = registry.lookup("sb-rotate").unwrap();
        assert_eq!(looked_up.pubkey_hash(), new_hash);

        // The old Arc clone we still hold is independent and still
        // points at the original key — until WE drop it.
        assert_eq!(old.pubkey_hash(), old_hash);
    }

    #[test]
    fn ca_registry_snapshot_lists_all_active_sandboxes() {
        let registry = CARegistry::new();
        registry.provision("sb-snap-1").unwrap();
        registry.provision("sb-snap-2").unwrap();
        registry.provision("sb-snap-3").unwrap();

        let mut snap = registry.snapshot();
        snap.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].0, "sb-snap-1");
        assert_eq!(snap[1].0, "sb-snap-2");
        assert_eq!(snap[2].0, "sb-snap-3");
        // Each entry has a 64-char hex pubkey hash.
        for (_, hex_hash, _) in &snap {
            assert_eq!(hex_hash.len(), 64);
        }
    }

    #[test]
    fn sandbox_ca_zeroized_on_drop() {
        // Same pattern as `ca_zeroized_on_drop` for the legacy CA:
        // capture the pointer to the cert PEM heap buffer, drop the
        // CA, read the buffer, and assert the original bytes did NOT
        // survive. Pin against any future regression where Drop is
        // skipped (e.g. `mem::forget` slipped into the lifecycle).
        let ca = SandboxCA::generate_for_sandbox("sb-zeroize-test").unwrap();
        let cert = ca.ca_cert_pem();
        assert!(cert.len() > 100);

        let mut original = [0u8; 64];
        let n = original.len().min(cert.len());
        original[..n].copy_from_slice(&cert[..n]);

        let cert_ptr: *const u8 = cert.as_ptr();
        drop(ca);

        let observed: [u8; 64] = unsafe {
            let mut buf = [0u8; 64];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = std::ptr::read_volatile(cert_ptr.add(i));
            }
            buf
        };

        assert_ne!(
            observed, original,
            "SandboxCA cert buffer survived Drop — zeroize did not run"
        );
    }
}
