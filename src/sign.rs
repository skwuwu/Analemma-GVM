//! Phase 6 — Anchor signing.
//!
//! `AnchorSigner` is the trait every anchor-attestation backend
//! implements. The ledger's batch task calls `sign(anchor_hash)` after
//! `GvmStateAnchor::seal()` and before serialization, attaching the
//! result to `anchor.signature`.
//!
//! Three concrete implementations:
//!   - `NoopSigner` — leaves `signature: None`. The default; preserves
//!     pre-Phase-6 behavior for operators who do not run a key.
//!   - `SelfSignedSigner` — local Ed25519 keypair. Cheap (~50µs/sign)
//!     and proves "GVM produced this anchor", but does NOT defeat
//!     clock rewind on its own (the same key signs whatever timestamp
//!     the producer chose).
//!   - Future: HSM and TSA variants slot in behind the same trait.
//!
//! Verification is intentionally separate (`verify_anchor_signature`)
//! so an external auditor can attach a `VerifyingKey` from a registry
//! and check arbitrary anchors without ever holding the signing key.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gvm_types::AnchorSignature;
use rand::rngs::OsRng;

/// Trait for anchor-attestation backends. Implementors are expected to
/// be cheap to clone (typically wrap an `Arc`) so the ledger can hold
/// one signer for the lifetime of the proxy.
pub trait AnchorSigner: Send + Sync {
    /// Sign the 32-byte anchor hash. Returning `None` is allowed and
    /// means "no attestation"; the anchor is still durable and chained.
    fn sign(&self, anchor_hash: &[u8; 32]) -> Option<AnchorSignature>;
}

/// Default signer — leaves `anchor.signature = None`. Preserves
/// pre-Phase-6 behavior for operators who do not run a key.
#[derive(Clone, Default)]
pub struct NoopSigner;

impl AnchorSigner for NoopSigner {
    fn sign(&self, _anchor_hash: &[u8; 32]) -> Option<AnchorSignature> {
        None
    }
}

/// Local Ed25519 self-signer. The key lives in process memory — fine
/// for "produced by GVM" proofs, but `Tsa` (RFC 3161) is the only
/// variant that defeats clock rewind because no in-process key can
/// attest to wall time.
#[derive(Clone)]
pub struct SelfSignedSigner {
    inner: std::sync::Arc<SelfSignedInner>,
}

struct SelfSignedInner {
    key_id: String,
    signing_key: SigningKey,
}

impl SelfSignedSigner {
    /// Generate a fresh keypair via the OS CSPRNG. The `key_id` is an
    /// operator-assigned label baked into every produced signature so a
    /// verifier knows which `VerifyingKey` from a registry to use.
    pub fn generate(key_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            inner: std::sync::Arc::new(SelfSignedInner {
                key_id: key_id.into(),
                signing_key,
            }),
        }
    }

    /// Construct from an existing 32-byte secret seed. Used by tests
    /// that need a deterministic key, and by future operator config
    /// that loads a key from an encrypted secrets file.
    pub fn from_secret(key_id: impl Into<String>, secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        Self {
            inner: std::sync::Arc::new(SelfSignedInner {
                key_id: key_id.into(),
                signing_key,
            }),
        }
    }

    /// Public key for this signer. An auditor pairs it with `key_id`
    /// in a registry to verify anchors.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.signing_key.verifying_key()
    }

    /// Operator-assigned label.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }
}

impl AnchorSigner for SelfSignedSigner {
    fn sign(&self, anchor_hash: &[u8; 32]) -> Option<AnchorSignature> {
        let sig: Signature = self.inner.signing_key.sign(anchor_hash);
        Some(AnchorSignature::SelfSigned {
            key_id: self.inner.key_id.clone(),
            signature: sig.to_bytes().to_vec(),
        })
    }
}

/// Verify an anchor's signature. Caller supplies the `VerifyingKey`
/// they associate with the `key_id` carried in the signature.
///
/// Returns `Ok(())` when the signature is valid for `anchor_hash`,
/// `Err` with a generic reason otherwise. Variants other than
/// `SelfSigned` are reported as unsupported here — HSM/TSA verifiers
/// live in their respective modules.
pub fn verify_anchor_signature(
    anchor_hash: &[u8; 32],
    signature: &AnchorSignature,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    match signature {
        AnchorSignature::SelfSigned { signature, .. } => {
            let bytes: &[u8; 64] = signature
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("self-signed signature must be 64 bytes"))?;
            let sig = Signature::from_bytes(bytes);
            verifying_key
                .verify(anchor_hash, &sig)
                .map_err(|_| anyhow!("self-signed signature verification failed"))
        }
        AnchorSignature::Hsm { .. } => Err(anyhow!("HSM signature verification not implemented")),
        AnchorSignature::Tsa { .. } => Err(anyhow!("TSA signature verification not implemented")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_signer_returns_none() {
        let signer = NoopSigner;
        let hash = [42u8; 32];
        assert!(signer.sign(&hash).is_none());
    }

    #[test]
    fn self_signed_round_trip_verifies() {
        let signer = SelfSignedSigner::generate("test-key");
        let hash = [7u8; 32];
        let sig = signer.sign(&hash).expect("signer must produce signature");
        match &sig {
            AnchorSignature::SelfSigned { key_id, signature } => {
                assert_eq!(key_id, "test-key");
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("expected SelfSigned variant"),
        }
        verify_anchor_signature(&hash, &sig, &signer.verifying_key()).expect("must verify");
    }

    #[test]
    fn signature_over_different_hash_fails_verify() {
        let signer = SelfSignedSigner::generate("test-key");
        let hash_a = [1u8; 32];
        let hash_b = [2u8; 32];
        let sig = signer.sign(&hash_a).expect("sig");
        assert!(
            verify_anchor_signature(&hash_b, &sig, &signer.verifying_key()).is_err(),
            "signature over hash_a must NOT verify against hash_b"
        );
    }

    #[test]
    fn signature_with_wrong_key_fails_verify() {
        let signer_a = SelfSignedSigner::generate("a");
        let signer_b = SelfSignedSigner::generate("b");
        let hash = [9u8; 32];
        let sig = signer_a.sign(&hash).expect("sig");
        assert!(
            verify_anchor_signature(&hash, &sig, &signer_b.verifying_key()).is_err(),
            "signature signed by key A must NOT verify under key B"
        );
    }

    #[test]
    fn from_secret_is_deterministic() {
        let secret = [3u8; 32];
        let signer1 = SelfSignedSigner::from_secret("k", secret);
        let signer2 = SelfSignedSigner::from_secret("k", secret);
        assert_eq!(
            signer1.verifying_key().to_bytes(),
            signer2.verifying_key().to_bytes(),
            "same secret must produce same public key"
        );
    }
}
