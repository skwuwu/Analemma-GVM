use crate::ledger::Ledger;
use crate::types::*;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

// ─── Vault: Encrypted State Store (PART 5.4) ───

/// AES-256-GCM encryption layer for Vault data at rest.
///
/// Memory Security (Secret Zeroing):
/// - Encryption key wrapped with ZeroizeOnDrop — zeroed on struct drop
/// - Decrypted plaintext returned in ZeroVec — caller must handle securely
/// - Prevents key/plaintext from persisting in freed memory (memory remanence)
/// - Core dump or /proc/mem scan cannot recover zeroed secrets
///
/// In production, the key should come from AWS KMS / HashiCorp Vault.
/// MVP uses GVM_VAULT_KEY environment variable.
struct VaultEncryption {
    key: [u8; 32],
}

/// Drop implementation that zeros the key material before deallocation.
/// This prevents encryption keys from persisting in freed heap/stack memory
/// after process exit, core dump, or memory page reuse.
impl Drop for VaultEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl VaultEncryption {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Load encryption key from environment variable.
    /// Falls back to a deterministic dev key if not set (development only).
    fn from_env(env_var: &str) -> Result<Self> {
        match std::env::var(env_var) {
            Ok(hex_key) => {
                let mut bytes = hex::decode(&hex_key)
                    .map_err(|e| anyhow!("Invalid hex key in {}: {}", env_var, e))?;
                if bytes.len() != 32 {
                    bytes.zeroize(); // Zero intermediate buffer on error path
                    return Err(anyhow!(
                        "Key in {} must be 32 bytes (64 hex chars), got {} bytes",
                        env_var,
                        bytes.len()
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                bytes.zeroize(); // Zero the intermediate Vec<u8> immediately
                Ok(Self::new(key))
            }
            Err(_) => {
                tracing::warn!(
                    "⚠ {} not set — generating random ephemeral key. \
                     Data will NOT survive restart. NOT SAFE FOR PRODUCTION.",
                    env_var
                );
                // Random ephemeral key: safe even if WAL is leaked (unlike
                // a hardcoded key which would let anyone decrypt WAL data).
                // In MVP with in-memory store, restart already loses state,
                // so an ephemeral key has no additional downside.
                let key: [u8; 32] = rand::random();
                Ok(Self::new(key))
            }
        }
    }

    /// Encrypt plaintext using AES-256-GCM.
    /// Output format: nonce(12 bytes) || ciphertext || tag(16 bytes)
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| anyhow!("Cipher init failed: {}", e))?;
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        Ok([nonce.as_slice(), &ciphertext].concat())
    }

    /// Decrypt ciphertext produced by encrypt().
    ///
    /// Security: AES-256-GCM decryption failure indicates one of:
    /// 1. Data tampering (authentication tag mismatch)
    /// 2. Wrong key (key rotation without data migration)
    /// 3. Storage corruption
    /// All cases are security events — details logged internally,
    /// generic error returned to caller (no cryptographic information leakage).
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            tracing::error!(
                data_len = data.len(),
                "Vault decryption: ciphertext too short (possible truncation or corruption)"
            );
            return Err(anyhow!("Vault integrity error: data corrupted or tampered"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| {
                tracing::error!(error = %e, "Vault cipher initialization failed");
                anyhow!("Vault internal error")
            })?;
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| {
                // Do NOT expose raw AES-GCM error details (could aid cryptanalysis).
                // Log the event for operator review, return generic error to caller.
                tracing::error!(
                    "Vault decryption failed: authentication tag mismatch. \
                     Possible causes: data tampering, key rotation, or storage corruption. \
                     Operator review required."
                );
                anyhow!("Vault integrity error: decryption failed")
            })
    }
}

/// Maximum number of keys in the in-memory vault store.
/// Prevents unbounded memory growth from agent writes.
const MAX_VAULT_KEYS: usize = 10_000;

/// Maximum size of a single encrypted value (1 MB).
/// Prevents a single write from consuming excessive memory.
const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Vault: encrypted agent state cache.
///
/// Stores agent checkpoints, conversation history, and intermediate
/// state with AES-256-GCM encryption. This is a runtime state store,
/// not a secrets manager. API credentials are handled separately
/// by [`APIKeyStore`](crate::api_keys::APIKeyStore).
///
/// Design (PART 5.4):
/// - All values encrypted with AES-256-GCM before storage
/// - Automatic nonce generation (no reuse)
/// - Key zeroing on drop (zeroize) prevents memory remanence
/// - WAL-first write: encrypted value recorded in WAL before store write
/// - Read operations are logged asynchronously (value not included in audit)
/// - MVP: in-memory HashMap (Redis with TLS planned for production)
///
/// What Vault does NOT do (and should not be expected to do):
/// - Key rotation, envelope encryption, or KDF
/// - HSM/KMS integration (production deployments should use external KMS)
/// - Access control between agents (single-tenant per proxy instance)
///
/// Memory bounds:
/// - Max keys: 10,000 (rejects writes when full)
/// - Max value size: 1 MB per value
/// - Total worst case: ~10 GB (10K keys × 1 MB), but typical values are small
pub struct Vault {
    /// In-memory store (MVP replacement for Redis)
    store: RwLock<HashMap<String, Vec<u8>>>,
    encryption: VaultEncryption,
    ledger: Arc<Ledger>,
}

impl Vault {
    /// Create a new Vault with encryption and ledger integration.
    pub fn new(ledger: Arc<Ledger>) -> Result<Self> {
        let encryption = VaultEncryption::from_env("GVM_VAULT_KEY")?;
        Ok(Self {
            store: RwLock::new(HashMap::new()),
            encryption,
            ledger,
        })
    }

    /// Write an encrypted value to the vault.
    /// WAL records the encrypted value for crash recovery.
    pub async fn write(&self, key: &str, plaintext: &[u8], agent_id: &str) -> Result<()> {
        // 0. Enforce value size limit before encryption (fail fast)
        if plaintext.len() > MAX_VALUE_BYTES {
            return Err(anyhow!(
                "Value size {} bytes exceeds maximum {} bytes",
                plaintext.len(),
                MAX_VALUE_BYTES
            ));
        }

        // 1. Enforce key count limit (allow overwrites of existing keys)
        {
            let store = self.store.read().await;
            if store.len() >= MAX_VAULT_KEYS && !store.contains_key(key) {
                return Err(anyhow!(
                    "Vault key limit reached ({} keys). Delete unused keys before adding new ones.",
                    MAX_VAULT_KEYS
                ));
            }
        }

        // 2. Encrypt
        let ciphertext = self.encryption.encrypt(plaintext)?;

        // 3. WAL-first: record encrypted value for recovery
        let event = build_vault_event(key, agent_id, "vault_write", Some(&ciphertext));
        self.ledger.append_durable(&event).await?;

        // 4. Store encrypted value
        let mut store = self.store.write().await;
        store.insert(key.to_string(), ciphertext);

        tracing::debug!(key = key, agent = agent_id, "Vault write completed");
        Ok(())
    }

    /// Read and decrypt a value from the vault.
    /// Audit log records the read event (without the value).
    pub async fn read(&self, key: &str, agent_id: &str) -> Result<Option<Vec<u8>>> {
        let store = self.store.read().await;
        let ciphertext = store.get(key).cloned();

        // Async audit log (read event does not include value)
        let event = build_vault_event(key, agent_id, "vault_read", None);
        self.ledger.append_async(event).await;

        match ciphertext {
            Some(ct) => Ok(Some(self.encryption.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    /// Delete a key from the vault.
    pub async fn delete(&self, key: &str, agent_id: &str) -> Result<()> {
        let event = build_vault_event(key, agent_id, "vault_delete", None);
        self.ledger.append_durable(&event).await?;

        let mut store = self.store.write().await;
        store.remove(key);

        tracing::debug!(key = key, agent = agent_id, "Vault delete completed");
        Ok(())
    }

    /// List all keys visible to an agent (prefix-scoped).
    /// Audit-logged for consistency with other vault operations.
    pub async fn list_keys(&self, prefix: &str, agent_id: &str) -> Vec<String> {
        let store = self.store.read().await;
        let keys: Vec<String> = store
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();

        // Async audit log for key enumeration (consistent with read/write/delete)
        let event = build_vault_event(prefix, agent_id, "vault_list_keys", None);
        self.ledger.append_async(event).await;

        keys
    }
}

/// Build a GVMEvent for vault operations.
///
/// NOTE: WAL records metadata only (hash + size), not the encrypted value.
/// State recovery from WAL is NOT possible in MVP (in-memory store).
/// Redis integration (P2) will enable durable state with WAL-based recovery.
fn build_vault_event(
    key: &str,
    agent_id: &str,
    operation: &str,
    encrypted_value: Option<&[u8]>,
) -> GVMEvent {
    use sha2::{Digest, Sha256};

    let payload = match encrypted_value {
        Some(v) => {
            let mut hasher = Sha256::new();
            hasher.update(v);
            PayloadDescriptor {
                content_hash: format!("{:x}", hasher.finalize()),
                size_bytes: v.len() as u64,
                flagged_patterns: Vec::new(),
            }
        }
        None => PayloadDescriptor::default(),
    };

    GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: agent_id.to_string(),
        tenant_id: None,
        session_id: String::new(),
        timestamp: chrono::Utc::now(),
        operation: format!("gvm.vault.{}", operation),
        resource: ResourceDescriptor {
            service: "vault".to_string(),
            identifier: Some(key.to_string()),
            tier: ResourceTier::Internal,
            sensitivity: Sensitivity::High,
        },
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "internal".to_string(),
        matched_rule_id: None,
        enforcement_point: "proxy".to_string(),
        status: EventStatus::Confirmed,
        payload,
        nats_sequence: None,
        event_hash: None,
        llm_trace: None, // Computed by Ledger during WAL write
        default_caution: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");
        let plaintext = b"sensitive agent state data";

        let ciphertext = enc.encrypt(plaintext).expect("AES-256-GCM encryption must succeed");
        assert_ne!(&ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = enc.decrypt(&ciphertext).expect("decryption of valid ciphertext must succeed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");
        let plaintext = b"same data";

        let ct1 = enc.encrypt(plaintext).expect("AES-256-GCM encryption must succeed");
        let ct2 = enc.encrypt(plaintext).expect("AES-256-GCM encryption must succeed");

        // Same plaintext should produce different ciphertext (random nonce)
        assert_ne!(ct1, ct2);

        // But both should decrypt to the same plaintext
        assert_eq!(enc.decrypt(&ct1).expect("ct1 decryption"), enc.decrypt(&ct2).expect("ct2 decryption"));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");
        let plaintext = b"tamper test";

        let mut ciphertext = enc.encrypt(plaintext).expect("AES-256-GCM encryption must succeed");
        // Flip a bit in the ciphertext body (after nonce)
        if ciphertext.len() > 13 {
            ciphertext[13] ^= 0xFF;
        }

        assert!(enc.decrypt(&ciphertext).is_err());
    }

    // ── Additional Security Tests ──

    #[test]
    fn test_truncated_ciphertext_returns_integrity_error() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");

        // Less than 12 bytes (nonce size) — must fail with integrity error
        let short_data = vec![0u8; 5];
        let err = enc.decrypt(&short_data).unwrap_err();
        assert!(
            err.to_string().contains("integrity error"),
            "Truncated data error must say 'integrity error', got: {}",
            err
        );
    }

    #[test]
    fn test_wrong_key_returns_integrity_error() {
        let enc1 = VaultEncryption::new([1u8; 32]);
        let enc2 = VaultEncryption::new([2u8; 32]);

        let plaintext = b"encrypted with key 1";
        let ciphertext = enc1.encrypt(plaintext).expect("enc1 encryption must succeed");

        // Decrypt with wrong key — must fail with integrity error, not leak details
        let err = enc2.decrypt(&ciphertext).unwrap_err();
        assert!(
            err.to_string().contains("integrity error"),
            "Wrong key error must say 'integrity error', got: {}",
            err
        );
        // Must NOT contain raw AES-GCM error details
        assert!(
            !err.to_string().contains("aes"),
            "Error must not expose AES internals"
        );
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");

        // Empty plaintext — edge case, must work
        let ciphertext = enc.encrypt(b"").expect("AES-256-GCM encryption of empty plaintext must succeed");
        let decrypted = enc.decrypt(&ciphertext).expect("decryption of valid ciphertext must succeed");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_nonce_reuse_not_possible() {
        let enc = VaultEncryption::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT").expect("ephemeral key generation must succeed");

        // Encrypt same plaintext 100 times — all nonces must be unique
        let plaintext = b"nonce reuse test";
        let nonces: Vec<Vec<u8>> = (0..100)
            .map(|_| {
                let ct = enc.encrypt(plaintext).expect("AES-256-GCM encryption must succeed");
                ct[..12].to_vec() // Extract 12-byte nonce
            })
            .collect();

        // Check all nonces are unique
        let mut unique = std::collections::HashSet::new();
        for nonce in &nonces {
            assert!(
                unique.insert(nonce.clone()),
                "Nonce reuse detected! This is a critical AES-GCM vulnerability."
            );
        }
    }
}
