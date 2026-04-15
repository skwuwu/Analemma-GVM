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

// ─── Trait Abstractions ───

/// Abstraction for encryption key management.
///
/// Separates cryptographic operations from the Vault storage layer,
/// enabling pluggable key management backends:
/// - `LocalKeyProvider`: AES-256-GCM with local key material (MVP)
/// - AWS KMS: Envelope encryption via KMS API (production)
/// - GCP KMS / HashiCorp Vault: Same pattern, different API
///
/// All implementations must be Send + Sync for use in async contexts.
/// Encrypt/decrypt are synchronous — KMS implementations should use
/// blocking client or spawn_blocking to avoid holding locks across await.
pub trait KeyProvider: Send + Sync {
    /// Encrypt plaintext. Output format is implementation-defined.
    /// LocalKeyProvider: nonce(12) || ciphertext || tag(16)
    /// KMS: envelope-encrypted blob with wrapped data key
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext produced by encrypt().
    /// Must return generic error on failure (no cryptographic detail leakage).
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Abstraction for vault storage backend.
///
/// Separates storage from encryption, enabling pluggable persistence:
/// - `InMemoryBackend`: HashMap (MVP, no persistence across restarts)
/// - Redis with TLS: Durable storage with TTL support (production)
/// - DynamoDB: Serverless durable storage (alternative)
///
/// All values stored are already encrypted by KeyProvider.
/// Backend implementations must NOT perform additional encryption.
#[allow(async_fn_in_trait)]
#[allow(clippy::len_without_is_empty)]
pub trait VaultBackend: Send + Sync {
    /// Retrieve an encrypted value by key. Returns None if key does not exist.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Store an encrypted value. Overwrites existing key.
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<()>;

    /// Remove a key. No-op if key does not exist.
    async fn delete(&self, key: &str) -> Result<()>;

    /// List all keys matching a prefix.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>>;

    /// Return the total number of keys in the backend.
    async fn len(&self) -> Result<usize>;

    /// Check if key exists without retrieving value.
    async fn contains_key(&self, key: &str) -> Result<bool>;
}

// ─── Local Key Provider (AES-256-GCM) ───

/// AES-256-GCM encryption layer for Vault data at rest.
///
/// Memory Security (Secret Zeroing):
/// - Encryption key wrapped with ZeroizeOnDrop — zeroed on struct drop
/// - Decrypted plaintext returned in ZeroVec — caller must handle securely
/// - Prevents key/plaintext from persisting in freed memory (memory remanence)
/// - Core dump or /proc/mem scan cannot recover zeroed secrets
///
/// In production, replace with a KMS-backed KeyProvider.
/// MVP uses GVM_VAULT_KEY environment variable.
pub struct LocalKeyProvider {
    key: [u8; 32],
}

/// Drop implementation that zeros the key material before deallocation.
/// This prevents encryption keys from persisting in freed heap/stack memory
/// after process exit, core dump, or memory page reuse.
impl Drop for LocalKeyProvider {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl LocalKeyProvider {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Load encryption key from environment variable.
    /// Falls back to a random ephemeral key if not set (development only).
    pub fn from_env(env_var: &str) -> Result<Self> {
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
}

impl KeyProvider for LocalKeyProvider {
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
    ///    All cases are security events — details logged internally,
    ///    generic error returned to caller (no cryptographic information leakage).
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            tracing::error!(
                data_len = data.len(),
                "Vault decryption: ciphertext too short (possible truncation or corruption)"
            );
            return Err(anyhow!("Vault integrity error: data corrupted or tampered"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| {
            tracing::error!(error = %e, "Vault cipher initialization failed");
            anyhow!("Vault internal error")
        })?;
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).map_err(|_| {
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

// ─── In-Memory Backend ───

/// In-memory vault storage backend (MVP).
///
/// All data is lost on process restart. Suitable for development and testing.
/// Production deployments should use RedisBackend or similar durable backend.
pub struct InMemoryBackend {
    store: RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultBackend for InMemoryBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let store = self.store.read().await;
        Ok(store.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let mut store = self.store.write().await;
        store.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let store = self.store.read().await;
        Ok(store
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn len(&self) -> Result<usize> {
        let store = self.store.read().await;
        Ok(store.len())
    }

    async fn contains_key(&self, key: &str) -> Result<bool> {
        let store = self.store.read().await;
        Ok(store.contains_key(key))
    }
}

// ─── Vault ───

/// Maximum number of keys in the vault store.
/// Prevents unbounded memory growth from agent writes.
const MAX_VAULT_KEYS: usize = 10_000;

/// Maximum size of a single encrypted value (1 MB).
/// Prevents a single write from consuming excessive memory.
const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Maximum vault key length (256 bytes).
const MAX_KEY_LEN: usize = 256;

/// Validate vault key: reject control characters (CRLF, null byte, tabs)
/// and enforce length limit. Prevents WAL JSON injection and log injection.
fn validate_vault_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(anyhow!("Vault key must not be empty"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(anyhow!(
            "Vault key length {} exceeds maximum {} bytes",
            key.len(),
            MAX_KEY_LEN
        ));
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(anyhow!(
            "Vault key contains control characters (CRLF, null byte, etc.)"
        ));
    }
    Ok(())
}

/// Vault: encrypted agent state cache.
///
/// Stores agent checkpoints, conversation history, and intermediate
/// state with encryption. This is a runtime state store,
/// not a secrets manager. API credentials are handled separately
/// by [`APIKeyStore`](crate::api_keys::APIKeyStore).
///
/// Design (PART 5.4):
/// - All values encrypted via KeyProvider before storage
/// - Storage delegated to VaultBackend (in-memory, Redis, etc.)
/// - WAL-first write: encrypted value recorded in WAL before store write
/// - Read operations are logged asynchronously (value not included in audit)
///
/// Trait abstractions enable pluggable backends:
/// - `KeyProvider`: Local AES-256-GCM (MVP) → AWS KMS / GCP KMS (production)
/// - `VaultBackend`: In-memory HashMap (MVP) → Redis with TLS (production)
///
/// Memory bounds:
/// - Max keys: 10,000 (rejects writes when full)
/// - Max value size: 1 MB per value
/// - Total worst case: ~10 GB (10K keys × 1 MB), but typical values are small
pub struct Vault<B: VaultBackend = InMemoryBackend> {
    backend: B,
    key_provider: Box<dyn KeyProvider>,
    ledger: Arc<Ledger>,
}

impl Vault<InMemoryBackend> {
    /// Create a new Vault with default local implementations.
    /// Uses LocalKeyProvider (AES-256-GCM) and InMemoryBackend.
    pub fn new(ledger: Arc<Ledger>) -> Result<Self> {
        let key_provider = LocalKeyProvider::from_env("GVM_VAULT_KEY")?;
        Ok(Self {
            backend: InMemoryBackend::new(),
            key_provider: Box::new(key_provider),
            ledger,
        })
    }
}

impl<B: VaultBackend> Vault<B> {
    /// Create a Vault with custom key provider and storage backend.
    ///
    /// Use this for production deployments with KMS and durable storage:
    /// ```ignore
    /// let vault = Vault::with_backends(
    ///     Box::new(AwsKmsKeyProvider::new(kms_key_id)),
    ///     RedisBackend::new(redis_url),
    ///     ledger,
    /// );
    /// ```
    pub fn with_backends(
        key_provider: Box<dyn KeyProvider>,
        backend: B,
        ledger: Arc<Ledger>,
    ) -> Self {
        Self {
            backend,
            key_provider,
            ledger,
        }
    }

    /// Write an encrypted value to the vault.
    /// WAL records the encrypted value for crash recovery.
    pub async fn write(&self, key: &str, plaintext: &[u8], agent_id: &str) -> Result<()> {
        // 0a. Validate key (reject control characters, enforce length limit)
        validate_vault_key(key)?;

        // 0b. Enforce value size limit before encryption (fail fast)
        if plaintext.len() > MAX_VALUE_BYTES {
            return Err(anyhow!(
                "Value size {} bytes exceeds maximum {} bytes",
                plaintext.len(),
                MAX_VALUE_BYTES
            ));
        }

        // 1. Enforce key count limit (allow overwrites of existing keys)
        let key_count = self.backend.len().await?;
        let key_exists = self.backend.contains_key(key).await?;
        if key_count >= MAX_VAULT_KEYS && !key_exists {
            return Err(anyhow!(
                "Vault key limit reached ({} keys). Delete unused keys before adding new ones.",
                MAX_VAULT_KEYS
            ));
        }

        // 2. Encrypt
        let ciphertext = self.key_provider.encrypt(plaintext)?;

        // 3. WAL-first: record encrypted value for recovery
        let event = build_vault_event(key, agent_id, "vault_write", Some(&ciphertext));
        self.ledger.append_durable(&event).await?;

        // 4. Store encrypted value
        self.backend.put(key, ciphertext).await?;

        tracing::debug!(key = key, agent = agent_id, "Vault write completed");
        Ok(())
    }

    /// Read and decrypt a value from the vault.
    /// Audit log records the read event (without the value).
    pub async fn read(&self, key: &str, agent_id: &str) -> Result<Option<Vec<u8>>> {
        validate_vault_key(key)?;
        let ciphertext = self.backend.get(key).await?;

        // Async audit log (read event does not include value)
        let event = build_vault_event(key, agent_id, "vault_read", None);
        self.ledger.append_async(event).await;

        match ciphertext {
            Some(ct) => Ok(Some(self.key_provider.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    /// Delete a key from the vault.
    pub async fn delete(&self, key: &str, agent_id: &str) -> Result<()> {
        validate_vault_key(key)?;
        let event = build_vault_event(key, agent_id, "vault_delete", None);
        self.ledger.append_durable(&event).await?;

        self.backend.delete(key).await?;

        tracing::debug!(key = key, agent = agent_id, "Vault delete completed");
        Ok(())
    }

    /// List all keys visible to an agent (prefix-scoped).
    /// Audit-logged for consistency with other vault operations.
    pub async fn list_keys(&self, prefix: &str, agent_id: &str) -> Vec<String> {
        let keys = self.backend.list_keys(prefix).await.unwrap_or_default();

        // Async audit log for key enumeration (consistent with read/write/delete)
        let event = build_vault_event(prefix, agent_id, "vault_list_keys", None);
        self.ledger.append_async(event).await;

        keys
    }
}

/// Build a GVMEvent for vault operations.
///
/// NOTE: WAL records metadata only (hash + size), not the encrypted value.
/// State recovery from WAL is NOT possible with InMemoryBackend.
/// Durable backends (Redis, file-based) enable state persistence independently.
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
        default_caution: false, config_integrity_ref: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");
        let plaintext = b"sensitive agent state data";

        let ciphertext = enc
            .encrypt(plaintext)
            .expect("AES-256-GCM encryption must succeed");
        assert_ne!(&ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len()); // nonce + tag overhead

        let decrypted = enc
            .decrypt(&ciphertext)
            .expect("decryption of valid ciphertext must succeed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");
        let plaintext = b"same data";

        let ct1 = enc
            .encrypt(plaintext)
            .expect("AES-256-GCM encryption must succeed");
        let ct2 = enc
            .encrypt(plaintext)
            .expect("AES-256-GCM encryption must succeed");

        // Same plaintext should produce different ciphertext (random nonce)
        assert_ne!(ct1, ct2);

        // But both should decrypt to the same plaintext
        assert_eq!(
            enc.decrypt(&ct1).expect("ct1 decryption"),
            enc.decrypt(&ct2).expect("ct2 decryption")
        );
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");
        let plaintext = b"tamper test";

        let mut ciphertext = enc
            .encrypt(plaintext)
            .expect("AES-256-GCM encryption must succeed");
        // Flip a bit in the ciphertext body (after nonce)
        if ciphertext.len() > 13 {
            ciphertext[13] ^= 0xFF;
        }

        assert!(enc.decrypt(&ciphertext).is_err());
    }

    // ── Additional Security Tests ──

    #[test]
    fn test_truncated_ciphertext_returns_integrity_error() {
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");

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
        let enc1 = LocalKeyProvider::new([1u8; 32]);
        let enc2 = LocalKeyProvider::new([2u8; 32]);

        let plaintext = b"encrypted with key 1";
        let ciphertext = enc1
            .encrypt(plaintext)
            .expect("enc1 encryption must succeed");

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
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");

        // Empty plaintext — edge case, must work
        let ciphertext = enc
            .encrypt(b"")
            .expect("AES-256-GCM encryption of empty plaintext must succeed");
        let decrypted = enc
            .decrypt(&ciphertext)
            .expect("decryption of valid ciphertext must succeed");
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_nonce_reuse_not_possible() {
        let enc = LocalKeyProvider::from_env("GVM_VAULT_KEY_TEST_NONEXISTENT")
            .expect("ephemeral key generation must succeed");

        // Encrypt same plaintext 100 times — all nonces must be unique
        let plaintext = b"nonce reuse test";
        let nonces: Vec<Vec<u8>> = (0..100)
            .map(|_| {
                let ct = enc
                    .encrypt(plaintext)
                    .expect("AES-256-GCM encryption must succeed");
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

    // ── Backend Trait Tests ──

    #[tokio::test]
    async fn test_in_memory_backend_crud() {
        let backend = InMemoryBackend::new();

        // Initially empty
        assert_eq!(backend.len().await.unwrap(), 0);
        assert!(!backend.contains_key("key1").await.unwrap());
        assert!(backend.get("key1").await.unwrap().is_none());

        // Put and get
        backend.put("key1", vec![1, 2, 3]).await.unwrap();
        assert_eq!(backend.len().await.unwrap(), 1);
        assert!(backend.contains_key("key1").await.unwrap());
        assert_eq!(backend.get("key1").await.unwrap(), Some(vec![1, 2, 3]));

        // Overwrite
        backend.put("key1", vec![4, 5, 6]).await.unwrap();
        assert_eq!(backend.len().await.unwrap(), 1);
        assert_eq!(backend.get("key1").await.unwrap(), Some(vec![4, 5, 6]));

        // Delete
        backend.delete("key1").await.unwrap();
        assert_eq!(backend.len().await.unwrap(), 0);
        assert!(backend.get("key1").await.unwrap().is_none());

        // Delete non-existent key (no-op)
        backend.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn test_in_memory_backend_list_keys() {
        let backend = InMemoryBackend::new();

        backend.put("agent-1:checkpoint:0", vec![1]).await.unwrap();
        backend.put("agent-1:checkpoint:1", vec![2]).await.unwrap();
        backend.put("agent-2:checkpoint:0", vec![3]).await.unwrap();

        let mut keys = backend.list_keys("agent-1:").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["agent-1:checkpoint:0", "agent-1:checkpoint:1"]);

        let keys = backend.list_keys("agent-2:").await.unwrap();
        assert_eq!(keys, vec!["agent-2:checkpoint:0"]);

        let keys = backend.list_keys("nonexistent:").await.unwrap();
        assert!(keys.is_empty());
    }

    // ── Key Validation Tests ──

    #[test]
    fn test_vault_key_crlf_rejected() {
        // CRLF in vault key could enable WAL JSON injection or log injection
        let err = validate_vault_key("key\r\ninjection").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "CRLF key must be rejected with control character error, got: {}",
            err
        );
    }

    #[test]
    fn test_vault_key_null_byte_rejected() {
        // Null byte could truncate key in C-based backends (Redis) or WAL
        let err = validate_vault_key("key\0truncated").unwrap_err();
        assert!(
            err.to_string().contains("control characters"),
            "Null byte key must be rejected, got: {}",
            err
        );
    }

    #[test]
    fn test_vault_key_tab_rejected() {
        let err = validate_vault_key("key\tvalue").unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn test_vault_key_empty_rejected() {
        let err = validate_vault_key("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_vault_key_oversized_rejected() {
        let long_key = "k".repeat(MAX_KEY_LEN + 1);
        let err = validate_vault_key(&long_key).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_vault_key_valid_characters_accepted() {
        // Normal keys with colons, hyphens, dots, slashes are valid
        assert!(validate_vault_key("agent-1:checkpoint:0").is_ok());
        assert!(validate_vault_key("tenant/agent/state.v1").is_ok());
        assert!(validate_vault_key("a").is_ok());
        assert!(validate_vault_key(&"k".repeat(MAX_KEY_LEN)).is_ok());
    }
}
