# Part 5: Vault (Encrypted Agent State Cache)

**Source**: `src/vault.rs` | **Config**: `GVM_VAULT_KEY` environment variable

---

## 5.1 Overview

GVM Vault is an encrypted key-value store for agent runtime state (checkpoints, conversation history, intermediate results). It is **NOT** a secrets manager — API credentials are handled separately by `APIKeyStore` (`src/api_keys.rs`).

**What Vault does:**
- AES-256-GCM encryption at rest
- Automatic nonce generation (no reuse)
- Key zeroing on drop (`zeroize`)
- WAL-first write for crash recovery metadata

**What Vault does NOT do:**
- Key rotation
- Envelope encryption
- KDF (key derivation function) — key is used directly from env var
- HSM/KMS integration
- Access control between agents

**Production deployments should:**
- Use KMS (AWS KMS, GCP KMS) for master key management
- Use Redis with TLS for persistent backend (planned)
- Restrict Vault API to localhost or mTLS-authenticated agents

**Design principle**: Agents never handle raw encryption. The proxy encrypts/decrypts transparently. Key material is zeroed on drop to prevent memory remanence attacks.

---

## 5.2 Encryption Layer (AES-256-GCM)

### Key Management

```rust
struct VaultEncryption {
    key: [u8; 32],  // AES-256 key
}
```

**Key source** (priority order):
1. `GVM_VAULT_KEY` environment variable (64 hex chars → 32 bytes)
2. Deterministic dev key (development only, logged as warning)
3. Production: AWS KMS / HashiCorp Vault (planned)

### Encrypt

```
Input:  plaintext
Output: nonce(12 bytes) || ciphertext || tag(16 bytes)
```

```rust
fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; 12] = rand::random();  // Random nonce per encryption
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}
```

**Nonce generation**: `rand::random()` generates a cryptographically random 12-byte nonce for each encryption. With 96-bit nonces, the birthday collision probability stays below 2^-32 for up to 2^32 (~4 billion) encryptions under the same key.

### Decrypt

```rust
fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("Vault integrity error: data corrupted or tampered"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Vault integrity error: decryption failed"))
}
```

**Error sanitization**: AES-GCM decryption failures return a generic "Vault integrity error" message. Raw cryptographic error details are logged internally for operator review but never exposed to the caller. This prevents:
- Padding oracle attacks
- Ciphertext malleability probing
- Key/algorithm information leakage

---

## 5.3 Memory Security (Secret Zeroing)

### Drop Implementation

```rust
impl Drop for VaultEncryption {
    fn drop(&mut self) {
        self.key.zeroize();  // Zero 32 bytes of key material
    }
}
```

The `zeroize` crate guarantees that the compiler will not optimize away the zeroing operation (unlike `memset` which can be eliminated by dead-store elimination). This ensures:

- Key material does not persist in freed memory after `VaultEncryption` is dropped
- Core dumps do not contain encryption keys
- Memory page reuse by other processes cannot recover key material

### Intermediate Buffer Zeroing

```rust
fn from_env(env_var: &str) -> Result<Self> {
    let mut bytes = hex::decode(&hex_key)?;
    if bytes.len() != 32 {
        bytes.zeroize(); // Zero on error path
        return Err(...);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    bytes.zeroize(); // Zero intermediate Vec<u8> immediately
    Ok(Self::new(key))
}
```

The intermediate `Vec<u8>` from hex decoding is zeroed on **all code paths** (success and error), preventing key material from lingering in the heap allocator's free list.

---

## 5.4 Vault Operations

### Write (WAL-First)

```
1. Encrypt plaintext → ciphertext
2. WAL append (encrypted value, fsync)  ← Fail-Close: reject on WAL failure
3. Store in HashMap
```

The WAL records the **encrypted** value, not plaintext. Even if the WAL file is compromised, stored values remain encrypted.

### Read (Async Audit)

```
1. Read ciphertext from HashMap
2. Async audit log (key name only, no value)  ← IC-1, loss tolerated
3. Decrypt ciphertext → return plaintext
```

Read audit events do **not** include the decrypted value — only the key name and agent identity. This prevents audit log compromise from leaking secrets.

### Delete (WAL-First)

```
1. WAL append (delete event, fsync)
2. Remove from HashMap
```

---

## 5.5 Concurrent Access

The Vault uses `tokio::sync::RwLock<HashMap>`:

- **Reads**: Multiple concurrent reads allowed (no blocking)
- **Writes**: Exclusive lock (serialized)
- **Concurrent writes to same key**: Last-writer-wins. Both writes succeed in WAL, HashMap takes the final value.

**TOCTOU note**: Under concurrent writes to the same key, both are recorded in the WAL (full audit trail), but the in-memory HashMap reflects only the last write. This is acceptable for the MVP; production would use Redis with atomic operations.

---

## 5.6 Test Coverage

### Unit Tests (src/vault.rs)

| Test | Assertion |
|------|-----------|
| `test_encrypt_decrypt_roundtrip` | Encrypt → decrypt returns original plaintext |
| `test_different_nonces_produce_different_ciphertext` | Same plaintext → different ciphertext (random nonce) |
| `test_tampered_ciphertext_fails` | Bit-flip in ciphertext → decryption fails |
| `test_truncated_ciphertext_returns_integrity_error` | < 12 bytes → "integrity error" message |
| `test_wrong_key_returns_integrity_error` | Wrong key → "integrity error", no AES internals leaked |
| `test_empty_plaintext_roundtrip` | Empty string encrypts/decrypts correctly |
| `test_nonce_reuse_not_possible` | 100 encryptions → 100 unique nonces |

### Integration Tests (tests/hostile.rs)

| Test | Assertion |
|------|-----------|
| `vault_concurrent_writes_to_same_key` | 50 concurrent writes → no deadlock, value exists |
| `vault_key_is_zeroed_on_drop` | VaultEncryption drop completes without crash, zeroize contract verified |

---

## 5.7 Security Implications

| Threat | Mitigation | Verification |
|--------|-----------|--------------|
| Key in RAM after drop | `zeroize` crate, `Drop` impl zeros `[u8; 32]` | `vault_key_is_zeroed_on_drop` |
| Nonce reuse | `rand::random()` per encrypt (96-bit random) | `test_nonce_reuse_not_possible` |
| Ciphertext tampering | AES-256-GCM authentication tag detects modification | `test_tampered_ciphertext_fails` |
| Error information leak | Generic "integrity error" message, details logged internally | `test_wrong_key_returns_integrity_error` |
| Intermediate key exposure | `bytes.zeroize()` on all paths (success + error) | Code review |
| WAL contains secrets | WAL stores encrypted ciphertext, not plaintext | By design |
| Audit log leaks values | Read audit events record key name only, not value | By design |

---

[← Part 4: WAL-First Ledger](04-ledger.md) | [Part 6: Proxy Pipeline →](06-proxy.md)
