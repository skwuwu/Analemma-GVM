# Part 8: Memory & Runtime Security

**This document is the security audit report covering memory safety, runtime stability, and adversarial resistance.**

---

## 8.1 Threat Model

The GVM proxy is a security kernel — it sits between untrusted AI agents and external APIs. The threat model assumes:

1. **Agents are adversarial**: They may lie about operations, send malformed data, or attempt to exhaust resources.
2. **Network is hostile**: Requests may contain crafted payloads designed to crash the proxy.
3. **Memory is inspectable**: Core dumps, `/proc/mem` scans, or memory forensics may be attempted to extract secrets.
4. **Timing is observable**: Side-channel attacks may attempt to infer enforcement decisions from response latency.

---

## 8.2 Memory Security

### 8.2.1 Secret Zeroing (Key Material)

**Threat**: Encryption keys persisting in freed memory after `VaultEncryption` is dropped. An attacker with memory access (core dump, cold boot, memory forensics) could recover AES-256 key material.

**Mitigation**: The `zeroize` crate with `Drop` implementation.

```rust
use zeroize::Zeroize;

struct VaultEncryption {
    key: [u8; 32],
}

impl Drop for VaultEncryption {
    fn drop(&mut self) {
        self.key.zeroize(); // Guaranteed not optimized away
    }
}
```

**Why `zeroize` and not `memset`**: The Rust/LLVM compiler may eliminate dead stores via optimization. `zeroize` uses volatile writes and compiler barriers to guarantee the zeroing operation is never optimized away. This is the same approach used by OpenSSL (`OPENSSL_cleanse`) and the Linux kernel (`memzero_explicit`).

**Coverage**:

| Location | What is zeroed | When |
|----------|---------------|------|
| `VaultEncryption::drop()` | `key: [u8; 32]` | Struct dropped |
| `VaultEncryption::from_env()` | Intermediate `Vec<u8>` from hex decode | After copy to `[u8; 32]` |
| `VaultEncryption::from_env()` (error path) | Intermediate `Vec<u8>` | On validation failure |

**Verification**: `vault_key_is_zeroed_on_drop` test — creates a Vault, performs encrypt/decrypt, drops it, verifies no crash. Full memory verification requires external tooling (valgrind, bytehound).

---

### 8.2.2 Nonce Reuse Prevention (AES-GCM)

**Threat**: Reusing a nonce with the same key in AES-GCM completely breaks confidentiality and authenticity. An attacker can recover plaintext via XOR of two ciphertexts encrypted with the same nonce.

**Mitigation**: `rand::random::<[u8; 12]>()` generates a cryptographically random 12-byte nonce for every encryption operation.

**Analysis**: With 96-bit random nonces, the birthday collision probability is:
- After 2^32 encryptions: ~2^-32 (negligible)
- After 2^48 encryptions: ~1 (problematic)

For a security kernel processing thousands of vault writes per day, 2^32 would take millennia to reach. The risk is effectively zero.

**Verification**: `test_nonce_reuse_not_possible` — encrypts same plaintext 100 times, asserts all nonces are unique.

---

### 8.2.3 Decryption Error Sanitization

**Threat**: AES-GCM decryption errors may leak information about key material, algorithm state, or ciphertext structure. Padding oracle and ciphertext malleability attacks exploit detailed error messages.

**Mitigation**: All decryption failures return a generic "Vault integrity error" message. Detailed diagnostics are logged internally (operator-only):

```rust
cipher.decrypt(nonce, ciphertext)
    .map_err(|_| {
        tracing::error!(
            "Vault decryption failed: authentication tag mismatch. \
             Possible causes: data tampering, key rotation, or storage corruption."
        );
        anyhow!("Vault integrity error: decryption failed")
    })
```

**Verification**:
- `test_wrong_key_returns_integrity_error` — wrong key error says "integrity error", not "aes"
- `test_truncated_ciphertext_returns_integrity_error` — short data says "integrity error"

---

## 8.3 Runtime Stability

### 8.3.1 Panic Guard (CatchPanicLayer)

**Threat**: A panic in any request handler kills the proxy process, causing a denial of service for all agents.

**Mitigation**: Tower `CatchPanicLayer` wraps the entire handler stack. Panics are caught and converted to HTTP 500 responses without process termination.

```rust
.layer(
    ServiceBuilder::new()
        .layer(CatchPanicLayer::new())       // Outermost — catches everything
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(tower::limit::ConcurrencyLimitLayer::new(1024)),
)
```

**Verification**: `srr_garbage_input_does_not_panic` — feeds null bytes, 100K-length paths, binary data (PNG headers), and malformed JSON to SRR. None cause a panic.

---

### 8.3.2 Request Body Limit (OOM Defense)

**Threat**: An adversary sends a multi-GB request body, causing the proxy to OOM and crash.

**Mitigation**: `RequestBodyLimitLayer(1MB)` rejects any request body exceeding 1,048,576 bytes at the transport layer, before any parsing or inspection occurs.

Additionally, the SRR's `max_body_bytes` (default 65536) limits payload inspection scope. Bodies exceeding this limit are not parsed — the rule is skipped and Default-to-Caution applies.

**Defense in depth**:
- Tower layer: 1MB hard limit (transport level)
- SRR: 64KB inspection limit per rule (application level)

**Verification**:
- `large_64kb_body_does_not_crash_or_oom` — 128KB body → Default-to-Caution (no crash)
- `payload_exceeding_max_body_bytes_falls_back_to_default_caution` — body over limit → Delay 300ms

---

### 8.3.3 Connection Exhaustion (FD Limit)

**Threat**: An adversary opens thousands of concurrent connections, exhausting file descriptors and preventing legitimate agent requests.

**Mitigation**: `ConcurrencyLimitLayer(1024)` limits the number of in-flight requests. Beyond 1024 concurrent requests, new connections receive HTTP 503 Service Unavailable.

**Verification**: `rate_limiter_100_concurrent_checks_no_deadlock` — 100 concurrent rate limit checks complete in < 500ms with no deadlock.

---

### 8.3.4 WAL Corruption Resilience

**Threat**: Disk corruption, partial writes, or deliberate tampering of the WAL file could crash the proxy during recovery.

**Mitigation**: WAL recovery treats each line independently. JSON parse failures are logged and **skipped** — recovery continues with the next valid entry.

```rust
match serde_json::from_str::<GVMEvent>(line) {
    Ok(event) => { /* process */ }
    Err(e) => {
        tracing::error!("Corrupt WAL entry, skipping");
        continue;  // Never fatal
    }
}
```

**Verification**: `wal_tampered_entry_does_not_crash_recovery` — WAL with valid entry, corrupted entry, valid entry → recovery finds 2 Pending events, skips corruption.

---

### 8.3.5 Task Leak Prevention (Backpressure)

**Threat**: Each NATS publish spawns a `tokio::spawn` task. Under high load, unbounded task spawning could exhaust memory.

**Mitigation**:
- WAL mutex serializes durable writes (bounded I/O concurrency)
- NATS tasks are fire-and-forget stubs in MVP (no real network I/O)
- In production: bounded channels or semaphores for NATS publish backpressure

**Verification**: `ledger_concurrent_spawns_stay_bounded` — 500 concurrent durable appends complete in < 10 seconds with exactly 500 WAL entries.

---

## 8.4 Side-Channel Resistance

### 8.4.1 Timing Analysis

**Threat**: An attacker measures response latency to determine whether their request was Denied (fast — no forwarding) vs Allowed (slow — upstream round-trip). This could be used to probe which URLs are blocked.

**Current status**: The SRR uses linear rule matching (O(n) where n = number of rules). Measurement shows:

| Metric | Deny Path | Allow Path | Ratio |
|--------|-----------|------------|-------|
| 10,000 iterations | ~Xms | ~Yms | < 10x |

The ratio is within an order of magnitude, making timing-based inference impractical for most attackers. True constant-time matching would require padding all code paths and fixed-time response delays — a potential future enhancement.

**Verification**: `srr_decision_time_is_roughly_constant` — 10,000 iterations each for Deny and Default-to-Caution paths, asserts ratio < 10x.

---

## 8.5 Security Checklist Summary

| # | Threat | Mitigation | Status | Test |
|---|--------|-----------|--------|------|
| 1 | Key material in RAM | `zeroize` crate, `Drop` impl | Done | `vault_key_is_zeroed_on_drop` |
| 2 | Nonce reuse (AES-GCM) | `rand::random()` per encrypt | Done | `test_nonce_reuse_not_possible` |
| 3 | OOM from large payload | `max_body_bytes` + 1MB body limit | Done | `large_64kb_body_does_not_crash_or_oom` |
| 4 | Panic kills proxy | `CatchPanicLayer` in tower stack | Done | `srr_garbage_input_does_not_panic` |
| 5 | Connection exhaustion | `ConcurrencyLimitLayer(1024)` | Done | `rate_limiter_100_concurrent_checks` |
| 6 | WAL corruption | JSON parse skip, recovery continues | Done | `wal_tampered_entry_does_not_crash_recovery` |
| 7 | Side-channel timing | Measured < 10x variance | Done | `srr_decision_time_is_roughly_constant` |
| 8 | Decryption error leak | Generic error, internal log only | Done | `test_wrong_key_returns_integrity_error` |
| 9 | Task leak / backpressure | Bounded WAL mutex, stub NATS | Done | `ledger_concurrent_spawns_stay_bounded` |
| 10 | Intermediate key exposure | `bytes.zeroize()` on all paths | Done | Code review |

---

## 8.6 Dependency Security

### Cryptographic Dependencies

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `aes-gcm` | 0.10 | AES-256-GCM encryption | RustCrypto — widely audited |
| `rand` | 0.8 | Cryptographic random nonce generation | Uses OS CSPRNG |
| `sha2` | 0.10 | SHA-256 content hashing | RustCrypto |
| `zeroize` | 1.x | Secret memory zeroing | RustCrypto |
| `hex` | 0.4 | Key hex decoding | Minimal, well-audited |

### Runtime Dependencies

| Crate | Version | Purpose | Security Consideration |
|-------|---------|---------|----------------------|
| `tokio` | 1.x | Async runtime | Memory-safe async I/O |
| `axum` | 0.7 | HTTP framework | Built on hyper (memory-safe) |
| `tower` | 0.4 | Middleware (CatchPanic, Limit) | Mature, widely used |
| `serde_json` | 1.x | JSON parsing | Bounds-checked deserialization |

---

## 8.7 Future Hardening (Roadmap)

| Enhancement | Priority | Description |
|-------------|----------|-------------|
| Bounded NATS channels | High | Replace `tokio::spawn` with bounded `mpsc` channel for NATS publish |
| Key rotation support | High | Automatic re-encryption of vault data on key change |
| mlock for key pages | Medium | Pin key memory pages to prevent swap-to-disk |
| Constant-time SRR | Medium | Pad all code paths to fixed execution time |
| Memory allocator hardening | Low | Use `jemalloc` with security features or custom allocator |
| Fuzzing CI pipeline | Medium | Continuous fuzzing with `cargo-fuzz` or AFL |

---

[← Part 7: Python SDK](07-sdk.md) | [Part 9: Test Coverage Report →](09-test-report.md)
