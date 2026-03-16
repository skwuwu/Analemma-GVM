# GVM Code Standards

> Authoritative engineering principles for all GVM contributions.
> Every pull request must comply with these rules. No exceptions.

---

## 1. Security Principles

### 1.1 Fail-Close by Default

GVM is a governance system. When in doubt, deny.

```
CORRECT:   Unknown input → Deny (or Delay)
INCORRECT: Unknown input → Allow
```

- Unknown Wasm decision type → `Delay { milliseconds: 300 }`, not `Allow`
- Unknown policy operator → `bail!()` at config load, not silent `Eq`
- Missing API credential → reject request, not silent passthrough
- Malformed WAL entry → skip and log, never treat as valid

### 1.2 No Panic in Runtime Paths

The proxy must never crash. A panic kills all governance for all agents.

```rust
// FORBIDDEN in any code path reachable after startup:
.unwrap()
.expect("...")
panic!()
unreachable!()  // unless provably unreachable

// REQUIRED:
.map_err(|e| anyhow!("context: {}", e))?
.unwrap_or_else(|| safe_default)
match mutex.lock() {
    Ok(guard) => { /* proceed */ }
    Err(_) => {
        tracing::error!("Mutex poisoned — failing closed");
        return Err(anyhow!("Internal error"));
    }
}
```

`unwrap()` is permitted ONLY in:
- Tests (`#[cfg(test)]`)
- Static initialization proven infallible (e.g., `Regex::new` on a literal)
- `main()` for fatal startup errors (with `.context("reason")`)

### 1.3 Error Sanitization

Internal errors must never reach external callers. Cryptographic details must never leak.

```rust
// FORBIDDEN:
Err(e) => json_response(500, &json!({"error": e.to_string()}))

// REQUIRED:
Err(e) => {
    tracing::error!(error = %e, key = %key, "Vault operation failed");
    json_response(500, &json!({"error": "Internal error"}))
}
```

Specific rules:
- AES-GCM errors → "integrity error" (never expose cipher internals)
- WAL I/O errors → "audit system error" (never expose file paths)
- Config parse errors → allowed at startup (operator sees them), forbidden in API responses

### 1.4 Secret Hygiene

```rust
// All key material must implement zeroize-on-drop
struct KeyMaterial {
    key: [u8; 32],
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// Intermediate buffers holding secrets must be zeroed immediately
let mut bytes = hex::decode(&hex_key)?;
key.copy_from_slice(&bytes);
bytes.zeroize(); // zero the Vec<u8> before it is dropped
```

Rules:
- No hardcoded keys (dev mode uses random ephemeral key)
- No secrets in log output (even at `tracing::debug` level)
- No secrets in error messages
- No secrets in WAL events (store content_hash, not plaintext)
- Environment variable keys: warn if not set, never silently use empty string

### 1.5 Input Validation

All external input is untrusted. This includes agent headers, request bodies, config files, and WAL entries.

```rust
// Headers from agents: validate format, reject injection
if !operation.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-') {
    return Err(anyhow!("Invalid operation name"));
}

// Config files: validate at load time, reject at startup
if parts.len() != 3 || parts[0] != "gvm" {
    bail!("Invalid core operation name: must be gvm.{{category}}.{{action}}");
}

// WAL recovery: skip corrupt entries, never trust blindly
let event: GVMEvent = match serde_json::from_str(line) {
    Ok(e) => e,
    Err(e) => {
        tracing::error!(error = %e, "Corrupt WAL entry, skipping");
        continue;
    }
};

// Body size: enforce limits before parsing
if body.len() > MAX_BODY_BYTES {
    return default_decision; // do not attempt to parse oversized input
}
```

### 1.6 Cryptographic Standards

- Encryption: AES-256-GCM only. No CBC, no ECB, no custom ciphers.
- Hashing: SHA-256 only for integrity. No MD5, no SHA-1.
- Nonces: 12-byte random (never sequential, never derived from content)
- Domain separation: all hashes must include a version prefix

```rust
hasher.update(b"gvm-checkpoint-v1|"); // domain separation
hasher.update(event.event_id.as_bytes());
```

- No custom cryptographic constructions. Use audited crates only (aes-gcm, sha2, hex).

---

## 2. Error Handling Principles

### 2.1 Error Propagation Hierarchy

```
Config load errors   → bail!() at startup. Proxy must not start with invalid config.
Runtime I/O errors   → Result<T, E>. Propagate to caller. Never panic.
WAL write errors     → Reject the request (fail-close). Never proceed without audit.
                        Use fallback WAL path for resilience. Full disk → auto-rotate.
                        Both paths fail → then reject.
Vault errors         → Return generic error to caller. Log details internally.
Network errors       → Return appropriate HTTP status. Log with trace context.
```

### 2.2 Startup vs Runtime

Startup (config loading, module initialization):
- `bail!()` and `expect()` are acceptable — invalid config should prevent startup
- All validation happens here: operation names, policy rules, regex patterns, IC mappings
- Compile regexes, validate field names, check duplicate priorities

Runtime (request processing):
- Zero panics. Every error is `Result<T, E>`.
- Timeouts on all external operations
- Graceful degradation: if Wasm fails, fall back to native (with warning log)

### 2.3 Explicit Configuration

Required configuration must cause startup failure if missing:

```
[ERROR] config/srr_network.toml not found.
        GVM cannot start without SRR rules.
```

Optional configuration uses safe defaults with visible warnings:

```
[WARN]  GVM_VAULT_KEY not set. Using ephemeral random key.
        Agent state will not survive restart.
        Set GVM_VAULT_KEY for persistent encryption.
```

Never silently use empty strings or zero values as defaults for security-critical settings.

---

## 3. Performance Principles

### 3.1 Hot Path Budget

The governance decision hot path must stay under these budgets:

```
IC-1 (Allow):  < 1µs  policy evaluation + < 0ms  added latency
IC-2 (Delay):  < 1µs  policy evaluation + 300ms  intentional delay
IC-3 (Deny):   < 1µs  policy evaluation + < 0ms  added latency
WAL append:    < 5ms  including fsync (group commit amortized)
```

Rules:
- No heap allocation in the SRR matching hot path
- No regex compilation at evaluation time (pre-compile at load)
- No network calls during policy evaluation
- No mutex contention on the decision path (use RwLock for read-heavy data)

### 3.2 Amortize Expensive Operations

```rust
// FORBIDDEN: regex compiled per evaluation
Operator::Regex => {
    let re = regex::Regex::new(&pattern)?; // compiles every call
    re.is_match(&haystack)
}

// REQUIRED: regex compiled at config load, stored in Condition
struct Condition {
    compiled_regex: Option<regex::Regex>, // pre-compiled
}
```

Other amortizable operations:
- WAL fsync: group commit batches multiple writes into one fsync
- Merkle root: computed once per batch, not per event
- JSON serialization: done by caller before entering batch task (CPU parallelism)

CI enforcement: `Regex::new` outside config/load/test paths is a build error.
```bash
# CI check: no runtime regex compilation
if grep -rn "Regex::new" src/ --include="*.rs" | grep -v "config\|load\|compile\|test"; then
    echo "ERROR: Regex::new found outside config/load paths"
    exit 1
fi
```

### 3.3 Bounded Resources

Every queue, buffer, and cache must have explicit bounds:

```rust
// Channel capacity: explicit, not unbounded
let (tx, rx) = tokio::sync::mpsc::channel(4096);

// Response size from Wasm: bounded
const MAX_RESPONSE_LEN: usize = 1024 * 1024;
if result_len > MAX_RESPONSE_LEN {
    return Err(anyhow!("Wasm response too large"));
}

// Rate limiter buckets: evict stale entries
if bucket.last_access.elapsed() > Duration::from_secs(600) {
    buckets.remove(&agent_id);
}

// Checkpoint size: bounded
const MAX_CHECKPOINT_SIZE: usize = 5 * 1024 * 1024;
```

Never use unbounded channels, unbounded caches, or unbounded string builders in runtime paths.

---

## 4. Deterministic Design Principles

### 4.1 Same Input → Same Decision

Policy evaluation must be deterministic. The same operation metadata must always produce the same enforcement decision regardless of:
- Time of day
- Number of concurrent requests
- Previous requests from the same agent
- Internal cache state

The only exception is rate limiting, which is explicitly stateful and documented as such.

### 4.2 Decision Ordering

`max_strict()` defines a total ordering on enforcement decisions:

```
Allow (0) < AuditOnly (1) < Throttle (2) < Delay (3) < RequireApproval (4) < Deny (5)
```

This ordering must be:
- Total: every pair has a defined winner
- Deterministic: same inputs always produce same output
- Documented: the strictness value of each decision type is part of the public API

### 4.3 Evaluation Independence

Layer 1 (ABAC) and Layer 2 (SRR) must evaluate independently:

```rust
let policy_decision = state.policy.evaluate(&operation);  // Layer 1
let srr_decision = state.srr.check(method, host, path, body); // Layer 2
let final_decision = max_strict(policy_decision, srr_decision); // combine
```

Rules:
- Layer 1 must not read Layer 2 results
- Layer 2 must not read Layer 1 results
- Combination happens only via `max_strict()` after both complete
- This independence enables semantic forgery detection

### 4.4 WAL Ordering Guarantees

- `wal_sequence` is monotonically increasing (AtomicU64, SeqCst)
- Events within a batch are ordered by submission time
- Merkle root is computed from events in batch order
- Batch records include `prev_batch_root` for inter-batch chain
- Recovery replays events in file order (append-only WAL)

### 4.5 No Hidden State

Every decision-relevant state must be visible in the audit log:

```rust
// Every GVMEvent must include:
event_id          // unique identifier
trace_id          // causal chain
agent_id          // who
operation         // what
decision          // outcome
decision_source   // which layer decided
status            // execution result
timestamp         // when
payload.content_hash  // integrity of associated data
```

No decision may depend on state that is not recorded in the WAL.

---

## 5. Concurrency Principles

### 5.1 Ownership Model

```
Prefer:  channel (ownership transfer) > RwLock (read-heavy) > Mutex (write-heavy)
Avoid:   Arc<Mutex<T>> unless structurally required (e.g., Wasmtime Store)
```

### 5.2 Lock Discipline

- Never hold two locks simultaneously (deadlock risk)
- Never perform I/O while holding a lock
- Mutex poisoning must not cause panic:

```rust
// FORBIDDEN:
let guard = self.buckets.lock().unwrap();

// REQUIRED:
let guard = match self.buckets.lock() {
    Ok(g) => g,
    Err(_) => {
        tracing::error!("Rate limiter mutex poisoned");
        return false; // fail-closed: deny the request
    }
};
```

### 5.3 Async Mutex Rule

Never hold `std::sync::Mutex` across an `.await` point — this blocks the tokio runtime thread and can deadlock under load. If a lock must span an async operation, use `tokio::sync::Mutex`. However, `tokio::sync::Mutex` should never appear on the hot path (policy evaluation, SRR matching) because its overhead is higher than `std::sync::Mutex` for synchronous access.

```rust
// FORBIDDEN: std::sync::Mutex held across await
let guard = self.data.lock().unwrap();
let result = some_async_op(&guard).await; // blocks runtime thread
drop(guard);

// REQUIRED: tokio::sync::Mutex if lock must span await
let guard = self.data.lock().await;
let result = some_async_op(&guard).await;
drop(guard);

// PREFERRED: release sync lock before await
let snapshot = {
    let guard = self.data.lock().map_err(|_| anyhow!("poisoned"))?;
    guard.clone() // copy what you need
};
let result = some_async_op(&snapshot).await;
```

### 5.4 Async Discipline

- All I/O operations must be async (tokio)
- CPU-intensive work (JSON serialization, hash computation) should run before entering async critical sections
- `tokio::spawn` tasks must be bounded (channel backpressure)
- Shutdown must flush pending WAL batches before exit

---

## 6. Testing Standards

### 6.1 Test Categories

Every module must have tests in these categories:

```
Unit:        Pure logic, no I/O, no async
Integration: Cross-module interaction, real file I/O
Boundary:    Security boundaries (Wasm↔Host, HTTP headers, Vault encryption)
Edge:        Missing input, null bytes, unicode, empty collections
Hostile:     Concurrent stress, garbage input, timing, resource exhaustion
```

### 6.2 Security Test Requirements

Every security claim must have a corresponding test:

```
Claim: "Deny short-circuits"         → test_deny_overrides_all
Claim: "Nonce is never reused"       → test_nonce_reuse_not_possible
Claim: "Tampered data is detected"   → test_tampered_ciphertext_fails
Claim: "SSRF is blocked"             → ssrf_localhost_blocked_by_srr
Claim: "Fail-close on WAL failure"   → group_commit_fail_close_all_callers_receive_error
```

No security claim in documentation without a test that verifies it.

### 6.3 Benchmark Requirements

Performance claims must be backed by Criterion benchmarks:

```
Claim: "Sub-microsecond policy"  → bench policy/allow_read, policy/deny_critical
Claim: "46x throughput"          → bench wal/sequential vs wal_group_commit/concurrent
Claim: "28-88ns SRR"             → bench srr/allow_safe_host, srr/deny_bank_transfer
```

No performance claim in documentation without a benchmark that measures it.

---

## 7. Documentation Standards

### 7.1 Code Documentation

Every public function must have a doc comment explaining:
- What it does (one sentence)
- Security implications (if any)
- Error conditions (when it returns Err)
- Performance characteristics (if on hot path)

### 7.2 Security Claims

Never claim more than what is implemented:

```
CORRECT:   "Policy logic runs in a Wasm sandbox"
INCORRECT: "The entire system is tamper-proof"

CORRECT:   "AES-GCM integrity verified"
INCORRECT: "Merkle verified" (if Merkle verification is not actually performed)
```

### 7.3 Known Limitations

Every known limitation must be documented in `security-model.md` with:
- Attack description
- Preconditions
- Impact
- Planned mitigation
- Why it is acceptable in the current threat model
