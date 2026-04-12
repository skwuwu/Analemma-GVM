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

### 1.8 Unsafe & FFI Discipline

GVM uses `unsafe` for Linux syscalls (clone, fork, waitpid, getsockopt, prctl, seccomp) and Wasm FFI. "Rust means safe" is false when `unsafe` is present.

**Rules:**
- Zero uninitialized memory into C structs before passing to syscalls: `libc::sockaddr_in = unsafe { mem::zeroed() }`
- Explicit pointer casts — never `as *mut _` (inferred). Always `as *mut libc::sockaddr_in as *mut libc::c_void`
- Check every syscall return value. `-1` or `< 0` → error. Never ignore.
- Never use `std::mem::forget()` for RAII resource management. Use explicit `Drop` impls and return guards to callers. `mem::forget` leaks resources and breaks cleanup invariants.
- Never use `std::mem::transmute`. Use `from_be`/`to_be` for endianness, `TryFrom` for type conversions.
- Document the safety contract of every `unsafe` block in a `// SAFETY:` comment.

**Wasm FFI:**
- `slice::from_raw_parts()` from Wasm linear memory — document the assumption that Wasmtime validates bounds.
- `copy_nonoverlapping()` — verify total copy size ≤ allocated size. Assert no overlap.

### 1.9 Namespace & Sandbox Isolation

Sandbox isolation is only as strong as its weakest mount/seccomp configuration.

**Mount namespace:**
- `/proc` must be mounted with `hidepid=2` inside PID namespace (prevents cross-process information leaks)
- `/sys` must NOT be mounted inside sandbox (prevents cgroup/kernel parameter manipulation)
- All bind-mounts inside sandbox must be read-only except `/workspace/output` and `/tmp`
- `pivot_root` must be used, not `chroot` (chroot is escapable with `open_by_handle_at`)
- After `pivot_root`, old root must be unmounted (`MNT_DETACH`) and directory removed

**seccomp-BPF:**
- Default ENOSYS for unknown syscalls (graceful fallback). Whitelist for known-safe. No KILL for unknowns (prevents kernel/glibc upgrade regressions).
- `socket()` must filter on `arg0` (domain): only AF_INET, AF_INET6, AF_UNIX allowed. AF_NETLINK allowed only if required for DNS. AF_PACKET blocked.
- Dangerous syscalls (ptrace, mount, bpf, unshare, setns, open_by_handle_at) get ENOSYS — the operation never executes.
- `openat()` argument filtering: seccomp cannot enforce path boundaries (kernel limitation). Rely on mount namespace for path isolation. Do not add false-confidence seccomp path filters.
- **seccomp must NEVER be disableable.** No `--seccomp off` flag, no `GVM_DEBUG_SECCOMP_DISABLE` env var, no runtime toggle. A sandbox without seccomp is not a sandbox — agents can call mount/ptrace/unshare to break all other isolation layers. If seccomp causes issues, debug with `dmesg | grep SECCOMP` and add the syscall to the whitelist, not disable the filter.

**TC ingress filter** (implemented as tc u32 classifier in `ebpf.rs`)**:**
- TC filter must be attached to host-side veth BEFORE signaling child process ready. No packet escape window.
- Use RAII guard (`EbpfGuard`) for filter lifecycle. Drop detaches the filter. Never use `mem::forget`.
- If TC filter is unavailable, fall back to iptables + seccomp AF_NETLINK blocking (defense-in-depth).

**Certificate MITM:**
- CA private key must NEVER enter the sandbox namespace (not on disk, not in env, not in /proc)
- CA certificate (public only) injected into sandbox trust store
- All certificates backdated by 24 hours (`not_before = now - 24h`) for clock drift tolerance
- ECDSA P-256 for all ephemeral certificates (fast generation, strong security)

### 1.10 Async I/O Discipline

GVM proxy runs on tokio. Blocking the executor starves all concurrent requests.

**Rules:**
- Never use `std::fs::*` inside `async fn`. Use `tokio::fs::*` with `.await`.
  - `std::fs::read_dir` → `tokio::fs::read_dir().await`
  - `std::fs::rename` → `tokio::fs::rename().await`
  - `std::fs::remove_file` → `tokio::fs::remove_file().await`
  - `std::fs::read_to_string` → `tokio::fs::read_to_string().await`
- Never use `std::thread::sleep` in async code. Use `tokio::time::sleep().await`.
- Never use `std::process::Command` in async code. Use `tokio::process::Command`.
- Heavy computation (>1ms) in async handlers: wrap in `tokio::task::spawn_blocking`.
  - Exception: SHA-256 hashing is CPU-bound but <1µs per event — acceptable inline.
  - Exception: regex evaluation uses pre-compiled `Regex` — no compilation on hot path.
- `fsync` is inherently blocking. WAL fsync runs inside the batch task (dedicated tokio task), not inline in the request handler. This is by design.

**Cold path exceptions (startup/shutdown only):**
- `recover_from_wal()` may use `std::fs` during startup (before accepting connections). Document with `// COLD PATH: blocking I/O acceptable at startup`.
- Config loading (`std::fs::read_to_string` for TOML files) is cold-path only.

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

Explicitly stateful exceptions (documented here as required by this rule):
- **Rate limiter** (`rate_limiter.rs`): per-agent token bucket, decisions depend on recent request history.
- **DNS governance** (`dns_governance.rs`): per-domain sliding window, decisions depend on recent query patterns. Tier escalation (Tier 2→3→4) and decay (back to Tier 2 on window expiry) are both intentionally stateful. All decision-relevant state (unique_subdomain_count, global_unique_count, window_age_secs) is captured in the WAL event context so auditors can reproduce the classification.

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

### 6.1 Interface-Driven Testing

**Principle**: System lifecycle control (Start, Stop, Status) and governance workflows (Approve, Reload) must be performed exclusively through CLI commands.

```
gvm run --sandbox -- <agent command>   # Agent execution
gvm status --json                       # Proxy health (machine-readable)
gvm check --json --host H --method M    # Policy dry-run
gvm reload                              # Hot-reload SRR rules
gvm approve                             # IC-3 approval workflow
gvm stop                                # Graceful proxy shutdown
gvm cleanup                             # Orphan resource cleanup
gvm events list                         # WAL event query
gvm audit verify                        # Merkle chain verification
gvm preflight                           # Environment check
```

**Exception (Internal API)**: The following cases permit direct HTTP protocol verification via `curl`:

- **Communication integrity tests**: Verifying the proxy engine's HTTP/gRPC response specification itself (e.g., `GET /gvm/ca.pem` returns valid PEM, `POST /gvm/intent` accepts the correct JSON schema).
- **Internal logic probing**: Validating experimental features not exposed to users (e.g., `/gvm/intent` for Shadow Mode 2-phase verification).
- **Payload precision tests**: Testing scenarios where CLI arguments are inadequate for the data involved (e.g., `/gvm/check` with a large base64-encoded body field for payload inspection rules).
- **Throughput measurement**: Burst/stress tests where CLI process spawn overhead would measure startup latency rather than proxy throughput (e.g., 100 sequential `curl /gvm/check` in a tight loop).

Mark all such exceptions with `# 6.1-exception: <reason>` inline comments for traceability.

**Prohibited** (no exceptions):
- `cat data/proxy.pid` or any direct PID file access → use `gvm status --json | jq .pid`
- `curl /gvm/health` for lifecycle checks → use `gvm status --json`
- `curl -X POST /gvm/reload` for rule changes → use `gvm reload`
- Direct `gvm-proxy` binary invocation for lifecycle → use `gvm run` or `gvm stop`
- `pkill -f gvm-proxy` for lifecycle → use `gvm stop` (chaos `kill -9` is allowed)

**Allowed** external operations:
- Chaos injection: `kill -9 $(gvm status --json | jq .pid)`, `tc netem`, `mount -t tmpfs` — PID obtained via CLI, kill is OS-level
- Reading result files (`results/*/summary.txt`, `data/proxy.log`)
- Sending prompts to agents (via OpenClaw CLI or Telegram Bot API)

**Rationale**: Lifecycle management via CLI tests the same code path users run in production. Internal API tests via curl are acceptable because they verify the API contract itself — the distinction is whether the test is checking "does GVM work" (CLI) or "does this specific endpoint respond correctly" (curl).

### 6.2 Test Categories

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

## 7. Architecture Principles

### 7.0 Governance Layer Model

GVM enforces agent I/O through a layered pipeline. DNS resolution must happen before any HTTP call, so DNS governance naturally precedes HTTP governance:

```
Agent Process
  │
  ├─ Layer 0: DNS Governance (dns_governance.rs)
  │   └─ UDP 53 → local DNS proxy → classify → delay → upstream resolve
  │   └─ Tier 1 (known) free pass / Tier 2-4 graduated delay
  │   └─ No Deny — worst case is 10s delay, never agent termination
  │
  ├─ Layer 1: HTTP Governance (proxy.rs + srr.rs + policy.rs)
  │   └─ HTTP/HTTPS → proxy → SRR check + ABAC eval → max_strict() → forward
  │   └─ Allow / Delay / RequireApproval / Deny
  │
  └─ Layer 2: Filesystem Governance (overlayfs + fs_approve)
      └─ All writes → overlay → human review → approve/reject
```

DNS and HTTP share the same WAL for unified audit. `gvm suggest` learns both DNS domains and HTTP hosts from the same watch session.

### 7.1 Single Execution Path (Pipeline Pattern)

Every agent execution mode (cooperative/sandbox/contained) must go through the same pipeline:
1. **Pre-launch**: proxy availability, DNS proxy spawn, orphan cleanup, CA download
2. **Launch**: mode-specific execution (the ONLY branching point)
3. **Post-exit**: cleanup, audit output

```
CORRECT:   watch calls pipeline::pre_launch() → pipeline::launch() → WAL tail
INCORRECT: watch has its own sandbox logic that partially duplicates run.rs
```

Mode-specific logic belongs ONLY in Phase 2. If you find yourself writing proxy health checks, SandboxConfig construction, or interpreter detection outside of the shared helpers, you are creating drift.

### 7.2 No Logic Duplication Across Modules

If the same logic appears in more than one function, extract it. Common violations:
- Proxy health check (must use `proxy_manager::ensure_available`)
- SandboxConfig construction (must use `assemble_sandbox_config`)
- Interpreter detection (must use `detect_interpreter`)
- Proxy env injection (must use `inject_proxy_env`)

When adding a feature to the agent execution path (e.g. new env var, new cleanup step), it must be added to the shared pipeline — not to individual mode functions. If your change requires touching `run_local`, `run_sandboxed`, AND `run_contained`, you are violating this principle.

### 7.3 Process Lifecycle Separation

Components with independent lifecycles must be managed by dedicated modules:
- **Proxy**: `proxy_manager.rs` — daemon with PID file, survives CLI exit
- **Sandbox**: `sandbox_impl.rs` — RAII guards, orphan cleanup on startup
- **WAL**: `ledger.rs` — group commit, shutdown flush

```
CORRECT:   Proxy started via proxy_manager (setsid, PID file, log file)
INCORRECT: Proxy spawned as child of CLI process (dies with parent)

CORRECT:   Sandbox cleanup via RAII guard + orphan scan
INCORRECT: Cleanup only in happy-path function exit
```

No process with an independent lifecycle should be spawned as a child of the CLI process without `setsid` or equivalent isolation. All long-lived processes must have PID files for reuse across invocations.

### 7.4 Configuration Path Consistency

All components must find config files and data directories from the same root:
- `workspace_root_for_proxy()` is the canonical source
- Relative paths (`data/wal.log`, `config/srr_network.toml`) are resolved from this root
- Working directory for spawned processes must be set explicitly

```
CORRECT:   .current_dir(&workspace_root) when spawning proxy
INCORRECT: Relying on whatever pwd the user ran gvm from
```

### 7.5 Parent-Mount Pattern (Sandbox Resource Survival)

Resources that must outlive the sandbox child process **must be created in the parent** before `clone()`. The child inherits via `clone(CLONE_NEWNS)` and bind-mounts into its namespace. After child exit, the parent retains access for scanning, cleanup, or review.

```
CORRECT:   Parent mounts overlayfs → child inherits → parent scans upper after exit
INCORRECT: Child mounts overlayfs → child exits → mount namespace destroyed → parent finds nothing
```

This applies to any resource that requires post-exit inspection:
- **$HOME overlay**: parent mounts at `/run/gvm/home-merged-{pid}`, child bind-mounts to `/home/agent`
- **Workspace overlay**: parent mounts at `/run/gvm/ws-merged-{pid}`, child bind-mounts to `/workspace`
- **Any future staging/export**: if the parent needs the data after the child dies, the parent must own the mount

**Anti-pattern**: mounting tmpfs or overlayfs inside the child's mount namespace for data that the parent needs to read. tmpfs in a child namespace is destroyed when the namespace is torn down — the parent will see an empty directory or "No such file."

### 7.6 Keep-Alive After Enforcement (MITM Proxy)

When the MITM proxy denies or delays a request, the TLS keep-alive connection must remain open unless the protocol requires closure. Breaking the connection forces the client to create a new CONNECT tunnel, which may trigger intermittent TLS handshake failures (Node.js undici edge case) and prevents natural agent fallback flows.

```
CORRECT:   Deny → 403 response (no Connection: close) → continue keep-alive loop
           Agent retries with fallback URL on same TLS session
INCORRECT: Deny → 403 + Connection: close + break → new CONNECT → handshake eof
           Agent's fallback attempt fails due to reconnect issues
```

This principle applies to all proxy-generated responses on the MITM path:
- **Deny (403)**: continue — agent may retry with different URL
- **Throttle (429)**: continue — agent retries after rate limit window
- **Classification error (500)**: break — internal error, connection state uncertain
- **RequireApproval (403)**: break — approval flow requires out-of-band communication
- **Circuit breaker (503)**: break — WAL is failing, reject all traffic

The distinction: break when the proxy's internal state is uncertain or the error is systemic. Continue when the denial is a normal policy decision and the connection is healthy.

### 7.7 Transport-Layer Framing Only (MITM Relay)

The MITM relay must dispatch on HTTP transport framing (Content-Length, Transfer-Encoding: chunked, EOF) — never on Content-Type or application-layer semantics. Content-Type is a content-layer concern; transport framing is how the server signals "this response is complete."

```
CORRECT:   chunked → relay_chunked() regardless of Content-Type
           Content-Length → relay_exact_bytes() regardless of Content-Type
           Neither → relay_until_eof()
INCORRECT: text/event-stream → relay_until_eof() (SSE has no terminator)
           But SSE + chunked → server uses chunk terminator (0\r\n\r\n) to end
           relay_until_eof() waits for TCP EOF that never comes (HTTP/1.1 keep-alive)
```

Anthropic `/v1/messages` with `stream:true` returns `Transfer-Encoding: chunked` + `Content-Type: text/event-stream`. The chunked parser detects the final chunk (`0\r\n\r\n`) correctly — the SSE content inside is irrelevant to transport framing. Dispatching on Content-Type caused the relay to hang indefinitely waiting for EOF on a keep-alive connection.

---

## 8. Documentation Standards

### 8.1 Code Documentation

Every public function must have a doc comment explaining:
- What it does (one sentence)
- Security implications (if any)
- Error conditions (when it returns Err)
- Performance characteristics (if on hot path)

### 8.2 Security Claims

Never claim more than what is implemented:

```
CORRECT:   "Policy logic runs in a Wasm sandbox"
INCORRECT: "The entire system is tamper-proof"

CORRECT:   "AES-GCM integrity verified"
INCORRECT: "Merkle verified" (if Merkle verification is not actually performed)
```

### 8.3 Known Limitations

Every known limitation must be documented in `security-model.md` with:
- Attack description
- Preconditions
- Impact
- Planned mitigation
- Why it is acceptable in the current threat model
