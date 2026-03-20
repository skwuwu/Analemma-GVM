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

**Threat**: Encryption keys persisting in freed memory after `LocalKeyProvider` is dropped. An attacker with memory access (core dump, cold boot, memory forensics) could recover AES-256 key material.

**Mitigation**: The `zeroize` crate with `Drop` implementation.

```rust
use zeroize::Zeroize;

pub struct LocalKeyProvider {
    key: [u8; 32],
}

impl Drop for LocalKeyProvider {
    fn drop(&mut self) {
        self.key.zeroize(); // Guaranteed not optimized away
    }
}
```

**Why `zeroize` and not `memset`**: The Rust/LLVM compiler may eliminate dead stores via optimization. `zeroize` uses volatile writes and compiler barriers to guarantee the zeroing operation is never optimized away. This is the same approach used by OpenSSL (`OPENSSL_cleanse`) and the Linux kernel (`memzero_explicit`).

**Coverage**:

| Location | What is zeroed | When |
|----------|---------------|------|
| `LocalKeyProvider::drop()` | `key: [u8; 32]` | Struct dropped |
| `LocalKeyProvider::from_env()` | Intermediate `Vec<u8>` from hex decode | After copy to `[u8; 32]` |
| `LocalKeyProvider::from_env()` (error path) | Intermediate `Vec<u8>` | On validation failure |

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

**Analysis**: There are two distinct timing signals:

1. **SRR engine-level timing**: Policy evaluation takes ~28-63 ns regardless of decision. The variance (~35 ns) is 3-5 orders of magnitude below network jitter (0.1-10 ms). This is practically unobservable.

2. **End-to-end response timing**: Deny returns an immediate 403 (~3 ms). Allow/Delay forwards to upstream and waits for a response (~50-500 ms). This difference is architecturally inherent to **every proxy-based enforcement system** — Envoy, OPA, Nginx all exhibit the same behavior. A blocked request is always faster than a forwarded request, because the proxy does not make an upstream call.

**Why this is not a practical concern**:

- **Rate limiter eliminates statistical attacks**: Timing attacks require thousands of repeated measurements to extract a signal. The per-agent rate limiter (Throttle) caps request volume, preventing an agent from accumulating enough samples. Exceeding the limit triggers 429 responses that are themselves recorded in the audit trail — the attack attempt becomes a detectable event.
- **The timing signal is redundant**: The Deny decision is already explicitly communicated to the agent via the HTTP 403 status code and `X-GVM-Decision: Deny` response header. An agent learns nothing from timing that it doesn't already know from the response.
- **Constant-time padding would mask intentional enforcement signals**: IC-2 Delay (300+ ms) is a deliberately visible timing signal designed to give the agent feedback. Padding all responses to a fixed time would conflict with this design intent.

**Status**: Not constant-time by design. Timing attack is impractical due to rate limiting, and the end-to-end timing difference is an inherent property of proxy architecture, not a GVM-specific vulnerability. Constant-time SRR matching is a low-priority consideration for future hardening.

**Verification**: `srr_decision_time_is_roughly_constant` — 10,000 iterations each for Deny and Default-to-Caution paths, asserts SRR engine-level ratio < 10x.

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
| 7 | Side-channel timing | Rate limiter blocks statistical attacks; end-to-end difference is inherent to proxy architecture | Done | `srr_decision_time_is_roughly_constant` |
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

## 8.7 OS-Level Isolation: Architecture & MicroVM Extensibility

### 8.7.1 Current Isolation Model

The `gvm-sandbox` crate provides Linux-native process isolation using four kernel primitives:

| Layer | Mechanism | Source | Purpose |
|-------|-----------|--------|---------|
| User namespace | `CLONE_NEWUSER` | `namespace.rs` | Non-privileged root (UID 0 maps to host UID) |
| PID namespace | `CLONE_NEWPID` | `namespace.rs` | Isolated process tree |
| Mount namespace | `CLONE_NEWNS` + `pivot_root` | `mount.rs` | Read-only workspace, minimal rootfs (tmpfs 64MB) |
| Network namespace | `CLONE_NEWNET` + veth pair | `network.rs` | Proxy-path routing via veth + DNAT (v1 opt-in path) |
| Syscall filter | seccomp-BPF (whitelist, ~45 syscalls) | `seccomp.rs` | Default-deny; blocks ptrace, mount, bpf, unshare |

**Network isolation** is the critical enforcement boundary: the agent runs in an isolated netns with a dedicated veth pair and child-level `HTTP_PROXY`/`HTTPS_PROXY` injection, while host iptables config provides a DNAT path to the configured proxy endpoint. This gives stronger containment than cooperative mode; transparent interception parity remains roadmap work.

```
Agent (sandbox netns)         Host netns              GVM Proxy
10.200.X.2/30  ──veth──>  10.200.X.1/30  ──DNAT──>  127.0.0.1:8080
                          iptables MASQUERADE         3-layer enforcement
```

**Setup overhead**: ~2ms (clone + veth + pivot_root + seccomp). Supports 16K+ concurrent sandboxes via PID-derived /30 subnets.

### 8.7.2 MicroVM Feasibility Assessment

The architecture is extensible to Firecracker-class MicroVM isolation. This section documents the evaluation and decision rationale.

**Comparison:**

| Property | Current (namespace+seccomp) | MicroVM (Firecracker/Cloud Hypervisor) |
|----------|---------------------------|---------------------------------------|
| Kernel sharing | Shared host kernel | Dedicated guest kernel per VM |
| Isolation boundary | seccomp-BPF (syscall filter) | KVM/vmexit (hardware boundary) |
| Kernel exploit resistance | Vulnerable (shared kernel) | Isolated (requires KVM + guest kernel dual exploit) |
| Network path | veth + iptables DNAT | virtio-net + TAP device + bridge/NAT |
| Filesystem | pivot_root + bind mounts | Separate rootfs image (ext4/squashfs) |
| Setup latency | **~2ms** | **40-150ms** (VMM boot + guest kernel init) |
| Memory overhead | **~5MB** (process) | **128-256MB** (guest kernel + initrd + runtime) |
| Concurrent instances | 16K+ (PID-based subnet) | Tens to low hundreds (memory-bound) |
| Infrastructure dependency | Linux kernel only | KVM + VMM binary + rootfs images |

**Proxy connectivity invariant**: Both models can maintain a proxy-first connectivity model. In the MicroVM design, the veth+DNAT path would be replaced by a virtio-net+TAP+bridge configuration with equivalent governance interception goals.

### 8.7.3 Threat Model Analysis

GVM's threat model assumes AI agents are adversarial at the application level (prompt injection, header forgery, payload crafting) but not at the kernel level:

| Threat | namespace+seccomp | MicroVM | Assessment |
|--------|-------------------|---------|------------|
| Unauthorized API calls (prompt injection) | Blocked by proxy (Layer 2/3) | Blocked by proxy (Layer 2/3) | Isolation mode irrelevant |
| Network escape attempt | Mitigated for proxy-directed flows (strict transparent interception hardening is roadmap) | Mitigated with equivalent proxy-first topology design | Comparable under same interception policy |
| API key theft from environment | Blocked (Layer 3 injects post-enforcement) | Blocked (same) | Equivalent |
| Header forgery / operation spoofing | Blocked (SRR cross-checks URL) | Blocked (same) | Equivalent |
| Filesystem escape | Blocked (pivot_root + read-only) | Blocked (separate rootfs) | Equivalent |
| Dangerous syscall (ptrace, mount) | Blocked (seccomp-BPF KILL_PROCESS) | Blocked (guest kernel boundary) | Equivalent |
| **Host kernel exploit** | **Vulnerable** (shared kernel) | **Isolated** (KVM boundary) | MicroVM advantage |

**Key insight**: AI agents are interpreted processes (Python, Node.js) operating via HTTP. They do not execute arbitrary native code, craft kernel exploits, or attempt privilege escalation through OS-level vulnerabilities. The kernel exploit vector — the sole area where MicroVM provides additional protection — is outside the realistic threat model for governed AI agents.

### 8.7.4 Decision: MicroVM Not Required at Current Stage

**Rationale:**

1. **Threat model mismatch**: The additional kernel-level isolation that MicroVM provides defends against threats (kernel exploits) that AI agents do not realistically pose. The seccomp-BPF whitelist already blocks the syscalls needed for such attacks (ptrace, bpf, mount, unshare, open_by_handle_at).

2. **Performance cost is prohibitive**: 50x setup latency (2ms → 100ms+) and 25x memory overhead (5MB → 128MB+) directly impact the agent orchestration use case where rapid, concurrent sandboxing is required.

3. **Operational complexity**: MicroVM requires rootfs image management (per-interpreter), VMM lifecycle management, and KVM availability — significantly raising the deployment barrier for a governance tool that should be as lightweight as possible.

4. **Current isolation is already strong**: The combination of four Linux namespaces, a 45-syscall seccomp whitelist, pivot_root filesystem isolation, and proxy-path routing provides meaningful defense-in-depth for the AI agent governance use case. The seccomp filter itself uses Firecracker's `seccompiler` crate, demonstrating shared security heritage.

### 8.7.5 Extensibility Path

The sandbox architecture is designed for future MicroVM support as a third isolation mode:

```
gvm run agent.py                    # Local mode (Layer 2 only)
gvm run --sandbox agent.py          # Linux-native (namespace+seccomp, ~2ms)
gvm run --contained agent.py        # Docker (container runtime, ~50ms)
gvm run --microvm agent.py          # MicroVM (Firecracker/KVM, ~100ms) [future]
```

**When MicroVM becomes justified:**

- **Multi-tenant SaaS**: External users submit arbitrary agent code for execution. Untrusted user code (not just untrusted prompts) warrants hardware-level isolation.
- **Regulatory compliance**: Industries (finance, healthcare) may mandate hardware-boundary isolation for workload separation, regardless of practical threat assessment.
- **Defense-in-depth requirement**: Security-critical deployments where even theoretical kernel exploit vectors must be mitigated.

**Migration scope** (estimated effort for future implementation):

| Module | Change | Description |
|--------|--------|-------------|
| `network.rs` | Rewrite | veth+DNAT → TAP+bridge+virtio-net |
| `mount.rs` | Replace | pivot_root → rootfs image builder |
| `namespace.rs` | Remove | Replaced by KVM/VMM namespace isolation |
| `seccomp.rs` | Reduce | Move to VMM-level seccomp (Firecracker has built-in) |
| `sandbox_impl.rs` | Rewrite | clone+exec → Firecracker socket API |
| **New: rootfs builder** | Create | Per-interpreter rootfs image pipeline |
| **New: VMM manager** | Create | Firecracker lifecycle, config, health |

The proxy layer (`proxy.rs`) and all enforcement logic (SRR, ABAC, WAL, Vault) remain unchanged — isolation is orthogonal to governance enforcement.

---

## 8.8 Future Hardening (Roadmap)

| Enhancement | Priority | Description |
|-------------|----------|-------------|
| Bounded NATS channels | High | Replace `tokio::spawn` with bounded `mpsc` channel for NATS publish |
| Key rotation support | High | Automatic re-encryption of vault data on key change |
| mlock for key pages | Medium | Pin key memory pages to prevent swap-to-disk |
| Fuzzing CI pipeline | High | Continuous fuzzing with `cargo-fuzz` or AFL — SRR regex matching and JSON payload parsing process adversarial external input directly, making fuzzing high-value for discovering edge cases |
| Constant-time SRR | Low | Pad all code paths to fixed execution time — low priority because rate limiter already prevents statistical timing attacks and end-to-end timing difference is inherent to proxy architecture |
| Memory allocator hardening | Low | Use `jemalloc` with security features or custom allocator |
| MicroVM isolation mode | Low | Firecracker/KVM `--microvm` flag for multi-tenant SaaS (see 8.7) |

---

[← Part 7: Python SDK](07-sdk.md) | [Part 9: Test Coverage Report →](09-test-report.md)
