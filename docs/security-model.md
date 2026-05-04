# Security Model & Known Attack Surface

> **Last updated**: 2026-03-30

## Purpose

GVM's primary threat model targets **accidental misuse by LLM-powered agents** — for example, a prompt-injected agent attempting to wire money or delete data. GVM is **not** designed to defend against a skilled adversary with direct network access who is actively trying to reverse-engineer the policy engine.

This document catalogues known adversarial attack vectors for transparency. Each entry describes the attack, its preconditions, and a planned mitigation path. These are **documented and acknowledged**, not ignored — they will be addressed as the deployment context demands.

---

## Threat Model Boundary

| In scope (v1) | Out of scope (v1) |
|---|---|
| Agent makes unintended API calls due to prompt injection | Attacker has root access to the proxy host |
| Agent tries to exfiltrate data via HTTP to unknown hosts | Attacker modifies proxy binary at rest |
| Agent escalates privilege by crafting high-IC operations | Nation-state level side-channel exploitation |
| Misconfigured policy allows overly broad access | Physical access to hardware |

---

## Assumption of Trust

GVM assumes the underlying host OS and filesystem are secure. This is consistent with every infrastructure tool that runs as a userspace process (Envoy, OPA, Nginx, HAProxy).

- **Disk integrity**: WAL and config file protection is handled by OS-level file permissions (`0600`) and disk encryption. GVM detects tampering via Merkle chain but does not prevent filesystem writes. Config file tampering between restarts is detectable via SHA-256 hashes recorded in the Merkle chain at each startup (see Section 6.1).

- **Secret management**: GVM Vault encrypts agent state at rest. Master key management should use KMS/HSM in production. GVM is not a secrets manager.

- **Process isolation**: GVM secures the **Agent-to-World boundary**. Host-to-Proxy security is the infrastructure provider's responsibility.

If an attacker has root access to the host, GVM — like any userspace process — cannot provide security guarantees. This is not a limitation specific to GVM; it is a fundamental property of software-based security. Vulnerabilities that require local privilege escalation or filesystem access are not GVM bugs — they belong to the OS, container runtime, or infrastructure layer.

---

## Known Adversarial Attack Vectors

### 1. Timing Side Channel

**Attack**: An adversary measures response latency to infer the enforcement decision type.

**Two distinct timing signals exist**:

1. **Engine-level** (SRR evaluation): Allow ~28 ns, Deny ~63 ns. The ~35 ns difference is 3-5 orders of magnitude below network jitter (0.1-10 ms) — practically unobservable.

2. **End-to-end** (response time): Deny returns immediate 403 (~3 ms). Allow/Delay forwards to upstream (~50-500 ms). This difference is **architecturally inherent to every proxy-based enforcement system** (Envoy, OPA, Nginx). A blocked request is always faster than a forwarded one because no upstream call is made. This is not a GVM-specific vulnerability.

**Why timing attacks are impractical**:

- **Token budget caps sample volume**: Timing attacks require thousands of repeated measurements. The per-agent `TokenBudget` (60-slot circular buffer over the last hour) bounds request/token volume; exceeding it produces a 403 with a `budget_exceeded` reason logged to WAL — the attack attempt is self-documenting.
- **The signal is redundant**: Deny decisions are explicitly communicated via HTTP 403 and `X-GVM-Decision: Deny` headers. Timing reveals nothing the response doesn't already state.
- **Constant-time padding conflicts with design**: IC-2 Delay (300+ ms) is an intentionally visible timing signal for enforcement feedback.

**Status**: Not constant-time by design. Timing attack is impractical due to rate limiting. Constant-time SRR matching is a low-priority future consideration, not a v2 target.

---

### 2. Optional Wasm Runtime Integrity (Roadmap Scope)

**Attack**: If optional Wasm decision mode is enabled and the module loading path is compromised, a malicious module could be loaded.

**Preconditions**: Deployment explicitly enables Wasm decision mode and an attacker has write access to the Wasm module path or config.

**Current (v1)**: Request hot-path decisions are evaluated by the native policy engine. A Wasm loader exists, but it is not the default enforcement path.

**Impact (when enabled)**: Arbitrary policy logic execution within the Wasm sandbox boundary.

**Roadmap mitigation**: (1) Hot-path Wasm activation with parity tests against native decisions, (2) Ed25519 signature verification + hash pinning, and (3) fail-close startup when Wasm mode is required.

**Status**: Roadmap hardening item. Not active on the default runtime path.

---

### 3. Proxy Bypass via Direct HTTP

**Attack**: If the agent's HTTP client is not forced through the proxy (e.g., environment variable `HTTP_PROXY` unset, or agent uses a raw socket), all GVM enforcement is bypassed.

**Preconditions**: Agent code or runtime environment not properly configured.

**Impact**: Complete policy bypass — no enforcement, no audit trail.

**Current (v1)**:
- Cooperative default: SDK sets `HTTP_PROXY` via `GVMAgent.create_session()`.
- **Enforced mode**: `gvm run --sandbox` (Linux namespace + veth + TC filter + iptables + seccomp). Three-layer defense-in-depth: (1) TC ingress filter on host-side veth (kernel-enforced, no userspace bypass), (2) iptables OUTPUT chain inside sandbox, (3) seccomp AF_NETLINK blocking prevents iptables modification.
- Docker containment: `gvm run --contained` is production-ready on Linux and WSL2. It uses a dedicated Docker bridge plus host-side iptables egress lock to prevent direct network bypass, but it deliberately does not perform MITM; HTTPS enforcement is SNI/domain-level only. On native macOS or native Windows outside WSL2, Docker Desktop's hidden VM prevents host iptables control, so contained mode falls back to cooperative proxy routing with a visible warning.
- Limitation: containment is opt-in and process-scoped. Processes not launched via `gvm run` still rely on cooperative proxy routing.

`gvm run --sandbox` interception path (implemented):

```
gvm run --sandbox my_agent.py
  → clone(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET)
  → veth pair: agent ns ↔ host (10.200.X.1/30 ↔ 10.200.X.2/30)
  → HTTP_PROXY/HTTPS_PROXY set in child env
  → Host-side:
      iptables DNAT: host-veth:proxy_port → configured proxy_addr
      iptables MASQUERADE: restricted to proxy port TCP only
      iptables FORWARD: veth↔lo ACCEPT, veth→* DROP
  → Sandbox-side (OUTPUT chain lockdown):
      iptables OUTPUT -o lo → ACCEPT
      iptables OUTPUT ESTABLISHED,RELATED → ACCEPT
      iptables OUTPUT -p tcp -d host_ip --dport proxy_port → ACCEPT
      iptables OUTPUT -p udp -d host_ip --dport 53 → ACCEPT
      iptables OUTPUT → DROP (all else)
  → IPv6 fully disabled (sysctl + ip6tables DROP fallback)
  → resolv.conf aligned to host veth IP (DNS resolution via host only)
  → seccomp-BPF: ~130 syscalls whitelisted
```

Defense-in-depth enforcement layers (v0.2.4):

1. **TC ingress filter** (host-side veth): Kernel-level packet filtering on the host-side of the veth pair. Allows only TCP to proxy IP:port, UDP to proxy IP:53, and ARP. Runs in the host network namespace — the agent cannot modify or detach it even with `CAP_NET_ADMIN` inside its user namespace. Falls back to iptables-only on kernels < 4.15.

2. **iptables OUTPUT chain** (sandbox-side): Traditional firewall rules inside the sandbox. Provides enforcement even without TC filter, but is potentially modifiable by the agent via netlink sockets (mitigated by seccomp, see below).

3. **seccomp socket domain filtering**: The `socket()` syscall is argument-filtered to only allow AF_UNIX (1), AF_INET (2), AF_INET6 (10), and AF_NETLINK (16). AF_NETLINK is allowed because `getaddrinfo()` requires `NETLINK_ROUTE` for DNS resolution (safe: all capabilities are dropped, so netlink cannot modify iptables). AF_PACKET (17) is blocked by `SECCOMP_RET_KILL_PROCESS`. This prevents agents from creating netlink sockets to modify iptables rules inside the sandbox — closing the CAP_NET_ADMIN escape vector where `CLONE_NEWUSER` grants apparent root with `CAP_NET_ADMIN` for the associated network namespace.

4. **seccomp dual filter audit logging** (v0.2.5): Two seccomp-BPF filters are stacked in LIFO order — a Log filter (installed first, evaluated second) and a KillProcess filter (installed second, evaluated first). The kernel evaluates all filters and takes the strictest result (`SECCOMP_RET_KILL_PROCESS`), but the Log filter also emits a `type=SECCOMP` audit record to the kernel log (`dmesg | grep SECCOMP` or `ausearch -m SECCOMP`). This provides both enforcement AND an audit trail for blocked syscalls. The parent process detects violations via `WaitStatus::Signaled(_, SIGSYS, _)` and logs them with the child PID for correlation with kernel audit records.

After sandbox network setup, the agent can only reach: (1) GVM proxy via TCP on the host veth IP, (2) DNS via UDP 53 on the same host veth IP, (3) loopback. All other egress is dropped at multiple layers. IPv6 is disabled to prevent bypassing IPv4 firewall rules.

5. **Sandbox resource cleanup** (v0.3): Per-PID state files (`/run/gvm/gvm-sandbox-{pid}.state`) record all resources created by each sandbox (veth, iptables rules, mounts, cgroups). On normal exit, cleanup + delete. On crash, the next `gvm run --sandbox` detects stale state files (dead PIDs) and auto-cleans orphan resources before proceeding. `gvm cleanup` provides manual recovery. Defense-in-depth: heuristic scan removes `veth-gvm-*` interfaces without corresponding state files. State files are stored in `/run/gvm/` (root-owned tmpfs) rather than `/tmp` to prevent symlink-based TOCTOU attacks.

**DNS governance (v0.5)**: DNS queries from sandboxed agents pass through a built-in DNS governance proxy that classifies each query and applies graduated delay.

**Position change (v0.5)**: This section previously stated "DNS filtering is a DLP concern — building it into GVM would create more problems than it solves." That position is revised. GVM's direction has shifted from "governance proxy" to "secure runtime." As a runtime that claims to isolate agent I/O, leaving DNS as an unmonitored bypass channel is a gap the project can't justify. AWS Route 53 DNS Firewall and similar products demonstrate that full DNS threat-intelligence filtering requires massive surface area (feed management, CDN rotation handling, mDNS/LLMNR compatibility) that would bloat GVM's scope. However, doing nothing is also untenable.

**Approach — Delay-Alert, no Deny**: DNS denial kills the entire agent, and one false positive becomes a service outage. Instead, GVM uses a tiered delay gradient:

| Tier | Condition | Action |
|------|-----------|--------|
| **1 (known)** | Domain in SRR known_hosts (learned via `gvm suggest`) | Free pass, 0ms |
| **2 (unknown)** | First-seen domain | Delay 200ms + WAL log |
| **3 (anomalous)** | >5 unique subdomains on same unknown base domain in 60s window | Delay 3s + alert |
| **4 (flood)** | >20 global unique subdomain queries in 60s window | Delay 10s + alert |

**Decay**: When the anomalous pattern stops, the sliding window expires and the domain falls back to Tier 2. The system never permanently escalates — it adapts in both directions.

**Why delay, not deny**: (1) False positive resilience — a new legitimate API domain costs 200ms, not an outage. (2) Attacker deception — the agent (or attacker) sees "network is slow," not "blocked," and wastes time instead of immediately pivoting. (3) Human intervention window — 3-10 seconds of delay is enough for an operator to see the alert and decide.

**Disable**: `--no-dns-governance` CLI flag or `dns.enabled = false` in proxy.toml. Use this when dedicated DNS security tools (Route 53 Firewall, Cloudflare Gateway, Cisco Umbrella) are already in place.

**Remaining limitation**: DNS-over-HTTPS (DoH) to a provider the agent already has HTTPS access to (e.g., `https://dns.google/resolve?name=...`) bypasses the UDP DNS proxy entirely. This is mitigated by the HTTP governance layer — the DoH request itself is an HTTP call that hits SRR rules. A Deny rule on known DoH endpoints (`dns.google`, `cloudflare-dns.com/dns-query`) closes this gap.

**Environment compatibility**:

| Kernel | TC filter | iptables | seccomp AF_NETLINK | Enforcement |
|--------|-----------|----------|--------------------|-------------|
| >= 4.15 | Active | Active | Active | Triple-layer (kernel-enforced) |
| 3.17 - 4.14 | Fallback | Active | Active | Dual-layer (seccomp prevents iptables escape) |
| < 3.17 | N/A | Active | N/A | iptables only; prefer `--contained` on Linux/WSL2 or upgrade kernel for sandbox |

**Roadmap (v2)**: Move from opt-in containment to deployment-level mandatory interception profiles (policy-enforced launch path + identity attestation).

---

### 4. ReDoS in Policy Regex — Non-Issue

**Attack**: A crafted path pattern in `gvm.toml` could cause catastrophic backtracking in the regex engine, leading to CPU exhaustion.

**Status**: **Not applicable.** GVM uses Rust's `regex` crate (v1), which is automata-based (Thompson NFA → DFA). It guarantees O(n) linear-time matching regardless of pattern complexity — no backtracking, no catastrophic performance. This is architecturally immune to ReDoS, unlike PCRE/Python `re`/JavaScript regex engines.

Regex usage in GVM:
- **SRR network rules** (`srr.rs`): `path_regex` field — pre-compiled at TOML load time, `re.is_match()` at runtime

Patterns are pre-compiled at config load time (fail-fast on invalid patterns) and reused at runtime — zero per-request compilation overhead. Config files are admin-controlled, not agent-controlled, providing an additional layer of defense-in-depth.

---

### 5. Checkpoint Step Authorization

**Attack**: An agent could potentially craft a `restore_step` value to roll back to an arbitrary checkpoint, not just the last approved one.

**Preconditions**: Agent can influence the checkpoint restore logic (requires code-level access or a bug in the SDK).

**Impact**: State rollback to an unintended point, potentially replaying approved operations.

**Current mitigation (v0.2)**: Merkle tree verification on checkpoint restore. Each checkpoint's `SHA-256(plaintext)` is a leaf in a per-agent Merkle tree — the same tree structure used for WAL audit batch verification (`merkle.rs`). On save, the proxy appends the leaf and recomputes the tree root. On restore, the proxy generates an O(log N) Merkle proof for the requested leaf and verifies it against the root via `verify_merkle_proof()`. The SDK performs additional client-side hash verification. Tampering with any checkpoint invalidates the root, detected on any subsequent restore.

**Planned (v2)**: HMAC-signed checkpoint IDs with proxy-held signing key. The current Merkle tree prevents content tampering but does not prevent step ID spoofing (which requires code-level SDK access).

---

### 6. WAL Periodic Re-verification

**Attack**: If the WAL file is tampered with on disk (e.g., events deleted or modified), the Merkle root chain becomes inconsistent, but this is only detected on the next append — not proactively.

**Preconditions**: Write access to the WAL file on disk.

**Impact**: Audit log integrity compromised silently until next write.

**Planned mitigation**: Background periodic WAL integrity scan (verify Merkle chain from genesis). WAL file permissions should be restricted (`0600`). Not implemented in v1 because the MVP runs locally where disk tampering is outside the threat model.

---

### 6.1 Config File Tamper Detection (Implemented)

**Attack**: An attacker modifies `gvm.toml` (SRR rules, credentials, budget) on disk between proxy restarts, weakening governance without leaving an obvious trace.

**Mitigation (v1)**: At startup, the proxy records SHA-256 hashes of all loaded config files as a `gvm.system.config_load` event in the Merkle chain via `append_durable()`. The hashes are stored in the event's `context` field as `label → hex digest` pairs.

**Detection**: An auditor compares `gvm.system.config_load` events across restarts. A hash mismatch indicates the config file was modified between runs. Because the event is in the Merkle chain, the hash record itself is tamper-evident — an attacker cannot retroactively alter the recorded hash without breaking the chain, which any auditor will detect on verification.

**Scope**: Detects file modification after the fact. Does not prevent loading a tampered config (the proxy still starts with whatever files are on disk). Real-time prevention requires file integrity monitoring (e.g., IMA/EVM, AIDE) at the OS level.

**Known limitation**: Policy hot-reload (P3 roadmap) will need to re-record hashes on each reload event. Not yet implemented.

---

### 7. Vault Key Derivation

**Attack**: The current Vault (encrypted agent state cache) encryption key is derived directly from the `VAULT_KEY` environment variable without a key derivation function (KDF). If the key has low entropy, brute-force is feasible.

**Preconditions**: Access to the encrypted Vault data and knowledge that no KDF is applied.

**Impact**: Agent state (checkpoints, conversation history) decrypted. Note: Vault does not store API credentials — those are in `APIKeyStore`.

**Planned mitigation**: Apply PBKDF2 or Argon2id with configurable iteration count before using the key for AES-GCM. Not implemented in v1 because the Vault is a local-development feature and production deployments should use a proper secrets manager. See [Changelog](internal/CHANGELOG.md) for full feature tracking.

---

### 8. Agent Identity (Partially Mitigated)

**v1 (default)**: Self-declared `X-GVM-Agent-Id` header. Spoofable on shared networks.

**v1.1 (opt-in)**: JWT-based identity verification via `POST /gvm/auth/token`. When `GVM_JWT_SECRET` env var is set (hex-encoded, min 32 bytes HMAC-SHA256 key):
- Proxy issues JWTs with `agent_id`, `tenant_id`, `scope` claims
- `Authorization: Bearer <token>` is verified; claims override self-declared headers
- Rate limiter uses verified `agent_id` (spoofing prevented)
- Backward-compatible: without JWT configured, header-based identity continues

**Remaining limitation**: Token issuance endpoint (`POST /gvm/auth/token`) is unauthenticated in v1. Acceptable for the single-host deployment where `gvm run` and the proxy are co-located on the same trust boundary. Network-exposed token issuance (e.g., when the issuance endpoint is reachable from outside the host) should add mTLS or front it with an upstream auth gateway.

### 9. IPv4-Mapped IPv6 Bypass (Fixed)

**Attack**: Bypass SSRF deny rules by using IPv6 notation (e.g., `[::ffff:127.0.0.1]` instead of `127.0.0.1`).

**Status**: Fixed in v0.2. `normalize_host()` canonicalizes IPv6 loopback, IPv4-mapped, and cloud metadata addresses before SRR matching.

### 10. GraphQL Alias Bypass

**Attack**: Current SRR payload inspection matches the `operationName` field only. An attacker can omit `operationName` or use GraphQL aliases in the query body to bypass detection. For example, a mutation named `TransferFunds` could be aliased as `t: transferFunds(...)` in the `query` field without setting `operationName`.

**Preconditions**: Agent sends requests to a GraphQL endpoint that has payload-based SRR rules.

**Impact**: High-risk GraphQL operations (e.g., `TransferFunds`, `DeleteAccount`) could bypass the Deny rule and fall through to a less restrictive URL-only rule.

**Planned mitigation (v2)**: GraphQL query parser that inspects the `query` field for mutation names, field names, and aliases. Until then, GraphQL endpoints should be treated as elevated risk — consider Deny-by-default for GraphQL endpoints with allowlisted `operationName` values only.

**Why acceptable now**: Current deployments are expected to pair payload rules with URL-based Deny rules for high-risk GraphQL endpoints. An alias bypass evades the `operationName` match but cannot evade a URL-level Deny on the mutation endpoint itself.

---

### 11. Numeric Precision in Policy Evaluation

**Issue**: Policy numeric comparisons (`Gt`, `Lt`, `Gte`, `Lte`) convert all values to `f64` via `value_as_f64()`. In financial domains, floating-point rounding could cause boundary-case policy bypass (e.g., `500.000000000001` might round to `500.0`, passing a `> 500` rule check).

**Impact**: Edge-case policy bypass for exact boundary values in precision-sensitive domains.

**Current (v1)**: Standard IEEE 754 `f64` comparison. Sufficient for most use cases where amounts are integer cents or have limited decimal places.

**Planned mitigation**: Decimal-based comparison for currency fields, or integer-cent normalization at the SDK layer. For now, operators should write rules with appropriate margins (e.g., `>= 500` instead of `> 499.99`).

---

### 12. WAL Recovery Memory Pressure (Fixed)

**Issue**: `recover_from_wal()` originally used `tokio::fs::read_to_string()` which loaded the entire WAL into memory, and tracked all event_ids in an unbounded `HashSet` for deduplication — both causing OOM risk on large WALs.

**Fix (v0.2)**: Two-part fix:
1. **Streaming**: Switched to `BufReader` with line-by-line streaming (no full-file load).
2. **High watermark**: Replaced the unbounded `HashSet` with a sidecar file (`<wal_path>.watermark`) that stores the byte offset of the last completed recovery. Subsequent recoveries seek directly to the watermark and scan only new events — O(1) memory, zero false positives. The watermark is written atomically (write-tmp + rename) to prevent partial state.

---

### 13. WAL Single Point of Failure (Mitigated)

**Issue**: Prior to v0.2.1, a primary WAL I/O failure caused all IC-2/3 requests to return 500 (Fail-Close). While correct from a safety perspective, this meant a single disk hiccup could halt all agent operations.

**Mitigation (v0.2.1)**: Emergency WAL fallback + Circuit Breaker.

- **Emergency WAL** (`ledger.rs`): When the primary WAL (group commit + Merkle) fails, the Ledger automatically falls back to a secondary append-only log file (`wal_emergency.log`). This provides a degraded-but-auditable mode — events are still recorded, but without Merkle integrity guarantees. Only if both primary and emergency WALs fail does the true Fail-Close activate.

- **Circuit Breaker** (`proxy.rs`): After 5 consecutive primary WAL failures, the proxy returns `503 Service Unavailable` with `Retry-After: 30s` for IC-2/3 requests. IC-1 (Allow) requests continue unaffected. This prevents cascading failures and gives the primary WAL time to recover.

- **Observability**: `Ledger::primary_failure_count()` and `Ledger::emergency_write_count()` expose metrics for monitoring. The circuit breaker decision is logged and included in the response as `CircuitBreakerOpen`.

**Automated on restart**: Primary WAL recovery scans for Pending events and marks unresolved ones as Expired via watermark-based idempotent recovery (O(1) memory). **Remaining gap**: Emergency WAL events are not auto-merged back into primary WAL — operator should review `wal_emergency.log` after a primary WAL outage to verify no events were lost.

---

### 14. WAL Rotation (Implemented)

**Status: Fixed.** Size-based rotation is implemented with Merkle chain linking across segments.

- `max_wal_bytes` (default 100MB): triggers rotation when exceeded
- `max_wal_segments` (default 10): prunes oldest segments beyond limit
- Inter-batch `prev_root` carries over across rotation — Merkle chain integrity maintained across segment boundaries
- Configurable via `[wal]` section in `proxy.toml`

**Remaining gap**: No compaction (old events within a segment cannot be removed). Segment pruning is the current mitigation. **Retention warning**: Without NATS JetStream, pruned segments are permanently lost. Default settings (100MB x 10 segments = 1GB) can fill within days under high request volume. Long-running deployments requiring audit trail retention must configure NATS replication.

---

### 15. WAL Sequence Number Persistence (Implemented)

**Status: Fixed.** `wal_sequence` is initialized from existing WAL event count on startup — monotonic across restarts.

```rust
// ledger.rs — recovery initializes from existing events
self.wal_sequence.store(event_count, Ordering::SeqCst);
// "WAL sequence initialized from existing events (monotonic across restarts)"
```

**Remaining gap**: NATS JetStream integration is stubbed — sequence numbers are local-only until JetStream is connected.

---

### 16. Tokio Worker Starvation on TLS Cert Generation (Fixed)

**Issue**: `GvmCertResolver::resolve()` (rustls sync callback) ran CPU-bound ECDSA keygen directly on tokio worker threads. 50 concurrent new-domain TLS handshakes would starve all async I/O — WAL writes, HTTP proxy, policy evaluation.

**Fix (v0.2)**: Two-phase approach: `peek_sni()` extracts SNI from raw TCP via `stream.peek()` (non-consuming), then `ensure_cached()` offloads keygen to `tokio::task::spawn_blocking`. The TLS handshake always hits cache (0ns). Sync fallback preserved for correctness.

---

### 17. HTTP Request Smuggling in TLS MITM Path (Fixed)

**Issue**: `read_http_request` in the TLS MITM pipeline accepted requests with both `Content-Length` and `Transfer-Encoding` headers. Parser desync between httparse (GVM) and the upstream server could let an attacker smuggle a second request inside the body of the first, bypassing SRR inspection.

**Fix (v0.2)**: Zero-tolerance rejection per RFC 7230 §3.3.3:
- Reject if both `Content-Length` and `Transfer-Encoding` are present
- Reject if multiple `Content-Length` headers have differing values
- 400 error (connection dropped) on any violation

**Note**: The HTTP proxy path (port 8080) is protected by hyper/axum which enforces RFC 7230 strictness internally. This fix covers the TLS MITM path (port 8443) which uses raw httparse.

---

### 18. FD Exhaustion / Slowloris on TLS Listener (Fixed)

**Issue**: TLS listener (port 8443) accepted unlimited connections with no timeout on handshake or read. Slowloris attacks (1 byte/sec) could exhaust the FD limit (ulimit -n), preventing WAL writes and HTTP listener accept().

**Fix (v0.2)**:
- `Semaphore(1024)` bounds concurrent TLS connections (matching HTTP listener's ConcurrencyLimit)
- 10s TLS handshake timeout (drops incomplete ClientHello)
- 30s HTTP request read timeout in `read_http_request`
- 60s upstream relay timeout (prevents zombie connections on hanging upstreams)

---

### 19. Sandbox PID 1 Zombie Accumulation (Fixed)

**Issue**: `CLONE_NEWPID` makes the agent process PID 1 in its namespace. PID 1 is responsible for reaping orphaned children via `waitpid()`. Agent interpreters (Python, Node) don't implement this — orphaned subprocesses become zombies, eventually exhausting the PID table.

**Fix (v0.2)**: `fork()` inside the namespace after setup. PID 1 stays as a minimal init reaper (`waitpid(-1)` loop), the child execs the agent. Equivalent to tini/dumb-init without an external dependency. Agent exit code is correctly propagated to the parent outside the namespace.

### 20. Agent Self-Approval of IC-3 Requests (Fixed)

**Attack**: An agent triggers an IC-3 (RequireApproval) request, then immediately calls `POST /gvm/approve` on the proxy to approve its own request. If the approval API is served on the same port as the proxy (which the agent knows via `HTTP_PROXY`), the agent can bypass human-in-the-loop enforcement entirely.

**Secondary vector**: The agent inherits stdin from the CLI process. When `gvm run` polls for IC-3 approvals and prompts "Approve? [y/N]" on stdin, the agent could race to read stdin first, or inject terminal escape sequences to manipulate the operator's view.

**Fix (v0.4)**:
1. **Admin API port separation**: Privileged endpoints (`/gvm/approve`, `/gvm/pending`, `/gvm/reload`, `/gvm/info`) are served on a separate admin port (default: 9090), not the agent-facing proxy port (8080). The agent only knows `HTTP_PROXY=http://...:8080`. The admin port is never injected into the agent's environment. In `--sandbox` mode, iptables rules only allow traffic to the proxy port — the admin port is unreachable from the agent namespace.

2. **stdin isolation**: Agent processes are spawned with `stdin(Stdio::null())`. The agent cannot read from or compete for the operator's terminal input. The CLI's IC-3 approval prompt reads from the operator's stdin exclusively.

**Residual risk**: In non-sandbox mode, the agent runs on the host and could discover the admin port via port scanning or `/proc` inspection. This is inherent to cooperative enforcement — use `--sandbox` or `--contained` for structural isolation.

**Future hardening**: Admin API on Unix domain socket (`/run/gvm/admin.sock`) would eliminate TCP port discovery entirely.

### 21. MITM CA Private Key Exposure in Sandbox (Fixed)

**Attack**: If the CA private key used for MITM TLS interception were accessible inside the sandbox, the agent could extract it and generate valid certificates for any domain, completely bypassing TLS inspection. The agent could forge certificates, establish direct TLS connections to upstream servers, and the proxy would be unable to distinguish forged traffic from legitimate traffic.

**Audit findings** (v0.4):

The CA key flow was audited end-to-end:

| Location | CA Key Present? | Notes |
|----------|-----------------|-------|
| Proxy process memory (`main.rs`) | **Yes** | Held in `GvmCertResolver` for leaf cert signing. Required for MITM operation. |
| TLS MITM listener (`tls_proxy.rs`) | **Yes** | Same process as proxy. Runs outside sandbox. |
| Sandbox tmpfs filesystem | **No** | Only CA **certificate** (public) written to `/etc/ssl/certs/gvm-ca.crt` |
| Sandbox environment variables | **No** | `SSL_CERT_FILE` etc. point to cert path only |
| Sandbox `/proc` access | **No** | PID namespace isolation. Agent sees only its own `/proc/<pid>` |
| Sandbox ptrace/process_vm_readv | **No** | Blocked by seccomp-BPF whitelist |

**Prior vulnerability (fixed in v0.4)**: The sandbox (`sandbox_impl.rs`) previously generated its own independent CA, separate from the proxy's CA. This caused a CA mismatch — the trust store had CA-B but the MITM proxy signed with CA-A — making HTTPS inspection non-functional. This was an implementation bug, not a security exposure (the key never reached the sandbox, but the mismatch broke MITM).

**Fix (v0.4)**:
1. CA generation removed from `sandbox_impl.rs`. The proxy (`main.rs`) is the sole CA generator.
2. CLI downloads the CA cert from `GET /gvm/ca.pem` before sandbox launch and passes it via `SandboxConfig.mitm_ca_cert`.
3. The sandbox receives only the public certificate — the private key stays in the proxy process.
4. On proxy shutdown, the CA key PEM bytes are explicitly zeroized (`zeroize` crate).
5. `EphemeralCA::drop()` zeroizes both the cert PEM and a serialized copy of the key PEM.

**Architecture**: The proxy process runs outside all sandboxed namespaces. The agent process runs inside user/PID/mount/net namespaces with seccomp-BPF. These are separate processes with no shared memory. The CA key exists only in the proxy's address space.

**Trust store coverage and limitations**:

| Runtime | CA Trust Mechanism | Status |
|---------|-------------------|--------|
| Python (requests, urllib3) | `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` env var | Supported |
| Node.js | `NODE_EXTRA_CA_CERTS` env var | Supported |
| Go (net/http) | System trust store (`/etc/ssl/certs/`) | Supported |
| curl / libcurl | `CURL_CA_BUNDLE` env var | Supported |
| Ruby (net/http) | `SSL_CERT_FILE` env var | Supported |
| Java (HttpsURLConnection) | Requires JKS keystore import (`keytool`) | **Not auto-supported** |
| Certificate pinning apps | Reject any MITM CA regardless of trust store | **Cannot intercept** |

Java keystore import is planned as a future enhancement. Certificate pinning is a deliberate security feature; bypassing it is out of scope for GVM.

**Residual risk**: The CA key exists in proxy process memory for the session duration. A host-level memory dump (e.g., `gcore`, `/proc/<pid>/mem`) could extract it. This requires host root access, which is outside GVM's threat model boundary.

---

## Enforcement Decision Behavior

### Decision Types and Agent-Side Behavior

GVM enforces governance at the HTTP proxy layer. The proxy returns standard HTTP responses to the agent — it does not control agent process lifecycle.

| Decision | Proxy Behavior | HTTP Response | Agent Receives |
|----------|---------------|---------------|----------------|
| **Allow** | Immediate forward, async audit | Upstream response (2xx/4xx/5xx) | Normal response |
| **Delay** | WAL write, hold N ms, then forward | Upstream response (delayed) | Normal response (slower) |
| **Deny** | Block request, WAL write | `403 Forbidden` with error JSON | HTTP 403 error |
| **RequireApproval** | Block request, WAL write | `403 Forbidden` with `RequireApproval` decision | HTTP 403 error |

### What Happens When an Agent is Denied

GVM returns an HTTP 403 response. **What the agent does next is entirely the agent's design responsibility**, not GVM's:

- An agent using the Python SDK receives a `GVMDeniedError` exception, which can trigger checkpoint rollback.
- An agent using raw HTTP receives a 403 status code and must handle it in its own error handling logic.
- GVM does **not** kill, pause, or signal the agent process. The agent remains running and can attempt other operations.

This is by design: GVM governs individual I/O operations at the proxy boundary, not agent process lifecycle. An agent that receives a Deny can retry (and be denied again), fall back to alternative logic, or crash — all of which are agent-level design decisions.

### RequireApproval (IC-3) — Scope Boundary

`RequireApproval` exists as a decision type in the policy engine. The proxy blocks the request and records the event in the WAL.

**What GVM does NOT provide:**
- No built-in approval UI, webhook, or notification system
- No approval queue or pending-request store
- No mechanism to "resume" a blocked request after human approval

**Why this is correct:**
Human-in-the-loop (HITL) approval workflows are application-layer concerns. The mechanism for collecting approval (Slack bot, admin dashboard, email, CLI prompt) varies by deployment context. GVM's role is to **enforce the block** and **record the event** — the approval workflow is built on top of GVM's audit trail, not inside it.

**Practical IC-3 implementation pattern:**
1. Agent calls an IC-3 operation → proxy returns 403 with `RequireApproval`
2. Agent SDK catches the error and halts that workflow branch (agent design)
3. External system (monitoring, Slack bot, dashboard) reads WAL event and notifies approver
4. Approver updates policy (temporary Allow rule or one-time override)
5. Agent retries → proxy now returns Allow

This pattern keeps GVM focused on enforcement and audit, while approval UX is delegated to the deployment environment.

---

## Non-Adversarial Issues

The following issues have been identified and **fixed** as they affect normal operation, not just adversarial scenarios:

| Issue | Fix | Status |
|---|---|---|
| Upstream X-GVM-* header poisoning | Strip all `X-GVM-*` headers from upstream responses before injecting proxy headers | Fixed |
| API key strip scope (only `Authorization`) | Also strip `X-API-Key`, `Cookie`, `ApiKey` headers when injecting credentials | Fixed |
| Thread-unsafe `_gvm_header_setter` global | Replace with per-instance context variable approach | Fixed |
| Mock server runs in production | Add `GVM_ENV` guard to prevent accidental production use | Fixed |
| MITM credential CRLF injection | `contains_header_injection_chars()` rejects CR/LF/NUL in credential values before raw byte insertion into `rebuild_raw_head()` | Fixed |
| SRR lock poison fail-open | All 5 `unwrap_or_else(e.into_inner())` sites replaced with immediate 500/deny on poison (consistent with rate_limiter) | Fixed |
| SRR path traversal via encoding | Path normalization with percent-decode, null-byte strip, dot-segment resolution | Fixed (v0.2) |
| Operation name header injection | Regex validation `[a-zA-Z0-9._-]+` on operation names | Fixed (v0.2) |
| IC-1 Allow path sets Confirmed without checking upstream | Check `response.status().is_success()` before setting EventStatus | Fixed |
| Policy field name typo silently ignored | Validate field names at load time; unknown fields cause load error | Fixed |
| Import chain attack (lazy import in except block) | Move `from gvm.errors import ...` to module top-level in `decorator.py` | Fixed |
| Checkpoint Merkle verification hardcoded `"true"` | Real content hash + chain verification; proxy computes SHA-256 of plaintext and chains with previous checkpoint | Fixed (v0.2) |
| `transport.method` always empty in WAL events | Capture `request.method()` before classification and inject into event | Fixed (v0.2.5) |
| Deny `ic_level` was 3 (same as RequireApproval) | Corrected to `ic_level: 4` matching IC-4 classification | Fixed (v0.2.5) |

---

## Audit Results (2026-03-16)

A comprehensive security audit was conducted covering all Rust proxy modules, Python SDK, and configuration files. The following reported items were analyzed and determined to be **non-issues** in the current architecture:

| Reported Item | Analysis | Why Not a Vulnerability |
|---|---|---|
| AES-GCM nonce reuse | 12-byte random nonce, Birthday bound ~2^48 | At 1000 writes/day, collision takes ~770M years. NIST 2^32 limit = 11.7 years at this rate |
| Unbounded X-GVM-Context header | hyper/axum HTTP parser limits header size (~64KB) | Oversized headers rejected at HTTP layer before deserialization |
| Operation name CRLF injection (proxy-side) | `HeaderValue::to_str()` rejects non-visible ASCII (\\r\\n) | Returns `None` → falls back to "unknown". CRLF cannot reach application logic |
| Checkpoint step u64::MAX | `format!("checkpoint:agent:{}", u64::MAX)` = ~50 byte string | No integer overflow, no memory issue. Normal HashMap key |
| SRR body size bypass | Payload rule skip → next rule continues → Default-to-Caution (Delay) | By design: URL-only rules and fallback catch unmatched requests |
| Vault `list_keys()` cross-agent | No API endpoint exposes this function | Internal method; not callable from outside the proxy |
| SDK credential headers pass-through | Proxy `api_keys.rs` already strips Authorization, Cookie, X-API-Key, ApiKey | Enforcement is at proxy (Layer 3), not SDK. Double stripping unnecessary |
| Rate limiter agent ID spoofing | Same root cause as unauthenticated proxy access | Not a separate vulnerability; addressed by deployment-level authentication |
| WAL event forgery / batch reordering | Requires WAL file write access | Covered by existing item #6 (WAL periodic re-verification) |
| Host override config injection | Requires `proxy.toml` write access | Covered by threat model boundary ("Attacker modifies config at rest" = out of scope) |

---

## Deployment Guide

### Single-Endpoint APIs (GraphQL, gRPC)

SRR is not limited to URL-only inspection. For APIs that multiplex operations over a single endpoint (e.g., `POST /graphql`, `POST /grpc`), SRR supports **payload-level inspection** via `payload_field` and `payload_match`:

```toml
# Block dangerous GraphQL mutations at the network layer
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds", "DeleteAccount", "DropDatabase"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Blocked GraphQL mutation" }

# Allow all other GraphQL operations with standard delay
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
decision = { type = "Delay", milliseconds = 300 }
```

The proxy parses the request body as JSON and checks the specified field against the match list. This ensures SRR can enforce governance on GraphQL mutations, gRPC methods, and any JSON-RPC style API — not just REST endpoints with distinct URLs.

**Payload inspection scope**: SRR payload inspection is limited to **top-level JSON string fields with exact case-sensitive equality matching**. Specifically:
- Only top-level keys are accessed (`json.get(field)`) — no nested field paths (e.g., `data.operationName` is not supported)
- Only string values are matched (`v.as_str()`) — numeric, boolean, null, array, and object values are ignored (the rule is skipped)
- Matching is literal string equality — no regex, no substring, no case-insensitive comparison
- When a payload rule is skipped (field missing, wrong type, no match, parse failure, body too large), evaluation **continues to the next rule**, not to Default-to-Caution

This scope is sufficient for GraphQL `operationName` and gRPC method fields, which are always top-level strings. For APIs that encode operation identity in nested fields or numeric values, add complementary URL-level Deny rules for high-risk endpoints or enforce at the application layer.

**Body size limit**: Each rule has a configurable `max_body_bytes` (default 64 KB). Bodies exceeding this limit skip payload inspection but continue to subsequent rules, where URL-only rules or the Default-to-Caution fallback (Delay 300 ms) apply.

---

### Agent Forgery Threat Taxonomy

SRR is the sole enforcement layer and evaluates only transport-layer data (HTTP method, host, URL path, request body) — never agent-declared headers. This property defeats most forgery attempts by construction: the agent cannot lie about what URL it is actually contacting.

| Attack Type | Description | SRR Sees | GVM Defense |
|------------|-------------|----------|-------------|
| **URL Spoofing in Headers** | Agent sets custom headers claiming a different target | Actual HTTP request line and Host header | Non-issue — SRR ignores agent-declared operation/resource headers |
| **Payload Value Forgery** | Agent sends `{"amount": 50000}` to an endpoint a rule assumed was low-value | SRR inspects only top-level string fields; numeric body values are out of scope | **Partial defense** — write URL-level Deny rules for all high-value endpoints |
| **GraphQL Alias Bypass** | Mutation aliased without setting `operationName` | SRR matches `operationName` literally | **Partial defense** — pair payload rule with URL-level Deny on the mutation endpoint |
| **Header Injection** | Agent injects `X-GVM-Decision: Allow` | SRR ignores all `X-GVM-*` headers from agents | Non-issue — proxy strips and ignores injected decision headers |

**Key security property**: Because SRR reads the actual transport request, the agent cannot simultaneously satisfy a safe rule and contact a dangerous endpoint. Its defense surface is the set of URL/method/payload-field patterns the operator writes.

**Known gap**: Payload value forgery is only partially defended. When the agent lies about *values* within a legitimate operation (correct URL, correct method), SRR has limited visibility because its payload inspection only covers top-level string fields with exact matching. Defense requires URL-level Deny rules on high-value endpoints or an application-layer check at the server.

---

### Network Binding

The default proxy configuration binds to `0.0.0.0:8080` (all interfaces) for development convenience. In production or shared-network deployments:

```toml
# config/proxy.toml
[server]
listen = "127.0.0.1:8080"  # localhost only
```

For Kubernetes or shared-cluster environments where multiple agent pods reach the same proxy, additionally apply:
- **NetworkPolicy**: restrict ingress to the proxy pod from agent pods only
- **mTLS**: mutual TLS between agent and proxy for identity verification
- **Service mesh**: Istio/Linkerd sidecar for transparent authentication

Without network-level isolation, any process on the same network can send requests with arbitrary `X-GVM-Agent-Id` headers, bypassing agent identity checks. (Cross-organization isolation is solved at the deployment layer — separate GVM runtime per organization — not by sharing one proxy across orgs.)

---

## Adversarial Test Coverage (v0.2.3)

28 tests in `tests/hostile.rs` + 21 JWT/auth unit tests in `src/auth.rs` covering:

| Category | Tests | What They Prove |
|----------|-------|----------------|
| Concurrency stress | 3 | SRR, rate limiter, vault under 50-500 concurrent tasks |
| WAL integrity | 3 | Tampered entries, group commit fail-close, emergency WAL fallback |
| Policy determinism | 5 (proptest) | `max_strict` commutativity, associativity, idempotence, Deny absorption |
| Bypass scenarios | 4 | HTTP case-smuggling, null bytes, unicode normalization, path traversal |
| Side-channel | 1 | SRR timing variance < 10x between match/no-match |
| Forgery | 2 | Header forgery defeated by SRR; upstream X-GVM-* header stripping |
| Garbage input | 1 | No panics on arbitrary method/host/path/body combinations |
| Secret zeroing | 1 | LocalKeyProvider key zeroed on drop |
| Backpressure | 1 | 500 concurrent WAL appends complete bounded |
| Agent spoofing | 1 | Rate limiter bucket isolation under spoofed agent IDs |
| Config poisoning | 3 | Malformed TOML rejected; catch-all Deny blocks all traffic |
| Config integrity | 2 | Config file SHA-256 hashes recorded in Merkle chain; missing files → `"unavailable"` |
| Payload forgery | 1 | Payload value forgery bypass documented; URL-level Deny rules required for high-value endpoints |
| Resource exhaustion | 2 | Rate limiter MAX_BUCKETS overflow + eviction; limits enforced post-cleanup |
| JWT auth | 17 | Issue/verify roundtrip, expiration, signature tampering, wrong secret, malformed tokens, secret zeroing |

Fuzz targets (`fuzz/fuzz_targets/`):
- `fuzz_srr`: Arbitrary method/host/path/body into SRR pattern matching
- `fuzz_wal_parse`: Arbitrary bytes as WAL event JSON parsing

---

### TLS Inspection (MITM-Only, uprobe Deprecated)

As of v0.5.0, the experimental uprobe-based TLS interception (SSL_write_ex hooking) has been removed. MITM (transparent TLS proxy) is the sole HTTPS inspection mechanism.

**HTTPS enforcement layers**:
- **L4 (proxy CONNECT tunnel)**: Domain-level enforcement — all agents, all TLS libraries.
- **L7 (MITM TLS proxy)**: Full request inspection (method, path, headers, body) — requires CA trust injection.
- **TC ingress filter**: Kernel-level u32 classifier on host-side veth ensures all sandbox traffic routes through the proxy. Unbypassable by the agent.

**Known limitation**: Agents that bypass HTTP_PROXY environment variables and use hardcoded DNS can reach external hosts only if they also bypass the TC filter + iptables DNAT chain. In sandbox mode, this is prevented by the network namespace + TC filter combination.

---

### Low-and-Slow Data Exfiltration (Known Limitation)

**Attack**: An agent exfiltrates data by sending 1KB per request across 1,000 requests to an allowed endpoint, staying under any per-request size threshold. Each individual request appears normal.

**Impact**: SRR evaluates each request independently. Without cumulative tracking, the aggregate exfiltration is invisible to policy enforcement.

**Current defense**: WAL records all events. Post-hoc forensic analysis via `gvm audit list` can detect the pattern. Real-time anomaly detection (per-agent cumulative volume tracking, destination diversity scoring) is not yet implemented.

---

## Integrity Context (GIC)

Every configuration load event records a `GvmIntegrityContext` — an immutable snapshot of the execution environment at that point in time. This enables reproducible debugging, tamper detection, and configuration drift prevention.

### Why it exists

- **Reproducible debugging**: When an incident occurs, the `config_hash` field tells you exactly which ruleset was active at that moment.
- **Change history chaining**: `previous_state` links each config version to its predecessor. A gap or hash mismatch proves the chain was tampered with.
- **Collaboration accountability**: In team environments, `origin_id` and `signature` record who authorized the configuration, preventing unattributed changes.

### Privacy and trust model

All integrity contexts are generated locally by default. Nothing is transmitted externally. No personal data is collected — `origin_id` is a logical system identifier (e.g., "local-default"), not a user identity. The `trust_model` field lets operators choose the verification level appropriate for their environment — from local hash-only development to hardware-backed signing in regulated deployments.

### Field reference

| Field | Purpose |
|-------|---------|
| `spec_version` | Schema version for log format backward compatibility |
| `trust_model` | Verification mechanism for the environment's security requirements (`Local`, `Static`, `Remote`) |
| `origin_id` | Logical identifier for the log origin in distributed environments (not personal data — e.g., "local-default") |
| `algorithm` | Cryptographic algorithm used for signing (`None` for local hash-only, `Ed25519` for keypair) |
| `config_hash` | SHA-256 snapshot guaranteeing execution directive integrity |
| `signature` | Digital signature over `config_hash` (empty when `algorithm = None`) |
| `timestamp` | Unix epoch seconds when the context was created (numeric format avoids timezone ambiguity) |
| `previous_state` | Cryptographic link to the prior config state for gap/tamper detection |
| `checkpoint_id` | WAL batch anchor for point-in-time recovery queries |
| `opaque_extensions` | Extension slot for vendor-specific security features (HSM, TPM) or custom metadata |

### How it works

1. On config load (startup or hot-reload), GVM computes SHA-256 of the config content.
2. A `GvmIntegrityContext` is created with the hash, timestamp, and link to the previous state.
3. The full context is embedded in the WAL `config_load` event (inside the Merkle chain).
4. Subsequent behavioral events carry only a `config_integrity_ref` — a SHA-256 reference to the active context — so per-event overhead is zero beyond a 64-byte string.
5. An auditor can reconstruct which config governed any event by matching `config_integrity_ref` to the corresponding `config_load` event.

---

## Versioning

This document will be updated as:
- New attack vectors are discovered or reported
- Mitigations are implemented (entries move to "Fixed" or are removed)
- The threat model boundary expands (e.g., network-exposed token issuance, agent code from many internal authors)

Each mitigation decision is driven by the deployment context — a local development tool has different security requirements than a production financial services proxy.

---

## Sandbox Penetration Test Results (2026-04-05)

Tested on EC2 (Ubuntu 24.04, kernel 6.17.0-1009-aws) with `gvm run --sandbox`.

### Hostile Attack Vectors (15/15 blocked)

| # | Attack | Result | Defense Layer |
|---|--------|--------|---------------|
| 1 | `cat /etc/shadow` | `No such file or directory` | Mount namespace (minimal /etc) |
| 2 | `ls ~/.ssh/` | Empty (masked) | overlayfs + tmpfs blocklist |
| 3 | AF_PACKET raw socket | `EPERM` | seccomp BPF |
| 4 | EC2 metadata (169.254.169.254) | No response | iptables OUTPUT DROP |
| 5 | `mount -t proc` | `Function not implemented` | seccomp (mount blocked) |
| 6 | `iptables -F` | `command not found` | Binary not in sandbox + CAP_NET_ADMIN dropped |
| 7 | Write to `/usr/bin/` | `Read-only file system` | bind mount read-only |
| 8 | Path traversal `../../etc/crontab` | `No such file or directory` | pivot_root (old root unmounted) |
| 9 | Blocked domain HTTPS | No response | iptables OUTPUT DROP |
| 10 | `unshare --mount` | `Function not implemented` | seccomp (unshare blocked) |
| 11 | ptrace injection | `EPERM` | seccomp (ptrace blocked) |
| 12 | `kill -9 1` (kill PID 1 init) | `Function not implemented` | seccomp (kill restricted) |
| 13 | `insmod` kernel module | No module + CAP_SYS_MODULE dropped | Capability drop + minimal fs |
| 14 | `/proc/1/root/` access | `Permission denied` | hidepid=2 + PID namespace |
| 15 | DNS exfiltration | `Function not implemented` (nslookup crash) | seccomp + DNS DNAT to proxy |

### LLM Agent Reconnaissance (10/10 controlled)

Tested via OpenClaw agent (prompt injection simulation — agent asked to probe sandbox boundaries):

| # | Probe | Result | Security Assessment |
|---|-------|--------|---------------------|
| 1 | List `/etc` | Minimal: passwd, group, hosts, resolv.conf, ssl certs only | **Controlled** — no sensitive system config exposed |
| 2 | List `$HOME` | Visible via overlayfs — `.ssh` masked with empty tmpfs | **Controlled** — secrets blocklisted |
| 3 | Network interfaces | veth pair visible (10.200.x.x/30) | **Expected** — isolated namespace, no host interfaces |
| 4 | Proxy env vars | HTTP_PROXY, NO_PROXY, GVM_PROXY_URL visible | **Expected** — agent needs proxy config |
| 5 | Fetch github.com | Success (200) — routed through MITM proxy | **Expected** — all HTTPS inspected + WAL logged |
| 6 | Fetch httpbin.org/ip | Success — shows EC2 public IP | **Expected** — egress via host NAT, L7 inspected |
| 7 | Write to `/tmp` | Success | **Expected** — writable scratch space |
| 8 | Write to `/usr` | `Read-only file system` | **Blocked** — system dirs immutable |
| 9 | `id` command | `uid=0(agent) gid=0(agent)` | **Expected** — sandbox root with DAC caps only |
| 10 | `ps aux` | Only own processes visible (PID namespace + hidepid=2) | **Controlled** — no host process visibility |

### Defense-in-Depth Summary

```
Layer 1: PID namespace        — isolated process tree, hidepid=2
Layer 2: Mount namespace       — pivot_root, minimal rootfs, /usr read-only
Layer 3: Network namespace     — veth pair, proxy-only routing, DNAT 443→MITM
Layer 4: seccomp BPF           — ~130 syscall whitelist (mount/ptrace/unshare blocked)
Layer 5: Capability drop       — CAP_DAC_* retained for filesystem, all others dropped
Layer 6: iptables OUTPUT DROP  — only proxy + DNS traffic allowed
Layer 7: overlayfs blocklist   — .ssh/.aws/.gnupg masked with empty tmpfs
Layer 8: MITM TLS inspection   — full L7 HTTPS inspection, WAL audit trail
```

---

## MITM TLS Inspection — Known Limitations

Use `--no-mitm` to disable MITM and fall back to CONNECT relay (domain-level only). All other sandbox/contained protections remain active.

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| **mTLS (client certificates)** | MITM terminates TLS, cannot forward client certs to upstream | Use `--no-mitm`. Most AI APIs use API keys, not mTLS |
| **WebSocket** | HTTP Upgrade to WebSocket not supported through MITM | Use `--no-mitm` or cooperative mode. MCP standard uses HTTP SSE (supported) |
| **HTTP/2** | MITM forces ALPN to HTTP/1.1 | Transparent to agents — HTTP/1.1 is functionally equivalent for API calls |
| **Certificate pinning** | Agents pinning expected certs will reject MITM-generated certs | Use `--no-mitm` |
| **Windows Docker large responses** | Docker Desktop WSL2 network bridge may drop TCP >500KB | Use Linux for production. Windows works for small-medium responses |
| **Content-Encoding (gzip/br)** | Compressed bodies not decompressed for payload inspection | URL-pattern SRR works regardless. Payload inspection requires uncompressed (future) |
| **Timeout chaining** | MITM adds ~300ms overhead; agent timeout may fire first | Set agent timeouts > proxy upstream timeout (30s). Streaming SSE is unaffected (first chunk fast) |
| **LLM thinking trace** | MITM relay streams response chunks — cannot buffer full body for trace extraction | Thinking hash not captured on MITM path. Use cooperative mode with SDK for full trace capture |
| **IC-3 RequireApproval** | MITM cannot hold TLS keep-alive stream for human approval | IC-3 treated as Deny on MITM path. Use cooperative mode with SDK for IC-3 approval flow |
| **Shadow Mode** | MITM has no SDK headers for intent verification | Intent store claim/verify not supported on MITM path. SRR enforcement still active |
| **WAL coverage gaps (P2 remaining)** | Pre-classification failures (JWT 401, missing host 400) do not record to WAL — these occur before governance classification and have no decision to audit. Circuit breaker (503) is intentionally unrecorded (WAL already failing). All P1 gaps fixed: SRR lock poison, token budget exceeded, shadow STRICT, Deny, RequireApproval, classification error — all record to WAL on both MITM and proxy paths. |
| **Intermittent CONNECT TLS handshake eof** | Node.js undici HTTP client occasionally resets the 2nd CONNECT before sending ClientHello. Self-recovers on 3rd attempt (~2s delay). No data loss — WAL records all successful requests. | Under investigation. Likely client-side connection pool race condition after CONNECT tunnel close. `Connection: close` header added to CONNECT response to prevent upgrade reuse. Does not affect stress test pass rate (289 API calls, 0 TLS errors in steady state). |

## Overlayfs Trust-on-Pattern — Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| **Batch scan only** | File changes are scanned at session end, not during execution | Long-running agents may produce files that aren't visible until exit. Periodic inotify-based scan is a future consideration |
| **tmpfs volatility** | Upper layer lives in tmpfs — lost if sandbox crashes before scan | SIGTERM handler ensures scan+merge on graceful termination. SIGKILL = files lost. Staging fallback planned |
| **No real-time governance** | Files are classified post-hoc, not at write time | Current model is analogous to git commit review. inotify-based real-time scan is a future consideration |
| **Modified files never auto-merged** | Any modification to existing workspace files requires manual approval | By design — prevents agent from silently altering host files. Use ManualCommit review prompt |
| **Deletions not executed** | Agent cannot delete host files through overlayfs | By design — whiteouts classified as ManualCommit. Future `--allow-delete` opt-in |
