# Changelog

> Architecture decisions, implementation history, and release planning.
> For security model, see [11-security-model.md](11-security-model.md).
> For configuration reference, see [13-reference.md](13-reference.md).

---

## Roadmap

### Current (v1.0 MVP)

HTTP enforcement proxy (Rust/axum/tower) with 3-layer architecture (ABAC + SRR + API key isolation), IC classification (Allow/Delay/RequireApproval/Deny), Merkle tree audit ledger with WAL group commit, AES-256-GCM encrypted state cache, Wasm runtime (optional, behind `--features wasm`), rate limiter, JWT agent identity, eBPF TC ingress filter, seccomp BPF sandbox with dual filter stacking. Python SDK with `@ic` decorators, checkpoint/rollback with Merkle verification, LangChain integration. 367+ tests, 19 benchmarks, 0 failures.

v0.2 shipped: Shadow Mode + intent store, CONNECT tunnel, SRR hot-reload, eBPF uprobe TLS capture, transparent MITM (ephemeral CA, DNAT, per-domain leaf certs), `gvm run` binary mode, MCP integration, Telegram/Discord rulesets.

### Planned

**v0.3**
- Multi-PID uprobe (multi-process TLS capture)
- Chunked transfer body reassembly
- Anomaly detection (low-and-slow exfiltration)
- WebSocket proxy support

**v1.1 — Hardening**
- ABAC hot-path execution via Wasm engine
- Ed25519 module signature verification + hash pinning
- Decimal-based numeric comparison for financial precision
- HashMap/Trie index for O(1) SRR host+method lookup
- `Cow<'a, str>` in SRR normalize paths
- File permission check on `secrets.toml`
- HMAC-signed checkpoint step
- Configurable `MAX_CHECKPOINT_SIZE` / `MAX_HISTORY_TURNS` per agent

**v2.0 — Runtime & Infrastructure**
- Mandatory-by-default interception profile
- macOS/Windows host-level interception fallback
- NATS JetStream WAL publish, Redis Vault backend, Policy hot-reload (`SIGHUP`)
- KMS integration (AWS/GCP), Redis VaultBackend, key rotation, KDF (Argon2id)
- Proxy-controlled step numbers, full LLM response storage, incremental checkpoints
- TypeScript/Node.js SDK, Go SDK
- Prometheus metrics, Grafana dashboard
- gRPC detection + passthrough, pluggable isolation backend (namespace/firecracker/docker)

**v3.0 — Platform**
- Generic outbound capability governance (filesystem, shell, database)
- Protocol expansion (WebSocket, gRPC method-level, SMTP)
- Cross-agent collusion detection, trust delegation, inter-agent governance
- Multi-tenant SaaS, Envoy filter mode, OPA compatibility layer, SOC 2 / ISO 27001

---

## Implementation Log

### 2026-04-01: Agent Launch Pipeline + Proxy Lifecycle Manager

**Pipeline architecture** (`pipeline.rs`): Single execution path for all modes. Mode branching only in Phase 2 (launch). Pre-launch (proxy, orphan cleanup, CA download) and post-exit (audit, cleanup) are shared.

**Proxy lifecycle** (`proxy_manager.rs`): Independent daemon (setsid, PID file, log to data/proxy.log). Survives CLI exit. SUDO_UID/GID drop. Stale PID detection. Watchdog uses same daemon restart logic.

**Sandbox fixes**: DNS DNAT target recorded in state file for deterministic cleanup (H2). ip_forward saved/restored on last sandbox exit (H4). MITM WAL uses append_durable instead of append_async. GVM_SANDBOX_TIMEOUT in watch-discovery.sh.

**Code standards** (§7): Pipeline pattern, no logic duplication, process lifecycle separation, config path consistency.

Files: `crates/gvm-cli/src/{pipeline,proxy_manager,run,watch}.rs`, `crates/gvm-sandbox/src/{network,sandbox_impl,seccomp}.rs`, `src/tls_proxy.rs`, `docs/GVM_CODE_STANDARDS.md` | Risk: Medium (structural refactoring)

### 2026-04-01: Seccomp Architecture — KILL→ENOSYS Default + Blocklist

Changed seccomp default action from `KillProcess` to `Errno(ENOSYS)`. Unknown/new syscalls now return "not implemented" instead of killing the process, allowing runtimes to gracefully fall back. High-risk syscalls (ptrace, mount, bpf, unshare, etc.) remain blocked — ENOSYS prevents execution just as effectively as KILL, but without crashing the agent. Added `fadvise64` to whitelist (coreutils dependency).

Why: glibc 2.39+ calls new syscalls (rseq, fadvise64, etc.) during process initialization. Whitelist-only approach causes regressions every time kernel/glibc adds syscalls. ENOSYS default matches Docker's seccomp philosophy.

Files: `crates/gvm-sandbox/src/seccomp.rs` | Risk: Medium (security model change — ENOSYS vs KILL for unknown syscalls)

### 2026-03-31: Fuzzing CI Pipeline + 4 New Fuzz Targets

Added 4 cargo-fuzz targets (fuzz_http_parse, fuzz_path_normalize, fuzz_llm_trace, fuzz_policy_eval) to the existing 2 (fuzz_srr, fuzz_wal_parse). GitHub Actions workflow runs all 6 targets daily (5 min each) with corpus caching and crash artifact upload.

Why: Fuzzing CI was High priority on roadmap but unimplemented. SRR regex matching, HTTP parsing, and path normalization are highest-ROI targets for edge case discovery.

Files: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/fuzz_*.rs`, `.github/workflows/fuzz.yml`, `Cargo.toml` (workspace exclude) | Risk: Low (additive, no runtime changes)

### 2026-03-31: Security — CRLF Injection Defense + Fail-Close Consistency

**CRLF injection in MITM credential injection**: `inject_credentials()` wrote credential values as raw bytes into `rebuild_raw_head()` without validating for `\r\n` or `\0`. A compromised `secrets.toml` token containing CRLF could cause HTTP response splitting. Added `contains_header_injection_chars()` validation — injection is rejected (returns false) if any credential field contains CR, LF, or NUL. The HTTP proxy path (`api_keys.rs::inject()`) was already safe via `HeaderValue::from_str()`.

**SRR RwLock poison handling inconsistency**: `proxy.rs` and `tls_proxy.rs` used `unwrap_or_else(|e| e.into_inner())` on poisoned SRR locks, silently continuing with partial state (fail-open). This contradicted GVM_CODE_STANDARDS §1.2 (fail-close) and was inconsistent with `rate_limiter.rs` which correctly denied on poison. Fixed all 5 locations (`proxy.rs` ×3, `tls_proxy.rs` ×1, `api.rs` ×1) to return 500/deny immediately on poison.

Files: `src/tls_proxy.rs`, `src/proxy.rs`, `src/api.rs`, `src/api_keys.rs` | Risk: Low (defense hardening, no behavior change on non-poisoned path)

### 2026-03-30: Sandbox Auto-Cleanup + seccomp Fix
Per-PID state files for crash-resilient orphan cleanup; `gvm cleanup` CLI; pwritev/preadv/socketpair added to seccomp.
Why: 1024 stacked tmpfs mounts from crashes; orphan veth/iptables on SIGKILL; OpenClaw SIGSYS.
Files: `gvm-sandbox/src/{network,sandbox_impl,seccomp}.rs`, `gvm-cli/src/{main,run}.rs` | Risk: Medium

### 2026-03-30: Stress Test Workloads Rewrite
Rewrote all stress test workloads to use legitimate, non-refusable prompts. Removed exfiltration-testing workloads.
Files: `scripts/stress-workloads/*`, `scripts/stress-test.{sh,ps1}` | Risk: Low

### 2026-03-29: Wasm Engine Behind Feature Flag
Moved wasmtime behind `--features wasm` (disabled by default). Eliminates 5 CVEs and ~10MB from default binary.
Files: `Cargo.toml`, `src/lib.rs`, `src/proxy.rs`, `src/main.rs`, `tests/integration.rs` | Risk: Low

### 2026-03-29: Contained Mode E2E Tests (68-75)
8 new E2E tests for Docker `--contained` mode: MITM pipeline, SRR Deny, proxy bypass, filesystem, parity.
Files: `scripts/ec2-e2e-test.sh` | Risk: Low

### 2026-03-28: E2E Mock Server + Security Tests + False-Pass Cleanup
Mock GitHub/httpbin server (rate limit avoidance). Security tests 61-63. Test 17 rewrite. 7 false-pass→skip.
Files: `scripts/mock-github.py`, `scripts/ec2-e2e-test.sh` | Risk: Low

### 2026-03-28: E2E Test Reliability + Overlayfs Default
ensure_proxy 10x retry, OSError catch fix, admin port conflict fix, overlayfs enabled by default.
Files: `scripts/ec2-e2e-test.sh`, `crates/gvm-cli/src/run.rs` | Risk: Medium

### 2026-03-27: MITM TLS End-to-End Fix
CA DN mismatch, original CA in chain, HTTPS_PROXY removal (CONNECT bypass), system CA bundle paths.
Why: MITM failed with requests/curl due to chain/DN mismatches and CONNECT tunneling.
Files: `src/tls_proxy.rs`, `gvm-sandbox/src/{sandbox_impl,mount}.rs` | Risk: Medium

### 2026-03-26: DNS DNAT + MITM TLS Pipeline Complete
PREROUTING DNAT redirects sandbox DNS to upstream resolver. Full MITM pipeline verified end-to-end.
Files: `crates/gvm-sandbox/src/network.rs` | Risk: Low

### 2026-03-26: Kernel Panic Fix — Mount Deduplication + seccomp sendmmsg
HashSet dedup prevents kernel panic on Linux 6.17 from duplicate bind mounts. sendmmsg/recvmmsg added to seccomp.
Files: `gvm-sandbox/src/{mount,sandbox_impl,seccomp}.rs` | Risk: Low

### 2026-03-26: Security Audit — Unsafe/FFI, Blocking I/O, Namespace
eBPF `mem::forget` → RAII guard. WAL rotation → async I/O. `/proc` with `hidepid=2`.
Files: `gvm-sandbox/src/{ebpf,sandbox_impl,mount}.rs`, `src/{ledger,tls_proxy}.rs` | Risk: Low

### 2026-03-26: MITM CA Key Isolation + Zeroization
Fixed dual-CA bug (sandbox CA-B vs proxy CA-A). Single CA via `GET /gvm/ca.pem`. Key zeroize on drop.
Files: `gvm-sandbox/src/{sandbox_impl,lib,ca}.rs`, `gvm-cli/src/run.rs`, `src/main.rs` | Risk: Low

### 2026-03-26: Admin API Port Separation + stdin Isolation
Agent port (8080) vs admin port (9090). Agent cannot reach `/gvm/approve`. stdin → Stdio::null().
Why: Agent could self-approve IC-3 requests; stdin race conditions.
Files: `src/{main,config}.rs`, `gvm-cli/src/{run,watch,main}.rs` | Risk: Medium (breaking)

### 2026-03-25: cgroups v2 Resource Limits for Sandbox
`--sandbox` mode supports cgroup v2 CPU and memory limits via `--memory` and `--cpus` flags. RAII `CgroupGuard` with graceful fallback if cgroup v2 unavailable.
Why: Sandbox mode lacked resource limits that Docker mode already had.
Files: `gvm-sandbox/src/cgroup.rs` (new), `lib.rs`, `sandbox_impl.rs`, `gvm-cli/src/run.rs`, `gvm-cli/src/main.rs`
Risk: Low

### 2026-03-25: SRR Payload Inspection Activation
Wired SRR payload inspection to actual request bodies. Body buffered with `max_body_bytes` limit (default 64KB), re-attached for forwarding. Opt-in via `payload_inspection = true`.
Why: Payload inspection was parsed from TOML but never connected to request bodies.
Files: `src/proxy.rs`, `src/config.rs`, `src/main.rs`, `tests/integration.rs`
Risk: Low (backward compatible, off by default)

### 2026-03-25: IC-3 Blocking Approval — Human-in-the-Loop
IC-3 now holds HTTP response via oneshot channel and waits for human approval (timeout 300s, fail-close). Added `GET /gvm/pending`, `POST /gvm/approve` endpoints and `gvm approve` CLI.
Why: IC-3 previously returned immediate 403 instead of actually waiting for human approval.
Files: `src/proxy.rs`, `src/api.rs`, `src/main.rs`, `src/config.rs`, `gvm-cli/src/approve.rs` (new), `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`
Risk: Low

### 2026-03-25: `gvm watch` — Observation-Only CLI
New CLI command for real-time API call stream, session summary, cost estimation, anomaly detection. Default allow-all config with RAII cleanup. Zero proxy changes.
Why: Entry point to GVM funnel: observe → discover rules → enforce.
Files: `gvm-cli/src/watch.rs` (new), `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`
Risk: Low

### 2026-03-24: README Rewrite — Agent Developer Framing
Full README rewrite repositioning from "security proxy" to "agent operations tool". Two-step Quick Start (observe → enforce), realistic demos, cross-layer forgery reframing, OPA+Envoy comparison.
Why: Previous README was security-focused; target audience is agent developers.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-24: WAL Sequence Persistence + Size-Based Rotation
`wal_sequence` initialized from WAL event count during recovery (monotonic across restarts). Size-based rotation at `max_wal_bytes` (100MB default) with Merkle chain continuity. Old segments pruned beyond `max_wal_segments` (10 default).
Why: Sequence reset on restart broke NATS consumer ordering; unbounded WAL growth.
Files: `src/ledger.rs`, `src/config.rs`, `src/main.rs`
Risk: Medium

### 2026-03-24: MITM API Key Injection
Implemented credential injection on MITM TLS path. Agent auth headers stripped, credentials from `secrets.toml` injected. Same security properties as HTTP path.
Why: `--sandbox` HTTPS traffic bypassed Layer 3 credential isolation; agents needed API keys for HTTPS calls.
Files: `src/tls_proxy.rs`, `src/api_keys.rs`, `src/main.rs`, `README.md`
Risk: Low

### 2026-03-23: MITM Hardening + uprobe Feature Flag + README Honesty
CA unification (single EphemeralCA shared between proxy and sandbox). Certificate 24h backdate for clock drift. memfd_create false claims removed. uprobe gated behind `--features uprobe`. README exaggeration removal. 6 new EC2 tests (35-40).
Why: Dual CA generation broke MITM pipeline; uprobe is observation-only, not primary enforcement; README overclaimed.
Files: `src/main.rs`, `src/proxy.rs`, `src/tls_proxy.rs`, `gvm-sandbox/src/ca.rs`, `gvm-sandbox/src/lib.rs`, `scripts/ec2-e2e-test.sh`, `README.md`
Risk: Low

### 2026-03-23: Runtime Hardening — 4 Structural Vulnerabilities
TLS cert gen moved to `spawn_blocking` (prevented tokio worker starvation). HTTP request smuggling CL/TE rejected. FD exhaustion mitigated (semaphore 1024, timeouts). Sandbox PID 1 zombie reaper added.
Why: 50 concurrent TLS handshakes blocked all async I/O; CL/TE desync bypassed SRR; slowloris on port 8443; zombie accumulation in PID namespace.
Files: `src/tls_proxy.rs`, `src/main.rs`, `gvm-sandbox/src/sandbox_impl.rs`
Risk: Low

### 2026-03-23: Memory Safety — WAL Recovery Watermark + TLS Cache Bound
WAL recovery HashSet replaced with sidecar watermark file (O(N) → O(1) memory). TLS SNI cache DashMap replaced with moka bounded LRU (max 10,000, 1h TTL).
Why: WAL recovery OOM on large files; unbounded TLS cert cache exhaustible by unique SNI domains.
Files: `src/ledger.rs`, `src/tls_proxy.rs`, `Cargo.toml`
Risk: Low

### 2026-03-23: Documentation Consistency Fix — MITM Status
Fixed README and roadmap where MITM (implemented in v0.2) was still described as "planned v0.3". Renamed doc files 14→15, 15→16.
Why: Multiple sections contradicted each other on MITM implementation status.
Files: `README.md`, `docs/13-roadmap.md`, `docs/00-overview.md`, `docs/12-quickstart.md`, `docs/13-reference.md`
Risk: Low (documentation only)

### 2026-03-23: Documentation Audit — 20 Issues Fixed
Full cross-reference audit of 18 docs. Critical: seccomp count ~45→~111 (4 locations), Vault WAL claim fix, Tower middleware order fix, LLM trace Content-Length claim removed, uprobe→eBPF TC in examples.
Why: Documentation diverged from implementation across multiple files.
Files: `docs/00-overview.md`, `04-ledger.md`, `05-vault.md`, `06-proxy.md`, `07-sdk.md`, `08-memory-security.md`, `10-architecture-changes.md`, `10-competitive-analysis.md`, `11-security-model.md`, `13-roadmap.md`, `15-reference.md`, `README.md`
Risk: Low (documentation only)

### 2026-03-23: Security Hardening — WAL OOM, Rate Limiter, README Honesty
WAL recovery streaming (BufReader instead of read_to_string). Rate limiter rewritten from f64 to u64 millitoken fixed-point. README renamed "Security Kernel" to "Security Proxy".
Why: WAL OOM on large files; floating-point precision drift in rate limiting; README overclaimed.
Files: `src/ledger.rs`, `src/rate_limiter.rs`, `gvm-cli/src/suggest.rs`, `README.md`
Risk: Medium

### 2026-03-23: Documentation Update — SRR, Proxy, Reference
Added Base64 decoding, path_regex, SRR hot-reload to docs/03-srr.md. Added CONNECT tunnel, Shadow Mode, control plane endpoints to docs/06-proxy.md. Added reference entries.
Why: Implemented features lacked documentation.
Files: `docs/03-srr.md`, `docs/06-proxy.md`, `docs/15-reference.md`
Risk: Low (documentation only)

### 2026-03-23: Binary Mode, Base64 Decoding, MCP Rulesets, EC2 E2E
`gvm run` binary mode with HTTPS_PROXY injection. Base64 payload decoding in SRR. Telegram/Discord rulesets. 34 EC2 E2E test scenarios.
Why: Support arbitrary binaries (not just Python); detect encoded payloads; MCP platform governance rules; automated testing.
Files: `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`, `src/srr.rs`, `scripts/ec2-e2e-test.sh`, `rulesets/telegram.toml`, `rulesets/discord.toml`
Risk: Low-Medium

### 2026-03-22: Uprobe SRR Policy Enforcement
Connected uprobe TLS probe to proxy SRR engine via `/gvm/check` HTTP callback. Fail-closed: proxy unreachable → Deny (SIGSTOP).
Why: Uprobe captured HTTPS plaintext but had hardcoded Allow-all callback.
Files: `gvm-sandbox/src/sandbox_impl.rs`, `lib.rs`, `Cargo.toml`, `gvm-cli/src/run.rs`
Risk: Low-Medium

### 2026-03-22: Shadow Mode, 11 Security Patches, Sandbox Improvements
Shadow Mode with 2-phase intent lifecycle (intent store, `/gvm/intent`, `/gvm/reload`, strict/permissive modes). 11 security patches: IPv6 expand OOB, Merkle domain separation, Wasm pointer bounds, auth header expansion, regex length limit, agent_id validation, intent TOCTOU, first-run guard, Docker non-root, audit hash sync, SDK URL validation. Sandbox `/workspace/output` writable mount.
Why: MCP-compatible governance; security audit findings; sandbox usability.
Files: `src/proxy.rs`, `src/intent.rs`, `src/config.rs`, `src/api.rs`, `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `sdk/python/gvm/session.py`
Risk: Medium (Merkle domain separation is backward-incompatible with pre-existing WAL)

### 2026-03-21: Security Audit — 8 Patches
IPv6 expand array OOB (critical), Merkle domain separation (high), Wasm pointer safety (high), auth header stripping 4→10 (medium), regex pattern length limit (medium), agent_id length validation (medium), IPv6 loopback scheme (low), IPv4-mapped parsing fix (low).
Why: Systematic security audit of input validation and boundary conditions.
Files: `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`
Risk: Medium (Merkle hash backward-incompatible)

### 2026-03-20: WAL Batch Window + LLM Trace Streaming
WAL default batch_window changed from 0 to 2ms (10-50x TPS improvement under load). LLM trace extraction unified into tap-stream pattern (no more full buffering before forwarding).
Why: Every request paid full fsync with batch_window=0; non-SSE responses blocked first byte until entire body received.
Files: `src/ledger.rs`, `src/config.rs`, `src/main.rs`, `src/proxy.rs`, `tests/stress.rs`
Risk: Medium

### 2026-03-20: Test Coverage Gap Fill (5 Integration Tests)
E2E proxy forwarding, GovernanceBlockResponse fields, SDK header contract, policy conflict regex edge case, emergency WAL recovery path.
Why: No test verified actual HTTP forwarding, SDK-facing JSON error contract, or emergency WAL recovery.
Files: `tests/integration.rs`, `docs/09-test-report.md`
Risk: Low

### 2026-03-20: Config File Hash Recording in Merkle Chain
SHA-256 hashes of config files recorded as `gvm.system.config_load` WAL event at proxy startup.
Why: Policy file tampering between restarts was undetectable.
Files: `src/ledger.rs`, `src/main.rs`, `tests/integration.rs`, `docs/04-ledger.md`, `docs/11-security-model.md`
Risk: Low

### 2026-03-20: Security Documentation Reframing
Timing side-channel reframed as intentional design (rate limiter prevents statistical attacks). Fuzzing CI elevated to High priority. Constant-time SRR lowered to Low priority.
Why: Previous framing implied GVM was pursuing constant-time but falling short; honest framing is that end-to-end timing difference is inherent to all proxy architectures.
Files: `docs/08-memory-security.md`, `docs/11-security-model.md`
Risk: Low (documentation only)

### 2026-03-19: Vault Trait Abstraction (KeyProvider + VaultBackend)
New `KeyProvider` and `VaultBackend` traits. `Vault<B: VaultBackend = InMemoryBackend>` generic with backward-compatible default. Enables future KMS and Redis backends.
Why: Hardcoded AES-256-GCM + in-memory HashMap blocked KMS integration, persistent storage, and mock testing.
Files: `src/vault.rs`
Risk: Low

### 2026-03-19: Security/Audit Layer Code Review
Consolidated port-stripping (4 locations → `strip_port()`), extracted `response_status_label()` helper, shared seccomp base syscall list between default/strict filters.
Why: Code duplication across security-critical paths increased maintenance risk.
Files: `src/srr.rs`, `src/proxy.rs`, `gvm-sandbox/src/seccomp.rs`
Risk: Low

### 2026-03-19: README Restructure (Feedback-Driven)
10 external feedback items addressed: IC-3 gap callout, WAL limitations caveat, mode comparison table, honest OpenShell comparison, trimmed roadmap, consolidated demos.
Why: External review identified positioning and honesty issues.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: README Thesis Restructure
Five core strengths reframed as consequences of one architectural choice (infrastructure control over ML classification). Causal chain table, stack comparison, trade-off callout.
Why: Features were presented as independent; they are all consequences of one architectural decision.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: Tier 1/Tier 2 Separation Disclosure
Documented that forgery detection requires SDK (`@ic` decorator for Layer 1 semantic data). Without SDK, `max_strict()` is never called.
Why: Previous README created false impression that all features work with zero code changes.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: DX Improvements (Build Time + First-Run)
GitHub Actions CI + release workflow (5 targets). cargo-binstall support. Startup governance summary banner. First-run interactive setup with industry templates and auto-restart.
Why: No pre-built binaries; no CI/CD; raw error on first run with missing config.
Files: `.github/workflows/ci.yml`, `release.yml` (new), `Cargo.toml`, `src/main.rs`, `src/srr.rs`, `src/policy.rs`, `README.md`
Risk: Low

### 2026-03-19: SDK Composition Refactor
Removed `GVMAgent` inheritance requirement. `@ic` decorator now works on standalone functions via `configure()` + `gvm_session()`. GVMAgent optional (only for checkpoint/rollback/state).
Why: Inheritance conflicted with CrewAI, AutoGen, OpenAI Agents SDK base classes.
Files: `sdk/python/gvm/session.py` (new), `decorator.py`, `agent.py`, `__init__.py`, `langchain_tools.py`, `examples/standalone_agent.py` (new), `README.md`, `docs/07-sdk.md`
Risk: Low

---

## Architecture Decisions

### Merkle Tree WAL Integrity (2026-03-15)

WAL events form a binary Merkle tree per batch (intra-batch O(log N) verification). Each `MerkleBatchRecord` references the previous batch's root, forming an inter-batch chain. Event hash: SHA-256 of canonical fields with domain separation prefix (`gvm-event-v1:` for events, `gvm-node-v1:` for internal nodes). SHA-256 per event adds ~200-500ns; Merkle root per 100-event batch adds ~20us — negligible relative to WAL fsync (2ms).

### IPv6 SSRF Normalization (2026-03-15)

`normalize_host()` in `src/srr.rs` expands all IPv6 variants (zero-compression, bracket notation, IPv4-mapped) to canonical IPv4 before SRR matching. 13 attack variants tested across loopback, IPv4-mapped, cloud metadata, and private ranges — all correctly denied.

### WASI Preview1 Fix (2026-03-15)

Core Wasm modules (`wasm32-wasip1`) require WASI preview1 imports. Fixed: `Store<WasiCtx>` → `Store<WasiP1Ctx>`, `.build()` → `.build_p1()`, `add_to_linker_sync` updated to preview1 variant.

### Key Benchmarks (2026-03-15)

| Benchmark | Latency |
|-----------|---------|
| SRR only | 88 ns |
| E2E native | 732 ns |
| E2E Wasm | 6.37 us |
| Vault fsync (1KB-256KB) | 2.06-2.50 ms |
| Chunked 16x16KB | 32.79 ms (13x slower — fsync dominated) |

---

## Assessed & Closed

Reported during security audit — determined non-vulnerabilities. See [11-security-model.md](11-security-model.md).

| Issue | Assessment |
|-------|-----------|
| AES-GCM nonce collision | Birthday bound: ~770M years at 1000 writes/day |
| Unbounded X-GVM-Context header | hyper/axum enforces ~64KB limit |
| Operation name CRLF injection | `HeaderValue::to_str()` rejects non-visible ASCII |
| Checkpoint step `u64::MAX` | Normal HashMap key, no overflow |
| SRR body size bypass | Default-to-Caution fallback catches unmatched requests |
| Vault `list_keys()` cross-agent | No API endpoint exposes this |
| SDK credential header pass-through | Proxy strips at Layer 3 |
| Rate limiter agent ID spoofing | Mitigated by JWT identity verification |

---

## Fixed Issues (v0.2)

| Issue | Fix |
|-------|-----|
| Upstream X-GVM-* header poisoning | Strip upstream response headers |
| API key strip scope | Strip Authorization, Cookie, X-API-Key, ApiKey |
| Thread-unsafe header setter | Thread-local `_gvm_context` |
| Mock server in production | `GVM_ENV` guard |
| SRR path traversal | Path normalization (percent-decode, null-byte, dot-segment) |
| Operation name header injection | Regex validation `[a-zA-Z0-9._-]+` |
| IC-1 event status | Check `response.status().is_success()` |
| Policy field typo silently ignored | Field name validation at load time |
| Import chain attack | Top-level imports in `decorator.py` |
| IPv6 SSRF defense | `normalize_host()` with `expand_ipv6()` |
| Checkpoint Merkle verification hardcoded | Real content hash + chain verification |
| Agent ID spoofing | JWT identity verification (HMAC-SHA256) |
| `transport.method` always empty in WAL | Capture method before body consumption |
| Throttle path always sets Confirmed | Check `response.status().is_success()` |
| Deny `ic_level` was 3 | Corrected to `ic_level: 4` (IC-4) |
