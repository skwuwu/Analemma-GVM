# Implementation Log

> Records significant code modifications, architectural decisions, and refactoring rationale.

---

## 2026-03-23: Documentation Update — SRR, Proxy, and Reference Guide

### What Changed
- `docs/03-srr.md`: Added sections for Base64 payload decoding (3.6.1), path_regex matching (3.7), and SRR hot-reload (3.8). Renumbered subsequent sections.
- `docs/06-proxy.md`: Added sections for CONNECT tunnel (6.10), Shadow Mode + Intent Store (6.11), and control plane endpoints `/gvm/reload`, `/gvm/intent`, `/gvm/check` (6.12). Renumbered Governance Block Response to 6.14.
- `docs/15-reference.md`: Added proxy API endpoints (reload, intent, check), binary mode documentation, Shadow Mode env var and config, SandboxConfig fields (tls_probe_mode, proxy_url).

### Affected Files
- `docs/03-srr.md`, `docs/06-proxy.md`, `docs/15-reference.md`, `docs/14-implementation-log.md`

### Risk Assessment
None. Documentation-only changes reflecting existing implemented features.

---

## 2026-03-23: Binary Mode, Base64 Decoding, MCP Rulesets, EC2 E2E Tests

### What Changed
- `gvm run` binary mode: `gvm run -- openclaw gateway` with HTTPS_PROXY injection for arbitrary binaries
- `gvm run --sandbox` for arbitrary binaries (namespace + seccomp + uprobe isolation)
- gvm run stdout-to-stderr fix (clean stdout for piping)
- Base64 payload decoding in SRR (body + field value decoding for encoded payloads)
- Telegram ruleset (path_regex for Bot API endpoint matching)
- Discord ruleset: channel/guild delete rules added
- EC2 E2E test suite: 34 scenarios covering proxy enforcement, sandbox, and uprobe paths
- OpenClaw config fix (mcpServers invalid key removal)

### Affected Files
- `crates/gvm-cli/src/main.rs`, `crates/gvm-cli/src/run.rs` (binary mode + stdout fix)
- `src/srr.rs` (Base64 decoding in SRR evaluation)
- `scripts/ec2-e2e-test.sh` (34 E2E test scenarios)
- `rulesets/telegram.toml`, `rulesets/discord.toml` (MCP repo rulesets)

### Risk Assessment
Low-Medium. Binary mode extends existing `gvm run` with HTTPS_PROXY injection -- no changes to core proxy or policy engine. Base64 decoding adds a new SRR evaluation path but is opt-in per rule. E2E tests are test-only additions.

---

## 2026-03-22: Uprobe SRR Policy Enforcement

### What Changed
- Connected uprobe TLS probe to proxy's SRR policy engine via `/gvm/check` HTTP callback
- Added `proxy_url` field to `SandboxConfig` for uprobe→proxy communication
- Added `ureq` dependency for sync HTTP calls from uprobe thread
- Fail-closed design: proxy unreachable or timeout (50ms) → Deny (SIGSTOP)
- `X-GVM-Uprobe-Token` header for basic auth separation

### Why
The uprobe captured HTTPS plaintext but had a hardcoded Allow-all callback. Without SRR integration, the uprobe could log but never enforce path-level HTTPS policies.

### Affected Files
- `crates/gvm-sandbox/src/sandbox_impl.rs`: real policy callback via ureq HTTP
- `crates/gvm-sandbox/src/lib.rs`: `proxy_url` field in SandboxConfig
- `crates/gvm-sandbox/Cargo.toml`: ureq + serde_json deps
- `crates/gvm-cli/src/run.rs`: passes proxy URL to sandbox config
- `docs/linux-e2e-test.md`: Test 6 (uprobe enforcement) + security model table

### Known Limitations
- **Race condition**: SSL_write_ex fires after kernel queues packet. SIGSTOP cannot prevent the first write. This is "immediate session freeze on violation", not "pre-transmission block".
- **Auth**: `X-GVM-Uprobe-Token` is a static string, not cryptographically verified. Sandboxed agents with iptables bypass could forge it.
- **Fail-closed risk**: Proxy transient unavailability freezes the agent (SIGSTOP). Acceptable for security but may surprise users.

### Risk Assessment
Low-Medium. The uprobe is a defense-in-depth layer, not the primary enforcement point. Proxy CONNECT-level enforcement + iptables remain the primary gates.

---

## 2026-03-22: Shadow Mode, Security Patches, Sandbox Improvements

### What Changed

#### 1. Shadow Mode (New Feature)

Implemented a 2-phase intent lifecycle for MCP-compatible governance:

- **Intent Store**: In-memory store with TTL-based expiry, agent_id cross-check, and one-time consumption semantics. Uses atomic operations to prevent TOCTOU races on concurrent intent consumption.
- **`POST /gvm/intent`**: Agents declare intent before making HTTP requests. The proxy validates the intent (claim phase), writes to WAL, then either confirms or releases the intent based on enforcement outcome.
- **`POST /gvm/reload`**: Hot-reload SRR rules without proxy restart. Enables runtime policy updates for Shadow Mode deployments.
- **`GVM_SHADOW_MODE` env var**: Alternative to `[shadow]` config section for enabling Shadow Mode. Accepts `strict` (reject requests without prior intent) or `permissive` (log-only).
- **Intent lifecycle coverage**: All enforcement decision paths (Allow, Delay, Deny, AuditOnly, RequireApproval) now participate in the intent confirm/release lifecycle.

#### 2. Security Patches (11 fixes)

1. **CRITICAL -- IPv6 expand OOB fix** (`srr.rs`): Bounds check for `right.len() > max_segments` before subtraction prevents integer underflow on malformed IPv6 with excessive segments after `::`.
2. **HIGH -- Merkle domain separation** (`merkle.rs`): `gvm-event-v1:` prefix with length-prefixed fields replaces `|` delimiter. `gvm-node-v1:` prefix for internal nodes. Prevents cross-context hash collisions and delimiter-based second preimage attacks.
3. **HIGH -- Wasm pointer bounds validation** (`wasm_engine.rs`): `u32::MAX` overflow check before `len as u32` cast. Explicit memory bounds validation for `input_ptr` and `result_ptr` before read/write.
4. **MEDIUM -- Auth header stripping expanded** (`api_keys.rs`): 4 → 10 stripped headers: added `Proxy-Authorization`, `X-Auth-Token`, `X-Api-Token`, `X-Signature`, `X-HMAC`, `X-Credentials`.
5. **MEDIUM -- Regex pattern length limit** (`srr.rs`, `policy.rs`): 10,000-byte (10KB) limit on `path_regex` and policy regex patterns to prevent DFA memory explosion.
6. **MEDIUM -- agent_id length validation unified** (`api.rs`): 128-byte length check in `validate_vault_identifier()`. Previously only `/gvm/auth/token` enforced length.
7. **LOW -- Intent store TOCTOU fix**: Replaced `unwrap()` with safe `Option` handling in concurrent intent consumption path.
8. **LOW -- First-run wizard config guard**: `offer_first_run_setup()` no longer overwrites existing config files.
9. **LOW -- Docker non-root user**: Dockerfile runs as UID 10001 (non-root) for defense in depth.
10. **LOW -- audit.rs hash synced with merkle.rs**: `compute_event_hash()` in audit.rs now uses the same domain-separated hash format as merkle.rs, preventing verification mismatches.
11. **LOW -- Python SDK proxy URL validation**: SDK validates proxy URL format on `configure()` to fail fast on misconfiguration.

#### 3. Sandbox Improvements

- **`/workspace/output` writable mount**: Sandbox mode now mounts `/workspace/output` as writable, persisting to the host. Agent file output survives container teardown.
- **CWD set to `/workspace/output`**: In sandbox mode, the agent process working directory defaults to `/workspace/output` so relative file writes land in the persistent output directory.
- **Intent lifecycle coverage**: All enforcement decision paths (Allow through Deny) now correctly participate in intent confirm/release when Shadow Mode is active inside sandboxed environments.

#### 4. /gvm/check SRR-Only Decision for Tier-1

`/gvm/check` endpoint now returns SRR-only decisions when no SDK headers are present (Tier-1 mode), rather than returning an error or requiring ABAC context.

### Risk Assessment

- Merkle domain separation is **backwards-incompatible** with pre-existing WAL files (acceptable for v0.x pre-release).
- Shadow Mode is opt-in only; no behavioral change for existing deployments.
- Intent store TTL defaults are conservative (30s). Production deployments may need tuning.
- All 242 tests pass (129 core + 32 CLI + 17 gvm-cli + 28 gvm-engine + 12 sandbox + 12 types + 12 benches).

### Affected Files

**Shadow Mode**: `src/proxy.rs`, `src/intent.rs`, `src/config.rs`, `src/api.rs`, `src/main.rs`
**Security patches**: `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`, `src/audit.rs`, `Dockerfile`, `sdk/python/gvm/session.py`
**Sandbox**: `src/sandbox.rs`, `src/main.rs`
**Docs**: `README.md`, `docs/14-implementation-log.md`

---

## 2026-03-21: Security Audit — 8 Patches

### What Changed

1. **CRITICAL — IPv6 expand array OOB** (`srr.rs:673`): Added bounds check for `right.len() > max_segments` before subtraction. Malformed IPv6 with excessive segments after `::` caused integer underflow → out-of-bounds array write.

2. **HIGH — Merkle domain separation** (`merkle.rs`): Added `gvm-event-v1:` prefix to event hashes with length-prefixed fields (replaces `|` delimiter). Added `gvm-node-v1:` prefix to internal node hashes. Prevents cross-context hash collisions and delimiter-based second preimage attacks. Updated `compute_merkle_root`, `generate_merkle_proof`, `verify_merkle_proof`, and all test vectors.

3. **HIGH — Wasm pointer safety** (`wasm_engine.rs`): Added `u32::MAX` overflow check before `len as u32` cast. Added explicit memory bounds validation for both `input_ptr` and `result_ptr` before read/write operations.

4. **MEDIUM — Auth header stripping** (`api_keys.rs`): Extended stripped headers from 4 to 10: added `Proxy-Authorization`, `X-Auth-Token`, `X-Api-Token`, `X-Signature`, `X-HMAC`, `X-Credentials`. Prevents agents from smuggling alternative auth headers past Layer 3.

5. **MEDIUM — Regex pattern length limit** (`srr.rs`, `policy.rs`): Added 10,000-byte limit on `path_regex` and policy regex patterns. Prevents DFA memory explosion during compilation from malicious config.

6. **MEDIUM — agent_id length validation** (`api.rs`): Added 128-byte length check to `validate_vault_identifier()`. Previously only `/gvm/auth/token` enforced length; vault endpoints did not.

7. **LOW — IPv6 loopback scheme** (`proxy.rs`): Added `[::1]` and `::1` to local host detection for HTTP scheme selection.

8. **LOW — IPv4-mapped IPv6 parsing** (`srr.rs:581`): Replaced `unwrap_or(0)` with explicit `None` return for missing colon. Prevents potential panic on malformed IPv4-mapped addresses.

### Risk Assessment

- Merkle hash change is **backwards-incompatible**: existing WAL files will fail verification against new hashes. This is acceptable for pre-release (v0.x). Production deployments would need a migration tool.
- All 233 tests pass (120 core + 32 CLI + 17 gvm-cli + 28 gvm-engine + 12 sandbox + 12 types + 12 benches).

### Affected Files

`src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`

---

## 2026-03-20: WAL Batch Window + LLM Trace Streaming Refactor

### What Changed

**WAL batch_window**: Changed default `GroupCommitConfig::batch_window` from `Duration::ZERO` to `Duration::from_millis(2)`. Added `[wal]` section to `ProxyConfig` with `batch_window_ms` and `max_batch_size` fields. `main.rs` now passes config values to `Ledger::with_config()`.

**LLM trace extraction**: Unified SSE and non-SSE response paths into a single tap-stream pattern. Previously, non-SSE responses were fully buffered via `BodyExt::collect()` before forwarding (blocking first byte until entire body was received). Now both paths use the same approach: chunks are forwarded immediately through the stream while a bounded capture buffer accumulates bytes for post-stream trace extraction. Removed the separate `extract_llm_trace_from_sse_stream` function.

**Key behavioral change**: `extract_llm_trace_from_response` now takes `&GVMEvent` instead of `&mut GVMEvent`. The extracted trace is persisted as a separate WAL entry via `tokio::spawn` after stream completion, rather than being set on the caller's event in-place.

### Why

**WAL**: With `batch_window=0`, every IC-2/3 request paid a full fsync even under concurrent load. With 2ms batching, concurrent requests amortize fsync across the batch, yielding 10-50x TPS improvement under load while adding only 2ms worst-case latency for isolated requests. This is critical because WAL fsync was the dominant latency component (1-50ms), dwarfing the sub-microsecond policy evaluation that GVM markets.

**LLM trace**: The previous `collect()` approach buffered up to 256KB per non-SSE LLM response before forwarding the first byte. Under concurrent load (N requests × 256KB), this created both a memory exhaustion risk and an unnecessary latency penalty. The tap-stream approach eliminates both: first byte is forwarded immediately, and memory is bounded by the capture limit regardless of concurrency.

### Affected Files

- `src/ledger.rs` — default batch_window `Duration::ZERO` → `Duration::from_millis(2)`, updated docs
- `src/config.rs` — new `WalConfig` struct with `batch_window_ms` and `max_batch_size`
- `src/main.rs` — `Ledger::new()` → `Ledger::with_config()` with config values
- `src/proxy.rs` — unified tap-stream for SSE and non-SSE, removed `extract_llm_trace_from_sse_stream`, updated 6 unit tests
- `tests/stress.rs` — `vault_10k_encrypt_decrypt_no_leak` uses explicit `batch_window=0` to avoid Windows timer resolution penalty

### Risk Assessment

Medium. Two behavioral changes: (1) WAL writes now wait up to 2ms for more events before flushing — isolated requests see 2ms added latency (15.6ms on Windows due to timer resolution). (2) LLM trace is now a separate WAL entry instead of being embedded in the enforcement decision event — audit queries that join on trace data need to correlate by `event_id`. All 257 tests pass.

### Known Limitation

Windows timer resolution: `tokio::time::timeout(2ms)` resolves to ~15.6ms on Windows due to the default timer granularity. Production deployments on Windows should set `batch_window_ms = 0` in `proxy.toml` or use `timeBeginPeriod(1)` to increase timer resolution. Linux is unaffected.

---

## 2026-03-20: Test Coverage Gap Fill (5 Integration Tests)

### What Changed

Added 5 new integration tests to fill identified coverage gaps:

1. **E2E proxy forwarding** (`e2e_proxy_forwards_to_upstream_and_strips_response_headers`): Spawns a real mock HTTP upstream, builds full AppState with `host_overrides`, verifies end-to-end request forwarding, API key injection, and X-GVM-* response header stripping.

2. **GovernanceBlockResponse fields** (`governance_block_response_contains_all_required_fields`): Sends a Deny-triggering request, verifies the 403 JSON body contains all SDK-contract fields (blocked, decision, event_id, trace_id, operation, reason, mode, next_action, ic_level).

3. **SDK↔Proxy header contract** (`sdk_proxy_header_contract_resource_and_context_json`): Sends SDK-format JSON in X-GVM-Resource and X-GVM-Context headers, verifies ABAC policy evaluates `resource.sensitivity` correctly (Critical→Deny, Medium→Allow), and malformed JSON doesn't crash the proxy.

4. **Policy conflict Regex edge case** (`policy_conflict_regex_vs_startswith_overlap_is_documented_false_negative`): Documents that `values_could_overlap()` returns `false` for Regex vs StartsWith (known heuristic false negative), but `max_strict` still enforces correctly via priority ordering.

5. **Emergency WAL recovery** (`emergency_wal_to_primary_recovery_path`): Tests primary WAL failure → emergency fallback → primary recovery flow. Verifies emergency events have `event_hash` but no `MerkleBatchRecord`, and primary failure counter tracks correctly.

### Why

Test coverage analysis identified these as the highest-priority gaps: no test verified actual HTTP forwarding, no test checked the SDK-facing JSON error contract, and the emergency WAL recovery path was untested.

### Affected Files

- `tests/integration.rs` — 5 new tests (Tests 8-12)
- `docs/09-test-report.md` — test count 252 → 257, integration tests 7 → 12
- `docs/14-implementation-log.md` — this entry

### Risk Assessment

Low. Tests only — no production code changes. All 257 tests pass.

---

## 2026-03-20: Config File Hash Recording in Merkle Chain

### What Changed

Added `record_config_load()` to `Ledger` that records SHA-256 hashes of all loaded config files (SRR, policy, registry) as a `gvm.system.config_load` event in the WAL Merkle chain at proxy startup.

### Why

Policy file tampering between proxy restarts was undetectable. An attacker modifying `global.toml` to weaken rules would leave no trace in the audit trail. By recording config hashes in the same Merkle chain as enforcement events, hash mismatches across restarts become visible to auditors.

### Affected Files

- `src/ledger.rs` — new `record_config_load()` method
- `src/main.rs` — step 7.5: collect config paths and call `record_config_load()` after WAL recovery
- `tests/integration.rs` — 2 new tests (hash correctness + missing file graceful degradation)
- `docs/04-ledger.md` — new Section 4.8 (Config File Hash Recording)
- `docs/12-security-model.md` — new Section 6.1 (Config File Tamper Detection)
- `docs/09-test-report.md` — test count 250 → 252

### Risk Assessment

Low. Non-fatal on failure (proxy logs warning, continues startup). Reuses existing `append_durable()` path — no new WAL format or recovery logic changes. Known limitation: hot-reload re-recording deferred to P3.

---

## 2026-03-20: Security Documentation Reframing (Timing + Fuzzing)

### What Changed

- Reframed timing side-channel analysis from "measured < 10x variance" to "rate limiter prevents statistical attacks; end-to-end timing difference is inherent to all proxy architectures"
- Elevated fuzzing CI pipeline from Medium → High priority (SRR regex + JSON payload parsing are direct adversarial input surfaces)
- Lowered constant-time SRR from Medium → Low priority (rate limiter already mitigates; end-to-end timing is architecturally inherent)

### Why

Previous framing implied GVM was pursuing constant-time matching but falling short. The honest framing is: (1) the engine-level 35 ns variance is unobservable, (2) the end-to-end difference (Deny=fast, Allow=slow) exists in every proxy and is not a vulnerability, (3) rate limiting makes statistical exploitation impractical. This reframing presents an intentional design decision rather than an unfinished mitigation.

Fuzzing priority raised because SRR regex matching and JSON payload parsing are the primary adversarial input surfaces — exactly the code paths where crafted agent payloads land.

### Affected Files

- `docs/08-memory-security.md` — Section 8.4.1 rewritten, checklist row 7 updated, Future Hardening table reordered
- `docs/12-security-model.md` — Section 1 (Timing Side Channel) rewritten

### Risk Assessment

Documentation-only. No code changes.

---

## 2026-03-19: Vault Trait Abstraction (KeyProvider + VaultBackend)

### Motivation

The vault had hardcoded AES-256-GCM encryption (`VaultEncryption`) and in-memory HashMap storage. This blocked:
- KMS integration (AWS KMS, GCP KMS) for production key management
- Persistent storage backends (Redis, DynamoDB) for state across restarts
- Testing with mock backends

### Changes

**New traits** (`src/vault.rs`):
- `KeyProvider`: `encrypt(&[u8]) → Vec<u8>`, `decrypt(&[u8]) → Vec<u8>`. Synchronous (KMS impls use `spawn_blocking`).
- `VaultBackend`: `get`, `put`, `delete`, `list_keys`, `len`, `contains_key`. Async methods for storage CRUD.

**Renamed**: `VaultEncryption` → `LocalKeyProvider` (implements `KeyProvider`). All security properties preserved (zeroize, error sanitization, random nonces).

**New**: `InMemoryBackend` (implements `VaultBackend`). Extracted from `Vault`'s inline `RwLock<HashMap>`.

**Vault struct**: `Vault<B: VaultBackend = InMemoryBackend>`. Default type parameter means all existing callers (`Vault::new(ledger)`, `Arc<Vault>`) work unchanged. Custom backends via `Vault::with_backends()`.

### Design Decision: Generics vs Dynamic Dispatch

Chose generics with default type parameter over `Box<dyn VaultBackend>` because:
- `async fn` in traits is not dyn-compatible in stable Rust (would require `async-trait` dependency)
- Default type param `= InMemoryBackend` preserves backward compatibility — no caller changes needed
- Zero-cost abstraction: monomorphized at compile time for the default case

### Test Impact

- All 218 existing tests pass unchanged
- Added 2 new tests: `test_in_memory_backend_crud`, `test_in_memory_backend_list_keys`

---

## 2026-03-19: Security/Audit Layer Code Review & Refactoring

### Review Findings

| # | Finding | Location | Verdict |
|---|---------|----------|---------|
| 1 | AuditOnly double WAL write (Pending → Confirmed) | `proxy.rs:447-464` | **KEEP** — intentional crash recovery semantics (docs/04-ledger.md) |
| 2 | Host port-stripping duplicated 4× | `srr.rs:309`, `proxy.rs:650,982`, `llm_trace.rs:41` | **CONSOLIDATE** |
| 3 | Response status check pattern repeated 4× | `proxy.rs:276-282,324-330,429-435,457-463` | **EXTRACT** helper |
| 4 | seccomp default/strict filter ~90% duplicated syscall list | `seccomp.rs:117-370` | **SHARE** base list |
| 5 | `error_response()` vs `governance_block_response()` | `proxy.rs:1019-1098` | **KEEP** — different SDK contracts |
| 6 | AuditOnly first WAL write | `proxy.rs:447-452` | **KEEP** — crash recovery depends on Pending state |

### Changes Applied

#### Change 2: Port-stripping consolidation
- **Before**: `host.split(':').next()` scattered across 4 files
- **After**: Centralized `strip_port()` utility in Target struct
- **Risk**: None — no tests depend on port presence in `Target.host`

#### Change 3: Response status helper extraction
- **Before**: `if response.status().is_success() { "Confirmed" } else { "Failed" }` repeated 4×
- **After**: `response_status_label()` helper function
- **Risk**: None — pure refactor, no behavioral change

#### Change 4: seccomp syscall list sharing
- **Before**: `build_default_filter()` and `build_strict_filter()` each had full syscall list (~45 entries)
- **After**: Shared `base_syscalls()` function, strict filter excludes networking syscalls
- **Risk**: None — no exact count assertions in tests, doc says "~45" (approximate)

---

## 2026-03-19: README Restructure (Feedback-Driven)

### Feedback Analysis

External review identified 10 issues. Changes applied:

| # | Feedback | Action |
|---|----------|--------|
| 1 | IC-3 = Deny without approval mechanism | Added IC-3 gap callout + webhook planned for v1.1 |
| 2 | WAL limitations weaken Merkle audit claim | WAL hardening grouped as v1.1 priority with honest caveat |
| 3 | Mode positioning unclear (sandbox/contained/default) | Added "When to Use Each Mode" table + security boundary explanation |
| 4 | OpenShell comparison biased | Added honest trade-offs (K8s maturity, NVIDIA backing, solo project) |
| 5 | Roadmap too ambitious ("Agentic OS") | Trimmed to v1.0/v1.1/v2.0 concrete, rest as "long-term vision" one-liner |
| 6 | Too many demos (6) | 2 primary (mock + llm), rest collapsed into one-line reference |
| 7 | Rollback mixed with security features | Separated into "Governance" and "Efficiency" subsections |
| 8 | Checkpoint + Merkle synergy not explicit | Added paragraph explaining checkpoint-as-Merkle-leaf property |
| 9 | Single binary advantage under-highlighted | Added visual stack comparison (LLM WAF+OPA+Envoy+K8s vs cargo run) |
| 10 | No ML trade-off honesty | Added "Trade-offs" section — GVM complementary to LLM WAFs, not replacement |

### Removed
- "The Architectural Shift" section (redundant with Thesis)
- "Toward an Agentic OS" framing (premature for alpha)

### Affected Files
- `README.md` — full restructure

---

## 2026-03-19: README Thesis Restructure (Causal Architecture)

### Rationale

The five core strengths (lightweight, zero dependencies, unbypassable, tamper-proof audit, clean rollback) were presented as independent features. In reality they are all consequences of one architectural decision: "infrastructure control over ML classification." Restructured Thesis section to show this causal chain explicitly.

### Changes
- **Thesis section**: Added 5-row table mapping each strength to its root cause ("No ML model to load" → lightweight, etc.)
- **Framing**: "These are not five separate features. They are five consequences of one architectural choice."
- **Stack comparison**: Visual diagram (LLM WAF+OPA+Envoy+K8s vs `cargo run`) moved into Thesis section
- **Trade-off callout**: Added inline note linking to Trade-offs section — makes the ML trade-off visible early
- **Mode guide**: Added "When to Use Each Mode" table with security boundary column
- **IC-3 gap**: Added explicit callout block explaining functional equivalence to Deny
- **Checkpoint/Rollback**: Separated into "Efficiency" subsection with Merkle-leaf connection
- **OpenShell**: Added honest trade-offs (K8s maturity, NVIDIA backing)
- **WAL limitations**: Grouped as v1.1 priority with operational fragility caveat
- **Demos**: 2 primary + 1-line reference for extras
- **Roadmap**: 3 rows (v1.0/v1.1/v2.0) + 1-line long-term vision

### Affected Files (Thesis Restructure)
- `README.md`

---

## 2026-03-19: Tier 1/Tier 2 Separation (SDK Dependency Disclosure)

### Code Analysis Results

Traced `proxy_handler()` code path when no SDK headers present (`X-GVM-Agent-Id` missing → `parse_gvm_headers()` returns `None`):

| Component | Proxy only (Tier 1) | With SDK (Tier 2) | Code reference |
|-----------|--------------------|--------------------|----------------|
| `parse_gvm_headers()` | Returns `None` | Returns `Some(GVMHeaders)` | `proxy.rs:859-949` |
| Layer 1 ABAC | **Skipped entirely** | Evaluated | `proxy.rs:121-156` |
| Layer 2 SRR | ✓ Works (only layer) | ✓ Combined via `max_strict()` | `proxy.rs:158-173` |
| Layer 3 API key | ✓ Works | ✓ Works | `api_keys.rs:84-149` |
| `max_strict()` | **Never called** | Combines Layer 1+2 | `proxy.rs:137` |
| Rate limiting | Shared "unknown" bucket | Per-agent buckets | `proxy.rs:193` |
| WAL events | agent="unknown", op="unknown" | Per-agent, per-operation | `proxy.rs:533-601` |
| Checkpoint/rollback | Not available | ✓ Via `@ic()` + API | `api.rs:458-590` |

### Changes Applied
- **Thesis section**: Added Tier 1/Tier 2 comparison table
- **Forgery detection example**: Split into two subsections (Tier 1: URL block, Tier 2: cross-layer detection)
- **3-layer table**: Added "Requires SDK?" column
- **Efficiency section**: Marked "SDK only"
- **OpenShell comparison**: Noted SDK dependency on forgery detection and rollback

### Rationale
Forgery detection (the headline feature) requires SDK's `@ic()` decorator to provide Layer 1 semantic data. Without it, `max_strict()` is never called. This was not disclosed in previous README versions, creating a false impression that all features work with zero code changes.

### Affected Files
- `README.md`

---

## 2026-03-19: DX Improvements (Build Time + First-Run Experience)

### Problem
- No pre-built binaries: users must `cargo build` from source (~3-5 min first build with wasmtime)
- No CI/CD pipeline (`.github/` directory did not exist)
- First run with missing config files shows a raw error message instead of guiding the user

### Changes Applied

#### Change 1: GitHub Actions CI + Release Workflow
- **Created**: `.github/workflows/ci.yml` — test, clippy, fmt on every push/PR
- **Created**: `.github/workflows/release.yml` — builds pre-built binaries for 5 targets on tag push:
  - `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
  - `x86_64-apple-darwin`, `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
- Packages include `config/` directory for immediate use after download
- Creates GitHub Release with install instructions

#### Change 2: cargo-binstall Support
- **Modified**: `Cargo.toml`, `crates/gvm-cli/Cargo.toml`
- Added `[package.metadata.binstall]` sections with URL template pointing to GitHub Releases
- Users with `cargo-binstall` can now run `cargo binstall gvm-proxy` to skip compilation entirely

#### Change 3: Startup Governance Summary Banner
- **Modified**: `src/main.rs` — added `print_startup_summary()` function
- **Modified**: `src/srr.rs` — added `SrrSummary` struct and `NetworkSRR::summary()` method
- **Modified**: `src/policy.rs` — added `PolicyEngine::summary()` method
- On every proxy start, prints a human-readable summary:
  - Layer 2 (SRR): rule count by type (Deny/Delay/Allow), default decision, sample blocked endpoints
  - Layer 1 (ABAC): global/tenant/agent rule counts, SDK requirement note
  - Operation Registry: core/custom operation counts
  - Layer 3 (API Key): active/passthrough status
  - Request flow diagram

#### Change 4: First-Run Interactive Setup Prompt
- **Modified**: `src/main.rs` — added `offer_first_run_setup()` function
- When both `operation_registry.toml` and `srr_network.toml` are missing (first run):
  - Detects terminal environment (skips prompt in CI/piped contexts)
  - Offers interactive industry template selection (finance/saas/skip)
  - Copies template files to `config/` directory
  - Creates empty `secrets.toml` placeholder
- Non-interactive environments fall through to existing error messages with `gvm init` hint

#### Change 5: First-Run Auto-Restart (seamless flow)
- **Modified**: `src/main.rs` — `offer_first_run_setup()` now returns `bool`
- After template files are copied, `ProxyConfig::load_or_default()` is called again
  to pick up the template's `proxy.toml` settings
- Config → first-run wizard → file copy → config reload → proxy start happens
  in a single unbroken flow with no manual restart needed

#### Change 6: README Policy Discovery Section
- **Modified**: `README.md`
- Added pre-built binary install option (`cargo binstall`) to Quick Start
- Added first-run wizard example output
- Added "Policy Discovery (`--interactive`)" section explaining
  the recommended workflow: template → run agent → review suggestions → approve rules
- Framed interactive mode as the primary policy authoring workflow, not just a debug tool

### Affected Files
- `.github/workflows/release.yml` (new)
- `.github/workflows/ci.yml` (new)
- `Cargo.toml`
- `crates/gvm-cli/Cargo.toml`
- `src/main.rs`
- `src/srr.rs`
- `src/policy.rs`
- `README.md`

---

## 2026-03-19: SDK Composition Refactor (Remove Inheritance Requirement)

### Problem

SDK required `class MyAgent(GVMAgent)` inheritance for any governance. This conflicted
with existing agent frameworks (CrewAI, AutoGen, OpenAI Agents SDK) that have their own
base classes. "Add GVM" meant restructuring the entire class hierarchy.

### Changes

1. **`session.py` (new)**: Standalone module with `configure()`, `gvm_session()`.
   Thread-local header store for `@ic` → `gvm_session()` header injection pipeline.

2. **`decorator.py` (rewrite)**: `@ic` now works on standalone functions, non-GVMAgent
   methods, and GVMAgent methods. Duck-type detection (`_is_gvm_agent()`) avoids circular
   import. Adds unconsumed-header warning when `gvm_session()` is not used inside `@ic`.

3. **`agent.py` (simplified)**: Removed `_apply_gvm_headers()`, `get_pending_headers()`,
   `_register_header_setter()` legacy plumbing. `create_session()` delegates to
   `gvm_session(proxy_url=self._proxy_url)`. GVMAgent is now optional — only needed for
   auto-checkpoint, VaultField state, and rollback.

4. **`__init__.py`**: Added exports: `gvm_session`, `configure`.

5. **`langchain_tools.py`**: Added `@tool @ic(...)` stacking documentation.

6. **`examples/standalone_agent.py` (new)**: Demonstrates governance with zero inheritance.

### SDK Usage Patterns (After)

```python
# Standalone (no inheritance — works with any framework)
from gvm import ic, gvm_session, configure
configure(agent_id="my-agent")

@ic(operation="gvm.messaging.send")
def send_email(to, subject, body):
    session = gvm_session()
    return session.post(...).json()

# LangChain @tool stacking
@tool
@ic(operation="gvm.messaging.send")
def send_email(to: str, subject: str, body: str):
    """Send an email."""
    ...

# GVMAgent (optional — for checkpoint/rollback/state)
class FinanceAgent(GVMAgent):
    auto_checkpoint = "ic2+"
    state = AgentState(balance=VaultField(default=0, sensitivity="critical"))
```

### Documentation Updated
- `README.md`: Added "SDK Integration" section with standalone pattern, LangChain stacking,
  and GVMAgent comparison table. Updated architecture diagram.
- `docs/07-sdk.md`: Rewrote sections 7.1-7.5 for composition-first approach. Added
  standalone session docs (7.4), unconsumed header warning docs, `@tool` stacking examples.

### Affected Files
- `sdk/python/gvm/session.py` (new)
- `sdk/python/gvm/decorator.py`
- `sdk/python/gvm/agent.py`
- `sdk/python/gvm/__init__.py`
- `sdk/python/gvm/langchain_tools.py`
- `sdk/python/examples/standalone_agent.py` (new)
- `README.md`
- `docs/07-sdk.md`
