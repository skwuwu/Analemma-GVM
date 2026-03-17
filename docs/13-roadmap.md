# Analemma-GVM Roadmap

> **Last updated**: 2026-03-17

---

## v1.0 — MVP Launch (Current)

### Core (Complete)

- [x] HTTP enforcement proxy (Rust/axum/tower)
- [x] 3-layer architecture (ABAC + SRR + API key isolation)
- [x] IC classification (Allow/Delay/RequireApproval/Deny)
- [x] `max_strict` cross-layer verification
- [x] Merkle tree audit ledger + WAL group commit
- [x] AES-256-GCM encrypted state cache (Vault)
- [x] Wasm runtime loader + host bridge (optional) + native fallback
- [x] Rate limiter (token bucket, per-agent)
- [x] Operation registry with namespace validation
- [x] 199 Rust tests (core unit + integration + adversarial + boundary + stress + CLI unit & integration + engine), 61 benchmark cases across 14 groups, 0 failures

### SDK (Complete)

- [x] Python SDK with `@ic` decorators
- [x] `auto_checkpoint = "ic2+"`
- [x] Checkpoint/rollback with Merkle tree verification
- [x] `GVMRollbackError` → LangChain tool error adapter
- [x] LLM thinking trace extraction (IC-2+ only)

### Checkpoint & Rollback (Complete)

- [x] Merkle proof-based checkpoint verification (same tree as WAL audit)
- [x] `X-GVM-Merkle-Verified` header — real verification (hardcoded `"true"` removed)
- [x] Domain separation hash prefix (`gvm-checkpoint-v1`)
- [x] Snapshot targets: conversation history + VaultField + local fields + execution position + last LLM response + metadata
- [x] `MAX_CHECKPOINT_SIZE` validation (5MB)
- [x] Conversation history truncation (`MAX_HISTORY_TURNS = 50`)
- [x] Checkpoint TTL + automatic cleanup (`MAX_CHECKPOINTS = 10`)
- [x] Rollback context injection into conversation history (LLM knows why it was rolled back)
- [x] Client-side hash cross-verification on save and restore
- [x] Checkpoint version check on restore (`gvm-checkpoint-v1`)
- [x] `checkpoint_delete` API endpoint for TTL cleanup
- [x] Graceful degradation on checkpoint save failure (warning only, execution continues)

### Demo (Complete)

- [x] Unified finance agent demo (all features in one scenario)
- [x] 4 domain demos (finance, email, DevOps, data analytics)
- [x] LLM demo (Claude autonomous agent)

### Config

- [x] LLM provider allowlist in SRR templates
- [x] Model allowlist via `payload_field` matching
- [ ] asciinema demo recording
- [ ] README restructure (Before/After diagram + condensed output)

### Docs

- [x] Security model & known attack surface (`docs/12-security-model.md`)
- [x] Threat model boundary + Assumption of Trust
- [x] `gvm run` design document
- [x] Why HTTP Proxy architectural rationale (`docs/00-overview.md`)
- [x] Vault naming clarification (Encrypted Agent State Cache)

### Launch

- [ ] LinkedIn article publish
- [ ] HN Show HN post
- [ ] First comment with architecture summary

---

## v1.1 — Hardening (Launch + 2-4 weeks)

### Code Quality (Code Review Feedback)

**Wasm Engine** (`src/wasm_engine.rs`):
- [x] `result_ptr` dealloc (memory leak fix)
- [x] Unknown decision → Delay (Fail-Close)
- [x] `MAX_RESPONSE_LEN` validation
- [ ] ABAC hot-path execution via Wasm engine (current request path uses native `policy.evaluate`)
- [ ] Ed25519 module signature verification + hash pinning + fail-close required mode

**Policy Engine** (`src/policy.rs`):
- [x] Regex pre-compile at load time
- [x] Unknown operator → bail (Fail-Close)
- [x] Debug format → explicit `as_policy_str()` (`tier_as_policy_str`, `sensitivity_as_policy_str`)
- [ ] Decimal-based numeric comparison for financial precision (current: f64, boundary-case rounding risk)

**SRR** (`src/srr.rs`):
- [x] Port number stripping in `match_host`
- [x] Oversized body: `continue` to next rule (documented design intent)
- [x] `path_regex` field for regex-based path matching (pre-compiled at load, O(n) guaranteed)
- [ ] Hash Map / Trie index for O(1) host+method lookup (current: O(N) linear scan, ~300µs @ 10K rules)
- [ ] `Cow<'a, str>` in `normalize_path` / `normalize_host` to reduce allocations on hot path

**Ledger** (`src/ledger.rs`):
- [x] Shutdown flush remaining batch
- [x] Recovery dedup by `event_id`
- [ ] `wal_sequence` persist across restart (currently resets to 0)
- [ ] Streaming WAL recovery (`BufReader` line-by-line instead of `read_to_string`)
- [ ] WAL rotation (size-based segment split with Merkle chain linking)

**Rate Limiter** (`src/rate_limiter.rs`):
- [x] Mutex poison → return false (Fail-Close)
- [x] Stale bucket eviction (`BUCKET_IDLE_TTL`)
- [x] Tokens clamp on policy change (`bucket.tokens.min(new_max)`)

**Registry** (`src/registry.rs`):
- [x] Duplicate operation name detection
- [x] Segment content validation (alphanumeric + underscore, non-empty, `validate_segments()`)

**Vault** (`src/vault.rs`):
- [x] Dev key → random ephemeral key
- [x] `list_keys` audit log
- [x] Error sanitization (no internal details in API responses; upstream errors sanitized)

**API** (`src/api.rs`):
- [x] `/gvm/check` includes `target_path` field
- [x] `/gvm/info` returns summary counts (not Debug format)
- [x] Checkpoint Merkle tree verification (was hardcoded `"true"`)
- [x] `checkpoint_delete` endpoint for TTL cleanup

**API Keys** (`src/api_keys.rs`):
- [x] Agent Authorization header strip (+ Cookie, X-API-Key, ApiKey)
- [ ] File permission check on `secrets.toml`

**Merkle** (`src/merkle.rs`):
- [x] `tampered_events` tracking in `VerificationReport`
- [x] `status` / `decision_source` in `compute_event_hash`

**gvm-engine** (`crates/gvm-engine/`):
- [x] Context attributes in `build_field_map` (`EvalRequest.context` + "context." prefix flattening)
- [x] Operator case normalization (`to_lowercase()` — accepts PascalCase, snake_case, and symbols)

### Security

- [ ] Vault API authentication (agent_id prefix scoping)
- [x] Checkpoint Merkle tree verification (O(log N) proof, same tree as WAL)
- [x] Timing side-channel: documented as "not constant-time but practically non-exploitable"

### Checkpoint Hardening

- [ ] HMAC-signed checkpoint step (prevent arbitrary step restore)
- [ ] Configurable `MAX_CHECKPOINT_SIZE` per agent via policy
- [ ] Configurable `MAX_HISTORY_TURNS` per agent via policy

### Config Templates

- [ ] LLM provider SRR templates (OpenAI, Anthropic, Gemini)
- [ ] Industry templates (finance, healthcare, SaaS)

---

## v2.0 — Runtime & Infrastructure (Launch + 2-3 months)

### `gvm run` — Network Namespace Enforcement

- [x] `gvm run --sandbox` Linux-native namespace isolation (`CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET`)
- [x] veth pair + iptables DNAT path to proxy
- [x] iptables OUTPUT chain lockdown (proxy TCP + DNS UDP only, all else DROP)
- [x] IPv6 fully disabled (sysctl + ip6tables DROP fallback)
- [x] MASQUERADE restricted to proxy port only
- [x] FORWARD DROP for veth traffic to non-proxy destinations
- [x] DNS alignment (resolv.conf + iptables both use host veth IP)
- [x] seccomp-BPF sandbox profile (default + strict)
- [x] Docker fallback mode (`gvm run --contained`)
- [x] Sandbox preflight gating for critical prerequisites (`CAP_NET_ADMIN`, `ip`, `iptables`, userns, seccomp)
- [x] Local proxy auto-start for `gvm run` when localhost target is unreachable
- [ ] Mandatory-by-default interception profile (reject non-contained launch in production)
- [ ] Transparent proxy parity (`SO_ORIGINAL_DST`, CONNECT tunnel)
- [ ] macOS/Windows host-level interception fallback (currently Docker fallback only)
- [ ] Static library list for common interpreters (Python, Node) as ldd fallback
- [ ] `mknod`-based /dev node creation as alternative to bind-mount

### Agent Identity

- [ ] JWT issued by `gvm run`, verified by proxy middleware
- [ ] `agent_id` / `tenant_id` from JWT claims (not self-declared)
- [ ] Token expiration + refresh

### Distributed Backend

- [ ] NATS JetStream integration (WAL → NATS async publish)
- [ ] Redis persistent Vault backend
- [ ] Policy hot-reload (`SIGHUP` or file watch)

### Proxy Enhancements

- [ ] TLS termination + certificate management
- [ ] HTTP CONNECT tunnel support (for HTTPS transparent proxy)
- [x] SSE response passthrough with bounded thinking trace tap (1MB capture)
- [ ] gRPC detection + passthrough (no inspection yet)
- [ ] Pluggable isolation backend interface:
  - `gvm run --isolation=namespace` (default)
  - `gvm run --isolation=firecracker` (planned)
  - `gvm run --isolation=docker` (dev/test)

### Vault Hardening

- [ ] KMS integration (AWS KMS, GCP KMS)
- [ ] Key rotation support
- [ ] KDF (Argon2id) for env-var derived keys

### Checkpoint & Rollback

- [ ] Proxy-controlled step numbers (atomic counter, multi-agent safe)
- [ ] Full LLM response storage (replay fidelity)
- [ ] Snapshot + diff pattern (incremental checkpoints for large state)
- [ ] Checkpoint browser (compare state across time points)

### SDK

- [ ] Worker-level tracing (`X-GVM-Worker-Id` from `os.getpid()`)
- [ ] TypeScript/Node.js SDK
- [ ] Go SDK

### Observability

- [ ] Prometheus metrics endpoint (`/gvm/metrics`)
- [ ] WAL verification CLI (`gvm events verify`)
- [ ] Dashboard template (Grafana)

---

## v3.0 — Platform (Launch + 6-12 months)

### Generic Outbound Capability Governance

- [ ] Filesystem governance (mount namespace, r/w/delete policies)
- [ ] Shell governance (seccomp allowlist: `execve`, `fork`, `clone`)
- [ ] Database governance (L4 TCP policy: allow/deny by host:port)
- [ ] Capability flag: `gvm run --capabilities=http,filesystem:read`
- [ ] Operation namespace extension:
  - `gvm.filesystem.read/write/delete`
  - `gvm.shell.execute`
  - `gvm.database.query/write`

### Protocol Expansion

- [ ] WebSocket frame-level inspection
- [ ] gRPC method-level policy (protobuf descriptor loading)
- [ ] SMTP inspection (for direct email agents)

### Multi-Agent

- [ ] Agent-to-agent communication governance
- [ ] Trust delegation (agent A grants agent B limited capability)
- [ ] Shared audit trail across agent cluster

### Enterprise

- [ ] Multi-tenant SaaS deployment mode
- [ ] Approval UI for RequireApproval (IC-3) — optional; HITL workflow is deployment/agent responsibility, not GVM core
- [ ] Envoy filter mode (GVM as Envoy Wasm filter)
- [ ] OPA policy format compatibility layer
- [ ] Firecracker isolation backend
- [ ] SOC 2 / ISO 27001 audit report generation

### Advanced Rollback

- [ ] Saga Coordinator (IC-2 compensation actions)
- [ ] Operation-specific rollback strategies
- [ ] Cross-agent causal quarantine

---

## Non-Issues (Assessed and Closed)

Reported during security audit — determined to be non-vulnerabilities. Documented to prevent re-investigation. See [security-model.md](12-security-model.md) for detailed analysis.

- AES-GCM nonce collision (Birthday bound: ~770M years at 1000 writes/day)
- Unbounded X-GVM-Context header (hyper/axum enforces ~64KB limit)
- Operation name CRLF injection (`HeaderValue::to_str()` rejects non-visible ASCII)
- Checkpoint step `u64::MAX` (normal HashMap key, no overflow)
- SRR body size bypass (Default-to-Caution fallback catches unmatched requests)
- Vault `list_keys()` cross-agent (no API endpoint exposes this)
- SDK credential header pass-through (proxy strips at Layer 3)
- Rate limiter agent ID spoofing (same root cause as unauthenticated proxy access)

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
