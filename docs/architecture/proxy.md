# Part 6: Proxy Pipeline

**Source**: `src/proxy.rs`, `src/main.rs` | **Config**: `config/proxy.toml`

---

## 6.1 Overview

The Proxy Pipeline is the central enforcement point. Every HTTP request — whether SDK-routed or direct — passes through a 3-layer security classification, enforcement decision, and conditional forwarding pipeline. The pipeline integrates all components: Policy Engine (Layer 1), Network SRR (Layer 2), Capability Token injection (Layer 3), Ledger, Vault, and Rate Limiter.

**Design principle**: The proxy is a transparent enforcement layer. Agent code is unchanged. The agent's HTTP traffic is routed through the proxy (via `HTTP_PROXY` env or SDK configuration), and the proxy enforces governance before forwarding.

---

## 6.2 Request Flow

```
Agent HTTP Request
       │
       ▼
┌─────────────────────────────────────────────────────┐
│  Tower Middleware Stack                             │
│  1. CatchPanicLayer    ← Panic → 500 (not crash)   │
│  2. RequestBodyLimitLayer(1MB) ← OOM defense        │
│  3. ConcurrencyLimitLayer(1024) ← FD exhaustion     │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Parse Request                                      │
│  - Extract GVM headers (X-GVM-Agent-Id, etc.)       │
│  - Extract target (X-GVM-Target-Host or Host)       │
└────────────────────────┬────────────────────────────┘
                         │
                ┌────────┴────────┐
                │ GVM headers?    │
                ▼                 ▼
       SDK-Routed            Direct HTTP
                │                 │
                ▼                 ▼
  ┌─────────────────┐  ┌─────────────────┐
  │ Layer 1: ABAC   │  │ Layer 2: SRR    │
  │ Policy Engine   │  │ (URL-based)     │
  │ + Layer 2: SRR  │  │                 │
  │                 │  │                 │
  │ max_strict(     │  │ decision =      │
  │   srr, policy)  │  │   srr.check()   │
  └────────┬────────┘  └────────┬────────┘
           │                    │
           └────────┬───────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│  Rate Limit Check (if Throttle decision)            │
│  Token-bucket per agent_id                          │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Enforcement (by decision type)                     │
│                                                     │
│  Allow → forward immediately, async audit           │
│  Delay → WAL write, sleep(ms), forward              │
│  RequireApproval → WAL write, return 403            │
│  Deny → WAL write, return 403                       │
│  Throttle → forward (rate already checked)          │
│  AuditOnly → WAL write, forward, elevate alert      │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│  Forward to Upstream                                │
│  1. Inject API credentials (Layer 3)                │
│  2. Remove X-GVM-* headers                          │
│  3. Build outbound URI                              │
│  4. HTTP client → upstream                          │
└─────────────────────────────────────────────────────┘
```

---

## 6.3 Classification Paths

### SDK-Routed (GVM Headers Present)

When `X-GVM-Agent-Id` is present, the request came through the SDK's `@ic()` decorator:

1. Build `OperationMetadata` from GVM headers
2. Evaluate ABAC policy: `policy.evaluate(operation)` → policy decision
3. Evaluate SRR: `srr.check(method, host, path, body)` → srr decision
4. Combine: `max_strict(srr_decision, policy_decision)` → **final decision**

### Direct HTTP (No GVM Headers)

When no GVM headers are present, the request bypassed the SDK:

1. Evaluate SRR only: `srr.check(method, host, path, body)` → **final decision**

This ensures that even raw HTTP calls (e.g., `curl`) are subject to Layer 2 enforcement.

---

## 6.4 GVM Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-GVM-Agent-Id` | Yes | Agent identity for policy lookup |
| `X-GVM-Operation` | No | Declared operation name |
| `X-GVM-Trace-Id` | No | Causal trace identifier |
| `X-GVM-Event-Id` | No | Unique event ID |
| `X-GVM-Parent-Event-Id` | No | Parent event for causal chain |
| `X-GVM-Resource` | No | JSON resource descriptor |
| `X-GVM-Context` | No | JSON ABAC context attributes |
| `X-GVM-Session-Id` | No | Session identifier |
| `X-GVM-Tenant-Id` | No | Tenant/organization identifier |
| `X-GVM-Target-Host` | No | Forwarding target host |
| `X-GVM-Rate-Limit` | No | Per-operation rate limit |

All `X-GVM-*` headers are **stripped** before forwarding to upstream APIs. The upstream never sees proxy-internal metadata.

---

## 6.5 Enforcement Behavior by Decision Type

### Allow (IC-1)
```
→ Forward immediately
→ Async ledger (no WAL, fire-and-forget NATS)
→ Event status: Confirmed
```
Latency: ~0ms enforcement overhead.

### Delay (IC-2)
```
→ WAL append (fsync) — Fail-Close on failure
→ Sleep(milliseconds)
→ Forward to upstream
→ Extract LLM thinking trace (if known LLM provider) — see 6.9
→ Update event status (Confirmed/Failed)
→ Best-effort WAL status update
```
Latency: configured delay (default 300ms) + WAL write (< 1ms).

### RequireApproval (IC-3)
```
→ WAL append (fsync), event status: Pending
→ Hold HTTP response (oneshot channel)
→ Wait for POST /gvm/approve or timeout (default 300s)
→ If approved: forward to upstream, return response
→ If denied or timeout: return HTTP 403 (fail-close)
```
The proxy **holds the HTTP connection open** and waits for human approval via `POST /gvm/approve` (admin API port 9090) or `gvm approve` CLI. On timeout, the request is auto-denied (fail-close). The agent experiences the approval wait as a slow HTTP response, not an immediate 403.

### Deny
```
→ WAL append (fsync)
→ Return HTTP 403 with reason
→ Event status: Failed { reason: "Denied: ..." }
```

### Throttle
```
→ Rate limiter check (token-bucket per agent)
→ If exceeded: HTTP 429 "Rate limit exceeded"
→ If allowed: forward, async audit
```

### AuditOnly
```
→ WAL append (fsync)
→ Forward to upstream
→ Update event status
→ If alert_level == Critical: operator notification log
```

---

## 6.6 Layer 3: Capability Token Injection

After enforcement, the proxy injects API credentials from the `APIKeyStore`:

```rust
// src/api_keys.rs
pub fn inject(&self, headers: &mut HeaderMap, host: &str) -> Result<()> {
    match self.credentials.get(host) {
        Some(Credential::Bearer { token }) => {
            headers.insert(AUTHORIZATION, format!("Bearer {}", token));
        }
        Some(Credential::ApiKey { header, value }) => {
            headers.insert(header, value);
        }
        None => {} // No credential for this host
    }
}
```

**Security guarantee**: The agent process never has access to API keys. Keys are loaded from `config/secrets.toml` (encrypted in production) and injected by the proxy only after enforcement passes. Even if an agent's memory is compromised, no API credentials are exposed.

---

## 6.7 Backpressure Stack

The Tower middleware stack provides three layers of runtime protection:

| Layer | Purpose | Configuration |
|-------|---------|---------------|
| `CatchPanicLayer` | Convert panics to HTTP 500 (never crash) | Always on |
| `RequestBodyLimitLayer` | Reject bodies > 1MB (OOM defense) | 1,048,576 bytes |
| `ConcurrencyLimitLayer` | Limit in-flight requests (FD exhaustion) | 1,024 connections |

**Order matters**: Tower applies layers in reverse declaration order. The concurrency limit is checked first (rejects when at capacity), body limit is next (rejects oversized bodies), and panic catch is innermost (converts panics from the handler into HTTP 500). In code, `CatchPanicLayer` is declared first but wraps outermost in the call stack.

---

## 6.8 Startup Sequence

```
1. Load config (proxy.toml)                    ← Fail: panic
2. Load Operation Registry (registry.toml)     ← Fail: panic
3. Load Network SRR rules (srr_network.toml)   ← Fail: panic
4. Load ABAC Policy Engine (policies/*.toml)   ← Fail: panic
5. Load API Key Store (secrets.toml)           ← Fail: panic
6. Initialize Ledger (WAL + NATS stub)         ← Fail: panic
7. WAL Crash Recovery                          ← Fail: warn (first boot)
8. Initialize Vault (AES-256-GCM)              ← Fail: panic
9. Build HTTP client                           ← —
10. Compose AppState                           ← —
11. Build Router + middleware                   ← —
12. Bind TCP listener                          ← Fail: panic
13. Serve                                      ← Running
```

**Fail-Close**: Steps 1–6 and 8 are fatal. If any component fails to initialize, the proxy does not start. This prevents a partially configured proxy from silently allowing traffic.

---

## 6.9 LLM Thinking Trace Extraction

**Source**: `src/llm_trace.rs` (379 lines, 8 unit tests)

When the proxy processes an IC-2 (Delay) response from a known LLM provider, it performs **best-effort bounded extraction** of reasoning/thinking content for governance audit.

Extraction behavior is transport-aware to avoid output drops:

- **JSON (`application/json`)**: tap-stream captures up to 256KB (`MAX_JSON_TRACE_CAPTURE_BYTES`) of the response body for extraction. The response is forwarded immediately (no pre-buffering). `Content-Length` is **not** checked — all JSON responses from known LLM providers are tapped regardless of size, but only the first 256KB is captured for trace extraction.
- **SSE (`text/event-stream`)**: tap-stream captures up to 1MB (`MAX_SSE_TRACE_CAPTURE_BYTES`) for best-effort extraction. The response streams through immediately. On stream completion, any extracted trace is appended asynchronously as a follow-up WAL update.

### Activation Conditions

Trace extraction baseline conditions:

1. The enforcement decision is **Delay** (IC-2 path)
2. The target host matches a **known LLM provider** (`identify_llm_provider()`)
3. The upstream response status is **2xx** (successful)

Additional extraction gates by response type:

- **JSON**: requires `Content-Type: application/json`; tap capture is bounded to 256KB
- **SSE**: requires `Content-Type: text/event-stream`; tap capture is bounded to 1MB

IC-1 (Allow) responses are forwarded without buffering. Deny/RequireApproval responses never reach upstream.

### Supported Providers

| Provider | Host Pattern | Thinking Field | Model Field |
|----------|-------------|---------------|-------------|
| OpenAI | `api.openai.com` | `choices[0].message.reasoning_content` | `model` |
| Anthropic | `api.anthropic.com` | `content[].thinking` (type=thinking blocks) | `model` |
| Google Gemini | `generativelanguage.googleapis.com` | `candidates[0].content.parts[].thought=true` | `modelVersion` |

### Data Flow

```
Agent → Proxy (IC-2 Delay) → Upstream LLM API
                     │
                     ▼
                 identify_llm_provider(host)
                     │
                  ┌─────┴─────┐
                  No          Yes
                  │            │
                  ▼            ▼
                Return      inspect content-type
                as-is             │
                         ├─ JSON: bounded buffer (≤256KB, known length)
                         │      ├─ collect fail: explicit 502 upstream error
                         │      └─ extract trace → event.llm_trace
                         │
                         └─ SSE: passthrough stream + bounded tap (≤1MB)
                                └─ stream end: extract trace → async WAL update
```

Failure semantics:

- JSON bounded-buffer collect failure returns explicit `502 Bad Gateway` (never silent empty success body).
- SSE upstream stream errors pass through as upstream stream errors; trace update is skipped when extraction cannot complete.

### Truncation

Thinking content is truncated to **2,048 bytes** (UTF-8 boundary safe). The `truncated` flag is set to `true` when content exceeds this limit. This prevents unbounded WAL growth while preserving the critical first portion for governance review.

### WAL Event Integration

The `GVMEvent` struct includes an optional `llm_trace` field:

```rust
// crates/gvm-types/src/lib.rs
pub struct LLMTrace {
    pub provider: String,           // "openai" | "anthropic" | "gemini"
    pub model: Option<String>,      // e.g. "o1-preview", "claude-sonnet-4-20250514"
    pub thinking: Option<String>,   // Extracted reasoning (truncated to 2KB)
    pub truncated: bool,            // Whether thinking was truncated
    pub usage: Option<LLMUsage>,    // Token usage stats
}

pub struct LLMUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}
```

### Governance Use Cases

- **Audit trail**: Record what the LLM was "thinking" when it decided to take a governed action
- **Post-incident analysis**: Investigate reasoning behind blocked operations
- **Cost attribution**: Token usage per agent, per operation, per tenant
- **Model compliance**: Verify that only approved models are being used

### Test Coverage (8 tests in `src/llm_trace.rs`)

| Test | Scenario |
|------|----------|
| `test_identify_llm_provider` | Host matching including port stripping |
| `test_extract_openai_reasoning` | OpenAI `reasoning_content` extraction |
| `test_extract_anthropic_thinking` | Anthropic `thinking` block extraction |
| `test_extract_gemini_thought` | Gemini `thought=true` parts extraction |
| `test_no_thinking_content_returns_usage_only` | No reasoning, usage data only |
| `test_non_llm_body_returns_none` | Non-JSON body returns None |
| `test_truncation` | Content > 2KB truncated with flag |
| `test_empty_provider_returns_none` | Unknown provider returns None |

---

## 6.10 CONNECT Tunnel (HTTPS Proxy)

**Source**: `src/proxy.rs` (function `connect_tunnel`)

For HTTPS traffic, clients issue a `CONNECT host:port` request. The proxy performs a **blind TCP relay** — TLS content is not inspected (no MITM). Policy enforcement is limited to domain and port level.

### Flow

```
Client                    Proxy                       Upstream
  │                         │                            │
  │─── CONNECT host:443 ──>│                            │
  │                         │── check_domain(host) ────>│
  │                         │   (SRR domain-level)      │
  │                         │                            │
  │                   ┌─────┴─────┐                      │
  │                   │ Decision  │                      │
  │                   ▼           ▼                      │
  │              Allow/Delay    Deny                     │
  │                   │           │                      │
  │                   │     ←─ 403 ──                    │
  │                   │                                  │
  │  ←─ 200 ─────────│                                  │
  │                   │── TCP connect ──────────────────>│
  │<══════════════════╪══ Blind relay (bidirectional) ══>│
  │                   │                                  │
```

### Domain-Level Policy (`check_domain()`)

Unlike normal HTTP requests where SRR matches method + host + path, CONNECT tunnels only have a host to evaluate. The `check_domain()` function applies these rules:

| Condition | Decision |
|-----------|----------|
| Any non-Deny, non-catch-all rule exists for this host | Allow |
| Only Deny rules exist for this host | Deny |
| No rules match at all | Default-to-Caution (Delay 300ms) |

### WAL Integration

- **Denied tunnels**: Synchronous WAL write with transport info (`method: "CONNECT"`, `path: ":port"`).
- **Allowed tunnels**: Async WAL write (loss tolerated, same as IC-1). Tunneled content is not auditable since TLS is opaque.

### Shadow Mode for CONNECT

When Shadow Mode is enabled, CONNECT requests are also subject to intent verification. In `Strict` mode, a CONNECT without a prior `gvm_declare_intent` is denied. Intent is confirmed immediately upon tunnel establishment (no WAL for tunneled content).

### Limitations

- No path-level or body-level enforcement (requires TLS inspection, planned for v0.2).
- No method-level enforcement (CONNECT is always the method).
- Port is logged but not currently used for policy decisions.

---

## 6.11 Shadow Mode and Intent Store

**Source**: `src/intent_store.rs`, `src/proxy.rs`, `src/api.rs`

Shadow Mode adds a **2-phase intent verification** layer on top of standard SRR/ABAC enforcement. Before making an outbound HTTP request, the agent declares its intent (via MCP tool or SDK). The proxy then verifies that incoming requests match a previously declared intent.

### Intent Lifecycle

```
MCP gvm_declare_intent
        │
        ▼
  POST /gvm/intent → IntentStore::register()
        │
        ▼
   ┌──────────┐
   │  Active   │ ← Ready to be claimed
   └─────┬────┘
         │  proxy request arrives
         ▼
   ┌──────────┐
   │ Claimed   │ ← Marked, pending WAL write
   └─────┬────┘
    ┌────┴─────┐
    │          │
    ▼          ▼
 confirm()  release()
 (WAL OK)   (WAL fail)
    │          │
    ▼          ▼
 Consumed   Active
 (deleted)  (restored)
```

**Invariant**: Intent deletion occurs ONLY on `confirm()`. This ensures: no decision without audit, no audit without decision (TOCTOU prevention).

### Shadow Modes

Controlled via `GVM_SHADOW_MODE` environment variable:

| Mode | On unverified request | Recommended for |
|------|----------------------|-----------------|
| `strict` | Deny (HTTP 403) | Production |
| `cautious` | Delay (default 5000ms) + audit warning | Staging / rollout |
| `permissive` | Allow + audit warning | Onboarding / development |
| `disabled` | No verification (default) | Legacy / opt-out |

### ABAC Re-evaluation

When a claimed intent includes an `operation` name, Shadow Mode performs ABAC re-evaluation using the declared operation. If the combined decision (ABAC + SRR) is stricter than the SRR-only decision, the stricter decision is used. This catches cases where the agent's declared operation would itself be restricted by policy.

### Configuration

```toml
# In proxy.toml or via environment variables
[shadow]
mode = "strict"          # or cautious, permissive, disabled
intent_ttl_secs = 30     # Intent expiry (default: 30s)
cautious_delay_ms = 5000 # Delay for cautious mode (default: 5000ms)
```

### Limits and Safety

- **Max intents**: 10,000 (hard cap). Returns HTTP 429 when exceeded.
- **Claim timeout**: 10 seconds (2x typical WAL fsync). Orphaned claims are released back to Active.
- **Case-insensitive matching**: Method and host matching is case-insensitive.
- **Path prefix matching**: Intent path is matched as a prefix of the request path.
- **Mutex poison**: Returns unverified (fail-closed) on mutex poison.

---

## 6.12 Control Plane Endpoints

The proxy exposes management endpoints under the `/gvm/` path prefix. These are handled directly by the proxy (never forwarded to upstream).

### `POST /gvm/reload` — SRR Hot-Reload

Reloads SRR rules from the config file without restarting the proxy. Atomically swaps the rule set. On parse failure, existing rules are preserved.

**Request**: No body required.

**Response (success)**:
```json
{"reloaded": true, "rules": 42}
```

**Response (parse failure)**:
```json
{"reloaded": false, "error": "Parse failed: ... Existing rules preserved."}
```

### `POST /gvm/intent` — Register Shadow Mode Intent

Registers a declared intent for shadow verification. Called by MCP tools or SDK before the agent makes an outbound HTTP request.

**Request**:
```json
{
  "method": "POST",
  "host": "api.slack.com",
  "path": "/api/chat.postMessage",
  "operation": "gvm.messaging.send",
  "agent_id": "agent-001",
  "ttl_secs": 30
}
```

**Response (success, 201)**:
```json
{
  "registered": true,
  "intent_id": 1,
  "method": "POST",
  "host": "api.slack.com",
  "path": "/api/chat.postMessage",
  "operation": "gvm.messaging.send",
  "ttl_secs": 30,
  "shadow_mode": "Strict"
}
```

**Response (capacity exceeded, 429)**:
```json
{"error": "Intent store full (max 10000)"}
```

### `POST /gvm/check` — Dry-Run Policy Check

Evaluates ABAC + SRR policies without forwarding, WAL writing, or credential injection. Useful for pre-flight checks and UI tooling.

**Request**:
```json
{
  "operation": "gvm.payment.charge",
  "target_host": "api.bank.com",
  "target_path": "/transfer/123",
  "method": "POST",
  "resource": {"service": "stripe", "tier": "external", "sensitivity": "critical"}
}
```

**Response**:
```json
{
  "decision": "Deny",
  "srr_decision": "Deny { reason: \"Wire transfer blocked\" }",
  "engine_ms": 0.1,
  "operation": "gvm.payment.charge",
  "method": "POST",
  "target_host": "api.bank.com",
  "matched_rule": "Wire transfer rule",
  "dry_run": true,
  "next_action": "This operation is blocked by policy. Contact your administrator."
}
```

**Fields**: `operation` defaults to `"unknown"`, `method` defaults to `"POST"`, `target_host` defaults to `"unknown"`, `target_path` defaults to `"/"`. When `operation` is `"unknown"` or `"test"`, only the SRR decision is returned (ABAC is not meaningful without a real operation).

---

## 6.13 Test Coverage

Proxy pipeline tests are covered indirectly through:

| Test | Component Tested |
|------|-----------------|
| `header_forgery_srr_denies_bank_transfer_regardless` | SDK path + max_strict |
| `max_strict_deny_overrides_allow` | Decision combination logic |
| `srr_100_concurrent_checks_complete_without_blocking` | SRR under load |
| `rate_limiter_100_concurrent_checks_no_deadlock` | Rate limiter concurrency |
| Python `hostile_demo.py` — Test 2 | End-to-end header forgery (HTTP 403) |
| Python `hostile_demo.py` — Test 3 | End-to-end payload OOM (proxy survives) |

---

## 6.14 Governance Block Response

When the proxy blocks an operation (Deny, RequireApproval, Throttle, or infrastructure failure), it returns a standard `GovernanceBlockResponse` JSON body. This is the contract between the proxy and all agent SDKs — every blocked request uses this format so agents can react programmatically.

### Response Schema

```json
{
  "blocked": true,
  "decision": "Deny",
  "event_id": "evt-abc-123",
  "trace_id": "trace-xyz",
  "operation": "gvm.messaging.send",
  "reason": "Policy rule finance-002 blocks transfers above $10,000",
  "mode": "halt",
  "next_action": "Contact administrator to request an exception",
  "retry_after_secs": null,
  "rollback_hint": "trace-xyz",
  "matched_rule_id": "finance-002",
  "ic_level": 3
}
```

### Block Response Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `halt` | Stop execution immediately. Agent must not retry. | Deny: categorically forbidden operations |
| `soft_pivot` | Suggest alternatives. Agent may adapt and retry differently. | RequireApproval: downgrade scope or wait for approval |
| `rollback` | Roll back current transaction and retry after conditions change. | Throttle: rate limit exceeded, retry after window |

### Configuration

```toml
[enforcement.on_block]
deny = "halt"                    # Deny: stop execution immediately
require_approval = "soft_pivot"  # IC-3: suggest alternatives
throttle = "rollback"            # Rate limit: roll back and retry later
infrastructure_failure = "halt"  # WAL/disk failure: halt for safety
```

### HTTP Headers

Block responses include these headers for SDK consumption:

| Header | Description |
|--------|-------------|
| `X-GVM-Decision` | Decision type (Deny, RequireApproval, Throttle) |
| `X-GVM-Block-Mode` | Block response mode (halt, soft_pivot, rollback) |
| `X-GVM-Event-Id` | Audit trail correlation ID |
| `X-GVM-Trace-Id` | Distributed trace correlation ID |
| `X-GVM-Rollback-Hint` | Trace ID for SDK checkpoint recovery |
| `Retry-After` | Seconds to wait before retrying (Rollback mode only) |

---

[← Part 5: Encrypted Vault](architecture/vault.md) | [Part 7: Python SDK →](architecture/sdk.md)
