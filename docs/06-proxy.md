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
┌──────────────────────────────────────────────────┐
│  Tower Middleware Stack                           │
│  1. CatchPanicLayer    ← Panic → 500 (not crash) │
│  2. RequestBodyLimitLayer(1MB) ← OOM defense     │
│  3. ConcurrencyLimitLayer(1024) ← FD exhaustion  │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│  Parse Request                                    │
│  - Extract GVM headers (X-GVM-Agent-Id, etc.)     │
│  - Extract target (X-GVM-Target-Host or Host)     │
└──────────────────────┬───────────────────────────┘
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
┌──────────────────────────────────────────────────┐
│  Rate Limit Check (if Throttle decision)          │
│  Token-bucket per agent_id                        │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│  Enforcement (by decision type)                   │
│                                                   │
│  Allow → forward immediately, async audit         │
│  Delay → WAL write, sleep(ms), forward            │
│  RequireApproval → WAL write, return 403           │
│  Deny → WAL write, return 403                     │
│  Throttle → forward (rate already checked)         │
│  AuditOnly → WAL write, forward, elevate alert    │
└──────────────────────┬───────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────┐
│  Forward to Upstream                              │
│  1. Inject API credentials (Layer 3)              │
│  2. Remove X-GVM-* headers                        │
│  3. Build outbound URI                            │
│  4. HTTP client → upstream                        │
└──────────────────────────────────────────────────┘
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
→ Update event status (Confirmed/Failed)
→ Best-effort WAL status update
```
Latency: configured delay (default 300ms) + WAL write (< 1ms).

### RequireApproval (IC-3)
```
→ WAL append (fsync)
→ Return HTTP 403: "IC-3: Administrator approval required"
→ Event status: Pending (awaiting human decision)
```
The request is **never forwarded**. Human must approve via a separate channel.

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

**Order matters**: Panic catch is outermost (catches panics from any inner layer). Body limit is next (rejects before buffering). Concurrency limit is innermost (applied after body is accepted).

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

## 6.9 Test Coverage

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

[← Part 5: Encrypted Vault](05-vault.md) | [Part 7: Python SDK →](07-sdk.md)
