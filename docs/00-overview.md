# Analemma-GVM Technical Whitepaper

**AI Agent Governance Virtual Machine — Security Kernel Architecture**

Version: 0.1.0 | Date: 2026-03-14

---

## Abstract

Analemma-GVM is a transparent enforcement proxy for AI agent I/O operations. It enforces security policies at the infrastructure level, ensuring that no agent — regardless of framework, language, or behavior — can bypass governance controls. The system operates as a "security kernel" sitting between AI agents and external APIs.

**Core thesis**: Security must be structural, not behavioral. Agent code is unchanged. Enforcement is guaranteed by the proxy layer.

---

## Architecture Overview

```
 Agent (Python SDK)        GVM Proxy (Rust)           External APIs
 ┌──────────────┐    ┌──────────────────────┐    ┌──────────────┐
 │  @ic()       │───>│ Layer 1: Semantic     │───>│ Stripe       │
 │  decorator   │    │   ABAC Policy Engine  │    │ Slack        │
 │              │    │ Layer 2: Network SRR  │    │ Gmail        │
 │  GVMAgent    │    │ Layer 3: Capability   │    │ Database     │
 │  base class  │    │   Token (API Key)     │    │ ...          │
 └──────────────┘    │                      │    └──────────────┘
                     │ WAL → NATS Ledger    │
                     │ AES-256-GCM Vault    │
                     └──────────────────────┘
```

### 3-Layer Security Model

| Layer | Name | Function | Bypass-Proof |
|-------|------|----------|-------------|
| 1 | Semantic (ABAC) | Operation-level policy evaluation | SDK declares operation; proxy evaluates ABAC rules |
| 2 | Network (SRR) | URL-based rule matching | Even if SDK lies about operation, URL is inspected independently |
| 3 | Capability Token | API key injection | Agent never holds API keys; proxy injects them post-enforcement |

**Combined Decision**: `max_strict(Layer1, Layer2)` — the stricter decision always wins.

### Enforcement Decision Model (IC Classification)

| IC Level | Decision | Behavior |
|----------|----------|----------|
| IC-1 | Allow | Immediate pass-through, async audit |
| IC-2 | Delay | WAL-first write, configurable delay, then forward |
| IC-3 | RequireApproval | Blocked until human approves |
| — | Deny | Unconditional block |

### Fail-Close Philosophy

When in doubt, block. The system defaults to **Delay 300ms** (Default-to-Caution) for any unrecognized request. If the WAL is unavailable, requests are rejected outright.

---

## Why HTTP Proxy?

### Three Enforcement Models and Their Tradeoffs

| Model | Strength | Weakness |
|-------|----------|----------|
| **SDK only** | Rich semantic context (operation name, resource, ABAC attributes) | Agent can bypass by not using the SDK |
| **Sandbox only** (seccomp/gVisor) | Impossible to bypass from userspace | Semantic blindness — sees `write(fd, buf, len)`, not "transfer $50K to account X" |
| **Proxy only** | Framework-agnostic, no agent cooperation needed | Cannot see agent-internal intent (operation name, IC level) |

No single model covers all requirements. GVM uses a **proxy + SDK hybrid**:

- **Level 0 (proxy only)**: Immediate value with zero agent changes. SRR inspects URLs and payloads, API keys are injected by the proxy, and all proxied traffic is audited. This is the "Datadog pattern" — drop in a proxy, get visibility instantly.
- **Level 1 (+ SDK `@ic` decorator)**: Agent declares operation semantics. ABAC policy evaluates context attributes. Checkpoint/rollback on denial. Progressive adoption — the agent opts in to richer governance.
- **Level 2 (+ `gvm run --sandbox`)**: Network namespace + seccomp containment for agents launched via `gvm run`. It steers child HTTP clients to a proxy path using veth+DNAT, reducing direct egress bypass risk versus cooperative mode. Optional in v1; roadmap moves toward mandatory deployment profiles.

This progressive adoption path mirrors how observability tools (Datadog, New Relic) gain traction: start with infrastructure-level metrics (free), then instrument application code for traces and custom metrics (opt-in). GVM starts with network-level governance (free), then adds semantic governance (opt-in).

### Why HTTP Layer, Not Syscall Layer

The enforcement layer determines what the system can *see*:

| Layer | Sees | Does Not See |
|-------|------|-------------|
| **Syscall** (`write`, `connect`, `sendto`) | File descriptors, raw bytes, IP addresses | HTTP method, hostname, URL path, request body structure |
| **HTTP** (`POST api.bank.com/transfer`) | Method, host, path, headers, JSON body fields | Raw socket operations, file I/O, process control |

For **governance** (deciding whether an agent *should* perform an action), semantic visibility is essential. A syscall-level monitor sees `connect(fd, 93.184.216.34:443)` + `write(fd, <TLS bytes>)` — it cannot distinguish a balance check from a wire transfer. An HTTP proxy sees `POST api.bank.com/v1/transfers {"amount": 50000, "currency": "USD"}` and can make a meaningful policy decision.

Syscall-level enforcement solves a *different* problem: **containment** (reducing sandbox escape and uncontrolled runtime behavior). This is Layer 3 territory — constraining namespace, filesystem, and syscall surface. GVM's `gvm run --sandbox` uses Linux namespace isolation + seccomp for this containment purpose today.

**Summary**: Syscall for containment (can the agent escape?), HTTP for governance (should the agent do this?). Different layers solve different problems. GVM enforces governance at the HTTP layer where semantic context is available, and adds containment via `gvm run --sandbox` with roadmap work to make containment mandatory by deployment profile.

---

## Document Map

| Part | Title | File |
|------|-------|------|
| 1 | [Operation Namespace & Registry](01-operations.md) | `src/registry.rs` |
| 2 | [ABAC Policy Engine](02-policy.md) | `src/policy.rs` |
| 3 | [Network SRR Engine](03-srr.md) | `src/srr.rs` |
| 4 | [WAL-First Ledger & Audit](04-ledger.md) | `src/ledger.rs` |
| 5 | [Encrypted Vault](05-vault.md) | `src/vault.rs` |
| 6 | [Proxy Pipeline](06-proxy.md) | `src/proxy.rs` |
| 6.9 | [LLM Thinking Trace Extraction](06-proxy.md) | `src/llm_trace.rs` |
| 7 | [Python SDK](07-sdk.md) | `sdk/python/gvm/` |
| 8 | [Memory & Runtime Security](08-memory-security.md) | (this whitepaper) |
| 8.7 | [OS Isolation & MicroVM Assessment](08-memory-security.md) | `crates/gvm-sandbox/` |
| 9 | [Test Coverage Report](09-test-report.md) | `tests/hostile.rs` |
| 10 | [Architecture Changes](10-architecture-changes.md) | `docs/10-architecture-changes.md` |
| 11 | [Competitive Analysis: GVM vs OPA+Envoy](11-competitive-analysis.md) | `docs/11-competitive-analysis.md` |
| 12 | [Security Model & Known Attack Surface](12-security-model.md) | `docs/12-security-model.md` |
| 13 | [Roadmap: Planned Features & Future Enhancements](13-roadmap.md) | `docs/13-roadmap.md` |

---

## Memory & Runtime Security Summary

See [Part 8: Memory & Runtime Security](08-memory-security.md) for full analysis.

| Threat | Mitigation | Test |
|--------|-----------|------|
| Key material in RAM | `zeroize` crate, Drop impl zeros key | `vault_key_is_zeroed_on_drop` |
| Nonce reuse (AES-GCM) | `rand::random()` per encrypt | `test_nonce_reuse_not_possible` |
| OOM from large payload | `max_body_bytes` + 1MB body limit | `large_64kb_body_does_not_crash_or_oom` |
| Panic kills proxy | `CatchPanicLayer` in tower stack | `srr_garbage_input_does_not_panic` |
| Connection exhaustion | `ConcurrencyLimitLayer(1024)` | `rate_limiter_100_concurrent_checks` |
| WAL corruption | JSON parse skip, recovery continues | `wal_tampered_entry_does_not_crash_recovery` |
| Side-channel timing | Measured <10x variance | `srr_decision_time_is_roughly_constant` |
| Decryption error leak | Generic error, internal log only | `test_wrong_key_returns_integrity_error` |
| Task leak / backpressure | Bounded WAL mutex, NATS spawn is fire-and-forget | `ledger_concurrent_spawns_stay_bounded` |

---

## Test Coverage: 146 Tests

| Category | Count | Source |
|----------|-------|--------|
| Unit (SRR, Policy, Vault, Registry, Merkle, Wasm, LLM Trace) | 54 | `src/lib.rs` |
| Integration (E2E) | 5 | `tests/integration.rs` |
| Boundary | 30 | `tests/boundary.rs` |
| Edge Cases | 17 | `tests/edge_cases.rs` |
| Hostile Environment | 11 | `tests/hostile.rs` |
| Stress | 12 | `tests/stress.rs` |
| Merkle Tree | 12 | `tests/merkle.rs` |
| Engine (gvm-engine) | 5 | `crates/gvm-engine/` |
| **Total** | **146** | |

All tests pass. Zero failures.
