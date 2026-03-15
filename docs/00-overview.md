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

## Document Map

| Part | Title | File |
|------|-------|------|
| 1 | [Operation Namespace & Registry](01-operations.md) | `src/registry.rs` |
| 2 | [ABAC Policy Engine](02-policy.md) | `src/policy.rs` |
| 3 | [Network SRR Engine](03-srr.md) | `src/srr.rs` |
| 4 | [WAL-First Ledger & Audit](04-ledger.md) | `src/ledger.rs` |
| 5 | [Encrypted Vault](05-vault.md) | `src/vault.rs` |
| 6 | [Proxy Pipeline](06-proxy.md) | `src/proxy.rs` |
| 7 | [Python SDK](07-sdk.md) | `sdk/python/gvm/` |
| 8 | [Memory & Runtime Security](08-memory-security.md) | (this whitepaper) |
| 8.7 | [OS Isolation & MicroVM Assessment](08-memory-security.md) | `crates/gvm-sandbox/` |
| 9 | [Test Coverage Report](09-test-report.md) | `tests/hostile.rs` |

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

## Test Coverage: 60 Tests

| Category | Count | Source |
|----------|-------|--------|
| Unit: Policy Engine (ABAC) | 4 | `src/policy.rs` |
| Unit: Operation Registry | 4 | `src/registry.rs` |
| Unit: Vault Encryption | 7 | `src/vault.rs` |
| Unit: Network SRR | 10 | `src/srr.rs` |
| Integration: Hostile Environment | 10 | `tests/hostile.rs` |
| **Total** | **60** (25 lib + 25 bin + 10 integration) | |

All tests pass. Zero failures.
