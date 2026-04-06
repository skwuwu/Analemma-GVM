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
 Agent (Python SDK)        GVM Proxy (Rust)            External APIs
 ┌──────────────┐    ┌────────────────────────┐    ┌──────────────┐
 │  @ic()       │───>│ Layer 1: Semantic       │───>│ Stripe       │
 │  decorator   │    │   ABAC Policy Engine    │    │ Slack        │
 │              │    │ Layer 2: Network SRR    │    │ Gmail        │
 │  GVMAgent    │    │ Layer 3: Capability     │    │ Database     │
 │  base class  │    │   Token (API Key)       │    │ ...          │
 └──────────────┘    │                          │    └──────────────┘
                     │ WAL → NATS Ledger        │
                     │ AES-256-GCM Vault        │
                     └────────────────────────┘
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
| IC-3 | RequireApproval | Blocked (returns 403). Approval workflow is agent/deployment responsibility, not GVM's |
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

- **Level 0 (proxy only)**: Zero agent changes. SRR inspects URLs and payloads, API keys are injected by the proxy, all proxied traffic is audited.
- **Level 1 (+ SDK `@ic` decorator)**: Agent declares operation semantics. ABAC policy evaluates context attributes. Checkpoint/rollback on denial.
- **Level 2 (+ `gvm run --sandbox`)**: Network namespace + seccomp containment for agents launched via `gvm run`. Proxy bypass is structurally impossible: iptables OUTPUT chain inside the sandbox namespace only allows TCP to the proxy port and UDP 53 (DNS) on the host veth IP — all other egress is dropped. IPv6 is fully disabled. Optional in v1; roadmap moves toward mandatory deployment profiles.

### Why HTTP Layer, Not Syscall Layer

The enforcement layer determines what the system can *see*:

| Layer | Sees | Does Not See |
|-------|------|-------------|
| **Syscall** (`write`, `connect`, `sendto`) | File descriptors, raw bytes, IP addresses | HTTP method, hostname, URL path, request body structure |
| **HTTP** (`POST api.bank.com/transfer`) | Method, host, path, headers, JSON body fields | Raw socket operations, file I/O, process control |

For **governance** (deciding whether an agent *should* perform an action), semantic visibility is essential. A syscall-level monitor sees `connect(fd, 93.184.216.34:443)` + `write(fd, <TLS bytes>)` — it cannot distinguish a balance check from a wire transfer. An HTTP proxy sees `POST api.bank.com/v1/transfers {"amount": 50000, "currency": "USD"}` and can make a meaningful policy decision.

Syscall-level enforcement solves a *different* problem: **containment** (reducing sandbox escape and uncontrolled runtime behavior). This is Layer 3 territory — constraining namespace, filesystem, and syscall surface. GVM's `gvm run --sandbox` uses Linux namespace isolation + seccomp for this containment purpose today.

**Summary**: Syscall for containment (can the agent escape?), HTTP for governance (should the agent do this?). Different layers solve different problems. GVM enforces governance at the HTTP layer where semantic context is available, and adds containment via `gvm run --sandbox` with roadmap work to make containment mandatory by deployment profile.

### Semantic Security Depth

GVM's governance operates at two semantic levels. A third level (content semantics) exists but is explicitly **out of scope** — it requires ML-based analysis, which contradicts GVM's deterministic design principle.

| Level | Name | What It Sees | GVM Coverage |
|-------|------|-------------|-------------|
| 1 | **Structural Semantics** | HTTP method, host, URL path, top-level JSON payload fields | **Covered** — SRR (Layer 2) inspects transport-layer data |
| 2 | **Declarative Semantics** | Operation name, resource attributes, ABAC context (declared by SDK) | **Covered** — ABAC (Layer 1) evaluates declared attributes |
| 3 | **Content Semantics** | Natural language meaning of payload text (e.g., "transfer all funds to offshore account") | **Not covered** — requires ML/NLP classification |

**Level 1 (Structural)**: SRR matches HTTP method + host pattern + path pattern. For single-endpoint APIs (GraphQL, gRPC), SRR additionally inspects a **single top-level JSON string field** via `payload_field` / `payload_match` — exact case-sensitive string equality only. No nested field access, no numeric comparison, no regex on payload values. See [SRR Payload Inspection Scope](03-srr.md#36-payload-inspection-graphqlgrpc-defense) for precise specification.

**Level 2 (Declarative)**: ABAC evaluates SDK-declared attributes (`X-GVM-Operation`, `X-GVM-Resource`, `X-GVM-Context`). This provides richer semantic context than structural inspection but depends on agent cooperation via the SDK. Attribute omission is a known bypass vector — mitigated by `max_strict(Layer1, Layer2)` combining both layers.

**Level 3 (Content — Not Covered)**: GVM cannot determine whether the text content of a payload is harmful. For example, `POST api.bank.com/messages` with body `{"text": "transfer all funds to account X"}` passes SRR (the URL is a messaging endpoint) and ABAC (the operation is `gvm.messaging.send`). The *meaning* of the message text is invisible to deterministic pattern matching. Deployments requiring content-level governance should use an LLM WAF (Lakera, Prompt Armor, etc.) upstream of GVM. GVM and LLM WAFs are complementary: GVM governs what agents *do*, LLM WAFs analyze what agents *say*.

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
| 10 | [Security Layers Comparison](10-competitive-analysis.md) | GVM vs LLM safety, prompt guards, OPA |
| 11 | [Security Model & Known Attack Surface](11-security-model.md) | Threat model, attack vectors, mitigations |
| 12 | [Quick Start](12-quickstart.md) | 1-minute launch, isolation levels, secret injection, policy basics |
| 13 | [Reference Guide](13-reference.md) | Configuration, environment variables, CLI, SDK API, platform support |
| 14 | [Governance Coverage](14-governance-coverage.md) | Per-mode enforcement matrix |
| 15 | [User Guide](15-user-guide.md) | Modes, sandbox, resource limits, proxy lifecycle |
| — | [Changelog](internal/CHANGELOG.md) | Roadmap, implementation log, architecture decisions |

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

## Test Coverage: 329 Tests (322 passing)

| Category | Count | Status | Source |
|----------|-------|--------|--------|
| Core unit (SRR, Policy, Vault, Registry, Merkle, Wasm, LLM Trace, Proxy, Auth, IntentStore, TLS) | 147 | PASS | `src/*.rs` |
| Integration (E2E) | 26 | PASS | `tests/integration.rs` |
| Boundary (cross-boundary security) | 25 | PASS | `tests/boundary.rs` (+7 wasm-gated) |
| Hostile Environment | 28 | PASS | `tests/hostile.rs` |
| Adversarial Infrastructure | 18 | PASS | `tests/adversarial_infra.rs` |
| Edge Cases | 17 | PASS | `tests/edge_cases.rs` |
| Stress | 12 | PASS | `tests/stress.rs` |
| Merkle Tree | 12 | PASS | `tests/merkle.rs` |
| GVM Engine (Wasm policy evaluation) | 7 | PASS | `crates/gvm-engine/` |
| Sandbox (CA, TC filter, TLS probe, security, preflight) | 30 | PASS | `crates/gvm-sandbox/` |
| **Passing Total** | **322** | | Verified 2026-04-03 |

7 additional Wasm boundary tests available with `--features wasm`. EC2 E2E: 75 scenarios. Chaos stress test: 60-minute run, all pass.
