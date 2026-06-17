# Analemma-GVM Technical Whitepaper

**Permission-grant runtime for AI agents — bounded actions, signed evidence, framework-independent**

Version: 0.5.3 | Whitepaper revision: 2026-06

---

## Abstract

Analemma-GVM (Governance Virtual Machine) is a **permission-grant runtime for autonomous AI agents**. It binds an agent's execution to a task-scoped set of HTTP, filesystem, and syscall permissions, enforces those permissions at the proxy and kernel layer, and produces a Merkle-chained, Ed25519-signed evidence trail that an external auditor can verify offline using only the public anchor key.

**Operational primitive.** The unit a user thinks in is not "give the agent a container" but "give the agent a *grant* for this task with these capabilities for this duration." That places GVM in the same product category as `docker run` (which gave operators "give the process a container") and IAM roles (which gave operators "give the workload a credential scope") — but for the agent-action layer, where the question is which network egress, which file write, and which API body shape an autonomous LLM-driven workflow is allowed to produce.

**Core thesis.** GVM does not make the model trustworthy. It makes the model's actions **bounded, auditable, and revocable**. The mechanism is structural rather than behavioral: agent code is unchanged, and a bypass requires either (a) compromising the host kernel (sandbox mode) or (b) breaking the cooperative `HTTP_PROXY` contract (cooperative mode, lower assurance, no sudo). The evidence chain rides on top of both modes and is the load-bearing piece for regulated workflows — claim review, internal coding agents, on-prem document review, sovereign AI deployments, CI/CD agent containment — where "the agent did X" must be *defensible to an auditor*, not just believed by an operator.

**Three enforcement modes** (same rules, three trust strengths):

- **Cooperative** — `HTTP_PROXY` env injection, runs on any OS, no root. Lowest assurance: depends on the agent's HTTP client honouring the env var.
- **`--sandbox`** — Linux kernel namespaces + seccomp-BPF (~130 syscalls) + iptables DNAT + per-sandbox MITM CA + overlayfs filesystem. Production default; bypass requires kernel-level escape.
- **`--contained`** — Docker isolation. **Experimental**, opt-in via `cargo build --release --features contained`. Host-side iptables egress lock works; in-container DNAT + CA injection NOT yet wired. Default release binary does not advertise this flag.

The **evidence boundary** (Merkle WAL + Ed25519 anchor + `gvm proof` CLI) ships in every mode and is described in §"Evidence Boundary" below.

---

## Architecture Overview

```
 Agent Process              GVM Runtime                     External
 ┌──────────────┐    ┌──────────────────────────┐    ┌──────────────┐
 │              │    │ Layer 0: DNS Governance   │    │              │
 │  Any agent   │───>│   Tiered delay on queries │───>│ DNS Resolver │
 │  (any lang)  │    │                            │    │              │
 │              │    │ Layer 1: HTTP Governance   │    │ Stripe       │
 │              │───>│   SRR + TokenBudget + Cred │───>│ Slack, Gmail │
 │              │    │                            │    │ GitHub, ...  │
 │              │    │ Layer 2: FS Governance     │    │              │
 │              │───>│   overlayfs + approve      │───>│ Host disk    │
 └──────────────┘    │                            │    └──────────────┘
                     │ WAL (Merkle chain)          │
                     │ AES-256-GCM Vault          │
                     │ seccomp-BPF (~130 syscalls) │
                     └──────────────────────────┘
```

### Governance Layer Model

| Layer | Name | Function | Bypass-Proof |
|-------|------|----------|-------------|
| 0 | DNS | Tiered delay on DNS queries (known=0ms, unknown=200ms, burst=3s, flood=10s). No Deny. | iptables DNAT forces all UDP 53 through governance proxy; seccomp blocks direct external DNS |
| 1 | HTTP (SRR) | URL/method/payload rule matching with cost governance | iptables DNAT forces all TCP 443 through MITM; TC ingress filter on host veth |
| 1+ | MITM upstream pool | Bounded LIFO pool of upstream HTTP/1.1 `SendRequest` handles (4 idle/host, 30 s TTL) — amortises the proxy↔upstream TLS handshake across requests, collapsing per-request MITM overhead from +528 ms to ~0 ms once the pool is warm. See [proxy.md §6.2.1](architecture/proxy.md#621-upstream-connection-pool-srcupstream_poolrs). | First request to a new host:port still pays one fresh handshake; subsequent requests reuse the cached connection until idle TTL expires |
| 2 | Filesystem | overlayfs copy-on-write + human approval | Mount namespace isolation; writes go to tmpfs upper layer |
| 3 | Capability Token | API key injection post-enforcement | Agent env has no external API keys; proxy injects after governance pass |

**Decision source**: SRR (Simple Request Rules) is the sole enforcement layer on Layer 1. Each rule yields one of five decisions; strictness ordering is total and deterministic. DNS (Layer 0) and FS (Layer 2) operate independently on their respective I/O channels.

### Enforcement Decision Model

Strictness order (total): `Allow (0) < AuditOnly (1) < Delay (2) < RequireApproval (3) < Deny (4)`

| Decision | Behavior |
|----------|----------|
| Allow | Immediate pass-through, async audit |
| AuditOnly | Allow, but force synchronous WAL write before forwarding |
| Delay | WAL-first write, configurable delay, then forward |
| RequireApproval | Blocked (returns 403). Approval workflow is agent/deployment responsibility, not GVM's |
| Deny | Unconditional block |

### Fail-Close Philosophy

When in doubt, block. The system defaults to **Delay 300ms** (Default-to-Caution) for any unrecognized request. If the WAL is unavailable, requests are rejected outright.

---

## Evidence Boundary

The Merkle WAL and the `gvm proof` CLI form the second half of GVM's value proposition. Where the **enforcement boundary** (above) decides whether an action happens, the **evidence boundary** answers the regulator's question: *"what exactly happened, who did it, under what policy, and prove it."*

### What Lands in the WAL

Every governance decision appends a structured JSON event with:

- **Subject** — `agent_id`, `tenant_id`, `session_id`, `token_id` (the `jti` from the JWT or `sandbox-peer:<id>` for namespace-bound identity, `None` for legacy entries)
- **Operation** — semantic operation name (`gvm.payment.charge`, `gvm.dns.query`, `http.POST`, etc.)
- **Resource descriptor** — `service`, `tier` (internal / external / customer-facing), `sensitivity` (low / medium / high / critical)
- **Decision** — one of Allow / AuditOnly / Delay / RequireApproval / Deny
- **Matched rule** — the SRR rule id and description that fired (None for Default-to-Caution)
- **Integrity context** — hash chain of the policy snapshot + config that was active at decision time
- **Event hash** — SHA-256 with domain-separation prefix, v1/v2/v3 dispatcher per `spec_version`

Batches of events are sealed at group-commit. The seal is a Merkle tree over the batch's event hashes; the root is signed with the operator-managed Ed25519 anchor key; the anchor signature is chained to the previous batch's anchor so a cross-rotation tamper is detectable.

### What `gvm proof` Exports

The proof bundle is a self-contained JSON document an auditor can verify offline using only the public anchor key. Contents:

| Field | Source | Purpose |
|-------|--------|---------|
| `event` (full or redacted) | WAL line | The decision record |
| `merkle_inclusion` | Merkle path | Proves the event is in the batch the seal covers |
| `batch_seal` | `BatchSealRecord` | The signed batch root + anchor signature |
| `config_chain` | `GvmIntegrityContext` | Short hash chain of policy + config active at decision time |
| `anchor_chain` | Cross-batch anchor history | Detects cross-rotation tamper |

Three CLI verbs:

```bash
gvm proof event   <event_id>   --wal data/wal.log   > evt.json     # single event
gvm proof batch   <batch_id>   --wal data/wal.log   > batch.json   # whole batch
gvm proof verify  evt.json     --anchor anchor.pub               # offline verify
```

`gvm proof verify` runs against just the public anchor key — the auditor does not need the host, the WAL, or the operator's signing material.

### What This Buys (and What It Does Not)

**Buys.** *Tamper-evident* audit: any local mutation of the WAL — by a compromised proxy, by an operator with shell access, by an attacker who has root — breaks the Merkle chain at the next verify. The chain is verifiable by anyone who has the anchor public key. Off-host replication via rsync / fluentd / vector / S3 is straightforward and turns the local tamper-evident chain into an externally-stored audit-grade record.

**Does not buy.** *Tamper-proof* logs. A host-root attacker can still delete or modify files; what they cannot do is change the WAL **without leaving a verifiable break in the chain**. The maturity ladder (see `docs/security-model.md`) extends through customer-managed signing keys, RFC 3161 external timestamping, WORM / S3 Object Lock storage, and HSM/KMS-backed signing — all hooks scoped for v0.7+. The current default ships customer-verifiable evidence inside a customer-managed-key model, which is the level most regulated workflows ask for first.

---

## Why HTTP Proxy?

### Two Enforcement Models and Their Tradeoffs

| Model | Strength | Weakness |
|-------|----------|----------|
| **Sandbox only** (seccomp/gVisor) | Impossible to bypass from userspace | Semantic blindness — sees `write(fd, buf, len)`, not "transfer $50K to account X" |
| **Proxy only** | Framework-agnostic, no agent cooperation needed | Without OS isolation, an agent can ignore `HTTP_PROXY` env vars and reach the network directly |

GVM combines both into a **proxy + sandbox hybrid**:

- **Level 0 (proxy only)**: Zero agent changes. SRR inspects URLs and payloads, API keys are injected by the proxy, all proxied traffic is audited. Suitable for development; in production an agent could in principle bypass the proxy by ignoring `HTTP_PROXY`.
- **Level 1 (+ `gvm run --sandbox`)**: Network namespace + seccomp containment for agents launched via `gvm run`. Proxy bypass is structurally impossible: iptables OUTPUT chain inside the sandbox namespace only allows TCP to the proxy port and UDP 53 (DNS) on the host veth IP — all other egress is dropped. IPv6 is fully disabled. Identity attribution for plain HTTP clients in this mode is automatic via the peer-IP → sandbox_id → agent_id lookup the proxy already maintains. **This is the recommended production posture on Linux.**

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

GVM's governance operates at one semantic level. A second level (content semantics) exists but is explicitly **out of scope** — it requires ML-based analysis, which contradicts GVM's deterministic design principle.

| Level | Name | What It Sees | GVM Coverage |
|-------|------|-------------|-------------|
| 1 | **Structural Semantics** | HTTP method, host, URL path, top-level JSON payload fields | **Covered** — SRR inspects transport-layer data |
| 2 | **Content Semantics** | Natural language meaning of payload text (e.g., "transfer all funds to offshore account") | **Not covered** — requires ML/NLP classification |

**Level 1 (Structural)**: SRR matches HTTP method + host pattern + path pattern. For single-endpoint APIs (GraphQL, gRPC), SRR additionally inspects a **single top-level JSON string field** via `payload_field` / `payload_match` — exact case-sensitive string equality only. No nested field access, no numeric comparison, no regex on payload values. See [SRR Payload Inspection Scope](srr.md) for precise specification.

**Level 2 (Content — Not Covered)**: GVM cannot determine whether the text content of a payload is harmful. For example, `POST api.bank.com/messages` with body `{"text": "transfer all funds to account X"}` passes SRR (the URL is a messaging endpoint). The *meaning* of the message text is invisible to deterministic pattern matching. Deployments requiring content-level governance should use an LLM WAF (Lakera, Prompt Armor, etc.) upstream of GVM. GVM and LLM WAFs are complementary: GVM governs what agents *do*, LLM WAFs analyze what agents *say*.

---

## Document Map

### For Users

Start here if you want to use GVM with your agents.

| Doc | What it covers |
|-----|----------------|
| [Quick Start](quickstart.md) | Build, run, isolate, MCP setup |
| [User Guide](user-guide.md) | Modes, sandbox, resource limits, proxy lifecycle |
| [Reference Guide](reference.md) | Configuration (`gvm.toml`), CLI, environment variables, API |
| [SRR Rules](srr.md) | Write URL-based rules in `gvm.toml` |
| [Security Model](security-model.md) | Threat model, known attack surface, mitigations |
| [Governance Coverage](governance-coverage.md) | Per-mode enforcement matrix |
| [Security Layers Comparison](security-layers.md) | GVM vs LLM safety, prompt guards, OPA |
| [Test Report](test-report.md) | Test coverage, benchmarks, chaos stress results |

### Architecture (`docs/architecture/`)

Internal design documents for contributors and code reviewers.

| Doc | Source |
|-----|--------|
| [WAL-First Ledger & Audit](architecture/ledger.md) | `src/ledger.rs` |
| [Encrypted Vault](architecture/vault.md) | `src/vault.rs` |
| [Proxy Pipeline](architecture/proxy.md) | `src/proxy.rs` |
| [Memory & Runtime Security](architecture/memory-security.md) | `crates/gvm-sandbox/` |
| [Changelog](internal/CHANGELOG.md) | Roadmap, implementation log |
| [Internal Security Review](internal/SECURITY_REVIEW.md) | Self-review + threat model + crypto inventory |

---

## Memory & Runtime Security Summary

See [Part 8: Memory & Runtime Security](architecture/memory-security.md) for full analysis.

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
| Task leak / backpressure | Bounded WAL mutex, group-commit batches | `ledger_concurrent_spawns_stay_bounded` |

---

## Test Coverage: 329 Tests (322 passing)

| Category | Count | Status | Source |
|----------|-------|--------|--------|
| Core unit (SRR, Vault, Merkle, Wasm, LLM Trace, Proxy, Auth, IntentStore, TLS, TokenBudget) | 147 | PASS | `src/*.rs` |
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
