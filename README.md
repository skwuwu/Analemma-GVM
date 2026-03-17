# Analemma-GVM

**Governance Virtual Machine — A Security Kernel for AI Agent I/O**

**Status: v0.1.0-alpha (pre-release software).**

> **How is this different from NVIDIA OpenShell?**
> OpenShell sandboxes agents with Docker+K3s (allow/deny).
> GVM governs agent actions with graduated enforcement,
> semantic forgery detection, and checkpoint rollback(with SDK) —
> in a single binary, no container runtime required.
> [See comparison →](#openshell-comparison)

> Smarter models do not mean safer systems.
> Safety must be structural, not behavioral.

<p align="center">
  <img src="demo.svg" alt="Analemma-GVM Unified Finance Agent Demo" width="860">
</p>

> *The recording above is a live demo using my personal Claude API key. To try GVM without an API key or personal Agent, run `python -m gvm.mock_demo` — same proxy enforcement, pre-scripted LLM decisions.*

---

## Why GVM?

| Approach | What it does | What it misses |
|----------|-------------|----------------|
| Prompt guardrails | Asks the model to behave | Bypassed by jailbreak or bugs |
| Sandbox (Docker/K8s) | Constrains the environment | Binary allow/deny only |
| Policy engines (OPA) | Evaluates metadata | Trusts what the agent declares |
| **GVM** | **Governs actual HTTP actions** | **Alpha — not hardened** |

Only GVM: graduated enforcement, semantic forgery detection, checkpoint rollback, Merkle-verified audit. No Docker required.

---

## The Problem

AI agents are getting better at doing things. That is exactly the problem.

A model that can compose emails, query databases, and call payment APIs is one prompt injection away from doing all three without authorization. Today's safety strategy — instruction tuning, guardrails in the prompt, RLHF alignment — operates at the **behavioral** level. It asks the model to be good. But a sufficiently capable model, a jailbreak, or a simple bug can bypass behavioral constraints entirely.

**Model sophistication is not control.** The gap between what an agent *can* do and what it *should* do is an infrastructure problem, not a model problem.

### The Contrarian Bet

Most AI security companies focus on prompt defense — a WAF for LLMs. We believe that approach is fundamentally limited. Language is ambiguous, but **syscalls are precise**. You cannot reliably determine intent from a prompt, but you *can* determine exactly what HTTP endpoint an agent is calling, with what payload, and whether it has authorization.

**We don't correct what agents *say*. We control what agents *do*.**

This is the same insight that separates OS-level security from application-level security. Anti-virus scans files; the kernel enforces permissions. We are building the kernel.

---

## The Thesis

Analemma-GVM is built on a single thesis:

**Security must be enforced at the infrastructure level, not the application level.**

The agent's code is unchanged. The agent doesn't know it's being governed. Every outbound HTTP request passes through a transparent proxy that classifies the operation, evaluates policy, and decides — in real time — whether to allow, delay, block, or escalate.

The agent cannot bypass this. Not because it's told not to, but because the architecture makes bypass structurally impossible:

- The agent has no API keys (Layer 3 injects them post-enforcement)
- The agent's declared operation is cross-checked against the actual URL (Layer 2 catches lies)
- If the proxy is down, the agent has no network path to external APIs (Fail-Close)

This is not a wrapper. This is a **kernel**.

---

## How It Catches a Lie — In 10 Seconds

```python
# Agent attempts a forgery attack
@ic(operation="gvm.storage.read")       # "I'm just reading data"
def steal_money(self):
    requests.post("https://api.bank.com/transfer/123",
                  json={"amount": 50000, "to": "attacker"})
```

```
 What the agent SAYS          What the agent DOES          What GVM decides
 ─────────────────────────────────────────────────────────────────────────────

 "gvm.storage.read"           POST api.bank.com/transfer   DENY
       │                              │                       ▲
       ▼                              ▼                       │
 ┌───────────┐               ┌──────────────┐          ┌─────┴────────┐
 │  Layer 1  │               │   Layer 2    │          │ max_strict   │
 │  (ABAC)   │               │   (SRR)      │          │              │
 │           │               │              │          │ Stricter     │
 │  Allow    │               │  DENY        │──────────│ always wins  │
 │  (IC-1)   │               │  "Wire       │          │              │
 │           │               │   transfer   │          │ → DENY       │
 └───────────┘               │   blocked"   │          └──────────────┘
                             └──────────────┘

 Layer 1 is fooled.           Layer 2 sees the URL.       Agent is blocked.
 Layer 2 is not.              It doesn't care what        403 Forbidden.
                              the header says.
```

**The agent's lie is irrelevant.** Layer 2 inspects the actual HTTP target — not the semantic header. The proxy takes `max_strict(Allow, Deny)` = **Deny**. The wire transfer never executes. The attempt is recorded in the WAL with a full audit trail.

---

## Quick Start

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo run                       # First build: 2-5 min (one-time). Subsequent runs: ~1s.
pip install -e sdk/python       # Install SDK (one-time)
gvm run my_agent.py             # Run your agent through GVM
```

That's it. Your agent's code is unchanged. Every outbound HTTP request now passes through the governance proxy.

```
 Your agent                GVM Proxy (:8080)                External API
 ┌──────────┐    HTTP      ┌──────────────────────┐  HTTPS  ┌──────────┐
 │ Any code │────PROXY────>│ URL check + policy   │────────>│ Stripe   │
 │ Any lang │              │ Key inject + audit   │         │ Gmail    │
 └──────────┘              └──────────────────────┘         └──────────┘
```

**Try the demo** (no API key needed):

```bash
cargo run                       # Terminal 1
python -m gvm.mock_demo         # Terminal 2 — mock LLM, real proxy enforcement
```

**Or run your own agent** — any language, any framework:

```bash
# Option A: gvm run (recommended — auto-starts proxy, sets up isolation)
gvm run my_agent.py                 # Proxy auto-starts, HTTP_PROXY set automatically
gvm run --sandbox my_agent.py       # + Linux namespace isolation (production)
gvm run --contained my_agent.py     # + Docker isolation (any OS)

# Option B: Manual proxy (any language)
HTTP_PROXY=http://localhost:8080 python my_agent.py
HTTP_PROXY=http://localhost:8080 node my_agent.js
HTTP_PROXY=http://localhost:8080 ./my_agent
```

> Platform support, SDK usage, isolation modes, LLM provider governance, checkpoint/rollback — see [Quick Start Guide →](docs/14-quickstart.md)

---

## Architecture

```
 Agent (Python SDK)        GVM Proxy (Rust)           External APIs
 ┌──────────────┐    ┌───────────────────────┐    ┌──────────────┐
 │  @ic()       │───>│ Layer 1: Semantic     │───>│ Stripe       │
 │  decorator   │    │   ABAC Policy Engine  │    │ Slack        │
 │              │    │ Layer 2: Network SRR  │    │ Gmail        │
 │  GVMAgent    │    │ Layer 3: Capability   │    │ Database     │
 │  base class  │    │   Token (API Key)     │    │ ...          │
 └──────────────┘    │                       │    └──────────────┘
                     │ WAL → NATS Ledger     │
                     │ AES-256-GCM Vault     │
                     └───────────────────────┘
```

### Why 3 Layers, Not 1

A single policy engine can be fooled. If the agent declares `storage.read` but sends a wire transfer, a semantic-only policy would allow it. The 3-layer model eliminates this:

| Layer | What It Checks | Why It Exists |
|-------|---------------|---------------|
| **Layer 1: Semantic (ABAC)** | Operation name, resource, context | Handles the happy path — SDK-declared operations |
| **Layer 2: Network (SRR)** | Actual URL, method, payload | Catches lies — inspects what the agent *does*, not what it *says* |
| **Layer 3: Capability Token** | API key injection | Removes the means — agent never holds credentials |

The final decision is `max_strict(Layer1, Layer2)` — the stricter ruling always wins.

### IC Classification (Enforcement Decisions)

| Level | Decision | Behavior |
|-------|----------|----------|
| IC-1 | Allow | Immediate pass-through, async audit |
| IC-2 | Delay | WAL-first write, configurable delay, then forward |
| IC-3 | RequireApproval | Blocked (returns 403). Approval workflow is agent/deployment responsibility |
| — | Deny | Unconditional block |

### Components

| Component | Moat | Details |
|-----------|------|---------|
| **ABAC Policy Engine** | Hierarchical rules (Global > Tenant > Agent), lower layers can only be stricter | [Details →](docs/02-policy.md) |
| **Network SRR** | URL inspection independent of SDK headers, regex path matching, payload inspection | [Details →](docs/03-srr.md) |
| **WAL-First Ledger** | Crash-safe audit: fsync before action, Merkle hash chain, NATS distribution | [Details →](docs/04-ledger.md) |
| **Encrypted Vault** | AES-256-GCM + `zeroize` on drop, no key material in freed memory | [Details →](docs/05-vault.md) |
| **Proxy Pipeline** | CatchPanicLayer + backpressure + 1024 connection limit, sub-μs policy eval | [Details →](docs/06-proxy.md) |
| **Python SDK** | `@ic()` decorator, auto-checkpoint/rollback, causal tracing, LangChain adapter | [Details →](docs/07-sdk.md) |
| **OS Isolation** | Linux namespace + seccomp-BPF (`--sandbox`), Docker fallback (`--contained`) | [Details →](docs/08-memory-security.md) |

> Full technical whitepaper: [Architecture Overview →](docs/00-overview.md)

---

## Demos

| Demo | What it shows | API key needed? |
|------|--------------|----------------|
| `python -m gvm.mock_demo` | Mock LLM + real proxy enforcement | No |
| `python -m gvm.unified_demo` | Scripted 4-step finance agent | No |
| `python -m gvm.hostile_demo` | Adversarial security tests | No |
| `python -m gvm.llm_demo` | Claude autonomous agent | Yes (`ANTHROPIC_API_KEY`) |
| `python -m gvm.langchain_demo` | LangChain + Gmail integration | Yes |
| `python -m gvm.rollback_demo` | Checkpoint/rollback + token savings | Yes |

All demos require the proxy (`cargo run`). The mock demo uses pre-scripted LLM decisions — same governance pipeline, no API key.

---

## Roadmap: Toward an Agentic OS

| Phase | Scope | Status |
|-------|-------|--------|
| **v0.1 — Kernel** | 3-layer enforcement, WAL ledger, encrypted vault, Python SDK, CLI | Done |
| **v0.1.1 — Hardening** | Linux-native sandbox, LLM provider governance, thinking trace audit | Done |
| **v0.1.2 — Rollback** | Merkle-verified checkpoints, auto-rollback, token savings, `@ic` decorator | Done |
| **v0.2 — Multi-Agent** | Agent identity (JWT), inter-agent governance, session isolation | Planned |
| **v0.3 — Observability** | Prometheus metrics, enforcement dashboard, cost attribution | Planned |
| **v0.4 — Multi-Framework** | TypeScript/Go SDK, LangChain/CrewAI/AutoGen adapters | Planned |
| **v1.0 — Agentic OS** | Agent scheduling, resource quotas, capability-based permissions, multi-tenant SaaS | Planned |

The goal is not to build another agent framework. The goal is to build the **operating system layer** that makes every agent framework safe to deploy in production.

> Full roadmap with implementation details: [Roadmap →](docs/13-roadmap.md)

---

## Documentation

| Part | Title |
|------|-------|
| [0](docs/00-overview.md) | Architecture Overview & Why HTTP Proxy |
| [1](docs/01-operations.md) | Operation Namespace & Registry |
| [2](docs/02-policy.md) | ABAC Policy Engine |
| [3](docs/03-srr.md) | Network SRR Engine |
| [4](docs/04-ledger.md) | WAL-First Ledger & Audit |
| [5](docs/05-vault.md) | Encrypted Vault |
| [6](docs/06-proxy.md) | Proxy Pipeline |
| [7](docs/07-sdk.md) | Python SDK |
| [8](docs/08-memory-security.md) | Memory & Runtime Security Report |
| [9](docs/09-test-report.md) | Test Coverage Report (199 tests, 0 failures) |
| [11](docs/11-competitive-analysis.md) | Competitive Analysis: GVM vs OPA+Envoy |
| [12](docs/12-security-model.md) | Security Model & Known Attack Surface |

---

## OpenShell Comparison

| Feature | NVIDIA OpenShell | Analemma-GVM |
|---------|------------------|-----------------|
| **Isolation** | Docker + K3s | Linux namespaces (no Docker required) |
| **Policy Granularity** | Allow / Deny | Allow / Delay / RequireApproval / Deny |
| **Forgery Detection** | Single layer (URL) | Cross-layer (semantic + network + capability) |
| **On Deny** | Agent waits for policy change | Auto-rollback to checkpoint (with SDK) |
| **Audit Integrity** | Audit trail | Merkle-verified hash chain |
| **Deployment** | Kubernetes | Standalone Rust proxy (no Kubernetes) |
| **Status** | Alpha | Alpha (v0.1) |

**Complementary, not competitive.** GVM can run *inside* an OpenShell sandbox for layered defense, or standalone. [Full analysis →](docs/11-competitive-analysis.md)

---

## Known Limitations

> What's implemented works. These are the edges we haven't polished yet.

| Area | Current State | Planned Fix |
|------|--------------|-------------|
| **Numeric Precision** | Policy comparisons use `f64` (boundary-case rounding risk in financial domains) | Decimal-based comparison |
| **WAL Recovery** | Loads entire WAL into memory (OOM risk on GB+ files) | Streaming `BufReader` recovery |
| **WAL Rotation** | Single file, no rotation | Size-based rotation with Merkle chain linking |
| **WAL Sequence** | Resets to 0 on restart | Initialize from last WAL event count |
| **Vault Key** | Ephemeral random key if `GVM_VAULT_KEY` not set (state lost on restart) | Require explicit key in production |

> Full security model and known attack surface: [Security Model →](docs/12-security-model.md)

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

---

*Analemma: the figure-eight path traced by the sun across a year. A pattern of constraint that enables predictability. That's what governance is — not a cage, but a shape that makes the system legible.*
