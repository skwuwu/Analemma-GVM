# Analemma-GVM

**Governance Virtual Machine — A Security Kernel for AI Agent I/O**

> Smarter models do not mean safer systems.
> Safety must be structural, not behavioral.

<p align="center">
  <img src="demo.svg" alt="Analemma-GVM Unified Finance Agent Demo" width="860">
</p>

---

## The Problem

AI agents are getting better at doing things. That is exactly the problem.

A model that can compose emails, query databases, and call payment APIs is one prompt injection away from doing all three without authorization. Today's safety strategy — instruction tuning, guardrails in the prompt, RLHF alignment — operates at the **behavioral** level. It asks the model to be good. But a sufficiently capable model, a jailbreak, or a simple bug can bypass behavioral constraints entirely.

**Model sophistication is not control.** GPT-5 will be smarter than GPT-4. It will not be more *governed*. The gap between what an agent *can* do and what it *should* do is an infrastructure problem, not a model problem.

The industry needs action-level enforcement at the runtime layer — something that sits between the agent and the world, something the agent cannot reason its way around.

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

## Why This Architecture

### Why a Proxy, Not a Library

Libraries run inside the agent's process. The agent can patch them, skip them, or ignore them. A proxy is an external enforcement point — the agent's traffic physically passes through it. There is no code path that bypasses the proxy.

### Why 3 Layers, Not 1

A single policy engine can be fooled. If the agent declares `storage.read` but sends a wire transfer, a semantic-only policy would allow it. The 3-layer model eliminates this:

| Layer | What It Checks | Why It Exists |
|-------|---------------|---------------|
| **Layer 1: Semantic (ABAC)** | Operation name, resource, context | Handles the happy path — SDK-declared operations |
| **Layer 2: Network (SRR)** | Actual URL, method, payload | Catches lies — inspects what the agent *does*, not what it *says* |
| **Layer 3: Capability Token** | API key injection | Removes the means — agent never holds credentials |

The final decision is `max_strict(Layer1, Layer2)` — the stricter ruling always wins.

### Why WAL-First, Not Fire-and-Forget

For irreversible operations (payments, deletions, external messages), the audit record must exist *before* the action executes. If the proxy crashes mid-request, the WAL contains a `Pending` entry that is explicitly marked `Expired` on recovery — "this action may or may not have executed." No phantom records, no silent failures.

### Why AES-256-GCM with Zeroize

Agent state contains sensitive data (balances, PII, credentials). The Vault encrypts everything at rest with AES-256-GCM. But encryption alone isn't enough — if the key persists in freed memory, a core dump or memory forensic tool can recover it. The `zeroize` crate guarantees key material is wiped on drop, using compiler barriers that prevent dead-store elimination. This is the same discipline applied in OpenSSL (`OPENSSL_cleanse`) and the Linux kernel (`memzero_explicit`). See the full [Memory & Runtime Security Report](docs/08-memory-security.md) for the 10-item security checklist covering nonce reuse, side-channel timing, OOM resistance, and more.

### Why Default-to-Caution

Any request that doesn't match a known rule gets a 300ms delay (not Allow, not Deny). This is the conservative middle ground: it doesn't break unknown legitimate operations, but it creates a review window and an audit trail. When in doubt, slow down.

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

### IC Classification (Enforcement Decisions)

| Level | Decision | Behavior |
|-------|----------|----------|
| IC-1 | Allow | Immediate pass-through, async audit |
| IC-2 | Delay | WAL-first write, configurable delay, then forward |
| IC-3 | RequireApproval | Blocked until human approves |
| — | Deny | Unconditional block |

---

## Components

| Component | Role | Design Choice |
|-----------|------|---------------|
| **Operation Registry** | Defines the vocabulary of agent actions | Schema-validated TOML; anti-downgrade protection on `maps_to` |
| **ABAC Policy Engine** | Evaluates operation metadata against hierarchical rules | Global > Tenant > Agent layers; lower layers can only be stricter |
| **Network SRR** | URL-based rule matching independent of SDK headers | First-match-wins; payload inspection for GraphQL/gRPC defense |
| **WAL-First Ledger** | Crash-safe audit log with NATS distribution | fsync before action; AtomicU64 sequence for NATS ordering |
| **Encrypted Vault** | AES-256-GCM key-value store for agent state | `zeroize` on drop; sanitized error messages; WAL-integrated writes |
| **Proxy Pipeline** | Central enforcement point with backpressure | CatchPanicLayer + 1MB body limit + 1024 connection limit |
| **Python SDK** | Zero-friction agent interface | `@ic()` decorator; transparent header injection; causal tracing |

---

## Quick Start (5 minutes)

### Prerequisites

- Rust 1.75+
- Python 3.9+ (only if using the Python SDK or running demos)

### 1. Build and start the proxy

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git
cd Analemma-GVM
cargo run
```

The proxy starts on `0.0.0.0:8080`. That's it — governance is now active.

### 2. Route any agent through the proxy

GVM is a **transparent HTTP proxy**. It works with any language, any framework, any agent — no SDK required. Just point your agent's HTTP traffic at the proxy:

```bash
# Any language, any framework — set the proxy and go
HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 python my_agent.py
HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 node my_agent.js
HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 ./my_agent
```

Every outbound HTTP request your agent makes now passes through the GVM proxy. The proxy inspects the **actual URL, method, and payload** (Layer 2: Network SRR) and enforces rules — regardless of what framework the agent uses.

```
 Your agent                GVM Proxy (localhost:8080)           External API
 ┌──────────┐    HTTP      ┌──────────────────────┐    HTTPS  ┌──────────┐
 │ Any code │────PROXY────>│ Layer 2: URL check   │──────────>│ Stripe   │
 │ Any lang │              │ Layer 3: Key inject  │           │ Slack    │
 │ Any fw   │              │ WAL audit log        │           │ Gmail    │
 └──────────┘              └──────────────────────┘           └──────────┘
```

**What the proxy does without the SDK:**

| Layer | What it does | SDK needed? |
|-------|-------------|-------------|
| **Layer 2: Network SRR** | Inspects actual URL/method/payload. Blocks `POST api.bank.com/transfer`, delays unknown endpoints 300ms. | No |
| **Layer 3: Capability Token** | Injects API keys by hostname. Agent never holds credentials. | No |
| **WAL Audit** | Records every request with tamper-proof Merkle hash chain. | No |
| **Rate Limiting** | Token-bucket rate limit per agent. | No |
| **Layer 1: Semantic ABAC** | Evaluates operation name, resource type, agent role against hierarchical policies. | **Yes** (needs `X-GVM-*` headers) |

Without the SDK, Layer 1 (ABAC) has no operation metadata to evaluate, so it defaults to **Default-to-Caution** (300ms delay). Layer 2 and Layer 3 work at full strength because they inspect the actual HTTP request, not agent-declared headers.

### 3. (Optional) Use the Python SDK for richer governance

The SDK is **not required** for enforcement — it's an enhancement. It adds Layer 1 (semantic ABAC policy) by injecting `X-GVM-*` headers that tell the proxy *what the agent thinks it's doing*. The proxy then cross-checks this against *what the agent is actually doing* (Layer 2).

```bash
pip install -e sdk/python
```

**What the SDK adds:**

| Feature | Without SDK | With SDK |
|---------|------------|----------|
| URL-based blocking (SRR) | Full | Full |
| API key injection (Layer 3) | Full | Full |
| Audit trail | URL/method only | Operation name, agent ID, trace chain |
| ABAC policy evaluation | Skipped (Default-to-Caution) | Full (per-agent, per-tenant, per-operation) |
| Causal tracing | No parent-child linking | Automatic trace_id + parent_event_id |
| Rate limiting | By source IP | By agent_id |
| Operation classification | `"unknown"` | `"gvm.messaging.send"` etc. |
| State checkpoint/rollback | None (full restart on deny) | Auto-checkpoint + Merkle-verified rollback |
| Token savings on deny | 0% | ~42% per blocked action |

**SDK agent example (10 lines):**

```python
from gvm import GVMAgent, ic, Resource

class MyAgent(GVMAgent):
    @ic(operation="gvm.messaging.send",
        resource=Resource(service="slack", tier="customer-facing"))
    def notify(self, channel: str, msg: str):
        session = self.create_session()
        return session.post(f"http://api.slack.com/post/{channel}",
                           json={"text": msg}).json()

agent = MyAgent(agent_id="my-agent", tenant_id="my-org")
agent.notify("#alerts", "Deploy complete")
# → Delayed 300ms by proxy, then forwarded. Audit trail recorded.
```

The `@ic()` decorator injects `X-GVM-Operation`, `X-GVM-Agent-Id`, and other headers. `GVMAgent.create_session()` returns a `requests.Session` pre-configured to route through the proxy. The proxy sees both the semantic header *and* the actual URL, and takes the stricter decision.

**Without SDK — same protection, less metadata:**

```python
import requests

# Just set the proxy — any HTTP library works
session = requests.Session()
session.proxies = {"http": "http://localhost:8080", "https": "http://localhost:8080"}

# This request goes through the proxy. Layer 2 (SRR) inspects the URL.
# If api.bank.com/transfer is in the deny list, it's blocked.
session.post("http://api.bank.com/transfer/123", json={"amount": 50000})
# → Denied by SRR. Agent never needed the SDK for this to work.
```

### 4. Run the demo

```bash
pip install -e sdk/python
python -m gvm.unified_demo
```

One scenario demonstrates every core feature — IC classification, SRR network defense, semantic forgery detection, checkpoint/rollback, token savings, and WAL-first audit:

```
[Step 1] read_inbox()        → ✓ Allow     (IC-1, no checkpoint)
[Step 2] send_summary()      → ⏱ Delay     (IC-2, checkpoint #0 saved)
[Step 3] wire_transfer()     → ✗ BLOCKED   (Deny, SRR catches URL)
         ↺ Rollback to checkpoint #0
         Agent continues from safe state
[Step 4] summarize_results() → ✓ Allow     (IC-1, agent resumes)

Token savings: 670 tokens saved per blocked action (42% reduction)
```

Additional demos for specific scenarios:

```bash
python -m gvm.langchain_demo    # LangChain + Gmail (4-step enforcement)
python -m gvm.hostile_demo      # Adversarial security tests
python -m gvm.rollback_demo     # Checkpoint/rollback token analysis
```

### Industry templates

```bash
# Finance (strict: payments IC-3, transfers denied)
GVM_CONFIG=config/templates/finance/proxy.toml cargo run

# SaaS (balanced: reads IC-1, sends IC-2, exports IC-3)
GVM_CONFIG=config/templates/saas/proxy.toml cargo run
```

### Dry-run policy check (no forwarding)

```bash
curl -X POST http://localhost:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"operation": "gvm.payment.transfer", "target_host": "api.bank.com", "target_path": "/transfer/123"}'
# → {"decision": "Deny", "engine_ms": 0.1, "dry_run": true, ...}
```

### Agent isolation (Layer 3: OS Containment)

GVM provides two OS-level isolation modes that restrict agents to communicate only through the proxy:

```bash
# Linux-native sandbox (recommended for production)
# Uses namespaces (user, PID, mount, network), seccomp-BPF, and veth pair.
# No Docker required. Analogous to Firecracker's MicroVM approach.
gvm run --sandbox agent.py

# Docker containment (dev/CI or non-Linux platforms)
# Uses Docker network isolation, read-only filesystem, resource limits.
gvm run --contained agent.py --image python:3.12-slim --memory 512m --cpus 1.0

# Local mode (Layer 2 only — no OS isolation)
gvm run agent.py
```

**Linux-native sandbox** is the primary deployment target:

| Feature | `--sandbox` (Linux-native) | `--contained` (Docker) |
|---------|---------------------------|----------------------|
| Isolation | User/PID/mount/network namespaces | Docker container |
| Syscall filter | seccomp-BPF (~45 allowed) | Docker default seccomp |
| Network | veth pair, proxy-only routing | `gvm-internal` network |
| Filesystem | pivot_root, read-only workspace | `--read-only` mount |
| Overhead | ~2ms setup, no daemon | Docker daemon required |
| Platform | Linux only | Any Docker-supported OS |

**Why not MicroVM?** The architecture is designed to be extensible to Firecracker-class MicroVM isolation (`--microvm` mode) for multi-tenant SaaS deployments where untrusted user code requires hardware-level (KVM) isolation. However, the current namespace+seccomp approach is sufficient for AI agent governance: agents are non-privileged interpreted processes (Python/Node), not arbitrary binaries capable of kernel exploits. MicroVM would add 50x setup latency (2ms → 100ms+) and 25x memory overhead (5MB → 128MB+) with no practical security gain for this threat model. See [Part 8: Memory & Runtime Security](docs/08-memory-security.md) for the full analysis.

### LLM provider governance

GVM inspects LLM API calls at the proxy level — no SDK changes needed:

- **Model pinning**: Only approved models allowed (e.g., `gpt-4o`, `claude-sonnet-4-20250514`)
- **Endpoint restriction**: Only authorized API paths (e.g., `chat/completions` only, not `fine-tuning`)
- **Provider allowlist**: Unauthorized providers (Together AI, Groq, Mistral, etc.) blocked
- **Thinking trace audit**: IC-2/IC-3 paths extract reasoning content from LLM responses into the WAL

See [`config/srr_network.toml`](config/srr_network.toml) for the full rule set.

### Checkpoint/Rollback (SDK Level 2)

When using the SDK, agents get **automatic state checkpointing and rollback** on denied operations — the key value-add over proxy-only (Level 0) enforcement.

**How it works:**

1. `@ic` decorator infers IC level from operation name
2. Before IC-2+ operations, agent state is checkpointed to Vault (AES-256-GCM encrypted, Merkle-verified)
3. If the operation is denied, state is rolled back to the last approved checkpoint
4. `GVMRollbackError` provides structured context for LLM agents to choose an alternative path

```python
from gvm import GVMAgent, ic, Resource

class MyAgent(GVMAgent):
    auto_checkpoint = "ic2+"  # Checkpoint before IC-2 and IC-3 operations

    @ic(operation="gvm.payment.charge",
        resource=Resource(service="bank", tier="external", sensitivity="critical"))
    def wire_transfer(self, to: str, amount: float):
        session = self.create_session()
        return session.post("http://api.bank.com/transfer/123",
                           json={"to": to, "amount": amount}).json()

agent = MyAgent(agent_id="finance-001")
try:
    agent.wire_transfer("account-123", 50000.00)
except GVMRollbackError as e:
    print(f"Blocked: {e.operation}, rolled back to checkpoint #{e.rolled_back_to}")
    # LLM agent receives structured error and chooses alternative action
```

**SDK vs No-SDK: Rollback behavior**

| Scenario | Level 0 (No SDK) | Level 2 (SDK) |
|----------|-----------------|---------------|
| Operation denied | Error returned, no state recovery | State rolled back to last checkpoint |
| LLM agent recovery | Must restart entire workflow from scratch | Resumes from checkpoint with full context |
| Token cost on deny | Re-run all prior steps (~670 tokens) | Resume cost only (~60 tokens) |
| State integrity | Manual reconstruction | Merkle-verified restoration |
| Developer effort | None (proxy-only) | One decorator per method (`@ic`) |

**Token savings demo:**

```bash
python -m gvm.unified_demo
```

Output:
```
Level 0 (no SDK):   1,580 tokens (run all steps + restart from scratch on deny)
Level 2 (SDK):        910 tokens (run all steps + resume from checkpoint on deny)
Saved: 670 tokens (42.4% reduction)
```

Savings are not a fixed percentage — they depend on where in the workflow the deny occurs. The later the deny, the more prior steps are skipped by resuming from a checkpoint instead of restarting. In this 4-step workflow with a deny at step 3, the saving is ~42%. A longer workflow with a later deny would save proportionally more.

### Run tests

```bash
cargo test   # 141 tests
```

---

## Documentation

The full technical whitepaper is in [`docs/`](docs/):

| Part | Title |
|------|-------|
| [0](docs/00-overview.md) | Architecture Overview |
| [1](docs/01-operations.md) | Operation Namespace & Registry |
| [2](docs/02-policy.md) | ABAC Policy Engine |
| [3](docs/03-srr.md) | Network SRR Engine |
| [4](docs/04-ledger.md) | WAL-First Ledger & Audit |
| [5](docs/05-vault.md) | Encrypted Vault |
| [6](docs/06-proxy.md) | Proxy Pipeline |
| [7](docs/07-sdk.md) | Python SDK |
| [8](docs/08-memory-security.md) | Memory & Runtime Security Report |
| [9](docs/09-test-report.md) | Test Coverage Report |
| [11](docs/11-competitive-analysis.md) | Competitive Analysis: GVM vs OPA+Envoy |

---

## Test Coverage

141 tests across unit, integration, boundary, edge-case, hostile, stress, and Merkle suites. Zero failures.

| Category | Count |
|----------|-------|
| Unit (SRR, Policy, Vault, Registry, Merkle, Wasm, LLM Trace) | 49 |
| Integration (E2E) | 5 |
| Boundary | 30 |
| Edge Cases | 17 |
| Hostile Environment | 11 |
| Stress | 12 |
| Merkle Tree | 12 |
| Engine (gvm-engine) | 5 |
| **Total** | **141** |

---

## Roadmap: Toward an Agentic OS

Analemma-GVM is the kernel. The vision is an **Agentic Operating System** — a complete runtime layer for governed AI agents.

| Phase | Scope | Status |
|-------|-------|--------|
| **v0.1 — Kernel** | 3-layer enforcement, WAL ledger, encrypted vault, Python SDK, LangChain demo, CLI | Done |
| **v0.1.1 — Hardening** | Linux-native sandbox (namespace + seccomp), LLM provider governance, thinking trace audit, model pinning | Done |
| **v0.1.2 — Rollback** | Merkle-verified state checkpoints, auto-rollback on deny, token savings quantification, `@ic` decorator SDK | Done |
| **v0.2 — Multi-Agent** | Agent identity management, inter-agent communication governance, session isolation | Planned |
| **v0.3 — Approval Workflows** | Human-in-the-loop approval UI, escalation chains, SLA-based auto-expiry | Planned |
| **v0.4 — Observability** | Real-time enforcement dashboard, anomaly detection, cost attribution per agent | Planned |
| **v0.5 — Multi-Framework** | LangChain / CrewAI / AutoGen adapters, language-agnostic SDK (gRPC) | Planned |
| **v1.0 — Agentic OS** | Agent scheduling, resource quotas, capability-based permissions, multi-tenant SaaS | Planned |

The goal is not to build another agent framework. The goal is to build the **operating system layer** that makes every agent framework safe to deploy in production.

An OS doesn't tell applications what to do. It controls what they *can* do. It doesn't inspect the source code of every program — it enforces permissions at the syscall boundary. An application can *try* to delete `/etc/passwd`; the kernel says no.

Analemma-GVM does the same for AI agents. The agent can *try* to wire-transfer $50,000; the kernel says no.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, modify, and distribute this software under the terms of the Apache 2.0 license. See the [LICENSE](LICENSE) file for the full text.

---

*Analemma: the figure-eight path traced by the sun across a year. A pattern of constraint that enables predictability. That's what governance is — not a cage, but a shape that makes the system legible.*
