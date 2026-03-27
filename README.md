# Analemma-GVM

**See what your AI agent calls. Block what it shouldn't. Roll back when it fails.**

4MB binary. Single process. No Docker, no K8s, no GPU.

> GVM is an HTTP proxy that sits between your AI agent and the internet — it shows you every API call, enforces URL/method/payload rules, injects credentials so the agent never holds keys, and logs everything in a tamper-evident audit chain.

**Status**: v0.4 pre-release. Not externally audited. [Security Model →](docs/12-security-model.md)

---

## The Problem

You've built an agent that calls external APIs. It mostly works. But:

- The agent called a production API by mistake — **GVM denies by URL pattern**
- API costs hit 10x expected — **per-agent rate limiting + audit trail**
- The agent looped 200 requests — **anomaly detection + rate limiter**
- The agent held API keys and leaked them — **agent never has keys; GVM injects post-enforcement**
- You can't tell what happened during an incident — **Merkle-chained WAL, per-request audit**
- Prompt injection made the agent misuse a tool — **cross-layer forgery detection (intent vs actual URL)**

One architectural choice produces all of these: **govern actions at the infrastructure boundary, not inside the agent.**

---

## Quick Start

### Step 1: Observe

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release
gvm watch my_agent.py
```

Every API call displayed in real time. Session summary with host breakdown, token costs, anomaly warnings. No rules, no blocking.

### Step 2: Enforce

```bash
gvm run my_agent.py --interactive       # discover rules from live traffic
gvm run my_agent.py                     # enforce rules
gvm run --contained my_agent.py         # + Docker isolation + HTTPS MITM
gvm run --sandbox my_agent.py           # + kernel-level isolation (Linux)
```

Workflow: **observe → discover → enforce.** Policies built in development work identically in production.

> [Quick Start Guide →](docs/15-quickstart.md)

---

## Three Layers

```
Agent (any framework)     GVM Proxy (Rust)           External APIs
┌──────────────┐    ┌───────────────────────┐    ┌──────────────┐
│  @ic()       │───>│ Layer 1: Semantic     │───>│ Stripe       │
│  decorator   │    │   (ABAC Policy)       │    │ Slack        │
│              │    │ Layer 2: Network      │    │ Gmail        │
│  gvm_session │    │   (SRR URL Rules)     │    │ Database     │
│  ()          │    │ Layer 3: Credential   │    │ ...          │
└──────────────┘    │   (API Key Injection) │    └──────────────┘
                    │ WAL → Merkle Ledger   │
                    └───────────────────────┘
```

| Layer | What it checks | Requires SDK? |
|-------|---------------|---------------|
| **Semantic (ABAC)** | What the agent *declares* it's doing | Yes (`@ic()`) |
| **Network (SRR)** | What the agent *actually* requests (URL, method, path, body) | **No** |
| **Credential Isolation** | What the agent *can access* — agent never holds API keys | **No** |

Layers are independent. `max_strict()` takes the stricter decision. This catches a prompt-injected LLM misusing a legitimate tool.

**Tier 1 (proxy only)** requires zero code changes — blocks known-bad URLs, injects credentials, logs everything.
**Tier 2 (+ SDK)** adds intent-action verification, per-agent policies, checkpoint/rollback.

---

## Enforcement Decisions

| Level | Decision | Behavior |
|-------|----------|----------|
| IC-1 | Allow | Pass-through, async audit |
| IC-2 | Delay | WAL-first, configurable delay, then forward |
| IC-3 | RequireApproval | Held until human approves via `gvm approve` CLI |
| — | Deny | Unconditional block |

Unknown URLs → configurable: `delay` (dev), `require_approval` (prod), `deny` (lockdown). [Reference →](docs/16-reference.md)

---

## Isolation Modes

| Mode | Command | Enforcement | Platform |
|------|---------|-------------|----------|
| **Observe** | `gvm watch agent.py` | No blocking, visibility only | Any OS |
| **Cooperative** | `gvm run agent.py` | Agent respects HTTP_PROXY | Any OS |
| **Docker** | `gvm run --contained agent.py` | Docker isolation + HTTPS MITM | Any OS + Docker |
| **Sandbox** | `gvm run --sandbox agent.py` | Kernel (namespace + seccomp + eBPF + overlayfs + cgroup) | Linux |

`--sandbox` governs network (iptables + eBPF TC + seccomp → proxy-only), filesystem (overlayfs Trust-on-Pattern), resources (cgroup v2), and processes (seccomp ~111 syscalls). [Detailed coverage →](docs/17-governance-coverage.md)

---

## SDK (optional)

```python
from gvm import ic, gvm_session

@ic(operation="gvm.messaging.send")
def send_email(to: str, subject: str, body: str):
    session = gvm_session()
    return session.post("http://gmail.googleapis.com/...", json={...}).json()
```

Works with any framework — CrewAI, AutoGen, LangChain, plain Python. [SDK Guide →](docs/07-sdk.md)

---

## Demos

| Demo | What it shows | API key? |
|------|--------------|----------|
| `python -m gvm.mock_demo` | Full proxy enforcement, mock LLM | No |
| `python -m gvm.llm_demo` | Claude autonomous agent, live governance | Yes |
| `gvm run -- openclaw gateway` | Any agent through GVM proxy | Varies |
| [MCP integration](https://github.com/skwuwu/analemma-gvm-openclaw) | 12 preset rulesets for Claude Desktop/Cursor | No |

---

## Comparisons

GVM targets a specific niche — AI agent HTTP governance — that general-purpose tools weren't designed for. For detailed analysis:

- [OPA+Envoy vs GVM →](docs/11-competitive-analysis.md)
- [NVIDIA OpenShell vs GVM →](docs/11-competitive-analysis.md#openshell)

**Short version**: Use OPA+Envoy for service-to-service policy. Use GVM when the client is an AI agent that generates actions at runtime and may be prompt-injected.

---

## Documentation

| Doc | Title |
|-----|-------|
| [Architecture](docs/00-overview.md) | Why HTTP proxy, design rationale |
| [Quick Start](docs/15-quickstart.md) | First-time setup guide |
| [Reference](docs/16-reference.md) | CLI commands, config, API |
| [SDK](docs/07-sdk.md) | Python SDK (`@ic`, `gvm_session`, `GVMAgent`) |
| [SRR Rules](docs/03-srr.md) | URL/method/path/payload matching |
| [ABAC Policy](docs/02-policy.md) | Semantic policy engine |
| [Security Model](docs/12-security-model.md) | Threat model, known attack surface |
| [Governance Coverage](docs/17-governance-coverage.md) | Per-mode coverage (network, filesystem, process) |
| [Competitive Analysis](docs/11-competitive-analysis.md) | OPA, Envoy, OpenShell comparison |
| [Roadmap](docs/13-roadmap.md) | Current status + planned features |
| [Implementation Log](docs/14-implementation-log.md) | Change history |

---

Apache 2.0. Contributions and feedback welcome — [issues](https://github.com/skwuwu/Analemma-GVM/issues).
