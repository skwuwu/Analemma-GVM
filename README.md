# Analemma-GVM

**Governance Virtual Machine — A Security Proxy for AI Agent I/O**

**Status: v0.2 (pre-release software). Primary platform: Linux.**

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

> *The recording above is a live demo using my personal Claude API key. To try GVM without an API key or personal AI Agent, run `python -m gvm.mock_demo` — same proxy enforcement, pre-scripted LLM mocked decisions.*

---

## Why GVM?

| Approach | What it does | What it misses |
|----------|-------------|----------------|
| Prompt guardrails | Asks the model to behave | Bypassed by jailbreak or bugs |
| Sandbox (Docker/K8s) | Constrains the environment | Binary allow/deny only |
| Policy engines (OPA) | Evaluates metadata | Trusts what the agent declares |
| **GVM** | **Governs actual HTTP actions** | **Alpha — not hardened yet** |

Only GVM: graduated enforcement, semantic forgery detection, checkpoint rollback, Merkle-chained audit for write operations (IC-2+).

---

### What is the problem? and why it's different?

Most AI security approaches rely on model-level inference control, prompt guardrails, and reinforcement learning. While these are certainly necessary measures, attempting to control intelligence solely through them is fundamentally impossible. Numerous leading tech companies and engineers, such as Google, Antropics, and OpenAI, have adopted this approach; although it is an excellent method, hallucinations and malfunctions have not been eradicated. Therefore, as the range of external actions an agent can perform increases, their behavior requires deterministic control.

**We don't correct what agents *say*. We control what agents *do*.**

This is the same insight that separates infrastructure-level enforcement from application-level checks. Anti-virus scans files; the firewall blocks packets. GVM is the firewall for agent actions — an HTTP governance proxy that enforces rules on actual network requests, not on agent self-reports.

---

## The Thesis

Analemma-GVM is built on a single thesis:

**Security must be enforced at the infrastructure level, not the application level.**

We chose deterministic infrastructure control over ML-based classification. That single decision produces five consequences simultaneously:

| What | How | Why it follows |
|------|-----|----------------|
| **Lightweight** | Single Rust binary, no GPU, sub-μs policy eval | No ML model to load or run |
| **Zero dependencies** | No K8s, no Docker, no sidecar | HTTP proxy is the only moving part |
| **Structurally unbypassable** | Agent has no keys, no direct network path | Enforcement is architectural, not cooperative |
| **Tamper-proof audit** | Merkle hash chain with domain separation (`gvm-event-v1:` prefix, length-prefixed fields) for IC-2+ events, async NATS for IC-1 (Allow) | IC-2+ events are WAL-first + Merkle chained; IC-1 events are fire-and-forget (loss tolerated < 0.1%) |
| **Clean rollback** | Checkpoint = Merkle leaf, state restore is cryptographically verified | Deterministic state transitions are reversible |

These are not five separate features. They are five consequences of one architectural choice: **govern actions at the infrastructure boundary, not at the language boundary.**

GVM works in two tiers. **Tier 1 requires zero code changes** — set `HTTP_PROXY` and every outbound HTTP request passes through the governance proxy. **Tier 2 adds the SDK** for deeper control:

| | Tier 1: Proxy only | Tier 2: + SDK (`@ic()` decorator) |
|---|---|---|
| **Code changes** | None | Add `@ic()` decorator to functions |
| **SRR: host / method / path rules** | ✓ | ✓ |
| **SRR: payload field inspection** | — (body not buffered)¹ | — (body not buffered)¹ |
| **API key injection** | ✓ (HTTP only)³ | ✓ (HTTP only)³ |
| **Merkle audit (IC-2+)** | ✓ (agent="unknown") | ✓ (per-agent, per-operation) |
| **Default-to-Caution** | ✓ (Delay 300ms on unknown URLs) | ✓ |
| **Semantic policy (ABAC)** | — | ✓ |
| **Cross-layer forgery detection** | — | ✓ (`max_strict(Layer1, Layer2)`) |
| **Per-agent rate limiting** | — (all unauthenticated traffic shares one bucket) | ✓ |
| **OS isolation (syscall + network)** | `--sandbox` flag² | `--sandbox` flag² |
| **Checkpoint/rollback** | — | ✓ |

> ¹ SRR payload inspection rules (`payload_field` / `payload_match`) are parsed and loaded but currently inactive — the proxy passes `body = None` to SRR in both tiers. Host/method/path rules work fully. Payload inspection is planned for a future release.
>
> ² OS isolation is independent of SDK usage. `--sandbox` (Linux only) applies to the **agent process**: user/PID/mount/net namespace isolation, seccomp-BPF syscall whitelist (~111 allowed, `ptrace`/`bpf`/`mount` killed), and TC ingress filter on the host veth (kernel-level, unbypassable even with CAP_NET_ADMIN inside the namespace). The proxy process itself is not sandboxed. Without `--sandbox`, the agent could bypass governance by making direct HTTPS connections.
>
> ³ API key injection currently works on **HTTP requests only**. HTTPS traffic uses CONNECT blind relay (domain-level), so the proxy cannot modify headers or inject credentials. Full HTTPS API key injection requires transparent MITM, planned for v0.3. See [HTTP vs HTTPS capability table](#http-vs-https-capabilities) below.

**Tier 1 alone** blocks known-bad URLs by host/method/path, injects credentials on HTTP (HTTPS injection requires v0.3 MITM), and logs everything with WAL — that's already more than most agent deployments have. **Tier 2** adds the cross-layer forgery detection that catches a lying agent. Start with the proxy, add the SDK when you need deeper control.

The agent cannot bypass this. Not because it's told not to, but because the architecture makes bypass structurally impossible:

- The agent has no API keys (Layer 3 injects them post-enforcement)
- In Tier 2: the agent's declared operation is cross-checked against the actual URL (Layer 2 catches lies)
- If the proxy is down, the agent has no network path to external APIs (Fail-Close)

```
Typical agent governance stack:              GVM:

  LLM WAF      (GPU, per-request cost)       ┌──────────────────┐
  + OPA         (separate server)             │  cargo run       │
  + Envoy       (sidecar proxy)               │                  │
  + Kubernetes  (orchestration)               │  One binary.     │
  + Infra team  (to operate all of above)     │  That's it.      │
                                              └──────────────────┘
```

> **Trade-off**: GVM is lightweight *because* it uses deterministic pattern matching instead of ML-based semantic analysis. It catches URL/method/payload mismatches and policy violations — not prompt injection or toxic content. If you need semantic payload analysis, run an LLM WAF upstream. GVM and LLM WAFs are complementary: one governs what agents *do*, the other analyzes what agents *say*. [Details →](#trade-offs)


---

## How It Works — Two Levels of Defense

### Tier 1: Proxy blocks known-bad URLs (no SDK needed)

```bash
# Agent sends a wire transfer through the proxy — no SDK, no @ic() decorator
HTTP_PROXY=http://localhost:8080 python -c "
import requests
requests.post('https://api.bank.com/transfer/123', json={'amount': 50000})
"
```

```
 What happens                                    Result
 ───────────────────────────────────────────────────────────

 POST api.bank.com/transfer                       DENY
       │
       ▼
 ┌──────────────┐
 │   Layer 2    │         SRR rule matches "api.bank.com/transfer"
 │   (SRR)      │         → Deny "Wire transfer blocked"
 │              │
 │  DENY        │         No SDK needed. URL pattern matching only.
 └──────────────┘
```

**Layer 2 (SRR) works alone.** It inspects the actual HTTP target regardless of what the agent claims. The wire transfer is blocked by URL pattern, API key is never injected, the attempt is logged.

### Tier 2: SDK catches forgery across layers (requires `@ic()`)

```python
# Agent lies about what it's doing — SDK enables cross-layer detection
@ic(operation="gvm.storage.read")       # "I'm just reading data"
def steal_money():
    session = gvm_session()
    session.post("https://api.bank.com/transfer/123",
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

**With SDK, the lie is caught AND recorded as forgery.** `max_strict(Allow, Deny)` = **Deny**. The WAL event records both what the agent *claimed* (`gvm.storage.read`) and what it *attempted* (`POST api.bank.com/transfer`) — creating a forensic trail of the forgery attempt.

**Without SDK, the URL is still blocked** (Tier 1), but Layer 1 is not invoked, so the semantic mismatch is not detected or logged as forgery.

---

## Quick Start

```bash
# Option 1: Pre-built binary (recommended — no build time)
cargo binstall gvm-proxy gvm-cli    # Requires: cargo install cargo-binstall
gvm-proxy                           # First run: interactive setup wizard

# Option 2: From source
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo run                           # First build: 2-5 min (one-time). Subsequent: ~1s.

# Then run your agent
gvm run my_agent.py                 # Auto-starts proxy, sets HTTP_PROXY, shows audit trail
```

On first run, if no config exists, GVM detects this and offers an interactive setup:

```
⚡ First Run Detected
  Choose an industry template:
    1  finance  — Wire transfers blocked, payments need IC-3 approval
    2  saas     — Default-to-Caution, balanced security for SaaS agents
  Select [1/2/3]: 2
  ✓ proxy.toml  ✓ srr_network.toml  ✓ operation_registry.toml
  saas template applied (5 files)
  Starting proxy with saas configuration...
```

The proxy then starts immediately — no restart needed.

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

### When to Use Each Mode

| Mode | Security boundary | Best for | Requires |
|------|-------------------|----------|----------|
| `gvm run` | HTTP proxy only (cooperative) | Development, testing, any OS | Nothing extra |
| `gvm run` + Shadow Mode | Proxy + MCP intent verification | MCP agents (OpenClaw, Claude Desktop) | `[shadow] mode = "strict"` in proxy.toml |
| `--sandbox` | Proxy + Linux namespaces + seccomp-BPF + TC veth filter (structural) | **Production on Linux** | `kernel.unprivileged_userns_clone=1`, kernel ≥ 4.15 |
| `--sandbox` + Shadow Mode | **Full dual-lock** — kernel isolation + intent verification | **Maximum security** | Linux + Shadow config |
| `--contained` | Proxy + Docker (structural) | Production on macOS/Windows | Docker daemon |

**Shadow Mode** (`[shadow]` in proxy.toml or `GVM_SHADOW_MODE=strict` env var): the proxy rejects any HTTP request that lacks a prior MCP intent declaration. This makes governance mandatory for MCP agents without requiring OS-level isolation. Works on any OS.

**`--sandbox`**: the agent process runs in isolated Linux namespaces (user/PID/mount/net). Its only network path is through the proxy veth pair. A TC ingress filter on the host-side veth runs in the kernel and cannot be removed even if the agent gains apparent `CAP_NET_ADMIN` inside the user namespace. Seccomp-BPF (dual-layer: log + kill) blocks dangerous syscalls (`ptrace`, `bpf`, `mount`, `unshare`, namespace escape vectors) — violations terminate the process immediately. `/workspace/output` is mounted writable inside the sandbox (persists to host), and CWD is set to `/workspace/output` so agent file output survives container teardown.

**Shadow + `--sandbox`** (recommended for production): two independent enforcement layers. Shadow Mode ensures every request has declared intent (proxy-level). `--sandbox` ensures the agent cannot bypass the proxy (kernel-level). Even if one layer fails, the other catches it.

### Policy Discovery (`--interactive`)

You don't need to write all rules upfront. Run your agent with `--interactive` and GVM learns which URLs your agent calls, then asks whether each should be allowed, delayed, or blocked:

```bash
gvm run my_agent.py --interactive
```

After the agent finishes, GVM shows every URL that hit Default-to-Caution (no explicit rule) and prompts:

```
SRR Rule Suggestions (Default-to-Caution detected)

⚠ POST api.example.com/v1/users (3 hits)
  [a] Allow   [d] Delay   [n] Deny   [s] Skip
  Choice: d
    ✓ Rule added to config/srr_network.toml

✓ 2 rule(s) added. Rules take effect on next proxy restart.
```

This is the recommended workflow for new deployments: **start with a template → run your agent in interactive mode → let GVM discover and propose rules → review and approve.** You build production-grade policies organically instead of guessing upfront.

> Platform support, isolation modes, LLM provider governance, checkpoint/rollback — see [Quick Start Guide →](docs/14-quickstart.md)

---

## SDK Integration

GVM SDK requires **no inheritance and no class changes**. Add `@ic` to functions that need governance, use `gvm_session()` for HTTP requests:

```python
from gvm import ic, gvm_session, configure, Resource

configure(agent_id="my-agent")  # or set GVM_AGENT_ID env var

@ic(operation="gvm.messaging.send",
    resource=Resource(service="gmail", tier="customer-facing"))
def send_email(to: str, subject: str, body: str):
    session = gvm_session()
    return session.post("http://gmail.googleapis.com/...", json={...}).json()

# Works with any framework — CrewAI, AutoGen, LangChain, plain Python
send_email("user@example.com", "Hello", "World")
```

### LangChain — stack `@tool` and `@ic`

```python
from langchain_core.tools import tool
from gvm import ic, gvm_session

@tool
@ic(operation="gvm.messaging.send")
def send_email(to: str, subject: str, body: str):
    """Send an email via Gmail."""
    session = gvm_session()
    return session.post("http://gmail.googleapis.com/...", json={...}).json()

tools = [send_email]  # standard LangChain tool list, no wrapper needed
```

### When to use `GVMAgent`

`GVMAgent` is optional — use it when you need auto-checkpoint, encrypted state, or rollback:

```python
from gvm import GVMAgent, AgentState, VaultField, ic

class FinanceAgent(GVMAgent):
    auto_checkpoint = "ic2+"
    state = AgentState(balance=VaultField(default=0, sensitivity="critical"))

    @ic(operation="gvm.payment.refund")
    def process_refund(self, customer_id, amount):
        session = self.create_session()  # same as gvm_session()
        ...
```

| Feature | Standalone (`@ic` + `gvm_session`) | `GVMAgent` subclass |
|---------|-----------------------------------|---------------------|
| Policy enforcement (Allow/Delay/Deny) | Yes | Yes |
| Audit trail + trace | Yes | Yes |
| Works with any class/framework | Yes | Requires inheritance |
| Auto-checkpoint before risky ops | — | Yes |
| Encrypted state (VaultField) | — | Yes |
| Auto-rollback on Deny | — | Yes |

---

## Architecture

```
 Agent (any framework)     GVM Proxy (Rust)           External APIs
 ┌──────────────┐    ┌───────────────────────┐    ┌──────────────┐
 │  @ic()       │───>│ Shadow: Intent Store  │───>│ Stripe       │
 │  decorator   │    │ Layer 1: Semantic     │    │ Slack        │
 │              │    │   ABAC Policy Engine  │    │ Gmail        │
 │  gvm_session │    │ Layer 2: Network SRR  │    │ Database     │
 │  ()          │    │ Layer 3: Capability   │    │ ...          │
 └──────────────┘    │   Token (API Key)     │    └──────────────┘
                     │ WAL → NATS Ledger     │
                     │ AES-256-GCM Vault     │
                     └───────────────────────┘
```

### Why 3 Layers, Not 1

A single policy engine can be fooled. If the agent declares `storage.read` but sends a wire transfer, a semantic-only policy would allow it. The 3-layer model eliminates this:

| Layer | What It Checks | Why It Exists | Requires SDK? |
|-------|---------------|---------------|---------------|
| **Layer 1: Semantic (ABAC)** | Operation name, resource, context | Catches semantic policy violations | Yes (`@ic()`) |
| **Layer 2: Network (SRR)** | Actual URL, method, path (host/method/path rules active; payload inspection not yet active¹) | Catches lies — inspects what the agent *does* | **No** |
| **Layer 3: Capability Token** | API key injection | Removes the means — agent never holds credentials | **No** |

**Without SDK**: Layer 2 + Layer 3 provide URL-based enforcement and credential isolation.
**With SDK**: Layer 1 adds semantic policies; `max_strict(Layer1, Layer2)` enables cross-layer forgery detection.

### Governance (Enforcement Decisions)

| Level | Decision | Behavior |
|-------|----------|----------|
| IC-1 | Allow | Immediate pass-through, async audit |
| IC-2 | Delay | WAL-first write, configurable delay, then forward |
| IC-3 | RequireApproval | Blocked (403). Webhook callback planned for v1.1 |
| — | Deny | Unconditional block |

> **IC-3 gap (known)**: Currently IC-3 returns 403 and records the event, but has no built-in approval workflow. A webhook/approval queue mechanism is planned for v1.1. Until then, IC-3 is functionally equivalent to Deny — use it when you want to distinguish "needs human review" from "unconditionally blocked" in audit logs.

### Efficiency (Checkpoint/Rollback) — SDK only

Governance tells you *what was blocked*. Checkpoint/rollback answers *what happens next*.

| Feature | What it does |
|---------|-------------|
| **Auto-checkpoint** | Saves agent state before IC-2+ operations |
| **Merkle-verified rollback** | Restores state with cryptographic proof — the checkpoint is a leaf in the same Merkle tree as audit events |
| **Token savings** | Denied at step 3 of 4? Resume from checkpoint instead of re-running the entire workflow |

The Merkle integration means rollback targets are tamper-evident: GVM can prove that the state you're restoring to hasn't been modified since it was recorded.

```python
# Option A: Standalone (for simple checkpoint needs)
@ic(operation="gvm.payment.charge", checkpoint=True)
def charge_card(amount):
    session = gvm_session()
    return session.post(...).json()

# Option B: GVMAgent (for auto-checkpoint + state management)
class MyAgent(GVMAgent):
    auto_checkpoint = "ic2+"  # Checkpoint before IC-2+ operations
    # On deny → auto-rollback + GVMRollbackError for LLM recovery
```

### Components

| Component | Moat | Details |
|-----------|------|---------|
| **Shadow Mode (Intent Store)** | 2-phase intent lifecycle (claim → WAL write → confirm/release), agent_id cross-check, TTL expiry, TOCTOU-safe consumption. `POST /gvm/intent` + `POST /gvm/reload` | [Details →](docs/06-proxy.md) |
| **ABAC Policy Engine** | Hierarchical rules (Global > Tenant > Agent), lower layers can only be stricter | [Details →](docs/02-policy.md) |
| **Network SRR** | URL inspection independent of SDK headers, regex path matching, payload inspection, hot-reload via `POST /gvm/reload` | [Details →](docs/03-srr.md) |
| **WAL-First Ledger** | Crash-safe audit: fsync before action for IC-2+ events, global Merkle chain (cross-agent ordering + collusion detection), async NATS for IC-1 | [Details →](docs/04-ledger.md) |
| **Encrypted Vault** | AES-256-GCM + `zeroize` on drop, no key material in freed memory | [Details →](docs/05-vault.md) |
| **Proxy Pipeline** | CatchPanicLayer + backpressure + 1024 connection limit, sub-μs policy eval | [Details →](docs/06-proxy.md) |
| **Python SDK** | `@ic()` + `gvm_session()` (no inheritance needed), optional `GVMAgent` for checkpoint/rollback, LangChain `@tool` stackable | [Details →](docs/07-sdk.md) |
| **OS Isolation** | Linux namespace + seccomp-BPF (`--sandbox`), Docker fallback (`--contained`) | [Details →](docs/08-memory-security.md) |

> Full technical whitepaper: [Architecture Overview →](docs/00-overview.md)

---

## Demos

| Demo | What it shows | API key? |
|------|--------------|----------|
| `python -m gvm.mock_demo` | **Start here.** Full proxy enforcement, mock LLM | No |
| `python -m gvm.llm_demo` | Claude autonomous agent, live governance | Yes |
| `gvm run -- openclaw gateway` | Any agent through GVM proxy | Varies |
| [MCP integration](https://github.com/skwuwu/analemma-gvm-openclaw) | 12 preset rulesets, MCP server for Claude Desktop/Cursor | No (proxy only) |

> More: `unified_demo` (scripted finance), `hostile_demo` (adversarial), `langchain_demo` (LangChain+Gmail), `rollback_demo` (checkpoint/rollback). All require `cargo run`.

### `gvm run` — run any command through GVM governance

```bash
# Script mode (auto-detect interpreter)
gvm run agent.py
gvm run --sandbox agent.py          # + kernel isolation (namespace + seccomp + eBPF)

# Binary mode (arbitrary command)
gvm run -- openclaw gateway          # Layer 2: proxy only
gvm run --sandbox -- openclaw gateway # Layer 2+3: proxy + namespace + seccomp + eBPF TC
gvm run -- python -m my_agent        # any command
```

`gvm run` injects `HTTPS_PROXY` into all child processes. With `--sandbox`, adds Linux namespace isolation, seccomp-BPF syscall filtering, and eBPF TC network enforcement. Transparent MITM (ephemeral CA inside sandbox for full L7 HTTPS inspection) is planned for v0.3.

### Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Proxy + SRR + WAL + Merkle | Yes | Yes | Yes |
| `gvm run` (HTTPS_PROXY) | Yes | Yes | Yes |
| `--sandbox` (namespace + seccomp + eBPF) | **Yes** | No | No |
| Transparent MITM (auto CA in sandbox) | **Planned v0.3** | `gvm trust-ca` | `gvm trust-ca` |
| `--contained` (Docker) | Yes | Yes | Yes |
| Shadow Mode | Yes | Yes | Yes |
| CONNECT tunnel (domain-level) | Yes | Yes | Yes |

### Defense Layers (Linux)

```
Layer 2: HTTP Proxy (all platforms)
  └─ SRR: URL/method/path matching + Base64 payload decoding
  └─ CONNECT tunnel: domain-level HTTPS enforcement (current)
  └─ WAL: Merkle-chained audit log
  └─ Hot-reload: POST /gvm/reload (zero-downtime rule swap)

Layer 3: OS Isolation (Linux only, --sandbox)
  └─ Namespace: PID/mount/net isolation
  └─ Seccomp-BPF: ~111 syscalls whitelisted
  └─ eBPF TC filter: kernel-level proxy-only enforcement
  └─ Transparent MITM: ephemeral CA auto-injected into sandbox (planned v0.3)
      → full L7: API key injection, path/method/body inspection, forgery detection
      → all work on HTTPS — no manual CA setup
```

**HTTPS inspection roadmap:**

| Mode | Current (v0.2) | Planned (v0.3) |
|------|---------------|----------------|
| `--sandbox` (Linux) | CONNECT blind relay (domain-level) | **Transparent MITM** — ephemeral CA injected into sandbox, full L7 inspection |
| macOS / non-sandbox | CONNECT blind relay | Optional MITM via `gvm trust-ca` (one-time manual CA install) |
| MITM refused | CONNECT blind relay | CONNECT blind relay (domain-only) |

In sandbox mode, the user does nothing — GVM auto-generates a per-session CA, injects it into `/etc/ssl/certs/` inside the namespace, redirects 443 traffic to the proxy, and performs TLS termination → plaintext inspection → re-encryption. The host system's CA store is never touched.

### Agent Integration Examples

GVM governs any agent that makes HTTP calls. No framework dependency.

```bash
# Any script/binary
gvm run agent.py                         # Python agent
gvm run -- node my_agent.js              # Node.js agent
gvm run --sandbox -- ./my_rust_agent     # Rust binary + kernel isolation

# Agent frameworks
gvm run -- openclaw gateway              # OpenClaw
gvm run -- python -m crewai run          # CrewAI
HTTP_PROXY=http://localhost:8080 autogen  # AutoGen (manual proxy)
```

**MCP Server** (optional — for Claude Desktop, Cursor, OpenClaw MCP clients):

```json
{
  "mcpServers": {
    "gvm-governance": {
      "command": "node",
      "args": ["path/to/mcp-server/dist/index.js"],
      "env": { "GVM_PROXY_URL": "http://127.0.0.1:8080" }
    }
  }
}
```

Provides `gvm_fetch`, `gvm_policy_check`, `gvm_status`, `gvm_select_rulesets` tools.
See the [MCP integration repo →](https://github.com/skwuwu/analemma-gvm-openclaw) for 12 preset rulesets and docs.

---

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **v0.1 — Alpha** | 3-layer enforcement, WAL ledger, encrypted vault, Python SDK, CLI, Linux sandbox, Merkle checkpoints, CONNECT tunnel, Shadow Mode, MCP integration | **Done** |
| **v0.2 — Hardening** | SRR hot-reload, Base64 payload decoding, `gvm run` binary mode, eBPF TC network enforcement, 34 E2E tests | **Done** |
| **v0.3 — Full L7** | **Transparent MITM** (ephemeral CA in sandbox), full HTTPS path/method/body inspection, API key injection on HTTPS, anomaly detection | Planned |
| **v1.0 — Production** | NATS JetStream, Redis vault backend, TLS termination hardening, Prometheus metrics | Planned |

Long-term: multi-agent governance, filesystem/shell/database capability controls, TypeScript/Go SDK, Envoy filter mode. [Full roadmap →](docs/13-roadmap.md)

---

## Trade-offs

GVM is lightweight because it uses deterministic pattern matching (URL, method, payload fields) instead of ML-based semantic analysis. This is an intentional architectural choice, not a missing feature.

| | GVM | LLM WAFs (Lakera, Prompt Armor, etc.) |
|---|---|---|
| **Catches** | URL/method/payload mismatches, policy violations, forgery | Prompt injection, toxic content, semantic attacks |
| **Misses** | Semantically valid but harmful requests | Jailbreaks, novel attacks, high false-positive rates |
| **Latency** | Sub-μs policy evaluation | 10-100ms per-request classification |
| **Infra** | Single binary, no GPU | GPU or SaaS API |

**GVM is complementary to LLM WAFs, not a replacement.** GVM enforces deterministic rules on what agents *do*; LLM WAFs analyze what agents *say*. Together they cover execution-layer and content-layer threats. Separately, each has a blind spot.

---

## OpenShell Comparison

| Feature | NVIDIA OpenShell | Analemma-GVM |
|---------|------------------|-----------------|
| **Isolation** | Docker + K3s (production-grade orchestration) | Linux namespaces (lighter, no Docker required) |
| **Policy Granularity** | Allow / Deny | Allow / Delay / RequireApproval / Deny |
| **Forgery Detection** | Single layer (URL) | Cross-layer with SDK; URL-only without SDK |
| **On Deny** | Agent waits for policy change | Auto-rollback to checkpoint (SDK only) |
| **Audit Integrity** | Audit trail | Merkle-verified hash chain |
| **Deployment** | Kubernetes (battle-tested at scale) | Standalone binary (simpler, but no K8s ecosystem) |
| **Maturity** | NVIDIA backing, growing community | Pre-release alpha, single developer |

**Honest trade-offs**: OpenShell's K8s isolation is more mature and operationally proven. GVM's namespace isolation is lighter but less battle-tested. Choose OpenShell if you already run K8s and want production-grade container isolation. Choose GVM if you need graduated enforcement, forgery detection, or want to avoid K8s complexity.

**Complementary, not competitive.** GVM can run *inside* an OpenShell sandbox for layered defense, or standalone.

---

## OPA+Envoy vs GVM

> OPA is a policy engine for microservices. GVM is a governance proxy for AI agents.
> They solve different problems that happen to share a surface similarity.

**The core divergence**: OPA+Envoy assumes honest services — your engineers write the code, your CI deploys it, requests follow known API contracts. GVM assumes adversarial agents — an LLM generates actions at runtime, headers may be forged, and the agent may be prompt-injected.

### What only GVM can do

These capabilities require architectural primitives that OPA+Envoy does not have. Building them on top of OPA would amount to rebuilding GVM.

| Capability | Why OPA Can't | GVM |
|-----------|---------------|-----|
| **Cross-layer lie detection** | No second classification engine to cross-check | `max_strict(ABAC, SRR)` catches forged headers |
| **LLM thinking trace** | No awareness of LLM response structure | Extracts reasoning from OpenAI/Anthropic/Gemini |
| **Checkpoint/rollback** | Proxy cannot manage agent state | Merkle-verified state restore on denial |

### What requires significant effort on OPA+Envoy

Achievable with custom Envoy filters + OPA extensions + additional systems, but the integration cost is high.

| Capability | What it would take on OPA | GVM |
|-----------|--------------------------|-----|
| Graduated enforcement | Custom filter + timer + approval queue | Built-in IC-2 Delay / IC-3 RequireApproval |
| Fail-close audit | Separate WAL + blocking Envoy filter | WAL fsync before every IC-2+ forward |
| API key isolation | Custom filter + secrets manager | Proxy injects post-enforcement, agent never holds keys |

### When to use what

**Use OPA+Envoy when** you govern service-to-service communication between trusted microservices, need a general-purpose policy engine (K8s admission, IAM, data filtering), or require production maturity and CNCF ecosystem integration.

**Use GVM when** the client is an AI agent that generates actions at runtime, you cannot trust self-reported metadata (prompt injection risk), you need graduated enforcement beyond binary allow/deny, or the agent should never hold API credentials.

**Honest assessment of OPA's advantages**: OPA has years of production use at scale (Netflix, Goldman Sachs, Pinterest), Rego's expressiveness far exceeds GVM's TOML-based rules, and the CNCF ecosystem integration (K8s admission, Terraform, Kafka) is mature. These are real strengths that matter in production. GVM is pre-release alpha software from a single developer. [Full competitive analysis →](docs/11-competitive-analysis.md)

---

## HTTP vs HTTPS Capabilities

GVM is an HTTP proxy. What the proxy can inspect and modify depends on the protocol:

| Capability | HTTP | HTTPS (CONNECT relay, v0.2) | HTTPS (MITM, planned v0.3) |
|------------|------|----------------------------|---------------------------|
| **Host filtering** | ✓ | ✓ (from CONNECT target) | ✓ |
| **Path/method inspection** | ✓ | ✗ (encrypted tunnel) | ✓ |
| **API key injection** | ✓ | ✗ (cannot modify headers) | ✓ |
| **Payload/body inspection** | ✓¹ | ✗ (encrypted tunnel) | ✓ |
| **WAL audit logging** | Full (host, method, path, headers) | Domain + method only | Full |
| **SRR rule matching** | Host + method + path | Host only | Host + method + path |
| **Forgery detection (with SDK)** | ✓ | Host-level only | ✓ |

> **What this means in practice**: Most AI API providers (OpenAI, Anthropic, Stripe, etc.) use HTTPS. In v0.2, GVM can block/allow by domain but cannot inspect paths, inject API keys, or read payloads on HTTPS traffic. Full L7 HTTPS governance requires the transparent MITM planned for v0.3 (`--sandbox` mode: automatic; non-sandbox: `gvm trust-ca`).
>
> **If you need full governance today**, route agent traffic over HTTP to the proxy and let the proxy handle the upstream HTTPS connection. This is how the `HTTP_PROXY` pattern works by default for most HTTP client libraries.

---

## Known Limitations

> What's implemented works. These are the edges we haven't polished yet.

**WAL Hardening (priority for v1.1)**: The WAL is the foundation of GVM's audit integrity claim. Three open limitations weaken this foundation and are prioritized for the next release:

| Area | Current State | Planned Fix | Priority |
|------|--------------|-------------|----------|
| **WAL Recovery** | ~~Loads entire WAL into memory~~ Fixed: streaming `BufReader` recovery | — | Done |
| **WAL Rotation** | Single file, no rotation | Size-based rotation with Merkle chain linking | v1.1 |
| **WAL Sequence** | Resets to 0 on restart | Initialize from last WAL event count | v1.1 |
| **IC-3 Approval** | Returns 403 with no approval mechanism | Webhook callback + approval queue | v1.1 |
| **Numeric Precision** | ~~Rate limiter uses `f64`~~ Fixed: millitoken `u64` fixed-point arithmetic | — | Done |
| **Vault Key** | Ephemeral random key if `GVM_VAULT_KEY` not set | Require explicit key in production | v1.1 |

Until WAL hardening ships, the Merkle chain is cryptographically sound but operationally fragile under infrastructure stress (crash during recovery, WAL exceeding available memory).

**Shadow Mode**: Intent store with configurable TTL (default 30s). Atomic operations prevent TOCTOU races. Opt-in via `GVM_SHADOW_MODE` env var.

**HTTPS inspection**: Currently CONNECT blind relay (domain-level only). Transparent MITM with ephemeral CA (full L7 path/method/body inspection on HTTPS) is planned for v0.3. In sandbox mode, CA injection will be automatic — no user action needed. Non-sandbox environments will require `gvm trust-ca` (one-time).

**SRR hot-reload**: `POST /gvm/reload` atomically swaps rules. Parse failure preserves existing rules. `gvm_select_rulesets` MCP tool triggers reload automatically.

> Full security model and known attack surface: [Security Model →](docs/12-security-model.md)

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
| [9](docs/09-test-report.md) | Test Coverage Report |
| [11](docs/11-competitive-analysis.md) | Competitive Analysis: GVM vs OPA+Envoy |
| [12](docs/12-security-model.md) | Security Model & Known Attack Surface |
| [13](docs/13-roadmap.md) | Roadmap |
| [14](docs/14-implementation-log.md) | Implementation Log |
| [14](docs/14-quickstart.md) | Quick Start Guide |
| [15](docs/15-reference.md) | Reference |

---

This software is open source (Apache 2.0), and I highly welcome your technical feedback and suggestions. Please contribute to this project!

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

