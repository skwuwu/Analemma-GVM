# Analemma-GVM

**See what your AI agent calls. Block what it shouldn't. Roll back when it fails.**

4MB binary. Single process. No Docker, no K8s, no GPU.

**Status: v0.2 (pre-release, single developer). Not externally audited. Primary platform: Linux.**

> **In one sentence:** GVM is an HTTP proxy that sits between your AI agent and the internet — it shows you every API call, enforces rules on what's allowed, injects credentials so the agent never holds keys, and logs everything in a tamper-evident audit chain.

---

## Who Is This For?

**Primary audience: developers who build and operate AI agents.**

You've built an agent that calls external APIs. It mostly works. But you've hit at least one of these:

- You don't know exactly which APIs your agent is calling in production
- The agent made an unexpected API call that cost you money or broke something
- You're nervous about giving the agent real API keys
- You need an audit trail of what the agent actually did (not what it said it did)

**Secondary audience: security teams** reviewing agent deployments. GVM provides the audit chain and enforcement layer — [Security Model →](docs/12-security-model.md)

---

## Why GVM?

### Real problems, concrete solutions

| What went wrong | How GVM prevents it |
|----------------|---------------------|
| **Agent called production API by mistake** | SRR rules deny by URL pattern. Unknown URLs get a 300ms delay + warning (Default-to-Caution) |
| **API costs were 10x expected** | Per-agent rate limiting. Audit trail shows exactly which calls went through |
| **Agent looped, sending the same request hundreds of times** | Rate limiter catches burst. WAL logs every attempt for diagnosis |
| **Agent held API keys and leaked them in logs** | Agent never has keys. GVM injects credentials post-enforcement (Layer 3) |
| **No idea what the agent did during an incident** | Merkle-chained WAL: tamper-evident, per-request audit log with trace chains |
| **Prompt injection made the agent misuse a legitimate tool** | Cross-layer forgery detection: what the agent *declared* vs what it *actually requested* — mismatch → Deny + forensic record |

These are not six separate features. They are consequences of one architectural choice: **govern agent actions at the infrastructure boundary, not inside the agent.**

> **Trade-off**: GVM uses deterministic pattern matching, not ML-based semantic analysis. It catches URL/method/payload mismatches and policy violations — not prompt injection or toxic content. For that, use an LLM WAF upstream. GVM and LLM WAFs are complementary: one governs what agents *do*, the other analyzes what agents *say*.

---

## Quick Start

### Step 1: Observe (zero config, zero risk)

Start by seeing what your agent does. No rules, no blocking — just visibility.

```bash
# Install
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release

# Watch your agent — all requests allowed through, nothing blocked
gvm watch my_agent.py
```

`gvm watch` wraps your agent, routes all HTTP traffic through the proxy, and shows you every API call in real time:

```
  TIME      METHOD HOST                           PATH                                      ST  TOKENS
  ──────────────────────────────────────────────────────────────────────────────────────────────────────
  14:23:01  ✓ POST   api.openai.com                 /v1/chat/completions                     200  [1,247 tokens]
  14:23:03  ✓ GET    api.github.com                 /repos/org/repo/pulls                    200
  14:23:03  ✓ POST   api.openai.com                 /v1/chat/completions                     200  [832 tokens]
  14:23:05  ✓ POST   api.stripe.com                 /v1/charges                              200
  ⚠ Unknown host (no SRR rule): POST api.stripe.com/v1/charges
```

After the agent finishes, you get a session summary:

```
═══ Session Summary ════════════════════════════════════════
  Duration: 2m 34s  |  42 requests  |  0.27 req/s

  Top Hosts:
    api.openai.com                       28 reqs  (66.7%)
    api.github.com                        9 reqs  (21.4%)
    api.stripe.com                        5 reqs  (11.9%)

  LLM Usage:
    Models: gpt-4o, gpt-4o-mini
    Tokens: 18,432 total (12,100 prompt + 6,332 completion)
    Est. Cost: $0.0940 (approximate)

  Status Codes:  2xx: 40  |  4xx: 1  |  5xx: 1

  ⚠ 3 request(s) hit unknown hosts (no SRR rule)

  → To enforce rules:          gvm run my_agent.py
  → To discover rules:         gvm run --interactive my_agent.py
  → To add kernel isolation:   gvm run --sandbox my_agent.py
════════════════════════════════════════════════════════════
```

Want to discover rules interactively? Use `gvm run --interactive`:

```bash
gvm run my_agent.py --interactive
```

GVM replays the same flow but with Default-to-Caution active, then prompts for each unknown URL:

```
⚠ POST api.stripe.com/v1/charges (7 hits)
  [a] Allow   [d] Delay   [n] Deny   [s] Skip
  Choice: a
    ✓ Rule added to config/srr_network.toml
```

### Step 2: Enforce

Now that you know what your agent calls, run it with rules enforced:

```bash
gvm run my_agent.py                    # Cooperative mode (any OS)
gvm run --sandbox my_agent.py          # Structural enforcement (Linux — production)
gvm run --contained my_agent.py        # Docker isolation (any OS)
```

Or, if you prefer manual proxy setup (any language):

```bash
# Terminal 1: start proxy
cargo run

# Terminal 2: run any agent
HTTP_PROXY=http://localhost:8080 python my_agent.py
HTTP_PROXY=http://localhost:8080 node my_agent.js
HTTP_PROXY=http://localhost:8080 ./my_agent
```

The recommended workflow: **observe → discover → enforce.** Start with Track A, graduate to Track B.

<details>
<summary><strong>First run: interactive setup wizard</strong></summary>

On first run, if no config exists, GVM offers an interactive setup:

```
⚡ First Run Detected
  Choose an industry template:
    1  finance  — Wire transfers blocked, payments need IC-3 approval
    2  saas     — Default-to-Caution, balanced security for SaaS agents
  Select [1/2]: 2
  ✓ proxy.toml  ✓ srr_network.toml  ✓ operation_registry.toml
  saas template applied (5 files)
  Starting proxy with saas configuration...
```

</details>

> Platform support, isolation modes, LLM provider governance, checkpoint/rollback — see [Quick Start Guide →](docs/15-quickstart.md)

---

## See It in Action

### Demo 1: Agent observation

```
 Your agent                GVM Proxy (:8080)                External API
 ┌──────────┐    HTTP      ┌──────────────────────┐  HTTPS  ┌──────────┐
 │ Any code │────PROXY────>│ URL check + policy   │────────>│ Stripe   │
 │ Any lang │              │ Key inject + audit   │         │ Gmail    │
 └──────────┘              └──────────────────────┘         └──────────┘
```

Every request flows through GVM. You see the target, method, path, decision, and timing — in real time.

### Demo 2: Catching a prompt-injected agent

An agent's code is well-designed — `read_storage(bucket, key)` takes structured parameters, not raw URLs. But a prompt injection corrupts the LLM's judgment. The LLM passes an attacker-controlled bucket name that, when assembled into a URL, redirects the request to an unintended host:

```python
@ic(operation="gvm.storage.read")
def read_storage(bucket: str, key: str):
    """Read an object from cloud storage. Code is correct — parameters are structured."""
    session = gvm_session()
    return session.get(f"https://{bucket}.s3.amazonaws.com/{key}").json()

# LLM is prompt-injected → passes a crafted bucket name
# The agent calls a legitimate function with legitimate-looking arguments
read_storage("api.bank.com/transfer/123?amount=50000&to=attacker#", "ignored")
# Actual URL: https://api.bank.com/transfer/123?amount=50000&to=attacker#.s3.amazonaws.com/ignored
```

```
 What the agent DECLARES    What actually happens             GVM decision
 ─────────────────────────────────────────────────────────────────────────

 "gvm.storage.read"         GET api.bank.com/transfer/...    DENY
       │                            │                       ▲
       ▼                            ▼                       │
 ┌───────────┐              ┌──────────────┐          ┌─────┴────────┐
 │  Layer 1  │              │   Layer 2    │          │ max_strict   │
 │  (ABAC)   │              │   (SRR)      │          │              │
 │           │              │              │          │ Stricter     │
 │  Allow    │              │  DENY        │──────────│ always wins  │
 │  (IC-1)   │              │  "Bank URL   │          │              │
 │           │              │   blocked"   │          │ → DENY       │
 └───────────┘              └──────────────┘          └──────────────┘

 Layer 1 is fooled.          Layer 2 sees the URL.      403 Forbidden.
 Layer 2 is not.             It doesn't care what
                             the intent header says.
```

**The key insight:** The code is correct. The function signature is safe. But the LLM's *judgment* was corrupted — it passed a crafted value through a legitimate interface. This is the realistic threat model for prompt injection: not rewriting code, but poisoning the inputs to well-designed functions.

**The forensic value:** The WAL records both the declared intent (`gvm.storage.read`) and the actual target (`GET api.bank.com/transfer/...`). This isn't just blocking — it's evidence of *intent disguise*. Post-incident, you can distinguish "agent made a mistake" from "agent was manipulated" by examining whether the declared operation matches the network behavior.

**Without SDK, the URL is still blocked** by SRR pattern matching alone. The intent-action mismatch isn't recorded, but the dangerous action is still prevented.

### Try it yourself

| Demo | What it shows | API key? |
|------|--------------|----------|
| `python -m gvm.mock_demo` | **Start here.** Full proxy enforcement, mock LLM | No |
| `python -m gvm.llm_demo` | Claude autonomous agent, live governance | Yes |
| `gvm run -- openclaw gateway` | Any agent through GVM proxy | Varies |
| [MCP integration](https://github.com/skwuwu/analemma-gvm-openclaw) | 12 preset rulesets, MCP server for Claude Desktop/Cursor | No |

> More: `unified_demo` (scripted finance), `hostile_demo` (adversarial), `langchain_demo` (LangChain+Gmail), `rollback_demo` (checkpoint/rollback). All require `cargo run`.

---

## How It Works

### Two tiers of integration

**Tier 1 requires zero code changes** — set `HTTP_PROXY` and every outbound HTTP request passes through the governance proxy. **Tier 2 adds the SDK** for deeper control.

| | Tier 1: Proxy only | Tier 2: + SDK (`@ic()` decorator) |
|---|---|---|
| **Code changes** | None | Add `@ic()` decorator to functions |
| **SRR: host / method / path rules** | ✓ | ✓ |
| **API key injection** | ✓ (HTTP; HTTPS in `--sandbox`)² | ✓ (HTTP; HTTPS in `--sandbox`)² |
| **Merkle audit (IC-2+)** | ✓ (agent="unknown") | ✓ (per-agent, per-operation) |
| **Default-to-Caution** | ✓ (Delay 300ms on unknown URLs) | ✓ |
| **Semantic policy (ABAC)** | — | ✓ |
| **Cross-layer forgery detection** | — | ✓ (`max_strict(Layer1, Layer2)`) |
| **Per-agent rate limiting** | — (shared bucket) | ✓ |
| **Linux namespace isolation** | `--sandbox` flag¹ | `--sandbox` flag¹ |
| **Checkpoint/rollback** | — | ✓ |

> ¹ `--sandbox` (Linux only): user/PID/mount/net namespace isolation, seccomp-BPF (~111 allowed syscalls), TC ingress filter on host veth. The proxy process itself is not sandboxed.
>
> ² In `--sandbox` mode, transparent MITM enables full HTTPS API key injection. Without `--sandbox`, HTTPS uses CONNECT blind relay (domain-level only) and API key injection works on HTTP only.

**Start with Tier 1.** It blocks known-bad URLs, injects credentials, and logs everything. Add the SDK when you need intent-action verification or per-agent policies.

### Three layers, three concerns

| Layer | What It Checks | What It Answers | Requires SDK? |
|-------|---------------|-----------------|---------------|
| **Layer 1: Semantic (ABAC)** | Operation name, resource, context | What the agent *declares* it's doing | Yes (`@ic()`) |
| **Layer 2: Network (SRR)** | Actual URL, method, path | What the agent *actually* does | **No** |
| **Layer 3: Credential Isolation** | API key injection + header stripping | What the agent *can access* | **No** |

These layers are independent by design. Layer 2 doesn't trust Layer 1. When both are active, `max_strict()` takes the stricter decision — this is what catches a prompt-injected LLM misusing a legitimate tool.

### Enforcement decisions

| Level | Decision | Behavior |
|-------|----------|----------|
| IC-1 | Allow | Immediate pass-through, async audit |
| IC-2 | Delay | WAL-first write, configurable delay, then forward |
| IC-3 | RequireApproval | Held until human approves via `gvm approve` CLI (timeout → auto-deny) |
| — | Deny | Unconditional block |

### Default-to-Caution: what happens with unknown URLs

When an agent calls a URL that matches no SRR rule, the behavior is configurable:

```toml
# proxy.toml
[enforcement]
default_unknown = "delay"          # "delay" | "require_approval" | "deny"
default_delay_ms = 300             # only used when default_unknown = "delay"
```

| Mode | Behavior | Best for |
|------|----------|----------|
| `delay` (default) | Allow after 300ms delay, record in WAL | **Development / testing** — agent keeps running, unknown URLs are logged for later review |
| `require_approval` | Hold request until human approves via `gvm approve` CLI | **Production finance / healthcare** — no unregistered API call proceeds without human review |
| `deny` | Block immediately with 403 | **High-security lockdown** — only explicitly allowed URLs can be called |

CLI override (temporary, does not modify config file):
```bash
gvm run --default-policy require_approval my_agent.py
gvm run --default-policy deny my_agent.py
```

Industry templates set this automatically: `saas` → `delay`, `finance` → `require_approval`.

---

## Works Today vs Roadmap

> Security tools earn trust through honesty. Here's exactly what works and what doesn't.

### Works Today (v0.2)

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP proxy with SRR enforcement (host/method/path) | **Shipping** | Sub-μs policy evaluation |
| API key injection (HTTP) | **Shipping** | Strips agent auth headers, injects from `secrets.toml` |
| API key injection (HTTPS, `--sandbox`) | **Shipping** | Transparent MITM, auto ephemeral CA |
| ABAC policy engine (3-layer hierarchy) | **Shipping** | Global > Tenant > Agent, regex pre-compiled |
| Merkle-chained WAL audit | **Shipping** | fsync before IC-2+ action, group commit batching |
| Checkpoint/rollback (SDK) | **Shipping** | Merkle-verified state restore |
| AES-256-GCM encrypted vault | **Shipping** | `zeroize` on drop, in-memory backend |
| Linux sandbox (`--sandbox`) | **Shipping** | Namespace + seccomp-BPF + TC filter |
| TLS MITM in sandbox | **Shipping** | SNI-based cert gen, ECDSA P-256, auto DNAT |
| JWT identity + rate limiting | **Shipping** | HMAC-SHA256, per-agent buckets |
| Shadow Mode (intent verification) | **Shipping** | 2-phase lifecycle, TOCTOU-safe |
| Cross-layer forgery detection (SDK) | **Shipping** | `max_strict(ABAC, SRR)` |
| `gvm watch` (observation mode) | **Shipping** | Real-time stream, session summary, cost estimation, anomaly detection, `--output json` |
| `gvm run` / `--interactive` / `--sandbox` / `--contained` | **Shipping** | CLI with auto proxy management |
| SRR hot-reload (`POST /gvm/reload`) | **Shipping** | Atomic swap, parse failure preserves existing rules |
| Docker fallback (`--contained`) | **Shipping** | For macOS/Windows |
| Python SDK (`@ic()` + `gvm_session()`) | **Shipping** | LangChain `@tool` stackable |

### Loaded but Inactive

| Feature | Current State | Impact |
|---------|--------------|--------|
| SRR payload inspection | Rules parsed from TOML, but proxy passes `body = None` | Host/method/path rules work fully. Body matching does not fire. |
| Wasm hot-path | Module loads and validates, but native engine is the default | No user impact — native engine is functionally identical |
| NATS JetStream | Connection stubbed, WAL-first design works locally | WAL is the primary audit path. NATS needed for distributed setups only. |

### Roadmap (Not Yet Implemented)

| Feature | Target | Notes |
|---------|--------|-------|
| IC-3 approval workflow (webhook/queue) | v1.1 | Currently IC-3 = Deny + "needs review" in audit log |
| Non-sandbox MITM (`gvm trust-ca`) | v1.1 | macOS/Windows full HTTPS inspection without `--sandbox` |
| SRR payload inspection activation | v1.1 | Wire up body buffering to SRR matching |
| NATS JetStream publish | v1.0 | Async event streaming for distributed audit |
| Redis/DynamoDB vault backend | v1.0 | Currently in-memory only |
| Prometheus metrics endpoint | v1.0 | Governance decisions + cost tracking |
| Multi-PID uprobe (TLS capture) | v0.3 | Experimental, observation-only |
| TypeScript/Go SDKs | v1.0+ | Currently Python only |
| Cross-agent collusion detection | v1.0+ | "Agent A denied → Agent B attempts same URL" |
| File permission check on `secrets.toml` | v1.1 | Currently loaded without permission verification |
| Decimal-precision numeric comparison | v1.1 | Currently f64 (boundary-case rounding risk) |

[Full roadmap →](docs/13-roadmap.md)

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
                     │ WAL → Merkle Ledger   │
                     │ AES-256-GCM Vault     │
                     └───────────────────────┘
```

### Checkpoint/Rollback — SDK only

| Feature | What it does |
|---------|-------------|
| **Auto-checkpoint** | Saves agent state before IC-2+ operations |
| **Merkle-verified rollback** | Restores state with cryptographic proof — the checkpoint is a leaf in the same Merkle tree as audit events |
| **Token savings** | Denied at step 3 of 4? Resume from checkpoint instead of re-running the entire workflow |

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

| Component | What it does | Details |
|-----------|-------------|---------|
| **Shadow Mode (Intent Store)** | 2-phase intent lifecycle, TOCTOU-safe consumption | [Details →](docs/06-proxy.md) |
| **ABAC Policy Engine** | Hierarchical rules (Global > Tenant > Agent), lower layers can only be stricter | [Details →](docs/02-policy.md) |
| **Network SRR** | URL-based enforcement independent of SDK headers, regex path matching, hot-reload | [Details →](docs/03-srr.md) |
| **WAL-First Ledger** | Crash-safe audit: fsync before action for IC-2+ events, Merkle chain | [Details →](docs/04-ledger.md) |
| **Encrypted Vault** | AES-256-GCM + `zeroize` on drop | [Details →](docs/05-vault.md) |
| **Proxy Pipeline** | CatchPanicLayer + backpressure + 1024 connection limit, sub-μs policy eval | [Details →](docs/06-proxy.md) |
| **Python SDK** | `@ic()` + `gvm_session()`, optional `GVMAgent` for checkpoint/rollback | [Details →](docs/07-sdk.md) |
| **OS Isolation** | Linux namespace + seccomp-BPF (`--sandbox`), Docker fallback (`--contained`) | [Details →](docs/08-memory-security.md) |

> Full technical whitepaper: [Architecture Overview →](docs/00-overview.md)

---

## Isolation Modes

### The development → production ladder

The recommended workflow matches how most developers already work: **develop on macOS/Windows, deploy to Linux.**

| Step | Command | Enforcement | HTTPS inspection | Platform |
|------|---------|-------------|-----------------|----------|
| **1. Observe** | `gvm run -i agent.py` | Cooperative (agent can bypass) | Domain-level only | Any OS |
| **2. Develop** | `gvm run --contained agent.py` | Docker isolation + MITM | Full L7 (path/method/body) | Any OS with Docker |
| **3. Production** | `gvm run --sandbox agent.py` | Kernel-level (namespace + seccomp + TC) | Full L7 (path/method/body) | Linux only |

Same CLI, same config files, same SRR rules at every step. Policies built in development work identically in production.

### `--contained` vs `--sandbox` — honest comparison

Both provide HTTPS MITM inspection via ephemeral CA injection and DNAT. The difference is enforcement depth:

| Feature | `--contained` (Docker) | `--sandbox` (Linux-native) |
|---------|----------------------|---------------------------|
| **Platform** | Any OS with Docker | Linux only |
| **HTTPS MITM** | ✓ (CA injected via volume mount, DNAT via iptables in container) | ✓ (CA injected via mount namespace, DNAT via iptables + host veth) |
| **API key injection (HTTPS)** | ✓ | ✓ |
| **Network isolation** | Docker bridge (`--internal`) | veth pair + iptables + TC ingress filter |
| **Proxy bypass prevention** | Hardened cooperative — Docker network + DNAT, but agent has `NET_ADMIN` for DNAT setup and could theoretically modify rules | **Structural** — TC filter on host-side veth (agent cannot touch), seccomp blocks AF_NETLINK |
| **Seccomp** | Docker default profile only | Custom profile: ~111 syscalls, `ptrace`/`bpf`/`mount` killed, AF_NETLINK blocked |
| **Filesystem** | Read-only root + tmpfs /tmp | Minimal rootfs via `pivot_root` |
| **Resource limits** | Configurable (`--memory`, `--cpus`) | OS-level limits |
| **CA trust coverage** | Python, Node.js, Go, curl, Ruby (via env vars + volume mount) | All (injected into system trust store via mount namespace) |
| **Java support** | Requires manual keystore import | Requires manual keystore import |

> **When to use which:** Use `--contained` for development and CI/CD on any OS — it provides full HTTPS inspection with Docker you already have. Use `--sandbox` for production on Linux — it provides kernel-level enforcement guarantees that Docker cannot match. The `NET_ADMIN` capability given to `--contained` for DNAT is a known trade-off: it's necessary for HTTPS MITM but weakens the isolation compared to `--sandbox`.

### Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Proxy + SRR + WAL + Merkle | Yes | Yes | Yes |
| `gvm run` (cooperative HTTP_PROXY) | Yes | Yes | Yes |
| `--contained` (Docker + MITM) | Yes | Yes (Docker Desktop) | Yes (Docker Desktop) |
| `--sandbox` (namespace + seccomp + TC) | **Yes** | No | No |
| Shadow Mode | Yes | Yes | Yes |

### HTTP vs HTTPS Capabilities

| Capability | HTTP | HTTPS — no isolation | HTTPS — `--contained` | HTTPS — `--sandbox` |
|------------|------|---------------------|----------------------|---------------------|
| **Host filtering** | ✓ | ✓ (CONNECT target) | ✓ | ✓ |
| **Path/method inspection** | ✓ | ✗ (encrypted) | ✓ (MITM) | ✓ (MITM) |
| **API key injection** | ✓ | ✗ | ✓ (MITM) | ✓ (MITM) |
| **Body inspection** | ✓ | ✗ (encrypted) | ✓ (MITM) | ✓ (MITM) |
| **WAL audit detail** | Full | Domain only | Full | Full |
| **SRR rule matching** | Host+method+path | Host only | Host+method+path | Host+method+path |
| **Proxy bypass prevention** | None | None | Hardened (Docker network) | Structural (kernel) |

> **Bottom line:** Both `--contained` and `--sandbox` provide full L7 HTTPS inspection. The difference is enforcement strength, not inspection capability. For most development workflows, `--contained` is sufficient.

### Agent Integration

GVM governs any agent that makes HTTP calls. No framework dependency.

```bash
# Any script/binary
gvm run agent.py                         # Python
gvm run -- node my_agent.js              # Node.js
gvm run --sandbox -- ./my_rust_agent     # Rust binary + kernel isolation

# Agent frameworks
gvm run -- openclaw gateway              # OpenClaw
gvm run -- python -m crewai run          # CrewAI
HTTP_PROXY=http://localhost:8080 autogen  # AutoGen (manual proxy)
```

---

## OPA+Envoy vs GVM

> OPA+Envoy is an excellent, production-grade policy infrastructure for service-to-service communication, battle-tested at Netflix, Goldman Sachs, and Pinterest. GVM exists separately not because OPA+Envoy is lacking, but because AI agents present a fundamentally different threat model: the "client" generates actions at runtime and may be prompt-injected.

**Why you should probably use OPA+Envoy instead**: OPA has years of production use at scale. Rego is far more expressive than GVM's TOML rules. The CNCF ecosystem (K8s admission, Terraform, Kafka) is mature. A large community provides support. Everything GVM does in Tier 2 can be built on OPA+Envoy with custom filters — it just requires more integration effort. GVM is a pre-release experiment by a single developer. Whether its pre-built agent-specific defaults justify adopting alpha software is a judgment call.

**That said, here's where the scope differs:**

### What GVM provides out of the box for agents

| Capability | OPA+Envoy | GVM |
|-----------|-----------|-----|
| Cross-layer verification (intent vs action) | Custom Rego per operation | Built-in `max_strict(ABAC, SRR)` |
| Graduated enforcement (Allow/Delay/Deny) | Custom filter + timer + approval queue | Built-in IC-1/IC-2/IC-3 |
| Fail-close audit (WAL-first) | Separate WAL + blocking Envoy filter | Built-in: fsync before every IC-2+ forward |
| API key isolation | Custom filter + secrets manager | Built-in: agent never holds keys |
| Checkpoint/rollback | Not available in proxy layer | Built-in via SDK |
| Single-binary deployment | K8s + OPA server + Envoy sidecar | 4MB `cargo run` |

### When to use what

**Use OPA+Envoy when** you govern service-to-service communication between trusted microservices, need a general-purpose policy engine, or require production maturity and CNCF ecosystem integration.

**Use GVM when** the client is an AI agent that generates actions at runtime, you cannot trust self-reported metadata (prompt injection risk), you need graduated enforcement beyond binary allow/deny, or the agent should never hold API credentials.

[Full competitive analysis →](docs/11-competitive-analysis.md)

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

## Known Limitations

> These are not minor polish items — some directly affect the core value proposition. Read before deploying.

**Fundamental gaps:**

| Gap | Impact | Mitigation |
|-----|--------|------------|
| **HTTPS without isolation** | Path/method/body inspection **does not work** — only domain filtering | Use `--contained` (Docker, any OS) or `--sandbox` (Linux) for full L7 HTTPS |
| **SRR payload inspection** | Rules are parsed but **currently inactive** — body is never inspected | Host/method/path rules work. Payload matching is roadmap |
| **No external security audit** | Pre-release alpha, single developer, no third-party review | 321+ tests including adversarial/stress suites, but not a substitute for audit |

**`--contained` (Docker) notes:**

- `--cap-add=NET_ADMIN` is granted to the container for DNAT iptables setup (HTTPS → MITM listener redirect). This is a trade-off: necessary for MITM but gives the agent the theoretical ability to modify iptables rules inside the container. Mitigated by `no-new-privileges` and `--internal` Docker network.
- CA trust coverage: Python, Node.js, Go, curl, Ruby are covered via env vars + volume mount. **Java requires manual keystore import** (`keytool -import`).
- Proxy failure is fail-closed: Docker's `--internal` network blocks external access, so the agent cannot fall back to direct connections.

**`--sandbox` (Linux) notes:**

- `kernel.unprivileged_userns_clone=1` (required) has historically been an attack surface for privilege escalation (CVE-2022-0185, CVE-2023-2640). GVM mitigates with seccomp blocking of `unshare`/`clone3`/`setns`, but the sysctl widens the host's attack surface. **Minimum**: kernel ≥ 4.15 (functional). **Recommended**: LTS kernel ≥ 6.1.
- Proxy failure is fail-closed: iptables OUTPUT DROP + TC filter = no network path without proxy. Watchdog auto-restarts proxy (max 3 attempts). Agent sees `ECONNREFUSED` during restart window.

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
| [10](docs/10-architecture-changes.md) | Architecture Changes |
| [11](docs/11-competitive-analysis.md) | Competitive Analysis |
| [12](docs/12-security-model.md) | Security Model & Known Attack Surface |
| [13](docs/13-roadmap.md) | Roadmap |
| [14](docs/14-implementation-log.md) | Implementation Log |
| [15](docs/15-quickstart.md) | Quick Start Guide |
| [16](docs/16-reference.md) | Reference |

---

This software is open source (Apache 2.0), and I highly welcome your technical feedback and suggestions. Please contribute to this project!

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
