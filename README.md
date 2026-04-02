# Analemma-GVM

**Your AI agent just called `DELETE /production/users`. Did you approve that?**

GVM is the enforcement layer between your AI agent and the internet. It sees every API call, blocks what you haven't approved, and logs everything in a tamper-evident chain — before the request ever reaches the upstream server.

```
Agent (any framework) → GVM Proxy → External APIs
                          ↓
                    See it. Block it.
                    Audit it. Roll back.
```

Single binary (~17MB). Single process. Zero code changes required.

**Status**: v0.4 pre-release. [Security Model →](docs/11-security-model.md) | [30-min chaos stress test PASS](docs/09-test-report.md#910-chaos-stress-test-30-minutes)

---

## Why

AI agents call APIs autonomously. When something goes wrong:

| Problem | Without GVM | With GVM |
|---------|------------|----------|
| Agent calls production API by mistake | Incident. Manual rollback. | **Denied by URL rule. Never reaches production.** |
| Agent loops 200 identical requests | $500 bill. Discovered next morning. | **Rate limited. Blocked after 10. Alerted immediately.** |
| Prompt injection makes agent misuse a tool | Agent had API keys. Data exfiltrated. | **Agent never holds keys. GVM injects post-enforcement.** |
| "What happened?" during incident review | Scattered logs across 5 services. | **Merkle-chained audit trail. Every request. Tamper-evident.** |
| New agent needs access to Stripe | Copy-paste API keys into env vars. | **`gvm check --agent-id new-agent --host api.stripe.com` → verify before deploy.** |

One architectural choice produces all of these: **govern actions at the network boundary, not inside the agent.**

---

## Quick Start (3 minutes)

```bash
# Build
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release

# Step 1: Observe — see what your agent calls
gvm watch my_agent.py

# Step 2: Generate rules from what you observed
gvm suggest --from session.jsonl --output config/srr_network.toml

# Step 3: Enforce — block what you didn't approve
gvm run my_agent.py

# Step 4 (production): Kernel-level isolation
gvm run --sandbox my_agent.py    # Linux: namespace + seccomp + MITM
```

**That's it.** Watch → suggest → enforce. [Detailed guide →](docs/12-quickstart.md)

---

## How It Works

```
┌─────────────┐     ┌───────────────────────────┐     ┌──────────────┐
│  AI Agent    │────>│  GVM Proxy                │────>│ Stripe API   │
│  (any framework)   │  1. Match URL rules (SRR) │     │ Slack API    │
│              │     │  2. Check agent policy     │     │ Gmail API    │
│              │     │  3. Inject API keys        │     │ ...          │
│              │     │  4. Log to audit chain     │     │              │
└──────────────┘     └───────────────────────────┘     └──────────────┘
```

| Decision | What happens | Example |
|----------|-------------|---------|
| **Allow** | Pass through, async audit | `GET api.github.com/repos` |
| **Delay** | Audit first, then forward (safety buffer) | Unknown host, first time seen |
| **RequireApproval** | Hold request until human approves (`gvm approve`) | `POST api.stripe.com/charges` |
| **Deny** | Block immediately | `DELETE production-db/users` |

### Dry-run before deployment

```bash
gvm check --agent-id finance-bot --operation gvm.payment.charge --host api.stripe.com
#  Decision:     RequireApproval
#  Path:         Policy(Allow) + SRR(RequireApproval) → Final(RequireApproval)
#  Matched rule: stripe-charges-approval-required
#  Latency:      38μs
```

Same `enforcement::classify()` function as the live proxy — check results always match real enforcement.

---

## Isolation Modes

| Mode | Command | HTTPS inspection | Platform |
|------|---------|-----------------|----------|
| **Observe** | `gvm watch agent.py` | None (observation only) | Any OS |
| **Cooperative** | `gvm run agent.py` | Python: full. Node.js: HTTP only* | Any OS |
| **Sandbox** | `gvm run --sandbox agent.py` | Full L7 (DNAT → MITM) | Linux (production) |

> \* Node.js ignores `HTTPS_PROXY`. Use `--sandbox` for Node.js agents. GVM warns when it detects Node.js in cooperative mode.

`--sandbox` isolates the agent in Linux namespaces with seccomp-BPF, intercepts all HTTPS via MITM, and injects credentials — the agent physically cannot bypass the proxy.

### MCP (Claude Desktop / Cursor)

GVM provides MCP tools for AI assistants. Claude Desktop can check policies, fetch URLs through governance, and browse audit logs — all governed by GVM.

```bash
# Start proxy, then configure Claude Desktop to use GVM MCP server
# See: docs/12-quickstart.md#7-mcp-integration--claude-desktop--cursor
```

---

## SDK (optional, zero required)

**Tier 1** — proxy only, no code changes: URL rules, credential injection, full audit trail.

**Tier 2** — add Python SDK for intent verification:

```python
from gvm import ic, gvm_session

@ic(operation="gvm.messaging.send")
def send_email(to, subject, body):
    return gvm_session().post("http://gmail.googleapis.com/...", json={...}).json()
```

The proxy cross-checks what the agent *says* it's doing (`@ic`) against what it *actually* requests (URL). `max_strict()` catches the mismatch. Works with CrewAI, AutoGen, LangChain, plain Python.

---

## Competitive Position

| | LLM Provider Safety | Prompt Guards (Lakera) | **GVM** |
|---|---|---|---|
| **Controls** | Model output content | Model input/output | **Agent actions (HTTP calls)** |
| **Enforcement** | Inside the model | Before/after model | **Between agent and APIs** |
| **Audit** | Provider logs (you don't own) | Prompt logs | **Merkle WAL (you own)** |

LLM safety says "don't generate harmful text." GVM says "don't call `DELETE /production`." [Full analysis →](docs/10-competitive-analysis.md)

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Quick Start](docs/12-quickstart.md) | First-time setup, isolation modes |
| [Reference](docs/13-reference.md) | CLI, config, API, CI/CD integration |
| [SRR Rules](docs/03-srr.md) | URL/method/path matching syntax |
| [Security Model](docs/11-security-model.md) | Threat model, known attack surface |
| [Architecture](docs/00-overview.md) | 3-layer design, Merkle WAL, enforcement decisions |
| [Governance Coverage](docs/14-governance-coverage.md) | Per-mode enforcement matrix |
| [Competitive Analysis](docs/10-competitive-analysis.md) | vs Lakera, Prompt Armor, OPA, OpenAI safety |
| [Changelog](docs/CHANGELOG.md) | Roadmap, implementation log |

---

Apache 2.0. Contributions and feedback welcome — [issues](https://github.com/skwuwu/Analemma-GVM/issues).
