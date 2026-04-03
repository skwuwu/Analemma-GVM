# Analemma-GVM

I wanted to run multiple OpenClaw agents for my startup. But every time I let an agent autonomously call external APIs, the same question stopped me: *what if it calls something it shouldn't?*

Existing answers required Kubernetes, Envoy sidecars, or trusting the agent to behave. I needed something I could `cargo build` and run in front of any agent, on a single machine, with no infrastructure team.

So I built GVM — an HTTP proxy that sits between your agent and the internet. It doesn't trust the agent. It watches every API call, blocks what you haven't approved, and keeps a tamper-evident log of everything.

```
Agent (any framework) → GVM Proxy → External APIs
                          ↓
                    See it. Block it.
                    Audit it.
```

Single binary. Single process. No Docker, no K8s, no GPU.

---

## Who needs this

- **Solo devs / small teams** running AI agents in production without a dedicated security team
- **Anyone who's nervous** about giving an agent access to Stripe, Slack, Gmail, or a database API
- **Startups** that need governance and audit trails but can't adopt enterprise infra (OPA, Envoy, NVIDIA OpenShell)
- **Agent framework users** (OpenClaw, CrewAI, LangChain, AutoGen) who want a safety layer that doesn't require code changes

If you have a Kubernetes cluster and a platform team, you probably don't need this. If you're one person running agents on an EC2 instance, this is for you.

---

## Quick Start

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release

# Watch what your agent calls (no blocking)
gvm run --watch my_agent.py

# Generate rules from what you saw
gvm suggest --from data/wal.log > config/srr_network.toml

# Enforce those rules
gvm run my_agent.py

# Production: kernel-level isolation (Linux)
gvm run --sandbox my_agent.py
```

Everything is `gvm run` with flags. Watch → suggest → enforce. [Quick Start →](docs/12-quickstart.md)

---

## What it does

GVM is the enforcement layer, not a filter. It doesn't read prompts or classify outputs — it intercepts the HTTP calls the agent actually makes.

| Decision | What happens | Example |
|----------|-------------|---------|
| **Allow** | Pass through, async audit | `GET api.github.com/repos` |
| **Delay** | Audit first, then forward | Unknown host, first time seen |
| **RequireApproval** | Hold until human approves | `POST api.stripe.com/charges` |
| **Deny** | Block immediately | `DELETE production-db/users` |

The agent never holds API keys. GVM strips whatever the agent sends and injects the real credentials from `config/secrets.toml` — post-enforcement.

### Verify before deployment

```bash
gvm check --agent-id finance-bot --host api.stripe.com --method POST
#  Decision:     RequireApproval
#  Path:         Policy(Allow) + SRR(RequireApproval) → Final(RequireApproval)
#  Latency:      38μs
```

Same classification function as the live proxy. Check results always match real enforcement.

---

## Modes

| Mode | Command | What it does |
|------|---------|-------------|
| **Watch** | `gvm run --watch agent.py` | See every API call. No blocking. |
| **Enforce** | `gvm run agent.py` | Apply URL rules + audit trail |
| **Discover** | `gvm run -i agent.py` | Enforce + suggest new rules after exit |
| **Sandbox** | `gvm run --sandbox agent.py` | Kernel isolation (namespace + seccomp + MITM) |

Sandbox mode intercepts all HTTPS at the network level — the agent physically cannot bypass the proxy. Works with any runtime (Python, Node.js, Go, binaries).

### MCP (Claude Desktop / Cursor)

GVM provides MCP tools for AI assistants. [Setup guide →](docs/12-quickstart.md#7-mcp-integration--claude-desktop--cursor)

---

## What it's not

- **Not a prompt filter.** Use Lakera or provider safety for that. GVM governs actions, not words.
- **Not enterprise infra.** No multi-node, no Kubernetes operator, no dashboard. Single binary, single machine.
- **Not a replacement for OPA.** OPA governs service-to-service. GVM governs agent-to-world.

| | LLM Provider Safety | Prompt Guards (Lakera) | **GVM** |
|---|---|---|---|
| **Controls** | Model output content | Model input/output | **Agent actions (HTTP calls)** |
| **Enforcement** | Inside the model | Before/after model | **Between agent and APIs** |
| **Audit** | Provider logs (you don't own) | Prompt logs | **Merkle WAL (you own)** |

[Full analysis →](docs/10-competitive-analysis.md)

---

## Technical facts

- Rust, ~17MB release binary, ~10MB RSS at idle
- Policy evaluation < 1μs (SRR + ABAC, no heap allocation on hot path)
- WAL with Merkle chain, size-based rotation (100MB default), watermark crash recovery
- 367+ tests, 30-min chaos stress test (proxy kill, network partition, disk pressure) — [PASS](docs/09-test-report.md#910-chaos-stress-test-30-minutes)
- seccomp-BPF with ~130 whitelisted syscalls, ENOSYS default for unknown
- Sandbox auto-cleanup via per-PID state files (Docker pattern)

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Quick Start](docs/12-quickstart.md) | Build, run, isolate, MCP setup |
| [Reference](docs/13-reference.md) | Config, CLI, API, CI/CD |
| [Security Model](docs/11-security-model.md) | Threat model, known attack surface |
| [Governance Coverage](docs/14-governance-coverage.md) | Per-mode enforcement matrix |
| [Changelog](docs/CHANGELOG.md) | Roadmap, implementation log |

---

**Status**: v0.4 pre-release. Not externally audited. [Security Model →](docs/11-security-model.md)

Apache 2.0. [Issues →](https://github.com/skwuwu/Analemma-GVM/issues)
