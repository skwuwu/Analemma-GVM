# Analemma-GVM

I wanted to run multiple OpenClaw agents for my startup. But every time I let agents everything what they wanna do, there was always a little anxiety: What if it does something it shouldn't?

Existing answers(such as Openshell, OPA+Envoy) required Kubernetes, Envoy sidecars, or trusting the agent to behave. I wanted a light weight alternative which doesn't need infrastructure settings and highly enforces what agents do.

So I built GVM(Governance Virtual Machine) — an governance runtime that exists between your agent and the actual actions. It is designed assuming that agents can't be fully trusted and can sometimes be hostile. It watches every API call, blocks what you haven't approved, and keeps a tamper-proof log(by Merkle chain) of agent's actions.

```
Agent (any framework) → GVM Proxy → External APIs
```

A single Rust binary. No Kubernetes, no service mesh, no sidecar, no GPU. Linux x86_64 host with glibc — that's the entire runtime requirement for cooperative and watch modes. Sandbox mode adds the standard `iproute2` / `iptables` userland that ships with every server distribution. See [Requirements](#requirements) below for the full matrix.

## Demo — Watch → Suggest → Enforce in 3 commands

![GVM demo: watch → suggest → enforce](docs/assets/gvm-demo.gif)

*33-second GIF, rendered from [`docs/assets/gvm-demo.cast`](docs/assets/gvm-demo.cast).
Replay interactively with `asciinema play docs/assets/gvm-demo.cast`.*

The demo runs the full Watch → Suggest → Enforce loop end-to-end on a real
Ubuntu 24.04 host:

1. **`gvm run --watch demo_agent.py`** — observes every URL the agent calls,
   prints a live stream and a session summary, marks unknown hosts as
   Default-to-Caution.
2. **`gvm run --watch --output json demo_agent.py > session.jsonl`** then
   **`gvm suggest --from session.jsonl > config/srr_network.toml`** — turns
   the recorded session into explicit SRR rules.
3. **`gvm run demo_agent.py`** — enforces. The known URLs land instantly;
   a fourth URL added after the rules were written falls into
   Default-to-Caution and lights up the audit trail with `2 delayed`,
   exactly as the rest of this README describes.

Agent code was not changed between steps. The same `demo_agent.py` and the
same proxy port handle all three runs — only the SRR config and the
agent's URL list differ.

---

## Who needs this

- **Solo devs / small teams** running AI agents in production without a dedicated security team
- **Anyone who's nervous** about giving an agent access to Stripe, Slack, Gmail, or a database API
- **Startups** that need governance and audit trails but can't adopt enterprise infra (OPA, Envoy, NVIDIA OpenShell)
- **Agent framework users** (OpenClaw, CrewAI, LangChain, AutoGen) who want a safety layer that doesn't require code changes

If you're running agents without any governance tools, you may need this.

---

## Requirements

- **OS**: Linux x86_64. The pre-built binary is dynamically linked against glibc — works on Ubuntu 20.04+, Debian 11+, RHEL 8+, Amazon Linux 2023, and equivalents. Alpine / other musl distros need a `x86_64-unknown-linux-musl` build from source.
- **Cooperative / watch modes**: glibc only. No extra system tools.
- **`--sandbox` mode**: additionally requires `iproute2` (`ip`), `iptables`, and `ip6tables` on the host (preinstalled on most server distros). `gvm preflight` reports exactly what is missing and prints the install command for your distro. Either run as `sudo` or grant the binary capabilities directly: `sudo setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace+ep' ./gvm`.
- **Other modes** (`--contained`): Docker on the host instead of the above.(not stabilized yet-experimental)

## Quick Start

```bash
# Option 1: Pre-built binary (glibc Linux x86_64)
curl -L https://github.com/skwuwu/Analemma-GVM/releases/latest/download/gvm-linux-x86_64.tar.gz | tar xz

# Option 2: Build from source
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release

# Verify your environment (sandbox prerequisites, available modes)
./gvm preflight
```

```bash
# Watch what your agent calls (no blocking)
gvm run --watch my_agent.py

# Generate rules from what you saw
gvm suggest --from data/wal.log > config/srr_network.toml

# Enforce those rules
gvm run my_agent.py

# Production: kernel-level isolation (Linux)
gvm run --sandbox my_agent.py
```

Everything is `gvm run` with flags. Watch → suggest → enforce. [Quick Start →](docs/quickstart.md)

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

---

## What it doesn't do

- **Not a prompt filter.** Use Lakera or provider safety for that. GVM governs actions, not words.
- **Not a replacement for OPA.** OPA governs service-to-service. GVM governs agent-to-world.

| | LLM Provider Safety | Prompt Guards (Lakera) | **GVM** |
|---|---|---|---|
| **Controls** | Model output content | Model input/output | **Agent actions (HTTP calls)** |
| **Enforcement** | Inside the model | Before/after model | **Between agent and APIs** |
| **Audit** | Provider logs (you don't own) | Prompt logs | **Merkle WAL (you own)** |

[Full analysis →](docs/security-layers.md)

---

## Technical facts

- Rust, ~17MB release binary, ~10MB RSS at idle
- Policy evaluation < 1μs (SRR + ABAC, no heap allocation on hot path)
- WAL with Merkle chain, size-based rotation (100MB x 10 segments). Local storage — bring your own retention (S3, GCS, etc)
- 329 tests, 60-min chaos stress test (proxy kill, network partition, disk pressure) — [PASS](docs/test-report.md#chaos-stress-test-30-minutes-2026-04-05)
- seccomp-BPF with ~130 whitelisted syscalls, ENOSYS default for unknown
- Sandbox auto-cleanup via per-PID state files (Docker pattern)

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Quick Start](docs/quickstart.md) | Build, run, isolate |
| [Reference](docs/reference.md) | Config, CLI, API, CI/CD |
| [Security Model](docs/security-model.md) | Threat model, known attack surface (not externally audited) |
| [Governance Coverage](docs/governance-coverage.md) | Per-mode enforcement matrix |
| [Changelog](docs/internal/CHANGELOG.md) | Roadmap, implementation log |

---
- Feedback on technical and structural issues or bug reports is always welcome.

v0.4 pre-release. Apache 2.0. [Issues →](https://github.com/skwuwu/Analemma-GVM/issues)
