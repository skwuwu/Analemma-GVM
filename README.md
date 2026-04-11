# Analemma-GVM

**A lightweight secure runtime for autonomous AI agents.** Governs every outbound HTTP call, isolates the filesystem, and locks down syscalls — using a Rust proxy and Linux kernel primitives.

I wanted to run multiple autonomous AI agents (such as OpenClaw) for my personal affairs. But every time I let agents do everything they want, there was always a little anxiety. What if it does something it shouldn't? What if it leaks personal information or deletes important data?

Existing answers (such as NemoClaw, OPA+Envoy) required Docker, an embedded Kubernetes cluster, NVIDIA GPUs, or Envoy sidecars. I wanted a lightweight alternative that doesn't need infrastructure setup and strictly enforces what agents do.

So I built GVM (Governance Virtual Machine) — a lightweight security runtime for AI agents. Two small Rust binaries (CLI + proxy, ~22MB total), no Kubernetes, no service mesh, no GPU. It sits between your agent and its actions, and assumes the agent can't be fully trusted.

## Demo — Watch, Suggest, Enforce in 3 commands

![GVM demo: watch → suggest → enforce](docs/assets/gvm-demo.gif)

*33-second GIF, rendered from [`docs/assets/gvm-demo.cast`](docs/assets/gvm-demo.cast).
Replay interactively with `asciinema play docs/assets/gvm-demo.cast`.*

The demo runs on a real Ubuntu 24.04 host. Agent code is not changed between steps — only the rules and flags differ.

---

## What happens when you run `gvm run --sandbox agent.py`

One command activates four security layers. This is the production mode — Linux only (requires namespaces, iptables, seccomp-BPF).

**DNS governance (Layer 0)** — Every DNS query passes through a built-in governance proxy before any HTTP call happens. Known domains (learned via `gvm suggest`) resolve instantly. Unknown domains are delayed 200ms. Repeated anomalous patterns (e.g. subdomain burst — a DNS tunneling signature) escalate to 3–10 second delays with alerts. No DNS query is ever denied — worst case is a delay, never an outage. Disable with `--no-dns-governance` if you already use dedicated DNS security tools.

**Network governance (Layer 1)** — Every outbound HTTP/HTTPS call goes through the GVM proxy. Calls that match your ruleset pass through; unknown calls are delayed or denied. The agent cannot bypass the proxy — even if it unsets env vars or opens raw sockets, kernel-level iptables DNAT redirects all traffic through GVM.

| Decision | What happens | Example |
|----------|-------------|---------|
| **Allow** | Pass through, async audit | `GET api.github.com/repos` |
| **Delay** | Audit first, then forward | Unknown host, first time seen |
| **RequireApproval** | Hold until human approves | `POST api.stripe.com/charges` |
| **Deny** | Block immediately | `DELETE production-db/users` |

**Filesystem governance (Layer 2)** — The agent works on an overlayfs layer, not the real host filesystem. Nothing lands on disk until a human reviews and approves via `gvm fs approve`.

**Credential isolation** — When the agent calls a governed API, GVM strips whatever credentials the agent sends and injects the real keys post-enforcement. The agent never needs to hold those API keys. (LLM provider keys that the agent needs for its own reasoning are passed through — stripping them would stop the agent from functioning.)

**Syscall filtering** — seccomp-BPF restricts the agent to ~130 whitelisted syscalls. This prevents the agent from modifying iptables rules (no `AF_NETLINK`) or opening raw sockets (no `AF_PACKET`), ensuring the network layer above can't be tampered with.

These aren't separate features you configure individually. They're layers of a single sandbox runtime, all activated by `--sandbox`.

---

## The three-step workflow

You don't need to write rules by hand. Watch what your agent does, let GVM generate rules, then enforce them.

```bash
# 1. Watch — observe every API call, no blocking
gvm run --sandbox --watch agent.py

# 2. Suggest — turn the recorded session into rules
gvm suggest --from session.jsonl > config/srr_network.toml

# 3. Enforce — apply those rules
gvm run --sandbox agent.py
```

After step 3, known URLs pass instantly. A new URL the agent tries to call — one that wasn't in the watch session — hits Default-to-Caution and gets delayed, flagged in the audit trail.

You can also discover rules interactively: `gvm run -i --sandbox agent.py` enforces and then prompts you to create rules for any unknown hosts on exit.

---

## Without sandbox — cooperative mode

Sandbox mode requires Linux. On **macOS, Windows**, or when you just want a quick run without root:

```bash
gvm run --watch agent.py      # watch mode, cooperative
gvm run agent.py              # enforce mode, cooperative
```

Cooperative mode injects `HTTP_PROXY` / `HTTPS_PROXY` into the agent's environment. All the same governance rules apply — but enforcement depends on the agent's HTTP client honouring those env vars. A non-cooperating client can bypass the proxy.

Use cooperative mode for agents you trust or wrote yourself (Python `requests`, curl). Use sandbox mode when running untrusted or third-party agents in production.

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

- Rust, two binaries totaling ~22MB on Linux x86_64 (gvm-proxy ~13MB + gvm CLI ~10MB)
- gvm-proxy RSS: ~11MB idle, ~13MB under load (measured on EC2 t3.medium)
- Sandbox MITM overhead: +14ms TTFB per request ([measured on EC2 t3.medium](docs/test-report.md#912-end-to-end-overhead-benchmark-2026-04-06-ec2-t3medium))
- Sandbox startup: ~928ms one-time (comparable to `docker run`)
- Policy evaluation < 1μs (SRR + ABAC, Criterion benchmark)
- WAL with Merkle chain, size-based rotation (100MB x 10 segments). Local storage — bring your own retention (S3, GCS, etc)
- 329 tests, 60-min chaos stress test (proxy kill, network partition, disk pressure) — [PASS](docs/test-report.md#910-chaos-stress-test-60-minutes)
- seccomp-BPF with ~130 whitelisted syscalls, ENOSYS default for unknown
- All data stays local. No telemetry, no phone-home.

---

## Requirements

- **Sandbox mode** (recommended for production): Linux only. Requires `iproute2` (`ip`), `iptables`, and `ip6tables` on the host (preinstalled on most server distros). Either run as `sudo` or grant capabilities: `sudo setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace+ep' ./gvm`. Run `gvm preflight` to check what's available.
- **Cooperative / watch modes**: any OS — Linux, macOS, Windows. No system tools required beyond the agent's own runtime (Python, Node, etc.).
- **Pre-built binary**: Linux x86_64 / glibc (Ubuntu 20.04+, Debian 11+, RHEL 8+, Amazon Linux 2023). On macOS or Windows, build from source with `cargo build --release`.
- **`--contained` mode** (experimental): Docker on the host instead of the kernel features above.

## Quick Start

```bash
# Option 1: Pre-built binary (glibc Linux x86_64)
curl -L https://github.com/skwuwu/Analemma-GVM/releases/latest/download/gvm-linux-x86_64.tar.gz | tar xz

# Option 2: Build from source
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release

# Verify your environment
./gvm preflight
```

```bash
# Production: sandbox mode (Linux)
gvm run --sandbox my_agent.py

# Quick run: cooperative mode (any OS)
gvm run my_agent.py
```

[Quick Start →](docs/quickstart.md)

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
- Feedback on technical and structural issues or bug reports is always welcome!

v0.4 pre-release. Apache 2.0. [Issues →](https://github.com/skwuwu/Analemma-GVM/issues)
