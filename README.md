# Analemma-GVM: Permission-Grant Runtime for AI Agents

**Bound the actions. Sign the evidence. Stay framework-independent.**

GVM gives an AI agent a **time-bounded set of permissions** for a specific task, enforces those permissions at the HTTP / filesystem / syscall boundary, and produces a Merkle-chained, Ed25519-signed evidence trail an external auditor can verify offline. Two small Rust binaries (CLI + proxy, ~35 MB on Linux). No Kubernetes, no service mesh, no GPU, no SDK to import.

GVM does **not** make the model trustworthy. It makes the model's actions **bounded, auditable, and revocable** — the framing regulated environments (claim review, internal coding agents, on-prem document workflows, sovereign AI deployments) need before turning autonomy on. Think of it less as a sandbox and more as **`docker run` for agent permissions, with a court-grade audit trail attached.**

Four things you get out of the box:

1. **Bound actions** — every outbound HTTP call, filesystem write, and DNS query is gated by a policy. Default-to-Caution on anything unrecognised; Deny / RequireApproval / Delay / Allow / AuditOnly as the five effects.
2. **Signed evidence** — every decision lands in a Merkle-chained WAL with an Ed25519 anchor signature. `gvm proof event` / `gvm proof batch` exports a self-contained JSON bundle; `gvm proof verify` runs offline against just the public anchor key.
3. **Framework-independent** — your agent isn't modified. Plain `requests`, `urllib`, `node-fetch`, `curl`, LangChain, hermes-agent, OpenClaw all work unchanged — governance sits at the proxy and kernel layer, not in your code.
4. **Zero-code-change cooperative path on any OS** + **kernel-enforced sandbox path on Linux** — same rules, two enforcement strengths, pick per environment.

What it is **not**: a prompt filter (use Lakera or provider safety for that), an LLM safety solution (it doesn't change what the model says — it bounds what the model can *do*), or a replacement for OPA (OPA governs service-to-service; GVM governs agent-to-world).

## Demo — Watch, Suggest, Enforce in 3 commands

![GVM demo: watch → suggest → enforce](docs/assets/gvm-demo.gif)

*33-second GIF, rendered from [`docs/assets/gvm-demo.cast`](docs/assets/gvm-demo.cast).
Replay interactively with `asciinema play docs/assets/gvm-demo.cast`.*

The demo runs on a real Ubuntu 24.04 host. Agent code is not changed between steps — only the rules and flags differ.

### What you see in the GIF, second by second

1. **0:00 – 0:07 — Watch mode boots.** The operator runs
   `gvm run --watch demo_agent.py`. GVM prints "Watch Mode (observation
   only)" and forwards every request the agent makes to its real
   destination — no rules exist yet, nothing is blocked. Each call is
   labelled `Allow` and recorded as a structured event in the WAL audit
   log.
2. **0:07 – 0:19 — Agent traffic streams past.** The demo agent makes
   a handful of HTTP calls (GitHub API, Anthropic API, an unknown
   internal host). They show up live in the watch terminal with their
   method, host, path, and decision. At the end GVM hints what to run
   next: `gvm run --interactive` to learn rules interactively, or
   `gvm run --sandbox` to add Linux-kernel isolation on top.
3. **0:19 – 0:29 — `gvm suggest` turns the recording into rules.**
   The operator runs `gvm suggest --from data/wal.log` and GVM emits
   TOML rules — one `[[rules]]` block per host pattern that appeared
   in the watch session, each with `decision = { type = "Allow" }`.
   These get appended to the agent's rule file and become the
   ground-truth for what this agent is allowed to do.
4. **0:29 – 0:33 — Enforce mode catches the new behaviour.** The
   operator re-runs the agent under the freshly suggested rules. The
   previously-seen calls pass instantly. A *new* URL the agent didn't
   touch during watch (`api.demo:9999` — represents an exfiltration
   attempt or a behaviour change) hits Default-to-Caution: marked
   `Delay { milliseconds: 300 }`, recorded with a full causal trace
   ID. The audit log now has a verifiable record of "agent tried
   something not in its known surface."

The point of the demo: governance for an existing agent costs three
commands and zero code changes. Watch records what the agent does,
suggest turns that into rules, enforce makes those rules binding —
and any future drift away from that surface is flagged in the audit
log on the first request.

---

## The enforcement boundary — what `gvm run --sandbox` actually contains

`--sandbox` is the **execution boundary** — one command activates four enforcement layers below. Linux-only (needs namespaces, iptables, seccomp-BPF). The complementary **evidence boundary** (signed WAL + `gvm proof verify`) is described in the next section and ships in all modes including the cooperative no-sudo path.

**DNS governance (Layer 0)** — Every DNS query passes through a built-in governance proxy before any HTTP call happens. Known domains (learned via `gvm suggest`) resolve instantly. Unknown domains are delayed 200ms. Repeated anomalous patterns (e.g. subdomain burst — a DNS tunneling signature) escalate to 3–10 second delays with alerts. No DNS query is ever denied — worst case is a delay, never an outage. Disable with `--no-dns-governance` if you already use dedicated DNS security tools.

**Network governance (Layer 1)** — Every outbound HTTP/HTTPS call goes through the GVM proxy. Calls that match your ruleset pass through; unknown calls are delayed or denied. The agent cannot bypass the proxy — even if it unsets env vars or opens raw sockets, kernel-level iptables DNAT redirects all traffic through GVM.

| Decision | What happens | Example |
|----------|-------------|---------|
| **Allow** | Pass through, async audit | `GET api.github.com/repos` |
| **AuditOnly** | Allow + synchronous WAL write before forwarding | High-value read on a sensitive endpoint |
| **Delay** | Audit first, then forward | Unknown host, first time seen |
| **RequireApproval** | Hold until human approves | `POST api.stripe.com/charges` |
| **Deny** | Block immediately | `DELETE production-db/users` |

**Filesystem governance (Layer 2)** — The agent works on an overlayfs layer, not the real host filesystem. Nothing lands on disk until a human reviews and approves via `gvm fs approve`.

**Credential isolation** — When the agent calls a governed API, GVM strips whatever credentials the agent sends and injects the real keys post-enforcement. The agent never needs to hold those API keys. (LLM provider keys that the agent needs for its own reasoning are passed through — stripping them would stop the agent from functioning.)

**Syscall filtering** — seccomp-BPF restricts the agent to ~130 whitelisted syscalls. This prevents the agent from modifying iptables rules (no `AF_NETLINK`) or opening raw sockets (no `AF_PACKET`), ensuring the network layer above can't be tampered with.

These aren't separate features you configure individually. They're layers of a single sandbox runtime, all activated by `--sandbox`.

---

## The evidence boundary — what `gvm proof` produces

The Merkle-chained WAL and the `gvm proof` CLI are the audit-grade evidence side of GVM and ship in **every mode** (cooperative, sandbox, contained). The audit trail is what makes "the agent ran" defensible to a regulator or an internal compliance team — not just a log file you have to trust.

**What's in the WAL.** Every governance decision is appended as a JSON event with: agent identity, token id, operation, resource descriptor, decision, matched rule id, request/response classification, integrity context (policy + config hash chain), and a SHA-256 event hash. Batches of events are sealed into a Merkle tree; the batch root is signed with an Ed25519 key whose public half is published as the anchor. WAL segments rotate at 100 MB × 10 by default.

**What `gvm proof` exports.** A self-contained JSON bundle with the event (full or redacted), its Merkle inclusion path to the batch root, the BatchSealRecord, the config integrity context, and the Ed25519 anchor signature.

```bash
gvm proof event   <event_id>   --wal data/wal.log   > evt.json
gvm proof batch   <batch_id>   --wal data/wal.log   > batch.json
gvm proof verify  evt.json     --anchor anchor.pub             # offline
```

Verify runs **offline against just the anchor public key** — the auditor doesn't need access to the host, the WAL, or the operator's signing material. A tamper-evident chain (not tamper-*proof*: a host-root attacker can still mutate local files, but any mutation breaks the chain at the next verify) covers events, batches, and the cross-rotation anchor history.

**Where the signing key lives.** The Ed25519 anchor key is generated by `gvm anchor keygen` and is **operator-managed by default**. Hooks for KMS / HSM backed signing and external timestamp authorities (RFC 3161) are scoped for v0.7+; the current default delivers customer-verifiable evidence inside a customer-managed-key model.

---

## The three-step workflow

You don't need to write rules by hand. Watch what your agent does, let GVM generate rules, then enforce them.

```bash
# 1. Watch — observe every API call, no blocking
sudo gvm run --sandbox --watch agent.py

# 2. Suggest — turn the recorded session into rules
gvm suggest --from session.jsonl >> gvm.toml

# 3. Enforce — apply those rules
sudo gvm run --sandbox agent.py
```

After step 3, known URLs pass instantly. A new URL the agent tries to call — one that wasn't in the watch session — hits Default-to-Caution and gets delayed, flagged in the audit trail.

`--sandbox` requires `sudo` because it sets up user/PID/mount/network namespaces, iptables DNAT, and a per-sandbox MITM CA. The proxy itself drops back to the original (`SUDO_UID`) user once those primitives are in place; only the kernel-isolation setup phase needs root.

You can also discover rules interactively: `sudo gvm run -i --sandbox agent.py` enforces and then prompts you to create rules for any unknown hosts on exit.

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

## For orchestrators — issue a grant, watch decisions, mutate policy

GVM is designed to sit underneath an external orchestrator (your own scheduler, a workflow engine, an MCP server, an internal portal) that decides *which agent gets which capability for how long*. The orchestrator owns the policy decision; GVM owns the enforcement and the evidence.

A typical orchestrated workflow today (v0.5.3):

```bash
# 1. Operator (or orchestrator) writes a task-scoped SRR ruleset
#    Per-agent ruleset under config/<agent-id>/srr_network.toml; hot-reloaded.
gvm reload                                # atomic ruleset swap, all in-flight requests use new rules

# 2. Launch the agent under the scoped permissions
sudo gvm run --sandbox --agent-id claims-reviewer-1842 ./agent

# 3. Operator monitors via the admin port (separate from the agent-facing proxy)
gvm approve                               # polls pending RequireApproval events, prompts to decide
gvm events list --agent claims-reviewer-1842 --last 1h

# 4. After the run, package the evidence
gvm proof batch <batch_id> --wal data/wal.log > claims-1842-evidence.json
```

**On the v0.7 roadmap** (see [CHANGELOG.md](docs/internal/CHANGELOG.md) for status): a push-based `GET /gvm/events` WAL stream subscription, granular `POST /gvm/srr/rule` / `DELETE /gvm/srr/rule/<id>` single-rule mutations, and `expires_at` on rules. The three compose into the **time-bounded permission grant pattern** — orchestrator inserts an `Allow` rule with a 5-minute TTL after approving an IC-3 request, agent's next N calls in that window pass without re-prompting, the rule auto-expires.

This is the position GVM aims for: not a sandbox you wrap an agent in, but a **runtime an orchestrator can drive** — the way Docker is a runtime Kubernetes drives. The operational primitive is the **task-scoped grant**, not the container.

---

## What it doesn't do

- **Not a prompt filter.** Use Lakera or provider safety for that. GVM governs actions, not words.
- **Not a substitute for the model's own safety.** GVM does not stop the model from being wrong; it limits the blast radius when the model is wrong.
- **Complementary to OPA, not a replacement.** OPA governs service-to-service. GVM governs agent-to-world. They compose: deploy OPA at your API edge AND GVM around your agent.

| | LLM Provider Safety | Prompt Guards (Lakera) | **GVM** |
|---|---|---|---|
| **Controls** | Model output content | Model input/output | **Agent actions (HTTP calls)** |
| **Enforcement** | Inside the model | Before/after model | **Between agent and APIs** |
| **Audit** | Provider logs (you don't own) | Prompt logs | **Merkle WAL (you own)** |

[Full analysis →](docs/security-layers.md)

---

## Technical facts

- Rust, two binaries totaling ~35MB on Linux x86_64 (gvm 17MB + gvm-proxy 18MB; ~29MB on Windows). Measured on `cargo build --release` of commit at the time of writing — anchor signing (`ed25519-dalek`) and CLI runtime deps account for the bulk.
- gvm-proxy RSS: ~14MB idle, ~17MB after a sustained `httpbin.org` workload (measured on EC2 t3.medium)
- Per-request MITM overhead — reported as the **delta vs a direct curl from the same host on the same run**, since the absolute timings are dominated by upstream RTT, not by GVM (n=20 fresh-TLS curl, EC2 Seoul → US, medians):

  | Upstream | Δ vs direct (median) | Notes |
  |----------|----------------------|-------|
  | `httpbin.org` (HTTP/1.1) | **~0 ms** (warm pool, 19/20 reuses) | the first request pays one TCP+TLS+HTTP/1.1 handshake; subsequent requests within 30 s reuse the cached upstream connection |
  | Anthropic API `claude-haiku-4-5` ("hi", 16 tokens) | **+28 ms** | HTTP/2 — hyper internally multiplexes per-stream over a single connection so handshake amortises natively |

  Plain `curl --no-keepalive` against an HTTP/1.1 endpoint without the upstream pool used to be the worst case at +215 ms (cooperative) / +528 ms (sandbox + DNS gov); the [bounded LIFO upstream pool](src/upstream_pool.rs) landed 2026-05-08 brings that delta to ~0 ms once the pool is warm.

- Full sandbox path on `httpbin.org` (MITM + iptables DNAT + DNS Tier-2 governance, with pool warm): **~0 ms** MITM contribution + ~95–295 ms sandbox+DNS-gov contribution depending on whether the agent's first request has hit the 200 ms Tier-2 delay yet. Pre-classify hot domains via `gvm suggest` to move them to Tier 1 (no DNS delay).

- ([raw bench, 2026-05-08](docs/test-report.md#http-overhead--layered-measurement) — pre-pool baseline kept for context)

- Sandbox cold start: **876ms median** (832-881ms range, n=5) — comparable to `docker run`.
- 10-parallel concurrent `httpbin.org`: 1104 ms direct vs 1269 ms via proxy = **+165 ms median**.
- Policy evaluation < 1μs (SRR, Criterion benchmark)
- WAL with Merkle chain + optional Ed25519 anchor signing (run `gvm anchor keygen` to generate the operator-managed keypair, set `[anchor] enabled = true`). Size-based rotation (100MB x 10 segments by default). Local storage — for off-host audit replication, tail the WAL with rsync / fluentd / vector / S3 backup.
- Cross-platform CI (Linux + Windows + macOS), `cargo fmt` + `cargo clippy --workspace -- -D warnings` clean on every push. 30-min chaos stress test (proxy kill, network partition, disk pressure) — [PASS](docs/test-report.md#hermes-agent-validation-2026-04-15-ec2-t3medium)
- Tested with [OpenClaw](https://github.com/openclaw/openclaw) and [hermes-agent](https://github.com/NousResearch/hermes-agent) — GVM is framework-independent; any agent that makes HTTP calls is governed
- seccomp-BPF with ~130 whitelisted syscalls, ENOSYS default for unknown
- All data stays local. No telemetry, no phone-home.

---

## Requirements

- **Sandbox mode** (recommended for production): Linux only. Requires `iproute2` (`ip`), `iptables`, and `ip6tables` on the host (preinstalled on most server distros). Either run as `sudo` or grant capabilities: `sudo setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace+ep' ./gvm`. Run `gvm preflight` to check what's available.
- **Cooperative / watch modes**: any OS — Linux, macOS, Windows. No system tools required beyond the agent's own runtime (Python, Node, etc.).
- **Pre-built binary**: Linux x86_64 / glibc (Ubuntu 20.04+, Debian 11+, RHEL 8+, Amazon Linux 2023). On macOS or Windows, build from source with `cargo build --release`.
- **Zero client-side library required.** Plain `requests`, `urllib`, `node-fetch`, `curl`, anything that talks HTTP/HTTPS works unmodified — governance is enforced at the proxy.
- **`--contained` mode** (Docker isolation, unfinished): gated behind `cargo build --features contained` and **not** in the default binary. Default `gvm run --help` does not advertise it. For HTTPS L7 inspection on Linux use `--sandbox` instead.

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
# Production: sandbox mode (Linux, root required for namespace + iptables setup)
sudo gvm run --sandbox my_agent.py

# Quick run: cooperative mode (any OS, no sudo)
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

v0.5.3. Apache 2.0. [Issues →](https://github.com/skwuwu/Analemma-GVM/issues)
