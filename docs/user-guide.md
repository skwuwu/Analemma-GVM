# GVM User Guide

## Quick Start — 3 Steps

You don't need to write rules. GVM learns from your agent's traffic and suggests them.

```bash
# 1. Watch — see what your agent calls (no rules needed)
gvm watch my_agent.py

# 2. Suggest — auto-generate rules from the audit log
gvm suggest --from data/wal.log > config/srr_network.toml

# 3. Run — enforce the generated rules
gvm run my_agent.py
```

Step 1 records every API call to the audit log (`data/wal.log`). Step 2 reads that log and generates Allow rules for every URL that was seen. Step 3 enforces those rules — anything not in the list gets delayed and flagged.

That's the entire workflow. Everything below is optional — use it when you need it.

> **First time on a fresh checkout?** Run `gvm init --industry saas` (or `--industry finance`) to drop a starter `config/` directory with sensible SRR rules, a `proxy.toml`, and an empty `secrets.toml`. Skip this if you already have a `config/` directory you want to keep.

---

## Level 1: Basic — Run and Watch

### `gvm run`

```bash
gvm run my_agent.py                    # Python
gvm run -- node my_agent.js            # Node.js
gvm run -- openclaw gateway            # Any binary
```

Output:
```
  GVM Audit Trail — 5 events
    ✓ Allow    GET  api.github.com
    ⏱ Delay    POST slack.com
    ✗ Deny     POST api.bank.com
  3 allowed  1 delayed  1 blocked
```

If a URL has no matching rule, GVM applies **Default-to-Caution**: delays the request 300ms and logs it. Nothing is silently allowed.

### `gvm watch`

```bash
gvm watch my_agent.py                  # Observe all traffic (no blocking)
gvm watch --with-rules my_agent.py     # Observe with existing rules active
```

Shows every request in real-time:
```
  14:23:01  ✓ POST  api.anthropic.com   /v1/messages       200  [1,234 tokens]
  14:23:05  ⏱ GET   catfact.ninja       /fact              200
```

At exit: host frequency, token cost estimate, unknown host warnings.

### `gvm run -i` (Interactive)

```bash
gvm run -i my_agent.py
```

After the agent finishes, GVM shows each unknown URL and asks whether to Allow or Deny:
```
  Unknown host: catfact.ninja (3 requests, GET /fact)
  (a)llow  (d)eny  (s)kip → a
  ✓ Rule added: catfact.ninja GET → Allow
```

Rules are written directly to `srr_network.toml`. No manual editing needed.

### `gvm suggest`

```bash
# After running gvm watch or gvm run, the audit log has all observed traffic:
gvm suggest --from data/wal.log > new-rules.toml

# Or from a JSON session log (for explicit capture):
gvm watch --output json my_agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
```

Reads the audit log (or a watch JSON log) and generates TOML rules for every URL that hit Default-to-Caution. Review the file, then merge into `config/srr_network.toml`.

---

## Level 2: Custom — Rules and Secrets

### SRR Rules (`config/srr_network.toml`)

URL pattern matching. No SDK needed.

```toml
# Allow GitHub reads
[[rules]]
pattern = "api.github.com"
path_regex = "^/repos/[^/]+/[^/]+/commits$"
method = "GET"
decision = { type = "Allow" }

# Block wire transfers
[[rules]]
pattern = "api.bank.com"
path_regex = "/transfer/.*"
method = "POST"
decision = { type = "Deny", reason = "Wire transfers blocked" }
```

**Patterns:** `"api.github.com"` (exact), `"api.github.com/{any}"` (host + any path), `"{any}"` (catch-all).

**Decisions:**

| Type | What happens |
|------|-------------|
| `Allow` | Pass immediately |
| `Delay { milliseconds: 300 }` | Pause then pass |
| `Deny { reason: "..." }` | Block with 403 |
| `RequireApproval` | Hold for human approval (clear the queue with `gvm approve`) |
| `Throttle { max_per_minute: 10 }` | Rate limit |
| `AuditOnly` | Pass but flag |

**Hot-reload:** Edit the file → `gvm reload`. No restart needed.

**Rule order matters:** SRR uses **first-match** — rules are evaluated in file order and the first matching rule wins. Place specific rules (e.g., `api.bank.com/transfer/{any} → Deny`) before catch-all rules (`{any} → Allow`). A catch-all before a specific rule makes the specific rule unreachable.

**Query strings:** Stripped automatically. `^/commits$` matches `/commits?per_page=5`.

> **Tip:** Don't write rules by hand. Use `gvm watch` + `gvm suggest` to generate them, then edit as needed.

### Credential Injection (`config/secrets.toml`)

```toml
[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_live_your_stripe_key"

[credentials."api.sendgrid.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.your_sendgrid_key"
```

| Agent code | secrets.toml has host? | Result |
|------------|----------------------|--------|
| No auth header | Yes | Proxy injects key |
| Own auth header | Yes | Proxy **replaces** with managed key |
| Own auth header | No | Agent's key passes through |
| No auth header | No | Sent without auth |

Existing agents with hardcoded keys work immediately — no code changes. When ready, move keys to `secrets.toml` for centralized management.

> **Scope:** HTTP headers only. LLM SDKs require keys at initialization — use `ANTHROPIC_API_KEY` env var for that. Credential injection is for tool API calls (Stripe, Slack, GitHub, etc.).

### `gvm approve` — Human-in-the-Loop Approvals

When an SRR rule decides `RequireApproval`, the proxy holds the request and queues it on the admin port (`/gvm/pending`). The agent's HTTP call blocks until either (a) `gvm approve` delivers a decision or (b) `ic3_approval_timeout_secs` (default 5 min) elapses and the request is auto-denied with 503.

**`gvm approve` is the only supported channel for human approval.** Run it in a separate terminal (or tmux pane, or systemd `Type=simple` service) from `gvm run`:

```bash
gvm approve                       # interactive prompt: y/n per pending request
gvm approve --auto-deny           # CI-friendly: deny everything still pending
gvm approve --admin http://127.0.0.1:9090   # custom admin port
```

The interactive prompt shows the agent ID, target host, method, and operation for each held request, then waits for `y`/`n`. Hit `Ctrl-C` to leave the rest of the queue alone — already-displayed decisions are still applied. Pair this with `RequireApproval` rules for high-risk endpoints (wire transfers, deletes, prod-only mutations).

> **Why a separate terminal?** Earlier versions of `gvm run` interleaved approval prompts with the agent's stdout in the same terminal. That fought for stdin against the running agent and produced confusing output. The current design has one channel: `gvm approve` reads pending from the admin port and writes the decision back, regardless of where `gvm run` is running.

### `gvm check` — Dry-Run Policy Test

```bash
gvm check --operation gvm.payment.charge --host api.bank.com --method POST
```

Output: decision, matched rule, decision path, engine latency. Use in CI to validate policy changes before deployment.

---

## Level 3: Enterprise — Isolation and Compliance

### Pre-flight Check

Before using sandbox mode for the first time, verify your environment:

```bash
gvm preflight
```

Shows which kernel features, tools, and configs are available, and which GVM modes your machine supports. Example output on Linux:

```
  Environment Check

  ✓ Proxy config              config/proxy.toml
  ✓ SRR rules                 47 rules loaded
  ✓ Credentials               3 hosts configured
  ✓ User namespaces           enabled
  ✓ seccomp-BPF               supported
  ✓ CAP_NET_ADMIN             available (run with sudo)
  ✓ iptables                  /usr/sbin/iptables
  ✗ TC ingress filter         unavailable (iptables fallback active)

  Available Modes
  ✓ cooperative               gvm run agent.py
  ✓ sandbox                   sudo gvm run --sandbox agent.py
  ✓ sandbox + MITM            sudo gvm run --sandbox agent.py (HTTPS L7 inspection)
  ✗ sandbox + TC filter       kernel upgrade needed (iptables fallback active)
  ✓ watch                     gvm watch agent.py
  ✓ MCP                       gvm_fetch / gvm_check tools
```

On non-Linux (Windows/macOS), sandbox modes show as unavailable — use cooperative mode instead.

### Sandbox Mode

```bash
sudo gvm run --sandbox my_agent.py
```

Agent runs in an isolated environment where it cannot bypass the proxy. Linux only, requires sudo.

#### Combining sandbox with other modes

Isolation (`--sandbox` / `--contained` / cooperative default) and enforcement
(`--watch` / normal enforce / `-i` interactive) are **orthogonal axes**. Pick
one from each column and combine with the corresponding flags. Every
combination below is a real, supported workflow — not just hypothetical.

```bash
# Watch an untrusted third-party agent in full namespace isolation.
# Every URL it tries to hit is logged; nothing is blocked by rules; but
# the agent physically cannot reach anything except through the proxy,
# so it cannot phone home while you profile it.
sudo gvm run --watch --sandbox third_party_agent.py

# Discover rules for a brand-new agent, with sandbox isolation on from
# day one. On exit you get an interactive prompt to turn each
# Default-to-Caution hit into an explicit rule.
sudo gvm run -i --sandbox my_agent.py

# Normal production path: enforce existing rules, kernel isolation on.
# The default when the agent is "trusted enough to run, untrusted
# enough to isolate."
sudo gvm run --sandbox my_agent.py

# Cooperative watch for your own agent during development — fastest
# iteration, no sudo required. Acceptable because *you* wrote the
# HTTP client.
gvm run --watch my_agent.py
```

The full matrix:

| Isolation ↓  /  Enforcement → | **Watch** (`--watch`) | **Enforce** (none) | **Discover** (`-i`) |
|---|---|---|---|
| **Cooperative** (default) | `gvm run --watch a.py` | `gvm run a.py` | `gvm run -i a.py` |
| **Sandbox** (`--sandbox`) | `sudo gvm run --watch --sandbox a.py` | `sudo gvm run --sandbox a.py` | `sudo gvm run -i --sandbox a.py` |
| **Contained** (`--contained`, experimental) | `gvm run --watch --contained a.py` | `gvm run --contained a.py` | `gvm run -i --contained a.py` |

All twelve cells work. `--watch` and `-i` are mutually exclusive (watch means
"no rules," interactive means "suggest rules for caution hits" — one
requires the other to be off). `--sandbox` and `--contained` are mutually
exclusive (pick one isolation layer). Everything else composes freely.

```bash
--sandbox-timeout 300       # Kill after 5 minutes (default: 3600)
--sandbox-timeout 0         # No timeout (persistent agent)
--no-mitm                   # Disable HTTPS inspection
--memory 1g                 # Memory limit via cgroup v2 (omit = unlimited)
--cpus 0.5                  # CPU limit via cgroup v2 (omit = unlimited)
```

Resource limits are **opt-in**. Without `--memory` or `--cpus`, the agent runs with no cgroup restrictions (Docker-equivalent behavior). Use limits when running untrusted agents or enforcing resource budgets:

```bash
# Unlimited (default) — agent uses all available memory
gvm run --sandbox -- node agent.js

# Restrict to 1GB memory and half a CPU
gvm run --sandbox --memory 1g --cpus 0.5 -- node agent.js
```

> **Note:** Node.js ignores `HTTPS_PROXY`. Sandbox mode solves this — all HTTPS is intercepted regardless of the agent's behavior.

> **Proxy restart recovery:** The MITM CA is persisted to `data/mitm-ca.pem` and reused across proxy restarts, so TLS trust is preserved. However, if the proxy crashes or is restarted, running sandboxes may lose their TCP connections. The agent's HTTP client may not recover automatically. Restart the sandbox:
> ```bash
> gvm cleanup        # remove orphaned veth/iptables from crashed sandbox
> gvm run --sandbox --sandbox-timeout 0 -- node agent.js   # fresh start
> ```

### ABAC Policies (`config/policies/`) — Experimental

> Requires the Python SDK (`@ic` decorator), which is experimental. ABAC policies are evaluated only when the SDK injects operation metadata. For most use cases, SRR rules (Level 2) are sufficient.

Semantic rules that go beyond URL matching — evaluates operation type, data sensitivity, and agent identity.

```toml
# config/policies/global.toml
[[rules]]
id = "block-critical-delete"
priority = 1
layer = "Global"

[rules.match]
operation = { starts_with = "gvm.data.delete" }
[rules.match.context]
sensitivity = { equals = "Critical" }

[rules.decision]
type = "Deny"
reason = "Critical data deletion is forbidden"
```

Policy hierarchy: `global.toml` → `tenant-{name}.toml` → `agent-{id}.toml`. Lower layers can only be stricter.

### Shadow Mode

```bash
gvm run --shadow-mode strict -- node agent.js
```

| Mode | Undeclared request | Use case |
|------|-------------------|----------|
| `disabled` | Normal processing | Default |
| `observe` | Allow + audit warning | Testing |
| `strict` | Deny (403) | Production |

### Filesystem Governance

```bash
sudo gvm run --sandbox --fs-governance my_agent.py
```

Agent file changes are classified at session end:

| Change | Pattern | Action |
|--------|---------|--------|
| New file | `*.csv, *.pdf, *.txt` | Auto-merged |
| New file | `*.sh, *.py, *.json` | Review prompt |
| New file | `*.log, __pycache__/*` | Discarded |
| Modified file | (any) | Review prompt |
| Deleted file | (any) | Review prompt |

**TTY (interactive)**: at session end, GVM walks each `manual_commit` file and prompts `(a)ccept / (r)eject / (s)kip rest`. Accepted files are copied to the workspace; rejected files are deleted from staging; skipped files stay in `data/sandbox-staging/<pid>/` for later.

**CI / non-TTY**: GVM prints the staging path and exits without a prompt. Drain it later with `gvm fs approve`:

```bash
# Inspect what's pending across all sandbox sessions on this host
gvm fs approve --list

# Interactive review (single TTY) — same prompt as inline review
gvm fs approve

# CI: copy every staged file to its recorded workspace, then clean up
gvm fs approve --accept-all

# Cron / disk-leak garbage collector: delete every staging dir
gvm fs approve --reject-all
```

Each session writes a `manifest.json` sidecar in its staging dir recording the workspace destination, the agent ID, and per-file metadata, so `gvm fs approve` can drain batches even after the original sandbox process is gone. Without this command, staging directories grow indefinitely. Wire `gvm fs approve --reject-all` into a daily cron on hosts that run untrusted agents.

---

## Troubleshooting

### Agent Blocked (403)

```bash
gvm events list --agent my-agent --since 5m      # What happened?
gvm check --host api.bank.com --method POST       # Dry-run same request
# Fix: edit config/srr_network.toml → hot-reload
```

### Agent Delayed (300ms)

URL didn't match any rule — Default-to-Caution. Run `gvm watch` then `gvm suggest --from data/wal.log` to discover and add rules.

### Proxy Won't Start

```bash
cat data/proxy.log | tail -20    # Check logs
lsof -i :8080                    # Port conflict
sudo gvm run --sandbox ...       # Sandbox needs sudo
```

### Stopping the proxy

`gvm run` launches the proxy as a background daemon (PID file at `data/proxy.pid`). To shut it down cleanly:

```bash
gvm stop                         # graceful shutdown + sandbox cleanup
```

`gvm stop` flushes the WAL, releases sandbox host state (veth, iptables, mounts, cgroups), and removes the PID file. Use this instead of `kill <pid>` so the audit trail closes properly. On systemd-managed hosts (see [Production deployment](#production-deployment-mode-systemd)) use `systemctl stop gvm-sandbox@<agent>` instead — systemd reads its own state, not `data/proxy.pid`.

---

## CLI Reference

| Command | Purpose |
|---------|---------|
| `gvm init --industry <finance\|saas>` | Initialize a starter `config/` directory from a template |
| `gvm run [--sandbox] [--] <cmd>` | Run agent with governance |
| `gvm watch [--with-rules] [--] <cmd>` | Observe traffic without enforcement |
| `gvm run -i <cmd>` | Interactive rule suggestion |
| `gvm check --host H --method M` | Dry-run policy test |
| `gvm suggest --from F` | Generate rules from watch log |
| `gvm approve [--auto-deny]` | Drain the `RequireApproval` queue (interactive or CI) |
| `gvm events list` | Query audit trail |
| `gvm audit verify` | Check WAL integrity |
| `gvm stats tokens` | Token usage per agent |
| `gvm status` | Show proxy health, SRR rules, WAL state, sandboxes |
| `gvm reload` | Hot-reload SRR rules and policies |
| `gvm preflight` | Check environment and available modes |
| `gvm cleanup [--dry-run]` | Remove orphaned sandbox resources (veth, iptables, mounts, cgroups) |
| `gvm fs approve [--list\|--accept-all\|--reject-all]` | Drain pending overlayfs staging dirs (`--fs-governance`) |
| `gvm stop` | Gracefully stop the proxy daemon and release sandbox state |

Full flags: `gvm <command> --help`

---

## Running on a remote host (EC2, cloud VM, SSH)

Pick one of two modes depending on how long the agent needs to live:

| Use case | Use this |
|---|---|
| Interactive debugging, short-lived runs, quick stress tests | **tmux** |
| Long-running production agents, host reboot survival, auto-restart on crash | **systemd** (see [Production deployment](#production-deployment-mode-systemd)) |

Both modes use the same `gvm` binary. `gvm status` records the tmux
session name (when present) in the per-sandbox state file, so you
can mix the two on one host without losing track of which session
owns which sandbox.

### tmux (interactive)

```bash
ssh ec2-host
tmux new -s gvm
cd ~/Analemma-GVM
sudo gvm run --sandbox my_agent.py
# Ctrl-b d to detach, re-attach later with: tmux attach -t gvm
```

SSH disconnects, terminal glitches, and laptop lid closures all race
against `nohup`, and losing a long-running pipeline halfway through
leaves kernel state behind (veth, iptables, mount points, cgroups)
that `gvm cleanup` has to sweep on the next invocation. tmux
sidesteps the race entirely. The `gvm` CLI itself does not start or
depend on tmux — it just notices `$TMUX` and records it for
observability.

If a sandbox does end up orphaned (tmux killed mid-run, `gvm`
segfault, etc.), `gvm status` will tell you loudly:

```
  ⚠ 1 orphaned sandbox(es) detected
    PID is gone but kernel resources (veth, iptables, mounts, cgroup) are still held.
    Run: sudo gvm cleanup to release them.

  PID 12345 (dead)  veth-gvm-h-7  cleanup needed  [tmux: session 0]
```

## Production Checklist

- [ ] Remove `[dev] host_overrides` from proxy.toml
- [ ] Set `GVM_SECRETS_KEY` and `GVM_VAULT_KEY`
- [ ] Configure NATS for WAL replication (**critical for long-term audit retention** — without NATS, rotated WAL segments are permanently deleted after 1GB local storage)
- [ ] Set credential policy to `Deny` (not Passthrough)
- [ ] Enable `--shadow-mode strict`
- [ ] `chmod 600 config/secrets.toml`
- [ ] Review SRR: no catch-all Allow
- [ ] Set up `gvm stats` + `gvm audit verify` in cron
- [ ] Test with `gvm check` before deploying policy changes

## Production deployment mode (systemd)

GVM ships two systemd unit files in
[`packaging/systemd/`](../packaging/systemd/) that turn `gvm run --sandbox`
into a production-grade daemon. No code change is needed — they wrap
the existing CLI directly.

| File | Type | Purpose |
|---|---|---|
| `gvm-cleanup.service` | oneshot | Boot-time orphan sweep. Releases any veth / iptables / mount / cgroup state left behind by a sandbox that crashed before reboot. |
| `gvm-sandbox@.service` | template | Per-agent supervisor. Instance name `%i` selects which script under `/etc/gvm/agents/<name>.py` to launch. |

### Install

```bash
sudo install -m 0644 packaging/systemd/gvm-cleanup.service  /etc/systemd/system/
sudo install -m 0644 packaging/systemd/gvm-sandbox@.service /etc/systemd/system/
sudo install -m 0755 target/release/gvm /usr/local/bin/gvm

sudo mkdir -p /etc/gvm/agents
sudo cp my-agent.py /etc/gvm/agents/my-agent.py

sudo systemctl daemon-reload
sudo systemctl enable --now gvm-cleanup.service
sudo systemctl enable --now gvm-sandbox@my-agent.service
```

Verify and observe:

```bash
sudo systemctl status gvm-sandbox@my-agent.service
journalctl -u gvm-sandbox@my-agent.service -f
gvm status            # also lists systemd-launched sandboxes
```

### What the units actually do

```
boot
 │
 ├── network-pre.target
 ├── gvm-cleanup.service          (sweeps any pre-reboot orphans)
 ├── network.target
 ├── multi-user.target
 │     │
 │     └── gvm-sandbox@my-agent.service
 │           ExecStartPre=gvm cleanup     ← second sweep, defense in depth
 │           ExecStart=gvm run --sandbox  ← long-running
 │           on crash → SIGTERM → 30s grace → SIGKILL
 │           ExecStopPost=gvm cleanup     ← release whatever the run leaked
 │           Restart=on-failure (capped at 3 restarts/min)
```

This gives you:

- **Survives SSH disconnect.** `gvm run --sandbox` runs as a systemd
  service, not a tty child.
- **Survives host reboot.** `gvm-cleanup.service` clears any
  pre-reboot orphans before agents launch; the unit is enabled at
  boot.
- **Auto-restart on crash.** `Restart=on-failure` re-launches the
  agent, with a 3 restarts/60s burst cap so a wedged agent does not
  busy-loop the host. Clean exit (the agent finished normally) does
  not trigger a restart.
- **Centralized logs.** Agent stdout and stderr stream to journald,
  tagged with `gvm-sandbox-<agent>` so `journalctl -u gvm-sandbox@<agent>`
  Just Works.
- **Belt-and-suspenders cleanup.** `ExecStartPre`, `ExecStopPost`, and
  the boot-time oneshot all run `gvm cleanup`, so even a SIGKILL or
  power loss leaves no host state behind on the next boot.

### Per-agent overrides (drop-ins)

Use a drop-in instead of editing the shipped unit file:

```bash
sudo systemctl edit gvm-sandbox@my-agent.service
```

```ini
[Service]
# Use a script outside the default /etc/gvm/agents/ location
Environment=AgentScript=/srv/agents/my-agent/main.py

# Layer a systemd memory limit on top of GVM's --memory flag
MemoryMax=2G

# Per-agent timeout
Environment=GVM_SANDBOX_TIMEOUT=3600
```

### tmux vs systemd

| Capability | tmux | systemd |
|---|---|---|
| Survives SSH disconnect | ✅ | ✅ |
| Survives host reboot | ❌ | ✅ |
| Auto-restart on crash | ❌ | ✅ |
| Auto-cleanup on boot | ❌ | ✅ (via `gvm-cleanup.service`) |
| Centralized log aggregation | ❌ | ✅ (journald) |
| Single-command setup | ✅ | ❌ (one-time install) |
| Best for short interactive runs | ✅ | ❌ |

`gvm` itself behaves identically in both modes. The only difference
is who supervises the process — your tty (tmux) or PID 1 (systemd).
Mix freely on the same host: `gvm status` will show every sandbox
regardless of how it was launched, with the tmux session name on
the rows that have one.

### Uninstall

```bash
sudo systemctl disable --now gvm-sandbox@my-agent.service
sudo systemctl disable --now gvm-cleanup.service
sudo rm /etc/systemd/system/gvm-cleanup.service \
        /etc/systemd/system/gvm-sandbox@.service
sudo systemctl daemon-reload
sudo gvm cleanup    # final safety net
```

For the full lifecycle diagram, drop-in patterns, and the install
matrix, see [`packaging/systemd/README.md`](../packaging/systemd/README.md).

---

> **Under the hood:** [Architecture](overview.md) | [SRR Rules](srr.md) | [ABAC Policies](policy.md) | [Merkle WAL](architecture/ledger.md) | [Security Model](security-model.md) | [Governance Coverage](governance-coverage.md)
