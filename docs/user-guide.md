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
| `RequireApproval` | Hold for human approval |
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

TTY: interactive accept/reject per file. CI/CD: staged for `gvm fs approve`.

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

---

## CLI Reference

| Command | Purpose |
|---------|---------|
| `gvm run [--sandbox] [--] <cmd>` | Run agent with governance |
| `gvm watch [--with-rules] [--] <cmd>` | Observe traffic |
| `gvm run -i <cmd>` | Interactive rule suggestion |
| `gvm check --host H --method M` | Dry-run policy test |
| `gvm suggest --from F` | Generate rules from watch log |
| `gvm events list` | Query audit trail |
| `gvm audit verify` | Check WAL integrity |
| `gvm stats tokens` | Token usage per agent |
| `gvm status` | Show proxy health, SRR rules, WAL state |
| `gvm reload` | Hot-reload SRR rules and policies |
| `gvm preflight` | Check environment and available modes |
| `gvm cleanup` | Remove orphaned sandbox resources |
| `gvm init --industry I` | Initialize config templates |

Full flags: `gvm <command> --help`

---

## Running on a remote host (EC2, cloud VM, SSH)

When you run `gvm run`, a stress test, or any multi-minute command
against a remote host, **host it inside a `tmux` session**. SSH
disconnects, terminal glitches, and laptop lid closures all race
against `nohup`, and losing a long-running pipeline halfway through
leaves kernel state behind (`tc netem` rules, `/run/gvm/` staging
dirs, orphan `gvm-proxy` processes) that `gvm cleanup` has to sweep
on the next invocation. `tmux` sidesteps the race entirely.

```bash
ssh ec2-host
tmux new -s gvm
cd ~/Analemma-GVM
sudo bash scripts/stress-test.sh --duration 60
# Ctrl-b d to detach, re-attach later with: tmux attach -t gvm
```

This is a recommendation for operators; the `gvm` CLI itself does
not start or depend on tmux.

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

## Production deployment mode

`gvm run` already launches `gvm-proxy` as a background daemon
(`setsid` + PID file + health check), so the short-term "run the
proxy and let it survive terminal exit" story is covered. For
a real production deployment you usually want one more layer:
a service supervisor that restarts the proxy on crash, forwards
its logs to the host's log aggregator, and boots it at system
start. GVM does not ship its own service unit yet, but a minimal
systemd drop-in is straightforward:

```ini
# /etc/systemd/system/gvm-proxy.service
[Unit]
Description=Analemma GVM Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gvm-proxy
WorkingDirectory=/var/lib/gvm
User=gvm
Group=gvm
# Needs CAP_NET_ADMIN for veth/iptables in --sandbox; drop if you
# only run cooperative mode.
AmbientCapabilities=CAP_NET_ADMIN
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
# Proxy listens on 8080 by default; expose via reverse proxy if
# you want TLS termination in front of it.

[Install]
WantedBy=multi-user.target
```

Known gaps when running under systemd today:
- `gvm stop` reads `data/proxy.pid`, which systemd doesn't use; use
  `systemctl stop gvm-proxy` instead on systemd-managed hosts.
- `gvm status` queries the proxy's HTTP health endpoint and is
  independent of the supervisor, so it keeps working under either
  model.
- Log rotation is delegated to journald/journalctl; the proxy's
  own `data/proxy.log` is a no-op under systemd (stdout/stderr go
  to the journal instead).
- The sandbox mode's kernel resources (veth, iptables, cgroups) are
  cleaned up by the per-sandbox lifecycle handlers regardless of
  supervisor. `/run/gvm/` state survives reboot because it's tmpfs.

Pick the systemd path when you need unattended restart on crash,
boot-time start, and centralised log ingestion. Stick with
`gvm run`'s built-in daemon for single-host dev/demo environments.

---

> **Under the hood:** [Architecture](overview.md) | [SRR Rules](srr.md) | [ABAC Policies](policy.md) | [Merkle WAL](architecture/ledger.md) | [Security Model](security-model.md) | [Governance Coverage](governance-coverage.md)
