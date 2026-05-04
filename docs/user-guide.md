# GVM User Guide

## Quick Start — 3 Steps

You don't need to write rules. GVM learns from your agent's traffic and suggests them.

```bash
# 1. Watch — see what your agent calls (no rules needed)
gvm watch my_agent.py

# 2. Suggest — auto-generate rules from the audit log
gvm suggest --from data/wal.log >> gvm.toml

# 3. Run — enforce the generated rules
gvm run my_agent.py
```

Step 1 records every API call to the audit log (`data/wal.log`). Step 2 reads that log and generates Allow rules for every URL that was seen. Step 3 enforces those rules — anything not in the list gets delayed and flagged.

That's the entire workflow. Everything below is optional — use it when you need it.

> **First time on a fresh checkout?** Run `gvm init --industry saas` (or `--industry finance`) to drop a starter `gvm.toml` (unified config: rules + credentials + budget + filesystem + seccomp). Skip this if you already have a config you want to keep.

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

Rules are appended directly to `gvm.toml`. No manual editing needed.

### `gvm suggest`

```bash
# After running `gvm run` or `gvm watch`, the WAL has every observed
# request (Allow/Delay/Deny all persist). Point suggest at it:
gvm suggest --from data/wal.log > new-rules.toml

# Equivalent alternative — capture the watch stream to a JSON file:
gvm watch --output json my_agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
```

Reads the audit log (WAL or watch session JSON) and emits an SRR rule for every URL seen. Merge into `gvm.toml` after review.

> Earlier versions of GVM skipped `Allow` decisions from the WAL, so `gvm suggest --from wal.log` only produced rules for `Default-to-Caution` hits. All governance decisions now persist durably; the WAL is the single source of truth for suggest.

---

## Level 2: Custom — Rules and Secrets

### SRR Rules (`gvm.toml` — `[[rules]]`)

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
| `AuditOnly` | Pass but force synchronous WAL write |
| `Delay { milliseconds: 300 }` | Pause then pass |
| `RequireApproval` | Hold for human approval (clear the queue with `gvm approve`) |
| `Deny { reason: "..." }` | Block with 403 |

Strictness order: `Allow (0) < AuditOnly (1) < Delay (2) < RequireApproval (3) < Deny (4)`. When multiple rules match, the strictest wins.

**Hot-reload:** Edit the file → `gvm reload`. No restart needed.

**Rule order matters:** SRR uses **first-match** — rules are evaluated in file order and the first matching rule wins. Place specific rules (e.g., `api.bank.com/transfer/{any} → Deny`) before catch-all rules (`{any} → Allow`). A catch-all before a specific rule makes the specific rule unreachable.

**Host + port precedence (Normalize then Match):** patterns are normalized before matching — default ports (`:80`, `:443`) are stripped, so `api.demo:443` and `api.demo` are the same pattern. Non-default ports are preserved. A pattern *with* an explicit non-default port (`api.demo:9999`) only matches requests to that exact port; a pattern *without* a port (`api.demo`) matches any port on that host. When both exist, first-match in file order still decides — put the port-qualified rule **above** the bare-host rule, otherwise the bare-host rule swallows every port first and the `:9999` rule is unreachable:

```toml
# Correct: specific port first
[[rules]]
pattern = "api.demo:9999"
decision = { type = "Deny", reason = "Admin port blocked" }

[[rules]]
pattern = "api.demo"
decision = { type = "Allow" }
```

**Query strings:** Stripped automatically. `^/commits$` matches `/commits?per_page=5`.

> **Tip:** Don't write rules by hand. Use `gvm watch` + `gvm suggest` to generate them, then edit as needed.

### Credential Injection (`gvm.toml` — `[credentials.*]`)

```toml
[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_live_your_stripe_key"

[credentials."api.sendgrid.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.your_sendgrid_key"
```

| Agent code | gvm.toml has host? | Result |
|------------|-------------------|--------|
| No auth header | Yes | Proxy injects key |
| Own auth header | Yes | Proxy **replaces** with managed key |
| Own auth header | No | Agent's key passes through |
| No auth header | No | Sent without auth |

Existing agents with hardcoded keys work immediately — no code changes. When ready, move keys to `gvm.toml` for centralized management. File permissions must be `0600` (checked at load).

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

**File ownership under `sudo`:** the proxy daemon drops privileges back to `SUDO_UID:SUDO_GID` on launch, so everything it writes (`data/wal.log`, `data/proxy.pid`, `data/proxy.log`, the MITM CA) stays owned by your normal user — you can `tail`, `cat`, and `rm` them without `sudo`. The **sandbox child itself** still runs as root inside its user namespace (uid 0 → host root), so files the *agent* creates inside `/workspace` end up root-owned on the host. If you pull those files out via `--fs-governance` or by copying from the staging dir, `chown` them back to your user before editing. Plain `data/` is never root-owned.

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
| **Contained** (`--contained`, Linux/WSL2) | `gvm run --watch --contained a.py` | `gvm run --contained a.py` | `gvm run -i --contained a.py` |

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

> **Proxy restart breaks TLS trust (CA-5):** Since CA-5 the MITM CA is held in proxy memory only — there is no `data/mitm-ca.pem` on disk. A restarted proxy mints a fresh keypair, so any sandbox still trusting the previous CA will fail TLS. The mitigation is a relaunch:
> ```bash
> gvm cleanup        # remove orphaned veth/iptables from the dead sandbox
> gvm run --sandbox --sandbox-timeout 0 -- node agent.js   # fresh CA injected
> ```
> This is intentional. Persisting a shared CA's private key to host disk was the larger security risk — anyone who could read `data/mitm-ca-key.pem` could forge any TLS identity until cert expiry. Per-sandbox CAs (provisioned via `POST /gvm/sandbox/launch`, CA-3) restore restart resilience by binding the trust to a single sandbox lifetime.

### Running multiple agents

GVM is designed for **N agents inside a single organization**, sharing one proxy and one ruleset. Spin up the proxy once, then launch each agent in its own session with a unique `--agent-id`:

```bash
# In separate terminals (or backgrounded jobs):
gvm run --agent-id agent-analyst   --sandbox -- python analyst.py
gvm run --agent-id agent-coder-1   --sandbox -- node coder.js
gvm run --agent-id agent-coder-2   --sandbox -- python coder2.py
```

**Always pass a unique `--agent-id`** — the default (`"agent-001"`) makes every agent share the same identity, which collapses per-agent budget isolation and audit attribution. There is no automatic uniqueness check; the burden is on you.

**What is isolated per agent_id**:

| Resource | Mechanism |
|---|---|
| Token + cost budget | `PerAgentBudgets` — agent A draining its quota does not block agent B |
| Audit trace | every event in the WAL carries `agent_id`; `gvm events list --agent <id>` filters |
| Sandbox namespace | `clone(CLONE_NEWUSER\|NEWPID\|NEWNS\|NEWNET)` per launch |
| MITM CA + leaf cert cache | per-sandbox CA when the launcher provisions via `POST /gvm/sandbox/launch` (CA-3) |
| veth subnet + iptables FORWARD chain | per-sandbox PID |

**What is shared (organization-wide)**:

- SRR ruleset — single source of truth; agent-specific rules are not supported (intentional, see CLAUDE.md "Code Reuse & Anti-Fragmentation")
- WAL Merkle chain — one append-only log for the whole organization, with per-agent filtering at query time
- Vault credentials — secrets are scoped to the organization, not the agent
- JWT signing secret — every agent's token is signed with the same key, only the `sub` claim differs

**Per-agent quota config** (`gvm.toml`):

```toml
[budget]
# Organization-wide ceiling (sum of all agents)
max_tokens_per_hour     = 1_000_000
max_cost_per_hour       = 100.0
reserve_per_request     = 500

# Per-agent ceiling. 0 = disabled.
# Agent A exhausting its share does not affect agent B.
per_agent_max_tokens_per_hour = 100_000
per_agent_max_cost_per_hour   = 10.0
```

**Identity verification (JWT)**: header-based `X-GVM-Agent-Id` is **spoofable** — any agent can claim to be any agent_id. To prevent this, enable JWT:

```toml
[jwt]
secret_env      = "GVM_JWT_SECRET"   # 32+ byte hex string
token_ttl_secs  = 3600
```

When JWT is enabled, `gvm run` automatically calls `POST /gvm/auth/token` for the agent's identity and exposes the resulting JWT as the `GVM_JWT_TOKEN` environment variable inside the agent's process. If JWT isn't configured on the proxy, the call returns 503 and the CLI silently falls back to the legacy header-based path.

**SDK-less agents** must read `GVM_JWT_TOKEN` and add it to outbound requests themselves — the proxy will not accept the identity otherwise. The simplest way:

```python
# Python (without the GVM SDK)
import os, urllib.request

token = os.environ.get("GVM_JWT_TOKEN")
req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=...)
if token:
    req.add_header("Authorization", f"Bearer {token}")
urllib.request.urlopen(req)
```

```javascript
// Node.js (without the GVM SDK)
const token = process.env.GVM_JWT_TOKEN;
const headers = {};
if (token) headers["Authorization"] = `Bearer ${token}`;
fetch("https://api.openai.com/v1/chat/completions", { headers, ... });
```

Without that header, the proxy logs `"No JWT token provided — using unverified X-GVM-Agent-Id header"` and accepts the self-declared identity. That is fine for dev runs but should NOT be relied on in any setting where one agent's process could pretend to be another.

**Per-agent monitoring**:

```bash
gvm events list --agent agent-coder-1 --since 5m   # filter by agent
gvm stats --agent agent-analyst                      # budget usage
```

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

**Where agent files actually live while the sandbox is running.** The agent sees a normal writable `/workspace`, but that path is an overlayfs mount: the read-only lower layer is the host workspace, and the writable upper layer is `data/sandbox-staging/<pid>/upper/` on the host. Every file the agent creates or modifies inside `/workspace/...` appears **immediately** at `data/sandbox-staging/<pid>/upper/<same-relative-path>` — you can `ls` and `cat` it from another terminal while the agent is still running. Nothing is copied back into the real workspace until the session ends and you (or `gvm fs approve`) accept it, so a crashed or killed agent leaves zero mess in your actual project tree. Deletions show up in the upper layer as overlayfs whiteout files (`.wh.<name>`) rather than touching the real file.

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

### DNS Governance (Layer 0)

DNS governance is **enabled by default** in sandbox mode. Every DNS query from the agent passes through a built-in governance proxy before any HTTP call can happen.

**How it works:**

```
Agent DNS query → sandbox iptables DNAT → GVM DNS proxy (classify + delay) → upstream resolver
```

The DNS proxy classifies each query into a tier based on whether the domain is known and the query pattern:

| Tier | Condition | Delay | What happens |
|------|-----------|-------|-------------|
| **1 (known)** | Domain learned via `gvm suggest` or in SRR known_hosts | 0ms | Free pass — no delay, no log |
| **2 (unknown)** | First-seen domain | 200ms | Short delay + logged in proxy.log |
| **3 (anomalous)** | >5 unique subdomains on the same unknown base domain within 60s | 3s | Alert-level delay + durable WAL entry |
| **4 (flood)** | >20 unique subdomain queries globally within 60s | 10s | Maximum delay + durable WAL entry |

**Key design decisions:**

- **No Deny**: DNS denial kills the entire agent. One false positive = outage. Worst case with GVM is a 10-second delay, not a crash.
- **Decay**: When the anomalous pattern stops (sliding window expires after 60s), the tier drops back to Tier 2. The system never permanently escalates.
- **WAL audit**: Tier 3/4 events include full window state in the WAL (unique_subdomain_count, global_unique_count, window_age_secs) so an auditor can reconstruct *why* the delay was applied.

**Typical workflow:**

```bash
# 1. Watch mode learns which domains the agent uses
gvm run --sandbox --watch agent.py

# 2. gvm suggest generates rules — these become the "known hosts" for DNS free-pass
gvm suggest --from session.jsonl >> gvm.toml

# 3. Enforce mode — known domains resolve instantly, unknown get 200ms delay
gvm run --sandbox agent.py
```

After step 2, domains like `api.github.com` and `api.anthropic.com` that appeared in the watch session are classified as Tier 1 (known) and resolve with zero governance delay.

**Disabling DNS governance:**

```bash
# CLI flag
gvm run --sandbox --no-dns-governance agent.py

# Or in proxy.toml
[dns]
enabled = false
```

Use this when you already have dedicated DNS security tools (Route 53 DNS Firewall, Cloudflare Gateway, Cisco Umbrella) handling DNS-level threats.

**Tuning the sliding window:**

The sliding-window duration (default 60s) is set in proxy config:

```toml
[dns]
window_secs = 60   # production default; minimum allowed is 5
```

Operators may shorten this for E2E tests (e.g. `window_secs = 5`)
to avoid 60-second waits when verifying decay. Values below 5 seconds
are clamped UP to 5, because Tier 3 detection requires ≥5 unique
subdomains in the window — anything shorter would render the
detection useless. A clamp triggers a `tracing::warn!` at startup.

The previous `GVM_TEST_DNS_WINDOW_SEC` env-var override was removed
in favor of config-file injection: env vars are ambient and
auditors can't see them in the WAL `gvm.system.config_load` event.
Configuration always lands in the audit chain. See
`GVM_CODE_STANDARDS.md` §6.5 for the rationale.

---

## Troubleshooting

### Agent Blocked (403)

```bash
gvm events list --agent my-agent --since 5m      # What happened?
gvm check --host api.bank.com --method POST       # Dry-run same request
# Fix: edit gvm.toml → hot-reload
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

### Quick Reference

The commands you use every day:

| Command | Intent | Example |
|---------|--------|---------|
| `gvm run` | Run an agent under governance — watch, enforce, or sandbox | `gvm run --sandbox agent.py` |
| `gvm status` | Is the proxy alive? How many rules? Any problems? | `gvm status --json \| jq .srr_rules` |
| `gvm suggest` | Auto-generate security rules from a recorded session — no manual TOML editing | `gvm suggest --from session.jsonl >> gvm.toml` |
| `gvm reload` | Apply rule changes without restarting the proxy or killing running agents | `gvm reload` |
| `gvm stop` | Shut down the proxy cleanly, flush the audit trail, release all sandbox resources | `gvm stop` |

### Full Command List

**Agent Execution**

| Command | Intent | Key flags |
|---------|--------|-----------|
| `gvm run [--] <cmd>` | Run agent with governance. Starts proxy automatically if not running. | `--sandbox` (kernel isolation), `--watch` (observe only), `-i` (interactive rule discovery), `--fs-governance` (overlayfs), `--no-dns-governance`, `--no-mitm` |
| `gvm demo` | Run built-in demo scenarios to see GVM in action without writing an agent | `--scenario finance\|assistant\|devops\|data` |

**Policy Management**

| Command | Intent | Key flags |
|---------|--------|-----------|
| `gvm suggest` | Convert a watch session into SRR rules. Eliminates manual rule writing — the agent teaches GVM what it needs. | `--from <jsonl>`, `--decision allow\|delay\|deny` |
| `gvm check` | Dry-run: "would this request be allowed?" Test rules before deploying them to production. | `--host H`, `--method M`, `--path P`, `--operation O`, `--json` |
| `gvm reload` | Hot-reload rules from disk. Edit `gvm.toml`, run this, new rules take effect on the next request. | — |
| `gvm approve` | Human-in-the-loop: review and approve/deny requests that hit RequireApproval rules. | `--auto-deny` (CI: reject all after timeout) |

**Monitoring & Audit**

| Command | Intent | Key flags |
|---------|--------|-----------|
| `gvm status` | Proxy health dashboard — version, SRR rules, WAL state, TLS, DNS governance, active sandboxes. | `--json` (machine-readable, includes PID) |
| `gvm events` | Query individual audit events from the WAL. "Show me what happened." | `list --agent <id>`, `trace --trace-id <id>` |
| `gvm stats` | Aggregate statistics — token usage per agent, cost tracking, blocked action counts. | `tokens` |
| `gvm audit` | Verify WAL Merkle chain integrity. "Has anyone tampered with the audit log?" | `verify` |

`gvm events` shows individual log entries (who called what, when, what decision). `gvm stats` shows aggregate numbers (total tokens, total blocked, cost per agent). They don't overlap — one is the raw journal, the other is the summary dashboard.

**Operations**

| Command | Intent | Key flags |
|---------|--------|-----------|
| `gvm stop` | Graceful shutdown. Flushes WAL, releases sandbox state (veth, iptables, mounts, cgroups), removes PID file. Use this instead of `kill`. | — |
| `gvm cleanup` | Remove orphaned sandbox resources left behind by crashes or `kill -9`. The "janitor" for when things go wrong. | `--dry-run` |
| `gvm fs approve` | Review file changes from `--fs-governance` sandboxes. Agent wrote files — do you accept them into the real workspace? | `--list`, `--accept-all`, `--reject-all` |

**Setup**

| Command | Intent | Key flags |
|---------|--------|-----------|
| `gvm init` | Generate starter config files from industry templates. First command after install. | `--industry saas\|fintech\|healthcare` |
| `gvm preflight` | "Can I run sandbox on this machine?" Checks namespaces, iptables, seccomp availability. | — |

Full flags for any command: `gvm <command> --help`

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
- [ ] `chmod 600 gvm.toml`
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

> **Under the hood:** [Architecture](overview.md) | [SRR Rules](srr.md) | [Merkle WAL](architecture/ledger.md) | [Security Model](security-model.md) | [Governance Coverage](governance-coverage.md)
