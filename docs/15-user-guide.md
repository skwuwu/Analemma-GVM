# GVM User Guide

## Quick Start — 3 Steps

You don't need to write rules. GVM learns from your agent's traffic and suggests them.

```bash
# 1. Watch — see what your agent calls (no rules needed)
gvm watch my_agent.py

# 2. Suggest — auto-generate rules from observed traffic
gvm suggest --from session.jsonl > config/srr_network.toml

# 3. Run — enforce the generated rules
gvm run my_agent.py
```

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
gvm watch --output json my_agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
```

Reads a watch session log and generates TOML rules for every URL that hit Default-to-Caution. Review the file, then merge into `config/srr_network.toml`.

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

**Hot-reload:** Edit the file → `POST /gvm/reload`. No restart needed.

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

### Sandbox Mode

```bash
sudo gvm run --sandbox my_agent.py
```

Agent runs in an isolated environment where it cannot bypass the proxy. Linux only, requires sudo.

```bash
--sandbox-timeout 300       # Kill after 5 minutes (default: 3600)
--no-mitm                   # Disable HTTPS inspection
--memory 256m               # Memory limit
--cpus 0.5                  # CPU limit
```

> **Note:** Node.js ignores `HTTPS_PROXY`. Sandbox mode solves this — all HTTPS is intercepted regardless of the agent's behavior.

### ABAC Policies (`config/policies/`)

Semantic rules evaluated with the SDK (`@ic` decorator). Goes beyond URL matching — evaluates operation type, data sensitivity, and agent identity.

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

URL didn't match any rule — Default-to-Caution. Run `gvm watch` + `gvm suggest` to discover and add rules.

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
| `gvm cleanup` | Remove orphaned sandbox resources |
| `gvm init --industry I` | Initialize config templates |

Full flags: `gvm <command> --help`

---

## Production Checklist

- [ ] Remove `[dev] host_overrides` from proxy.toml
- [ ] Set `GVM_SECRETS_KEY` and `GVM_VAULT_KEY`
- [ ] Configure NATS for WAL replication
- [ ] Set credential policy to `Deny` (not Passthrough)
- [ ] Enable `--shadow-mode strict`
- [ ] `chmod 600 config/secrets.toml`
- [ ] Review SRR: no catch-all Allow
- [ ] Set up `gvm stats` + `gvm audit verify` in cron
- [ ] Test with `gvm check` before deploying policy changes

---

> **Under the hood:** [Architecture](00-overview.md) | [SRR Design](03-srr.md) | [ABAC Engine](02-policy.md) | [Merkle WAL](04-ledger.md) | [Security Model](11-security-model.md) | [Governance Coverage](14-governance-coverage.md)
