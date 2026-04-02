# GVM User Guide

---

## 1. Running Agents

### Cooperative Mode

```bash
gvm run my_agent.py                    # Python script
gvm run -- node my_agent.js            # Node.js binary
gvm run -- openclaw gateway            # Any binary + args
```

Routes agent HTTP traffic through the governance proxy. No code changes needed.

**Output:**
```
  Agent ID:     agent-001
  Security layers active:
    ✓ Layer 2: Enforcement Proxy
    ○ Layer 3: OS Containment (add --sandbox)

  --- Agent output below ---
  [agent runs here]

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GVM Audit Trail — 5 events
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✓ Allow    GET  api.github.com
    ⏱ Delay    POST slack.com
    ✗ Deny     POST api.bank.com

  3 allowed  1 delayed  1 blocked
```

> **Note:** Node.js ignores `HTTPS_PROXY`. Use `--sandbox` for HTTPS visibility.

### Sandbox Mode

```bash
sudo gvm run --sandbox my_agent.py
```

Runs the agent in an isolated environment where it cannot bypass the proxy. Linux only, requires sudo.

```bash
--sandbox-timeout 300       # Kill after 5 minutes (default: 3600)
--no-mitm                   # Disable HTTPS inspection
--memory 256m               # Memory limit
--cpus 0.5                  # CPU limit
--fs-governance             # File change governance (see §6)
```

### Watch Mode

```bash
gvm watch my_agent.py                     # Allow all, observe traffic
gvm watch --with-rules my_agent.py        # Apply existing rules while watching
gvm watch --sandbox --output json \       # JSON output for piping
  -- node agent.js
```

Real-time traffic display:
```
  14:23:01  ✓ POST  api.anthropic.com    /v1/messages       200  [1,234 tokens]
  14:23:05  ⏱ GET   raw.githubusercontent /torvalds/linux..  301
  14:23:06  ✓ GET   api.github.com       /repos/torvalds..  200
```

Session summary at exit: host frequency, decisions, token cost estimate, anomaly warnings (burst, loop, unknown host).

---

## 2. Policy Configuration

### SRR Rules — URL Pattern Matching (`config/srr_network.toml`)

Works without SDK. Applies to any agent in any language.

```toml
# Allow GitHub reads
[[rules]]
pattern = "api.github.com"
path_regex = "^/repos/[^/]+/[^/]+/commits$"
method = "GET"
decision = { type = "Allow" }
reason = "List commits (read-only)"

# Block wire transfers
[[rules]]
pattern = "api.bank.com"
path_regex = "/transfer/.*"
method = "POST"
decision = { type = "Deny", reason = "Wire transfers blocked" }

# Default: delay and audit unmatched URLs
[[rules]]
pattern = "{any}"
method = "*"
decision = { type = "Delay", milliseconds = 300 }
```

**Patterns:**
- `"api.github.com"` — exact host
- `"api.github.com/{any}"` — host + any path
- `"{any}"` — catch-all (Default-to-Caution)

**Decision types:**
| Type | Behavior |
|------|----------|
| `Allow` | Pass immediately |
| `Delay { milliseconds: N }` | Pause N ms then pass |
| `Deny { reason: "..." }` | Block with 403 |
| `RequireApproval { urgency: "High" }` | Hold for human approval |
| `Throttle { max_per_minute: N }` | Rate limit |
| `AuditOnly { alert_level: "Medium" }` | Pass but flag for review |

**Hot-reload:** Edit the file, call `POST /gvm/reload`. No proxy restart needed.

**Query strings:** Automatically stripped before regex matching. `^/commits$` matches `/commits?per_page=5`.

### ABAC Policies (`config/policies/`)

Used with the SDK (`@ic` decorator).

```toml
# config/policies/global.toml

[[rules]]
id = "block-critical-delete"
priority = 1
layer = "Global"
description = "Block critical data deletion"

[rules.match]
operation = { starts_with = "gvm.data.delete" }

[rules.match.context]
sensitivity = { equals = "Critical" }

[rules.decision]
type = "Deny"
reason = "Critical data deletion is forbidden"
```

**Policy file structure:**
```
config/policies/
  global.toml             # Applies to all agents
  tenant-acme.toml        # Applies to "acme" tenant
  agent-finance-001.toml  # Applies to specific agent
```

Lower layers can only be **stricter**, never more permissive.

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

> **Scope:** HTTP headers only. LLM SDKs (Anthropic, OpenAI) require keys at initialization — use `ANTHROPIC_API_KEY` env var. Credential injection applies to **tool API calls** the agent makes after LLM response.

---

## 3. Troubleshooting

### Agent Got Blocked (403 Deny)

```bash
# 1. Check what happened
gvm events list --agent my-agent --since 5m

# 2. Dry-run the same request
gvm check --operation gvm.payment.charge --host api.bank.com --method POST

# 3. Fix the policy (edit srr_network.toml → hot-reload)
```

### Agent Got Delayed (300ms)

The URL didn't match any SRR rule — **Default-to-Caution** kicked in.

```bash
# Auto-discover patterns
gvm watch --output json agent.py > session.jsonl
gvm suggest --from session.jsonl --output new-rules.toml

# Or add a rule manually in config/srr_network.toml:
# [[rules]]
# pattern = "catfact.ninja/{any}"
# method = "GET"
# decision = { type = "Allow" }
```

### Proxy Won't Start

```bash
# Check logs
cat data/proxy.log | tail -20

# Port conflict
lsof -i :8080

# Sandbox requires sudo
sudo gvm run --sandbox agent.py
```

---

## 4. CLI Commands

### `gvm run`

```
gvm run [FLAGS] [--] <command...>

--sandbox              Isolated environment (requires sudo)
--no-mitm              Disable HTTPS inspection
--fs-governance        Enable file governance
--shadow-mode <MODE>   disabled | observe | strict
--sandbox-timeout <N>  Seconds (default: 3600)
--memory <SIZE>        256m, 1g (default: 512m)
--cpus <N>             0.5, 1.0 (default: 1.0)
-i, --interactive      Suggest rules after run
--default-policy <P>   allow | delay | deny
--agent-id <ID>        Agent identifier
--proxy <URL>          Proxy address (default: http://127.0.0.1:8080)
```

### `gvm watch`

```
gvm watch [FLAGS] [--] <command...>

--with-rules           Apply existing rules while watching
--sandbox              Watch in sandbox
--output <FORMAT>      text (default) | json
```

### `gvm check`

Dry-run policy evaluation.

```bash
gvm check --operation gvm.payment.charge --host api.bank.com --method POST
gvm check --operation test --host api.github.com --method GET --path /repos
```

Output: decision, matched rule, decision path, engine latency.

### `gvm events`

```bash
gvm events list [--agent <ID>] [--since <DURATION>] [--format json]
gvm events trace --trace-id <UUID>
```

### `gvm audit`

```bash
gvm audit verify [--wal data/wal.log]
gvm audit export [--since 1h] [--format jsonl]
```

Output:
```
OK: WAL integrity verified. Events: 635, Batches: 42, Chain: intact
```
```
TAMPER DETECTED: 2 event(s) have invalid hashes. Batch 7: merkle root mismatch
```

### `gvm stats`

```bash
gvm stats tokens [--agent <ID>] [--since 1h]
gvm stats rollback-savings [--since 24h]
```

### `gvm suggest`

```bash
gvm suggest --from session.jsonl [--output rules.toml] [--decision allow]
```

Generates TOML rules from `gvm watch --output json` for URLs that hit Default-to-Caution.

### `gvm cleanup`

```bash
gvm cleanup              # Clean up crashed sandbox remnants
gvm cleanup --dry-run    # Show what would be cleaned
```

### `gvm init`

```bash
gvm init --industry saas          # SaaS template
gvm init --industry healthcare    # HIPAA defaults
```

---

## 5. Shadow Mode

```bash
gvm run --shadow-mode strict -- node agent.js
```

| Mode | Undeclared request | Use case |
|------|-------------------|----------|
| `disabled` | Normal processing | Default |
| `observe` | Allow + audit warning | Testing |
| `strict` | Deny (403) | Production |

MCP integration: `gvm_declare_intent` tool registers intent before API calls. [MCP section →](12-quickstart.md#7-mcp-integration--claude-desktop--cursor)

---

## 6. Filesystem Governance (Trust-on-Pattern)

```bash
sudo gvm run --sandbox --fs-governance my_agent.py
```

Classifies and reviews agent file changes at session end.

| Change | Pattern | Action |
|--------|---------|--------|
| New file | `*.csv, *.pdf, *.txt` | Auto-merged to workspace |
| New file | `*.sh, *.py, *.json` | Needs manual review |
| New file | `*.log, __pycache__/*` | Discarded |
| Modified file | (any) | Always needs review |
| Deleted file | (any) | Always needs review |

**TTY:**
```
  ── File Changes ──
    Created:  output.csv (12KB)  auto-merged → workspace/output.csv
    Created:  analysis.py (2KB)  needs review (*.py)

  [1/1] analysis.py (Created, 2KB)
  +#!/usr/bin/env python3
  +import pandas as pd

  (a)ccept  (r)eject  (s)kip all → a
  ✓ analysis.py → workspace/analysis.py
```

**CI/CD:** Files staged to `data/sandbox-staging/`. Use `gvm fs approve` later.

---

## 7. CI/CD Integration

```yaml
# GitHub Actions
- name: Validate governance policies
  run: |
    gvm-proxy &
    sleep 2
    gvm check --operation gvm.payment.charge --host api.bank.com --method POST \
      | grep -q "Deny" || exit 1
    gvm check --operation gvm.storage.read --host api.github.com --method GET \
      | grep -q "Allow" || exit 1
```

### Pattern Discovery + Rule Generation

```bash
gvm watch --output json agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
```

---

## 8. Production Checklist

- [ ] Remove `[dev] host_overrides` from proxy.toml
- [ ] Set `GVM_SECRETS_KEY` (vault encryption)
- [ ] Set `GVM_VAULT_KEY` (state encryption)
- [ ] Configure NATS for WAL replication (`proxy.toml [nats]`)
- [ ] Set credential policy to `Deny` (not Passthrough)
- [ ] Enable `--shadow-mode strict`
- [ ] `chmod 600 config/secrets.toml`
- [ ] Review SRR rules: no catch-all Allow, Default-to-Caution is Delay
- [ ] Set up monitoring: `gvm stats tokens` + `gvm audit verify` in cron
- [ ] Test with `gvm check` before deploying policy changes

---

> **How it works under the hood:** [Architecture Overview](00-overview.md) | [SRR Design](03-srr.md) | [ABAC Policy Engine](02-policy.md) | [Merkle WAL](04-ledger.md) | [Security Model](11-security-model.md) | [Governance Coverage](14-governance-coverage.md)
