# GVM User Guide

Complete guide to using Analemma GVM — from first run to production deployment.

---

## 1. Running Agents

### Basic (Cooperative Mode)

```bash
gvm run my_agent.py                    # Python script
gvm run -- node my_agent.js            # Node.js binary
gvm run -- openclaw gateway            # Any binary + args
```

The proxy sets `HTTP_PROXY` and `HTTPS_PROXY` so HTTP-based agents route through governance automatically. No code changes needed.

**Output:**
```
  Analemma-GVM — Agent Governance Monitor

  Agent ID:     agent-001
  Security layers active:
    ✓ Layer 2: Enforcement Proxy
    ○ Layer 3: OS Containment (add --sandbox or --contained)

  --- Agent output below ---
  [agent runs here]

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  GVM Audit Trail — 5 events captured
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ✓ gvm.data.read              Allow               GET api.github.com
    ⏱ gvm.messaging.send         Delay { ms: 300 }   POST slack.com
    ✗ gvm.payment.charge         Deny                POST api.bank.com

  3 allowed  1 delayed  1 blocked
```

### Sandbox Mode (Linux — Full Isolation)

```bash
sudo gvm run --sandbox my_agent.py
sudo gvm run --sandbox -- node my_agent.js
```

Adds kernel isolation: PID namespace, mount namespace, veth network, seccomp-BPF, eBPF TC filter. Agent cannot bypass the proxy — all HTTPS traffic is intercepted via DNAT + MITM.

**Options:**
```bash
--sandbox-timeout 300       # Kill agent after 5 minutes (default: 3600)
--no-mitm                   # Disable HTTPS interception (CONNECT relay only)
--memory 256m               # cgroup memory limit
--cpus 0.5                  # cgroup CPU limit
--fs-governance             # Enable file change review (see §6)
```

### Watch Mode (Observation Only)

```bash
gvm watch my_agent.py                     # Allow-all, observe traffic
gvm watch --with-rules my_agent.py        # Apply existing rules while watching
gvm watch --sandbox --output json \       # Sandbox + JSON output for piping
  -- node agent.js
```

Watch mode temporarily sets all rules to Allow, runs the agent, and shows every HTTP request in real-time:

```
  TIME      METHOD HOST                          PATH                     ST  TOKENS
  ────────────────────────────────────────────────────────────────────────────────
  14:23:01  ✓ POST   api.anthropic.com             /v1/messages             200  [1,234 tokens]
  14:23:05  ⏱ GET    raw.githubusercontent.com     /torvalds/linux/master.. 301
  14:23:06  ✓ GET    api.github.com                /repos/torvalds/linux/c.. 200
```

Session summary at exit shows host frequency, decisions, token cost estimate, and anomaly warnings (burst detection, loop detection, unknown hosts).

---

## 2. Policy Configuration

### SRR Rules — URL Pattern Matching (`config/srr_network.toml`)

SRR (Static Request Rules) match requests by host, path, and method. No SDK needed — works with any agent.

```toml
# Allow GitHub read operations
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

# Delay unknown APIs for audit
[[rules]]
pattern = "{any}"
method = "*"
decision = { type = "Delay", milliseconds = 300 }
```

**Pattern types:**
- `pattern = "api.github.com"` — exact host match
- `pattern = "api.github.com/{any}"` — host + any path
- `pattern = "{any}"` — catch-all (Default-to-Caution)

**Decision types:**
- `Allow` — pass immediately
- `Delay { milliseconds: N }` — pause then pass (audit trail guaranteed)
- `Deny { reason: "..." }` — block with 403 + structured error
- `RequireApproval { urgency: "High" }` — hold for human approval (IC-3)
- `Throttle { max_per_minute: N }` — rate limit
- `AuditOnly { alert_level: "Medium" }` — pass but flag for review

**Hot-reload:** Edit the file, call `POST /gvm/reload` or wait for auto-detect. No proxy restart needed.

**Query strings:** Automatically stripped before regex matching. `^/commits$` matches `/commits?per_page=5`.

### ABAC Policies — Semantic Rules (`config/policies/`)

ABAC (Attribute-Based Access Control) evaluates operation metadata from the SDK. Requires `@ic` decorator in Python or equivalent SDK headers.

```toml
# config/policies/global.toml — applies to ALL agents

[[rules]]
id = "block-critical-delete"
priority = 1                    # Lower number = higher priority
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

**Hierarchy:** Global > Tenant > Agent. Lower layers can only be **stricter**, never more permissive. `Deny` at Global cannot be overridden to `Allow` by an agent policy.

**Tenant/Agent policies:**
```
config/policies/
  global.toml           # Applies to everyone
  tenant-acme.toml      # Applies to tenant "acme" agents
  agent-finance-001.toml  # Applies to specific agent
```

### Credential Injection (`config/secrets.toml`)

```toml
[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_live_your_stripe_key"

[credentials."api.sendgrid.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.your_sendgrid_key"

[credentials."api.github.com"]
type = "OAuth2"
access_token = "gho_your_github_token"
refresh_token = "ghr_refresh"
expires_at = "2027-01-01T00:00:00Z"
```

**How it works:**
| Agent sends | secrets.toml has host? | Result |
|-------------|----------------------|--------|
| No auth header | Yes | Proxy injects key |
| Own auth header | Yes | Proxy **replaces** with managed key |
| Own auth header | No | Agent's key passes through |
| No auth header | No | No auth (API may reject) |

**Scope:** HTTP headers only. LLM SDKs (Anthropic, OpenAI) require keys at initialization — use `ANTHROPIC_API_KEY` env var for that. Credential injection is for **tool API calls** the agent makes after LLM response.

---

## 3. Debugging & Troubleshooting

### Agent Got Blocked (403 Deny)

1. **Check what happened:**
   ```bash
   gvm events list --agent my-agent --since 5m
   ```

2. **Dry-run the same request:**
   ```bash
   gvm check --operation gvm.payment.charge \
     --host api.bank.com --method POST
   ```
   Output shows decision path: `Policy(Allow) + SRR(Deny) → Final(Deny)`, matched rule ID, and engine latency.

3. **Fix the policy:**
   - Edit `config/srr_network.toml` to change the rule
   - Or add a more specific Allow rule with higher priority
   - Rules hot-reload — no restart needed

### Agent Got Delayed (300ms)

This is **Default-to-Caution** — the URL didn't match any explicit SRR rule. The proxy delays and audits rather than silently allowing.

1. **Find which hosts hit Default-to-Caution:**
   ```bash
   gvm events list --since 1h | grep "default_caution"
   ```

2. **Add an explicit rule:**
   ```toml
   [[rules]]
   pattern = "catfact.ninja/{any}"
   method = "GET"
   decision = { type = "Allow" }
   reason = "Public API — cat facts"
   ```

3. **Or discover all patterns automatically:**
   ```bash
   gvm watch --output json agent.py > session.jsonl
   gvm suggest --from session.jsonl --output new-rules.toml
   ```

### Proxy Not Starting

```bash
gvm run agent.py
# "Proxy not reachable at http://127.0.0.1:8080. Starting..."
# If it hangs: check data/proxy.log
cat data/proxy.log | tail -20
```

Common issues:
- Port 8080 already in use: `lsof -i :8080`
- Config error: check `config/proxy.toml` syntax
- Permission: sandbox requires `sudo`

### Sandbox SSH Blocked (EC2)

If sandbox iptables blocks SSH on EC2:
```bash
# From AWS console, reboot the instance
# iptables rules are cleared on reboot
# GVM now has FORWARD ESTABLISHED/RELATED protection (K1 fix)
```

---

## 4. CLI Command Reference

### `gvm run`

Run an agent with governance.

```bash
gvm run [FLAGS] [--] <command...>

FLAGS:
  --sandbox              Linux kernel isolation (requires sudo)
  --contained            Docker isolation (experimental)
  --no-mitm              Disable HTTPS MITM inspection
  --fs-governance        Enable file change governance (overlayfs)
  --shadow-mode <MODE>   Intent verification: disabled|observe|strict
  --sandbox-timeout <N>  Kill agent after N seconds (default: 3600)
  --memory <SIZE>        Memory limit: 256m, 1g (default: 512m)
  --cpus <N>             CPU limit: 0.5, 1.0 (default: 1.0)
  -i, --interactive      Interactive SRR rule suggestion after run
  --default-policy <P>   Override unmatched URL policy: allow|delay|deny
  --agent-id <ID>        Agent identifier for audit trail
  --proxy <URL>          Proxy address (default: http://127.0.0.1:8080)
```

### `gvm watch`

Observe agent API calls without enforcement.

```bash
gvm watch [FLAGS] [--] <command...>

FLAGS:
  --with-rules           Apply existing SRR rules while watching
  --sandbox              Run in sandbox (MITM for HTTPS visibility)
  --output <FORMAT>      text (default) or json
```

### `gvm check`

Dry-run policy evaluation — test what decision the proxy would make.

```bash
gvm check --operation <OP> --host <HOST> --method <METHOD> [--path <PATH>]

# Examples:
gvm check --operation gvm.payment.charge --host api.bank.com --method POST
gvm check --operation test --host api.github.com --method GET --path /repos
```

Output: decision, matched rule, decision path (ABAC + SRR → max_strict), engine latency in microseconds.

### `gvm events`

Query the audit trail.

```bash
gvm events list [--agent <ID>] [--since <DURATION>] [--format json]
gvm events trace --trace-id <UUID>
```

### `gvm audit`

WAL integrity verification and export.

```bash
gvm audit verify [--wal data/wal.log]     # Check Merkle chain integrity
gvm audit export [--since 1h] [--format jsonl] [--wal data/wal.log]
```

`verify` output:
```
OK: WAL integrity verified. No issues found.
  Events: 635, Batches: 42, Chain: intact
```
Or on tampering:
```
TAMPER DETECTED: 2 event(s) have invalid hashes.
  Batch 7: merkle root mismatch
```

### `gvm stats`

Agent usage statistics.

```bash
gvm stats tokens [--agent <ID>] [--since 1h]    # Token usage per agent
gvm stats rollback-savings [--since 24h]          # Tokens saved by governance
```

### `gvm suggest`

Generate SRR rules from watch session.

```bash
gvm suggest --from session.jsonl [--output rules.toml] [--decision allow]
```

Reads a JSON session log (from `gvm watch --output json`) and generates TOML rules for all URLs that hit Default-to-Caution.

### `gvm cleanup`

Remove orphaned sandbox resources.

```bash
gvm cleanup                # Clean up crashed sandbox remnants
gvm cleanup --dry-run      # Show what would be cleaned
```

### `gvm init`

Initialize configuration from industry templates.

```bash
gvm init --industry saas          # SaaS template (Stripe, Slack, etc.)
gvm init --industry healthcare    # HIPAA-aware defaults
```

---

## 5. Shadow Mode (Intent Verification)

Shadow Mode adds 2-phase verification: the agent declares what it's about to do, then the proxy verifies the actual request matches.

```bash
gvm run --shadow-mode strict -- node agent.js
```

| Mode | Unmatched request | Use case |
|------|------------------|----------|
| `disabled` | Normal processing | Default |
| `observe` | Allow + audit warning | Testing shadow mode |
| `strict` | Deny (403) | Production — no undeclared API calls |

**MCP integration:** `gvm_declare_intent` tool registers intent before API calls. See [MCP section](12-quickstart.md#7-mcp-integration--claude-desktop--cursor).

---

## 6. Filesystem Governance (Trust-on-Pattern)

When using `--sandbox --fs-governance`, the agent's file changes are captured via overlayfs and reviewed at session end.

```bash
sudo gvm run --sandbox --fs-governance my_agent.py
```

**Classification:**

| Change | Pattern | Action |
|--------|---------|--------|
| Created file | `*.csv, *.pdf, *.txt` | Auto-merged to workspace |
| Created file | `*.sh, *.py, *.json` | Needs manual review |
| Created file | `*.log, __pycache__/*` | Discarded |
| Modified file | (any) | Always needs review |
| Deleted file | (any) | Always needs review |

**Interactive review (TTY):**
```
  ── File Changes ──
    Created:  output.csv (12KB)  auto-merged → workspace/output.csv
    Created:  analysis.py (2KB)  needs review (manual_commit: *.py)
    Discarded: 3 file(s)

  [1/1] analysis.py (Created, 2KB)
  +#!/usr/bin/env python3
  +import pandas as pd
  +df = pd.read_csv('output.csv')

  (a)ccept  (r)eject  (s)kip all → a
  ✓ analysis.py → workspace/analysis.py
```

**CI/CD (non-TTY):** Files staged to `data/sandbox-staging/`, printed path for later `gvm fs approve`.

---

## 7. CI/CD Integration

### Policy Validation in CI

```yaml
# GitHub Actions
- name: Validate governance policies
  run: |
    gvm-proxy &
    sleep 2
    # Critical endpoints must be blocked
    gvm check --operation gvm.payment.charge --host api.bank.com --method POST \
      | grep -q "Deny" || exit 1
    # Read access must be allowed
    gvm check --operation gvm.storage.read --host api.github.com --method GET \
      | grep -q "Allow" || exit 1
```

### Watch Mode for Pattern Discovery

```bash
gvm watch --output json agent.py > session.jsonl
gvm suggest --from session.jsonl --decision allow > new-rules.toml
# Review new-rules.toml, merge into srr_network.toml
```

---

## 8. Production Checklist

- [ ] Remove `[dev] host_overrides` from proxy.toml
- [ ] Set `GVM_SECRETS_KEY` for vault encryption
- [ ] Set `GVM_VAULT_KEY` for state encryption
- [ ] Configure NATS for WAL replication (proxy.toml `[nats]`)
- [ ] Set credential policy to `Deny` (not Passthrough) in production
- [ ] Enable `--shadow-mode strict` for intent verification
- [ ] Set file permissions: `chmod 600 config/secrets.toml`
- [ ] Review SRR rules: no catch-all Allow, Default-to-Caution is Delay
- [ ] Set up monitoring: `gvm stats tokens` + `gvm audit verify` in cron
- [ ] Test with `gvm check` before deploying policy changes

---

[← Quick Start](12-quickstart.md) | [Reference](13-reference.md) | [Architecture](00-overview.md)
