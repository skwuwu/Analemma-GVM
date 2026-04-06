# Quick Start

**Zero code changes. Your agent doesn't know it's being governed.**

---

## 1. Launch

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo run --release          # First build: 2-5 min. After that: ~1s.
```

Proxy is now listening on `:8080`. Every HTTP request that passes through it is classified, enforced, and audited.

---

## 2. Run Your Agent

```bash
gvm run my_agent.py          # Any Python/Node/binary. No code changes.
```

That's it. `gvm run` auto-configures the proxy, routes all HTTP traffic through governance, and prints an audit trail when the agent finishes:

```
  Checking proxy at http://127.0.0.1:8080... OK
  Agent ID:     agent-001
  Security layers active:
    ✓ Layer 1: Governance Engine (policy evaluation)
    ✓ Layer 2: Enforcement Proxy (request interception)
    ○ Layer 3: OS Containment (add --sandbox or --contained)

  --- Agent output below ---
  ...

  GVM Audit Trail — 4 events captured
  ✓ gvm.messaging.read     Allow       GET gmail.googleapis.com
  ⏱ gvm.messaging.send     Delay       POST gmail.googleapis.com
  ✗ gvm.payment.charge      Deny        POST api.bank.com
  ✗ gvm.storage.delete      Deny        DELETE gmail.googleapis.com

  2 allowed  1 delayed  2 blocked
```

### Choose Your Isolation Level

```bash
gvm run my_agent.py              # Lite:  HTTP proxy only (dev/testing)
gvm run --sandbox my_agent.py    # Hard:  + Linux namespaces + seccomp (production)
gvm run --contained my_agent.py  # Docker isolation (experimental — see note)
```

> **Non-Linux?** `--sandbox` is Linux-only (production). `--contained` (Docker) is implemented but experimental — unstable on WSL2 and slim images. On Windows/macOS, run without isolation — Layer 2 SRR still enforces governance on all HTTP traffic.

---

## 3. Secret Injection — Stop Passing API Keys to Agents

Don't put API keys in `.env` files or agent code. Let the proxy inject them at the edge.

**`config/secrets.toml`:**

```toml
[credentials."api.slack.com"]
type = "Bearer"
token = "xoxb-your-slack-token"

[credentials."api.stripe.com"]
type = "ApiKey"
header = "Authorization"
value = "Bearer sk_test_your-stripe-key"
```

What happens at runtime:

```
 Agent sends request          Proxy strips agent auth       Proxy injects managed key
 ───────────────────          ──────────────────────        ────────────────────────
 POST api.stripe.com    →     Removes Authorization,   →   Adds "Bearer sk_test_..."
 Authorization: ???           Cookie, X-API-Key             from secrets.toml
```

The agent never sees the secret. Even if its memory is dumped, no credentials are exposed.

**Both patterns work — no migration required:**

| Agent code | secrets.toml has host? | What happens |
|-----------|----------------------|--------------|
| No auth header | Yes | Proxy injects managed key |
| Has own auth header | Yes | Proxy **replaces** with managed key |
| Has own auth header | No | Agent's key passes through unchanged |
| No auth header | No | Request sent without auth (API rejects) |

This means existing agents with hardcoded keys work immediately — just add them behind the proxy. When you're ready, move keys to `secrets.toml` for centralized management. No code changes needed either way.

**Scope and limitations:**
- Credential injection operates at the **HTTP layer** (headers). It cannot inject credentials into request bodies (e.g., GraphQL variables).
- **LLM SDKs** (Anthropic, OpenAI) require API keys at **client initialization time** (before HTTP requests). The proxy cannot help with SDK initialization — agents must have the LLM key in their environment (`ANTHROPIC_API_KEY`). Credential injection is for **tool API calls** (Stripe, Slack, GitHub, etc.) that the agent makes via HTTP after receiving tool_use from the LLM.
- For LLM keys, use the standard `ANTHROPIC_API_KEY` environment variable. The proxy governs what the agent *does* with LLM responses, not how it authenticates to the LLM.

---

## 4. Define What's Allowed

### Block by URL Pattern (`config/srr_network.toml`)

No SDK needed. Works with any language.

```toml
[[rules]]
id = "block-wire-transfer"
host_pattern = "api.bank.com"
path_pattern = "/transfer/.*"
method = "POST"
decision = "Deny"
reason = "Wire transfers are blocked"
```

Rules hot-reload — edit the file, the proxy picks up changes immediately.

### Block by Semantic Policy (`config/policies/global.toml`)

Requires the Python SDK (`@ic` decorator injects operation metadata).

```toml
[[rules]]
id = "block-critical-external"
priority = 1
layer = "Global"

[[rules.conditions]]
field = "resource.sensitivity"
operator = "Eq"
value = "Critical"

[[rules.conditions]]
field = "resource.tier"
operator = "Eq"
value = "External"

[rules.decision]
type = "Deny"
reason = "Critical data to external targets is forbidden"
```

Policies are hierarchical: **Global > Tenant > Agent**. Lower layers can only be stricter, never more permissive.

---

## 5. Try the Demo (No API Key Needed)

```bash
cargo run                       # Terminal 1: proxy
python -m gvm.mock_demo         # Terminal 2: mock LLM, real enforcement
```

The demo runs 4 pre-scripted actions through the real proxy — read inbox (Allow), send email (Delay 300ms), wire transfer (Deny), delete emails (Deny) — and prints a full governance audit.

---

## 6. Add the SDK (Experimental)

> **The proxy enforces governance without the SDK.** URL blocking, credential injection, and audit trail all work at full strength with zero code changes. The SDK is an experimental add-on — not required for production governance.

The SDK adds intent verification (`@ic` decorator) and checkpoint/rollback. These features are **not yet stabilized** — the proxy-only path is the recommended approach.

```python
from gvm import ic, gvm_session

@ic(operation="gvm.messaging.send")
def send_email(to, subject, body):
    return gvm_session().post("http://gmail.googleapis.com/...", json={...}).json()
```

**Without SDK vs. With SDK:**

- Without: URL blocking, key injection, audit trail — **all work at full strength (recommended)**
- With: + semantic intent verification, + checkpoint/rollback (experimental), + token savings on deny

```bash
pip install -e sdk/python       # Install once
```

---

## 7. MCP Integration — Claude Desktop / Cursor

GVM provides MCP tools for AI assistants that support the Model Context Protocol. This lets Claude Desktop, Cursor, or any MCP-compatible client govern agent API calls through GVM.

### Setup

```bash
# 1. Start GVM proxy
cd Analemma-GVM && cargo run --release

# 2. Clone MCP server
git clone https://github.com/skwuwu/analemma-gvm-openclaw.git
cd analemma-gvm-openclaw/mcp-server
npm install && npm run build
```

### Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "gvm": {
      "command": "node",
      "args": ["/path/to/analemma-gvm-openclaw/mcp-server/dist/index.js"],
      "env": {
        "GVM_PROXY_URL": "http://127.0.0.1:8080"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | What it does |
|------|-------------|
| `gvm_status` | Check proxy health and loaded rule count |
| `gvm_policy_check` | Dry-run: "would this request be allowed?" |
| `gvm_fetch` | Fetch a URL through GVM governance |
| `gvm_select_rulesets` | Browse and apply pre-built rulesets (GitHub, Slack, etc.) |
| `gvm_blocked_summary` | Summary of recently blocked requests |
| `gvm_audit_log` | Query the Merkle-chained audit trail |
| `gvm_declare_intent` | Register intent before making API calls (Shadow Mode) |

### Shadow Mode

Shadow Mode adds a 2-phase verification: the MCP tool declares what it's about to do (`gvm_declare_intent`), then the proxy verifies the actual request matches the declaration.

```toml
# config/proxy.toml
[shadow]
mode = "cautious"       # strict | cautious | permissive | disabled
intent_ttl_secs = 30    # how long an intent stays valid
cautious_delay_ms = 5000 # delay for unverified requests in cautious mode
```

| Mode | Unverified request behavior |
|------|----------------------------|
| `strict` | Deny (403) — safest for production |
| `cautious` | Delay 5s + audit warning — good for testing |
| `permissive` | Allow + audit warning — monitoring only |
| `disabled` | No verification (default) |

### Example: Claude Desktop with GVM

```
User: "Search GitHub for Rust async runtime projects"

Claude → gvm_policy_check(host="api.github.com", method="GET")
       → Allow ✓

Claude → gvm_fetch("https://api.github.com/search/repositories?q=rust+async+runtime")
       → Result: [{name: "tokio", stars: 24000}, ...]
       → Governed, audited, rate-limited through GVM proxy

User: "Delete the test repository"

Claude → gvm_policy_check(host="api.github.com", method="DELETE")
       → Deny ✗ (DELETE blocked by SRR rule)

Claude: "I can't delete repositories — that operation is blocked by governance policy."
```

---

## Next Steps

| Want to... | Go to |
|-----------|-------|
| **Full usage guide** — CLI commands, policy writing, debugging, CI/CD | **[User Guide →](user-guide.md)** |
| Configure policies, SRR rules, secrets | [Reference Guide →](reference.md) |
| Understand the 3-layer architecture | [Architecture Overview →](overview.md) |
| Connect Claude Desktop / Cursor via MCP | [Section 7 above](#7-mcp-integration--claude-desktop--cursor) |
| See the full SDK API (`@ic`, `GVMAgent`, errors) | [Python SDK →](architecture/sdk.md) |
| Write custom SRR rules | [Network SRR →](srr.md) |
| Write ABAC policies | [ABAC Policy →](policy.md) |
| Validate policies in CI/CD | [User Guide §7 →](15-user-guide.md#7-cicd-integration) |
| Debug a blocked agent | [User Guide §3 →](15-user-guide.md#3-debugging--troubleshooting) |
| Production deployment | [User Guide §8 →](15-user-guide.md#8-production-checklist) |
| Run tests | `cargo test --workspace --all-targets` |
