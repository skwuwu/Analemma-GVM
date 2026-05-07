# Quick Start

**Zero code changes. Your agent doesn't know it's being governed.**

Governance is enforced by a Rust proxy in front of your agent. There is
no Python SDK to import, no decorator to add, no client library to wrap
your code. Plain `requests`, `urllib`, `node-fetch`, `curl`, or anything
else that talks HTTP/HTTPS works unmodified.

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
    ✓ SRR enforcement (request pattern matching)
    ✓ Proxy interception (HTTP + MITM TLS)
    ○ OS containment (add --sandbox)

  --- Agent output below ---
  ...

  GVM Audit Trail — 4 events captured
  ✓ Allow       GET  gmail.googleapis.com
  ⏱ Delay       POST gmail.googleapis.com
  ✗ Deny        POST api.bank.com
  ✗ Deny        DELETE gmail.googleapis.com

  1 allowed  1 delayed  2 blocked
```

### Choose Your Isolation Level

```bash
gvm run my_agent.py              # Lite:  HTTP proxy only (dev/testing)
gvm run --sandbox my_agent.py    # Hard:  + Linux namespaces + seccomp + MITM (production, Linux)
```

> **Non-Linux?** `--sandbox` is Linux-only. For development on macOS or
> Windows, the cooperative HTTP-proxy mode still enforces SRR rules and
> credential injection — only kernel-level isolation is unavailable.
>
> **`--contained`** (Docker isolation) is gated behind the
> `cargo build --features contained` flag and is **not** in the default
> binary. It is unfinished — the in-container DNAT to MITM and CA
> injection are not yet wired — and will not appear in `gvm run --help`
> on a default build. For full HTTPS L7 inspection use `--sandbox`.

---

## 3. Secret Injection — Stop Passing API Keys to Agents

Don't put API keys in `.env` files or agent code. Let the proxy inject them at the edge.

GVM uses a **single unified config file** — `gvm.toml` — for rules, credentials, cost budget, filesystem patterns, and seccomp. Here is the credential section:

**`gvm.toml`:**

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
 Authorization: ???           Cookie, X-API-Key             from gvm.toml
```

The agent never sees the secret. Even if its memory is dumped, no credentials are exposed.

**Both patterns work — no migration required:**

| Agent code | gvm.toml has host? | What happens |
|-----------|-------------------|--------------|
| No auth header | Yes | Proxy injects managed key |
| Has own auth header | Yes | Proxy **replaces** with managed key |
| Has own auth header | No | Agent's key passes through unchanged |
| No auth header | No | Request sent without auth (API rejects) |

This means existing agents with hardcoded keys work immediately — just add them behind the proxy. When you're ready, move keys to `gvm.toml` (and `chmod 600`) for centralized management. No code changes needed either way.

**Scope and limitations:**
- Credential injection operates at the **HTTP layer** (headers). It cannot inject credentials into request bodies (e.g., GraphQL variables).
- **LLM client libraries** (Anthropic, OpenAI, Cohere, …) require API keys at **client initialization time** (before HTTP requests). The proxy cannot help with library initialization — agents must have the LLM key in their environment (`ANTHROPIC_API_KEY`). Credential injection is for **tool API calls** (Stripe, Slack, GitHub, etc.) that the agent makes via HTTP after receiving tool_use from the LLM.
- For LLM keys, use the standard `ANTHROPIC_API_KEY` environment variable. The proxy governs what the agent *does* with LLM responses, not how it authenticates to the LLM.

---

## 4. Define What's Allowed

### Block by URL Pattern (`gvm.toml` — `[[rules]]`)

Works with any language. No client library needed — the rules are evaluated by the proxy.

```toml
[[rules]]
pattern = "api.bank.com"
path_regex = "/transfer/.*"
method = "POST"
decision = { type = "Deny", reason = "Wire transfers are blocked" }
```

Rules hot-reload — edit `gvm.toml` and run `gvm reload`, the proxy picks up changes immediately.

Decisions available (strictness order): `Allow < AuditOnly < Delay < RequireApproval < Deny`. When multiple rules match, the strictest wins.

---

## 5. Identity for Sandboxed Agents — Automatic

When you launch an agent with `gvm run --sandbox`, the proxy resolves
its identity from the source IP of the veth pair it allocated (the
proxy minted that IP itself, so source spoofing requires breaking out
of the network namespace — the same boundary that already separates
sandboxes from each other). Bare `urllib`, `requests`, `node-fetch`,
or anything else that opens an HTTP socket is automatically attributed
to the right `agent_id` in the audit chain. **No SDK, no header, no
JWT for the agent author to wire up.**

If you also enable JWT-based identity (`GVM_JWT_SECRET` env var,
`[jwt]` config section), the proxy's order of precedence is:

1. Valid `Authorization: Bearer <jwt>` → identity from claims
2. Sandboxed peer (recognized veth IP) → identity from sandbox metadata
3. Self-declared `X-GVM-Agent-Id` header → unverified, dev only
4. None of the above → request flagged as `agent=unknown` in WAL

Production deployments should configure JWT for cooperative-mode
clients and rely on the sandbox-peer fallback for `--sandbox`
agents.

---

## 6. Try the Demo (No API Key Needed)

```bash
cargo run                # Terminal 1: proxy
gvm demo finance         # Terminal 2: pre-scripted agent against the proxy
```

The demo runs 4 pre-scripted actions through the real proxy — read
inbox (Allow), send email (Delay 300ms), wire transfer (Deny), delete
emails (Deny) — and prints a full governance audit. Other scenarios:
`gvm demo assistant`, `gvm demo devops`, `gvm demo data`.

---

## 7. Tamper-Proof Audit (Optional, Recommended for Production)

Every WAL anchor record can be Ed25519-signed by an operator-managed
key. External auditors verify the chain offline using only the matching
public key — no need to trust the runtime.

```bash
# One-time keygen on the operator host
sudo install -d -o gvm -g gvm -m 0700 /etc/gvm
gvm anchor keygen --out /etc/gvm/anchor.key --key-id gvm-prod-1
```

This produces:
- `/etc/gvm/anchor.key` — secret, mode 0600, NEVER committed or distributed
- `/etc/gvm/anchor.key.pub` — public, mode 0644, sent to the auditor

Then in `proxy.toml`:

```toml
[anchor]
enabled = true
key_path = "/etc/gvm/anchor.key"
```

The proxy refuses to start if `enabled = true` but the key file is
missing or malformed (fail-close — operators who turned signing on
cannot accidentally end up with unsigned anchors).

Auditors verify with the public key only:

```bash
gvm audit verify --wal /path/to/wal.log
```

For the full operator checklist (file mode, encryption-at-rest,
backup hygiene, rotation runbook), see
[`config/proxy.production.toml.example`](../config/proxy.production.toml.example).

---

## 8. MCP Integration — Claude Desktop / Cursor

GVM provides MCP tools for AI assistants that support the Model Context
Protocol. This lets Claude Desktop, Cursor, or any MCP-compatible
client govern agent API calls through GVM.

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
# proxy.toml
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
| Configure rules, credentials, budget in `gvm.toml` | [Reference Guide →](reference.md) |
| Understand the architecture | [Architecture Overview →](overview.md) |
| Connect Claude Desktop / Cursor via MCP | [Section 8 above](#8-mcp-integration--claude-desktop--cursor) |
| Write custom SRR rules | [Network SRR →](srr.md) |
| Debug a blocked agent | [User Guide →](user-guide.md) |
| Production deployment | [User Guide →](user-guide.md) and [`config/proxy.production.toml.example`](../config/proxy.production.toml.example) |
| Run tests | `cargo test --workspace --all-targets` |
