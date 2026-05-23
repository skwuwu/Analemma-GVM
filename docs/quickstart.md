# Quick Start

**Zero code changes. Your agent doesn't know it's being governed.**

Governance is enforced by a Rust proxy in front of your agent. There is
no Python SDK to import, no decorator to add, no client library to wrap
your code. Plain `requests`, `urllib`, `node-fetch`, `curl`, or anything
else that talks HTTP/HTTPS works unmodified.

---

## 1. Install

GVM ships as two pre-built Rust binaries (`gvm` and `gvm-proxy`) on the [Releases page](https://github.com/skwuwu/Analemma-GVM/releases). Pick your platform, download, extract, install — no Docker, no Kubernetes, no Python runtime, no compiler. Total disk: ~35 MB on Linux, ~29 MB on Windows.

### Linux x86_64 (production target)

```bash
VERSION=v0.5.3
curl -LO https://github.com/skwuwu/Analemma-GVM/releases/download/${VERSION}/gvm-${VERSION}-x86_64-unknown-linux-gnu.tar.gz
tar xzf gvm-${VERSION}-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  gvm-${VERSION}-x86_64-unknown-linux-gnu/gvm \
  gvm-${VERSION}-x86_64-unknown-linux-gnu/gvm-proxy \
  /usr/local/bin/
```

### macOS (Apple Silicon / Intel)

```bash
VERSION=v0.5.3
ARCH=$(uname -m | sed 's/arm64/aarch64/;s/x86_64/x86_64/')
curl -LO https://github.com/skwuwu/Analemma-GVM/releases/download/${VERSION}/gvm-${VERSION}-${ARCH}-apple-darwin.tar.gz
tar xzf gvm-${VERSION}-${ARCH}-apple-darwin.tar.gz
sudo install -m 0755 \
  gvm-${VERSION}-${ARCH}-apple-darwin/gvm \
  gvm-${VERSION}-${ARCH}-apple-darwin/gvm-proxy \
  /usr/local/bin/
```

### Windows x86_64

Download `gvm-v0.5.3-x86_64-pc-windows-msvc.zip` from the Releases page, extract, and add the directory containing `gvm.exe` and `gvm-proxy.exe` to your `PATH`.

### From source (any platform with Rust)

```bash
cargo install --git https://github.com/skwuwu/Analemma-GVM gvm-proxy
cargo install --git https://github.com/skwuwu/Analemma-GVM gvm-cli
```

Verify:

```bash
$ gvm --version
gvm 0.5.3
```

You don't need to start `gvm-proxy` yourself — `gvm run` autostarts it on first use, reuses it across invocations, and writes its PID + log under `data/proxy.{pid,log}` (or under `$GVM_WORKSPACE` if set). Manual `gvm-proxy &` invocations are never needed.

---

## 2. First Run — Pick a Starter Ruleset

The first `gvm run` from a directory without `config/proxy.toml` (or `gvm.toml`) drops you into an interactive industry-template chooser:

```
  ⚡ First Run Detected

  No governance rules found. GVM needs a ruleset to enforce policies.
  Choose an industry template to get started:

    1  finance  — Wire transfers blocked, payments need IC-3 approval
    2  saas     — Default-to-Caution, balanced security for SaaS agents
    3  Skip     — Exit and configure manually

  Select [1/2/3]:
```

Choosing `1` or `2` copies `config/templates/<industry>/{proxy.toml,srr_network.toml}` into the working directory and continues the proxy boot. **In CI / non-interactive shells the prompt is skipped** — wire it explicitly with `gvm init --industry saas` (or `--industry finance`) before running.

To pick the workspace explicitly (for example when the operator's CWD doesn't match the install layout) use the [`GVM_WORKSPACE` / `GVM_CONFIG`](reference.md) env vars; the proxy resolves them in that order before falling back to CWD walk-up.

---

## 3. Run Your Agent

### Linux production — sandbox mode (recommended)

`--sandbox` activates kernel-level isolation: user/PID/mount/network namespaces, seccomp-BPF (~130 syscalls), per-sandbox MITM CA, iptables DNAT to the proxy. This is the only mode where the agent **cannot** bypass the proxy regardless of what its HTTP library does. Requires root because namespace + iptables setup needs CAP_SYS_ADMIN / CAP_NET_ADMIN:

```bash
sudo gvm run --sandbox my_agent.py
```

What you'll see:

```
  Analemma GVM — Sandbox Mode (Layer 2 + 3)
  Kernel isolation: namespace + seccomp + veth + TC filter.

  Agent ID:     agent-001
  Command:      python3 my_agent.py
  Proxy:        http://127.0.0.1:8080

  Proxy not reachable at http://127.0.0.1:8080. Starting...
  Binary: /usr/local/bin/gvm-proxy
  Proxy started (PID 1653340)
  ✓ Per-sandbox MITM CA provisioned (sandbox_id=1e530789, ca=6625dd29)

  Security layers active:
    ✓ Layer 2: Enforcement Proxy
    ✓ Layer 3: Linux Namespace Isolation
      • PID namespace: isolated process tree
      • Mount namespace: minimal rootfs
      • Network namespace: veth pair, proxy-only routing
      • Seccomp-BPF: syscall whitelist
      • Transparent MITM: ephemeral CA, full L7 HTTPS inspection

  --- Output below ---
  hello from my_agent.py

  Cleanup verified: network, mounts, cgroup, state file all clean.
  Process completed successfully

  GVM Audit Trail — 4 events captured
  ✓ Allow       GET  gmail.googleapis.com
  ⏱ Delay  300  POST api.unknown.com
  ✗ Deny        POST api.bank.com/transfer
  ✗ Deny        DELETE prod-db/users
  1 allowed  1 delayed  2 blocked
```

### Cooperative mode (macOS, Windows, dev)

Sandbox mode is Linux-only (relies on namespaces + iptables DNAT). On macOS, Windows, or for fast dev iteration on Linux, drop the `--sandbox` flag — no `sudo` needed:

```bash
gvm run my_agent.py
```

Cooperative mode injects `HTTP_PROXY` / `HTTPS_PROXY` into the agent's environment and trusts the agent's HTTP library to honour them. SRR rules, audit, credential injection still apply — only kernel-level isolation is unavailable. Don't use cooperative mode for untrusted agents in production: a non-cooperating client can `unset HTTP_PROXY` and bypass the proxy.

### `--contained` (Docker isolation)

Gated behind `cargo build --features contained`. Not in the default binary surface — does not appear in `gvm run --help` on a stock release. Experimental: in-container DNAT to MITM and CA injection aren't wired yet. For full HTTPS L7 inspection, use `--sandbox`.

---

## 4. Secret Injection — Stop Passing API Keys to Agents

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

## 5. Define What's Allowed

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

## 6. Identity for Sandboxed Agents — Automatic

When you launch an agent with `gvm run --sandbox`, the proxy resolves
its identity from the source IP of the veth pair it allocated (the
proxy minted that IP itself, so source spoofing requires breaking out
of the network namespace — the same boundary that already separates
sandboxes from each other). Bare `urllib`, `requests`, `node-fetch`,
or anything else that opens an HTTP socket is automatically attributed
to the right `agent_id` in the audit chain. **No SDK, no header, no
JWT for the agent author to wire up.**

If you also enable JWT-based identity (`GVM_JWT_ED25519_SEED` env var
+ `[jwt] algorithm = "ed25519"` config — HS256/HMAC was removed in
v1.6), the proxy's order of precedence is:

1. Valid `Authorization: Bearer <jwt>` → identity from claims
2. Sandboxed peer (recognized veth IP) → identity from sandbox metadata
3. Self-declared `X-GVM-Agent-Id` header → unverified, dev only
4. None of the above → request flagged as `agent=unknown` in WAL

Token issuance (`POST /gvm/auth/token`) lives on the **admin port**
(`127.0.0.1:9090` by default, loopback-only). The CLI uses it
automatically; if you script against it, ensure your bootstrap can
reach the admin port. When `admin_listen` is non-loopback, the
proxy auto-enables the JWT middleware and prints a one-shot
bootstrap admin token to stderr — capture it on first launch and
`export GVM_ADMIN_TOKEN=<token>` for subsequent CLI calls.

Production deployments should configure JWT for cooperative-mode
clients and rely on the sandbox-peer fallback for `--sandbox`
agents.

---

## 7. Try the Demo (No API Key Needed)

```bash
cargo run                # Terminal 1: proxy
gvm demo finance         # Terminal 2: pre-scripted agent against the proxy
```

The demo runs 4 pre-scripted actions through the real proxy — read
inbox (Allow), send email (Delay 300ms), wire transfer (Deny), delete
emails (Deny) — and prints a full governance audit. Other scenarios:
`gvm demo assistant`, `gvm demo devops`, `gvm demo data`.

---

## 8. Tamper-Proof Audit (Optional, Recommended for Production)

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

## 9. Multi-Agent Production (systemd)

When running more than a couple of agents on a Linux box, prefer systemd over hand-launching `gvm run` in a shell. Two unit files ship in the repo (`packaging/systemd/`):

- `gvm-cleanup.service` — boot-time orphan-resource sweep (veth, iptables, mounts, cgroups). `Type=oneshot`, blocks `multi-user.target` until clean.
- `gvm-sandbox@.service` — per-agent template. `systemctl start gvm-sandbox@my-agent` runs `/etc/gvm/agents/my-agent.py` under `gvm run --sandbox`. `Restart=on-failure`, 5s backoff, capped at 3 restarts/min so a wedged agent can't busy-loop the host. `gvm cleanup` runs on `ExecStartPre` and `ExecStopPost` so kernel state is reclaimed deterministically across crashes.

Install:

```bash
sudo install -m 0644 \
  packaging/systemd/gvm-cleanup.service \
  packaging/systemd/gvm-sandbox@.service \
  /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now gvm-cleanup.service
sudo systemctl start gvm-sandbox@my-agent.service
sudo journalctl -u gvm-sandbox@my-agent.service -f
```

Override the agent script path per-instance via a drop-in:

```bash
sudo systemctl edit gvm-sandbox@my-agent.service
# In the editor:
#   [Service]
#   Environment=AgentScript=/opt/agents/custom/path.py
```

Full unit-file commentary (why `StartLimitIntervalSec` lives in `[Unit]`, why `gvm cleanup` runs both pre-start and post-stop, etc.) is inline in the unit files themselves.

---

## 10. MCP Integration — Claude Desktop / Cursor

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
