# Reference Guide

> Configuration, CLI commands, and advanced options.
> For first-time setup, see [Quick Start →](quickstart.md).

---

## Configuration

GVM uses a single unified config file: `gvm.toml`. Everything the user cares about (rules, credentials, cost budget, filesystem patterns, seccomp) lives there. `proxy.toml` remains as an optional infrastructure-tuning file (server port, WAL paths, NATS, DNS listen port); most users don't need it.

### Config File Location

Load order (first match wins for each concern):

1. `GVM_CONFIG` environment variable (points at `gvm.toml`)
2. `gvm.toml` (current working directory)
3. `~/.config/gvm/gvm.toml`
4. Built-in defaults

Optional `proxy.toml` is loaded from `config/proxy.toml` or `~/.config/gvm/proxy.toml` if present. Fields absent from `proxy.toml` use built-in defaults.

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `GVM_CONFIG` | Path to `gvm.toml` | `gvm.toml` |
| `GVM_ENV` | `production` disables dev features (host overrides) | `development` |
| `GVM_VAULT_KEY` | AES-256 key for Vault encryption (64 hex chars) | Random ephemeral key |
| `GVM_SECRETS_KEY` | Encryption key for credential block in `gvm.toml` | None (plaintext + `0600`) |
| `GVM_PROXY_URL` | Override proxy URL in Python SDK | `http://127.0.0.1:8080` |
| `GVM_SHADOW_MODE` | Shadow Mode: `strict`, `cautious`, `permissive`, `disabled` | `disabled` |
| `RUST_LOG` | Proxy log level | `info` |

### Unified Config (`gvm.toml`)

```toml
# ─── Network rules (SRR) ───
[[rules]]
pattern = "api.anthropic.com"
method = "POST"
decision = { type = "Allow" }

[[rules]]
pattern = "api.github.com/repos/*/pulls/*/merge"
method = "PUT"
decision = { type = "RequireApproval" }

[[rules]]
pattern = "api.github.com/repos/*/git/refs/*"
method = "DELETE"
decision = { type = "Deny", reason = "Branch deletion blocked" }

# ─── API credentials ───
[credentials."api.anthropic.com"]
type = "ApiKey"
header = "x-api-key"
value = "sk-ant-..."

[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_live_..."

# ─── Cost / token budget ───
[budget]
max_tokens_per_hour = 100000
max_cost_per_hour = 1.00

# ─── Filesystem governance ───
[filesystem]
auto_merge = ["*.csv", "*.pdf", "*.txt", "*.png"]
manual_commit = ["*.sh", "*.py", "*.js", "*.json"]
discard = ["/tmp/*", "*.log", "__pycache__/*"]

# ─── Seccomp profile ───
[seccomp]
profile = "default"    # "default" | "strict" | "custom"
# custom_path = "./my-seccomp.json"
```

> **Permissions:** `gvm.toml` must be `0600` when credentials are present (checked at load). Use `GVM_SECRETS_KEY` to encrypt the credential block for production.

### Infrastructure Tuning (`config/proxy.toml`, optional)

```toml
[server]
listen = "0.0.0.0:8080"

[enforcement]
default_decision = { type = "Delay", milliseconds = 300 }  # Fail-Close default
ic1_async_ledger = true       # Async WAL for IC-1 reads (higher throughput)
ic1_loss_threshold = 0.001    # Tolerate 0.1% WAL loss for IC-1

# DNS governance (Layer 0). Default: enabled.
[dns]
enabled = true
listen_port = 5353

# Dev-only: remap hosts to local mock server. Ignored when GVM_ENV=production.
[dev]
host_overrides = { "gmail.googleapis.com" = "127.0.0.1:9090" }
```

Fields not listed here (NATS, Redis URLs, JWT keys, WAL tuning) retain built-in defaults. See `src/config.rs` for the complete schema.

---

## Credential Types

Credentials live under `[credentials."<host>"]` in `gvm.toml`:

```toml
[credentials."api.slack.com"]
type = "Bearer"
token = "xoxb-your-slack-token"

[credentials."api.stripe.com"]
type = "ApiKey"
header = "Authorization"
value = "Bearer sk_test_your-stripe-key"

[credentials."api.google.com"]
type = "OAuth2"
access_token = "ya29.access-token"
refresh_token = "1//refresh-token"
expires_at = "2026-12-31T00:00:00Z"
```

### Missing Credential Policy

- **Development** (default `Passthrough`): No credential configured → request passes through as-is
- **Production** (`Deny`): No credential → request rejected. Prevents agents from using their own keys.

In production, set `GVM_SECRETS_KEY` to encrypt the credential block. Plaintext is for development only and requires `chmod 600 gvm.toml`.

---

## Decision Reference

### Decision Types

Strictness order (total): `Allow (0) < AuditOnly (1) < Delay (2) < RequireApproval (3) < Deny (4)`.

| Type | Fields | Behavior |
|------|--------|----------|
| `Allow` | — | Pass through; async WAL write |
| `AuditOnly` | — | Pass through; synchronous WAL write before forwarding |
| `Delay` | `milliseconds` | WAL-first write, wait, then forward |
| `RequireApproval` | `urgency?` | Hold on admin port; `gvm approve` or timeout (503) |
| `Deny` | `reason` | Block with 403 |

SRR is the sole enforcement layer on Layer 1. Decisions are deterministic — same request → same decision.

---

## SDK Reference

### GVMAgent Constructor

```python
GVMAgent(
    agent_id="finance-001",           # Required
    tenant_id="acme",                 # Optional: org-scoped tag for audit correlation
    session_id="custom-session",      # Optional: auto-generated if omitted
    proxy_url="http://custom:8080",   # Optional: overrides GVM_PROXY_URL
    auto_checkpoint="ic2+",           # Optional: None | "ic2+" | "ic3" | "all"
    max_history_turns=100,            # Optional: default 50
)
```

### `@ic` Decorator

```python
@ic(
    operation="gvm.payment.charge",     # Auto-generated if omitted
    checkpoint=True,                    # Force checkpoint (optional)
)
```

The decorator attaches operation metadata and optionally snapshots agent state for rollback. Enforcement decisions come from SRR on the proxy — the decorator does not evaluate policy.

### Error Hierarchy

```
GVMError                         # Base
├── GVMDeniedError               # 403 — Deny decision
├── GVMApprovalRequiredError     # 403 — RequireApproval
└── GVMRollbackError             # 403 — Denied + state rolled back
    ├── .operation               # Blocked operation name
    ├── .reason                  # Why it was blocked
    └── .rolled_back_to          # Checkpoint step restored to
```

All exceptions include `event_id` for audit trail correlation.

### Checkpoint Modes

| Mode | Checkpoints before |
|------|--------------------|
| `None` | Never (use `@ic(checkpoint=True)` per-operation) |
| `"all"` | Every `@ic` operation |

Limits: 5MB per checkpoint, 10 retained, conversation history truncated to `max_history_turns`.

---

## CLI Reference

All commands read from the WAL — no separate database required. Use `--wal-file data/wal.log` if NATS is not connected.

### Events

```bash
gvm events list                                    # Last 1 hour
gvm events list --agent agent-001 --last 24h       # Filter by agent + time
gvm events list --decision Deny --last 7d          # Filter by decision
gvm events list --format json --wal-file data/wal.log  # JSON from WAL

gvm events trace --trace-id abc123                 # Causal chain visualization
```

### Stats

```bash
gvm stats tokens --agent agent-001 --since 24h     # Per-agent token usage
gvm stats rollback-savings --since 7d               # Tokens saved by governance
```

### Audit

```bash
gvm audit verify --wal data/wal.log                # WAL integrity check
gvm audit export --wal data/wal.log --format jsonl  # Export events
```

### Policy Tools

```bash
gvm check --operation gvm.payment.charge \
  --service stripe --tier external --sensitivity critical \
  --host api.bank.com --method POST                # Dry-run policy check

gvm init --industry finance --config-dir config    # Scaffold from template
```

### Agent Observation

```bash
gvm run --watch agent.py                   # Observe all API calls (no enforcement)
gvm run --watch -- node my_agent.js        # Binary mode observation
gvm run --watch --with-rules agent.py      # Observe with existing SRR rules active
gvm run --watch --output json agent.py     # JSON output for CI/CD piping
gvm run --watch --sandbox agent.py         # Observe inside Linux sandbox
```

> `gvm watch` is a hidden alias for `gvm run --watch`. Both are identical. All agent execution uses `gvm run` with flags.

Watch mode runs the agent with all requests allowed through (default). No SRR rules are enforced unless `--with-rules` is set. Provides:
- **Real-time stream**: every HTTP request displayed as it happens (method, host, path, status, token usage)
- **Session summary**: host breakdown, LLM token/cost stats, status code distribution, anomaly warnings
- **Anomaly detection**: burst patterns (>10 req/2s), request loops (same URL >5x/10s), unknown hosts
- **Cost estimation**: approximate USD cost based on LLM provider/model token pricing
- **`--output json`**: all events as JSON lines + session summary as JSON object (for piping to `jq`, CI, etc.)

Watch mode generates a temporary allow-all SRR config in the OS temp directory and reloads the proxy via `POST /gvm/reload`. The original SRR rules are restored when watch exits. The user's `gvm.toml` is never modified.

### Agent Execution

```bash
gvm run agent.py                     # Basic
gvm run --agent-id custom-id agent.py  # Custom audit identity
gvm run -i agent.py                  # Interactive: suggest rules after run
gvm run --sandbox agent.py           # Linux namespace isolation
gvm run --contained agent.py         # Docker isolation
gvm run --contained --detach agent.py  # Docker in background

# Binary mode: run any command through GVM proxy
gvm run -- openclaw gateway            # Arbitrary binary + args
gvm run --sandbox -- openclaw gateway  # Binary in Linux sandbox
```

### Sandbox Cleanup

```bash
gvm cleanup              # Remove orphaned sandbox resources
gvm cleanup --dry-run    # Show what would be cleaned (no action)
```

Scans for per-PID state files (`/run/gvm/gvm-sandbox-{pid}.state`) from previously crashed sandbox sessions. If the owning PID is dead, cleans up all listed resources: veth interfaces, iptables DNAT/FORWARD rules, mount paths, and cgroup directories. Also removes any `veth-gvm-*` interfaces without corresponding state files (defense-in-depth). Legacy state files in `/tmp` are auto-migrated on first scan.

Auto-cleanup also runs at the start of every `gvm run --sandbox` — you only need `gvm cleanup` for manual recovery after abnormal termination without a subsequent sandbox launch.

### Binary Mode (`gvm run -- <command>`)

When the argument after `--` is not a recognized script file (`.py`, `.js`, `.ts`, `.sh`, `.bash`) or when multiple arguments follow `--`, `gvm run` enters **binary mode**. The specified command is executed with `HTTP_PROXY` and `HTTPS_PROXY` set to route all outbound traffic through the GVM proxy.

Binary mode provides full SRR enforcement (URL/method/payload matching). No SDK headers are injected; all audit output goes to stderr to keep stdout clean for piping.

With `--sandbox`, binary mode uses Linux-native isolation (namespaces + seccomp + veth + TC filter) — the same security layers as script sandbox mode.

---

## Proxy API Endpoints

Management endpoints served directly by the proxy under `/gvm/`.

### `POST /gvm/reload`

Hot-reload SRR rules from the config file. Atomically swaps the rule set. On parse failure, existing rules are preserved and an error is returned.

| Field | Value |
|-------|-------|
| Method | POST |
| Body | None |
| Success | `200 {"reloaded": true, "rules": <count>}` |
| Parse failure | `400 {"reloaded": false, "error": "..."}` |

### `POST /gvm/intent`

Register a Shadow Mode intent for pre-flight verification. MCP tools or SDK call this before the agent makes an outbound HTTP request.

| Field | Value |
|-------|-------|
| Method | POST |
| Body | `{"method", "host", "path", "operation", "agent_id", "ttl_secs?"}` |
| Success | `201 {"registered": true, "intent_id": <id>, ...}` |
| Capacity exceeded | `429 {"error": "Intent store full"}` |

### `POST /gvm/check`

Dry-run policy evaluation. Evaluates SRR without forwarding, WAL writing, or credential injection.

| Field | Value |
|-------|-------|
| Method | POST |
| Body | `{"operation", "target_host", "target_path", "method", "resource?"}` |
| Success | `200 {"decision", "srr_decision", "engine_ms", "matched_rule", "dry_run": true}` |

---

## Shadow Mode

Shadow Mode adds 2-phase intent verification. Agents declare intent before making API calls; the proxy verifies the match.

### Environment Variable

```
GVM_SHADOW_MODE=strict|cautious|permissive|disabled
```

| Mode | Unverified request behavior |
|------|-----------------------------|
| `strict` | Deny (HTTP 403) |
| `cautious` | Delay (default 5000ms) + audit warning |
| `permissive` | Allow + audit warning |
| `disabled` | No verification (default) |

### Configuration (`proxy.toml`)

```toml
[shadow]
mode = "strict"
intent_ttl_secs = 30        # Intent expiry
cautious_delay_ms = 5000    # Delay for cautious mode
```

---

## SandboxConfig Fields

Configuration fields for `gvm run --sandbox` (Linux-native isolation). Defined in `crates/gvm-sandbox/src/lib.rs`.

| Field | Type | Description |
|-------|------|-------------|
| `script_path` | `PathBuf` | Absolute path to the agent script or binary |
| `workspace_dir` | `PathBuf` | Directory exposed inside the sandbox (read-only bind mount) |
| `interpreter` | `String` | Interpreter or binary to execute (python, node, bash, or binary path) |
| `interpreter_args` | `Vec<String>` | Arguments passed to the interpreter |
| `proxy_addr` | `SocketAddr` | GVM proxy address for the veth network route |
| `agent_id` | `String` | Agent ID injected as environment variable |
| `seccomp_profile` | `Option<SeccompProfile>` | Seccomp profile override (None = default whitelist) |
---

## Platform Support

| Platform | Proxy | SDK | `--sandbox` | `--contained` |
|----------|-------|-----|-------------|---------------|
| Linux | Native | Native | **Production** (with MITM) | **Production** (no MITM) |
| Windows (WSL2) | Native | Native | Not supported | **Production** (run gvm from WSL2) |
| Windows (native) | Native | Native | Not supported | Cooperative fallback |
| macOS | Native | Native | Not supported | Cooperative fallback |

> **`--contained` design**: Host-side iptables on a dedicated `gvm-docker-{slot}` bridge force all container egress through the proxy port. Non-cooperative HTTP clients (Node.js raw `https`, raw sockets) that would bypass `HTTP_PROXY` are dropped at the host. No MITM — use `--sandbox` on Linux for HTTPS payload inspection.
>
> **Cooperative fallback** (native Windows / macOS): Docker Desktop's host VM iptables is inaccessible to `gvm`, so Docker mode sets `HTTP_PROXY` only. Non-cooperative clients can bypass — the same caveat as plain cooperative mode. For guaranteed enforcement on Windows, run `gvm` from WSL2.

### Sandbox Prerequisites (Linux only)

- `kernel.unprivileged_userns_clone=1`
- `CAP_NET_ADMIN` for `gvm run`
- `ip` and `iptables` in `PATH`
- `net.ipv4.ip_forward=1`

---

## LLM Provider Governance

Proxy-level inspection of LLM API calls — no SDK needed:

- **Model pinning**: Whitelist allowed models via `payload_field = "model"` in SRR rules
- **Endpoint restriction**: Allow `chat/completions` only, block `fine-tuning`
- **Provider allowlist**: Block unauthorized providers
- **Thinking trace audit**: SHA-256 hash of reasoning content stored in WAL

See [`gvm.toml`](../gvm.toml) for the full rule set.

---

## Operational Notes

### Proxy Lifecycle

The proxy runs as an independent daemon managed by `proxy_manager`:
- **Auto-start**: `gvm run` and `gvm watch` start the proxy automatically if not running
- **PID file**: `data/proxy.pid` — enables reuse across CLI invocations
- **Logs**: `data/proxy.log` (append mode)
- **Survival**: Proxy survives CLI exit (setsid daemon). Kill explicitly with `kill $(cat data/proxy.pid)`
- **Sudo**: When run via `sudo gvm run --sandbox`, the proxy drops to the original user (SUDO_UID)

### WAL Management

**Do NOT delete `data/wal.log` while the proxy is running.** The proxy holds an open file descriptor to the WAL. Deleting the file removes the directory entry but the proxy continues writing to the deleted inode — new data is lost.

To reset the WAL:
1. Stop the proxy: `kill $(cat data/proxy.pid)`
2. Delete or truncate: `> data/wal.log`
3. Restart: `gvm run ...` (auto-starts proxy)

Or truncate in-place (proxy detects size decrease): `> data/wal.log`

WAL rotation is automatic when `max_wal_bytes` is configured in `proxy.toml`.

### Sandbox Cleanup

Sandbox resources (veth, iptables, cgroups, mounts) are cleaned up automatically:
- **Normal exit**: RAII guards in `sandbox_impl.rs`
- **Crash/SIGKILL**: State file (`/run/gvm/gvm-sandbox-{pid}.state`) enables cleanup on next `gvm run --sandbox`
- **Manual**: `gvm cleanup` scans for orphaned resources
- **ip_forward**: Restored to original value when last sandbox exits

### Filesystem Governance (Trust-on-Pattern)

Two filesystem modes for sandbox:

**Legacy mode** (default — no `--fs-governance`):
```bash
gvm run --sandbox agent.py
```
- Agent can only write to `workspace/output/` directory
- All other paths are read-only
- Simple and safe — no file review needed
- Agent results are in `output/` immediately

**Governance mode** (`--fs-governance`):
```bash
gvm run --sandbox --fs-governance agent.py
```
- Agent can write anywhere in workspace (overlayfs copy-on-write)
- Writes are captured in an overlay layer, not applied directly
- At session end, changes are classified by Trust-on-Pattern:

| Change Type | Pattern Match | Action |
|------------|---------------|--------|
| **Created** file | `*.csv, *.pdf, *.txt, *.png` | **Auto-merge** → copied to workspace |
| **Created** file | `*.sh, *.py, *.js, *.json` | **ManualCommit** → review prompt |
| **Created** file | `*.log, __pycache__/*` | **Discarded** |
| **Modified** file | (any pattern) | **ManualCommit** → always needs approval |
| **Deleted** file | (any pattern) | **ManualCommit** → never auto-deleted |

Safety principles:
- **Created** files with safe extensions auto-merge (no overwrite risk)
- **Modified** files always require approval (protects existing workspace)
- **Deleted** files are never auto-executed (agent cannot delete host files)
- **Symlinks** targeting outside workspace are rejected
- **Path traversal** (`../`) is blocked

**Interactive review** (TTY):
When `--fs-governance` produces ManualCommit files and stdin is a terminal, a review prompt appears:
```
[1/2] analysis.py (Created, 2KB)
+#!/usr/bin/env python3
+import pandas as pd
... (8 more lines)

(a)ccept  (r)eject  (s)kip all →
```

**CI/CD** (non-TTY):
ManualCommit files are staged to `data/sandbox-staging/{pid}/` with instructions to review later:
```
Files staged at: data/sandbox-staging/12345/
Review and approve: gvm fs approve
```

**Configuration** (`proxy.toml`):
```toml
[sandbox]
filesystem_governance = true   # Override CLI default (false)
```
CLI `--fs-governance` flag overrides config.

**Custom patterns**:
Default patterns can be overridden in `proxy.toml`:
```toml
[sandbox.filesystem_policy]
auto_merge = ["*.csv", "*.pdf", "*.txt", "*.png", "*.xml", "*.md"]
manual_commit = ["*.sh", "*.py", "*.js", "*.json", "*.toml", "*.yaml"]
discard = ["/tmp/*", "*.log", "__pycache__/*", ".git/*"]
default = "manual_commit"   # For files matching no pattern
```

### Policy Check (`gvm check`)

Dry-run policy evaluation — tests what decision the proxy would make without sending real requests. Uses the same `enforcement::classify()` code path as the live proxy, guaranteeing check results match real enforcement.

```bash
gvm check --operation gvm.payment.charge --host api.bank.com --method POST
gvm check --agent-id finance-001 --operation gvm.storage.read --host s3.amazonaws.com
gvm check --operation test --host api.github.com --method GET --path /repos
```

Output includes **decision path** (`Policy(Allow) + SRR(Deny) → Final(Deny)`), matched rule, and engine latency in microseconds.

### CI/CD Policy Validation

Run `gvm check` in CI pipelines to catch unintended permission changes before deployment:

```yaml
# GitHub Actions example
- name: Validate governance policies
  run: |
    gvm-proxy &
    sleep 2
    # Verify critical endpoints are blocked
    gvm check --operation gvm.payment.charge --host api.bank.com --method POST \
      | grep -q "Deny" || (echo "FAIL: payment endpoint not blocked" && exit 1)
    # Verify read access is allowed
    gvm check --operation gvm.storage.read --host api.github.com --method GET \
      | grep -q "Allow" || (echo "FAIL: read access blocked" && exit 1)
    # Test agent-specific policies
    gvm check --agent-id finance-001 --operation gvm.payment.charge --host api.bank.com \
      | grep -q "RequireApproval" || (echo "FAIL: finance agent should require approval" && exit 1)
```

This catches policy regressions: adding a new SRR rule that accidentally opens access, or changing rule ordering so a stricter rule becomes unreachable.

### Proxy Status

```bash
gvm status                          # Show proxy health, rules, WAL state
gvm status --proxy http://host:8080 # Custom proxy URL
```

Returns proxy health, SRR rule count, WAL status, emergency write count, and Shadow Mode state.

### Sandbox Options

| Flag | Description |
|------|-------------|
| `--sandbox` | Linux namespace + seccomp + MITM isolation |
| `--no-mitm` | Disable MITM TLS inspection. HTTPS uses CONNECT relay (domain-level only). Use for mTLS endpoints or certificate pinning. |
| `--sandbox-timeout N` | Kill agent after N seconds (default: 3600) |
| `--fs-governance` | Enable overlayfs Trust-on-Pattern file governance |
| `--no-dns-governance` | Disable DNS governance proxy (Layer 0). Use when dedicated DNS security tools (Route 53 Firewall, Cloudflare Gateway) are already in place. Default: DNS governance enabled. |
| `--shadow-mode MODE` | `disabled` (default), `observe`, or `strict` |
| `--memory 512m` | cgroup v2 memory limit |
| `--cpus 1.0` | cgroup v2 CPU limit |

### Config File Security

On startup, GVM checks `gvm.toml` file permissions (Unix only) when credentials are present. If group or other users have read access (`mode & 0o077 != 0`), GVM:
1. Logs a warning: `gvm.toml has insecure permissions`
2. Attempts auto-fix to `0600` (owner read/write only)
3. If fix fails, continues with a warning (does not block startup)

Best practice: `chmod 600 gvm.toml` before first use.

---

[← Quick Start](quickstart.md) | [Architecture Overview →](overview.md)
