# Reference Guide

> Configuration, CLI commands, and advanced options.
> For first-time setup, see [Quick Start →](quickstart.md).

---

## Configuration

GVM uses a single unified config file: `gvm.toml`. Everything the user cares about (rules, credentials, cost budget, filesystem patterns, seccomp) lives there. `proxy.toml` remains as an optional infrastructure-tuning file (server port, WAL paths, JWT/anchor key paths, DNS listen port); most users don't need it.

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
| `GVM_PROXY_URL` | Proxy URL hint published by `gvm run` to the agent's environment (e.g. `HTTP_PROXY=$GVM_PROXY_URL`) | `http://127.0.0.1:8080` |
| `GVM_JWT_SECRET` | HMAC-SHA256 secret (hex, ≥ 32 bytes) — enables JWT identity verification | None (JWT disabled) |
| `GVM_JWT_TOKEN` | JWT issued by `gvm run` and exposed inside the agent's environment | None |
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

# JWT identity (recommended for production cooperative-mode clients;
# sandboxed agents are covered automatically by source-IP attribution)
[jwt]
secret_env     = "GVM_JWT_SECRET"
token_ttl_secs = 3600

# Ed25519 anchor signing (every WAL anchor record is signed; auditors
# verify offline with the matching .pub file). Generate the key with
# `gvm anchor keygen --out /etc/gvm/anchor.key --key-id <stable-label>`.
# Proxy refuses to start if enabled = true and the file is missing or
# malformed (fail-close).
[anchor]
enabled  = true
key_path = "/etc/gvm/anchor.key"

# Dev-only: remap hosts to local mock server. Ignored when GVM_ENV=production.
[dev]
host_overrides = { "gmail.googleapis.com" = "127.0.0.1:9090" }
```

Fields not listed here (WAL tuning, IC-3 timeout, etc.) retain
built-in defaults. See `src/config.rs` for the complete schema.

> **External streaming integrations are operator-managed.** GVM does
> not connect to NATS, Redis, Kafka, or SIEM systems on the
> operator's behalf — the local WAL is the single source of truth.
> For off-host audit replication, tail `data/wal.log` with rsync,
> fluentd, vector, syslog, or your S3 backup tool. Older
> `proxy.toml` files with `[nats]` / `[redis]` sections still load
> without erroring; the values are silently ignored.

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

## Agent integration — what your code needs

**Nothing.** Governance is enforced at the proxy. Plain `requests`,
`urllib`, `node-fetch`, `curl`, or any HTTP/HTTPS client works
unmodified — the proxy classifies and enforces every request that
passes through it.

The only situation where the agent's process needs to read anything
GVM-specific is when JWT identity is enabled in cooperative mode
(non-sandboxed). In that case the CLI exposes the agent's JWT as
`GVM_JWT_TOKEN` in the environment, and the agent's HTTP client
must add `Authorization: Bearer $GVM_JWT_TOKEN` to outbound
requests. See [User Guide → Identity verification](user-guide.md)
for the minimal Python / Node snippets.

For sandboxed agents (`gvm run --sandbox`), even that is not
required: the proxy resolves identity from the source IP of the
veth pair it allocated, so plain HTTP clients are correctly
attributed in the audit chain with zero code changes.

A response carries the proxy's decision in HTTP headers that the
agent's HTTP library treats as ordinary 403/200 responses:

```
X-GVM-Decision: Deny | Allow | RequireApproval | Delay | AuditOnly
X-GVM-Event-Id: <uuid>
X-GVM-Block-Reason: <human-readable reason, on Deny only>
```

Catch HTTP status codes the way you would for any external API
(`requests.HTTPError`, `fetch().ok === false`, etc.) — there is no
GVM-specific exception type to import.

---

## CLI Reference

All commands read from the WAL — no separate database required.
Use `--wal-file data/wal.log` to point at a non-default location.

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
gvm run agent.py                            # Basic (cooperative, no sudo)
gvm run --agent-id custom-id agent.py       # Custom audit identity
gvm run -i agent.py                         # Interactive: suggest rules after run
sudo gvm run --sandbox agent.py             # Linux namespace + seccomp + MITM (recommended for production; root required)

# Binary mode: run any command through GVM proxy
gvm run -- openclaw gateway                 # Arbitrary binary + args (cooperative)
sudo gvm run --sandbox -- openclaw gateway  # Binary in Linux sandbox
```

> **`--contained` (Docker isolation)** is gated behind
> `cargo build --features contained` and is not in the default
> binary. The default `gvm run --help` does not advertise it.
> See [Platform Support](#platform-support) for the current
> readiness of that mode.

### Sandbox Cleanup

```bash
gvm cleanup              # Remove orphaned sandbox resources
gvm cleanup --dry-run    # Show what would be cleaned (no action)
```

Scans for per-PID state files (`/run/gvm/gvm-sandbox-{pid}.state`) from previously crashed sandbox sessions. If the owning PID is dead, cleans up all listed resources: veth interfaces, iptables DNAT/FORWARD rules, mount paths, and cgroup directories. Also removes any `veth-gvm-*` interfaces without corresponding state files (defense-in-depth). Legacy state files in `/tmp` are auto-migrated on first scan.

Auto-cleanup also runs at the start of every `gvm run --sandbox` — you only need `gvm cleanup` for manual recovery after abnormal termination without a subsequent sandbox launch.

### Binary Mode (`gvm run -- <command>`)

When the argument after `--` is not a recognized script file (`.py`, `.js`, `.ts`, `.sh`, `.bash`) or when multiple arguments follow `--`, `gvm run` enters **binary mode**. The specified command is executed with `HTTP_PROXY` and `HTTPS_PROXY` set to route all outbound traffic through the GVM proxy.

Binary mode provides full SRR enforcement (URL/method/payload matching). All audit output goes to stderr to keep stdout clean for piping.

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

Register a Shadow Mode intent for pre-flight verification. MCP tools (or any pre-call gate) call this before the agent's outbound HTTP request.

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

| Platform | Proxy | `--sandbox` |
|----------|-------|-------------|
| Linux | Native | **Production** (kernel namespaces + seccomp + MITM) |
| Windows (WSL2) | Native | Not supported (use Linux directly inside WSL2) |
| Windows (native) | Native | Not supported (proxy enforces, no kernel-level isolation) |
| macOS | Native | Not supported (proxy enforces, no kernel-level isolation) |

On non-Linux hosts, the cooperative HTTP-proxy mode still enforces
SRR rules and credential injection — only kernel-level isolation is
unavailable. For production isolation use Linux + `--sandbox`.

> **`--contained` (Docker isolation)** is gated behind the
> `contained` cargo feature and **not** in the default binary.
> Default builds do not show `--contained` in `gvm run --help`.
> The mode is unfinished: the in-container DNAT to MITM, runtime
> CA injection, and `HTTPS_PROXY` env handling are not yet wired,
> so transparent HTTPS interception inside the container does not
> work today. Builds that opt into Docker isolation
> (`cargo build --release --features contained`) get the host-side
> iptables egress lock as the only governance signal in the
> container; agents that don't honour `HTTP_PROXY` are dropped by
> the lock rather than transparently redirected. For HTTPS L7
> inspection use `--sandbox` on Linux.

### Sandbox Prerequisites (Linux only)

- `kernel.unprivileged_userns_clone=1`
- `CAP_NET_ADMIN` for `gvm run`
- `ip` and `iptables` in `PATH`
- `net.ipv4.ip_forward=1`

---

## LLM Provider Governance

Proxy-level inspection of LLM API calls — no client library required:

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
sudo gvm run --sandbox agent.py
```
- Agent can only write to `workspace/output/` directory
- All other paths are read-only
- Simple and safe — no file review needed
- Agent results are in `output/` immediately

**Governance mode** (`--fs-governance`):
```bash
sudo gvm run --sandbox --fs-governance agent.py
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
