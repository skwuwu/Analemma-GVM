# Reference Guide

> Configuration, CLI commands, and advanced options.
> For first-time setup, see [Quick Start →](12-quickstart.md).

---

## Configuration

### Config File Location

The proxy loads configuration in this order (first match wins):

1. `GVM_CONFIG` environment variable
2. `config/proxy.toml` (current working directory)
3. `~/.config/gvm/proxy.toml` (home directory)
4. Built-in defaults

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `GVM_CONFIG` | Proxy config file path | `config/proxy.toml` |
| `GVM_ENV` | `production` disables dev features (host overrides) | `development` |
| `GVM_VAULT_KEY` | AES-256 key for Vault encryption (64 hex chars) | Random ephemeral key |
| `GVM_SECRETS_KEY` | Encryption key for `secrets.toml` | None (plaintext) |
| `GVM_PROXY_URL` | Override proxy URL in Python SDK | `http://127.0.0.1:8080` |
| `GVM_SHADOW_MODE` | Shadow Mode: `strict`, `cautious`, `permissive`, `disabled` | `disabled` |
| `RUST_LOG` | Proxy log level | `info` |

### Proxy Configuration (`config/proxy.toml`)

```toml
[server]
listen = "0.0.0.0:8080"

[enforcement]
default_decision = { type = "Delay", milliseconds = 300 }  # Fail-Close default
ic1_async_ledger = true       # Async WAL for IC-1 reads (higher throughput)
ic1_loss_threshold = 0.001    # Tolerate 0.1% WAL loss for IC-1

# What agents see when blocked
[enforcement.on_block]
deny = "halt"                    # Stop immediately
require_approval = "soft_pivot"  # Suggest alternatives
throttle = "rollback"            # Auto-rollback on rate limit
infrastructure_failure = "halt"  # Halt if WAL fails

[srr]
network_file = "config/srr_network.toml"
semantic_file = "config/srr_semantic.toml"  # Optional: semantic SRR rules
hot_reload = true                # Live-reload without restart

[policies]
directory = "config/policies/"
hot_reload = true                # Live-reload without restart

[secrets]
file = "config/secrets.toml"
key_env = "GVM_SECRETS_KEY"

# Dev-only: remap hosts to local mock server. Ignored when GVM_ENV=production.
[dev]
host_overrides = { "gmail.googleapis.com" = "127.0.0.1:9090" }
```

---

## API Key Management

### Credential Types (`config/secrets.toml`)

```toml
# Bearer token
[credentials."api.slack.com"]
type = "Bearer"
token = "xoxb-your-slack-token"

# API key with custom header
[credentials."api.stripe.com"]
type = "ApiKey"
header = "Authorization"
value = "Bearer sk_test_your-stripe-key"

# OAuth2
[credentials."api.google.com"]
type = "OAuth2"
access_token = "ya29.access-token"
refresh_token = "1//refresh-token"
expires_at = "2026-12-31T00:00:00Z"
```

### Missing Credential Policy

- **Development** (default `Passthrough`): No credential configured → request passes through as-is
- **Production** (`Deny`): No credential → request rejected. Prevents agents from using their own keys.

In production, set `GVM_SECRETS_KEY` to encrypt `secrets.toml`. Plaintext is for development only.

---

## Policy Reference

### ABAC Conditions

| Field | Example Values |
|-------|---------------|
| `operation` | `gvm.payment.charge`, `gvm.messaging.send` |
| `resource.sensitivity` | `Low`, `Medium`, `High`, `Critical` |
| `resource.tier` | `Internal`, `External`, `CustomerFacing` |
| `resource.service` | `gmail`, `stripe`, `slack` |
| `agent_id` | `finance-001` |
| `tenant_id` | `acme` |

### ABAC Operators

`Eq`, `EndsWith`, `StartsWith`, `Contains`

### Decision Types

| Type | Fields | IC Level | Block response `ic_level` |
|------|--------|----------|--------------------------|
| `Allow` | — | IC-1 | — (not blocked) |
| `Delay` | `milliseconds` | IC-2 | — (forwarded after delay) |
| `RequireApproval` | `urgency` | IC-3 | 3 |
| `Deny` | `reason` | — | 4 |
| `Throttle` | `max_per_minute` | — | 2 (when rate limit exceeded) |

### Custom Operations (`config/operation_registry.toml`)

```toml
[[custom]]
name = "custom.acme.banking.wire_transfer"
vendor = "acme"
version = 1
default_ic = 3
required_context = ["amount", "currency", "destination_bank"]
maps_to = "gvm.payment.charge"
```

Custom operations require a vendor prefix (`custom.{vendor}.{name}`) and map to a core operation.

---

## SDK Reference

### GVMAgent Constructor

```python
GVMAgent(
    agent_id="finance-001",           # Required
    tenant_id="acme",                 # Optional: multi-tenant identity
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
    resource=Resource(service="stripe", tier="external", sensitivity="critical"),
    rate_limit=100,                     # Max invocations/min (optional)
    checkpoint=True,                    # Force checkpoint (optional)
    amount=None, currency=None,         # Custom ABAC context (optional)
)
```

IC level is inferred from operation name if not explicit:
- `.read`, `.list` → IC-1
- `.delete`, `gvm.payment.*`, `gvm.identity.*` → IC-3
- Everything else → IC-2

### Error Hierarchy

```
GVMError                         # Base
├── GVMDeniedError               # 403 — Deny decision
├── GVMApprovalRequiredError     # 403 — RequireApproval (with urgency)
├── GVMRateLimitError            # 429 — Throttle
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
| `"ic2+"` | IC-2 and IC-3 operations |
| `"ic3"` | IC-3 only |
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
gvm watch agent.py                   # Observe all API calls (no enforcement)
gvm watch -- node my_agent.js        # Binary mode observation
gvm watch --with-rules agent.py      # Observe with existing SRR rules active
gvm watch --output json agent.py     # JSON output for CI/CD piping
gvm watch --sandbox agent.py         # Observe inside Linux sandbox
```

`gvm watch` runs the agent with all requests allowed through (default). No SRR rules are enforced unless `--with-rules` is set. Provides:
- **Real-time stream**: every HTTP request displayed as it happens (method, host, path, status, token usage)
- **Session summary**: host breakdown, LLM token/cost stats, status code distribution, anomaly warnings
- **Anomaly detection**: burst patterns (>10 req/2s), request loops (same URL >5x/10s), unknown hosts
- **Cost estimation**: approximate USD cost based on LLM provider/model token pricing
- **`--output json`**: all events as JSON lines + session summary as JSON object (for piping to `jq`, CI, etc.)

Watch mode generates a temporary allow-all SRR config in the OS temp directory and reloads the proxy via `POST /gvm/reload`. The original SRR rules are restored when watch exits. The user's `srr_network.toml` is never modified.

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

Scans for per-PID state files (`/tmp/gvm-sandbox-{pid}.state`) from previously crashed sandbox sessions. If the owning PID is dead, cleans up all listed resources: veth interfaces, iptables DNAT/FORWARD rules, mount paths, and cgroup directories. Also removes any `veth-gvm-*` interfaces without corresponding state files (defense-in-depth).

Auto-cleanup also runs at the start of every `gvm run --sandbox` — you only need `gvm cleanup` for manual recovery after abnormal termination without a subsequent sandbox launch.

### Binary Mode (`gvm run -- <command>`)

When the argument after `--` is not a recognized script file (`.py`, `.js`, `.ts`, `.sh`, `.bash`) or when multiple arguments follow `--`, `gvm run` enters **binary mode**. The specified command is executed with `HTTP_PROXY` and `HTTPS_PROXY` set to route all outbound traffic through the GVM proxy.

Binary mode provides **Layer 2 enforcement only** (SRR URL-based rules). No SDK headers are injected, so ABAC policy evaluation is not available. All audit output goes to stderr to keep stdout clean for piping.

With `--sandbox`, binary mode uses Linux-native isolation (namespaces + seccomp + veth + uprobe) — the same security layers as script sandbox mode.

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

Dry-run policy evaluation. Evaluates ABAC + SRR without forwarding, WAL writing, or credential injection.

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
| `tls_probe_mode` | `TlsProbeMode` | TLS probe mode: `Audit` (default), `Enforce`, `Disabled` |
| `proxy_url` | `Option<String>` | Proxy URL for uprobe `/gvm/check` queries (None = allow-all) |

### `tls_probe_mode`

Controls uprobe-based TLS plaintext inspection inside the sandbox. Requires Linux 5.5+ and root/CAP_BPF.

| Mode | Behavior |
|------|----------|
| `Audit` | Log HTTPS plaintext but do not block (default, safe for v0.1) |
| `Enforce` | Log and block denied HTTPS requests via SIGSTOP |
| `Disabled` | Disable TLS probing entirely |

### `proxy_url`

When set (e.g., `"http://127.0.0.1:8080"`), the uprobe queries the proxy's `/gvm/check` endpoint for SRR decisions on observed TLS connections. When `None`, uprobe uses allow-all mode (audit-only regardless of `tls_probe_mode`).

---

## Platform Support

| Platform | Proxy | SDK | `--sandbox` | `--contained` |
|----------|-------|-----|-------------|---------------|
| Linux | Native | Native | **Production** | Experimental |
| Windows | Native | Native | Not supported | Experimental (Docker Desktop) |
| macOS | Native | Native | Not supported | Experimental (Docker Desktop) |

> **`--contained` status**: Implemented but experimental. Known issues: WSL2 network bridge drops large TCP responses, `python:3.12-slim` lacks iptables, `NET_ADMIN` capability can be abused by agents, Windows path translation failures. Use `--sandbox` on Linux for production. Stabilization planned for a future release.

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

See [`config/srr_network.toml`](../config/srr_network.toml) for the full rule set.

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
- **Crash/SIGKILL**: State file (`/tmp/gvm-sandbox-{pid}.state`) enables cleanup on next `gvm run --sandbox`
- **Manual**: `gvm cleanup` scans for orphaned resources
- **ip_forward**: Restored to original value when last sandbox exits

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

This catches policy regressions: adding a new SRR rule that accidentally opens access, or modifying ABAC that changes an agent's permission level.

---

[← Quick Start](12-quickstart.md) | [Architecture Overview →](00-overview.md)
