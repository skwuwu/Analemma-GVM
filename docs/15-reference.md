# Reference Guide

> Configuration, CLI commands, and advanced options.
> For first-time setup, see [Quick Start →](14-quickstart.md).

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

| Type | Fields | IC Level |
|------|--------|----------|
| `Allow` | — | IC-1 |
| `Delay` | `milliseconds` | IC-2 |
| `RequireApproval` | `urgency` | IC-3 |
| `Deny` | `reason` | — |

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

### Agent Execution

```bash
gvm run agent.py                     # Basic
gvm run --agent-id custom-id agent.py  # Custom audit identity
gvm run -i agent.py                  # Interactive: suggest rules after run
gvm run --sandbox agent.py           # Linux namespace isolation
gvm run --contained agent.py         # Docker isolation
gvm run --contained --detach agent.py  # Docker in background
```

---

## Platform Support

| Platform | Proxy | SDK | `--sandbox` | `--contained` |
|----------|-------|-----|-------------|---------------|
| Linux | Native | Native | Native | Docker |
| Windows | Native | Native | Not supported | Docker Desktop |
| macOS | Native | Native | Not supported | Docker Desktop |

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

[← Quick Start](14-quickstart.md) | [Architecture Overview →](00-overview.md)
