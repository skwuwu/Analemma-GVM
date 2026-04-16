# Part 7: Python SDK (Experimental)

**Source**: `sdk/python/gvm/`

> **Experimental**: The Python SDK is not yet stabilized. Checkpoint/rollback, `GVMAgent`, and `@ic` decorator APIs may change. **GVM's core value is zero-code-change governance** — the proxy alone provides URL rules, credential injection, and audit trail without any SDK. Use the SDK only if you need intent verification or checkpoint/rollback, and expect breaking changes.
>
> **Historical note:** References to ABAC policy evaluation, `Throttle` / `GVMRateLimitError`, and `max_strict(ABAC, SRR)` in this document reflect an older architecture. ABAC has been removed — SRR is the sole enforcement layer — and rate limiting is now handled by `TokenBudget` (returns 403, not 429). The SDK still provides `@ic` for operation tagging and checkpointing, but policy decisions come from SRR on the proxy.

---

## 7.1 Overview

The Python SDK provides an experimental interface for AI agents to operate under GVM governance. **No inheritance required** — add `@ic()` decorator to functions and use `gvm_session()` for HTTP requests. For advanced features (checkpoint, rollback, encrypted state), optionally extend `GVMAgent`.

**Design principle**: Adding GVM to an existing agent requires `import` + `@ic` + `gvm_session()`. No class restructuring, no framework lock-in.

---

## 7.2 Module Structure

```
sdk/python/gvm/
├── __init__.py         # Public API: ic, gvm_session, configure, GVMAgent, ...
├── session.py          # Standalone session: configure(), gvm_session()
├── decorator.py        # @ic() decorator (works on functions and methods)
├── agent.py            # GVMAgent base class (optional, for checkpoint/rollback)
├── state.py            # AgentState + VaultField
├── resource.py         # Resource descriptor
├── errors.py           # GVM error hierarchy
├── checkpoint.py       # CheckpointManager (Merkle-verified state)
├── langchain_tools.py  # LangChain adapter + @tool stacking docs
├── unified_demo.py     # Unified finance demo (all features in one scenario)
├── demo.py             # Enforcement demo
├── rollback_demo.py    # Rollback + token savings demo
└── hostile_demo.py     # Hostile environment tests
```

---

## 7.3 `@ic()` Decorator

The `@ic()` decorator declares a function or method as a GVM-controlled operation. It injects governance headers into the HTTP context before the function executes. Works on standalone functions, class methods, and `GVMAgent` methods.

### Standalone Usage (recommended for most cases)

```python
from gvm import ic, gvm_session, configure, Resource

configure(agent_id="my-agent")  # or set GVM_AGENT_ID env var

@ic(
    operation="gvm.payment.refund",
    resource=Resource(service="stripe", tier="external", sensitivity="critical"),
    rate_limit=10,
)
def process_refund(customer_id: str, amount: float):
    session = gvm_session()
    return session.post("http://api.stripe.com/refund", json={...}).json()
```

### Non-GVMAgent Class Method

```python
class MyCrewAIAgent(CrewAIBase):  # keeps existing inheritance
    @ic(operation="gvm.search.web")
    def search(self, query):
        session = gvm_session()
        return session.get(f"http://api.search.com/?q={query}").json()
```

### LangChain @tool Stacking

```python
from langchain_core.tools import tool
from gvm import ic, gvm_session

@tool
@ic(operation="gvm.messaging.send")
def send_email(to: str, subject: str, body: str):
    """Send an email via Gmail."""
    session = gvm_session()
    return session.post("http://gmail.googleapis.com/...", json={...}).json()

tools = [send_email]  # standard LangChain tool list, no wrapper needed
```

### Minimal Usage

```python
@ic()  # Auto-generates operation name: "custom.auto.send_email"
def send_email(to, subject, body):
    ...
```

### Safety: Unconsumed Header Warning

If an `@ic`-decorated function makes HTTP requests without using `gvm_session()` or `self.create_session()`, the SDK emits a warning:

```
[GVM] @ic('gvm.messaging.send'): GVM headers were not consumed.
Use gvm_session() or self.create_session() to ensure Layer 2 (ABAC) policy enforcement.
```

This catches the common mistake of using `requests.post()` directly, which bypasses semantic governance (Layer 1) while still passing through the proxy (Layer 2/3 via `HTTP_PROXY`).

### Injected Headers

| Header | Value |
|--------|-------|
| `X-GVM-Agent-Id` | Agent ID (from `GVMAgent` or `configure()`) |
| `X-GVM-Trace-Id` | Thread-local trace UUID |
| `X-GVM-Event-Id` | Unique per invocation |
| `X-GVM-Parent-Event-Id` | Previous event in causal chain |
| `X-GVM-Operation` | Declared operation name |
| `X-GVM-Resource` | JSON-serialized resource descriptor |
| `X-GVM-Context` | JSON-serialized context kwargs |
| `X-GVM-Rate-Limit` | Per-operation rate limit |
| `X-GVM-Tenant-Id` | Agent's tenant (if set) |
| `X-GVM-Session-Id` | Agent's session (if set) |

### Causal Tracing

The decorator maintains a thread-local trace context:

```python
_trace_context = threading.local()

def get_trace_id() -> str:
    if not hasattr(_trace_context, "trace_id"):
        _trace_context.trace_id = str(uuid.uuid4())
    return _trace_context.trace_id
```

When operation A calls operation B, the parent-event chain is preserved:

```
@ic(operation="gvm.payment.refund")    # event_id = "evt-1"
def process_refund(self):
    self.send_confirmation()           # parent_event_id = "evt-1"

@ic(operation="gvm.messaging.send")   # event_id = "evt-2"
def send_confirmation(self):
    ...
```

This creates an auditable causal chain: `evt-1 → evt-2`, visible in the ledger.

---

## 7.4 Standalone Session: `configure()` + `gvm_session()`

For most use cases, you don't need `GVMAgent`. Configure once, then use `gvm_session()` inside `@ic`-decorated functions:

```python
from gvm import configure, gvm_session

# One-time setup (or use env vars: GVM_AGENT_ID, GVM_PROXY_URL)
configure(agent_id="my-agent", tenant_id="acme", proxy_url="http://localhost:8080")

# Inside any @ic function:
session = gvm_session()  # returns requests.Session routed through GVM proxy
session.get("https://api.example.com/data")  # GVM headers auto-injected
```

`gvm_session()` creates a `requests.Session` that:
- Routes all traffic through the GVM proxy
- Auto-injects pending `@ic` headers into each outgoing request
- Clears headers after consumption (one-shot per `@ic` invocation)

## 7.5 `GVMAgent` Base Class (Optional)

Use `GVMAgent` only when you need auto-checkpoint, encrypted state (`VaultField`), or rollback. For basic governance, standalone `@ic` + `gvm_session()` is sufficient.

```python
class GVMAgent:
    state: Optional[AgentState] = None
    auto_checkpoint: Optional[str] = None  # None, "ic2+", "ic3", "all"

    def __init__(
        self,
        agent_id: str,
        tenant_id: str = None,
        session_id: str = None,
        proxy_url: str = None,  # default: GVM_PROXY_URL env or localhost:8080
    ):
```

### Key Responsibilities

1. **Auto-Checkpoint**: Saves agent state before risky operations (IC-2+)
2. **Encrypted State**: `VaultField` values stored with AES-256-GCM via Vault API
3. **Rollback**: Restores agent state to last approved checkpoint on Deny
4. **Session**: `create_session()` delegates to `gvm_session()` with the agent's proxy URL

### Session Creation

```python
session = agent.create_session()  # equivalent to gvm_session(proxy_url=agent.proxy_url)
session.get("https://api.example.com/data")
```

---

## 7.6 `AgentState` and `VaultField`

### Declaration

```python
class FinanceAgent(GVMAgent):
    state = AgentState(
        balance=VaultField(default=0, sensitivity="critical"),
        last_action=VaultField(default="", sensitivity="medium"),
        temp_data="not persisted",  # Regular attribute (in-memory only)
    )
```

### VaultField

```python
class VaultField:
    VALID_SENSITIVITIES = {"low", "medium", "high", "critical"}

    def __init__(self, default=None, sensitivity="medium"):
        ...
```

- `VaultField` values are stored encrypted in the proxy's Vault (AES-256-GCM)
- `sensitivity` determines audit and policy behavior (Critical fields trigger stricter enforcement)
- Regular attributes remain in-memory only

### State Access

```python
agent.state.balance        # Read (returns default or stored value)
agent.state.balance = 100  # Write (in-memory; Vault sync via API)
```

---

## 7.7 `Resource` Descriptor

```python
resource = Resource(
    service="stripe",        # Target service name
    identifier="cust-42",   # Resource identifier
    tier="external",         # "internal", "external", "customer-facing"
    sensitivity="critical",  # "low", "medium", "high", "critical"
)
```

Resources are serialized as JSON in `X-GVM-Resource` header and used by the ABAC policy engine for condition evaluation (e.g., `resource.tier == "CustomerFacing"`).

---

## 7.8 Error Hierarchy

```
GVMError
├── GVMDeniedError          # HTTP 403 — Deny decision
├── GVMApprovalRequiredError # HTTP 403 — IC-3 RequireApproval
├── GVMRateLimitError        # HTTP 429 — Throttle exceeded
└── GVMRollbackError         # Auto-rollback triggered on Deny (GVMAgent only)
```

```python
try:
    agent.process_refund("cust-42", 1000)
except GVMApprovalRequiredError as e:
    print(f"Blocked: {e.urgency}")  # "standard"
except GVMDeniedError as e:
    print(f"Denied: {e.reason}")
except GVMRateLimitError:
    print("Rate limited — retry later")
```

---

## 7.9 Demo Scripts

### Unified Finance Demo (`unified_demo.py`) — Primary Demo

One scenario demonstrating every core feature. Run with: `python -m gvm.unified_demo`

| Step | Operation | Decision | Features Shown |
|------|-----------|----------|----------------|
| 1 | `read_inbox()` → `gvm.messaging.read` | Allow (IC-1) | ABAC policy, safe read classification |
| 2 | `send_summary()` → `gvm.messaging.send` | Delay 300ms (IC-2) | SRR delay, **checkpoint #0 saved** |
| 3 | `wire_transfer()` → `gvm.payment.charge` | **Deny** | SRR URL block, ABAC RequireApproval, `max_strict()`, **rollback to #0** |
| 4 | `summarize_results()` → `gvm.messaging.read` | Allow (IC-1) | Agent resumes from safe state |

Features covered in one scenario:
- IC classification (Allow / Delay / Deny)
- SRR network defense (URL inspected independent of headers)
- Semantic forgery defense (`max_strict(ABAC, SRR)` catches lies)
- Checkpoint/rollback (Merkle-verified state restore on deny)
- Token savings (~42% reduction vs full restart)
- WAL-first audit trail (fsync before forward)
- API key isolation (agent never holds credentials)
- Hierarchical policy (Global > Tenant > Agent)

### Enforcement Demo (`demo.py`)

Demonstrates the full IC classification pipeline:

| Step | Operation | Expected Decision |
|------|-----------|-------------------|
| 1 | `check_balance` → `gvm.storage.read` | Allow (IC-1) |
| 2 | `send_refund_email` → `gvm.messaging.send` | Delay 300ms (IC-2) |
| 3 | `process_refund` → `gvm.payment.refund` | RequireApproval (IC-3) |
| 4 | Direct HTTP to `api.bank.com/transfer` | Deny (SRR) |
| 5 | Audit trail | All events with trace_id chain |

### Hostile Environment Demo (`hostile_demo.py`)

5 adversarial security tests:

| Test | Scenario | Expected |
|------|----------|----------|
| 1 | Fail-Close: proxy down | Agent HTTP fails (ConnectionRefused) |
| 2 | Header forgery: lie about operation | HTTP 403 (SRR catches URL) |
| 3 | Payload OOM: 128KB body | Proxy survives (Default-to-Caution) |
| 4 | Secret isolation: env scan | No API keys in agent environment |
| 5 | Wrong operation name | Proxy handles gracefully (no crash) |

---

## 7.10 Checkpoint/Rollback (Experimental)

> **Experimental**: Checkpoint/rollback is not stabilized. The API, storage format, and Merkle verification behavior may change. For production governance, the proxy-only path (URL rules + credential injection + audit trail) is recommended.

The SDK provides automatic state checkpoint and rollback for IC-2+ operations.

### Auto-Checkpoint Modes

Set via class attribute or constructor:

```python
class MyAgent(GVMAgent):
    auto_checkpoint = "ic2+"  # Options: None, "ic2+", "ic3", "all"
```

| Mode | Checkpoints before |
|------|-------------------|
| `None` | Disabled (default) |
| `"ic2+"` | IC-2 (send/write) and IC-3 (payment/delete) |
| `"ic3"` | IC-3 only |
| `"all"` | Every `@ic` operation |

### How Rollback Works

1. Before an IC-2+ operation, the SDK saves agent state (conversation history, vault fields) to the Vault checkpoint API
2. The checkpoint is encrypted (AES-256-GCM) and stored with a Merkle hash
3. If the proxy denies the operation, the SDK:
   - Retrieves the last approved checkpoint from the Vault
   - Verifies Merkle integrity
   - Restores agent state to the checkpoint
   - Raises `GVMRollbackError` instead of `GVMDeniedError`

### GVMRollbackError

```python
try:
    agent.wire_transfer("attacker-9999", 50000)
except GVMRollbackError as e:
    print(e.operation)      # "gvm.payment.charge"
    print(e.reason)         # "Operation denied: ..."
    print(e.rolled_back_to) # 0 (checkpoint step)
    print(e.blocked_at)     # 1 (step where blocked)
```

For LLM agents, the `gvm_tool()` wrapper converts this to structured JSON:

```json
{
  "error": "ACTION_BLOCKED_AND_ROLLED_BACK",
  "blocked_action": "gvm.payment.charge",
  "reason": "Operation denied: SRR rule",
  "state_restored_to": "checkpoint #0",
  "instruction": "This action was blocked by governance policy. ..."
}
```

### Token Savings

Without rollback (Level 0), a denied action forces the LLM to restart the entire workflow. With rollback (Level 2), the agent resumes from the last checkpoint:

| Metric | Level 0 (No SDK) | Level 2 (SDK) |
|--------|-----------------|---------------|
| Recovery strategy | Full restart | Resume from checkpoint |
| Tokens per denied action (4-step workflow, deny at step 3) | ~1,580 | ~910 |
| Token savings | — | ~42% |
| At 1,000 denials/day | ~1.58M tokens | ~910K tokens |

Actual savings vary by workflow length and deny position — the later in the workflow a deny occurs, the more tokens are saved by resuming from a checkpoint instead of restarting.

Run the demo: `python -m gvm.unified_demo`

---

## 7.11 Security Guarantees

| Property | Mechanism |
|----------|-----------|
| Agent never holds API keys | Layer 3 injection by proxy |
| All HTTP goes through proxy | `HTTP_PROXY` env or session config |
| Operation is declared, not enforced | SDK declares; proxy enforces |
| Trace context propagated | Thread-local trace_id + parent chain |
| State encrypted at rest | VaultField → AES-256-GCM via proxy API |

---

[← Part 6: Proxy Pipeline](architecture/proxy.md) | [Part 8: Memory & Runtime Security →](architecture/memory-security.md)
