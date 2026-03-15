# Part 7: Python SDK

**Source**: `sdk/python/gvm/`

---

## 7.1 Overview

The Python SDK provides a zero-friction interface for AI agents to operate under GVM governance. Agents inherit from `GVMAgent`, declare operations with the `@ic()` decorator, and use `AgentState` with `VaultField` for encrypted persistence. All HTTP traffic is automatically routed through the GVM proxy.

**Design principle**: Agent code is unchanged. The SDK injects governance metadata into HTTP requests transparently. The agent developer declares *what* they're doing (`@ic(operation=...)`); the proxy decides *whether* to allow it.

---

## 7.2 Module Structure

```
sdk/python/gvm/
├── __init__.py         # Public API exports
├── agent.py            # GVMAgent base class
├── decorator.py        # @ic() decorator
├── state.py            # AgentState + VaultField
├── resource.py         # Resource descriptor
├── errors.py           # GVM error hierarchy
├── checkpoint.py       # CheckpointManager (Merkle-verified state)
├── langchain_tools.py  # LangChain adapter with rollback handling
├── demo.py             # Enforcement demo
├── rollback_demo.py    # Rollback + token savings demo
└── hostile_demo.py     # Hostile environment tests
```

---

## 7.3 `@ic()` Decorator

The `@ic()` decorator declares a method as a GVM-controlled operation. It injects governance headers into the HTTP context before the method executes.

### Usage

```python
from gvm import ic, Resource

class FinanceAgent(GVMAgent):
    @ic(
        operation="gvm.payment.refund",
        resource=Resource(service="stripe", tier="external", sensitivity="critical"),
        rate_limit=10,
        amount=None,  # Context attribute for ABAC
    )
    def process_refund(self, customer_id: str, amount: float):
        # HTTP calls within this method go through the proxy
        # with X-GVM-Operation: gvm.payment.refund
        ...
```

### Minimal Usage

```python
@ic()  # Auto-generates operation name: "custom.auto.send_email"
def send_email(self):
    ...
```

### Injected Headers

| Header | Value |
|--------|-------|
| `X-GVM-Agent-Id` | `self._agent_id` |
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

## 7.4 `GVMAgent` Base Class

```python
class GVMAgent:
    state: Optional[AgentState] = None

    def __init__(
        self,
        agent_id: str,
        tenant_id: str = None,
        session_id: str = None,
        proxy_url: str = None,  # default: GVM_PROXY_URL env or localhost:8080
    ):
```

### Key Responsibilities

1. **Proxy Configuration**: All HTTP traffic routes through `self._proxy_url`
2. **Identity**: Agent ID, tenant ID, session ID for ABAC policy lookup
3. **State Binding**: Connects `AgentState` VaultFields to the Vault API
4. **Header Injection**: Registers callback for `@ic()` to inject GVM headers

### Session Creation

```python
session = agent.create_session()
session.get("https://api.example.com/data")
# → Routed through GVM proxy with X-GVM-* headers
```

The `create_session()` method returns a `requests.Session` pre-configured with:
- Proxy settings (`http_proxy`, `https_proxy` → GVM proxy URL)
- Header injection hook (GVM headers added to every request)
- Target host extraction (for SRR evaluation)

---

## 7.5 `AgentState` and `VaultField`

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

## 7.6 `Resource` Descriptor

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

## 7.7 Error Hierarchy

```
GVMError
├── GVMDeniedError          # HTTP 403 — Deny decision
├── GVMApprovalRequiredError # HTTP 403 — IC-3 RequireApproval
└── GVMRateLimitError        # HTTP 429 — Throttle exceeded
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

## 7.8 Demo Scripts

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

## 7.9 Checkpoint/Rollback

The SDK provides automatic state checkpoint and rollback for IC-2+ operations. This is the primary value-add over proxy-only (Level 0) enforcement.

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
| Tokens per denied action | ~1,340 | ~600 |
| Token savings | — | ~55% |
| At 1,000 denials/day | ~1.34M tokens | ~600K tokens |

Run the demo: `python -m gvm.rollback_demo`

---

## 7.10 Security Guarantees

| Property | Mechanism |
|----------|-----------|
| Agent never holds API keys | Layer 3 injection by proxy |
| All HTTP goes through proxy | `HTTP_PROXY` env or session config |
| Operation is declared, not enforced | SDK declares; proxy enforces |
| Trace context propagated | Thread-local trace_id + parent chain |
| State encrypted at rest | VaultField → AES-256-GCM via proxy API |

---

[← Part 6: Proxy Pipeline](06-proxy.md) | [Part 8: Memory & Runtime Security →](08-memory-security.md)
