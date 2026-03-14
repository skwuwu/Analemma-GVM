# Part 2: ABAC Policy Engine

**Source**: `src/policy.rs` | **Config**: `config/policies/`

---

## 2.1 Overview

The ABAC (Attribute-Based Access Control) Policy Engine is Layer 1 of the 3-layer security model. It evaluates operation metadata — operation name, resource attributes, subject identity, and context — against hierarchical rules to produce an enforcement decision.

**Design principle**: Policies are declarative TOML, not code. The engine compiles rules at startup and evaluates them in priority order. Lower layers can only be **stricter**, never more permissive.

---

## 2.2 Policy Hierarchy

```
┌─────────────────────────────────────────┐
│           Global Layer                   │  ← Cannot be overridden
│  global.toml                             │  ← Applies to ALL agents
├─────────────────────────────────────────┤
│           Tenant Layer                   │  ← Can only be stricter
│  tenant-{name}.toml                      │  ← Per-organization rules
├─────────────────────────────────────────┤
│           Agent Layer                    │  ← Can only be stricter
│  agent-{name}.toml                       │  ← Per-agent overrides
└─────────────────────────────────────────┘
```

**Strictness is monotonic**: Global sets the floor. Tenant can raise it. Agent can raise it further. No layer can lower the enforcement level set by a higher layer.

---

## 2.3 Rule Structure

```toml
[[rules]]
id = "payment-approval"
priority = 1
layer = "Global"
description = "All payment operations require human approval"

[[rules.conditions]]
field = "operation"
operator = "StartsWith"
value = "gvm.payment"

[rules.decision]
type = "RequireApproval"
urgency = "Standard"
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique rule identifier for audit trail |
| `priority` | u32 | Lower = higher priority. First match wins per layer |
| `layer` | Enum | `Global`, `Tenant`, or `Agent` |
| `conditions` | Vec | AND-combined attribute conditions |
| `decision` | Enum | Enforcement action (Allow, Delay, RequireApproval, Deny, Throttle, AuditOnly) |

---

## 2.4 Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `Eq` | Exact match | `operation == "gvm.storage.read"` |
| `NotEq` | Not equal | `resource.tier != "Internal"` |
| `Gt` / `Lt` / `Gte` / `Lte` | Numeric comparison | `context.amount > 500` |
| `Contains` | Substring match | `operation contains "payment"` |
| `StartsWith` | Prefix match | `operation starts with "gvm.payment"` |
| `EndsWith` | Suffix match | `operation ends with ".read"` |
| `Regex` | Regular expression | `operation matches "gvm\.(payment|identity)\..*"` |
| `In` | Set membership | `resource.sensitivity in ["High", "Critical"]` |
| `NotIn` | Set exclusion | `subject.agent_id not in ["admin-agent"]` |

---

## 2.5 Resolvable Field Paths

The engine resolves dotted field paths from the `OperationMetadata` struct:

| Field Path | Source | Example Value |
|------------|--------|---------------|
| `operation` | Operation name | `"gvm.payment.refund"` |
| `resource.service` | Target service | `"stripe"` |
| `resource.tier` | Resource tier | `"CustomerFacing"` |
| `resource.sensitivity` | Sensitivity level | `"Critical"` |
| `subject.agent_id` | Agent identity | `"finance-001"` |
| `subject.tenant_id` | Organization | `"acme"` |
| `context.*` | Dynamic ABAC attributes | `context.amount`, `context.currency` |

---

## 2.6 Evaluation Algorithm

```
evaluate(operation):
    final_decision = Allow
    matched_rule = None

    // Layer 1: Global
    for rule in global_rules (sorted by priority):
        if all conditions match:
            if Deny → return (Deny, rule.id)    // Short-circuit
            if strictness > final → update
            break

    // Layer 2: Tenant (lookup by tenant_id)
    for rule in tenant_rules[tenant_id]:
        if all conditions match:
            if Deny → return (Deny, rule.id)
            if strictness > final → update
            break

    // Layer 3: Agent (lookup by agent_id)
    for rule in agent_rules[agent_id]:
        if all conditions match:
            if Deny → return (Deny, rule.id)
            if strictness > final → update
            break

    return (final_decision, matched_rule)
```

**Key behaviors**:
- Rules within a layer are sorted by priority (ascending). First match wins.
- Deny at any layer causes immediate return (short-circuit).
- The final decision is the **strictest** across all layers.
- No conditions = unconditional match (used for fallback/catch-all rules).

---

## 2.7 Decision Types

| Decision | IC Level | Behavior |
|----------|----------|----------|
| `Allow` | IC-1 | Immediate pass-through, async audit |
| `Delay { milliseconds }` | IC-2 | WAL-first write, configurable delay, then forward |
| `RequireApproval { urgency }` | IC-3 | Blocked until human approves |
| `Deny { reason }` | — | Unconditional block |
| `Throttle { max_per_minute }` | — | Token-bucket rate limiting per agent |
| `AuditOnly { alert_level }` | — | Allow but elevate audit priority |

**Strictness order**: `Allow < AuditOnly < Throttle < Delay < RequireApproval < Deny`

---

## 2.8 Example Policy: Global Rules

```toml
# config/policies/global.toml

[[rules]]
id = "payment-approval"
priority = 1
layer = "Global"
description = "All payment operations require approval"
[[rules.conditions]]
field = "operation"
operator = "StartsWith"
value = "gvm.payment"
[rules.decision]
type = "RequireApproval"
urgency = "Standard"

[[rules]]
id = "deny-critical-delete"
priority = 2
layer = "Global"
description = "Deny deletion of Critical-sensitivity resources"
[[rules.conditions]]
field = "operation"
operator = "Eq"
value = "gvm.storage.delete"
[[rules.conditions]]
field = "resource.sensitivity"
operator = "Eq"
value = "Critical"
[rules.decision]
type = "Deny"
reason = "Critical data deletion forbidden by global policy"

[[rules]]
id = "customer-facing-delay"
priority = 10
layer = "Global"
description = "Delay all customer-facing operations by 300ms"
[[rules.conditions]]
field = "resource.tier"
operator = "Eq"
value = "CustomerFacing"
[rules.decision]
type = "Delay"
milliseconds = 300

[[rules]]
id = "allow-reads"
priority = 100
layer = "Global"
description = "Allow all read operations"
[[rules.conditions]]
field = "operation"
operator = "EndsWith"
value = ".read"
[rules.decision]
type = "Allow"

[[rules]]
id = "fallback"
priority = 999
layer = "Global"
description = "Default-to-Caution: delay unmatched operations"
[rules.decision]
type = "Delay"
milliseconds = 300
```

---

## 2.9 Interaction with SRR (Layer 2)

The policy engine's decision is combined with the Network SRR decision using `max_strict()`:

```
final_decision = max_strict(srr_decision, policy_decision)
```

This means even if the policy says Allow (e.g., for `gvm.storage.read`), the SRR can override with Deny if the URL matches a dangerous pattern (e.g., `api.bank.com/transfer/*`). This is the core defense against header forgery attacks.

---

## 2.10 Test Coverage

| Test | Assertion |
|------|-----------|
| `test_starts_with_condition` | StartsWith operator matches correctly |
| `test_ends_with_condition` | EndsWith operator matches correctly |
| `test_numeric_gt_condition` | Numeric Gt comparison on context.amount |
| `test_deny_overrides_all` | Deny with priority 1 short-circuits evaluation |

---

[← Part 1: Operations](01-operations.md) | [Part 3: Network SRR →](03-srr.md)
