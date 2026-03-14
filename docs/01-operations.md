# Part 1: Operation Namespace & Registry

**Source**: `src/registry.rs` | **Config**: `config/operation_registry.toml`

---

## 1.1 Overview

The Operation Registry defines the vocabulary of all actions an AI agent can declare. Every `@ic(operation=...)` call in the SDK must reference a registered operation. The registry enforces naming conventions, schema contracts, and mapping safety at proxy startup (Fail-Close).

**Design principle**: If the registry is invalid, the proxy does not start. No ambiguous operations, no undefined behavior.

---

## 1.2 Operation Naming Convention

### Core Operations (Platform-Defined)

Format: `gvm.{category}.{action}` — exactly 3 segments.

| Operation | IC | Description |
|-----------|-----|-------------|
| `gvm.messaging.send` | IC-2 | Send message (Slack, email, etc.) |
| `gvm.messaging.read` | IC-1 | Read messages |
| `gvm.payment.charge` | IC-3 | Charge a payment |
| `gvm.payment.refund` | IC-3 | Process refund |
| `gvm.storage.read` | IC-1 | Read from storage |
| `gvm.storage.write` | IC-2 | Write to storage |
| `gvm.storage.delete` | IC-3 | Delete from storage |
| `gvm.data.export` | IC-3 | Export data |
| `gvm.identity.modify` | IC-3 | Modify identity/permissions |
| `gvm.system.execute` | IC-3 | Execute system command |

### Custom Operations (Vendor-Defined)

Format: `custom.{vendor}.{domain}.{action}` — exactly 4 segments.

```toml
[[custom]]
name = "custom.acme.banking.wire_transfer"
description = "Wire transfer via ACME banking API"
vendor = "acme"
version = 1
status = "stable"
default_ic = 3
required_context = ["amount", "currency", "recipient"]
maps_to = "gvm.payment.charge"
```

Vendor segment must match the declared `vendor` field — prevents impersonation.

---

## 1.3 Schema Validation

Each operation carries a semantic contract:

```rust
pub struct CoreOperation {
    pub name: String,           // gvm.{category}.{action}
    pub description: String,
    pub version: u32,           // Schema version
    pub status: String,         // "stable", "deprecated", "experimental"
    pub default_ic: u8,         // 1, 2, or 3
    pub required_context: Vec<String>,  // ABAC attributes the SDK must provide
    pub semantic_contract: Option<String>,
}
```

**Validation at startup**:
1. Name format enforcement (3-segment for core, 4-segment for custom)
2. IC level range check (1–3)
3. Vendor segment consistency
4. `maps_to` safety verification

---

## 1.4 `maps_to` Safety — Anti-Downgrade Protection

Custom operations can map to core operations for policy inheritance. This mapping is **strictly validated** to prevent policy weakening:

```
Rule: core.default_ic must be >= custom.default_ic
```

**Blocked example**:
```
custom.acme.banking.wire_transfer (IC-3) → gvm.storage.read (IC-1)
```

This would allow a high-risk wire transfer to inherit IC-1 (Allow) policies intended for storage reads. The registry rejects this at startup:

```
Error: Unsafe mapping: 'custom.acme.banking.wire_transfer' (IC-3) → 'gvm.storage.read' (IC-1).
Custom IC exceeds core IC — policy would be weakened.
```

**Allowed example**:
```
custom.acme.crm.email_customer (IC-2) → gvm.messaging.send (IC-2)
```

Same IC level — safe. The custom operation inherits all policies applied to `gvm.messaging.send`.

---

## 1.5 Lookup Flow

```
SDK declares: @ic(operation="custom.acme.crm.email_customer")
                          │
                          ▼
              OperationRegistry::lookup()
                          │
              ┌───────────┴───────────┐
              │  Custom ops HashMap   │
              │  found? → return      │
              │  not found?           │
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              │  Core ops HashMap     │
              │  found? → return      │
              │  not found? → None    │
              └───────────────────────┘
```

`effective_core_operation()` resolves `maps_to` chains:
- `custom.acme.crm.email` → `gvm.messaging.send` (via maps_to)
- `gvm.storage.read` → `gvm.storage.read` (identity)
- Unknown → `None` (triggers Default-to-Caution)

---

## 1.6 Test Coverage

| Test | Assertion |
|------|-----------|
| `test_valid_registry_loads` | Valid TOML with core + custom ops loads successfully |
| `test_unsafe_mapping_rejected` | IC-3 → IC-1 mapping blocked at startup |
| `test_invalid_core_name_rejected` | Non-3-segment core name fails validation |
| `test_vendor_mismatch_rejected` | Mismatched vendor segment detected |

---

## 1.7 Security Implications

- **Fail-Close**: Invalid registry → proxy does not start. No runtime ambiguity.
- **Anti-Downgrade**: `maps_to` validation prevents policy weakening through semantic aliasing.
- **Namespace Isolation**: `gvm.*` is reserved for platform operations; vendors use `custom.{vendor}.*`.
- **Unknown Operations**: Operations not in the registry trigger Default-to-Caution (Delay 300ms) in the policy engine, never Allow.

---

[← Overview](00-overview.md) | [Part 2: ABAC Policy Engine →](02-policy.md)
