# Part 3: Network SRR Engine

**Source**: `src/srr.rs` | **Config**: `config/srr_network.toml`

---

## 3.1 Overview

The Network SRR (Security Rule Router) is Layer 2 of the 3-layer security model. It provides **URL-based defense** independent of semantic operation headers. Even if an agent lies about its operation (header forgery), the SRR inspects the actual HTTP target and enforces rules based on method, host, path, and optionally request body.

**Design principle**: The SRR is the bypass-proof safety net. The agent SDK cannot influence SRR evaluation because it operates on transport-layer data (URL, method), not semantic headers.

---

## 3.2 Rule Matching Architecture

```
Incoming Request
      │
      ▼
┌─────────────────────────────┐
│  For each rule (in order):  │
│   1. Method match?          │
│   2. Host pattern match?    │
│   3. Path pattern match?    │
│   4. Payload inspection?    │
│   → First full match wins   │
└──────────────┬──────────────┘
               │
       ┌───────┴───────┐
       │ Match found   │ No match
       ▼               ▼
   rule.decision   Default-to-Caution
                   (Delay 300ms)
```

Rules are evaluated in **TOML definition order**. First match wins. If no rule matches, the engine returns Default-to-Caution (Delay 300ms).

---

## 3.3 Host Pattern Types

| Pattern | Type | Matches |
|---------|------|---------|
| `api.bank.com` | Exact | Only `api.bank.com` |
| `{host}.database.com` | Suffix | `prod.database.com`, `staging.database.com`, etc. |
| `{any}` or `*` | Any | All hosts |

```rust
pub enum HostPattern {
    Exact(String),    // "api.bank.com"
    Suffix(String),   // ".database.com"
    Any,              // matches everything
}
```

---

## 3.4 Path Matching

| Pattern | Matches |
|---------|---------|
| `/transfer/*` | `/transfer/123`, `/transfer/abc` |
| `/graphql` | Only `/graphql` (exact) |
| `/*` or `*` | All paths |

Trailing `*` is a prefix wildcard. No intermediate wildcards (by design — keeps matching O(1) per rule).

---

## 3.5 Method Expansion

The `*` method expands to all standard HTTP methods at compile time:

```
method = "*"  →  GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
```

Each expansion creates a separate compiled rule, ensuring O(1) method comparison.

---

## 3.6 Payload Inspection (GraphQL/gRPC Defense)

For APIs that multiplex operations over a single URL (e.g., GraphQL), SRR supports body inspection:

```toml
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds", "DeleteAccount", "ModifyPermissions"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Dangerous GraphQL operation" }
```

**Inspection flow**:

1. Check `body.len() > max_body_bytes` → skip rule, return Default-to-Caution (OOM defense)
2. Parse body as JSON → on failure, skip rule (continue to next)
3. Extract `payload_field` value → check against `payload_match` list
4. Match → return rule decision
5. No match → continue to next rule

**OOM Protection**: Bodies exceeding `max_body_bytes` (default 65536) are **never parsed**. The rule is skipped and Default-to-Caution is returned. This prevents adversarial payloads from causing memory exhaustion.

---

## 3.7 Configuration Example

```toml
# Block wire transfers
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Deny", reason = "Wire transfer — blocked by proxy" }

# Block database deletions (all subdomains)
[[rules]]
method = "DELETE"
pattern = "{host}.database.com/{any}"
decision = { type = "Deny", reason = "Database deletion — blocked by proxy" }

# Delay Slack messages (review window)
[[rules]]
method = "POST"
pattern = "api.slack.com/{any}"
decision = { type = "Delay", milliseconds = 300 }

# GraphQL payload inspection
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds", "DeleteAccount"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Dangerous GraphQL operation" }

# Default-to-Caution (catch-all)
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
```

---

## 3.8 Header Forgery Defense

The SRR's primary security value: it **ignores** the semantic operation header (`X-GVM-Operation`).

**Attack scenario**:
1. Agent declares `@ic(operation="gvm.storage.read")` → SDK sets `X-GVM-Operation: gvm.storage.read`
2. Agent targets `POST https://api.bank.com/transfer/123` (wire transfer)
3. Policy engine evaluates `gvm.storage.read` → Allow (IC-1)
4. **SRR evaluates the URL** → `POST api.bank.com/transfer/*` → **Deny**
5. `max_strict(Allow, Deny)` → **Deny**

The agent's lie is caught at Layer 2 regardless of what it declared at Layer 1.

---

## 3.9 Test Coverage

| Test | Assertion |
|------|-----------|
| `payload_exceeding_max_body_bytes_falls_back_to_default_caution` | >100 byte body → Delay 300ms, not Deny |
| `payload_at_exact_limit_is_inspected` | Body at limit → payload inspection proceeds |
| `large_64kb_body_does_not_crash_or_oom` | 128KB body → no crash, returns Default-to-Caution |
| `malformed_json_body_skips_payload_rule` | Invalid JSON → skip to next rule |
| `no_body_for_payload_rule_skips_to_next` | No body → skip payload rule |
| `srr_catches_url_regardless_of_operation_header` | URL-based Deny ignores headers |
| `unknown_url_gets_default_to_caution` | Unknown URL → Delay 300ms |
| `suffix_host_pattern_blocks_all_subdomains` | `{host}.database.com` blocks prod/staging/dev |
| `method_mismatch_does_not_trigger_rule` | GET doesn't match POST-only rule |
| `wildcard_method_matches_all_http_methods` | `*` matches GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS |

### Integration Tests (tests/hostile.rs)

| Test | Assertion |
|------|-----------|
| `srr_100_concurrent_checks_complete_without_blocking` | 100 concurrent checks < 1 second |
| `header_forgery_srr_denies_bank_transfer_regardless` | SRR + max_strict catches header forgery |
| `srr_garbage_input_does_not_panic` | Fuzz inputs (null bytes, 100K paths, PNG headers) → no panic |
| `srr_decision_time_is_roughly_constant` | Deny vs Allow timing variance < 10x |

---

[← Part 2: ABAC Policy](02-policy.md) | [Part 4: WAL-First Ledger →](04-ledger.md)
