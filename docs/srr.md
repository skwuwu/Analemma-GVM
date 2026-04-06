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

1. Check `body.len() > max_body_bytes` → skip this rule, continue to next rule
2. Parse body as JSON → on failure, skip this rule (continue to next)
3. Extract `payload_field` as a **top-level JSON key** → if missing or not a string, skip rule
4. Compare extracted string value against `payload_match` list using **exact case-sensitive equality**
5. Match → return rule decision
6. No match → continue to next rule

**Payload inspection scope and limitations**:

| Capability | Supported | Example |
|-----------|-----------|---------|
| Top-level string field match | Yes | `{"operationName": "TransferFunds"}` → matches `"TransferFunds"` |
| Case-sensitive exact equality | Yes | `"transferfunds"` does NOT match `"TransferFunds"` |
| Multiple match values | Yes | `payload_match = ["TransferFunds", "DeleteAccount"]` |
| Nested field access | **No** | `{"data": {"operationName": "X"}}` → field not found, rule skipped |
| Numeric field comparison | **No** | `{"amount": 50000}` → `as_str()` returns None, rule skipped |
| Boolean/null field values | **No** | Non-string JSON values are ignored |
| Regex on payload values | **No** | Match is literal string equality only |
| Array field values | **No** | `{"ops": ["Transfer"]}` → not a string, rule skipped |

When a payload rule is skipped (body too large, JSON parse failure, field missing, field not a string, no match), evaluation **continues to the next rule** — it does not immediately return Default-to-Caution. This allows URL-only fallback rules for the same endpoint to still match. Default-to-Caution only applies if no rule matches at all.

**OOM Protection**: Bodies exceeding `max_body_bytes` (default 65536) are **never parsed**. The rule is skipped and evaluation continues to subsequent rules. This prevents adversarial payloads from causing memory exhaustion.

### Base64 Payload Decoding

SRR automatically decodes Base64-encoded content before pattern matching. This prevents bypass via encoding obfuscation. Two decoding strategies are applied in order:

1. **Entire body is Base64**: If the body fails JSON parsing, SRR attempts standard Base64 decoding of the entire body (after trimming whitespace). If decoding succeeds and the result is valid JSON, payload inspection proceeds on the decoded JSON.

2. **Individual field values are Base64**: After normal JSON parsing succeeds, SRR checks whether the target `payload_field` value is itself a Base64-encoded string. If so, the decoded content is compared against `payload_match` entries using **substring matching** (`contains`), not exact equality. This catches cases like a webhook body where `{"data": "Z2hwX2FiYzEyM3NlY3JldHRva2Vu"}` contains an encoded GitHub token (`ghp_abc123secrettoken`).

| Scenario | Decoding | Match Type |
|----------|----------|------------|
| Normal JSON body | None | Exact string equality |
| Entire body is Base64-encoded JSON | Decode body, then extract field | Exact string equality |
| JSON field value is Base64-encoded | Decode field value | Substring match (`contains`) |
| Non-JSON, non-Base64 body | Rule skipped | — |

**Security note**: Base64 decoding uses standard alphabet only (RFC 4648). URL-safe or non-standard encodings are not decoded — these cause the rule to be skipped, and evaluation falls through to subsequent rules.

---

## 3.7 Path Regex Matching

**Config field**: `path_regex` (optional, per-rule)

The default path matching (prefix wildcard with trailing `*`) does not support mid-pattern wildcards. For URLs like Telegram's `/bot<token>/sendMessage` where the variable segment appears in the middle, `path_regex` provides full regex matching via Rust's `regex` crate.

```toml
[[rules]]
method = "POST"
pattern = "api.telegram.org"
path_regex = "^/bot[^/]+/sendMessage$"
decision = { type = "Delay", milliseconds = 500 }
description = "Telegram message send — review delay"
```

**Behavior**:

- When `path_regex` is set, it **overrides** the path portion of `pattern` for matching. The host portion of `pattern` is still used for host matching.
- Regex is **pre-compiled at load time** using Rust's automata-based regex engine (guaranteed O(n) linear-time matching, no backtracking).
- Invalid regex patterns cause a **startup error** (fail-fast).
- Regex length is bounded to 10,000 bytes to prevent resource exhaustion.
- Both the normalized path and the original request path are tested against the regex — normalization expands what gets caught, it never hides matches.

| Use Case | Example `path_regex` |
|----------|---------------------|
| Versioned API endpoints | `"^/api/v[1-3]/users/.*"` |
| Sensitive admin paths (case-insensitive) | `"(?i)/(admin\|internal\|debug)(/\|$)"` |
| Telegram bot URLs | `"^/bot[^/]+/sendMessage$"` |
| Destructive DB operations | `"^/(drop\|truncate\|delete)/"` |

**Note**: A rule with `method = "*"`, `pattern = "{any}"`, and `path_regex` set is **not** treated as a catch-all rule, since the regex restricts which paths match.

---

## 3.8 SRR Hot-Reload

The SRR rule set can be reloaded at runtime without restarting the proxy via `POST /gvm/reload`.

**Reload flow**:

1. Proxy receives `POST /gvm/reload`
2. Loads and parses the SRR config file (`config/srr_network.toml`)
3. Pre-compiles all regex patterns, validates all rules
4. On **success**: acquires a write lock on the SRR and atomically swaps the entire rule set. Returns `200 OK` with the new rule count.
5. On **parse failure**: existing rules are **preserved unchanged**. Returns `400 Bad Request` with the parse error. The proxy continues operating with the previous rules.

**Atomicity guarantee**: The rule set is stored behind an `RwLock`. The write lock is held only for the pointer swap (not during parsing). Concurrent requests continue to evaluate against the old rules until the swap completes.

```
POST /gvm/reload → 200 {"reloaded": true, "rules": 42}
POST /gvm/reload → 400 {"reloaded": false, "error": "Parse failed: ... Existing rules preserved."}
```

---

## 3.9 Configuration Example

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

## 3.10 Header Forgery Defense

The SRR's primary security value: it **ignores** the semantic operation header (`X-GVM-Operation`).

**Attack scenario**:
1. Agent declares `@ic(operation="gvm.storage.read")` → SDK sets `X-GVM-Operation: gvm.storage.read`
2. Agent targets `POST https://api.bank.com/transfer/123` (wire transfer)
3. Policy engine evaluates `gvm.storage.read` → Allow (IC-1)
4. **SRR evaluates the URL** → `POST api.bank.com/transfer/*` → **Deny**
5. `max_strict(Allow, Deny)` → **Deny**

The agent's lie is caught at Layer 2 regardless of what it declared at Layer 1.

---

## 3.11 Test Coverage

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

[← Part 2: ABAC Policy](policy.md) | [Part 4: WAL-First Ledger →](architecture/ledger.md)
