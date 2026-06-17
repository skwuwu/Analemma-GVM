# Part 3: Network SRR Engine

**Source**: `src/srr.rs` | **Config**: `gvm.toml` (`[[rules]]` section)

---

## 3.1 Overview

The Network SRR (Simple Request Rules) is the sole enforcement layer in GVM. It provides **transport-layer defense** independent of agent-declared semantics. Even if an agent tries to misrepresent its operation, SRR inspects the actual HTTP target and enforces rules based on method, host, path, and optionally request body.

**Design principle**: The SRR is the bypass-proof safety net. No client-side library or declarative header can influence SRR evaluation because it operates on transport-layer data (URL, method), not semantic claims — even if an agent fabricates `X-GVM-Operation` or any other declarative header, the SRR's URL/method/payload match still fires.

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

For APIs that multiplex operations over a single URL (e.g., GraphQL), SRR supports body inspection. Payload inspection is **on by default since v0.5.2** (`fix(security): payload_inspection default ON`) — it activates implicitly on any rule that declares both `payload_field` and `payload_match`. There is no separate global on/off toggle; if a rule wants body inspection, it sets those two fields. The default `max_body_bytes` cap (65 536) applies regardless of whether the operator names it explicitly, so a body-rule cannot accidentally degenerate into an unbounded read.

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

#### Fail-Close on Unverifiable Body — `unsafe_body_action`

The "skip and continue" behaviour described above is the legacy permissive
default. It's the right choice when payload rules are advisory and a URL-only
rule for the same endpoint provides the real boundary. For endpoints where
"we couldn't verify the body" is itself a security signal, set
`unsafe_body_action` on the rule:

```toml
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
payload_field = "amount"
payload_match = ["LARGE_TRANSFER"]
max_body_bytes = 65536
# Fail-close: if the body exceeds 64 KB, or cannot be parsed as either
# plain JSON or base64-of-JSON, return Deny instead of falling through
# to the next rule.
unsafe_body_action = { type = "Deny", reason = "body inspection failed; cannot verify safety" }
decision = { type = "Allow" }
```

**When `unsafe_body_action` fires**:

| Body state | unsafe_body_action set | Result |
|------------|------------------------|--------|
| Absent (no body) | — | Rule trivially does not apply; continue to next rule |
| Present, parses, matches `payload_match` | — | Apply the rule's `decision` |
| Present, parses, does not match | — | Continue to next rule (rule legitimately not applicable) |
| Present, exceeds `max_body_bytes` | unset | Continue to next rule (legacy) |
| Present, exceeds `max_body_bytes` | set | **Apply `unsafe_body_action`** |
| Present, neither plain-JSON nor base64-JSON parses | unset | Continue to next rule (legacy) |
| Present, neither plain-JSON nor base64-JSON parses | set | **Apply `unsafe_body_action`** |

**Key invariant**: `unsafe_body_action` does NOT fire on absent body. A GET
request (no body) or a body-less POST hitting a rule that requires payload
inspection is "rule does not apply", not "inspection failed". This matters
because operators want URL-only fallback rules to keep working — silently
denying every body-less request would be a footgun.

**Accepted effect types**: any value that `decision` accepts —
`{ type = "Deny", reason = "..." }`, `{ type = "RequireApproval" }`,
`{ type = "Delay", milliseconds = 5000 }`, etc. The compile path validates
the value at proxy startup; a typo in `type = "..."` fails `gvm reload`
loudly rather than at the first matching request.

Regression coverage: [tests/srr_unsafe_body_action.rs](../tests/srr_unsafe_body_action.rs)
(9 cases — fail-close paths + legacy permissive paths + alternate effect types).

### Rule Expiration — `expires_at`

A rule can carry an absolute deadline. After the deadline, the rule
silently stops matching — the next request that would have hit it
falls through to the next rule (or to Default-to-Caution if nothing
else matches).

```toml
[[rules]]
method = "POST"
pattern = "api.payments.com/transfer"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
```

**TOML format**: RFC 3339 (ISO 8601 with timezone). `chrono`'s
`DateTime<Utc>` deserializer is strict — a date-only or
timezone-less string is rejected at proxy startup (`gvm reload`),
not at the first matching request.

**Validity semantics**: half-open `[start_of_time, expires_at)` —
the rule fires while `now < expires_at`, dies at `now == expires_at`.
This mirrors the `time_window` exclusive-end convention.

**Determinism**: the comparison uses the same `now` `check_at` already
takes. An auditor replaying the WAL with the event's recorded
timestamp reproduces the producer's decision exactly. No `Utc::now()`
in the match path.

**Use case — time-bounded permission grant**: an external orchestrator
approves an IC-3 request, then inserts a 5-minute `Allow` rule with
`expires_at = now + 5m`. Subsequent agent calls in that window pass
without re-prompting. The rule auto-expires on the next match attempt
after the deadline — no separate teardown call needed. This is the
first building block of the lease primitive ([CHANGELOG.md v0.7
roadmap](internal/CHANGELOG.md)).

Regression coverage: [tests/srr_expires_at.rs](../tests/srr_expires_at.rs)
(6 cases — strictly-before / at-instant / strictly-after / legacy
no-deadline / malformed-string-fails-load / replay-determinism).

### Principal-Bound Rules — `principal_filter`

A rule can require an exact agent identity. The rule only fires when
the caller's verified `agent_id` matches the configured string exactly
(case-sensitive). This promotes `agent_id` from an audit-only label to
an SRR matching input.

```toml
[[rules]]
method = "POST"
pattern = "workflow.internal/claims/1842"
principal_filter = "agent:claims-reviewer-1842"
decision = { type = "Allow" }
```

**Identity source.** The proxy resolves the principal in this order:

1. JWT-verified `agent_id` (cryptographic — Bearer token signed with
   the configured Ed25519 key).
2. Sandbox peer-IP → agent_id mapping (topological — the proxy minted
   the veth pair so peer-IP equates to the sandbox's identity).
3. `X-GVM-Agent-Id` header (operator-supplied label, lowest trust).

The first one that resolves wins. Whatever string it produces is
passed to the matcher.

**Match contract**:

| Rule | Caller supplies `agent_id` | Result |
|------|----------------------------|--------|
| `principal_filter = None` (legacy) | anything | match (back-compat) |
| `principal_filter = Some(p)` | `Some(p)` (exact match) | match |
| `principal_filter = Some(p)` | `Some(q)` (different string) | skip |
| `principal_filter = Some(p)` | `None` (unauthenticated) | skip (fail-closed) |

**Fail-close direction**: a rule "for one agent" never accidentally
fires for an unrelated agent or for traffic that hasn't established an
identity. Code paths that call the legacy entry point (`srr.check(...)`
without a principal) implicitly pass `None`, so principal-filtered
rules are invisible to them. This is the intended safety boundary for
non-audited callers.

**Exact match, case-sensitive**. The first cut deliberately does not
support glob / wildcard matching (`agent:claims-reviewer-*`). Exact
equality gives the strongest semantics and rules out smuggling via
similar-named principals. Wildcard support is a follow-up; it would
need the same compile-time validation that the existing host-pattern
glob receives.

**Lease primitive composition**: combined with `expires_at`,
`principal_filter` is the v0.5.3 spelling of a time-bounded permission
grant — "this principal may do these things until this instant":

```toml
[[rules]]
method = "POST"
pattern = "workflow.internal/claims/1842"
principal_filter = "agent:claims-reviewer-1842"
expires_at = "2026-07-01T12:05:00Z"
decision = { type = "Allow" }
```

After the deadline the rule expires; before the deadline it only fires
for the named agent. An orchestrator emits this rule after approving
an IC-3 request and forgets about cleanup — both the principal scope
and the time scope are enforced by the engine, not by the caller.

Regression coverage:
[tests/srr_principal_filter.rs](../tests/srr_principal_filter.rs)
(7 cases — match path, non-matching principal, absent principal,
legacy `check` entry, back-compat, lease composition with
`expires_at`, case-sensitivity).

### Provider Action Packs

A curated set of SRR rule files that map common SaaS API endpoints to
**semantic action names**. Each rule's `description` field carries the
canonical action name (`github.pr.merge`, `slack.message.send`, ...);
the WAL records that name as `matched_rule_id`; the audit CLI surfaces
it as the operator-readable label for what the agent did.

The internal compile target is unchanged — `method + host +
path_regex` — but the operator writes (and the auditor reads) the
agent-IAM vocabulary, not the URL.

```bash
# Append the relevant pack to your SRR config and hot-reload
cat config/templates/_action_packs/github.toml >> config/srr_network.toml
cat config/templates/_action_packs/slack.toml  >> config/srr_network.toml
gvm reload
```

**Default effects** (operator overrides per agent + per task via a
lease):

| Action class | Default effect | Reason |
|--------------|----------------|--------|
| Reads | `Allow` | Side-effect-free; audit suffices |
| Writes | `Delay 300ms` | Visible in the watch stream; operator can promote |
| High-risk writes | `RequireApproval` | Holds for human or orchestrator review |
| Destructive | `Deny` | Operator must explicitly opt in per agent |
| Catch-all | `Delay 300ms` | Unrecognised endpoint on a known provider — audit |

**Lease composition** — append the lease rule **before** the pack so it
fires first (SRR is first-match-wins):

```toml
# Promote github.pr.merge from RequireApproval to Allow for one bot,
# one PR, one 5-minute window. Append BEFORE github.toml's pack rules.
[[rules]]
method = "PUT"
pattern = "api.github.com/{any}"
path_regex = "^/repos/my-org/my-repo/pulls/1842/merge$"
principal_filter = "agent:release-bot"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
description = "github.pr.merge"
```

**Ships in v0.5.3**:
- [config/templates/_action_packs/github.toml](../config/templates/_action_packs/github.toml)
  — repo.read, issue.read, pr.read, issue.comment.create, pr.create,
  pr.merge, workflow.dispatch, repo.delete + catch-all
- [config/templates/_action_packs/slack.toml](../config/templates/_action_packs/slack.toml)
  — user.lookup, conversations.list, message.send, message.update,
  file.upload, channel.create, workflow.trigger, message.delete +
  catch-all
- [config/templates/_action_packs/README.md](../config/templates/_action_packs/README.md)
  — checklist for adding a new pack

Regression coverage:
[tests/srr_action_packs.rs](../tests/srr_action_packs.rs)
(5 tests — each pack loads via production `NetworkSRR::load`, each
canonical URL maps to its declared action name and risk class, the
lease shape correctly shadows pack defaults for the named principal
in the named window).

### Importing a Baseline from OpenAPI — `gvm import openapi`

For an internal or third-party API the operator already has an
OpenAPI 3.x spec for, `gvm import openapi` generates a
deny-by-default SRR file in one shot. The vocabulary is the same:
`operationId` becomes the rule's `description`, so the audit log
records the semantic action name instead of the URL.

```bash
# YAML or JSON, both accepted
gvm import openapi spec.yaml > srr_network.toml
gvm import openapi spec.json --out config/srr_network.toml
```

For each `paths.<template>.<method>` in the spec, the importer emits
a `[[rules]]` block with:

- `method` from the HTTP verb
- `pattern = "<host>/{any}"` from `servers[0].url`
- `path_regex` from the path template — `{name}` becomes `[^/]+`,
  regex metacharacters in literal segments are escaped
- `description = operationId` (or a `method_path` placeholder when
  the spec omits it)
- `label = to_snake_case(operationId)`
- `decision = { type = "Deny", reason = "outside imported baseline" }`

The operator reviews each rule and promotes individual actions to
`Allow` / `Delay` / `RequireApproval` by hand, or appends a lease
rule (with `principal_filter` + `expires_at`) **before** the
imported baseline so the lease's match shadows the deny.

```toml
# Per-agent lease — fires first, overrides the imported Deny for
# this principal, this URL, and this window only.
[[rules]]
method = "POST"
pattern = "api.internal.corp/{any}"
path_regex = "^/v1/workflows/release/runs$"
principal_filter = "agent:release-bot"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
description = "triggerWorkflow"

# === BEGIN imported baseline (gvm import openapi spec.yaml) ===
# ... generated rules ...
```

The importer deliberately does NOT guess risk class by HTTP verb
(POST = Delay, DELETE = Deny, etc.). The OpenAPI spec doesn't
reliably carry that information, and a wrong guess that produces
an Allow rule is the worst possible outcome. Deny-by-default plus
explicit operator review is the safe default.

**Errors are loud.** The importer exits non-zero with a stderr
message when:
- the spec file does not exist or cannot be read
- the spec parses neither as YAML nor as JSON
- `servers` is missing or empty (host cannot be inferred)

Regression coverage:
- [crates/gvm-cli/src/import.rs](../crates/gvm-cli/src/import.rs)
  `mod tests` (7 unit tests — path-template-to-regex with params,
  multiple params, metacharacter escaping, host extraction with
  and without base path, snake_case for camelCase and dotted
  identifiers)
- [crates/gvm-cli/tests/import_openapi.rs](../crates/gvm-cli/tests/import_openapi.rs)
  (4 integration tests — end-to-end YAML → generated TOML →
  `NetworkSRR::load` → request match for canonical URLs with the
  right `description`; bare-host server URL; `--out` flag writes
  to a file path; missing `servers` fails loudly)

### Single-Rule Mutation — `POST /gvm/srr/rule` and friends

The orchestrator control-plane endpoint for issuing a single rule
without rewriting the SRR file. Used to land a per-task lease
(principal_filter + expires_at) in front of the file's defaults.

```bash
# Inject a 5-minute Allow rule for one bot, one PR
curl -X POST http://127.0.0.1:9090/gvm/srr/rule \
  -H 'Authorization: Bearer <admin-jwt>' \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "PUT",
    "pattern": "api.github.com/{any}",
    "path_regex": "^/repos/my-org/my-repo/pulls/1842/merge$",
    "principal_filter": "agent:release-bot",
    "expires_at": "2026-07-01T15:00:00Z",
    "decision": { "type": "Allow" },
    "description": "github.pr.merge.lease.claim-1842"
  }'

# 201 Created
# { "id": "github.pr.merge.lease.claim-1842",
#   "applied": true,
#   "injected_count": 1 }
```

Companions:

```bash
# List the IDs of currently injected rules
curl -s http://127.0.0.1:9090/gvm/srr/rule
# 200 { "ids": ["github.pr.merge.lease.claim-1842"], "count": 1 }

# Remove a rule before its expires_at — orchestrator's emergency
# brake
curl -X DELETE http://127.0.0.1:9090/gvm/srr/rule/github.pr.merge.lease.claim-1842
# 200 { "id": "...", "removed": true, "injected_count": 0 }
```

**Endpoint contract** (admin port only — not exposed on the
agent-facing proxy port; the sandbox cannot self-grant):

| Endpoint | Status codes |
|----------|--------------|
| `POST /gvm/srr/rule` | 201 OK, 400 bad body / missing description / bad regex, 409 duplicate id, 429 cap reached (1 000 rules) |
| `DELETE /gvm/srr/rule/:id` | 200 removed, 404 not found |
| `GET /gvm/srr/rule` | 200 + `{ "ids": [...], "count": N }` |

**Lifecycle.** Injected rules iterate **before** file-loaded rules
in the engine (first-match-wins is preserved within and across
slots). The slot survives `gvm reload` (file reload only touches
the file slot). The slot does **not** survive proxy restart — for
first cut, the orchestrator owns lease lifecycle and re-issues on
restart. Persistence is a v0.7+ follow-up if real demand surfaces.

**Cap.** 1 000 injected rules (`MAX_INJECTED_RULES`). Mirrors the
IC-3 pending cap; designed to absorb burst lease issuance from a
broken orchestrator without OOMing the proxy. Hit the cap → 429.

Regression coverage:
- [tests/srr_rule_mutation.rs](../tests/srr_rule_mutation.rs)
  (10 library-layer cases: shadow file rule, restore after remove,
  empty-description error, duplicate-id error, unknown remove
  returns false, cap, bad regex compile error, lease composition
  with principal_filter + expires_at, inspection IDs, rule_count
  vs injected_rule_count)
- [tests/srr_rule_api.rs](../tests/srr_rule_api.rs)
  (9 HTTP-layer cases: 201 / 400 / 409 / 404 / 200 round-trip;
  list endpoint; insert → check fires → remove → check doesn't)

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

## 3.8 Time-Window Conditions

A rule can carry an optional `condition` block that gates when the rule fires. The current implementation defines one condition kind — `time_window` — but the schema is a tagged enum (`#[serde(tag = "kind")]`), so future variants (`request_count`, `header_value`, …) extend without breaking existing TOML.

```toml
# Allow Slack only during business hours (Asia/Seoul, 09:00-18:00).
# Outside the window the rule does not fire — the request falls through
# to the next matching rule (or to Default-to-Caution).
[[rules]]
method = "POST"
pattern = "api.slack.com/{any}"
decision = { type = "Allow" }
condition = { kind = "time_window", window = "09:00-18:00", tz = "Asia/Seoul" }

# Inverse — block deploys outside business hours.
[[rules]]
method = "POST"
pattern = "api.github.com/repos/{any}/deployments"
decision = { type = "Deny", reason = "Deploys only during business hours" }
condition = { kind = "time_window", window = "09:00-18:00", tz = "Asia/Seoul", outside = true }

# Cross-midnight ranges are supported (start_min > end_min).
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 1000 }
condition = { kind = "time_window", window = "22:00-06:00", tz = "UTC" }
```

**Field reference**:

| Field | Required | Default | Notes |
|-------|----------|---------|-------|
| `window` | yes | — | `"HH:MM-HH:MM"`, both endpoints in the rule's `tz`. Cross-midnight (`"22:00-06:00"`) is encoded as `start_min > end_min` internally. |
| `tz` | no | `"UTC"` | IANA name. Validated at load via `chrono-tz`; an unknown zone fails the rule's compile, surfaced as a parse error on `gvm reload`. |
| `outside` | no | `false` | Inverts the match — rule fires *outside* the window. |

**Determinism contract.** Conditions evaluate against the request's timestamp, which is committed to the Merkle leaf in `compute_event_hash`. An auditor running `gvm replay --wal` against the same rule set with `check_at(event.timestamp)` reproduces the producer's decision exactly — no system-clock dependence. `Condition` carries the same audit guarantee as unconditional rules; the timestamp dependency adds no new trust assumption because the timestamp itself is anchor-signed. See `src/srr/mod.rs::Condition` for the compiled form and `crates/gvm-cli/src/replay.rs` for the replay path.

**`--strict` flag for replay.** `gvm replay --wal <path> --strict` rejects any WAL event whose `timestamp` cannot parse as RFC 3339 instead of falling back to `Utc::now()`. For audits of time-window-conditional rules `--strict` is the right mode — without it a malformed-timestamp event would silently re-evaluate against the auditor's wall clock, possibly flipping the decision. Production replays should pass `--strict`; the lenient default exists for incremental WAL inspection during development.

---

## 3.9 Interactive Rule Builder (`gvm suggest --interactive`)

`gvm suggest` can run interactively, walking through every unknown URL the agent hit during `gvm watch` and asking the operator to make a per-target decision. The interactive flow is what most operators actually use — direct hand-editing of TOML is the escape hatch.

For each unknown target the prompt lists the path segmented and indexed, followed by the available choices:

```
GET api.github.com/repos/foo/orders/12345

   [1] repos  [2] foo  [3] orders  [4] 12345

   [a] Allow     (IC-1: instant, no delay)
   [d] Delay     (IC-2: 300ms safety delay + audit)
   [n] Deny      (IC-3: block completely)
   [s] Skip      (leave as Default-to-Caution)
   [e <nums>] Edit     (wildcard segments — e.g. "e 2 3")
   [t] Time      (gate by HH:MM-HH:MM in your timezone)

   Choice: e 2 4
```

Key shortcuts:

| Key | Effect |
|-----|--------|
| `a` / `d` / `n` | Stage the rule with Allow / Delay 300ms / Deny respectively |
| `s` | Skip — let the URL fall to Default-to-Caution at runtime |
| `e <nums>` | Replace the listed path segments with `{any}`. `"e 2 3"` turns `/repos/foo/orders/...` into `/repos/{any}/{any}/...`. Loops back to the prompt with the new pattern so the operator can iterate. |
| `t` | Prompts for an HH:MM-HH:MM window + timezone, stages a `condition.time_window` block on the rule. After staging, the prompt re-displays with a **preview** of the resulting `[[rules]]` block so the operator can sanity-check before pressing `a`/`d`/`n`. |
| `c` | Visible only after `[t]` has staged a condition. Drops the staged condition. |

The segment editor exists because `gvm suggest`'s built-in `looks_like_id` heuristic (numeric / UUID / hex hash detection) misses domain-specific identifiers — base64 IDs, slug-like tokens, custom serialisation. Rather than re-running watch with a different agent path, the operator wildcards the right segments interactively.

The time-window condition is intentionally NOT auto-suggested. `gvm suggest` is a baseline-construction tool; condition design ("deny outside biz hours") is policy authoring and stays operator-driven. The `[t]` key surfaces the feature without making it the default path.

---

## 3.10 SRR Hot-Reload

The SRR rule set can be reloaded at runtime without restarting the proxy via `POST /gvm/reload`.

**Reload flow**:

1. Proxy receives `POST /gvm/reload`
2. Loads and parses the SRR section of `gvm.toml`
3. Pre-compiles all regex patterns, validates all rules
4. On **success**: acquires a write lock on the SRR and atomically swaps the entire rule set. Returns `200 OK` with the new rule count.
5. On **parse failure**: existing rules are **preserved unchanged**. Returns `400 Bad Request` with the parse error. The proxy continues operating with the previous rules.

**Atomicity guarantee**: The rule set is stored behind an `RwLock`. The write lock is held only for the pointer swap (not during parsing). Concurrent requests continue to evaluate against the old rules until the swap completes.

```
POST /gvm/reload → 200 {"reloaded": true, "rules": 42}
POST /gvm/reload → 400 {"reloaded": false, "error": "Parse failed: ... Existing rules preserved."}
```

---

## 3.11 Configuration Example

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

## 3.12 Header Forgery Defense

The SRR's primary security value: it **ignores** the semantic operation header (`X-GVM-Operation`).

**Attack scenario**:
1. Agent (or any tool the agent uses) sets `X-GVM-Operation: gvm.storage.read` to misrepresent the call
2. Agent targets `POST https://api.bank.com/transfer/123` (wire transfer)
3. Any classifier that trusted the declarative header would log a benign `gvm.storage.read` event
4. **SRR evaluates the URL** → `POST api.bank.com/transfer/*` → **Deny**
5. The denial fires regardless of the declared operation; the audit event records the URL the proxy actually saw

The agent's lie about its intent is caught at the transport layer regardless of any client-side declaration.

---

## 3.13 Test Coverage

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

[← Architecture Overview](overview.md) | [WAL-First Ledger →](architecture/ledger.md)
