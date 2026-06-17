# Cooperative intent lease

**Tier-3 P3-c — body-aware policy enforcement when MITM is blind.**

GVM's primary enforcement path is **network-observed**: the proxy
decrypts (via MITM), parses the HTTP body, and runs the SRR engine
against what it actually saw on the wire. For traffic the proxy can
fully observe, this is the highest-evidence path and it does not
change.

For traffic the proxy **cannot fully observe** — certificate-pinned
clients, mutual-TLS, gRPC-over-h2, raw CONNECT relay — the agent
itself (or its SDK / sidecar / MCP adapter) cooperates by
**declaring** what it is about to send. GVM evaluates policy
against the declaration, mints a short-lived bearer token bound to
the lease, and records the decision with a lower evidence level so
the audit chain reflects what the engine actually had access to.

This document is the canonical reference for the design. It
captures the trust-boundary reasoning behind each choice, the
phasing of the implementation, and the parts that are deliberately
deferred.

---

## What this DOES and DOES NOT do

> **Cooperative payload context does not replace MITM inspection.**
>
> When GVM can observe the real payload, observed payload wins and
> the cooperative context is cross-checked. When GVM cannot observe
> the real payload, cooperative context allows policy evaluation in
> declared-only mode, which is recorded in the audit chain with a
> lower evidence level.

The cooperative path is **additive**, not a replacement. It
extends policy enforcement into the network paths MITM cannot
reach, at the cost of a lower-evidence audit trail when no
cross-check is possible.

| Scenario | MITM today | + Cooperative |
|---|---|---|
| Plain HTTP / HTTPS where MITM works | ✅ Network-observed body | Same — high-evidence path unchanged. Declaration is cross-checked when present. |
| Certificate-pinned HTTPS client | ❌ Pinned client rejects MITM cert | ✅ Declaration enforced; evidence `cooperative.declared_only` |
| mTLS (client certs) | ❌ Proxy has no client private key | ✅ Same as above |
| gRPC over HTTP/2 | ❌ MITM currently forces ALPN h1.1 | ✅ Same as above |
| Host-root attacker on the agent host | ✅ Tamper-evident audit | ❌ Agent can lie in declaration; **must combine with sandbox isolation** |

---

## Trust boundary statement

> Cooperative declaration extends enforcement only when GVM can bind
> the declaration to a visible transport event — an HTTP request,
> a CONNECT request, a sidecar-mediated egress, or a sandbox-scoped
> network event. Without one of those bindings, the declaration is
> recorded but is not load-bearing for enforcement.

The binding requirement is what prevents an agent from declaring
"I will GET /benign" and actually executing "POST /transfer". Phase
2 (claim-side) is where binding is enforced; Phase 1 only issues
the lease and records evidence.

---

## API: `POST /gvm/intent`

The legacy URL-only intent body still works (back-compat). Adding
any of the new `payload_context` / `payload_hash` / `content_type`
fields switches the handler into **cooperative lease mode**.

### Request — legacy URL-only (unchanged)

```json
{
  "method": "POST",
  "host": "api.bank.com",
  "path": "/transfer",
  "operation": "bank.transfer.create",
  "agent_id": "release-bot",
  "ttl_secs": 30
}
```

Response:

```json
{ "registered": true, "intent_id": 42, ... }
```

### Request — cooperative lease

```json
{
  "method": "POST",
  "host": "api.bank.com",
  "path": "/transfer",
  "operation": "bank.transfer.create",
  "agent_id": "release-bot",
  "ttl_secs": 30,
  "payload_context": { "channel": "C_INTERNAL", "case_id": "1842" },
  "payload_hash": "sha256:<64-hex>",
  "content_type": "application/json"
}
```

Response on Allow / Delay / AuditOnly (`201 Created`):

```json
{
  "registered": true,
  "decision": "Allow",
  "decision_source": "cooperative.declared_only",
  "evidence_level": "declared_only",
  "intent_id": 42,
  "context_token": "ctx_<43-char-base64url>",
  "ttl_secs": 30,
  "payload_context_hash": "sha256:<64-hex>",
  "policy_epoch": "<config-integrity-context-hash>",
  "matched_rule": "transfer.allowlist"
}
```

Response on Deny (`200 OK`, no token, no intent_id, no WAL
`lease_issued` event):

```json
{
  "registered": false,
  "decision": "Deny",
  "decision_source": "cooperative.declared_only",
  "matched_rule": "transfer.deny",
  "payload_context_hash": "sha256:<64-hex>"
}
```

### Hard limits

| Limit | Value | Status code on violation |
|---|---|---|
| `payload_context` canonical JSON size | 16 KB (`MAX_PAYLOAD_CONTEXT_BYTES`) | `413 Payload Too Large` |
| `payload_hash` format | `sha256:<64-hex>` or bare 64-hex | `400 Bad Request` |
| Active intents (legacy or lease) | 10 000 (`MAX_INTENTS`) | `429 Too Many Requests` |
| `ttl_secs` ceiling | 300 (5 min) | Clamped silently to 300 |
| Lease secret bytes | 32 (256-bit) from `OsRng` | — |

---

## Token discipline

The `context_token` is the most security-sensitive part of the
design. Five rules govern it:

1. **Token is opaque random, not an ID.** The `intent_id` and
   `claim_id` are sequential `u64`s — guessable by inspection. The
   token is 32 bytes from `OsRng`, base64url-no-pad encoded, with
   a `ctx_` prefix for grep-ability. On-wire length 47 characters.
2. **Original token leaves the proxy exactly once.** The response
   to the cooperative-lease POST is the only emission. The proxy
   keeps **only the SHA-256** of the on-wire bytes; the original
   `[u8; 32]` is zeroed before the function returns.
3. **No "fetch my token" endpoint.** Once a caller loses the
   original, they re-issue. This rules out "retrieve the token
   later" workflows that would force the proxy to hold a recoverable
   form.
4. **Compare by hash on claim.** Phase 2's claim path will hash
   the presented token bytes and look up the hashed form. Constant-
   time comparison via the underlying SHA-256 reduces timing-side-
   channel surface (each lookup hashes the full input regardless
   of mismatch position).
5. **One-time use.** Phase 2 will mark the token consumed on
   successful claim. Re-use returns `cooperative.unbound` Deny.

---

## Payload privacy

Raw declared payloads do **not** land on the WAL. The audit chain
records only:

- `payload_context_hash` — SHA-256 of the canonical JSON of the
  caller's projection.
- Optional `payload_hash` — caller's commitment to the actual body
  it will send (Phase 2 uses this for cross-check when MITM body
  is available).
- `content_type` — MIME type the caller declared.

The store holds the raw `payload_context` (a `serde_json::Value`)
in memory while the lease is active, for Phase 2 cross-check. It
is dropped when the lease is consumed or expires. Operators who
need to inspect declared payloads do so via the proxy's admin
endpoint while the lease is live; they cannot reconstruct the
declaration from the WAL.

This is why the API field is named `payload_context` and not
`payload`. Callers are expected to project only policy-relevant
fields:

```json
// What the agent declares
{ "channel": "C_INTERNAL_REVIEW", "case_id": "1842", "text_len": 1200 }

// NOT what they declare
{ "channel": "C_INTERNAL_REVIEW", "case_id": "1842",
  "text": "<the full 1200-character message body>" }
```

Future work (v0.7+): auto-redaction of common PII patterns at
register time, with operator opt-in.

---

## Decision source — the seven evidence levels

Every governance decision now records *what kind of evidence the
engine had*. The same `decision = Allow` means different things
to an auditor depending on whether GVM observed the wire, the
agent declared and was cross-checked, or the agent declared in
isolation.

| Variant (enum) | String form | Meaning |
|---|---|---|
| `MitmNetworkObserved` | `mitm.network_observed` | GVM decrypted, parsed, and matched the real body. Highest evidence. |
| `SrrNetworkObserved` | `srr.network_observed` | URL/method/host match at the network layer. Body inspection either not required or completed without a payload rule firing. |
| `CooperativeCrossChecked` | `cooperative.cross_checked` | Agent declared a context AND GVM observed the request; declaration confirmed to match. Equivalent evidence to network-observed. |
| `CooperativeDeclaredOnly` | `cooperative.declared_only` | Agent declared a context; GVM has no network-side observation. **Phase 1's lease_issued events use this.** Lower evidence — depends on agent honesty plus sandbox isolation. |
| `CooperativeMismatch` | `cooperative.mismatch` | Declared X, observed Y. Always Deny. Both forms captured in WAL. |
| `CooperativeExpired` | `cooperative.expired` | Token presented after lease TTL elapsed. Always Deny. |
| `CooperativeUnbound` | `cooperative.unbound` | Token presented does not bind to any active lease (re-use, forgery, replay). Always Deny. |

Serialised as a dotted string (`From<DecisionSource> for String`)
into the existing WAL `decision_source` field. No schema change;
old auditors continue to read the field as a string.

---

## Policy epoch (TOCTOU between issuance and claim)

A lease issued under policy version A might be claimed after the
proxy reloaded to policy version B. Two reasonable behaviours:

- **Default (Phase 2): epoch mismatch → Deny.** The token carries
  the policy epoch active at issuance (the `config_integrity_ref`
  hash from `current_integrity_ref()`). At claim time the engine
  compares; mismatch returns `cooperative.expired`. Safer for
  regulated workflows where an emergency `gvm reload` to block a
  hostname must actually block.

- **Opt-in (Phase 2 flag `allow_pinned_lease`): TTL-bound regardless
  of reload.** The lease semantic is "issued at policy A, valid for
  N seconds." A reload during that window does not invalidate the
  lease. Useful for high-throughput workflows where the cost of
  re-prompting on every reload is unacceptable.

Phase 1 only records the issuance-time `policy_epoch` in the
lease for Phase 2 to compare against.

---

## Phasing

### Phase 1 — Issuance (this commit)

- `IntentRequest` gains `payload_context`, `payload_hash`,
  `content_type`.
- New `IntentStore::register_lease()` mints the opaque token,
  stores only its SHA-256, snapshots the policy epoch, and
  stores the projected payload context for Phase 2.
- HTTP handler runs SRR preflight against `canonical(payload_context)`.
- Issuance emits `gvm.intent.lease_issued` WAL event with
  `decision_source = cooperative.declared_only`. Raw payload is
  NOT in the event.
- Preflight Deny short-circuits: no token, no intent_id, no
  lease_issued event.
- `DecisionSource` enum added to gvm-types; existing
  `decision_source: String` field accepts the new dotted strings.

**Tests** (10):

1. Token is opaque random (not intent_id, not claim_id) — entropy
   check confirms 32 bytes from a uniform distribution
2. Token length and prefix (`ctx_` + 43 base64url-no-pad chars)
3. Two consecutive leases produce unrelated tokens
4. Response records `payload_context_hash` not raw payload
5. `decision_source = "cooperative.declared_only"`
6. Oversize payload (≥ 16 KB) → 413
7. Malformed `payload_hash` → 400
8. Preflight Deny → no token, no intent_id
9. Legacy URL-only intent unchanged
10. `DecisionSource` enum round-trips through its dotted-string form

### Phase 2 — Claim path (next)

- Proxy hot path extracts `X-GVM-Context-Token` from visible HTTP
  requests.
- `IntentStore::claim_by_token_hash(sha256(token))` looks up the
  lease.
- Cross-check logic:
  - Observed body + declared body → SRR runs on observed; declared
    is hashed and compared; mismatch → `cooperative.mismatch` Deny.
  - Observed body only → existing `srr/mitm.network_observed` path.
  - Declared only (MITM-blind) → SRR runs on declared body;
    `cooperative.declared_only`.
- Policy epoch comparison with `allow_pinned_lease` opt-in.
- Token consumed on successful claim (one-time use).
- `X-GVM-Context-Token` stripped before upstream forward
  (CRITICAL — must not leak to GitHub, Slack, Stripe, etc.).

**Tests planned** (8):

- Claim with valid token → existing enforcement flow
- Claim with expired lease → `cooperative.expired` Deny
- Claim with re-used token → `cooperative.unbound` Deny
- Claim with mismatching observed body → `cooperative.mismatch`
  Deny; WAL captures both bodies (hashed)
- Header stripped before upstream
- Policy epoch mismatch → Deny by default, allowed under
  `allow_pinned_lease`
- Concurrent claim attempts on the same token — exactly one wins
- TOCTOU race: lease expires between header parse and claim

### Phase 3 — Blind-path token delivery (later)

- CONNECT-visible token: token presented on the CONNECT request
  line itself so the proxy can read it before the TLS tunnel
  closes over.
- Sidecar / out-of-band binding: token correlated to a sandbox-
  scoped network event (e.g. veth source-IP + dest-host + time
  window), removing the requirement that the agent set a header
  at all.
- Documentation of the trust model for each delivery channel.

---

## Why deny is logged but issuance is short-circuited

When the preflight SRR returns Deny:

- **No `context_token` is issued.** Returning a token alongside a
  Deny would be a footgun — orchestrators might inadvertently
  re-use it.
- **No `intent_id` is allocated.** A Denied lease should not occupy
  the intent store cap.
- **No `gvm.intent.lease_issued` WAL event.** That event's
  semantics are "a lease exists in the system."

A separate audit-only path could record `gvm.intent.lease_denied`
to surface attempted privilege escalations. **Phase 1 does not
emit this event** to keep the first cut surface small. Operators
who need denial visibility today should subscribe to the SRR
event stream (`GET /gvm/events?decision=Deny`), which captures
every Deny including the SRR rule that fired.

This is a deferred decision; if real demand surfaces, the
`lease_denied` event lands trivially in the existing handler.

---

## Why we extended `/gvm/intent` instead of creating a new endpoint

- The legacy URL-only register already lives at `POST /gvm/intent`.
  Existing MCP `gvm_declare_intent` callers continue to work
  unmodified.
- The lifecycle (Active → Claimed → Consumed) is the same. The
  cooperative variant adds policy-decision evidence and a token but
  uses the same state machine.
- The decision to "add fields" vs "fork an endpoint" follows the
  same principle that v0.5.3 SRR field additions did:
  `Option<>`-shaped additions are non-breaking and preserve a single
  source of truth.

---

## Why not a header-only fast path (X-GVM-Payload-Context)

The strategic review considered making the body context delivery a
header on the real request:

```http
POST /transfer HTTP/1.1
X-GVM-Payload-Context: {"amount": 100, ...}
```

Rejected as the **primary** path because:

- Header size limits (~8 KB on common proxy stacks) are smaller
  than the 16 KB payload context budget.
- In a TLS-pinned path the header lives inside TLS and the proxy
  cannot read it.
- Token / WAL lifecycle gets tangled with HTTP retries.

The pre-flight registration path (current design) lets the body
context arrive over a visible channel and lets the proxy commit
the decision to the WAL before the agent makes the real request.
A header fast path is left as a **future optional supplement** for
the visible-HTTP / MITM-success case where the agent's SDK
authored the request and can carry the projected context inline.
That supplement is Phase 4+ work.

---

## Open issues

- **Auto-projection / PII redaction.** Phase 1 trusts the
  operator to project `payload_context` correctly. A future
  `gvm.toml` clause could declare an allowlist of fields per host;
  the proxy would mask the rest at register time.
- **Lease persistence.** Like the injected SRR rules, leases live
  only in memory. A proxy restart loses them; orchestrators must
  re-issue. Persistence is a v0.7+ open question.
- **Multi-region.** A lease on one proxy is not visible to a
  sibling proxy in another availability zone. Phase 1 assumes
  per-agent affinity; cluster-wide lease coordination is a v0.7+
  decision.

---

## References

- [docs/srr.md](srr.md) — SRR engine, payload inspection, rule
  fields.
- [docs/security-model.md](security-model.md) — overall threat
  model and known limitations.
- [docs/internal/CHANGELOG.md](internal/CHANGELOG.md) — Phase 1
  ship entry under `2026-06-18: Cooperative intent lease`.
- [tests/cooperative_intent_lease.rs](../tests/cooperative_intent_lease.rs)
  — Phase 1 regression suite.
