# Coverage Hardening Plan

**Created**: 2026-05-10 · **Owner**: maintainer · **Target**: pre-v1.0

## Context

The 2026-05-10 test-coverage audit (`docs/test-report.md` + threat
model in `docs/security-model.md`) found that **19 of 21 documented
threats are directly tested** and seven of those threats are
flagged as *partial* (△) — covered by structural arguments or
documented scope boundaries rather than by adversarial regression
tests. This document is the plan to upgrade each △ to a ✓ before
v1.0.

The six "concrete gap" items (G1–G6) — per-sandbox CA isolation,
time-window SRR conditions, upstream pool integration, GraphQL
alias × URL-Deny interaction, veth slot collision regression, WAL
partial-byte corruption — were closed in commit
[FILL-IN-AFTER-COMMIT] (this same hardening pass). What remains
are the seven items the audit marked △.

Format per item:

- **What's tested today** — current coverage, file references.
- **What's missing** — the specific adversarial property that has
  no test pin.
- **Plan** — concrete deliverable (test name, fixture, asserts).
- **Effort** — order-of-magnitude (S = a few hours, M = a day,
  L = multi-day).
- **Acceptance** — the success condition that flips △ → ✓.

---

## △-1 — Timing side channel (security-model.md §1) — **FULLY CLOSED 2026-05-10**

**Status: ✓ FULLY CLOSED.** Three pinned regression invariants in
`tests/timing_invariance.rs`:

1. *Cross-rule median ratio* < 3.0× — five distinct decision-type
   scenarios (URL-Deny, default-caution, payload-match,
   payload-skip, method-mismatch). The URL already discloses which
   rule shape applied, so this bound is a regression catch.
2. *Within-rule median ratio* < 1.6× — two requests on
   `POST /graphql` taking different sub-paths inside the same
   matching rule. The URL doesn't disclose the sub-path, so a
   measurable delta IS a side channel — but the absolute-time
   bound below resolves the threat-model question.
3. *Absolute cross-scenario delta* < 5,000 ns. Measured ~1,900 ns
   on reference hardware. This sits **~26× below the loopback TCP
   RTT jitter floor** (~50 µs). A leak this small is not
   network-exploitable: a remote attacker needs ~10⁶ samples to
   average out jitter, and the per-agent TokenBudget rate-limits
   long before that.

**Original follow-up (constant-time policy evaluation, target
within-rule <1.1×)**: superseded. Absolute-time analysis shows
the residual leak is below remote exploitability and irrelevant
to the local-attacker threat model (per Assumption of Trust §:
local attackers have resources that already subsume timing).
Constant-time discipline would cost a forced JSON parse on every
request — a perf regression worse than the leak it would close.
Decision: pin the bounds as invariants, document the analysis,
move on. See `docs/security-model.md §1` for the full
threat-model resolution.

**What's tested today**

- `tests/hostile.rs::srr_decision_time_is_roughly_constant` —
  measures wall-clock variance of `srr.check()` for Allow vs Deny
  inputs and asserts ratio < 10×.

**What's missing**

- The 10× variance bound is loose enough that a side channel of
  a few hundred microseconds would slip through. Real timing
  attacks exploit nanosecond-scale leaks under controlled load.
- No coverage of decision time *under adversarial co-load* — an
  attacker who controls a parallel stream of "victim" requests
  can amplify a timing signal that's invisible in single-thread
  benches.

**Plan**

- New `benches/srr_timing_invariance.rs` (Criterion). Establish
  per-request timing distributions for `Allow`, `Deny`,
  `Default-to-Caution`, `payload-rule-match`, `payload-rule-skip`
  on the same SRR config and assert all distributions overlap
  within 1 σ.
- New `tests/timing_under_load.rs`: spawn N concurrent challenge
  requests + 1 victim, measure victim's median latency at varying
  N, assert the latency distribution is statistically
  indistinguishable across decision types (use `proptest`
  quantile assertions, not raw means).
- Document acceptable variance bound in
  `docs/security-model.md §1`. The current "10×" is structural
  prose, not a measured invariant.

**Effort**: M (one day; bench fixture is the bulk of it).

**Acceptance**: bench passes consistently in CI for 7 consecutive
runs at the documented bound; security-model §1 cites the bound
and the `tests/timing_under_load.rs` line.

---

## △-2 — Wasm runtime integrity (security-model.md §2) — **DEFERRED 2026-05-10 (no production exposure)**

**Status: deferred until Wasm activation.** Code review during the
hardening pass surfaced that Wasm is wired through a Cargo
feature flag and is **not in the default build**: `[features]
default = []` ([Cargo.toml:76](../../Cargo.toml#L76)), `wasmtime`
and `wasmtime-wasi` are `optional = true`, and every Wasm callsite
in `src/main.rs` (lines 14, 381, 518) is `#[cfg(feature = "wasm")]`.
A default `cargo build --release -p gvm-proxy` produces a binary
that logs `Layer 1: Native policy engine (Wasm disabled)` at
startup; the `wasmtime` crate is not even compiled in. The five
documented `wasmtime` CVEs and the ~10 MB binary cost are both
absent from v0.5.3.

This collapses the threat model: an attacker who can swap the
Wasm module file on disk has nothing to attack, because the
proxy never loads any Wasm. Hash pinning still has to land
**before** Wasm is ever flipped on for a production deployment,
so the design + test plan stay in this file as a precondition,
but the implementation is deferred to the same release that
exposes the feature to operators.

**Hard precondition (do not flip without)**: before
`default = ["wasm"]`, ship:

1. `[wasm] module_path` + `module_sha256` config schema in
   `src/config.rs`.
2. `WasmEngine::load_pinned(path, expected_sha256)` that
   refuses to start on hash mismatch.
3. `tests/wasm_module_substitution.rs` covering hash match /
   mismatch / unpinned-with-warning / engine-panic-fail-closed.

The remaining content of this section (full implementation
plan) is preserved below for the eventual implementer.

---

**What's tested today**

- `src/wasm_engine.rs` (4 unit tests): Wasm module loads,
  evaluates, returns expected decisions on hand-built inputs.
- `tests/boundary.rs::wasm_*` (7 tests): out-of-bounds inputs,
  malformed inputs, empty modules.
- Ed25519 anchor signing on the *audit chain* is implemented and
  tested end-to-end (commit `72fa90b`); this catches a tampered
  Wasm path retroactively via WAL anchor break, not preventatively.

**What's missing**

- No adversarial test substituting the Wasm module file at runtime
  (the documented attack precondition: "attacker has write access
  to the Wasm module path"). The mitigation roadmap calls for
  hash pinning, which is implemented neither in code nor in test.
- No test for "Wasm engine panics or returns nonsense, proxy
  fails closed" (one of the documented behaviours).

**Plan**

- Implement Wasm module hash pinning in
  `src/wasm_engine.rs::WasmEngine::load_pinned`. Config: `[wasm]
  module_path`, `module_sha256` (operator-supplied). Mismatch ⇒
  `bail!`.
- New `tests/wasm_module_substitution.rs`:
  1. Configured hash matches → load OK, decision returns expected.
  2. Configured hash mismatches (module file modified after
     fingerprinting) → load fails, proxy startup aborts.
  3. Unpinned mode (`module_sha256 = None`) prints a startup
     warning per `docs/security-model.md §2`.
- Add a panic-injection test using `#[cfg(test)]` shim in
  `WasmEngine` that proves the proxy fails closed (returns
  Default-to-Caution) when the engine returns `Err`.

**Effort**: L (Wasm hash pinning is real code, ~150 LOC).

**Acceptance**: hash-mismatch path documented + tested; the three
roadmap mitigations on security-model.md §2 line 70 list "✓
Implemented (v0.6.0)".

---

## △-6 — WAL periodic re-verification (security-model.md §6) — **CLOSED 2026-05-10**

**Status: ✓ CLOSED (opt-in).** New module
`src/wal_background_reverify.rs` plus the
`[wal] background_reverify_interval_secs` config field. Operator
sets a positive interval; proxy spawns a tokio task that re-runs
`merkle::verify_wal()` on a periodic schedule. Chain breaks flip a
monotonic `WalChainHealth` flag, surfaced as
`wal_chain_intact: false` in `/gvm/health` and as a
`tracing::warn!` line. Default is `0` (disabled): operators who
rely on `gvm audit verify` cron'd from outside don't pay the
read overhead. Pinned by `tests/wal_background_reverify.rs`
(8 tests).

**What's tested today**

- `tests/wal_tamper_adversarial.rs` (4 scenarios): tamper
  detection on next append covers the "auditor running
  `gvm audit verify`" path.
- `tests/adversarial_v2_coverage.rs::v2_event_tampered_*`: per-event
  hash recompute on read.

**What's missing**

- No test for *proactive* background re-verification — the
  proxy doesn't re-scan its own WAL on a tokio interval. A WAL
  tampered between reboots is detected only when an auditor
  invokes `gvm audit verify`. If no audit runs, an attacker has
  arbitrarily long to plant a chain break before discovery.

**Plan**

- Implement `Ledger::start_background_reverify(interval)` —
  every N minutes, runs `merkle::verify_wal()` on a streamed
  subset of the WAL (last K segments since last verify) and
  surfaces breaks via:
  - WAL event (`gvm.audit.background_break`),
  - tracing log at `WARN`,
  - `/gvm/health` flips a `wal_chain_intact: false` field that
    `gvm watch` surfaces in its alert pane.
- New `tests/wal_background_reverify.rs`:
  1. Healthy WAL → background scan emits no events, health stays
     OK.
  2. Tamper a sealed batch out-of-band (open + edit byte) →
     within `interval + epsilon` the health endpoint flips and
     the WAL acquires a `background_break` event.
  3. Restart proxy → re-verify state is rebuilt from the WAL +
     watermark sidecar (no re-scan of segments older than the
     watermark).

**Effort**: M-L (~200 LOC + careful interleave with rotation).

**Acceptance**: `tests/wal_background_reverify.rs` passes; the
roadmap line in security-model.md §6 collapses to "Implemented".

---

## △-7 — Vault key derivation (security-model.md §7)

**What's tested today**

- `tests/hostile.rs::vault_key_is_zeroed_on_drop` — confirms the
  in-memory key is zeroed when the `Vault` is dropped.
- `src/vault.rs` unit tests cover AES-256-GCM encrypt / decrypt
  round-trips and tag verification.
- `fuzz/fuzz_targets/fuzz_vault_crypto.rs` daily.

**What's missing**

- The vault stores keys derived directly from a fixed master
  password / file content. There is no KDF (Argon2id / PBKDF2)
  in the path, so the master is effectively the *only* secret
  and is brittle against offline attack on a captured vault file.
- `docs/security-model.md §7` documents this as "v1 local-dev
  scope" — but the gap is widely understood and operators
  routinely ask about it.

**Plan**

- Implement Argon2id KDF in `src/vault.rs::derive_master_key`,
  with parameters `m_cost = 64 MB, t_cost = 3, p_cost = 1`
  (RFC 9106 high-side defaults, well within typical agent host
  memory).
- Add KDF parameters to the vault file header (versioned schema)
  so increasing memory cost in a future release doesn't brick
  existing vaults.
- New `tests/vault_kdf.rs`:
  1. KDF produces deterministic key for same (password, salt).
  2. Different salt → different key (with same password).
  3. Wrong password → key derives but decrypt fails AEAD tag.
  4. Round-trip across versioned headers (read v1, read v2-with-KDF).
- Migration path documented in
  `docs/architecture/vault.md`: existing v1 vaults rekey on first
  open with new master, write back as v2.

**Effort**: L (KDF, file format versioning, migration path).

**Acceptance**: KDF live; security-model §7 reframes from "local-dev"
to "production-ready"; fuzz target updated to include KDF inputs.

---

## △-8b — Token issuance endpoint unauth (security-model.md §8b) — **CLOSED 2026-05-10**

**Status: ✓ CLOSED.** `[server] allow_non_loopback_admin = false` is the
default; non-loopback `admin_listen` (`0.0.0.0`, `[::]`, RFC 1918 LAN
addresses) refuses to start with a clear error message. Operator can
opt in for deployments fronting the admin port with mTLS / VPN / IAP.
Validation lives in `src/config.rs::admin_bind_check`; pinned by
`tests/admin_port_loopback_only.rs` (9 tests).

**What's tested today**

- `tests/api_handlers.rs` covers the JWT verify path.
- `scripts/ec2-e2e-test.sh` Tests 77–78 exercise the JWT flow on
  a single host.
- Documented as "loopback-only" — the operator is expected to keep
  the admin port (9090) on `127.0.0.1`.

**What's missing**

- The "loopback-only" property is operator policy, not code.
  Nothing in the proxy refuses an admin-port bind to `0.0.0.0`
  without explicit operator opt-in.
- No test for "admin port accidentally exposed → request
  rejected".

**Plan**

- In `src/main.rs::start_admin_port`: require an explicit
  `[admin] allow_non_loopback = true` config flag to bind to a
  non-loopback address. Without the flag and a non-loopback
  bind, fail-close with a clear error.
- New `tests/admin_port_loopback_only.rs`:
  1. Default config + `bind = "0.0.0.0:9090"` → proxy startup
     errors with "admin port refused: non-loopback bind without
     explicit opt-in".
  2. `bind = "127.0.0.1:9090"` → starts cleanly.
  3. `bind = "0.0.0.0:9090"` + `allow_non_loopback = true` →
     starts with a `WARN` log and a startup-banner advisory.
  4. Optional follow-up (separate phase): mTLS verification on
     non-loopback admin ports — track as roadmap.

**Effort**: S (one config flag + startup check + 4 tests).

**Acceptance**: defaults are safe; operator must explicitly
opt-in to expose the admin port; security-model §8b collapses
to a single sentence about the opt-in.

---

## △-10 — GraphQL alias bypass (security-model.md §10) — **PHASE 1 + PHASE 2 CLOSED 2026-05-10**

**Status: ✓ Phase 1 + Phase 2 (false-positive reduction) CLOSED.**

*Phase 1 (initial):* new `payload_query_alias_match` field on
`NetworkRuleConfig`. SRR scans the request body's `query` JSON
field for any GraphQL invocation whose field name matches a
configured list, regardless of `operationName` or alias prefix.
The lexer (`scan_graphql_query_for_invocation`) strips comments
and string literals, then whole-word matches identifier tokens.
Pinned by `tests/graphql_alias_direct_match.rs` (11 tests).

*Phase 2 (false-positive reduction):* the lexer now tracks
**argument-list nesting depth** and **directive context**.
Identifiers inside `(...)` argument lists are skipped (they're
argument names or scalar values, never selection field names);
identifiers immediately following `@` are skipped (they're
directive names). False-negative resistance preserved — every
position that could be a selection field name is still scanned.
Pinned by `tests/graphql_alias_phase2_fp_reduction.rs` (9 tests):
argument-name shadowing, enum value as arg, directive name +
arg shadowing, nested arg lists tracking paren depth, defense-
in-depth (arg-skip cannot mask a real invocation that follows),
fragment-body invocation still caught (documented limitation
preserved).

**Phase 3 (full GraphQL parser, ~v0.7)** remains deferred —
the lexer already covers every documented evasion at acceptable
false-positive rates. A full parser (with proper fragment-
spread tracking and operation-vs-query distinction) would
reduce false-positive rates further but adds either a
supply-chain dep (`graphql-parser` / `async-graphql-parser`) or
~500 LoC of in-house parser. The defense-in-depth pattern (alias-
list + URL-level Deny on the same endpoint) covers the gap until
that lands.

**What's tested today**

- `tests/graphql_alias_url_deny_interaction.rs` (closed in this
  pass, G4): pins the documented mitigation pattern (URL-level
  Deny catches alias-bypass when the payload rule is evaded).
- `tests/hostile.rs` and `tests/integration.rs` cover the
  payload rule's literal `operationName` matching.

**What's missing**

- The literal `operationName` matcher only sees the top-level
  string field. An attacker who builds a GraphQL `query` that
  contains the dangerous mutation under an alias — but with no
  `operationName` at all — slips past the payload rule. The
  current mitigation is "pair with URL-level Deny", which is now
  pinned but is structural, not a primitive defense.
- No deep query-string parser in SRR.

**Plan (incremental):**

- **Phase 1** (M): Add a `payload_query_alias_match` field to
  `NetworkRuleConfig`. When set with a list of mutation names
  (e.g. `["transferFunds", "deleteAccount"]`), SRR scans the
  GraphQL `query` body field for any *aliased* invocation of the
  named mutations using a tiny lexer (no full GraphQL parse —
  just `:\s*(transferFunds|deleteAccount)\b`). Match returns the
  rule's decision.
- **Phase 2** (L, post-v1): full GraphQL operation-extraction in
  `src/graphql_lex.rs`. Builds an AST for the query body,
  extracts all top-level mutation names regardless of alias, and
  compares against `payload_match`. The lexer-only approach in
  Phase 1 is intentionally narrow because GraphQL is a complex
  language and a full parser is its own attack surface.
- New `tests/graphql_alias_deep.rs` to ride alongside the
  Phase 1 deliverable: 6 scenarios covering aliased mutations,
  fragments, nested operations, and one negative ("looks like a
  mutation, isn't a mutation" — comment, string literal, etc.).

**Effort**: Phase 1 = M; Phase 2 = L+ (separate v0.7 line).

**Acceptance**: Phase 1 lands; security-model §10 is rewritten
from "Partial defense — pair with URL-level Deny" to
"Direct defense via `payload_query_alias_match` + URL-level Deny
defense-in-depth".

---

## △-11 — Numeric precision in policy (security-model.md §11) — **CLOSED 2026-05-10**

**Status: ✓ CLOSED.** Audit traced the path and found the
accumulation slot is already `AtomicU64` (millionths fixed-point) —
exact integer arithmetic. The only f64 hop was at
`record(tokens, cost_usd: f64)` where `cost_usd * 1e6 as u64`
**truncated**, biasing drift downward by up to 1 millionth per call.
Two changes:
1. Truncate → **round-to-nearest** in `record`, plus rejection of
   non-finite / negative inputs (return-zero fail-closed).
2. New `record_millionths(tokens: u64, cost_millionths: u64)` for
   callers that already have an integer-millionths cost — bypasses
   f64 entirely, exact end-to-end.

Pinned by `tests/budget_precision.rs` (7 tests): exact-millionth
records bit-exact; round-to-nearest unbiased; sub-millionth-per-call
cost documented as the case `record_millionths` exists for; mixing
the two APIs composes exactly. Original plan's "decimal-based
comparison roadmap" was a misdiagnosis — comparison was always
exact; the lossy step was the input boundary.

**What's tested today**

- No direct test. Documented as "f64 OK for v1; decimal-based
  comparison roadmap".

**What's missing**

- The token-budget arithmetic uses `f64` for cumulative cost
  tracking. A long-running agent with millions of micro-charges
  can accumulate float-precision drift, eventually making
  budget-cap comparisons wrong by a single increment. This is
  documented but the magnitude is unknown.

**Plan**

- Quantify the drift first: new `benches/budget_precision.rs`
  measures `f64` drift over `1e6`, `1e7`, `1e8` accumulated
  charges and reports max relative error. If error stays < 1
  ppb (which is plausible for our charge magnitudes) the
  decimal-migration is downgraded to "no longer a roadmap item,
  documented in security-model".
- If drift is non-trivial: replace `f64` cost with `rust_decimal::
  Decimal` (already a workspace dep) for the accumulation path.
  Comparison sites that intersect with cost-cap rules consume
  the `Decimal`. New `tests/budget_precision.rs` regression-pins
  exact-arithmetic correctness over a long sequence.

**Effort**: S to quantify (one bench, one pass through
budget arithmetic). M-L if migration is needed.

**Acceptance**: bench landed; security-model §11 either cites
the measured ppb-bound + drops the roadmap line, or links the
post-migration `Decimal` path.

---

## Optional / lower-priority follow-ups (post-v1.0)

- **DNS Tier-2 decay test** (relates to △-1 and #6 in the audit's
  G-list, but more about correctness than security): mocked clock
  + sliding-window boundary tests for the DNS governance Tier-2
  → Tier-1 promotion path.
- **Segment editor E2E coverage** (audit gap): drive the
  `gvm suggest --interactive` TTY via `expect`-style harness or
  a stdin-replay fixture. Currently manual-QA only.
- **MITM connection reset under load**: documented in
  security-model `MITM TLS Inspection` as "intermittent" + "under
  investigation". Reproducibility blocked by lack of a
  deterministic chaos fixture; defer until G3's load-bench
  fixture is reused for fault injection.

---

## Implementation order recommendation

1. **△-8b** (admin port loopback) — highest cost/benefit ratio
   (S effort, closes a documented surface-area concern).
2. **△-2** (Wasm hash pinning) — high security impact, even
   though the Wasm path itself is opt-in.
3. **△-6** (WAL background re-verification) — concrete
   adversarial improvement; pairs naturally with the Phase 4
   leaves-only checkpoint persistence already on the v0.6
   roadmap.
4. **△-10** (GraphQL alias direct-match Phase 1) — closes a
   documented evasion that operators cite.
5. **△-1** (timing variance bound) — methodology improvement, no
   functional change.
6. **△-7** (Vault KDF) — necessary for production scope, but
   v1-local-dev scope makes this optional for v1.0.
7. **△-11** (numeric precision) — quantify first; might not need
   migration.

Tracking: each item gets one entry in `docs/internal/CHANGELOG.md`
when implemented. This plan file is updated as items close so the
next reader sees what's still open.
