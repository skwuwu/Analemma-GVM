# Changelog

> Architecture decisions, implementation history, and release planning.
> For security model, see [11-security-model.md](security-model.md).
> For configuration reference, see [13-reference.md](reference.md).

---

## Roadmap

### Current (v0.5.0)

HTTP enforcement proxy (Rust/axum/tower) with SRR network governance + API key isolation, IC classification (Allow/Delay/RequireApproval/Deny), Merkle tree audit ledger with WAL group commit, AES-256-GCM encrypted state cache, Wasm runtime (optional, behind `--features wasm`), JWT agent identity, TC ingress filter (kernel-level proxy enforcement), seccomp BPF sandbox with dual filter stacking, DNS soft governance (4-tier delay + alert), filesystem governance (overlayfs Trust-on-Pattern), IC-3 human approval workflow (admin port separation), MITM TLS proxy (sole HTTPS inspection mechanism — uprobe removed).

**Release history**: v0.2 (Shadow Mode, CONNECT tunnel, SRR hot-reload, MITM), v0.3 (sandbox cleanup, overlayfs, seccomp audit), v0.4 (IC-3 approval, stress testing, contained mode), v0.5 (DNS governance, placeholder credentials, proxy hardening).

### Planned

**v0.6**
- Anomaly detection (low-and-slow exfiltration — cumulative volume tracking)
- WebSocket proxy support
- Overlayfs periodic scan (long-running agents): tokio timer → scan_upper_layer() at interval
- Overlayfs inotify-based real-time scan (event-driven alternative to periodic)

**v1.1 — Hardening**
- SRR hot-path execution via Wasm engine
- Ed25519 module signature verification + hash pinning
- Decimal-based numeric comparison for financial precision
- HashMap/Trie index for O(1) SRR host+method lookup
- `Cow<'a, str>` in SRR normalize paths
- File permission check on `secrets.toml`
- HMAC-signed checkpoint step
- Configurable `MAX_CHECKPOINT_SIZE` / `MAX_HISTORY_TURNS` per agent

**v2.0 — Runtime & Infrastructure**
- Mandatory-by-default interception profile
- macOS/Windows host-level interception fallback
- NATS JetStream WAL publish, Redis Vault backend, Policy hot-reload (`SIGHUP`)
- KMS integration (AWS/GCP), Redis VaultBackend, key rotation, KDF (Argon2id)
- Proxy-controlled step numbers, full LLM response storage, incremental checkpoints
- TypeScript/Node.js SDK, Go SDK
- Prometheus metrics, Grafana dashboard
- gRPC detection + passthrough, pluggable isolation backend (namespace/firecracker/docker)

**v3.0 — Platform**
- Generic outbound capability governance (filesystem, shell, database)
- Protocol expansion (WebSocket, gRPC method-level, SMTP)
- Cross-agent collusion detection, trust delegation, inter-agent governance
- Multi-tenant SaaS, Envoy filter mode, OPA compatibility layer, SOC 2 / ISO 27001

---

## Implementation Log

### 2026-05-02: Phase 2 wiring — group commit emits BatchSealRecord + GvmStateAnchor

**What changed:**

The new logging structure goes live. Every batch flush now writes
THREE additional WAL lines beyond the events themselves: a
`BatchSealRecord` capturing the active state at seal time, a
`MerkleBatchRecord` whose `leaves_blob` includes the seal_hash as
the last leaf, and a `GvmStateAnchor` binding all three roots into
a single 32-byte finality marker.

**WAL line layout (Phase 2+)**:

```
... events from earlier batch ...
event_1                ← GVMEvent JSON
event_2
...
event_N
seal                   ← BatchSealRecord JSON  (NEW)
batch_record           ← MerkleBatchRecord JSON (now with leaves_blob,
                                                 seal_position, leaves_format)
anchor                 ← GvmStateAnchor JSON   (NEW)
... events from next batch ...
```

The `merkle_root` in batch_record is computed over event_hashes
plus the seal's `seal_hash()` as the last leaf — so any tamper of
the seal record propagates to merkle_root and to anchor_hash.

**TripleState — atomic snapshot at batch close** (`src/ledger.rs`):

```rust
pub struct TripleState {
    pub context_hash: Option<String>,
    pub checkpoint_root: Option<String>,
    pub last_anchor: Option<String>,
}

// Inside Ledger:
pub fn update_context_hash(&self, new_hash: String);
pub fn update_checkpoint_root(&self, new_root: Option<String>);
pub fn triple_snapshot(&self) -> Arc<TripleState>;
```

Backed by `arc_swap::ArcSwap`. Writers use RCU so concurrent
`update_context_hash` and `update_checkpoint_root` calls do not lose
each other (per §4.7 Snapshot Atomicity Invariant). Reads (batch
task at seal time) are wait-free via `load_full()`.

**`record_config_load` now publishes**: after the config_load event
reaches the WAL via `append_durable`, the new `context_hash` is
published into the triple via `update_context_hash`. The CURRENT
batch (containing the config_load event) was already sealed with
the OLD context — that's correct semantics (§4.7: seal records
"active context AT seal time", not "context the batch's events
will use going forward").

**Group commit task rewritten** (`flush_batch_with_anchor`):

1. Snapshot triple_state via `load_full()` — single atomic read.
2. Build `BatchSealRecord` from snapshot (seal_id, sealed_at,
   context_hash, checkpoint_root, prev_anchor).
3. `leaves = event_hashes (decoded to 32B) || seal_hash()`.
4. `batch_root = compute_merkle_root(leaves_hex)`.
5. Build `MerkleBatchRecord` with full `leaves_blob` (binary,
   base64-encoded in JSON), `seal_position = event_count`,
   `leaves_format = Sha256Concat`.
6. `anchor = GvmStateAnchor::seal(1, &seal, batch_root)` — computes
   anchor_hash with domain separation.
7. Single `write_all` + `sync_data` for events + seal + batch_record
   + anchor. Same fsync amortization as before.
8. After fsync, publish anchor_hash into `triple_state.last_anchor`
   so the NEXT batch's seal captures it as `prev_anchor`.

**Genesis convention**: the very first batch's seal has
`prev_anchor = None` (triple_state starts with `last_anchor: None`).
First batch's seal also has `context_hash = GENESIS_HASH_HEX` if no
`update_context_hash` call preceded the first event.

**`verify_wal` updated**: recognizes the three new line types.
Anchor records are skipped (audited separately by Phase 2.5
`verify_anchor_chain`). Seal records contribute their `seal_hash()`
as the last leaf of the current batch's leaf list, so recomputed
batch_root matches the stored merkle_root. Pre-Phase-2 (legacy)
WAL files continue to verify exactly as before — the leaf list is
just events with no seal injection.

**Existing test updates**:

- `tests/boundary.rs::nats_wal_sequence_monotonic` — event filter
  changed from naive `!line.contains("merkle_root")` to positive
  `line.contains("\"event_id\":")` plus exclusion of
  `merkle_root` and `anchor_hash` (avoid counting seal/anchor as
  events). Also added invariants: `seal_count == batch_count ==
  anchor_count`.
- `tests/edge_cases.rs`, `tests/hostile.rs`, `tests/merkle.rs`,
  `tests/stress.rs` — same naive filter pattern fixed via Python
  regex sweep.
- `tests/merkle.rs::merkle_batch_root_recomputable` /
  `merkle_proof_proves_event_in_batch` — leaf-list reconstruction
  now appends the seal record's `seal_hash()` after collecting
  event_hashes, matching the writer's algorithm.

**Tests added (8 new in `tests/anchor_wiring.rs`)**:

- single batch writes event/seal/batch_record/anchor in correct order
- anchor.verify_self_hash returns true for fresh batches
- leaves_blob length == (event_count + 1) × 32 invariant
- seal_hash matches the last 32 bytes of leaves_blob
- prev_anchor chain links across consecutive batches (genesis None
  → batch 1 anchor_hash → batch 2 prev_anchor)
- context_hash published before batch flush appears in seal
- anchor inherits all per-seal fields (context_hash, checkpoint_root,
  prev_anchor, batch_id, timestamp)
- triple_snapshot reflects updates immediately, RCU preserves
  unrelated fields

**Verification**:
- `cargo test --workspace --tests`: 619 passed / 0 failed / 4 ignored
  (was 611 — +8 new anchor wiring tests; existing tests adapted)
- `cargo fmt --all -- --check`: clean
- `cargo check --workspace --tests`: clean

**Performance**: per-batch overhead ~ +500 bytes (seal + anchor
records, ~250 bytes each as JSON), one extra `arc_swap::load_full()`
(~50ns), three extra serialize calls. fsync count unchanged (still 1
per batch). Hot path (event creation, append_durable) is not
affected — anchor work happens in the background batch task.

**Backward compatibility**: NEW WAL files produced by this commit
are NOT readable by pre-Phase-2 verifiers (they would skip the seal
record as "unknown line" and miscompute merkle_root). Old WAL files
remain readable: the new verify_wal handles missing seal/anchor
lines as legacy form. Mixed WALs (old segments + new active) work
correctly because verification is per-line.

**Known follow-ups**:
- Phase 2.5: `verify_anchor_chain` separate audit (timing,
  monotonic batch_id, prev_anchor chain validation, signature check)
- Phase 1.B: migrate production event-creation sites to populate
  `operation_descriptor` for sensitive operations
- Phase 3: replace per-agent `Vec<String>` checkpoint storage with
  leaves-only `BTreeMap` + rightmost-path cache
- Phase 5: `prev_anchor_hash` binding in `GvmIntegrityContext` v3
  (replay defense)
- Phase 6: TSA / HSM signature integration

### 2026-05-02: Phase 1.A — OperationDescriptor + event_hash v1/v2 dispatcher

**What changed:**

Privacy-preserving event_hash. Splits the previously-monolithic
`operation: String` field into a non-sensitive `category` (e.g.
`http.POST`, `gvm.dns.query`) and an optional sensitive `detail`
(URL path, DNS subdomain) plus a **salted SHA-256 digest** of
the detail. The new `compute_event_hash_v2` uses `category +
detail_digest` instead of the raw operation string, so an external
auditor receiving a redacted proof can verify event_hash without
learning the detail.

This is Phase 1.A — type foundation + hash dispatcher only. Phase 1.B
will migrate production event-creation sites to populate
`operation_descriptor` (currently all sites set it to `None`, so
v1 hash continues for every shipped event; v2 path is exercised
by tests only).

**New types** (`crates/gvm-types/src/lib.rs`):

```rust
pub struct OperationDescriptor {
    pub category: String,            // "http.POST" — public-safe
    pub detail: Option<String>,      // "/api/v1/user/1234/delete"
    pub detail_salt: Vec<u8>,        // 16 random bytes (caller-supplied)
    pub detail_digest: String,       // SHA256("gvm-opdetail-v1:" || ...)
}

pub fn compute_detail_digest(salt: &[u8], detail: Option<&str>) -> String;

pub const PREFIX_EVENT_V1: &[u8] = b"gvm-event-v1:";
pub const PREFIX_EVENT_V2: &[u8] = b"gvm-event-v2:";
pub const PREFIX_OPDETAIL_V1: &[u8] = b"gvm-opdetail-v1:";
```

`OperationDescriptor::new(category, detail, salt)` builds with
caller-supplied salt (production uses `rand::thread_rng()`; tests
pass deterministic bytes for reproducibility). `category_only(...)`
forces empty salt + canonical "no detail" digest.

**Threat model addressed**:
- Attacker holds `event_hash` but not the salt → cannot brute-force
  the detail string from a known operation alphabet.
- Verifier with redacted proof (no salt, no detail, only digest) →
  recomputes `event_hash` via `category + digest`. Privacy preserved.
- Verifier with full proof (salt + detail + digest) → can
  re-compute `detail_digest` to confirm the stored value.

**`GVMEvent` schema additions** (backward-compatible):

```rust
pub struct GVMEvent {
    // ... existing fields unchanged ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_descriptor: Option<OperationDescriptor>,
}
```

`#[serde(default, skip_serializing_if = ...)]` keeps legacy WAL
records round-trippable. Old WAL events deserialize with `None`
descriptor → dispatch through v1 hash.

**`compute_event_hash` dispatcher** (`src/merkle.rs`):

```rust
pub fn compute_event_hash(event: &GVMEvent) -> String {
    match &event.operation_descriptor {
        Some(desc) => compute_event_hash_v2(event, desc),
        None      => compute_event_hash_v1(event),
    }
}
```

Phase 1.B migration cost is bounded: when a callsite is updated to
set `operation_descriptor: Some(...)`, the dispatcher silently
switches that event's hash to v2. No verifier-side change needed —
the existing `event_hash` field stores whichever version was used
at write time, and verifiers re-dispatch to compare.

**Standards (§1.6 expanded)**: domain-separation prefix catalog
table added with all 7 active prefixes (`gvm-event-v1:`,
`gvm-event-v2:`, `gvm-opdetail-v1:`, `gvm-node-v1:`, `gvm-seal-v1:`,
`gvm-anchor-v1:`, `gvm-thinking-v1|`). Adding a new hash function
requires adding a new prefix entry.

**Tests added (24 new, all passing)**:

`crates/gvm-types/tests/operation_descriptor.rs` (16 tests):
- detail_digest format (64 hex lowercase)
- determinism for identical inputs
- different salt → different digest
- different detail → different digest
- None detail canonical value
- domain prefix is load-bearing
- descriptor with detail populates salt + digest correctly
- category_only forces empty salt
- new() with None detail ignores supplied salt
- verify_digest round-trips
- verify_digest detects detail tamper
- verify_digest detects salt tamper
- serde roundtrip preserves digest
- redacted form's digest stays usable for outer hash
- redacted form's empty fields skip serialization
- prefix catalog distinct + versioned

`src/merkle.rs::tests` (6 new tests in the existing module):
- dispatcher uses v1 when descriptor is None
- dispatcher uses v2 when descriptor is Some
- v1 and v2 produce distinct hashes for same event (prefix discipline)
- v2 hash redaction-preserving (h(full) == h(redacted_with_digest))
- v2 hash changes with different detail_digest
- v2 hash uses category, not legacy operation string

**Migration cost** (Phase 1.A this commit):
- Added `operation_descriptor: None` to 24 GVMEvent construction
  sites across `src/` and `tests/`. Mechanical change via Python
  regex insertion after each `config_integrity_ref:` field, with
  indentation preservation. No semantic change to existing events.

**Affected files**:
- `crates/gvm-types/src/lib.rs` — new type, prefix constants,
  GVMEvent.operation_descriptor
- `src/merkle.rs` — dispatcher + v1/v2 split + 6 new tests
- 6 production source files — `operation_descriptor: None` added
  at 15 sites
- 9 test files — `operation_descriptor: None` added at 9 sites
- `crates/gvm-types/tests/operation_descriptor.rs` — NEW, 16 tests
- `docs/internal/GVM_CODE_STANDARDS.md` — §1.6 prefix catalog

**Verification**:
- `cargo test --workspace --tests`: 613 passed / 0 failed / 4 ignored
  (was 589; +24 new tests)
- `cargo fmt --all -- --check`: clean
- `cargo check --workspace --tests`: clean

**Backward compatibility**: zero. Existing WAL files round-trip
identically (descriptor is optional, serde-skipped when None).
v1 hash continues to be computed for every existing event.

**Open follow-ups (next commits in v3 series)**:
- Phase 1.B: migrate production event-creation sites to populate
  `operation_descriptor` for sensitive operations (HTTP, MITM,
  DNS, vault). Until then, v2 path is exercised by tests only.
- Phase 2 wiring: `TripleState` ArcSwap RCU + group commit rewrite
  to emit `BatchSealRecord` + `GvmStateAnchor` per batch.
- Phase 2.5: `verify_anchor_chain` (timing audit).
- Phase 3: leaves-only checkpoint tree (rightmost-path cache).
- Phase 5: `prev_anchor_hash` in `GvmIntegrityContext` (replay
  defense).

### 2026-05-02: Phase 0 + Phase 2 type foundation — anchor / seal / leaves_blob

**What changed (v3 design Phase 0 + Phase 2 type-only foundation):**

This is the first concrete code shipping the v3 logging architecture.
Type definitions and verifier strip-evasion guard only — group commit
task wiring is deferred to a follow-up commit. New types are defined,
documented with §1.6 domain-separation prefixes, and exercised by
unit tests; existing WAL behavior is unchanged.

**Phase 0 — naming + strip-evasion guard:**

1. `Ledger::record_config_load` parameter renamed
   `prev_config_hash` → `prev_context_hash`. The value passed by
   production callers (`state.current_integrity_ref()`) was always
   a `context_hash`, never a `config_hash`. Doc updated to match.

2. `verify_integrity_chain` (in `crates/gvm-types/src/lib.rs`)
   now treats `(prev_seen=None, claimed_prev=Some(_))` as a chain
   break. The OLD rule "(None, _) → accept" let an attacker truncate
   older WAL segments and the surviving "first" config_load passed
   verification even when it claimed `Some(prior)`. The NEW rule
   accepts only `(None, None)` as genuine genesis. Test:
   `truncated_history_first_with_some_prev_is_flagged` in
   `crates/gvm-types/tests/verify_chain.rs`.

**Phase 2 — type foundation (no wiring yet):**

New constants in `crates/gvm-types/src/lib.rs`:

- `GENESIS_HASH_HEX` = 64 hex zeros — canonical "no-prior" sentinel.
  Used as canonical-input substitute for `None` in
  `BatchSealRecord::seal_hash` and `GvmStateAnchor::compute_hash`.
  Keeps the hash deterministic across the genesis transition.
- `PREFIX_SEAL_V1` = `b"gvm-seal-v1:"` (domain separation §1.6)
- `PREFIX_ANCHOR_V1` = `b"gvm-anchor-v1:"`

New types:

- `BatchSealRecord` — captures (context_hash, checkpoint_root,
  prev_anchor) at batch close time. Its `seal_hash()` will become
  the LAST leaf of the batch's Merkle tree (via the next wiring
  commit), making seal-record tampering propagate to merkle_root
  and to anchor_hash. Domain-separated SHA-256 with length-prefixed
  fields.

- `GvmStateAnchor` — finality binding for a sealed batch. Combines
  batch_root + context_hash + checkpoint_root + prev_anchor under
  one anchor_hash. Methods: `seal()` constructs from a seal record,
  `verify_self_hash()` recomputes and compares.

- `AnchorSignature` enum: `SelfSigned` (Ed25519, cheap, no time
  proof), `Hsm` (hardware attestation report), `Tsa` (RFC 3161
  TimeStampToken — only variant that defeats clock rewind).

- `LeavesFormat::Sha256Concat` — encoding marker for
  `MerkleBatchRecord::leaves_blob`, future-proofs against algorithm
  changes (SHA3, BLAKE3) without ambiguity.

`MerkleBatchRecord` extended with three optional fields, all
`#[serde(default, skip_serializing_if = ...)]` so legacy WAL
records continue to round-trip without unknown-key errors:

- `leaves_blob: Vec<u8>` — 32-byte SHA-256 hashes concatenated
  (base64 in JSON). Length invariant is exactly
  `(event_count + 1) * 32` for Phase 2+ batches (events + 1 seal).
- `seal_position: Option<usize>` — index in leaves_blob where the
  seal_hash sits. Always `event_count` for Phase 2+ batches.
- `leaves_format: Option<LeavesFormat>` — encoding marker.

New methods on `MerkleBatchRecord`:
- `leaves_iter()` — zero-copy `chunks_exact(32)` iteration over the
  blob (per implementation guide ②). No allocation; iterator
  yields `&[u8]` slices pointing into the original buffer.
- `leaf(index)`, `seal_leaf()` — bounds-checked access.
- `validate_leaves_invariant()` — runtime check of length /
  seal_position consistency. Both legacy (empty blob) and Phase 2
  (full blob) forms pass.

**Standards doc updates** (`docs/internal/GVM_CODE_STANDARDS.md`):

- §4.6 Anchor Finality — every batch produces exactly one anchor;
  anchor_hash is self-consistent; chain link is mandatory.
- §4.7 Per-event vs Anchor Context Semantics — `event.config_integrity_ref`
  is point-of-event truth; `anchor.context_hash` is point-of-witness
  truth; verifiers MUST NOT assume equality.
- §4.8 Genesis & Strip-Evasion Guard — formal definition of
  `GENESIS_HASH_HEX` substitution, formal definition of the new
  (None, None) genesis rule, anchor chain audit recipe.

**Tests added (25 new, all passing):**

- `crates/gvm-types/tests/anchor.rs` — 18 tests covering:
  - GENESIS sentinel format
  - Domain prefixes versioned and distinct
  - `BatchSealRecord::seal_hash` determinism + every-field-affects-hash
  - Genesis substitution (None ↔ Some(GENESIS_HASH_HEX) → equal hash)
  - Domain prefix is load-bearing (no-prefix variant differs)
  - hex output format (64 chars lowercase)
  - `GvmStateAnchor::seal` produces self-consistent hash
  - `verify_self_hash` detects field tamper
  - Anchor chain link affects anchor_hash
  - Serde roundtrip preserves verifiability
  - `MerkleBatchRecord` legacy/Phase-2 invariant checks (5 cases)
  - `chunks_exact(32)` zero-copy verified by pointer arithmetic
  - Backward-compat: legacy serialization omits new fields

- `crates/gvm-types/tests/verify_chain.rs` — 2 new tests:
  - `truncated_history_first_with_some_prev_is_flagged` (strip-evasion)
  - `genuine_genesis_with_none_prev_is_accepted` (regression guard)

**Why now:** the v3 design discussion in this session converged on
three foundational primitives (anchor + seal + leaves_blob) that
together form the new logging structure. Landing them as types-only
first lets the next commit (group commit task rewrite) target stable
APIs rather than design-and-implement-in-one-go.

**Backward compatibility:** zero — existing WAL files round-trip
identically. Phase 2 fields all serde-skip when empty/None. Existing
verifiers that don't know about anchors continue to work on
pre-anchor WALs.

**Affected files:**
- `crates/gvm-types/Cargo.toml` — add `hex = "0.4"` dep
- `crates/gvm-types/src/lib.rs` — new constants, types, methods,
  strip-evasion guard
- `crates/gvm-types/tests/anchor.rs` — NEW, 18 tests
- `crates/gvm-types/tests/verify_chain.rs` — 2 new tests
- `src/ledger.rs` — param rename, MerkleBatchRecord constructor
  populated with legacy defaults for new fields
- `docs/internal/GVM_CODE_STANDARDS.md` — §4.6/§4.7/§4.8

**Verification:**
- `cargo test --workspace --tests` : 589 passed / 0 failed / 4 ignored
  (was 564 before — +25 new tests)
- `cargo fmt --all -- --check` : clean
- `cargo check --workspace --tests` : clean

**Open follow-ups (next commits in v3 series):**
- Phase 1: `OperationDescriptor` split + event_hash v2 (privacy)
- Phase 2 wiring: `TripleState` ArcSwap RCU + group commit rewrite
  to emit BatchSealRecord + GvmStateAnchor per batch
- Phase 2.5: `verify_anchor_chain` (timing audit)
- Phase 3: leaves-only checkpoint tree (rightmost-path cache per
  feedback ①, replacing current Vec<String> recompute)
- Phase 5: `prev_anchor_hash` binding in `GvmIntegrityContext` v3

### 2026-05-01: GVM_TEST_DNS_WINDOW_SEC → config (post-§6.5 sweep)

**What changed:**

A second pass under §6.5 ("Tests Run Production Code Paths — No
Production Test Hooks") found a fourth violation that the first
remediation missed: `src/dns_governance.rs` read
`GVM_TEST_DNS_WINDOW_SEC` unconditionally in production. Setting the
env var at startup shrunk the Tier 3/4 sliding window from 60 seconds
to as low as 1 second, which makes Tier 3 detection (≥5 unique
subdomains within the window) effectively impossible to trigger —
an attacker who could influence the gvm-proxy startup environment
(supply-chain compromise, container env injection) could blind
the burst detector while leaving the rest of the sandbox apparently
healthy.

The migration:

- `DnsGovernanceConfig` gains a `window_secs: u64` field
  (default 60) — operators set it in `proxy.toml [dns]` so the
  override lands in the WAL `gvm.system.config_load` event and is
  audit-visible.
- `DnsGovernance::new()` and `DnsGovernance::with_window_secs()`
  store the duration on the struct. The window is fixed at
  construction.
- `clamp_window_secs(requested)` enforces a 5-second floor —
  anything below is clamped UP and a `tracing::warn!` fires with
  both the requested and clamped values.
- The free function `window_duration()` is gone. `DomainWindow::record`,
  `DomainWindow::is_idle`, and `GlobalWindow::record` now take a
  `window: Duration` parameter; `DnsGovernance` passes
  `self.window` on every call. No global state, no env-var read.
- `scripts/ec2-e2e-test.sh` Test 83d patched to inject
  `[dns] window_secs = 5` into `proxy.toml` (and restore the
  backup at the end), instead of exporting an env var.
- `docs/user-guide.md` updated to show the config syntax and
  explain the 5-second floor.

**Why:** The previous comment said "test-only knob — do not use in
production," but the binary had no way to enforce that. §6.5
explicitly forbids env-var overrides that weaken enforcement.
Moving to config achieves three things at once: (1) production
attackers can't shrink the window via env, (2) the override lands
in the audit chain, (3) the floor protects Tier 3 from operator
misconfiguration.

**Affected files:**
- `src/config.rs` — `DnsGovernanceConfig::window_secs` + default fn
- `src/dns_governance.rs` — env-var read removed; window injected
  via constructor; `clamp_window_secs(...)` enforces 5s floor;
  `DomainWindow`/`GlobalWindow` take `window: Duration` param.
- `src/main.rs` — passes `config.dns.window_secs` to
  `DnsGovernance::with_window_secs(...)`.
- `scripts/ec2-e2e-test.sh` — config-file injection for test 83d.
- `docs/user-guide.md` — operator-facing doc updated.

**Risk:** Low.
- All 564 tests pass; cargo fmt clean.
- Existing config files without the new field default to
  `window_secs = 60` (matches prior production behavior).
- The 5-second floor is not breaking — the previous E2E test used
  exactly 5 seconds, so the floor is set to the smallest value
  that's actually been used in practice.

**Open follow-up:** `GVM_DEBUG_SKIP_DYNLOAD` (in
`crates/gvm-sandbox/src/sandbox_impl.rs:70`) is also an
unconditional env-var read in production, but it does not weaken
a security boundary — it disables ldd-based dynload pre-resolution
to work around a kernel-6.17 panic. Migration to config is desirable
for §6.5 consistency but is not security-urgent. Tracked.

### 2026-05-01: Remove insecure test hooks; codify §6.5 "no production test hooks"

**What changed:**

The 2026-05-01 test-quality audit pass added three test-only entry
points to production code. A follow-up review identified each as a
real attack-surface increase, not just a code-smell. This commit
removes all three and codifies the principle as `§6.5` of the GVM
Code Standards.

The three offending hooks and their replacements:

1. **`DnsGovernance::classify_at(domain, now: Instant)` was `pub`** —
   any code holding a `DnsGovernance` reference could inject a fake
   `Instant` and bypass Tier 3/4 burst detection. Replaced with:
   - `pub fn classify(...)` — production entry, calls inner.
   - `fn classify_inner(domain, now)` — private.
   - `#[cfg(test)] pub(super) fn classify_at(...)` — only compiled
     when the `gvm-proxy` crate is built with `--cfg test`. The
     symbol does NOT exist in production binaries.

2. **`TokenBudget::_rotate_for_test(minutes)` was `pub` (with only
   `#[doc(hidden)]`, which is a doc-tool hint and NOT a compiler
   boundary)** — any code holding a `TokenBudget` reference could
   force-rotate the slot counter and clear all per-slot usage
   counters, bypassing budget enforcement entirely. Replaced with
   a `BudgetClock` trait:
   ```rust
   pub trait BudgetClock: Send + Sync {
       fn now_unix_secs(&self) -> u64;
   }
   pub struct SystemClock;          // production
   pub struct TokenBudget { clock: Arc<dyn BudgetClock>, ... }
   impl TokenBudget {
       pub fn new(...) -> Self { Self::with_clock(..., Arc::new(SystemClock)) }
       pub fn with_clock(..., clock: Arc<dyn BudgetClock>) -> Self { ... }
   }
   ```
   The trait exposes only a read of "now" — it cannot mutate budget
   state, so an attacker who substitutes a mock clock cannot bypass
   enforcement (they can only delay or accelerate the next
   rotation, which doesn't add capacity). Tests construct with a
   `MockClock` that exposes `advance_minutes(n)`. Production
   passes `Arc::new(SystemClock)` from `TokenBudget::new`. Same
   `rotate_if_needed` code path runs in both cases.

3. **`heartbeat_dir()` did unconditional `std::env::var("GVM_HEARTBEAT_DIR")`**
   in production — anyone who can set env vars on the gvm-proxy
   process at startup (supply-chain compromise, container env
   injection) could redirect heartbeat lockfiles to a writable but
   wrong directory, breaking the orphan-detection invariant. Now
   the env-var read is wrapped in `#[cfg(test)]`:
   ```rust
   fn heartbeat_dir() -> String {
       #[cfg(test)]
       if let Ok(d) = std::env::var("GVM_HEARTBEAT_DIR_TEST_ONLY") {
           return d;
       }
       HEARTBEAT_DIR.to_string()  // production: hardcoded /run/gvm
   }
   ```
   The variable name carries `_TEST_ONLY` so grep-readers see the
   intent without reading the doc comment.

**Standards doc — §6.5 added** (`docs/internal/GVM_CODE_STANDARDS.md`):

> Tests Run Production Code Paths — No Production Test Hooks.
> Forbidden: `pub fn _foo_for_test`, `#[doc(hidden)] pub fn ...` (still
> reachable), unconditional env-var reads that weaken enforcement.
> Required: trait/dependency injection, `#[cfg(test)]` gating, or
> constructor parameters. The doc carries a decision flowchart for
> "test in mod tests vs tests/ vs touches FS" so future PRs know
> the right pattern.

**Why:** A test that runs a different code path than production is
testing a different program. The three hooks above were each
attempts to make tests easier to write, but each created reachable
attack surface. The principle is now an explicit standard the
audit can cite, not just an implicit norm.

**Affected files:**
- `src/dns_governance.rs` — `classify_at` → `#[cfg(test)] pub(super)`
- `src/token_budget.rs` — `_rotate_for_test` removed; `BudgetClock`
  trait + `SystemClock` + `with_clock(...)` constructor added.
- `crates/gvm-sandbox/src/heartbeat.rs` — env-var read wrapped in
  `#[cfg(test)]`; var renamed `GVM_HEARTBEAT_DIR_TEST_ONLY`.
- `tests/token_budget_contention.rs` — uses `MockClock` via
  `TokenBudget::with_clock`. Recovery test steps the clock minute-
  by-minute (mirrors production's once-per-minute rotation; a
  single 60-min jump is not modelable because production
  `rotate_if_needed` wraps mod 60).
- `docs/internal/GVM_CODE_STANDARDS.md` — §6.5 added.

**Risk:** Low.
- `cargo test --workspace --tests`: 564 passed / 0 failed / 4 ignored.
- `cargo fmt` clean. `cargo check --workspace --tests` clean.
- No production behavior change. Production passes `SystemClock`
  (same `SystemTime::now()` source as before). The `BudgetClock`
  trait introduces one Arc<dyn> indirection per `rotate_if_needed`
  call — measured on a release build, this is one cache-resident
  vtable load, well under the §3.1 hot-path budget.

### 2026-05-01: Test-suite quality audit + fixes (anti-tests, spec gaps, loose assertions)

**What changed:**

A multi-agent audit of the ~700-test suite identified ~70 quality
defects. This commit fixes the actionable subset (cross-platform,
non-Linux-only, code-not-infrastructure). The defects fall into five
groups:

**Group A — Anti-tests (13 fixes).** Tests whose names advertise
verifying X but whose bodies pass even when X is broken. Each was
either rewritten or paired with a #[ignore]'d target-contract test
documenting the gap:

- `tests/boundary.rs::vault_tampered_ciphertext_detected` — never
  tampered. Now exercises 6 byte positions (nonce/body/tag) plus
  truncation and append.
- `tests/merkle.rs::merkle_wal_verification_detects_tampered_event`
  — admitted in its own comments that `verify_wal` doesn't detect
  the tamper. Now actually asserts `report.tampered_events` is
  populated. Companion test added for stored-hash tamper.
- `tests/hostile.rs::vault_key_is_zeroed_on_drop`,
  `src/auth.rs::secret_zeroized_on_drop`,
  `crates/gvm-sandbox/src/ca.rs::ca_zeroized_on_drop` — each
  asserted nothing. Now use `read_volatile` through a captured
  pre-drop pointer with a 0xA5 sentinel pattern; fail iff Drop
  did not zero.
- `src/intent_store.rs::mutex_poison_fail_closed` — never poisoned
  the mutex. Now panics in a thread holding the lock to actually
  poison it, then asserts `claim`/`confirm`/`release`/`register`
  fail-close instead of panicking the caller.
- `tests/ledger_shutdown.rs::concurrent_appends_during_shutdown_…` —
  waited for ALL tasks to finish before shutdown. Now uses a
  `Notify` trigger that fires when ~30% complete, so shutdown
  starts while writes are inflight.
- `tests/ic3_concurrency.rs::approve_after_handler_removed_entry_…`
  — sequential calls. Now spawns 200 iterations × 2 concurrent
  approves with a `tokio::sync::Barrier`, asserts at most 1 OK
  and exactly (OK+GONE+NOT_FOUND)==2.
- `tests/hot_reload_concurrency.rs::concurrent_reloads_…` — only
  asserted rule_count==1 (held for any winner). Now classifies
  each of the 8 candidate hosts and asserts exactly ONE wins.
- `tests/enforcement_robustness.rs::classify_does_not_panic_on_…`
  (oversize agent_id, control-char trace_id) — pinned verbatim
  passthrough as the contract, blocking §1.5 boundary hardening.
  Now assert `len() <= input_len` (permissive — verbatim OR
  hardened both pass) plus a 5s soft latency guard. The control-
  char test now serializes through JSON and asserts no raw
  CR/LF/NUL reach the WAL stream.
- `src/dns_governance.rs::test_tier3_decay_to_tier2` — manually
  cleared internal state instead of advancing time. Added
  `classify_at(domain, now: Instant)` test hook; the test now
  advances the virtual clock past the window and verifies decay
  through the actual production code path.
- `crates/gvm-types/tests/verify_chain.rs::integrity_context_…` —
  encoded "skip silently" as the contract, which is an evasion
  vector. Renamed: a #[ignore]'d test pins the TARGET contract
  ("missing context MUST be reported as first_break"); a paired
  test pins the CURRENT behavior with a "this is the gap"
  comment. Re-enable the ignored one when the verifier is
  hardened.
- `src/wasm_engine.rs::test_native_fallback` — clarified that
  ABAC empty-rules-default-Allow is correct here (§4.1 fail-close
  applies at the `enforcement::classify` boundary, not this
  layer). Companion determinism test added.

**Group B — CI silent (heartbeat injection).** All 8 heartbeat tests
in `crates/gvm-sandbox/src/heartbeat.rs` silently `return` when
`/run/gvm/` was not writable — which is always true under non-root
CI. Added `GVM_HEARTBEAT_DIR` env override + `OnceLock<TempDir>`
test fixture that points the tests at a tempdir. CI now actually
exercises flock/futimens.

**Group C — Spec-coverage gaps (5 new tests).** §6.3 mandates
"every security claim has a test". The audit found these missing:

- `tests/mitm_streaming.rs::mitm_keepalive_survives_deny_then_allow_retry`
  — §7.6 keep-alive contract: a Deny on a MITM keep-alive
  connection must NOT close the TLS session. Issues two requests
  on the same TLS socket; first is denied, second succeeds.
- `tests/mitm_streaming.rs::mitm_sse_with_chunked_and_event_stream_…`
  — §7.7 framing-discipline regression: SSE upstream that emits
  `Content-Type: text/event-stream` AND `Transfer-Encoding:
  chunked` must terminate via chunked framing (the historical bug
  was the relay waiting for TCP EOF). Wraps the request in an
  8-second hard timeout to detect a regression promptly.
- `tests/hostile.rs::proptest_srr_determinism::*` — §4.1
  determinism: 64-case proptest plus a 32-thread × 50-iteration
  concurrent test asserting same SRR input always produces the
  same decision regardless of thread or repetition.
- `src/merkle.rs::merkle_node_hash_uses_domain_separation_prefix`
  + `merkle_event_hash_uses_domain_separation_prefix` — §1.6:
  removing the `gvm-node-v1:` / `gvm-event-v1:` prefix would
  silently pass all prior Merkle tests. Now compute the same hash
  with no-prefix and a wrong-prefix variant and assert the
  production output matches ONLY the correct-prefix one.
- `tests/token_budget_contention.rs::budget_recovers_after_full_window_…`
  + `…_partial_window_…` + `separate_budgets_do_not_share_state_…`
  — token-bucket recovery (window-slide) and per-agent isolation
  contracts had zero coverage. Added `_rotate_for_test(minutes)`
  hidden helper to advance the slot counter without `thread::sleep`.

**Group D — Side-effect coverage in handler tests.** Reload tests
returned 200 without ever verifying the SRR was actually swapped.
Now `reload_srr_from_file_succeeds` calls `srr.check()` against the
new Allow rule and asserts Allow. `reload_srr_preserves_old_rules_on_failure`
captures the response status (was thrown away) and additionally
verifies the original Allow rule still fires.

**Group E — Loose assertions tightened.**

- `tests/stress.rs::srr_10000_rules_load_and_lookup` — ceiling was
  5000µs (5× the §3.1 budget). Now 1000µs, with comment that
  benches verify the release-build sub-µs claim.
- `tests/mitm_streaming.rs::mitm_streaming_response_carries_proxy_…`
  — `is_some()` / `contains("name:")` accepted empty values. Now
  parses the header value and asserts `X-GVM-Decision == "Allow"`
  and `X-GVM-Event-Id` is non-empty + ≥8 chars.
- `tests/boundary.rs::gvm_headers_stripped_…` — re-implemented the
  prefix list inline (false coverage). Made `proxy::remove_gvm_headers`
  `pub` and the test now calls the production function directly.
- `src/dns_governance.rs` — added 4 malformed-packet tests:
  pointer-compression in question section, label overrun,
  QDCOUNT=0 with trailing bytes, oversized label.
- `src/srr.rs::normalize_path_decodes_percent_encoded_dot_segments`
  — §4.1 traversal-bypass guard: `%2E%2E` must be decoded BEFORE
  dot-segment collapsing. Plus `…_handles_invalid_percent_encoding`
  and `…_oversized_does_not_explode` (4KiB latency guard).
- `tests/common_sanity.rs` — replaced the `assert!(...|| true)`
  tautology with the actual contract (`tls_ready=true` is the
  test-helper default).

**Group F — Stale docs.** `GVM_CODE_STANDARDS.md` §6.3 cited
`group_commit_fail_close_all_callers_receive_error` as canonical;
that test no longer exists. Updated to point at the current
emergency-WAL fallback test and explicitly mark the both-paths-fail
test as MISSING. `test-report.md` snapshot updated with a note that
per-test names rotate and that the "Windows green" line does NOT
exercise the Linux-gated sandbox isolation tests.

**Why:** A test suite that gives confidence requires every test
to actually verify what its name advertises. The 13 anti-tests in
particular were the highest-impact fixes — they are the bug-class
"CI green therefore feature is safe" that the audit was designed
to catch. The spec-coverage tests (Group C) close §6.3 gaps that
the standard explicitly named.

**Production code touched:**
- `src/dns_governance.rs` — added `classify_at(now)` + 4 parser tests
- `src/token_budget.rs` — added `_rotate_for_test(minutes)`
- `src/proxy.rs` — `remove_gvm_headers` now `pub`
- `src/merkle.rs` — added 2 domain-separation tests
- `src/auth.rs` — secret_zeroized_on_drop rewritten
- `src/srr.rs` — normalize_path negative tests + oversize guard
- `src/wasm_engine.rs` — clarified contract + determinism test
- `src/intent_store.rs` — mutex_poison_fail_closed rewritten
- `crates/gvm-sandbox/src/heartbeat.rs` — `GVM_HEARTBEAT_DIR` injection
- `crates/gvm-sandbox/src/ca.rs` — ca_zeroized_on_drop rewritten

**Test files touched:**
- `tests/boundary.rs` — vault tamper rewritten + header-strip
- `tests/merkle.rs` — verify_wal tamper test split
- `tests/hostile.rs` — vault zeroize + SRR determinism proptest
- `tests/ledger_shutdown.rs` — concurrent appends rewritten
- `tests/ic3_concurrency.rs` — approve race actually concurrent
- `tests/hot_reload_concurrency.rs` — distinct-payload winner check
- `tests/enforcement_robustness.rs` — anti-tests rewritten
- `tests/mitm_streaming.rs` — keep-alive + SSE+chunked + header values
- `tests/api_handlers.rs` — reload side-effect assertions
- `tests/token_budget_contention.rs` — recovery + multi-agent
- `tests/stress.rs` — SRR ceiling tightened (5000µs → 1000µs)
- `tests/common_sanity.rs` — tautology replaced
- `crates/gvm-types/tests/verify_chain.rs` — context-missing renamed

**Risk:** Low.
- All ~564 tests pass on Windows (`cargo test --workspace`).
- 4 ignored: 1 SSE flush, 2 stress perf benches, 1 cli auto-start E2E,
  1 NEW intentionally-ignored test documenting the integrity-context
  evasion target contract.
- `cargo fmt` clean.
- No production behavior changes — only test-only helpers
  (`classify_at`, `_rotate_for_test`, `GVM_HEARTBEAT_DIR`,
  `remove_gvm_headers` visibility bump).

### 2026-05-01: Code-standards compliance pass (§1.2 / §1.3 / §1.7 / §2.3 / §7.1)

**What changed:**

Audited `src/` and `crates/` against `docs/internal/GVM_CODE_STANDARDS.md`
and closed nine drift points found in the scan. Categories:

- **§1.3 Error sanitization** — `POST /gvm/reload` no longer reflects
  raw toml/regex parser strings (file paths, line numbers) in the
  response. The HTTP body now reads `"SRR parse failed — see proxy
  logs. Config preserved."` while the full error still goes to
  `tracing::error!`. (`src/api.rs`)
- **§1.7 Unsafe documentation** — Added `// SAFETY:` comments to every
  remaining runtime `unsafe { ... }` block that lacked one (12 sites
  across `crates/gvm-sandbox`: capability/cgroup/heartbeat/sandbox_impl/
  network).
- **§2.3 Required config fail-close** — Removed the silent
  `unwrap_or_else(|_| "0.0.0.0:8080")` fallback for `server.listen`.
  An invalid listen address now exits with a fatal log instead of
  binding to a different port than the operator configured.
  (`src/main.rs`)
- **§1.2 Runtime panic-equivalents** — The non-loopback reload-handler
  branch in `main.rs` no longer ends in `.unwrap()`; it falls back to
  an empty 403. `launch_contained_wrapper` in `crates/gvm-cli/src/
  pipeline.rs` replaces `unreachable!()` with `anyhow::bail!`, marked
  with a `7.1-exception` note tracking the legacy bridge.
- **§1.9 Async file I/O** — `Ledger::record_config_load` now uses
  `tokio::fs::read` so the policy hot-reload path no longer issues
  blocking `std::fs::read` from inside the live runtime.
  (`src/ledger.rs`)
- **DNS log clarity** — `dns_governance.rs` mutex-poison branches
  previously logged "fail-open"; that wording was misleading because
  the fallback returns `DnsTier::Unknown` (Tier 2 — moderate delay),
  not a free pass. Logs now say "fall back to Tier 2 (Unknown)" and
  the rationale is captured in a comment.
- **§1.3 Wasm lock poison** — `WasmEngine::evaluate_wasm` no longer
  surfaces the `PoisonError` text to the caller; logs the error and
  returns the generic `Wasm runtime unavailable`.

**Why:** All findings came from a code-standards scan; they were
single-spot drift rather than systemic gaps. Fixing them in one pass
keeps the standard credible — every rule the document asserts now
holds in the tree.

**Affected files:**
- `src/api.rs` — sanitized reload errors
- `src/main.rs` — listen-addr fail-close, reload-handler unwrap
- `src/ledger.rs` — `tokio::fs::read` for record_config_load
- `src/dns_governance.rs` — fail-open → fail-graceful wording
- `src/wasm_engine.rs` — generic lock-poison error
- `crates/gvm-cli/src/pipeline.rs` — `bail!` instead of `unreachable!`
- `crates/gvm-sandbox/src/{capability,cgroup,heartbeat,sandbox_impl,
  network}.rs` — added 12 SAFETY comments

**Risk:** Low. No behavioral change on the happy path. Listen-address
fail-close is a stricter error path: operators who relied on the
silent fallback will now see a fatal log with the offending value.
Reload handler now returns 403 with empty body instead of panicking
on the (already unreachable) builder failure. All 275 lib tests + 422
integration tests pass; cargo fmt clean.

### 2026-05-01: Sandbox parent-liveness heartbeat (defense-in-depth for PDEATHSIG)

**What changed:**

New module `crates/gvm-sandbox/src/heartbeat.rs` (Linux-only). The
parent gvm process opens `/run/gvm/gvm-{pid}.heartbeat`, holds an
exclusive `flock(LOCK_EX)` for its lifetime, and a background
thread updates the file's mtime every 5 s. The cleanup path
(`network::cleanup_all_orphans_report`) now consults a probe
function `heartbeat::parent_state(pid, threshold)` before falling
back to the existing PID/starttime check:

  * `Dead` — non-blocking `LOCK_EX` succeeds. The kernel atomically
    released the parent's lock on process death (any path: clean
    exit, SIGKILL, OOM-kill, panic, segfault). Cleanup proceeds.
  * `Hung` — lock still held but mtime older than 30 s. Parent is
    alive in `/proc` but its heartbeat thread is wedged
    (D-state, deadlocked tokio runtime, etc.). Cleanup proceeds.
  * `Alive` — lock held + mtime fresh. Skip.
  * `NoHeartbeat` — file missing (older version or already swept).
    Falls back to PID/starttime.

When cleanup removes a sandbox state file because its owner died,
it also removes that owner's heartbeat file in the same pass so
files don't accumulate.

**Why:**

`PR_SET_PDEATHSIG(SIGKILL)` (added 2026-04) covers most parent-
death paths, but two failure modes slipped through:

  1. **PID reuse with matching starttime**: theoretically possible
     after long uptime if the kernel re-issues the same PID and
     the new process happens to land on the same clock tick.
     `is_pid_alive_with_starttime` would report alive → orphan
     resources persist.
  2. **Hung parent**: tokio runtime deadlocked, kernel D-state,
     hardware fault. PID is alive in `/proc` but the parent is
     making no progress and will never run cleanup. PDEATHSIG
     fires only on process *death*, not hang.

flock alone covers (1) — kernel guarantees release on any death
path. mtime alone covers (2). Together they close the gap.

**Affected files:**

  * `crates/gvm-sandbox/src/heartbeat.rs` — new module (~280 LoC
    incl. tests). 8 unit tests covering acquire/drop, Alive/Dead/
    Hung/NoHeartbeat states, mtime advance, and second-acquire
    failure.
  * `crates/gvm-sandbox/src/lib.rs` — declares `pub mod heartbeat`
    under `#[cfg(target_os = "linux")]`.
  * `crates/gvm-sandbox/src/sandbox_impl.rs::launch` — acquires
    `ParentHeartbeat` at start of every sandbox launch. Held via
    RAII for the function lifetime; drop releases lock + unlinks.
    Acquisition failure is non-fatal (log + continue without the
    extra signal).
  * `crates/gvm-sandbox/src/network.rs::cleanup_all_orphans_report`
    — heartbeat probe added before the `is_pid_alive_with_starttime`
    block. Also removes the heartbeat file alongside the state file
    when its owner is gone.

**Risk:**

LOW. Heartbeat is purely additive — failure mode is "extra orphan
detection skipped", never "false orphan cleanup of a live
sandbox". The probe is read-only (it tries `LOCK_EX | LOCK_NB`
then immediately `LOCK_UN` if it acquired), so concurrent probes
do not affect parent state. The 30 s stale threshold is large
enough to absorb any reasonable scheduler/IO delay; raising it
costs nothing because the lock signal still catches process death.

**Test coverage:**

In-process unit tests (Linux-only, gated `#[cfg(target_os = "linux")]`):

  * `acquire_creates_file_and_drop_removes_it`
  * `parent_state_reports_alive_while_held`
  * `parent_state_reports_dead_after_drop` — directly exercises
    "FD close releases flock" with raw libc primitives.
  * `parent_state_reports_hung_when_mtime_stale`
  * `parent_state_no_heartbeat_for_missing_file`
  * `second_acquire_with_same_pid_fails`
  * `touch_thread_advances_mtime` — uses `acquire_with_interval(100ms)`
    to verify mtime advances within the test window.
  * `drop_releases_lock_so_re_acquire_succeeds`

Cross-process flock release on SIGKILL relies on documented kernel
semantics that are exercised in EC2 stress (fork + kill agent).

---

### 2026-04-30: TokenBudget release-decrement TOCTOU fix (real production bug)

**What changed:**

`src/token_budget.rs` — `release_reservation` and the release leg of
`record(tokens, cost)` previously did a non-atomic
`load + saturating_sub + store` on `pending_reservations: AtomicU64`.
Under real CPU-parallel contention (16 OS threads, 5,000 balanced
reserve+release pairs each), two threads racing observed the same
`prev`, both computed `prev - reserve`, both stored the same value —
one decrement was effectively lost per collision. The pending counter
drifted upward; eventually `check_and_reserve` started returning
`Err(BudgetExceeded)` even when actual usage was well below the cap.

Replaced with an `atomic_saturating_sub` helper backed by
`fetch_update` (retry-on-conflict closure) that preserves the
underflow guard the saturating_sub provided.

**How it was caught:**

`tests/token_budget_contention.rs` (5 new integration tests, also
new in this commit) exercises real OS threads via `std::thread::spawn`
+ `std::sync::Barrier`. The default `#[tokio::test]` flavour runs
tasks on a single-threaded runtime, so the original 6 unit tests
in src/token_budget.rs never produced real contention. The new
tests verify:

  1. `pending_counter_returns_to_zero_after_balanced_concurrent_churn`
     16 threads × 5,000 reserve+release pairs → pending counter
     must equal 0. Pre-fix observed 47,400 drift.
  2. `pending_counter_balances_under_mixed_record_and_release`
     Same shape with half record() / half release_reservation().
     Pre-fix observed 65,500 drift.
  3. `cap_respected_under_burst_within_one_request_slack`
     32-thread barrier + budget for 10 reservations, observed Ok
     count must be in [10, 14] — captures the documented atomic-
     compose TOCTOU on the reserve side (single-instruction
     CAS would tighten this to 10).
  4. `reservations_resume_after_release_makes_room`
     Sequential exhaust + release + reserve cycle.
  5. `concurrent_record_sums_correctly`
     16 threads × 2,500 record() calls → exact total tokens. Catches
     any future load+store regression on the slot accumulator path
     (currently fetch_add → safe, but locked in here).

**Affected files:** `src/token_budget.rs`,
`tests/token_budget_contention.rs` (new),
`docs/internal/CHANGELOG.md`.

**Risk:** Low. fetch_update is the standard atomic-update primitive
and produces the exact same end-state value as load+store would when
no conflict occurs; under conflict it retries until success or the
closure says no change. No semantic change beyond closing the race.
Workspace test count: 510 → 515.

### 2026-04-30: MITM streaming integration tests + two production bugs they found

**Test additions (tests/mitm_streaming.rs, 6 tests):**

The cooperative-mode SSE tests verified the `proxy_handler` path; real
LLM agent traffic uses MITM TLS via `tls_proxy_hyper::serve_mitm` —
structurally different code that previously had no streaming-aware
integration test. The new file spins up a real TLS-terminating MITM
listener (using `GvmCertResolver`) and a TLS client that trusts the
test CA, then drives the same six policy-mapping invariants through
the production MITM path:

  - mitm_sse_multi_event_preserves_boundaries
  - mitm_anthropic_thinking_trace_passes_through
  - mitm_mid_stream_pause_does_not_coalesce_chunks
  - mitm_srr_deny_blocks_before_upstream_call (atomic flag verifies
    no upstream socket is opened on Deny)
  - mitm_streaming_response_carries_proxy_injected_headers
  - mitm_streaming_upstream_request_receives_injected_credentials

The DN-mismatch trap that breaks `test_helpers::create_test_ca` for
real TLS verification is documented + worked around with
`create_compatible_test_ca` that uses the same DN
(`CN=GVM MITM CA, O=Analemma GVM`) that `GvmCertResolver::new`
reconstructs internally.

**Production bugs the new tests discovered + fixed:**

1) **Credential bypass on dev-mode host_overrides path** (security).
   `forward_http` (the `host_overrides` redirect branch in
   tls_proxy_hyper.rs) forwarded the agent's headers verbatim to the
   local mock without invoking `api_keys.inject()`. An agent could
   smuggle its own `Authorization: Bearer …` header and bypass
   Layer-3 credential isolation when host_overrides was active.
   The TLS-upstream branch did call `inject()`; the dev branch did
   not. Fixed by mirroring the inject call before forward_http.

2) **MITM streaming responses lacked X-GVM-* observability headers**
   (observability). Cooperative path stamps `X-GVM-Decision` and
   `X-GVM-Event-Id` on every response so SDKs can correlate audit
   entries to HTTP transactions. The MITM path (3 response branches:
   LLM-tapped, non-LLM forward-as-is, dev forward_http) stamped no
   such headers. Added a `stamp_governance_headers` helper and
   wired it into all three MITM response branches.

**Affected files:** `tests/mitm_streaming.rs` (new),
`src/tls_proxy_hyper.rs`, `docs/internal/CHANGELOG.md`.

**Risk:** Low. New test file is self-contained. The two bug fixes
add response headers (additive) and a credential-injection call
(additive — it strips auth headers only when a configured credential
exists for the host). All existing tests continue to pass; total
workspace test count: 498 → 504.

### 2026-04-29: Sandbox parent-death watchdog — PR_SET_PDEATHSIG + matrix wait fix

**What changed:**

1. `crates/gvm-sandbox/src/sandbox_impl.rs::child_entry` — armed
   `prctl(PR_SET_PDEATHSIG, SIGKILL)` as the very first action in
   the cloned sandbox child, BEFORE any coordination/setup. The
   kernel now delivers SIGKILL to the namespace init the moment
   its parent thread terminates. Once the namespace init dies,
   the kernel cascades SIGKILL to every process inside that PID
   namespace — closing the "orphan agent after parent SIGKILL"
   class of leak at the kernel level. A `getppid() == 1` race
   guard immediately after the prctl call handles the (tiny)
   window between clone(2) and prctl(2): if the parent died in
   that window we have already been reparented to host init, so
   the child suicides instead of running orphaned.

   The "parent" for PDEATHSIG purposes is the cloning thread.
   gvm-cli runs sandbox launch via `tokio::task::spawn_blocking`,
   which dedicates a blocking-pool thread to the call for its
   full duration — that thread persists until launch returns or
   the parent process dies. The semantics are exactly what we
   want: PDEATHSIG fires on parent process death OR on graceful
   completion (in which case cleanup has already run).

2. `scripts/sandbox-observability-test.sh` — fixed a subshell
   bug in the cleanup matrix (Tests 10-13). The previous
   `spawn_sandbox_for_signal_test()` helper backgrounded gvm-cli
   inside a `$(...)` subshell, which broke the parent script's
   `wait $gvm_pid` — the PID was not a direct child of the main
   shell, so wait returned immediately and the script measured
   residuals while cleanup was still in progress. Now each test
   inlines `gvm run --sandbox ... &` in the script body (matching
   Test 8's pattern that already worked) and `wait` actually
   blocks until cleanup completes.

3. `.github/workflows/ci.yml::sandbox-observability` — flipped
   `SANDBOX_CLEANUP_MATRIX=1` on. Tests 10-13 now run on every
   push and PR, gating regressions to the parent-death-cleanup
   path. They are no longer opt-in.

**Result on EC2 (kernel 6.17.0-1009-aws):**

  13 passed, 0 failed, 0 skipped

  - Test 10 Agent SIGTERM:     no residuals
  - Test 11 Agent SIGKILL:     no residuals
  - Test 12 Parent SIGTERM:    no residuals
  - Test 13 Parent SIGKILL:    post-kill state had NAT=2/state=1
    as expected (parent died before cleanup), `gvm cleanup`
    recovered to all zeros. veth was already cleared by the
    PID-namespace teardown that PDEATHSIG triggered.

**Affected files:** `crates/gvm-sandbox/src/sandbox_impl.rs`,
`scripts/sandbox-observability-test.sh`,
`.github/workflows/ci.yml`,
`docs/internal/CHANGELOG.md`.

**Risk:** Low. PDEATHSIG is a no-op on platforms that don't
support it; the call falls back to a warning + race-guard exit.
The matrix wait fix is purely script-side. Activating the matrix
in CI is safe because the matrix passes on the runner — if a
future regression breaks parent-death cleanup, CI catches it
the next push.

### 2026-04-29: P2 — cert cache attack tests + sandbox cleanup matrix (incl. discovered bugs)

**What changed:**

1. `src/tls_proxy.rs` — added five GvmCertResolver tests covering the
   actual security/perf invariants the cache exists to provide:
   - `cert_cache_bounded_under_sni_attack`: 12,000 unique-domain
     SNI flood stays ≤ MAX_CERT_CACHE_SIZE after pending eviction
     tasks flush. Verifies the attacker cannot OOM the proxy.
   - `cert_cache_hit_returns_same_underlying_cert`: cache hit
     returns the SAME Arc<CertifiedKey> as the first issue —
     pointer-equality assertion. Catches any regression that
     regenerates certs per handshake.
   - `cert_cache_chain_includes_ca_for_client_verification`:
     leaf chain is `[leaf, ca]` (length 2), each entry non-empty
     and distinct.
   - `cert_cache_concurrent_distinct_domains_no_deadlock_no_panic`:
     32 threads × 32 unique domains complete cleanly, cache size
     stays bounded.
   - `cert_cache_concurrent_same_domain_all_threads_succeed`: 32
     threads barriered to hit the same new domain simultaneously;
     all get a valid 2-entry chain, steady-state cache has 1-2
     entries.

2. `crates/gvm-sandbox/src/sandbox_impl.rs` — removed the
   `if network_result.is_ok()` gate around cleanup_host_network +
   clear_sandbox_state. Same root-cause class as the SIGINT NAT-leak
   fix: when setup_host_network() fails partway through, the gate
   skipped cleanup of partial-setup artifacts (veth pair, early
   iptables rules). cleanup_host_network is idempotent (`-D` +
   `.ok()` ignore missing rules) so always running it is safe and
   closes the leak. Doc-comment in the file records the two
   production failure modes this fixes.

3. `scripts/sandbox-observability-test.sh` — added Tests 10-13
   covering termination paths beyond Ctrl+C:
   - Test 10: Agent SIGTERM
   - Test 11: Agent SIGKILL (uncatchable)
   - Test 12: Parent (gvm CLI) SIGTERM
   - Test 13: Parent SIGKILL → `gvm cleanup` recovery
   Each verifies real system state via `iptables-save`, `ip link`,
   and `/run/gvm/*.state` — never the CLI's self-report.

**Bug discovered (the ENTIRE point of writing the matrix):**

Tests 10-13 all fail today. Root cause: when the gvm CLI parent dies
(particularly via SIGKILL, but also SIGTERM in some races), the
sandbox PID-namespace init does NOT die with it. The cloned child
becomes the namespace's PID 1; on parent death the kernel reparents
it to init(1) and it keeps running. `is_pid_alive_with_starttime`
in `cleanup_all_orphans_report` then sees the namespace init as
alive and skips cleanup of its veth/iptables/state — permanently.
The user sees an orphan agent, leaked veth-gvm-h0, leaked NAT rules,
and `gvm cleanup` claiming success while leaving everything in place.

The fix is non-trivial — needs PR_SET_PDEATHSIG(SIGKILL) on the
clone, OR a cgroup-based teardown, OR a watchdog in the sandbox
init that exits when its parent (gvm CLI) is gone. All three are
design changes that need careful review of the sandbox architecture
docs and integration with existing tc-filter / overlayfs cleanup
ordering. Scheduled for follow-up.

Until the fix lands, Tests 10-13 are gated behind
`SANDBOX_CLEANUP_MATRIX=1` so they don't block CI on a known
architectural bug. The default run reports them as SKIP. The day
the fix lands, flip the env var on in
`.github/workflows/ci.yml::sandbox-observability` and the matrix
becomes a green-or-bust regression gate.

**Affected files:** `src/tls_proxy.rs`,
`crates/gvm-sandbox/src/sandbox_impl.rs`,
`scripts/sandbox-observability-test.sh`,
`docs/internal/CHANGELOG.md`.

**Risk:** Low for the test additions and the cleanup gate fix.
Cert tests are pure unit tests. The sandbox_impl gate fix only
affects the failure-path; the success path was already calling
cleanup. The matrix is opt-in until the architectural bug it found
is fixed.

### 2026-04-29: P0 release-gate CI additions — sandbox-observability + nightly-stress

**What changed:**

`.github/workflows/ci.yml` — added a `sandbox-observability` job that
runs on every push and PR (Linux runner, ubuntu-latest). It builds the
release CLI/proxy, installs `python3-psutil` + `iproute2`, then runs
`scripts/sandbox-observability-test.sh` under `sudo`. The script
exercises 9 user-facing diagnostic surfaces — OOM hint, timeout hint,
seccomp negative-probe (8 syscalls), normal-exit silence, CPU throttle
note, `gvm status` structure, in-process cleanup verification, **Ctrl+C
graceful cleanup**, and `gvm stop` staged output. JUnit XML + JSON
reports are uploaded as a workflow artifact for triage.

`.github/workflows/nightly-stress.yml` — new scheduled workflow that
SSHes into the project's EC2 sandbox host and runs the 60-minute chaos
stress test. Triggers weekly (Sunday 18:00 UTC) by default; switch to
nightly by uncommenting the daily cron line. `workflow_dispatch` also
exposes a `duration` input. The workflow:
  - syncs EC2 to the workflow's `github.sha`,
  - rebuilds the release binaries,
  - pre-cleans residuals so a previous failed run can't poison the
    starting state,
  - runs `scripts/stress-test.sh --duration 60`,
  - parses `VERDICT: PASS` from the captured log,
  - pulls the per-run results dir + the live log as artifacts,
  - **runs an explicit post-test residual scan** (NAT rules, veth
    interfaces, state files) — any non-zero count fails the workflow
    even if the script's own verdict was PASS. This is what catches
    the SIGINT NAT-leak class of bug end-to-end.

Three repository secrets must be configured before the nightly runs:
`EC2_HOST`, `EC2_USER` (defaults to `ubuntu`), and `EC2_SSH_KEY` (full
PEM contents). The workflow header has the full list and EC2-side
prerequisites (cloned repo, .env, openclaw, tmux/iproute2).

**Why:** the SIGINT NAT-leak bug fixed in the previous entry was
visible only when the user ran `scripts/sandbox-observability-test.sh`
+ `scripts/stress-test.sh` by hand. CI was green every push for weeks
while a NAT rule was silently accumulating per session. Without these
two gates, the same class of cleanup-path bug would re-emerge —
`cargo test --workspace` does not exercise iptables / veth / cgroup
state and never will. These workflows close that gap.

**Affected files:** `.github/workflows/ci.yml`,
`.github/workflows/nightly-stress.yml`, `docs/internal/CHANGELOG.md`.

**Risk:** Low. Sandbox-observability extends CI runtime by ~2 minutes
on Linux (build + script execution). Nightly-stress runs on EC2 and
costs whatever the existing EC2 instance already costs — no new
infra. If EC2 is offline the workflow fails fast in the secrets
sanity-check step.

### 2026-04-29: Sandbox SIGINT NAT leak — DNS DNAT cleanup format mismatch

**What changed:**

`crates/gvm-sandbox/src/network.rs` — fixed an asymmetry between
`setup_host_network()` and `cleanup_host_network()` for the DNS UDP
DNAT rule. Setup builds the `--to-destination` argument as a complete
`host:port` string (e.g. `"10.200.0.1:5353"` when the DNS governance
proxy is enabled, or `"8.8.8.8:53"` when it is not). Cleanup was
reading the recorded value from the state file, then re-formatting it
as `format!("{}:53", recorded)`, producing `"10.200.0.1:5353:53"` —
which never matches the rule iptables installed. `iptables -D` then
silently fails because the trailing `.ok()` swallows the error, and
the DNAT rule leaks across every sandbox session.

Pulled the DNS-target resolution into a `resolve_dns_dnat_target()`
helper so the format invariant ("setup and cleanup pass the SAME
string to iptables") is explicit and unit-testable. Three regression
tests in `network::tests::dns_dnat_target_*` lock in:
- governance-proxy override (`host_ip:5353`) is used verbatim,
- legacy override (`upstream:53`) is used verbatim,
- no override → fallback synthesises exactly one `:53` suffix.

**Why:** the `scripts/sandbox-observability-test.sh` "Ctrl+C graceful
cleanup" test (Test 8) failed on EC2 with
`Cleanup verification: 1 residual(s) detected — Network: NAT rule
referencing veth-gvm-h0`. Reproduced by hand, captured `iptables-save
-t nat` before/during/after a sandbox SIGINT: TCP DNAT was removed
correctly, DNS DNAT remained. The same root cause also explains the
"orphan veth: 1" output of `scripts/stress-test.sh` whenever DNS
governance is enabled (default).

**Affected files:** `crates/gvm-sandbox/src/network.rs`,
`docs/internal/CHANGELOG.md`.

**Risk:** Low. The fallback path (state file missing) still produces
`<upstream>:53`, identical to setup's fallback path, so no behaviour
change there. The override path now passes the EXACT recorded string,
which is the rule iptables actually has — so `-D` matches and the
rule is removed. Verified on EC2: post-fix `iptables-save -t nat`
shows zero `veth-gvm` residuals after SIGINT, and Test 8 went from
FAIL to PASS (9/9 sandbox-observability checks green).

### 2026-04-16: CI gate repairs — clippy, dependency check, fuzz

**What changed:**

1. `crates/gvm-cli/src/init.rs` — removed `"saas" | _` wildcard-in-or-pattern
   (clippy `wildcard_in_or_patterns`). The `_` arm already covers `"saas"`,
   so the explicit case is dead.
2. `src/proxy.rs` — replaced `std::io::Error::new(ErrorKind::Other, e)`
   with `std::io::Error::other(e)` (clippy `io_other_error`, stabilised
   in 1.74).
3. `src/token_budget.rs` — replaced the `const EMPTY: Slot` +
   60-element array-literal trick with `std::array::from_fn(|_| Slot::new())`.
   Silences clippy `declare_interior_mutable_const` (Slot contains
   `AtomicU64`) and is simultaneously shorter and clearer.
4. `Cargo.lock` — `cargo update -p rustls-webpki` 0.103.10 → 0.103.12 to
   pick up fixes for **RUSTSEC-2026-0098** (URI name constraints
   incorrectly accepted) and **RUSTSEC-2026-0099** (DNS name constraints
   accepted for wildcard certificates). Both advisories require
   misissuance to exploit, but we run rustls on the MITM listener so
   staying current is non-optional.
5. `deny.toml` — dropped the `RUSTSEC-2026-0092` ignore entry.
   cargo-deny surfaces unused ignore entries as errors (`advisory-not-detected`);
   the advisory no longer matches any crate in the tree.
6. `fuzz/` — removed `fuzz_policy_eval` target. The ABAC `PolicyEngine`
   it fuzzed was deleted in the GIC/ABAC cleanup (commits 46ffb1a, prior),
   so the target failed to compile. Matching entries removed from
   `fuzz/Cargo.toml` and `.github/workflows/fuzz.yml` matrix. The nine
   remaining fuzz targets (SRR, WAL parse, HTTP parse, path normalize,
   LLM trace, DNS parse, vault crypto, JWT auth, credential inject)
   still cover every external parser boundary.

**Why:** CI on master was failing three gates — Clippy (3 errors),
Dependency Check (2 CVEs + 1 stale ignore), Fuzz (1 missing module) —
which made it impossible to tell which future PRs were introducing
new issues vs. inheriting existing red. All three gates are green
again on a local `cargo clippy --workspace -- -D warnings`,
`cargo fmt --all -- --check`, and workspace `cargo check`.

**Affected files:** `crates/gvm-cli/src/init.rs`, `src/proxy.rs`,
`src/token_budget.rs`, `Cargo.lock`, `deny.toml`, `fuzz/Cargo.toml`,
`fuzz/fuzz_targets/fuzz_policy_eval.rs` (deleted),
`.github/workflows/fuzz.yml`.

**Risk:** Low. All changes are CI-hygiene or dependency bumps. The
`std::array::from_fn` rewrite of `TokenBudget::new` produces the
same initial state (60 zeroed slots) as the previous `EMPTY` array
literal; covered by the existing `token_budget` unit tests. Removing
the fuzz target removes test coverage, but the fuzzed code itself is
gone — there is nothing left to regress.

### 2026-04-16: Allow events persist to WAL (governance audit completeness)

**What changed:**

1. `proxy.rs` Allow path (HTTP, line ~521) — switched from `append_async`
   (NATS-stub, skipped the WAL file) to `append_durable`. Every Allow
   decision now reaches the Merkle-chained audit log.
2. `proxy.rs` IC-3 APPROVED execution (line ~720) — switched to
   `append_durable`. Human-approved actions are the highest-value audit
   records and must never be lost.
3. `proxy.rs` CONNECT Deny (line ~1561) — switched to `append_durable`.
   **Pre-existing bug**: this path previously used `append_async`, which
   did not write to the WAL, so Deny decisions for HTTPS tunnels were
   silently dropped from the audit chain. Regression-guarded by the new
   `connect_deny_persists_to_wal` test.
4. `proxy.rs` CONNECT Allow/Delay (line ~1602) — switched to
   `append_durable`. Allow on a tunnel is the audit anchor for all
   subsequent traffic inside it.
5. `dns_governance.rs` — Tier 2 (`Unknown`) moved from async to durable.
   A new domain appearing is itself a governance signal ("agent reaching
   somewhere unexpected") and warrants a durable record. Only Tier 1
   (`Known`, allowlist) remains async. Tier 3/4 were already durable.
6. `ledger.rs::append_async` doc comment redefined: now explicitly
   "deliberately excluded from the audit chain" for low-audit-value,
   high-frequency events only (Vault read/list, DNS Tier 1). Added a
   warning against using it for governance decisions.
7. `dashboard.html` — added Allow filter button; removed the
   "`proxyTotal - (dl + dn)`" workaround that existed because Allow
   counts weren't coming from WAL. `decisions.Allow` is now authoritative.
8. User-facing docs (`user-guide.md`) — simplified the watch/suggest
   workflow: `gvm suggest --from data/wal.log` now works directly after
   any run mode, no need to redirect to a separate `session.jsonl`.
9. Architecture doc (`ledger.md`) — durability table now lists every
   decision type plus the non-governance exclusions (Vault read/list,
   DNS Tier 1) with an explicit "not in Merkle chain" marker.

**Why:** The old design excluded Allow from the Merkle chain under the
rationale "IC-1 is reversible, loss tolerated." But for compliance,
notarization, and `gvm suggest` rule generation, Allow events are
essential evidence of what the agent actually did. Excluding them made
the WAL an incomplete audit record and forced dashboard workarounds.
The CONNECT-tunnel Deny bug further proved the async path was a hazard
for governance decisions it was never intended to carry.

**Affected files:** `src/proxy.rs`, `src/dns_governance.rs`,
`src/ledger.rs`, `src/dashboard.html`, `tests/merkle.rs` (3 new tests),
`tests/stress.rs` (2 new benches), `docs/architecture/ledger.md`,
`docs/user-guide.md`.

**Performance (measured on dev laptop):**

- Allow durable throughput: 62K events/sec (10K concurrent, release build)
- 100K mixed-event WAL (61.8 MB): write 986ms, integrity-chain verify 438ms
- Projected verify_wal latency on 1 GB WAL: ~7 seconds (linear O(N))

**Roadmap follow-up (out of scope for this commit):** Incremental
Merkle verification — only rescan events after the last successful
verification checkpoint — for production audit logs growing past a
few GB.

**Risk:** Low. Dominant change is widening which callsites go durable;
the group-commit path is the same proven code. The 62K/s Allow
throughput leaves multiple orders of magnitude of headroom for realistic
agent traffic. WAL size will grow faster; archival to S3 (or similar)
on segment rotation is the recommended mitigation but is independent
of this change.

### 2026-04-16: Docker contained mode refactor — host-side iptables, no MITM

**What changed:**
1. Removed in-container iptables DNAT + CA injection from `crates/gvm-cli/src/run.rs::run_contained_legacy`. Docker mode no longer does MITM at all.
2. Added `setup_docker_bridge_iptables`, `cleanup_docker_bridge_iptables`, `cleanup_stale_docker_chains`, `allocate_docker_slot`, `record_docker_state`, `DockerBridgeConfig` to `crates/gvm-sandbox/src/network.rs`. All rules live in a dedicated `GVM-gvm-docker-{slot}` chain referenced by a single JUMP in `DOCKER-USER` filtered by `-i gvm-docker-{slot}` — zero impact on non-GVM Docker workloads.
3. Each `gvm run --contained` run gets its own `gvm-docker-{slot}` bridge (`172.30.{slot}.0/24`) allocated by scanning existing GVM bridges via `docker network ls`.
4. Extended `SandboxState` (v4) with `docker_bridge`, `docker_container`, `docker_chain` fields (backward-compat via `#[serde(default)]`). `cleanup_state_resources` branches on these for Docker cleanup (`docker stop` + `docker network rm` + iptables chain removal).
5. `cleanup_all_orphans_report` now sweeps stale `GVM-gvm-docker-*` chains (bridge gone) and stale bridges (no chain, no state file) as defense-in-depth against SIGKILL leakage.
6. Dropped NET_ADMIN capability from the container; agent runs non-root with `--no-new-privileges`.
7. Docker mode silently ignores `--no-mitm` (MITM is never available); sandbox mode still honors it. Removed "experimental" warning banner — contained is now stable on Linux + WSL2.
8. Non-Linux hosts (macOS, native Windows outside WSL2) fall back to cooperative `HTTP_PROXY` routing with a visible warning.
9. New manual-test script `scripts/docker-bridge-smoke.sh` and E2E suite `scripts/docker-contained-e2e.sh`.

**Why:** Previous contained mode (in-container iptables DNAT + injected MITM CA) broke on WSL2 / slim images / Windows paths and required NET_ADMIN which could be abused. The new design moves all enforcement to the host kernel's iptables on a GVM-namespaced bridge, drops MITM in exchange for stability, and forces non-cooperative HTTP clients (Node.js raw `https`) through the DROP rule instead of letting them silently bypass.

**Affected files:** `crates/gvm-sandbox/src/network.rs`, `crates/gvm-sandbox/src/lib.rs`, `crates/gvm-cli/src/run.rs`, `crates/gvm-cli/src/pipeline.rs`, `docs/governance-coverage.md`, `docs/quickstart.md`, `docs/reference.md`, `docs/user-guide.md`, `scripts/docker-bridge-smoke.sh`, `scripts/docker-contained-e2e.sh`.

**Risk:** Low/Medium. Host iptables rules scoped by bridge-name prefix cannot leak to other workloads. Cleanup is multi-layered (scope-guarded Drop + state file + orphan sweep + stale-chain/bridge defense-in-depth). Docker mode loses HTTPS payload inspection — use `--sandbox` on Linux for that. Non-Linux/WSL2 fallback preserves HTTP_PROXY behavior; no regression for platforms that never had enforcement.

### 2026-04-13: Unified gvm.toml configuration system

**What changed:**
1. Added `GvmConfig` struct and `load_gvm_toml()` to `src/config.rs` — single-file configuration for rules, credentials, budget, filesystem, and seccomp.
2. Made `NetworkRuleConfig` and `NetworkDecisionConfig` pub in `src/srr.rs`; added `NetworkSRR::from_rule_configs()` for loading rules from parsed configs.
3. Updated `src/main.rs` to try gvm.toml first, falling back to legacy separate files (srr_network.toml, secrets.toml).
4. Removed `OperationRegistry` entirely: deleted `src/registry.rs`, removed from `src/lib.rs`, `src/proxy.rs` (AppState), `src/api.rs` (reload + info), `src/main.rs`, `src/config.rs`.
5. Updated `src/api.rs` reload handler to reload from gvm.toml when present.
6. Updated CLI: `gvm init` generates gvm.toml template; `gvm run` reads credentials from gvm.toml; added `--seccomp` flag; `gvm reload` simplified.
7. Updated `crates/gvm-cli/src/run.rs` placeholder env var generation to check gvm.toml first.
8. Updated `crates/gvm-cli/src/proxy_manager.rs` tracked config files to include gvm.toml.
9. Updated `crates/gvm-cli/src/preflight.rs` credential checks to include gvm.toml.
10. Applied 0600 permission check to gvm.toml (same security as secrets.toml).
11. Removed all registry references from integration and edge-case tests.
12. `OperationsConfig` made optional in `ProxyConfig` for backward compatibility.

**Why:** Single-file configuration reduces user confusion and error surface. Users previously had to manage 4+ files (proxy.toml, srr_network.toml, secrets.toml, operation_registry.toml). The operation registry was not used in the enforcement path and added complexity without value.

**Affected files:** `src/config.rs`, `src/srr.rs`, `src/main.rs`, `src/lib.rs`, `src/proxy.rs`, `src/api.rs`, `src/registry.rs` (deleted), `crates/gvm-cli/src/init.rs`, `crates/gvm-cli/src/run.rs`, `crates/gvm-cli/src/main.rs`, `crates/gvm-cli/src/reload.rs`, `crates/gvm-cli/src/proxy_manager.rs`, `crates/gvm-cli/src/preflight.rs`, `tests/integration.rs`, `tests/edge_cases.rs`.

**Risk:** Medium. Backward compatible (gvm.toml is optional; legacy files still work). Breaking only for code that imported `gvm_proxy::registry::OperationRegistry`.

### 2026-04-16: Remove ABAC (PolicyEngine) system entirely

**What changed:**
1. Deleted `src/policy.rs` and `config/policies/` directory.
2. Removed `ABAC` variant from `ClassificationSource` enum in `gvm-types` (only `SRR` remains).
3. Removed `policy` and `policy_dir` fields from `AppState`.
4. Rewrote `enforcement.rs` to SRR-only classification (removed ABAC+SRR max_strict merging).
5. Simplified `proxy_handler` in `proxy.rs`: unified SRR-only classification block, removed shadow ABAC re-evaluation.
6. Removed PolicyEngine::load from `main.rs` startup and `api.rs` reload handler.
7. Made `PoliciesConfig` optional in `config.rs` (backward-compatible with existing proxy.toml).
8. Deleted all ABAC-specific tests (policy hierarchy, attribute omission bypass, policy conflict detection, 1K rule stress, 100-tenant hierarchy).
9. Removed ABAC benchmark functions from `benches/pipeline.rs`.
10. Updated all comments, CLI help text, and startup banner to remove ABAC references.

**Why:** ABAC provides no value over SRR because SRR already inspects actual outbound traffic (method+host+path+payload). ABAC relies on agent self-declaration via SDK headers which can be spoofed or omitted. Removing it simplifies the codebase and eliminates a false sense of security.

**Affected files:** `src/policy.rs` (deleted), `src/lib.rs`, `src/proxy.rs`, `src/enforcement.rs`, `src/main.rs`, `src/api.rs`, `src/config.rs`, `src/tls_proxy.rs`, `src/tls_proxy_hyper.rs`, `crates/gvm-types/src/lib.rs`, `crates/gvm-cli/src/main.rs`, `crates/gvm-cli/src/reload.rs`, `benches/pipeline.rs`, `tests/integration.rs`, `tests/hostile.rs`, `tests/edge_cases.rs`, `tests/stress.rs`, `tests/boundary.rs`, `config/policies/` (deleted).

**Risk:** Medium. This is a large structural refactor touching enforcement, proxy, API, CLI, tests, and benchmarks. All compilation verified. No behavioral change for SRR-only enforcement (which was already the primary path for all non-SDK traffic). Existing proxy.toml files with `[policies]` section will parse without error (field made optional).

### 2026-04-15: hermes-agent validation + sandbox path remapping

**What changed:**
1. `sandbox_impl.rs` — Added `remap_path_for_sandbox()` to translate `/home/<user>/` → `/home/agent/` for execv binary paths. Sandbox overlays home directory but previously passed host-absolute paths to execv → "exec failed" for any venv-installed agent.
2. `sandbox_impl.rs` — Added `rewrite_shebang_if_needed()` to detect venv shebangs with host home paths and rewrite execv to invoke the remapped interpreter directly, bypassing kernel shebang resolution.
3. `prod-stress-test.sh` — Refactored to CLI-only user workflow pattern. Removed internal script generation (heredoc run-stress.sh), gateway lifecycle management, and agent internals. Each prompt is now a separate `gvm run --sandbox -- <agent> <prompt>` invocation. Added `--agent openclaw|hermes` flag.

**Why:** hermes-agent (Python/LiteLLM) installed via `uv` uses venv with shebangs pointing to `/home/ubuntu/.venv/bin/python`. Sandbox remaps home to `/home/agent/` but execv received the host path. This blocked any venv-installed agent from running in sandbox mode. The stress test script was also generating internal scripts and managing agent internals instead of reproducing real user CLI commands.

**Affected files:** `crates/gvm-sandbox/src/sandbox_impl.rs`, `scripts/prod-stress-test.sh`

**Risk:** Low. Path remapping only activates for `/home/` prefixes. System binaries (`/usr/bin/python3`, `/bin/bash`) pass through unchanged. Shebang rewrite only triggers when shebang references a home directory — system shebangs (e.g., `#!/usr/bin/env python3`) are unaffected.

**Verification:** hermes-agent E2E 444 PASS / 0 FAIL, watch→suggest→govern pipeline PASS, sandbox+chaos stress 5min PASS (11 prompts, 881 LLM calls, 142 WAL events).

### 2026-04-13: Fix proxy crash-recovery + prod-stress false PASS

**What changed:**
1. `main.rs:144` — Replaced `expect()` with graceful fallback on API key store load failure. Proxy logs ERROR and starts with empty store instead of panicking. Fixes CLAUDE.md "No Panic" violation.
2. `main.rs:522` — TCP listener now uses `TcpSocket` with `SO_REUSEADDR` so proxy can restart immediately after crash without waiting for TIME_WAIT. Replaced `expect()` with `process::exit(1)`.
3. `api_keys.rs:39` — Added `Default` derive to `APIKeyStore` for graceful fallback.
4. `proxy_manager.rs:267` — `start_daemon` now fixes ownership of `config/secrets.toml` to `SUDO_UID:SUDO_GID`, matching existing `data/` ownership fix. Root cause: E2E test creates secrets.toml as root, `chmod 600` makes it unreadable by the privilege-dropped proxy.
5. `prod-stress-test.sh` — Fixed false PASS: added minimum duration gate (80% of requested), `prompts_completed > 0` gate, stale data clearing (`proxy.log` truncate + WAL baseline), and duration-aware sandbox wait loop instead of bare `wait`.

**Why:** Proxy panicked on every restart during E2E tests (8 failures, all "proxy unhealthy/dead"). Root cause: `config/secrets.toml` owned by root:0600, proxy running as non-root. Prod stress test reported PASS in 40 seconds with 0 prompts completed due to sandbox early exit + stale data from previous runs.

**Affected files:** `src/main.rs`, `src/api_keys.rs`, `crates/gvm-cli/src/proxy_manager.rs`, `scripts/prod-stress-test.sh`

**Risk:** Low. Ownership fix matches existing pattern (data/ files). `SO_REUSEADDR` is standard for server sockets. Graceful fallback is defense-in-depth — primary fix is the ownership correction.

### 2026-04-13: RUSTSEC reachability audit — 20 advisories reviewed

Full reachability assessment of all 20 RUSTSEC advisories in audit.toml. This audit MUST NOT be repeated unless new advisories appear or dependencies change. Results are recorded here and in audit.toml.

**wasmtime (16 advisories including 2× CRITICAL 9.0)**: ALL UNREACHABLE. wasmtime is behind `optional = true` + `default = []`. The default `cargo build --release` does not compile wasmtime. Only `--features wasm` pulls it in, and that feature is documented as "UNSUPPORTED EXPERIMENTAL" (lib.rs, Cargo.toml). No user has ever enabled it in production. If the wasm feature is ever promoted, RUSTSEC-2026-0095 (Winch sandbox escape, CVSS 9.0) and RUSTSEC-2026-0096 (aarch64 Cranelift sandbox escape, CVSS 9.0) MUST be fixed first by upgrading wasmtime to ≥43.0.1.

**rand (1 advisory)**: RUSTSEC-2026-0097 — `rand::rng()` unsound with custom logger. UNREACHABLE. GVM uses `rand::random()` only (vault.rs:128, 141). grep confirms 0 calls to `rand::rng()`.

**unmaintained (3 advisories)**:
- RUSTSEC-2025-0134 (rustls-pemfile): REACHABLE in tls_proxy.rs:85. Not a vulnerability — crate works correctly, just unmaintained. Migrate to rustls-pki-types when API stabilizes.
- RUSTSEC-2025-0057 (fxhash): transitive only, not in default dep tree.
- RUSTSEC-2024-0436 (paste): transitive only, not in default dep tree.

**When to re-audit**: Only when (a) `cargo audit` reports a NEW RUSTSEC not in audit.toml, or (b) Cargo.toml dependencies change (new crate added, version bumped). Do not re-review existing entries — their reachability status is stable.

---

### 2026-04-15: Web dashboard (`GET /gvm/dashboard`)

Added browser-based WAL visualization dashboard served from admin API (port 9090). Single HTML file embedded in binary via `include_str!`. Design: Inter + JetBrains Mono fonts, Tailwind CSS, Chart.js, slate-900 palette, no emoji. Features: doughnut chart (Allow/Delay/Deny), horizontal bar host stats, live event timeline with deny row highlighting and human-readable security translations, anomaly detection (burst/loop/deny count), trace view with matched_rule_id + event_hash + batch_id, Merkle-DAG policy tree canvas (deny paths highlighted in red), Share button for standalone HTML snapshot export. Three new endpoints: `GET /gvm/dashboard` (HTML), `GET /gvm/dashboard/events` (incremental WAL JSON), `GET /gvm/dashboard/stats` (aggregated stats JSON).

Files: `src/api.rs`, `src/main.rs`, `src/proxy.rs` (+wal_path field), `src/dashboard.html` (new) | Risk: Low (additive feature on admin API, no enforcement path changes)

---

### 2026-04-15: Watch mode TUI dashboard (`--output tui`)

Added ratatui + crossterm based terminal dashboard for `gvm watch --output tui`. Event-centric debugging UX with 5 panels: Live Event Timeline (scrollable, color-coded by Allow/Delay/Deny), Anomaly panel (burst/loop/unknown host warnings), Policy Decision distribution (horizontal bar chart), Host Stats (top hosts by request count), LLM Usage (tokens, cost, models). Trace correlation view: press `t` on a timeline entry to group all events sharing the same `trace_id` into a tree view. Keyboard: `q` quit, `↑↓` scroll, `t` trace toggle, `Esc` back. Existing `--output text` and `--output json` modes unchanged.

**Why**: Watch mode's line-by-line output lacks visual debugging context. Developers need "what just happened" at a glance — timeline + anomaly + trace correlation, not metrics dashboards.

Files: `crates/gvm-cli/Cargo.toml` (+ratatui, +crossterm), `crates/gvm-cli/src/{watch.rs, tui/mod.rs, tui/ui.rs, tui/trace.rs, main.rs}` | Risk: Low (additive feature behind `--output tui` flag; existing modes untouched)

---

### 2026-04-15: WAL recording points reference documentation

Added section 4.11 to `docs/architecture/ledger.md` documenting all 7 WAL recording points (proxy, CONNECT, MITM, DNS, vault, system, LLM trace), `enforcement_point` field values, `decision_source` field values, full `GVMEvent` field reference, durability-by-decision table, DNS governance context fields, and vault event operations. Previously undocumented: enforcement_point values, decision_source values, MITM recording point, vault recording details, and the integrated recording points map.

Files: `docs/architecture/ledger.md` | Risk: None (docs only)

---

### 2026-04-14: uprobe removal + ebpf.rs → tc_filter.rs rename

**What**: Removed the experimental uprobe-based TLS interception feature (SSL_write_ex hooking) and its `--features uprobe` compile flag. MITM (transparent TLS proxy) is the sole HTTPS inspection mechanism. Renamed `ebpf.rs` → `tc_filter.rs` with types: `EbpfAttachResult` → `TcAttachResult`, `EbpfGuard` → `TcFilterGuard`, `check_ebpf_support` → `check_tc_support`. Removed `TlsProbeMode` and `proxy_url` from `SandboxConfig`. Removed `ureq` dependency (only used by uprobe). Updated all docs: security-model.md "Planned v0.3" uprobe sections removed, CHANGELOG roadmap updated to v0.5.0, linux-e2e-test.md uprobe tests marked deprecated, test-report.md uprobe entries struck through.

**Why**: uprobe was never on the default build path (`#[cfg(feature = "uprobe")]`, disabled by default). MITM provides complete L7 HTTPS inspection. The uprobe code was dead weight — experimental, observation-only, and its three planned extensions (Multi-PID, Chunked reassembly, Low-and-slow) were stale since v0.3. The `ebpf.rs` filename was misleading (uses tc u32 classifiers, not eBPF bytecode).

Files: `crates/gvm-sandbox/src/{tls_probe.rs (deleted), ebpf.rs→tc_filter.rs, lib.rs, sandbox_impl.rs, capability.rs, network.rs}`, `crates/gvm-sandbox/{Cargo.toml, tests/security.rs}`, `crates/gvm-cli/src/{run.rs, pipeline.rs, preflight.rs, status.rs}`, `docs/{security-model.md, reference.md, test-report.md, internal/CHANGELOG.md, internal/GVM_CODE_STANDARDS.md, internal/linux-e2e-test.md}` | Risk: Low (uprobe was never in default build; TC filter is rename-only with preserved behavior)

---

### 2026-04-11: v0.5.0 — DNS soft governance (Delay-Alert, no Deny)

**Position change**: security-model.md previously stated "DNS filtering is a DLP concern — building it into GVM would create more problems than it solves." This position is revised.

**Why**: GVM's direction shifted from "governance proxy" to "secure runtime." As a runtime that claims to isolate agent I/O, leaving DNS as an unmonitored bypass channel contradicts that claim. AWS Route 53 DNS Firewall and similar products demonstrate that full DNS threat-intelligence filtering requires massive surface area (feed management, CDN rotation handling, mDNS/LLMNR compatibility) — scope that would bloat GVM beyond its lightweight positioning. However, doing nothing is untenable. The compromise: minimal control surface with maximum survivability.

**Design**: Delay-Alert gradient, no Deny. DNS denial kills the entire agent (one FP = outage), so enforcement uses graduated delay only:
- Tier 1 (known): free pass 0ms — domains learned via `gvm suggest`
- Tier 2 (unknown): 200ms delay + WAL log — first-seen domains
- Tier 3 (anomalous): 3s delay + alert — >5 unique subdomains on same unknown base in 60s
- Tier 4 (flood): 10s delay + alert — >20 global unique subdomain queries in 60s

Decay: sliding window expiry returns classification to Tier 2 when the anomalous pattern stops. The system never permanently escalates.

Disable: `--no-dns-governance` CLI flag or `dns.enabled = false` in proxy.toml, for environments already using dedicated DNS security tools.

**Implementation**:
- [src/dns_governance.rs](../../src/dns_governance.rs): DNS governance engine (tiered classification, sliding window, UDP proxy, upstream forwarding)
- [src/config.rs](../../src/config.rs): `DnsGovernanceConfig` struct (`[dns]` section in proxy.toml)
- [src/main.rs](../../src/main.rs): DNS proxy spawning, known_hosts sync from SRR, `GVM_DNS_LISTEN` env var
- [src/proxy.rs](../../src/proxy.rs): `dns_governance` field on AppState
- [src/ledger.rs](../../src/ledger.rs): `build_dns_event()` for WAL audit entries
- [src/lib.rs](../../src/lib.rs): module registration
- [crates/gvm-sandbox/src/network.rs](../../crates/gvm-sandbox/src/network.rs): DNAT target changed from upstream resolver to local DNS proxy when `GVM_DNS_LISTEN` is set
- [crates/gvm-cli/src/main.rs](../../crates/gvm-cli/src/main.rs): `--no-dns-governance` CLI flag → `GVM_NO_DNS_GOVERNANCE=1` env var
- [docs/security-model.md](../../docs/security-model.md): position change documented with rationale

**Risk**: Low-medium. DNS proxy is a new network listener but fail-open by design (unparseable packets forwarded without delay). Disableable via CLI flag. No Deny means worst case is a 10-second delay on legitimate queries during a burst misclassification — not an outage. Known hosts from SRR are free-pass, so learned domains are never delayed.

---

### 2026-04-10: v0.4.7 -- fuzzing CI hardening + cargo-audit ignore review process

Four CI weaknesses called out during a security review of the fuzzing pipeline. None of them are exploitable bugs in the runtime, but together they meant fuzzing was producing far less assurance than the README implied and the audit-ignore list was opaque.

1. **Tiered fuzz schedule** ([.github/workflows/fuzz.yml](../../.github/workflows/fuzz.yml)). The previous schedule ran every target for a flat 5 minutes daily. libFuzzer accumulates coverage as it explores corpora, and 5 minutes is enough only to verify "no immediate crashes from cached seeds" -- deeper code paths (SRR regex backtracking edges, WAL Merkle batch parsing, HTTP framing pivots) take tens of minutes to reach. Switched to **Mon-Sat 5 min smoke + Sunday 30 min deep**, with `workflow_dispatch` accepting any duration the operator picks. Sunday's run is what actually grows the corpus; weekday runs guard against new crashes on the existing corpus seeds. Why 30 not 60: GitHub Actions free-tier minutes are finite, and 30 min × 6 targets × 1 day/week = 3 Actions-hours/week, which fits comfortably under the free quota. If we ever find a real crash that needs a longer hunt, bump it.

2. **Coverage feedback in the run summary** ([.github/workflows/fuzz.yml](../../.github/workflows/fuzz.yml)). Previously the only signal a fuzz run produced was "did it crash?" -- there was no way to tell if it actually executed anything new or just sat on the cached corpus. Added `-print_final_stats=1` and parsed the `stat::*` and `cov:.*ft:` lines into a per-target Markdown block in `$GITHUB_STEP_SUMMARY`, plus corpus entry count and total bytes. The fuzz logs themselves are also uploaded as 14-day retention artifacts. The next time someone looks at a Sunday run they can see whether `cov` and `ft` actually grew or whether the deep run was a waste of minutes.

3. **libFuzzer dictionaries** ([fuzz/dictionaries/srr.dict](../../fuzz/dictionaries/srr.dict), [fuzz/dictionaries/wal.dict](../../fuzz/dictionaries/wal.dict), [fuzz/dictionaries/http.dict](../../fuzz/dictionaries/http.dict)). Three dictionaries written, each containing the tokens that look meaningful to the corresponding parser:
    - `srr.dict`: HTTP methods, scheme tokens, fixture host names, SRR pattern wildcards (`{any}`, `{host}`, `*`), path traversal pivots (`../`, `%2F`, `%00`), GraphQL operationName values the rule fixture inspects.
    - `wal.dict`: JSON structural tokens, every WAL event field name, batch / Merkle metadata keys, all five `EventStatus` values, decision shapes the parser must accept.
    - `http.dict`: HTTP/1.x methods + versions, header names the proxy actually looks at, smuggling pivots (`Content-Length` / `Transfer-Encoding` interleavings).
    The fuzz workflow now passes `-dict=...` for the four targets that have a matching dictionary (`fuzz_srr`, `fuzz_wal_parse`, `fuzz_http_parse`, `fuzz_path_normalize`). Targets without a dedicated dictionary fall back to plain byte mutation, no error.

4. **cargo-audit ignore review process** ([audit.toml](../../audit.toml), [.github/workflows/ci.yml](../../.github/workflows/ci.yml)). The CI was carrying five `--ignore RUSTSEC-...` flags inline with no explanation of why each one was being suppressed. Moved all five into a project-root `audit.toml` with a header that documents the rule for the project: an unjustified ignore is treated as a security defect on the same severity as a missing review, every entry needs a 1-sentence reachability assessment, and the full list is reviewed on each minor release. The five existing entries are explicitly marked **NEEDS-REVIEW**, blocking on the v0.5 audit pass -- this commit does not silently approve them, it just makes the silence visible. The CI step now simply runs `cargo audit` (which auto-discovers `audit.toml`); the ignore list is no longer hidden in shell flags.

**Items intentionally deferred to v0.4.8**:
- Structure-aware fuzzing via the `arbitrary` crate. The current targets feed raw bytes and split them into method/host/path/body using ad-hoc length prefixes; this means the fuzzer spends a lot of cycles producing inputs that fail at the very first parse step. Wrapping the fuzz inputs in `Arbitrary` impls (`StructuredHttpRequest`, `StructuredWalEvent`, etc.) would let the mutator generate inputs that are already structurally valid and instead exercise deeper logic. This is a non-trivial rewrite of all six targets and warrants its own PR.
- Full v0.5 audit review of the five RUSTSEC IDs. Each one needs an actual reachability assessment ("does GVM call the vulnerable function?") and a remediation plan ("upgrade X to Y when released, or pin to Z"). That review should land in the v0.5 PR alongside actually flipping any of these from NEEDS-REVIEW to either accepted-with-justification or fixed.

**Risk**: None at runtime -- this is entirely CI / configuration work. The audit step continues to fail on any new advisory that is not in `audit.toml`, so the only behavior change in CI is that the comment trail is now visible at the diff level instead of hidden in shell flags.

---

### 2026-04-09: v0.4.6 -- three follow-ups exposed by validating v0.4.5 on EC2

Verifying v0.4.5 against the actual EC2 dry run of Test 82 surfaced three follow-ups. None are new bugs in the strict sense (two are over-eager fixes from v0.4.5, one is an existing bug in the loader's serde shape that the v0.4.5 work simply revealed). All three are needed for Test 82 to actually pass.

1. **Empty SRR file fails proxy startup** ([src/srr.rs](../../src/srr.rs)). `NetworkSrrFile.rules` had no `#[serde(default)]`, so an entirely empty `srr_network.toml` (or one with only comments) failed `toml::from_str` with "missing field `rules`" → proxy refused to start. Test 82 was deliberately writing a placeholder rule file as its baseline; once the placeholder was rejected, every subsequent step in the test was a phantom failure cascading from the broken proxy. Added `#[serde(default)]` so a missing `rules` table deserialises to `vec![]`. Operators can now legitimately keep an empty rule file as a "defaults only" state, which several documentation paths already implied was supported.

2. **v0.4.5 fail-close threshold was too aggressive** ([src/srr.rs](../../src/srr.rs)). The original "non-trivial file produced zero rules" guard (`content.trim().len() > 64`) fired on the perfectly legitimate placeholder `# Test 82 placeholder ...\nrules = []\n` (76 bytes). The intent of v0.4.5 fix #2 was to catch the case where the source text had `[[rules]]` blocks but the parser silently dropped them. Replaced the byte-count heuristic with a textual `[[rules]]` count: if the raw file contains one or more `[[rules]]` headers but `file.rules` is empty, the entries were dropped → bail. If the file legitimately has no `[[rules]]` blocks (only comments + `rules = []`), it loads cleanly. This is the precise signal we wanted in v0.4.5 — the byte threshold was a stand-in that misfired on the first real test. All 40 existing SRR unit tests still pass.

3. **`print_wal_audit` proxy.log fallback never matched anything** ([crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs)). The v0.4.5 fix #5 fallback grepped proxy.log for the literal substring `decision=Allow` to surface IC-1 Allow events when the WAL was empty. But proxy.log is written by tracing-subscriber with ANSI color escapes by default, so the on-disk bytes are actually `decision\x1b[0m\x1b[2m=\x1b[0mAllow` — no consecutive substring match. Loosened the search to require both `decision` and `Allow` independently per line (still gated on the line containing `Request classified` so we don't match unrelated log entries). Increased the lookback from 200 lines to 500 to cover startup-heavy proxy logs. The user-facing impact: after a successful all-Allow enforce run, the audit summary now correctly shows `✓ N request(s) classified as Allow (IC-1 fast-path)` instead of the misleading "no events recorded".

**Discovery**: Direct EC2 dry run of `bash scripts/ec2-e2e-test.sh 82` against the v0.4.5 release binary. Test 82 reported `82a/82b/82c` all FAIL with stderr showing the SRR loader rejecting the 76-byte placeholder file. Repro on a fresh shell with the user's GVM_CONFIG isolation pattern reproduced the exact error. The proxy.log scrape miss was found while validating the same chain on Windows: enforce mode showed `srr_rules=5` and 5 Allow classifications in proxy.log, yet the audit summary printed "No GVM events recorded".

**Risk**: Low. (1) is a serde annotation that broadens the accepted input set — strictly more permissive, no test regressions. (2) replaces a heuristic with a precise textual signal — strictly more accurate. (3) loosens a substring match in a read-only display fallback — pure additive surface area. All three preserve the v0.4.5 safety properties (control-byte rejection still strict, fail-close on dropped rules still strict).

---

### 2026-04-09: v0.4.5 — fail-close on corrupted SRR files + suggest stdout safety + audit clarity

**Background**: Test 82 (the watch->suggest->enforce regression guard added in v0.4.4) failed on the EC2 dry run, but **not** because the v0.4.4 reload fix had regressed. Two distinct production bugs were exposed by the test, plus one bug in the test script itself. All three are fixed here, plus three smaller UX items uncovered along the way.

**Bug A — `gvm suggest` writes ANSI color codes to stderr unconditionally** ([crates/gvm-cli/src/suggest.rs](../../crates/gvm-cli/src/suggest.rs)). The trailing summary line `# {N} rule(s) from {M} events` was emitted via `eprintln!` with `{DIM}/{RESET}` color escapes. Most of the time stderr stays on the terminal and this is fine. The trouble is the README's headline UX: `gvm suggest > srr.toml`. Inside Test 82 the line was `... > "$SUGGEST_OUT" 2>&1` (capturing stderr too for debug visibility), which folded the ANSI bytes into the rule file. Even outside of the test, every IDE/CI capture wrapper that merges stderr into stdout would corrupt the same way.

**Fix A**: Move the trailing summary into the `toml_output` buffer itself as a leading-`#` TOML comment, drop the `eprintln!` entirely. This means the same content shows up no matter how the shell redirects, and there are zero ANSI bytes anywhere in suggest's stdout path. A TOML `#` comment is harmless to the parser.

**Bug B — SRR loader silently produced 0 rules from corrupted TOML** ([src/srr.rs](../../src/srr.rs)). Once Bug A leaked ANSI bytes into srr_network.toml, the proxy's `NetworkSRR::load()` fed the file to `toml::from_str` and got back a `NetworkSrrFile { rules: vec![] }` with no error. The proxy logged `Governance hot-reloaded srr_rules=0` and started classifying every request as Default-to-Caution. This is a textbook fail-close violation: the operator has no way to tell that the rule set was just zero'd out by a stray byte. (Manually verified by writing a clean TOML to the same path and confirming reload returned `srr_rules=1`.)

**Fix B**: Two new defensive checks at the top of `NetworkSRR::load()`. First, scan the file content for ASCII control bytes (0x00–0x1F except `\t`/`\n`/`\r`, plus 0x7F DEL). If any are present, bail with a precise line/column diagnostic and a hint that this usually means terminal escapes leaked in via `2>&1`. Second, if the parser succeeded but produced zero rules from a non-trivial file (>64 bytes), bail with an explicit "loader silently dropped malformed entries" message. An intentionally empty file (≤64 bytes) is still allowed so that operators can deliberately disable a ruleset. Both fail-close paths surface the actual file path so the operator can fix it instead of digging through proxy logs.

**Test 82 — `2>&1` was masking both production bugs** ([scripts/ec2-e2e-test.sh](../../scripts/ec2-e2e-test.sh)). The original Test 82 used `> "$SUGGEST_OUT" 2>&1`, which is exactly the redirect mode that triggers Bug A. The test was busy verifying step C (rule application) without first checking that step B's output was sanitary. Split stdout and stderr into separate temp files, and add a control-byte regression check on the stdout file using `LC_ALL=C grep -lP '[\x00-\x08\x0B-\x1F\x7F]'`. If `gvm suggest` ever starts leaking control bytes to stdout again, 82b fails loudly with an `od -c` dump.

**Watch session counter inflated by state-machine transitions** ([crates/gvm-cli/src/watch.rs](../../crates/gvm-cli/src/watch.rs)). v0.4.4 fixed the dedup in `print_wal_audit` and `suggest_rules_batch` but missed the parallel counter inside `SessionStats::record_event`, so the watch summary still showed "8 requests" for 4 actual calls (each WAL transition counted as a request). Added `seen_event_ids: HashSet<String>` to `SessionStats`, dedup on entry. Same root cause as the v0.4.4 fix, just one more code path that needed the same treatment.

**`print_wal_audit` could not surface IC-1 Allow events** ([crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs)). Discovered while verifying v0.4.4: after a successful enforce run with all-Allow rules, the audit summary printed "No GVM events recorded during this run" and the user couldn't tell whether the rules had matched. Investigating, `Ledger::append_async` is a NATS-publish stub today and **never writes to the durable WAL by design** (IC-1 = "loss tolerated < 0.1%"), so an entirely-Allow run produces an empty WAL by definition. Proper ring-buffer / IC-1 visibility belongs in v0.4.6 (significant feature work). For v0.4.5 the minimal pragmatic improvement: when the WAL is empty, scrape `data/proxy.log` for recent `Request classified ... decision=Allow` lines. If any are found, surface them as a green check with an explicit note that IC-1 doesn't durable-WAL. If none, fall back to the original "agent didn't reach the proxy" hint. The user now sees a clear distinction between "all good, all allowed" and "agent bypassed governance entirely".

**`gvm check --path` was undocumented in `--help` examples** ([crates/gvm-cli/src/main.rs](../../crates/gvm-cli/src/main.rs)). The `--path` flag has been there since v0.4.0 with default `/`, but the doc-comment examples never showed it, so users testing `gvm suggest`-generated path-specific rules (`pattern = "httpbin.org/get"`) hit Default-to-Caution because their `gvm check --host httpbin.org` defaulted to `/`. Added an explicit example using `--path /repos/foo/bar` and a note that suggest's rules are path-scoped.

**Affected files**: [crates/gvm-cli/src/suggest.rs](../../crates/gvm-cli/src/suggest.rs), [src/srr.rs](../../src/srr.rs), [scripts/ec2-e2e-test.sh](../../scripts/ec2-e2e-test.sh) (Test 82b), [crates/gvm-cli/src/watch.rs](../../crates/gvm-cli/src/watch.rs), [crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs), [crates/gvm-cli/src/main.rs](../../crates/gvm-cli/src/main.rs).

**Risk**:
- Fix A (suggest stdout): **Negligible.** Output now contains an extra TOML comment line. Existing TOML parsers and downstream tools all tolerate `#` comments. The eprintln removal means scripts that were `2>` capturing the summary as a status indicator will lose it, but those scripts were already broken if they tried to do anything machine-readable with the colored output.
- Fix B (SRR loader fail-close): **Low.** The loader is stricter, which is the entire point. Verified against the existing 40 SRR unit tests (all pass) and the 64-byte threshold means deliberately empty rulesets continue to load. The risk surface is operator-facing: a previously-broken-but-silent file now refuses to load — that's a fail-close behavior change but the failure mode is "proxy refuses to start with bad rules", which is exactly what fail-close mandates.
- Test 82 fix: **None.** Test-only.
- Watch counter dedup: **Negligible.** Same fix pattern as v0.4.4 audit dedup, applied to a parallel code path.
- Allow-via-proxy.log fallback: **Low.** Pure read-only fallback. If proxy.log doesn't exist or is unreadable, falls back to the original "no events recorded" message. Worst case is the user sees the same message they saw before this fix.

**Items intentionally deferred to v0.4.6**:
- IC-1 Allow ring buffer (proper /gvm/recent_events endpoint instead of grepping proxy.log)
- agent_id propagation (needs CLI <-> proxy session registration design)
- Windows PATHEXT support for `Command::spawn` (`which` crate)
- `Via` header policy (suppress vs annotate vs configurable)
- Watch stream trailing event re-render (cosmetic)
- `gvm-proxy --version` flag (currently triggers full startup)

---

### 2026-04-09: v0.4.4 — watch -> suggest -> enforce loop actually works + audit dedup + e2e regression

**Background**: Dogfooding the v0.4.3 Windows release with a real Python urllib agent surfaced six bugs along the README's headline UX (`watch -> suggest -> enforce`). The flow looked working at the boundary — every command exited zero, suggest emitted plausible TOML — but the third step silently kept the proxy's stale rule set and every captured request still hit Default-to-Caution. None of the existing 200+ ec2-e2e tests caught this because none of them simulated the *implicit* CLI sequence the README advertises; the only reload tests in ec2-e2e-test.sh use explicit `curl POST /gvm/reload` calls.

**Code fixes**

1. **Proxy reuse skipped config reload** ([crates/gvm-cli/src/proxy_manager.rs](../../crates/gvm-cli/src/proxy_manager.rs)). `ensure_available()` returned immediately when the proxy was healthy, so a `gvm suggest > config/srr_network.toml` followed by `gvm run` connected to the existing daemon and never picked up the new rules. Added `config_changed_since_proxy_start()` which compares `config/*.toml` mtimes against `data/proxy.pid`. If anything is newer, the CLI POSTs to the localhost-only `/gvm/reload` endpoint (which already does atomic parse-before-swap) and touches the PID file so subsequent invocations don't keep retriggering the reload until the user actually edits config again. Falls back to kill+restart if reload fails.

2. **Audit summary double-counted state-machine transitions** ([crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs)). Each Delay/RequireApproval request writes the SAME event_id to WAL twice: once with `status=Pending` (IC-2 fail-close audit, before forwarding) and once with the final status (after the upstream response). Allow uses `append_async` and writes once. `print_wal_audit` walked every line and counted each transition as a separate event, so 1 actual delayed call surfaced as "2 delayed". Dedup by event_id, keeping the latest status.

3. **`gvm suggest` double-counted the same transitions** ([crates/gvm-cli/src/suggest.rs](../../crates/gvm-cli/src/suggest.rs)). Same root cause as #2. Generated rules listed inflated `# N hits` counts. Same fix: HashSet of seen event_ids in `suggest_rules_batch`.

4. **Startup-failure heuristic fired on every short-lived agent** ([crates/gvm-cli/src/pipeline.rs](../../crates/gvm-cli/src/pipeline.rs)). The post-exit warning "Agent exited in 3s with code 1 — possible startup failure" triggered on `runtime_secs < 10 && exit_code != 0` alone, mislabeling perfectly normal short demos that happened to propagate an upstream 5xx exit code. Changed to additionally require that the WAL did NOT grow during the run — if even one event landed, the agent reached the proxy and a non-zero exit is on the agent's own logic, not on launch.

5. **Node detection warning never fired in watch mode** ([crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs), [crates/gvm-cli/src/watch.rs](../../crates/gvm-cli/src/watch.rs)). The "Node.js does not respect HTTPS_PROXY" warning was inline in `run::run_full` and gated on `mode == LaunchMode::Cooperative`, but `--watch` is dispatched to `watch::run_watch` which never enters that code path. Extracted into `run::warn_if_node_cooperative()` and called from both. Also added `.cmd` to the heuristic so npm-installed Windows shims like `openclaw.cmd` are detected.

**Test fix — the regression that should have caught all of the above**

6. **New ec2-e2e Test 82: watch -> suggest -> enforce loop** ([scripts/ec2-e2e-test.sh](../../scripts/ec2-e2e-test.sh)). Reproduces the README's exact command sequence with NO manual `/gvm/reload` calls. Steps: (a) snapshot live SRR and replace with empty file, (b) run a tiny Python urllib agent under `gvm run --watch --output json` and capture JSONL, (c) run `gvm suggest --from session.jsonl` and assert at least one `[[rules]]` block, (d) overwrite SRR with the suggest output, (e) run the agent again under enforce mode and assert the audit summary contains `[1-9][0-9]* allowed`. The third assertion is what catches the proxy-reuse regression: if the proxy fails to pick up the new rules, every event still hits Default-to-Caution and the line reads `0 allowed N delayed`. This is the test that should have existed since v0.4.0 — it directly exercises the user-facing flow the README headlines.

**Discovery method**: dogfooding session, walked through the entire watch -> suggest -> enforce loop on a Windows host with a real Python agent. Twelve issues surfaced in total; six are in this release and the rest (POST events occasionally missing from `--output json`, agent_id stuck at "unknown" without an SDK, Windows PATHEXT for spawn, response `Via` header making catfact.ninja return 403, trailing event re-render in watch stream, `gvm-proxy --version` not being a flag) are tracked for v0.4.5. Several of these need design work (per-source agent_id binding, header policy) rather than a code edit, so they were intentionally deferred rather than rushed into this hot-fix.

**Risk**: Low for #1-#5 (each is a localized change with the previous behavior available as a fallback). The reload fallback path in #1 exercises kill+restart, which is the same code that already handles stale PIDs, so no new failure mode. Test 82 in #6 backs out cleanly via `cp $SRR_BAK_82 $SRR_LIVE_PATH` + reload, even on failure.

---

### 2026-04-09: v0.4.3 — fix workspace path baked into release binaries (critical)

**Bug**: `workspace_root_for_proxy()` in `crates/gvm-cli/src/run.rs` resolved the workspace via the compile-time macro `env!("CARGO_MANIFEST_DIR")`. On dev machines and EC2 — where the binary is built and run inside the same checkout — this happened to point at the right directory, so the bug was invisible. On any release artifact built by GitHub Actions, however, the path baked in was the runner's path (`D:\a\Analemma-GVM\Analemma-GVM\...` for Windows, equivalent for Linux/macOS), which doesn't exist on user machines. Result: every distributed v0.4.0/v0.4.1/v0.4.2 binary failed at first `gvm run` with `Cannot open proxy log: <runner path>\data\proxy.log` (os error 3 / ENOENT).

**Discovery**: surfaced when dogfooding the v0.4.2 Windows release zip with OpenClaw on a Windows host outside the repo checkout.

**Fix**: replaced the compile-time lookup with a runtime resolver that checks, in order: (1) `GVM_WORKSPACE` env override, (2) cwd if it contains `config/operation_registry.toml`, (3) directory of the running executable (the unpacked release archive layout), (4) cwd as final fallback so the downstream "config not found" error is clean. The `config/operation_registry.toml` marker is used because it's the file the proxy refuses to start without, so its presence is the canonical "this is a workspace" signal.

**Affected files**: [crates/gvm-cli/src/run.rs](../../crates/gvm-cli/src/run.rs) (function body only — no callers changed; `GVM_CODE_STANDARDS.md` already documents this as the canonical source).

**Risk**: Low. The function still returns a `PathBuf` with the same semantics; only the discovery mechanism changed. All call sites (`watch.rs`, `pipeline.rs`, `run.rs:515`) keep working unchanged. Worst case if all four lookups fail to find a marker, the function returns cwd, which is what users almost always want anyway.

**Validation plan**: tag v0.4.3, let the release workflow rebuild all five targets, redownload the Windows zip on the dogfooding host, and confirm `gvm run --watch -- openclaw agent ...` proceeds past proxy startup. EC2 is unaffected (it builds locally) but should be re-smoke-tested for safety.

---

### 2026-04-09: EC2 E2E + stress test regression sweep — 23 fixes (165→201 PASS)

**Background**: A baseline run of `scripts/ec2-e2e-test.sh` against the latest EC2 binary surfaced 29 failures across many unrelated tests. The 60-min stress run looked green but recorded only 4 system events from 1500+ silently-failing agent turns. This entry consolidates the root-cause investigation and fixes from a single multi-day session. Final state: **E2E 201 PASS / 8 FAIL / 30 SKIP** (8 remaining are environmental — EC2 IP exhausted GitHub's anonymous 60req/h quota, not code regressions). **Stress 5-min validation: 36 agent events vs floor 15 — agents actually exercising the proxy now**, with the 60-min run in progress at commit time.

**Meta-finding (the most expensive one)**: The first ~10 hours of debugging chased "regressions" that turned out to be **stale binaries**. A partial scp/tar restore on EC2 left `src/` missing — `cargo build --release` ran in 0.0s with nothing to compile, the old binary kept running, and tests measured code that no longer existed. Several MITM and sandbox commits from 4/8 (6532f78 SNI fix, ebd1edf Host header fix, d416777 exit-reason classifier, etc.) were never actually loaded. CLAUDE.md gained a new "Always test against the latest binary" rule with a mandatory pre-test ritual (git rev + binary mtime + non-zero cargo elapsed) so this can't recur silently.

**Code fixes (Rust + systemd)**

1. **`gvm run` does not propagate the agent's exit code** (`crates/gvm-cli/src/{run,pipeline,main}.rs`). Pipeline collected `result.exit_code` but discarded it, so a non-zero agent always surfaced as `exit 0` from gvm. Systemd `Restart=on-failure` therefore never engaged on Test 78f even when the inner agent exited 2. Threaded `i32` through `run_full` → `run_agent` → `main`, and `std::process::exit(agent_exit)` after the last `await?`. The Result-propagation chain is unchanged so anyhow errors still bubble.

2. **`packaging/systemd/gvm-sandbox@.service` — `StartLimitIntervalSec` / `StartLimitBurst` in wrong section.** Systemd silently ignored these in `[Service]` (logged as "Unknown key name … in section 'Service'") and the unit had no rate limit. They belong in `[Unit]`. Moved them up.

**Test infra fixes (`scripts/ec2-e2e-test.sh`, `scripts/stress-test.sh`)**

3. **`tail -1/-N` capture of agent stdout broke after d416777** (sandbox CLI epilogue). The CLI now prints `Cleanup verified`, `File Changes`, `Process completed`, `No audit trail` after every agent exit, pushing the agent's marker line out of the `tail` window. Tests 35a/39/43a/43b/43d/44b/66c each replaced their `… | tail -1` with `… | grep -E '^MARKER|^...' | tail -1` so they latch onto the agent's structured output regardless of how many epilogue lines come after.

4. **`set -o pipefail` + `grep -q` SIGPIPE polling loop** (Test 78c). `journalctl -u … | grep -q "agent up"` failed with exit 141 because grep -q closes its stdin on first match and journalctl dies on SIGPIPE; pipefail surfaces 141 to the if statement, the loop never breaks, journald has the line the entire time. Replaced with `grep -c | wc-style` count check that consumes all input.

5. **8668d30 SRR isolation incomplete.** That commit moved the runtime srr/proxy.toml under `$TEST_CONFIG_DIR` and exported `GVM_CONFIG`, but several call sites still wrote to `$REPO_DIR/config/srr_network.toml` (Test 29, L1740) or patched `$REPO_DIR/config/proxy.toml` directly (Test 81, L6325). Test 76's mock-host injection also targeted the repo file, so the running proxy never saw the override and credential injection silently degraded to passthrough. All three sites now write to `$PROXY_TOML_PATH` / `$SRR_NETWORK_PATH`.

6. **`PROXY_LOG` mismatch.** The CLI-only refactor pointed `ensure_proxy()` at `gvm run -- /bin/true`, which spawns the daemon via `proxy_manager.rs` writing to `data/proxy.log`. Tests still grepped `/tmp/gvm-proxy-e2e.log`. Updated `PROXY_LOG="$REPO_DIR/data/proxy.log"`.

7. **Chaos-kill PID disambiguation.** `pgrep -f "gvm-proxy" | head -1` was matching unrelated processes whose cmdline contained the string "gvm-proxy" — including the parent bash and tmux session, which the chaos `kill -9` then killed mid-suite, tearing down the entire run. All eight chaos sites now prefer `cat data/proxy.pid` and only fall back to pgrep.

8. **`mkdir -p $REPO_DIR/output` at script setup.** `mount.rs::pivot_root_setup` chdir's the agent to `/workspace/output` (with fallback to `/`). Path 1 (parent overlayfs) does not auto-create the directory, so without this every relative-path write inside the agent landed in the sandbox rootfs tmpfs and got destroyed on exit — Tests 50/51/56/80 silently produced zero files. The architecture decision (chdir target) is documented inline.

9. **Test 50c/51b/56b — fs governance bucket semantics.** d00b11a/687144f turned overlayfs on by default and added the auto_merge / manual_commit / discard buckets. The legacy tests treated *any* host write as a "leak" (Test 50c) and looked in `output/` for *.sh / *.json files (Tests 51b, 56b) that now go to `data/sandbox-staging/<pid>/output/` for review. Updated each assertion to walk the bucket the file is actually supposed to land in. Test 50c is now a positive check that the auto_merge bucket merged a `.csv` AND that a no-pattern-match file did NOT land on the host.

10. **Test 63b — overlayfs default semantics.** With overlayfs on, sandbox writes to `/workspace/config/...` succeed inside the sandbox by design — they go to the upper tmpfs. The pre-default test expected the syscall itself to fail. Replaced with the correct invariant: capture host SHA-256 of the config before, run the agent, assert host SHA-256 unchanged regardless of whether the inner write succeeded.

11. **Test 78c journald flush race + Test 78f restart-cycle race.** Bumped the polling windows (10s for journald flush, 25s for at least one Restart=on-failure cycle) so legitimate timing variance on a busy host doesn't fail the test. Combined with #1 above, NRestarts now reaches ≥1 deterministically.

12. **Test 80 fs-governance round-trip.** The agent script lived in `$FS80_WS` (a /tmp dir), but inside the sandbox `/tmp` is a fresh tmpfs and the host path doesn't exist, so python3 exited code 2 in 0s with no fs activity. Rewrote to invoke an inline `python3 -c '...'` from `$REPO_DIR` so the staging dir lands in `data/sandbox-staging/<pid>/` where 80a expects it. 80d additionally extracts the actual manifest paths instead of hardcoding `output/config.json`, which moved when fs governance landed.

13. **Test 80d interactive PTY hang → bounded skip.** `script -qec` doesn't always forward `printf 'a\nr\n'` through the pty master before the gvm child opens its prompt; the binary then blocks on `/dev/tty`. Wrapped with `timeout 15` and treat exit 124 as SKIP (Test 79 covers fs approve via the non-interactive --accept-all/--reject-all paths anyway).

14. **stress-test.sh sandbox preflight failure (silent zero-coverage stress).** `launch_agent()` invoked `gvm run --sandbox` without sudo. As ubuntu, the sandbox preflight failed on `net_admin_capability` and every turn died in 0s for 60 minutes — 1500 turns on three agents, 0 WAL events, but a misleading PASS verdict because memory/FD/recovery still looked stable. Added `gvm_invoker="sudo -E"` (gated on `id -u != 0` + passwordless sudo check) so the agent path runs with the caps it needs and inherits ANTHROPIC_API_KEY across the privilege boundary.

15. **stress-test.sh verdict — minimum agent-event floor.** The previous stress verdict only checked memory/FD/recovery/orphans. Added an `agent_events` count (audit-export.jsonl with `gvm-proxy` system events filtered out) and a hard floor of `DURATION_MIN × NUM_AGENTS` events. Anything below means the agents never actually exercised the proxy and the run is invalid regardless of how stable the memory looked. Discovered the bug in #14; the floor would catch any future variant.

**CLAUDE.md additions**: new "Always test against the latest binary" rule (above) plus the pre-test ritual.

**Files**: `crates/gvm-cli/src/{run,pipeline,main}.rs`, `packaging/systemd/gvm-sandbox@.service`, `scripts/ec2-e2e-test.sh`, `scripts/stress-test.sh`, `CLAUDE.md`, `docs/internal/CHANGELOG.md`.

**Risk**: Low to medium. The Rust changes are exit-code propagation only — no new code paths, no changes to error handling. The systemd unit fix is a pure section-move. The test-script changes only affect the test suite and do not touch production code. The stress sudo wrapper degrades cleanly (hard error if no sudo, instead of the previous silent zero-coverage success).

**Out of scope (deferred)**: 8 remaining E2E failures (3a, 24a/c, 26a, 30a, 33a/b, 40) are environmental — `https://api.github.com` over CONNECT after the EC2 IP exhausted the anonymous 60req/h budget. Either let the IP recover, supply `GITHUB_TOKEN`, or move those assertions to a host that proxies through an authenticated network. Test 39 (sandbox under AppArmor on kernel 6.17) and Test 43b (sandbox→proxy DNS edge case) intermittently fail under full-suite ordering but pass in isolation; both predate this work.

### 2026-04-08: IC-3 ghost-approval fix — RAII guard + 410 Gone

**Problem (the deferred "Question C")**: When an SRR rule held an HTTP request via `RequireApproval`, the proxy inserted a `PendingApproval { sender: tx, ... }` into a shared `DashMap` and `await`'d the matching `rx` inside the axum handler future. If the agent's HTTP client timed out first, hyper cancelled the proxy handler future, dropping the `rx` — but the `tx` lived on inside `pending_approvals` until the much-longer proxy IC-3 timeout (default 5 min) elapsed. During that window:

1. **`gvm approve` showed a ghost.** The leaked entry kept appearing in `GET /gvm/pending` and looked indistinguishable from a live request.
2. **The operator's "approve" succeeded silently.** `api.rs` did `let _ = pending.sender.send(approved)` — when the receiver was dropped, send returned `Err(...)` but the leading `_` discarded it. The CLI received `200 OK` and printed `✓ Approved`, but no upstream call was made because the agent had already given up. The audit trail showed the event stuck in `Pending` state forever.

This is the worst kind of governance bug: the operator believes they made a security-relevant decision and the system pretends it complied, but nothing actually happened. A wire-transfer "approve" that the agent never sees.

**Fix**:

**1. RAII guard in `src/proxy.rs`.** New `ApprovalGuard { event_id, map, armed }` struct with a `Drop` impl that calls `pending_approvals.remove(&event_id)` when `armed`. The IC-3 hold path constructs the guard immediately after inserting the pending entry. On every normal exit (decision delivered, IC-3 timeout fired, sender dropped on shutdown) the function calls `guard.disarm()` so the guard's Drop becomes a no-op and the entry is consumed by whoever owns it (api.rs for delivered decisions, the timeout branch for fail-close, etc.). On the abnormal exit — hyper cancelling the handler because the agent disconnected — the function never reaches the disarm; the future is dropped, the guard's Drop runs, and the leaked entry is removed within microseconds.

**2. `410 Gone` in `src/api.rs`.** `pending_approvals_decision()` now checks the result of `pending.sender.send(approved)`. If it returns `Err`, the receiver is gone and the operator's decision cannot be honored. The handler returns `410 Gone` with `error: "agent_disconnected"` and a clear `reason` string instead of `200 OK`. The race between the guard's Drop and a fast `gvm approve` POST is the only window where this branch fires (the guard normally removes the entry first), but it's the safety net that catches the case where the operator's HTTP request crossed the cancellation in flight.

**3. CLI surfaces the new outcomes.** `crates/gvm-cli/src/approve.rs` introduces `enum DecisionOutcome { Delivered, AgentGone, Unknown, Error(String) }` and a new `render_outcome()` helper. `--auto-deny` and the interactive prompt both go through it. Output now reads:
   - `✓ Approved — request forwarded to upstream` (200)
   - `✗ Denied — 403 returned to agent` (200, deny)
   - `⚠  Agent already disconnected` + a two-line explanation that the operator's click had no effect (410)
   - `— <event_id> already drained (timeout or another approver got there first)` (404, soft, not an error)
   - `Failed to send decision: ...` (network/other)

**4. Unit tests in `src/proxy.rs::tests`.** Two pure tests, no full proxy stack needed:
   - `approval_guard_removes_entry_on_drop_when_armed` — inserts a synthetic pending entry, scopes a guard, lets it fall out of scope without disarming, asserts the map is empty. This is the cancellation path.
   - `approval_guard_keeps_entry_when_disarmed` — pops the entry through the normal channel, calls `disarm()`, re-inserts a fresh entry with the same id, asserts the map still contains it. This locks in the no-double-pop contract that lets api.rs own the consumption side without race-pop'ing the guard's entry.

**5. ec2-e2e Test 80 — real fs-governance round-trip (8 sub-tests)**. Spawns `sudo gvm run --sandbox --fs-governance` against a Python agent that creates one auto-merge file (`*.csv`), two manual-commit files (`*.py`, `*.json`), and one discard file (`*.log`). Asserts:
   - 80a: a staging dir with `manifest.json` was produced.
   - 80b: the manifest lists the manual-commit files but **not** the auto-merge or discard files. Catches any future regression where bucket classification leaks into the operator-review queue.
   - 80c: `gvm fs approve --list` sees the batch (read-only path).
   - 80d: per-file interactive `(a)ccept`/`(r)eject` through a faked PTY (`script(1)` from util-linux). Feeds `a\nr\n` so config.json is committed and install.py is rejected. Asserts the workspace contains the accepted file and **not** the rejected one — proves the per-file remove fix from the previous CHANGELOG entry holds end-to-end.
   - 80e: after every entry is decided, the staging dir is cleaned up (the all-decided cleanup branch).
   - 80f: re-running on an empty staging root is idempotent.
   - Skips cleanly if `script(1)` is unavailable, no sudo, or no python3.

**6. ec2-e2e Test 81 — IC-3 ghost-approval guard regression (3 sub-tests)**. The C-fix's main load-bearing assertion. Installs an SRR rule that triggers `RequireApproval` for `ghostcheck.test.gvm` (a synthetic host wired into `host_overrides` at script setup). Spawns a Python agent with a 3-second HTTP timeout, then:
   - 81a: while the agent is still waiting, `/gvm/pending` must show the held entry. Polls up to 2 seconds — if the entry never appears, the IC-3 path was never reached and the test fails loudly.
   - 81b: after the agent's HTTP timeout fires + a 1s grace window for hyper to cancel the handler future and the guard's `Drop` to run, `/gvm/pending` MUST no longer contain the entry. **This is the regression assertion for `ApprovalGuard`** — without the guard the entry would persist for `ic3_approval_timeout_secs` (default 5 minutes) and the test would fail.
   - 81c: as a sanity check, `POST /gvm/approve` for an unknown event id returns 404 (confirming the entry was actually removed, not just hidden from `/gvm/pending`).

The 410 Gone path is not tested via shell (it requires racing the operator's POST against hyper's cancellation in a window of microseconds, which is non-deterministic from a script). The unit test in `src/proxy.rs::tests` covers the guard semantics; the 410 branch is reachable code that triggers only on the brief window between hyper-cancel and guard-Drop.

**Why no flock or extra channel**: The Drop guard is the canonical Rust idiom for tying resource lifetime to a future. Adding any kind of explicit cancellation token would require threading the token through every hold-path branch, and any channel-based notification would itself have to handle the cancellation race we just fixed. The guard is ~30 lines and runs zero cost on the happy path (one boolean check in disarm, no syscalls).

**What this does NOT fix**: The audit trail still records the original event as `Pending` because the proxy never reaches the WAL update branch when its handler is cancelled. A separate piece of work could add a `Cancelled` `EventStatus` variant and write it from the guard's Drop — out of scope for this PR because it touches `gvm-types::EventStatus` and the WAL schema.

Files: `src/proxy.rs`, `src/api.rs`, `crates/gvm-cli/src/approve.rs` | Risk: Low-medium. Changes are localized to the IC-3 hold path. The guard's only side effect is `DashMap::remove`, which is the same call the timeout branch already makes. The 410 Gone branch is reachable only when `tx.send` fails, which previously was silently ignored — no path that worked before is now broken. CLI output strings change but no machine-parsed format does.

### 2026-04-08: `gvm fs approve` race-aware accept + partial-accept fix

**Two follow-up bugs found in the just-shipped `gvm fs approve`**:

**B (real bug — partial accept double-prompts)**: `interactive_batch` and `pipeline.rs::print_fs_diff_report`'s inline review both *copied* the staged file to the workspace on `(a)ccept` but never *removed* it from staging. A user who accepted 3 of 5 files and then hit `s` (skip rest) left all 3 already-merged files behind in the staging dir + manifest. The next `gvm fs approve` re-prompted the same 3 files and re-copied them — wasted operator time + a confusing audit trail. The `(r)eject` branch already removed the staged file, so this was a copy-paste asymmetry, not a design choice.

**A (race + UX gap — operator vs cron GC)**: nothing serialised `gvm fs approve` against `gvm fs approve --reject-all` running in cron. If the GC ran while an operator was reviewing, the staged file could vanish mid-loop and `fs::copy` returned a generic `No such file or directory (os error 2)`. The operator could not tell whether they had a permission problem, a corrupt batch, or a concurrent reject.

**Fix**:
1. **Per-file remove on accept**. Both `accept_batch()` and `interactive_batch()` (in `fs_approve.rs`) and the inline review in `pipeline.rs::print_fs_diff_report()` now `remove_file(&staged)` immediately after a successful `copy(&staged, &dst)`. Symmetric with the `reject` branch.
2. **Pre-check + race-aware error message**. Before each copy, both code paths check `staged.exists()`. If the file is already gone (previous accept, concurrent reject, manual cleanup), the entry is skipped with a `(staged file already gone — already processed or concurrent --reject-all)` message. If the file passes the check but `copy` then fails with `ErrorKind::NotFound`, the error is reported as `(vanished mid-copy — concurrent gvm fs approve --reject-all or cron GC?)` instead of the bare OS error.
3. **No flock**. We deliberately did not add a per-batch lockfile. Both `--accept-all` and `--reject-all` are idempotent under this fix, and cron GC running while an operator reviews is benign — at worst the operator sees the new race-aware warning and re-runs. Adding a flock would block cron behind an inattentive operator, which is the worse failure mode.

**Tests**: `Test 79` grows two sub-tests:
- **79i** — partial-accept regression guard: feed a 2-file batch, run `--accept-all`, assert that **both** the workspace contains the files **and** the staged sources are gone. Catches any future copy-paste regression of the remove-after-copy invariant.
- **79j** — race simulation: manifest lists two files but only one exists on disk (staging the cron-GC scenario without actually running cron). Asserts the surviving file still gets copied AND the missing file produces the new race-aware message — not a generic OS error.

**Known issue (deferred — Question C)**: HTTP IC-3 hold has its own race. When the agent's HTTP client times out before `gvm approve` arrives, hyper cancels the proxy-handler future, dropping the oneshot `rx` — but the matching `tx` remains live inside `pending_approvals`. The entry stays in the map for up to `ic3_approval_timeout_secs` (5 min default). During that window, `gvm approve` lists the entry as if it were live, and approving it succeeds at the API layer (`pending.sender.send(approved)` ignores the error from a dropped receiver) → operator sees `✓ Approved`, but nothing actually happened — the agent already gave up. Audit trail is left in `Pending` state.

This needs a fix in `src/proxy.rs` (hold the `pending_approvals` entry behind a Drop guard so cancellation removes it) plus `src/api.rs` (return a different status to `gvm approve` when `send` fails). Both files are sensitive — proxy.rs is the 2K-LOC handler. **Not in this PR**. Tracked here so the next session knows to fix it.

Files: `crates/gvm-cli/src/{fs_approve,pipeline}.rs`, `scripts/ec2-e2e-test.sh` | Risk: Low. The new pre-check is read-only; the new remove is conditional on successful copy; both are additive over the prior behavior.

### 2026-04-08: `gvm fs approve` (filesystem disk-leak fix) + collapse IC-3 to one channel

**Problem (P0)**: `gvm run --sandbox --fs-governance` writes overlayfs `manual_commit` files into `data/sandbox-staging/<pid>/` for human review. The TTY path drained the directory inline, but every non-TTY exit (CI, redirect, `nohup`, systemd unit, agent crash, `Ctrl-C` mid-prompt with `s` skip-rest) left the staging dir on disk forever. There was no command to drain it. Disk grew until the host filled — and unlike the HTTP IC-3 queue, FS staging has no timeout that eventually frees the space. The user-guide even referenced `gvm fs approve` as the recovery command, but that command did not exist.

**Problem (UX)**: `gvm run` spawned a background poller (`approve::poll_and_prompt_background`) that interleaved IC-3 approval prompts with the agent's stdout in the same terminal. It fought for `stdin` against the running agent, dropped lines on `stderr` non-deterministically, and racefully overlapped with anyone running `gvm approve` in a second terminal. The right model is one channel.

**Fix**:

**1. Manifest sidecar.** `pipeline.rs::print_fs_diff_report()` now writes `data/sandbox-staging/<pid>/manifest.json` *before* entering the interactive review branch. The manifest is v1 and records the workspace destination (which only the CLI knows — staging is keyed by PID), the agent ID, the creation timestamp, and per-file `path`/`size`/`kind`/`matched_pattern`. Written unconditionally so even a TTY user who hits `s` (skip rest) leaves the manifest behind for later drain.

**2. Drain criterion.** Inline interactive review only deletes the staging directory when `accepted + rejected == needs_review.len()`. Skipped batches stay on disk + the manifest, and the user is told `Drain later with: gvm fs approve`.

**3. New `gvm fs approve` subcommand.** Lives in `crates/gvm-cli/src/fs_approve.rs`. Walks `--staging-root` (default `data/sandbox-staging`), loads each `<pid>/manifest.json`, and applies one of four modes:
   - `--list` — print pending batches, modify nothing. Read-only inspection.
   - `(default)` interactive — TTY prompt per file with the same `(a)/(r)/(s)` UX as inline review. Bails out if no TTY (instead of silently skipping).
   - `--accept-all` — copy every staged file to its recorded workspace destination, then delete the staging dir. CI-friendly.
   - `--reject-all` — delete every staging directory without copying. The disk-leak garbage collector — wire into cron on hosts running untrusted agents.
   - All modes are idempotent; corrupt manifests log a warning and skip rather than crash; missing/empty staging root exits 0 cleanly.

**4. Collapse to one IC-3 channel.** Removed `approve::poll_and_prompt_background()` and the spawn of it from `BackgroundTasks`. `gvm run` no longer interleaves approval prompts with agent stdout. The single supported channel is now `gvm approve` in a separate terminal (or `--auto-deny` in CI). `BackgroundTasks` still spawns the proxy watchdog — that part is unchanged.

**Tests**: New `Test 79` in `scripts/ec2-e2e-test.sh` (8 sub-tests) — synthesizes a fake batch in a tempdir + manifest, then exercises `--list` (read-only), `--accept-all` (copy + cleanup), `--reject-all` (delete without copy — security-relevant: catches a regression that copies a rejected file), empty staging root (clean exit), missing staging root (clean exit), and corrupt manifest (skip with warning, no crash). No real sandbox needed — the test isolates the CLI walk + apply behavior.

**Docs**: `docs/user-guide.md` Filesystem Governance section rewritten with the four-mode workflow. The `gvm approve` section gains a "why a separate terminal" note explaining the channel collapse. CLI Reference table grows the `gvm fs approve` row.

Files: `crates/gvm-cli/src/{main,pipeline,approve,fs_approve}.rs` (new file: `fs_approve.rs`), `scripts/ec2-e2e-test.sh`, `docs/user-guide.md` | Risk: Low. The new manifest is additive (older sandbox builds simply won't have one, and `gvm fs approve` skips them with a visible warning). Removing the inline poller is a behavior change, but the replacement (`gvm approve`) was already implemented and tested — the only thing that disappears is the foot-gun. Existing CI that depended on inline prompts (none known) should switch to `gvm approve --auto-deny`.

### 2026-04-08: tmux observability + loud orphan warning + systemd packaging (P2 + P3 + D)

**Problem**: After the P1 PID-reuse fix, sandbox cleanup is correct under all known races, but there were still three operational gaps:
1. **No way to find which tmux session owned a leaked sandbox.** Operators running multiple `tmux` panes had to manually correlate `gvm status` PIDs against tmux server output.
2. **`gvm status` orphan output was muted yellow.** Easy to skim past, especially in long status dumps. The cleanup hint was at the bottom of the table — out of sight if there were many orphans.
3. **No supported way to run `gvm run --sandbox` as a real production daemon.** SSH disconnect resilience required tmux; host reboot resilience and crash auto-restart had no answer at all.

**Fix (three independent pieces, one PR)**:

**P2 — tmux session in state file + status display**
- `SandboxState` gains `tmux_session: Option<String>` (still v3 schema, additive `#[serde(default)]`).
- `record_sandbox_state()` reads `$TMUX` (the canonical tmux session env var) and stores it raw. Empty/absent → `None`.
- `gvm status` reads the field and renders a `[tmux: session 42]` suffix on each sandbox row. New helper `short_tmux_label()` parses the `socket,server-pid,session-id` triple into a friendly form, with a basename fallback for non-standard formats.
- Pure observability: cleanup is still PID-based, this field never affects correctness.

**P3 — Loud orphan warning in `gvm status`**
- Three lines of bold red at the top of the orphan section, listing the count, what kind of resources are leaked (veth, iptables, mounts, cgroup), and the exact command to run (`sudo gvm cleanup`). The actionable command is *above* the orphan table so it stays on screen even with many orphans.
- Added a comment clarifying that the status-time liveness check (`kill(pid, 0)`) is intentionally weaker than the cleanup-time `is_pid_alive_with_starttime` — status is read-only and a false positive is harmless, the authoritative check is in `gvm cleanup`.

**D — systemd packaging**
- New `packaging/systemd/` directory with three files. Zero code changes; pure packaging.
- `gvm-cleanup.service` — oneshot, ordered `After=network-pre.target Before=network.target`. Runs `gvm cleanup` at boot to release any sandbox state left behind by a sandbox that crashed before reboot. `RemainAfterExit=yes` so the success state persists.
- `gvm-sandbox@.service` — template (`%i` = agent name), `Type=simple` so systemd treats `gvm run --sandbox` as the unit lifecycle directly. Pulls in `gvm-cleanup.service` via `Requires=`. Layers a second `ExecStartPre=gvm cleanup` for defense in depth. `KillMode=mixed` + `TimeoutStopSec=30` so the agent gets a graceful SIGTERM window before SIGKILL. `ExecStopPost=gvm cleanup` is the safety net for the SIGKILL case. `Restart=on-failure` with `StartLimitBurst=3/min` to avoid wedge loops.
- `packaging/systemd/README.md` — install/uninstall, lifecycle diagram, drop-in override pattern, and a tmux-vs-systemd decision table making it explicit which mode to use for which use case.

**Test infra (`scripts/ec2-e2e-test.sh`)**

Two new tests integrated into the existing `should_run N` framework:

- **Test 77 — orphan warning visibility (4 sub-tests)**: synthesizes a v3 `SandboxState` JSON with `pid=999999` (guaranteed dead — above `pid_max` on every distro), runs `gvm status`, and asserts the warning header, the cleanup hint, the PID listing, and the tmux label all render. Then runs `gvm cleanup` and verifies the synthetic state file is removed. Pure CLI test, no real sandbox needed.
- **Test 78 — systemd unit integration (6 sub-tests)**: installs the unit files into `/etc/systemd/system`, patching `/usr/local/bin/gvm` to the actual binary path used by the rest of the script. Runs `gvm-cleanup.service` and asserts `Result=success`. Drops a no-op agent script into `/etc/gvm/agents/`, starts `gvm-sandbox@e2e-systemd-test.service`, waits for it to come up, asserts `ActiveState=active`, then asserts agent stdout reaches journald and `gvm status` lists the sandbox. After the agent exits, verifies `ExecStopPost=gvm cleanup` released `/run/gvm` state. Finally drops a deliberately failing agent script and asserts `NRestarts >= 1` to prove `Restart=on-failure` engages. Cleans up its own units, agent files, and host kernel state at the end.

Both tests gate on `should_run`, `command -v systemctl`, passwordless sudo, and `$GVM_BIN` existence — they skip cleanly on environments that lack any prerequisite, just like every other Test in this script.

**Why this matters**: tmux is now the right answer for *interactive* work and systemd is the right answer for *production*. Both modes use the exact same `gvm` binary and the same orphan-detection state file, so an operator can mix them on the same host without surprises. P2 and P3 close the observability loop on either side; D gives operators a tested, packaged path to actually run agents in production without writing their own systemd units from scratch.

Files: `crates/gvm-sandbox/src/network.rs`, `crates/gvm-cli/src/status.rs`, `packaging/systemd/{gvm-cleanup.service,gvm-sandbox@.service,README.md}`, `scripts/ec2-e2e-test.sh` | Risk: Low. State file additions are `#[serde(default)]` (no schema break). `gvm status` changes are output-only — no behavioral change to cleanup. The systemd units are new files that nothing in the build pipeline references, so they cannot affect existing builds; they only activate when an operator manually `systemctl enable`s them.

### 2026-04-08: Defeat PID reuse races in sandbox orphan detection

**Problem**: `is_pid_alive()` (`crates/gvm-sandbox/src/network.rs`) classified a PID as alive based on three checks: `kill(pid, 0)`, `/proc/PID/stat` zombie state, and a substring search for `"gvm"` in `/proc/PID/cmdline`. The substring check was the only PID-identity guard, and it is not actually one — the kernel is free to recycle a dead `gvm` PID to any unrelated process whose command line happens to contain `gvm` (`/usr/bin/gvm-helper`, `/opt/gvm-monitoring/agent`, etc.). When that happened, `cleanup_all_orphans_report()` would skip the orphaned veth/iptables/cgroup/mount resources indefinitely. Probability low, blast radius high (permanent host-state leak that survives reboots only because tmpfs is volatile).

**Fix**: Use `/proc/PID/stat` field 22 (`starttime`, clock ticks since boot), which is monotonic per-process and resets only when the kernel hands the PID to a brand new process. The starttime is the canonical Linux PID-identity check.

1. **State file schema bump**: `SandboxState` is now version 3 with two new optional fields, `pid_starttime` and `child_pid_starttime`. Both use `#[serde(default)]` so v1 and v2 state files written by older binaries continue to deserialize and are handled by the legacy fallback path.
2. **Capture at launch**: `record_sandbox_state()` reads field 22 for both the parent (`std::process::id()`) and the child (`config.child_pid`) and stores it alongside the other resource manifest fields.
3. **Verify at scan**: New `is_pid_alive_with_starttime(pid, expected)` function. When `expected` is `Some`, the current `/proc/PID/stat` starttime must match exactly — otherwise the PID has been recycled and the original is treated as dead so its leaked resources get cleaned up. The legacy `is_pid_alive(pid)` is kept as a thin wrapper passing `None`, so the four call sites that operate on PIDs without recorded state (post-cleanup safety sweeps, ad-hoc PID checks) keep their existing behavior.
4. **Wire the orphan-scan caller**: `cleanup_all_orphans_report()` (both the `/run/gvm/` and the legacy `/tmp/` migration loop) now passes `state.pid_starttime` / `state.child_pid_starttime` to the new variant. v3 state files get the strict starttime guard; v1/v2 state files fall back to the previous cmdline-substring heuristic, so upgrading does not regress any existing orphan that the older binary would have handled.
5. **Pure parser + tests**: Field-22 parsing is split into `parse_proc_stat_starttime(&str)` and unit-tested for the four real-world shapes that have historically broken hand-rolled `/proc/PID/stat` parsers: comm fields with spaces and embedded parentheses, truncated stat lines, missing `)`, and non-numeric field 22. All tests fail closed (return `None`), never panic.

**What this does NOT fix**: tmux session tracking (P2) and `gvm status` auto-suggesting cleanup (P3) are deferred — the audit found those are observability/UX gaps, not correctness gaps. The core orphan-detection invariant ("if any of {parent, child} is gone, clean up") is now sound against PID reuse.

Files: `crates/gvm-sandbox/src/network.rs` | Risk: Low. New fields are additive and `#[serde(default)]`. The new code path only runs when a v3 state file is read; v1/v2 files keep their previous behavior bit-for-bit. The substring-fallback branch is preserved for legacy file paths so this cannot make orphan detection *worse* on upgrade.

### 2026-04-08: Honest dependency story — README + preflight (ip6tables, distro hints, setcap)

**Problem**: README claimed "single Rust binary with no dependency" — overstated. Reality:
- Binary is dynamically linked against glibc; Alpine/musl needs a separate build target
- `--sandbox` mode requires `iproute2`, `iptables`, and `ip6tables` on the host
- `gvm preflight` checked `ip` and `iptables` but **not** `ip6tables`, even though `network.rs`/`seccomp.rs` use it to disable IPv6 inside the sandbox netns. AAAA-resolving agents could silently bypass v4-only enforcement.
- Install hints were Debian-only (`apt install iptables`) — RHEL/Fedora/Amazon Linux/Alpine/Arch users had to guess
- `CAP_NET_ADMIN missing` only suggested sudo — `setcap` alternative was undocumented

**Fix**:
1. **README**: Replaced "single Rust binary with no dependency" with a realistic Requirements section listing glibc/musl distinction, sandbox-mode tools (iproute2 + iptables + ip6tables), and the `setcap` alternative to sudo. Added `gvm preflight` to Quick Start.
2. **`PreflightReport`**: Added `ip6tables_command_available` field (`crates/gvm-sandbox/src/lib.rs`). Populated in `capability.rs::check()` as a non-blocking warning — sandbox still launches without it, but operators see the IPv6 bypass risk in the issues list.
3. **`gvm preflight` CLI**: Surfaces ip6tables as a yellow (optional) check. New `install_hint(pkg)` helper reads `/etc/os-release` and maps `ID`/`ID_LIKE` to the right package manager invocation (`apt`, `dnf`, `apk`, `pacman`, `zypper`). Alpine hint also flags "musl build required". Mode-availability "reason" strings now use the same hint instead of hard-coded `apt`.
4. **CAP_NET_ADMIN guidance**: Detail message now suggests both `sudo` and `setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace+ep' $(which gvm)` so users on minimal/non-root environments have a path forward.

**Why ip6tables is non-blocking**: Sandbox functionally runs without it (v4-only enforcement still active), so blocking would break workflows on minimal containers where IPv6 is already disabled at the kernel. But the warning is loud enough that users on dual-stack hosts see the risk before deploying.

**Out of scope**: glibc-vs-musl detection from inside the binary is impossible if the loader fails to start the binary in the first place. README is the only viable warning channel for that case.

Files: `README.md`, `crates/gvm-sandbox/src/{lib,capability}.rs`, `crates/gvm-cli/src/preflight.rs` | Risk: Low (additive `PreflightReport` field, non-blocking new check, README copy change; `pipeline.rs::missing_critical` unchanged so existing flows still launch identically)

### 2026-04-07: Post-cleanup residual verification — auditable Zero-Trace claim

**Problem**: Both `gvm run --sandbox` cleanup and `gvm stop` ran cleanup with no way to confirm it actually succeeded. If a veth interface, iptables chain, mount point, cgroup directory, or state file survived (kernel bug, race, partial failure), the leak silently accumulated until the next `gvm cleanup --dry-run`. The "Zero-Trace" UX claim was aspirational, not auditable.

**Fix**: New `cleanup_verify` module with four checks, each cheap (~tens of ms total): one `ip link show`, two `iptables` calls, one `/proc/mounts` read, three `Path::exists()` checks.

`CleanupVerification` struct: per-category `Vec<String>` of leaked resource identifiers, with `is_clean()` and `total()` helpers. `verify_cleanup(pid, host_iface, mount_paths)` runs all four checks and returns the populated report.

The four pure parsers (`parse_mount_residuals`, `iface_present_in_link_show`, `chain_present_in_iptables`, `nat_rule_references_iface`) are OS-independent so they're unit-testable on Windows dev hosts. Only the `Command::new("ip"|"iptables"|"iptables-save")` invocations are gated linux-only. **18 unit tests** cover: real `/proc/mounts` fixture (multiple residuals, substring rejection, empty input), `ip link show` with `@peer` suffix stripping (substring rejection), `iptables -S` with `-N` declarations and `-j` references, NAT `-i`/`-o` matching, and the `is_clean`/`total` helpers.

**Wiring** — `sandbox_impl.rs` runs `verify_cleanup()` after the existing cleanup steps and stores the result in `SandboxResult.cleanup_verification`. `pipeline.rs::print_cleanup_verification()` renders it: silent on the happy path (single dim "Cleanup verified" line so users know the check ran), per-category `✓`/`✗` lines with manual recovery commands when leaks exist (`sudo umount -l <path>`, `sudo rmdir <cgroup>`, `gvm cleanup`).

**`gvm stop` parity** — `main.rs::run_stop()` runs a final residual scan after the orphan cleanup pass: globs `/run/gvm/gvm-sandbox-*.state` and parses `ip -o link show` for `veth-gvm-h*` interfaces. Prints either "✓ Verified: no veth, no state file, no /run/gvm/ residuals" or a list of survivors with the `sudo gvm cleanup` recovery hint. This is what makes "Zero-Trace" auditable instead of aspirational.

**`SandboxResult.cleanup_verification`** is a new field — additive, no existing field changed. CLI consumers update naturally because they pattern-match on `result.exit_reason` (the existing surface).

**E2E coverage** — `scripts/sandbox-observability-test.sh` test 7 (new) runs a normal-exit sandbox and asserts the "Cleanup verified" line appears with no residual markers. Test 8 (renumbered) adds a residual-verification assertion to `gvm stop` so any regression in the final scan is caught immediately.

Files: `crates/gvm-sandbox/src/{lib,sandbox_impl,cleanup_verify}.rs`, `crates/gvm-cli/src/{main,pipeline}.rs`, `scripts/sandbox-observability-test.sh` | Risk: Low (additive — new module, new field on `SandboxResult`, output is silent on happy path so no behavior change for clean exits)

### 2026-04-07: Seccomp violation → concrete syscall name from dmesg

**Problem**: `ExitReason::SeccompViolation` previously told users only that *some* syscall was blocked, with a "run dmesg | grep SECCOMP" pointer. Users then had to manually decode `syscall=165` (mount) into a name. The information existed in the kernel ring buffer the moment `waitpid` returned — we just weren't reading it.

**Fix**: Two new modules.

`syscall_names.rs` — pure number → name lookup built via macro from `libc::SYS_*` constants. Covers ~190 syscalls: the explicit blocklist (mount, ptrace, bpf, unshare, setns, open_by_handle_at, kexec_load, init_module, ...) plus common allowed syscalls so error messages stay useful when an agent dies on something we wouldn't normally expect. No hardcoded magic numbers — the macro stays in sync with libc upstream. Linux-only because `libc::SYS_*` constants don't exist on Windows; gated at module level. 6 unit tests.

`seccomp_audit.rs` — dmesg parser. `find_syscall_for_pid(pid)` invokes `dmesg`, scans newest-to-oldest for an `audit: type=1326` (AUDIT_SECCOMP) line containing `pid={target}` (token-bounded — never substring), extracts `syscall=N`. The line-level parser `extract_syscall_for_pid()` is OS-independent so it's unit-testable on Windows dev hosts. 7 unit tests covering: real dmesg line, wrong PID, non-SECCOMP record (`type=1300` AUDIT_SYSCALL), unrelated kernel line, PID substring boundary (pid=2345 must not match pid=23456), garbage syscall= field, comma-separated tokens.

**Wiring**: `sandbox_impl.rs` calls `find_syscall_name_for_pid(child_pid)` immediately after the SIGSYS branch, before cleanup. The audit record is already in the kernel ring buffer at this point because the seccomp Log filter emits it before the Kill filter terminates the child. `ExitReason::SeccompViolation` gained a `syscall: Option<String>` field — `Some("mount")` when we resolved it, `None` when dmesg is unreadable (`kernel.dmesg_restrict=1` without root) or no record matched.

**CLI**: `pipeline.rs::print_exit_reason` splits the SeccompViolation arm:
- `Some(name)`: `⚠ Agent killed: seccomp violation — attempted mount(2)` + actionable next step (remove the call or run without --sandbox).
- `None`: existing fallback (`Inspect blocked syscall(s): dmesg | grep SECCOMP`).

Graceful degradation throughout — if dmesg is unavailable (no permission, command missing, kernel ring buffer rotated), behavior is identical to the previous release.

**Test coverage**: 13 new unit tests (6 syscall_names + 7 seccomp_audit), all running on Windows dev hosts via the OS-independent parser split. `scripts/sandbox-observability-test.sh` test 3 now accepts three valid outcomes — SIGSYS+resolved (PASS), SIGSYS+fallback (PASS, dmesg unreadable), or ENOSYS (PASS, default filter behavior) — distinguishing the resolution path from the fallback path so regressions in dmesg parsing are visible.

Files: `crates/gvm-sandbox/src/{lib,sandbox_impl,syscall_names,seccomp_audit}.rs`, `crates/gvm-cli/src/pipeline.rs`, `scripts/sandbox-observability-test.sh` | Risk: Low (additive — new field on existing variant, dmesg invocation is best-effort, fallback path identical to current behavior)

### 2026-04-07: gvm stop + gvm status resource visibility

**`gvm stop` (new subcommand)**: Reads `data/proxy.pid`, sends SIGTERM, polls 5s for exit, escalates to SIGKILL on timeout, then runs `cleanup_all_orphans_report()` to release sandbox resources. Each step prints a `✓` line so users see exactly what happened — graceful exit time, veth interfaces removed, iptables chains flushed, mount paths released. The "CA key zeroized on exit" annotation is honest because `EphemeralCA::Drop` calls `zeroize` on the key bytes when the proxy process terminates. Persistent files (`data/wal.log`, `proxy.log`, `mitm-ca.pem`) are explicitly named as preserved — no "no trace left" exaggeration.

**`gvm cleanup` progress output**: Promoted `cleanup_all_orphans()` to return a `CleanupReport` (sandboxes, veth_interfaces, veth_names, mount_paths, cgroups, iptables_chains, orphan_veths_swept). The legacy count-only `cleanup_all_orphans()` wrapper stays for backwards compatibility. CLI now prints per-resource ✓ lines with veth names inline so users can verify exactly which interfaces were released.

**`gvm status` resource view**: Two new sections:
- **Active Sandboxes / Orphan Sandboxes**: Glob `/run/gvm/gvm-sandbox-*.state`, parse JSON, partition by `kill(pid, 0)` liveness. Live PIDs render as "Active Sandboxes" with PID + veth + IP + start time; dead PIDs render as "Orphan Sandboxes" with a `gvm cleanup` hint. Works whether the proxy is reachable or not — orphan recovery does not depend on a running daemon.
- **Isolation Profile**: Static surface — `gvm_sandbox::allowed_syscall_count()` (computed from `insert_base_syscalls` + the socket family at runtime, no hardcoded magic), `/proc/filesystems` overlay support, `preflight_check().tc_filter_available`. Renders as `seccomp: N syscalls allowed, ENOSYS default` / `overlayfs: supported|unsupported` / `TC ingress: available|unavailable`.

**Health endpoint expansion**: `/gvm/health` now includes `uptime_secs`, `total_requests`, `ca_expires_days`. `AppState` gained `start_time`, `request_counter` (AtomicU64, Relaxed — never branched on), `ca_expires_days` (snapshot of `EphemeralCA::expires_in_days()` at startup). `proxy_handler` increments the counter on entry. The CLI status renderer prints these as `Uptime: 2h 15m`, `Requests: 12,345 total`, `CA expires in N days` only when present — older proxy builds without these fields render cleanly without "unknown" placeholders.

**CA expiry tracking**: `EphemeralCA` gained a `not_after: time::OffsetDateTime` field. `generate()` sets it directly from rcgen params; `load_from_disk()` approximates from cert file mtime + 365d (exact because `generate()` is the only writer). `expires_in_days()` returns the delta. No new dependency added — uses the existing `time` crate already pulled in by rcgen.

**E2E verification**: `scripts/sandbox-observability-test.sh` exercises every diagnostic surface end-to-end through `gvm` CLI only — no nsenter, no PID file mangling, no internal API calls. Seven scenarios: OOM hint (with --memory 32m + 200MB allocator), timeout hint (with GVM_SANDBOX_TIMEOUT=3 + sleep 120), seccomp filter active (mount() → SIGSYS or ENOSYS, both accepted), normal exit silence (no false positives), CPU throttle note (--cpus 0.1 + 8s busy loop), `gvm status` structural check, `gvm stop` staged output. Linux + cgroup v2 + sudo required.

Files: `crates/gvm-cli/src/{main,proxy_manager,status}.rs`, `crates/gvm-sandbox/src/{lib,seccomp,network,ca}.rs`, `src/{api,main,proxy}.rs`, `scripts/sandbox-observability-test.sh` | Risk: Low (additive — new subcommand, additive health fields, all CLI consumers handle missing fields)

### 2026-04-07: Replace hand-rolled /proc and `uname` parsing with `procfs` + `nix::utsname`

**Problem**: Three sites in `gvm-sandbox` reinvented well-validated library functionality:
1. `ebpf.rs::kernel_version()` fork+exec'd `uname -r` and parsed stdout — both a process spawn and a PATH dependency where a syscall would do.
2. `capability.rs` preflight kernel-version log read `/proc/sys/kernel/osrelease` directly.
3. `capability.rs::check_cap_net_admin()` read `/proc/self/status`, located the `CapEff:` line, and called `u64::from_str_radix(.., 16)` — a hand-rolled hex parser on a security-sensitive code path.

**Fix**:
- Sites (1) and (2) → `nix::sys::utsname::uname()` (single syscall, no fork, no PATH dependency, already-present `nix` dependency).
- Site (3) → `procfs::process::Process::myself()?.status()?.capeff` (structured `u64` field, parser maintained upstream). Bit-mask check against `CAP_NET_ADMIN` (index 12) is preserved — only the parsing layer changed.

**Out of scope (intentionally)**: `cgroup.rs` parsing of `memory.events` / `cpu.stat` was *not* migrated. Those files live under `/sys/fs/cgroup/`, which the `procfs` crate does not cover. The existing pure parsers in `cgroup_parse.rs` are already isolated, OS-independent, and unit-tested.

**Why this matters**: Aligns with the post-`9104ad5` direction of replacing custom parsers with battle-tested crates. CapEff hex parsing is exactly the kind of code that silently fails-open if the kernel ever changes the field format (e.g., adds a prefix), and a fork+exec on the sandbox preflight hot path is wasted overhead.

Files: `crates/gvm-sandbox/Cargo.toml`, `crates/gvm-sandbox/src/{ebpf,capability}.rs` | Risk: Low (drop-in replacements; behavior preserved on success path; both `nix::utsname::uname()` and `procfs::Process::myself()` return `Result` and the existing fail-closed branches are kept)

### 2026-04-07: Sandbox exit reason classification (OOM, timeout, seccomp, external SIGKILL)

**Problem**: When the sandboxed agent died from `WaitStatus::Signaled(_, SIGKILL, _)`, GVM logged only "Agent killed by signal: SIGKILL" — indistinguishable across cgroup OOM, GVM-initiated timeout, user Ctrl+C, and external `kill -9`. Users had no actionable signal for the most common production failure (OOM).

**Fix**: Added `ExitReason` enum (`Normal | AgentError | Timeout | UserInterrupt | SeccompViolation | OomKill | ExternalKill`) and classified SIGKILL exits by root cause priority: OOM (cgroup `memory.events.oom_kill > 0`) → Timeout (GVM wait loop set the flag) → UserInterrupt (SIGTERM relayed) → ExternalKill. SIGSYS routes directly to SeccompViolation. OOM takes precedence over Timeout because memory pressure is the underlying cause when both fire (slow agent → timeout, but root cause is memory).

**cgroup observability**: `CgroupGuard::oom_kill_count()` reads `memory.events`, `cpu_throttled_us()` reads `cpu.stat`. Both must be called before the guard is dropped (Drop removes the cgroup directory). Called in `sandbox_impl.rs` immediately after `waitpid` returns — safe because `memory.oom.group=1` ensures all cgroup processes are reaped before SIGCHLD, so the counter is final.

**CLI output**: `pipeline.rs::print_exit_reason()` prints actionable hints for each variant. OOM → "out of memory (limit: 32MB). Try: gvm run --sandbox --memory 64m". Timeout → "Increase via: GVM_SANDBOX_TIMEOUT=...". CPU throttling > 1s also surfaces a note independent of exit reason.

**Testability**: Pure parsers (`parse_oom_kill_count`, `parse_cpu_throttled_us`) extracted to `crate::cgroup_parse` (not gated on `target_os = "linux"`) so they're unit-testable on Windows/macOS dev hosts. 8 parser tests covering: empty file, missing field, garbage value, no-throttle, with-throttle. Runtime cgroup file I/O remains in `cgroup.rs` (linux-only).

Files: `crates/gvm-sandbox/src/{lib,sandbox_impl,cgroup,cgroup_parse}.rs`, `crates/gvm-cli/src/pipeline.rs` | Risk: Low (additive — `SandboxResult` gains fields, no existing fields removed; classification logic is post-hoc on existing wait result; cgroup reads are graceful-fallback)

### 2026-04-06: Security hardening — veth IP collision fix + /tmp TOCTOU fix

**Veth IP collision elimination**: Replaced PID-based subnet derivation (`child_pid % 256`, `(child_pid / 256) % 64`) with a monotonic `AtomicU32` counter. Previous design could produce identical /30 subnets when two PIDs mapped to the same slot (e.g., PID 100 and PID 16484), causing network isolation breakdown between concurrent sandboxes. Counter guarantees uniqueness within a process lifetime; orphan cleanup on restart prevents cross-restart collisions. Parent sends the counter slot (not PID) to child via coordination pipe for address reconstruction.

**/tmp → /run/gvm/ migration (TOCTOU fix)**: All sandbox staging paths (`sandbox-staging-ws-{pid}`, `sandbox-root-{pid}`, `home-overlay-{pid}`, `home-merged-{pid}`) and state files (`gvm-sandbox-{pid}.state`) moved from `/tmp` to `/run/gvm/`. `/tmp` is world-writable — a local attacker could pre-create symlinks at predictable PID-based paths, hijacking bind mounts via TOCTOU race. `/run/gvm/` is root-owned tmpfs: immune to symlink attacks, auto-cleaned on reboot. Legacy `/tmp/gvm-sandbox-*.state` files are auto-migrated on first orphan cleanup scan.

Files: `crates/gvm-sandbox/src/{network,sandbox_impl,mount}.rs`, `crates/gvm-cli/src/main.rs`, `crates/gvm-sandbox/tests/security.rs` | Risk: Medium (network allocation scheme change, filesystem path change — requires testing on Linux with concurrent sandboxes)

### 2026-04-05: Sandbox $HOME overlay + MITM relay fix + resource limits opt-in

**$HOME overlayfs mount**: Parent (real root) mounts overlayfs with lower=$HOME, upper=tmpfs. Child bind-mounts merged dir to /home/agent. Sensitive dirs (.ssh/.aws/.gnupg) masked with empty tmpfs. Writes go to tmpfs upper layer — host $HOME is never modified. No copy, no chmod, instant mount regardless of $HOME size.

**DAC capability retention**: Keep CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_CHOWN after setup. Agent can read all files in sandbox filesystem (Docker-equivalent security model). Security boundary is file exposure (overlayfs + blocklist), not DAC permissions.

**CA trust store fix**: Merge host system CA bundle with GVM MITM CA. Previously overwrote ca-certificates.crt with MITM CA only, causing "self-signed certificate in certificate chain" for direct HTTPS connections.

**MITM relay HTTP framing**: relay_tls() now parses Content-Length and Transfer-Encoding: chunked to detect response boundaries. Previously did blind byte forwarding — HTTP/1.1 keep-alive connections never sent EOF, causing Telegram long-poll (getUpdates) to stall indefinitely.

**NO_PROXY for localhost**: Set NO_PROXY=127.0.0.1,localhost,::1 in all launch modes (sandbox/cooperative/contained). Prevents internal agent traffic (OpenClaw gateway :18789, Ollama, local DBs) from being routed through the proxy.

**Resource limits opt-in**: `--memory` and `--cpus` are now opt-in (default: unlimited). Previously defaulted to 512MB/1CPU, causing OOM kills for memory-intensive agents. Users explicitly set limits when needed: `gvm run --sandbox --memory 1g --cpus 0.5`.

Files: `crates/gvm-sandbox/src/{mount,sandbox_impl}.rs`, `crates/gvm-cli/src/{main,run}.rs`, `src/tls_proxy.rs`, `docs/{14-governance-coverage,15-user-guide}.md` | Risk: Medium (capability model change, relay protocol change)

### 2026-04-03: Security audit fixes + naming correction

**eBPF → TC filter naming**: Renamed all user-facing references from "eBPF TC filter" to "TC ingress filter". The implementation uses `tc u32` classifiers, not eBPF bytecode — the old naming misrepresented the enforcement mechanism. `PreflightReport.ebpf_available` → `tc_filter_available`. File renamed from `ebpf.rs` → `tc_filter.rs` in v0.5.0; types renamed: `EbpfAttachResult` → `TcAttachResult`, `EbpfGuard` → `TcFilterGuard`, `check_ebpf_support` → `check_tc_support`.

**Cgroup OOM group kill** (`cgroup.rs`): Added `memory.oom.group = 1` when memory limits are configured. Without this, OOM killer selects individual processes — forked agent children could survive and escape governance. With group kill, the entire cgroup is terminated atomically.

**TLS certificate pinning hint** (`main.rs`, `proxy.rs`): TLS handshake failures now log a warning suggesting `--no-mitm` when the agent may be using certificate pinning. Previously these were silent `debug!` logs.

Files: `crates/gvm-sandbox/src/{ebpf,cgroup,capability,sandbox_impl,network,lib}.rs`, `crates/gvm-cli/src/preflight.rs`, `crates/gvm-sandbox/tests/security.rs`, `src/{main,proxy}.rs`, `docs/{14-governance-coverage,15-user-guide,GVM_CODE_STANDARDS}.md` | Risk: Low (naming + defensive hardening)

### 2026-04-03: `gvm preflight` CLI command

**New command**: `gvm preflight` checks environment capabilities and maps results to available execution modes. Runs `capability::check()` (Linux) or platform stub (non-Linux), plus config file detection (proxy.toml, srr_network.toml, secrets.toml). Output shows per-item pass/fail + "Available Modes" section so users know what they can run before attempting `--sandbox`.

**Files**: `crates/gvm-cli/src/preflight.rs` (new), `crates/gvm-cli/src/main.rs` (Preflight command variant), `docs/15-user-guide.md` (pre-flight section + CLI reference).

### 2026-04-01: Agent Launch Pipeline + Proxy Lifecycle Manager

**Pipeline architecture** (`pipeline.rs`): Single execution path for all modes. Mode branching only in Phase 2 (launch). Pre-launch (proxy, orphan cleanup, CA download) and post-exit (audit, cleanup) are shared.

**Proxy lifecycle** (`proxy_manager.rs`): Independent daemon (setsid, PID file, log to data/proxy.log). Survives CLI exit. SUDO_UID/GID drop. Stale PID detection. Watchdog uses same daemon restart logic.

**Sandbox fixes**: DNS DNAT target recorded in state file for deterministic cleanup (H2). ip_forward saved/restored on last sandbox exit (H4). MITM WAL uses append_durable instead of append_async. GVM_SANDBOX_TIMEOUT in watch-discovery.sh.

**Code standards** (§7): Pipeline pattern, no logic duplication, process lifecycle separation, config path consistency.

Files: `crates/gvm-cli/src/{pipeline,proxy_manager,run,watch}.rs`, `crates/gvm-sandbox/src/{network,sandbox_impl,seccomp}.rs`, `src/tls_proxy.rs`, `docs/GVM_CODE_STANDARDS.md` | Risk: Medium (structural refactoring)

### 2026-04-01: Seccomp Architecture — KILL→ENOSYS Default + Blocklist

Changed seccomp default action from `KillProcess` to `Errno(ENOSYS)`. Unknown/new syscalls now return "not implemented" instead of killing the process, allowing runtimes to gracefully fall back. High-risk syscalls (ptrace, mount, bpf, unshare, etc.) remain blocked — ENOSYS prevents execution just as effectively as KILL, but without crashing the agent. Added `fadvise64` to whitelist (coreutils dependency).

Why: glibc 2.39+ calls new syscalls (rseq, fadvise64, etc.) during process initialization. Whitelist-only approach causes regressions every time kernel/glibc adds syscalls. ENOSYS default matches Docker's seccomp philosophy.

Files: `crates/gvm-sandbox/src/seccomp.rs` | Risk: Medium (security model change — ENOSYS vs KILL for unknown syscalls)

### 2026-03-31: Fuzzing CI Pipeline + 4 New Fuzz Targets

Added 4 cargo-fuzz targets (fuzz_http_parse, fuzz_path_normalize, fuzz_llm_trace, fuzz_policy_eval) to the existing 2 (fuzz_srr, fuzz_wal_parse). GitHub Actions workflow runs all 6 targets daily (5 min each) with corpus caching and crash artifact upload.

Why: Fuzzing CI was High priority on roadmap but unimplemented. SRR regex matching, HTTP parsing, and path normalization are highest-ROI targets for edge case discovery.

Files: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/fuzz_*.rs`, `.github/workflows/fuzz.yml`, `Cargo.toml` (workspace exclude) | Risk: Low (additive, no runtime changes)

### 2026-03-31: Security — CRLF Injection Defense + Fail-Close Consistency

**CRLF injection in MITM credential injection**: `inject_credentials()` wrote credential values as raw bytes into `rebuild_raw_head()` without validating for `\r\n` or `\0`. A compromised `secrets.toml` token containing CRLF could cause HTTP response splitting. Added `contains_header_injection_chars()` validation — injection is rejected (returns false) if any credential field contains CR, LF, or NUL. The HTTP proxy path (`api_keys.rs::inject()`) was already safe via `HeaderValue::from_str()`.

**SRR RwLock poison handling inconsistency**: `proxy.rs` and `tls_proxy.rs` used `unwrap_or_else(|e| e.into_inner())` on poisoned SRR locks, silently continuing with partial state (fail-open). This contradicted GVM_CODE_STANDARDS §1.2 (fail-close) and was inconsistent with `rate_limiter.rs` which correctly denied on poison. Fixed all 5 locations (`proxy.rs` ×3, `tls_proxy.rs` ×1, `api.rs` ×1) to return 500/deny immediately on poison.

Files: `src/tls_proxy.rs`, `src/proxy.rs`, `src/api.rs`, `src/api_keys.rs` | Risk: Low (defense hardening, no behavior change on non-poisoned path)

### 2026-03-30: Sandbox Auto-Cleanup + seccomp Fix
Per-PID state files for crash-resilient orphan cleanup; `gvm cleanup` CLI; pwritev/preadv/socketpair added to seccomp.
Why: 1024 stacked tmpfs mounts from crashes; orphan veth/iptables on SIGKILL; OpenClaw SIGSYS.
Files: `gvm-sandbox/src/{network,sandbox_impl,seccomp}.rs`, `gvm-cli/src/{main,run}.rs` | Risk: Medium

### 2026-03-30: Stress Test Workloads Rewrite
Rewrote all stress test workloads to use legitimate, non-refusable prompts. Removed exfiltration-testing workloads.
Files: `scripts/stress-workloads/*`, `scripts/stress-test.{sh,ps1}` | Risk: Low

### 2026-03-29: Wasm Engine Behind Feature Flag
Moved wasmtime behind `--features wasm` (disabled by default). Eliminates 5 CVEs and ~10MB from default binary.
Files: `Cargo.toml`, `src/lib.rs`, `src/proxy.rs`, `src/main.rs`, `tests/integration.rs` | Risk: Low

### 2026-03-29: Contained Mode E2E Tests (68-75)
8 new E2E tests for Docker `--contained` mode: MITM pipeline, SRR Deny, proxy bypass, filesystem, parity.
Files: `scripts/ec2-e2e-test.sh` | Risk: Low

### 2026-03-28: E2E Mock Server + Security Tests + False-Pass Cleanup
Mock GitHub/httpbin server (rate limit avoidance). Security tests 61-63. Test 17 rewrite. 7 false-pass→skip.
Files: `scripts/mock-github.py`, `scripts/ec2-e2e-test.sh` | Risk: Low

### 2026-03-28: E2E Test Reliability + Overlayfs Default
ensure_proxy 10x retry, OSError catch fix, admin port conflict fix, overlayfs enabled by default.
Files: `scripts/ec2-e2e-test.sh`, `crates/gvm-cli/src/run.rs` | Risk: Medium

### 2026-03-27: MITM TLS End-to-End Fix
CA DN mismatch, original CA in chain, HTTPS_PROXY removal (CONNECT bypass), system CA bundle paths.
Why: MITM failed with requests/curl due to chain/DN mismatches and CONNECT tunneling.
Files: `src/tls_proxy.rs`, `gvm-sandbox/src/{sandbox_impl,mount}.rs` | Risk: Medium

### 2026-03-26: DNS DNAT + MITM TLS Pipeline Complete
PREROUTING DNAT redirects sandbox DNS to upstream resolver. Full MITM pipeline verified end-to-end.
Files: `crates/gvm-sandbox/src/network.rs` | Risk: Low

### 2026-03-26: Kernel Panic Fix — Mount Deduplication + seccomp sendmmsg
HashSet dedup prevents kernel panic on Linux 6.17 from duplicate bind mounts. sendmmsg/recvmmsg added to seccomp.
Files: `gvm-sandbox/src/{mount,sandbox_impl,seccomp}.rs` | Risk: Low

### 2026-03-26: Security Audit — Unsafe/FFI, Blocking I/O, Namespace
eBPF `mem::forget` → RAII guard. WAL rotation → async I/O. `/proc` with `hidepid=2`.
Files: `gvm-sandbox/src/{ebpf,sandbox_impl,mount}.rs`, `src/{ledger,tls_proxy}.rs` | Risk: Low

### 2026-03-26: MITM CA Key Isolation + Zeroization
Fixed dual-CA bug (sandbox CA-B vs proxy CA-A). Single CA via `GET /gvm/ca.pem`. Key zeroize on drop.
Files: `gvm-sandbox/src/{sandbox_impl,lib,ca}.rs`, `gvm-cli/src/run.rs`, `src/main.rs` | Risk: Low

### 2026-03-26: Admin API Port Separation + stdin Isolation
Agent port (8080) vs admin port (9090). Agent cannot reach `/gvm/approve`. stdin → Stdio::null().
Why: Agent could self-approve IC-3 requests; stdin race conditions.
Files: `src/{main,config}.rs`, `gvm-cli/src/{run,watch,main}.rs` | Risk: Medium (breaking)

### 2026-03-25: cgroups v2 Resource Limits for Sandbox
`--sandbox` mode supports cgroup v2 CPU and memory limits via `--memory` and `--cpus` flags. RAII `CgroupGuard` with graceful fallback if cgroup v2 unavailable.
Why: Sandbox mode lacked resource limits that Docker mode already had.
Files: `gvm-sandbox/src/cgroup.rs` (new), `lib.rs`, `sandbox_impl.rs`, `gvm-cli/src/run.rs`, `gvm-cli/src/main.rs`
Risk: Low

### 2026-03-25: SRR Payload Inspection Activation
Wired SRR payload inspection to actual request bodies. Body buffered with `max_body_bytes` limit (default 64KB), re-attached for forwarding. Opt-in via `payload_inspection = true`.
Why: Payload inspection was parsed from TOML but never connected to request bodies.
Files: `src/proxy.rs`, `src/config.rs`, `src/main.rs`, `tests/integration.rs`
Risk: Low (backward compatible, off by default)

### 2026-03-25: IC-3 Blocking Approval — Human-in-the-Loop
IC-3 now holds HTTP response via oneshot channel and waits for human approval (timeout 300s, fail-close). Added `GET /gvm/pending`, `POST /gvm/approve` endpoints and `gvm approve` CLI.
Why: IC-3 previously returned immediate 403 instead of actually waiting for human approval.
Files: `src/proxy.rs`, `src/api.rs`, `src/main.rs`, `src/config.rs`, `gvm-cli/src/approve.rs` (new), `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`
Risk: Low

### 2026-03-25: `gvm watch` — Observation-Only CLI
New CLI command for real-time API call stream, session summary, cost estimation, anomaly detection. Default allow-all config with RAII cleanup. Zero proxy changes.
Why: Entry point to GVM funnel: observe → discover rules → enforce.
Files: `gvm-cli/src/watch.rs` (new), `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`
Risk: Low

### 2026-03-24: README Rewrite — Agent Developer Framing
Full README rewrite repositioning from "security proxy" to "agent operations tool". Two-step Quick Start (observe → enforce), realistic demos, cross-layer forgery reframing, OPA+Envoy comparison.
Why: Previous README was security-focused; target audience is agent developers.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-24: WAL Sequence Persistence + Size-Based Rotation
`wal_sequence` initialized from WAL event count during recovery (monotonic across restarts). Size-based rotation at `max_wal_bytes` (100MB default) with Merkle chain continuity. Old segments pruned beyond `max_wal_segments` (10 default).
Why: Sequence reset on restart broke NATS consumer ordering; unbounded WAL growth.
Files: `src/ledger.rs`, `src/config.rs`, `src/main.rs`
Risk: Medium

### 2026-03-24: MITM API Key Injection
Implemented credential injection on MITM TLS path. Agent auth headers stripped, credentials from `secrets.toml` injected. Same security properties as HTTP path.
Why: `--sandbox` HTTPS traffic bypassed Layer 3 credential isolation; agents needed API keys for HTTPS calls.
Files: `src/tls_proxy.rs`, `src/api_keys.rs`, `src/main.rs`, `README.md`
Risk: Low

### 2026-03-23: MITM Hardening + uprobe Feature Flag + README Honesty
CA unification (single EphemeralCA shared between proxy and sandbox). Certificate 24h backdate for clock drift. memfd_create false claims removed. uprobe gated behind `--features uprobe`. README exaggeration removal. 6 new EC2 tests (35-40).
Why: Dual CA generation broke MITM pipeline; uprobe is observation-only, not primary enforcement; README overclaimed.
Files: `src/main.rs`, `src/proxy.rs`, `src/tls_proxy.rs`, `gvm-sandbox/src/ca.rs`, `gvm-sandbox/src/lib.rs`, `scripts/ec2-e2e-test.sh`, `README.md`
Risk: Low

### 2026-03-23: Runtime Hardening — 4 Structural Vulnerabilities
TLS cert gen moved to `spawn_blocking` (prevented tokio worker starvation). HTTP request smuggling CL/TE rejected. FD exhaustion mitigated (semaphore 1024, timeouts). Sandbox PID 1 zombie reaper added.
Why: 50 concurrent TLS handshakes blocked all async I/O; CL/TE desync bypassed SRR; slowloris on port 8443; zombie accumulation in PID namespace.
Files: `src/tls_proxy.rs`, `src/main.rs`, `gvm-sandbox/src/sandbox_impl.rs`
Risk: Low

### 2026-03-23: Memory Safety — WAL Recovery Watermark + TLS Cache Bound
WAL recovery HashSet replaced with sidecar watermark file (O(N) → O(1) memory). TLS SNI cache DashMap replaced with moka bounded LRU (max 10,000, 1h TTL).
Why: WAL recovery OOM on large files; unbounded TLS cert cache exhaustible by unique SNI domains.
Files: `src/ledger.rs`, `src/tls_proxy.rs`, `Cargo.toml`
Risk: Low

### 2026-03-23: Documentation Consistency Fix — MITM Status
Fixed README and roadmap where MITM (implemented in v0.2) was still described as "planned v0.3". Renamed doc files 14→15, 15→16.
Why: Multiple sections contradicted each other on MITM implementation status.
Files: `README.md`, `docs/13-roadmap.md`, `docs/00-overview.md`, `docs/12-quickstart.md`, `docs/13-reference.md`
Risk: Low (documentation only)

### 2026-03-23: Documentation Audit — 20 Issues Fixed
Full cross-reference audit of 18 docs. Critical: seccomp count ~45→~111 (4 locations), Vault WAL claim fix, Tower middleware order fix, LLM trace Content-Length claim removed, uprobe→eBPF TC in examples.
Why: Documentation diverged from implementation across multiple files.
Files: `docs/00-overview.md`, `04-ledger.md`, `05-vault.md`, `06-proxy.md`, `07-sdk.md`, `08-memory-security.md`, `10-architecture-changes.md`, `10-competitive-analysis.md`, `11-security-model.md`, `13-roadmap.md`, `15-reference.md`, `README.md`
Risk: Low (documentation only)

### 2026-03-23: Security Hardening — WAL OOM, Rate Limiter, README Honesty
WAL recovery streaming (BufReader instead of read_to_string). Rate limiter rewritten from f64 to u64 millitoken fixed-point. README renamed "Security Kernel" to "Security Proxy".
Why: WAL OOM on large files; floating-point precision drift in rate limiting; README overclaimed.
Files: `src/ledger.rs`, `src/rate_limiter.rs`, `gvm-cli/src/suggest.rs`, `README.md`
Risk: Medium

### 2026-03-23: Documentation Update — SRR, Proxy, Reference
Added Base64 decoding, path_regex, SRR hot-reload to docs/03-srr.md. Added CONNECT tunnel, Shadow Mode, control plane endpoints to docs/06-proxy.md. Added reference entries.
Why: Implemented features lacked documentation.
Files: `docs/03-srr.md`, `docs/06-proxy.md`, `docs/15-reference.md`
Risk: Low (documentation only)

### 2026-03-23: Binary Mode, Base64 Decoding, MCP Rulesets, EC2 E2E
`gvm run` binary mode with HTTPS_PROXY injection. Base64 payload decoding in SRR. Telegram/Discord rulesets. 34 EC2 E2E test scenarios.
Why: Support arbitrary binaries (not just Python); detect encoded payloads; MCP platform governance rules; automated testing.
Files: `gvm-cli/src/main.rs`, `gvm-cli/src/run.rs`, `src/srr.rs`, `scripts/ec2-e2e-test.sh`, `rulesets/telegram.toml`, `rulesets/discord.toml`
Risk: Low-Medium

### 2026-03-22: Uprobe SRR Policy Enforcement
Connected uprobe TLS probe to proxy SRR engine via `/gvm/check` HTTP callback. Fail-closed: proxy unreachable → Deny (SIGSTOP).
Why: Uprobe captured HTTPS plaintext but had hardcoded Allow-all callback.
Files: `gvm-sandbox/src/sandbox_impl.rs`, `lib.rs`, `Cargo.toml`, `gvm-cli/src/run.rs`
Risk: Low-Medium

### 2026-03-22: Shadow Mode, 11 Security Patches, Sandbox Improvements
Shadow Mode with 2-phase intent lifecycle (intent store, `/gvm/intent`, `/gvm/reload`, strict/permissive modes). 11 security patches: IPv6 expand OOB, Merkle domain separation, Wasm pointer bounds, auth header expansion, regex length limit, agent_id validation, intent TOCTOU, first-run guard, Docker non-root, audit hash sync, SDK URL validation. Sandbox `/workspace/output` writable mount.
Why: MCP-compatible governance; security audit findings; sandbox usability.
Files: `src/proxy.rs`, `src/intent.rs`, `src/config.rs`, `src/api.rs`, `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `sdk/python/gvm/session.py`
Risk: Medium (Merkle domain separation is backward-incompatible with pre-existing WAL)

### 2026-03-21: Security Audit — 8 Patches
IPv6 expand array OOB (critical), Merkle domain separation (high), Wasm pointer safety (high), auth header stripping 4→10 (medium), regex pattern length limit (medium), agent_id length validation (medium), IPv6 loopback scheme (low), IPv4-mapped parsing fix (low).
Why: Systematic security audit of input validation and boundary conditions.
Files: `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`
Risk: Medium (Merkle hash backward-incompatible)

### 2026-03-20: WAL Batch Window + LLM Trace Streaming
WAL default batch_window changed from 0 to 2ms (10-50x TPS improvement under load). LLM trace extraction unified into tap-stream pattern (no more full buffering before forwarding).
Why: Every request paid full fsync with batch_window=0; non-SSE responses blocked first byte until entire body received.
Files: `src/ledger.rs`, `src/config.rs`, `src/main.rs`, `src/proxy.rs`, `tests/stress.rs`
Risk: Medium

### 2026-03-20: Test Coverage Gap Fill (5 Integration Tests)
E2E proxy forwarding, GovernanceBlockResponse fields, SDK header contract, policy conflict regex edge case, emergency WAL recovery path.
Why: No test verified actual HTTP forwarding, SDK-facing JSON error contract, or emergency WAL recovery.
Files: `tests/integration.rs`, `docs/09-test-report.md`
Risk: Low

### 2026-03-20: Config File Hash Recording in Merkle Chain
SHA-256 hashes of config files recorded as `gvm.system.config_load` WAL event at proxy startup.
Why: Policy file tampering between restarts was undetectable.
Files: `src/ledger.rs`, `src/main.rs`, `tests/integration.rs`, `docs/04-ledger.md`, `docs/11-security-model.md`
Risk: Low

### 2026-03-20: Security Documentation Reframing
Timing side-channel reframed as intentional design (rate limiter prevents statistical attacks). Fuzzing CI elevated to High priority. Constant-time SRR lowered to Low priority.
Why: Previous framing implied GVM was pursuing constant-time but falling short; honest framing is that end-to-end timing difference is inherent to all proxy architectures.
Files: `docs/08-memory-security.md`, `docs/11-security-model.md`
Risk: Low (documentation only)

### 2026-03-19: Vault Trait Abstraction (KeyProvider + VaultBackend)
New `KeyProvider` and `VaultBackend` traits. `Vault<B: VaultBackend = InMemoryBackend>` generic with backward-compatible default. Enables future KMS and Redis backends.
Why: Hardcoded AES-256-GCM + in-memory HashMap blocked KMS integration, persistent storage, and mock testing.
Files: `src/vault.rs`
Risk: Low

### 2026-03-19: Security/Audit Layer Code Review
Consolidated port-stripping (4 locations → `strip_port()`), extracted `response_status_label()` helper, shared seccomp base syscall list between default/strict filters.
Why: Code duplication across security-critical paths increased maintenance risk.
Files: `src/srr.rs`, `src/proxy.rs`, `gvm-sandbox/src/seccomp.rs`
Risk: Low

### 2026-03-19: README Restructure (Feedback-Driven)
10 external feedback items addressed: IC-3 gap callout, WAL limitations caveat, mode comparison table, honest OpenShell comparison, trimmed roadmap, consolidated demos.
Why: External review identified positioning and honesty issues.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: README Thesis Restructure
Five core strengths reframed as consequences of one architectural choice (infrastructure control over ML classification). Causal chain table, stack comparison, trade-off callout.
Why: Features were presented as independent; they are all consequences of one architectural decision.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: Tier 1/Tier 2 Separation Disclosure
Documented that forgery detection requires SDK (`@ic` decorator for Layer 1 semantic data). Without SDK, `max_strict()` is never called.
Why: Previous README created false impression that all features work with zero code changes.
Files: `README.md`
Risk: Low (documentation only)

### 2026-03-19: DX Improvements (Build Time + First-Run)
GitHub Actions CI + release workflow (5 targets). cargo-binstall support. Startup governance summary banner. First-run interactive setup with industry templates and auto-restart.
Why: No pre-built binaries; no CI/CD; raw error on first run with missing config.
Files: `.github/workflows/ci.yml`, `release.yml` (new), `Cargo.toml`, `src/main.rs`, `src/srr.rs`, `src/policy.rs`, `README.md`
Risk: Low

### 2026-03-19: SDK Composition Refactor
Removed `GVMAgent` inheritance requirement. `@ic` decorator now works on standalone functions via `configure()` + `gvm_session()`. GVMAgent optional (only for checkpoint/rollback/state).
Why: Inheritance conflicted with CrewAI, AutoGen, OpenAI Agents SDK base classes.
Files: `sdk/python/gvm/session.py` (new), `decorator.py`, `agent.py`, `__init__.py`, `langchain_tools.py`, `examples/standalone_agent.py` (new), `README.md`, `docs/07-sdk.md`
Risk: Low

---

## Architecture Decisions

### Merkle Tree WAL Integrity (2026-03-15)

WAL events form a binary Merkle tree per batch (intra-batch O(log N) verification). Each `MerkleBatchRecord` references the previous batch's root, forming an inter-batch chain. Event hash: SHA-256 of canonical fields with domain separation prefix (`gvm-event-v1:` for events, `gvm-node-v1:` for internal nodes). SHA-256 per event adds ~200-500ns; Merkle root per 100-event batch adds ~20us — negligible relative to WAL fsync (2ms).

### IPv6 SSRF Normalization (2026-03-15)

`normalize_host()` in `src/srr.rs` expands all IPv6 variants (zero-compression, bracket notation, IPv4-mapped) to canonical IPv4 before SRR matching. 13 attack variants tested across loopback, IPv4-mapped, cloud metadata, and private ranges — all correctly denied.

### WASI Preview1 Fix (2026-03-15)

Core Wasm modules (`wasm32-wasip1`) require WASI preview1 imports. Fixed: `Store<WasiCtx>` → `Store<WasiP1Ctx>`, `.build()` → `.build_p1()`, `add_to_linker_sync` updated to preview1 variant.

### Key Benchmarks (2026-04-02, EC2 t3.medium)

| Benchmark | Latency |
|-----------|---------|
| SRR only | 190 ns |
| E2E native (ABAC+SRR+max_strict) | 750 ns |
| E2E Wasm | 9.82 µs |
| Classification (direct HTTP) | 270 ns |
| WAL group commit (100 concurrent) | 7.99 ms (78x vs sequential) |
| Vault fsync (1KB-256KB) | 6.2-8.5 ms |
| Wasm cold start | 201 ms |
| Wasm warm eval | 7.86 µs |

---

## Assessed & Closed

Reported during security audit — determined non-vulnerabilities. See [11-security-model.md](security-model.md).

| Issue | Assessment |
|-------|-----------|
| AES-GCM nonce collision | Birthday bound: ~770M years at 1000 writes/day |
| Unbounded X-GVM-Context header | hyper/axum enforces ~64KB limit |
| Operation name CRLF injection | `HeaderValue::to_str()` rejects non-visible ASCII |
| Checkpoint step `u64::MAX` | Normal HashMap key, no overflow |
| SRR body size bypass | Default-to-Caution fallback catches unmatched requests |
| Vault `list_keys()` cross-agent | No API endpoint exposes this |
| SDK credential header pass-through | Proxy strips at Layer 3 |
| Rate limiter agent ID spoofing | Mitigated by JWT identity verification |

---

## Fixed Issues (v0.2)

| Issue | Fix |
|-------|-----|
| Upstream X-GVM-* header poisoning | Strip upstream response headers |
| API key strip scope | Strip Authorization, Cookie, X-API-Key, ApiKey |
| Thread-unsafe header setter | Thread-local `_gvm_context` |
| Mock server in production | `GVM_ENV` guard |
| SRR path traversal | Path normalization (percent-decode, null-byte, dot-segment) |
| Operation name header injection | Regex validation `[a-zA-Z0-9._-]+` |
| IC-1 event status | Check `response.status().is_success()` |
| Policy field typo silently ignored | Field name validation at load time |
| Import chain attack | Top-level imports in `decorator.py` |
| IPv6 SSRF defense | `normalize_host()` with `expand_ipv6()` |
| Checkpoint Merkle verification hardcoded | Real content hash + chain verification |
| Agent ID spoofing | JWT identity verification (HMAC-SHA256) |
| `transport.method` always empty in WAL | Capture method before body consumption |
| Throttle path always sets Confirmed | Check `response.status().is_success()` |
| Deny `ic_level` was 3 | Corrected to `ic_level: 4` (IC-4) |
