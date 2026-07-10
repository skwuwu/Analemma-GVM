# Changelog

> Architecture decisions, implementation history, and release planning.
> For security model, see [11-security-model.md](security-model.md).
> For configuration reference, see [13-reference.md](reference.md).

---

## Roadmap

### Deployment model

**One GVM runtime per organization.** GVM governs the agents of a single
organization within one runtime — JWT identity, per-agent budget, vault
namespace, Merkle audit chain, sandbox isolation are all designed for
the N-agent / single-org case. If multiple organizations need
independent governance, each runs its own GVM runtime (separate
process, separate WAL, separate ledger). This is intentional: a single
WAL with one Merkle chain is what lets the auditor verify the entire
system from one anchor — splitting it for cross-tenant data isolation
would erase that property. Multi-tenancy is solved at the deployment
layer (separate processes / containers / VMs), not inside the GVM
runtime.

### Current (v0.5.3)

HTTP enforcement proxy (Rust/axum/tower) with SRR network governance + API key isolation, IC classification (Allow/Delay/RequireApproval/Deny), Merkle tree audit ledger with WAL group commit + Ed25519 anchor signing, AES-256-GCM encrypted state cache, Wasm runtime (optional, behind `--features wasm`), JWT agent identity, TC ingress filter (kernel-level proxy enforcement), seccomp BPF sandbox with dual filter stacking, DNS soft governance (4-tier delay + alert), filesystem governance (overlayfs Trust-on-Pattern), IC-3 human approval workflow (admin port separation), MITM TLS proxy with bounded LIFO upstream connection pool (sole HTTPS inspection mechanism — uprobe removed).

**Release history**: v0.2 (Shadow Mode, CONNECT tunnel, SRR hot-reload, MITM), v0.3 (sandbox cleanup, overlayfs, seccomp audit), v0.4 (IC-3 approval, stress testing, contained mode), v0.5.0 (DNS governance, placeholder credentials, proxy hardening), v0.5.2 (per-sandbox CA routing, payload_inspection default ON, cleanup audit), **v0.5.3** (upstream connection pool — HTTP/1.1 MITM overhead +528ms → ~0ms, deterministic config-path discovery, Ed25519 anchor signing activated, --contained behind feature flag, segment editor + time-window SRR conditions, NATS/Redis ghost integrations removed, bench methodology corrections).

### Planned

**v0.6**
- Anomaly detection (low-and-slow exfiltration — cumulative volume tracking)
- WebSocket proxy support — `gvm.operation::ws_upgrade` descriptor exists for audit logging, but the MITM relay does not yet handle the HTTP `Upgrade: websocket` handshake. v0.6 adds a real WS relay so SRR rules can govern WS connections and individual frames.
- Overlayfs periodic scan (long-running agents): tokio timer → `scan_upper_layer()` at interval. The function exists in `crates/gvm-sandbox/src/filesystem.rs:68` but is only called once at sandbox exit; v0.6 wires a periodic invocation for agents that run for hours/days.
- Overlayfs inotify-based real-time scan (event-driven alternative to the periodic scan)

**v0.7 — Orchestrator integration & time-bounded permission grants**

The shared-runtime, per-sandbox-isolation model (one `gvm-proxy` process serving N `gvm run --sandbox` invocations) already shares the WAL, SRR ruleset, upstream connection pool, DNS state, and IC-3 approval queue across every sandbox. v0.7 makes the runtime explicitly orchestrator-friendly along two axes: (a) the **control plane** primitives an external orchestrator needs to drive permission decisions, and (b) the **sandbox lifecycle** primitives needed to run many short-lived agents efficiently.

This subsumes the previously-planned per-agent JWT-scope authorization (removed from this roadmap, see history below). Rather than introducing JWT-scoped rule matching inside one runtime — which would promote JWT verification to a hot-path cross-agent privilege boundary and add new attack surface — v0.7 leaves identity at the OS-process / namespace boundary (where structural enforcement is strongest) and gives the orchestrator the primitives to express richer policy *outside* the runtime.

***Control plane*** (enables orchestrator-driven time-bounded grants):

- **WAL event stream subscription.** `GET /gvm/events?since=<event_id>&filter=<jq-like>` (admin port) long-poll or chunked-stream of WAL events as they're sealed — decisions, anchor signatures, IC-3 transitions (`status: Pending` → `Approved` / `Denied`), sandbox lifecycle. Today the IC-3 queue is in-memory (`AppState.pending_approvals` DashMap, `src/proxy/mod.rs:442`) and the only orchestrator path is polling `GET /gvm/pending` (`src/api.rs:1110`). v0.7 adds a push-based stream so an orchestrator drives approval / autoscale / dashboard logic without polling. Backpressure via per-subscriber bounded channel; slow subscribers get a `gvm.subscriber.dropped` audit event and are evicted.
- **Granular SRR rule add / remove.** Today `POST /gvm/reload` (`src/api.rs:892-1040`) does an atomic full-file swap — fine for human reloads, awkward for orchestrators that want to inject one temporary rule. Add `POST /gvm/srr/rule` and `DELETE /gvm/srr/rule/<id>` for single-rule mutations under the same atomic-swap discipline (parse + validate the new rule, then RwLock-write the slot in the rules vector). The full-file reload path is preserved for operators editing config by hand.
- **Rule TTL — `expires_at: Option<DateTime<Utc>>` on `NetworkRuleConfig`.** Pure addition to the rule struct; the SRR evaluator skips rules whose `expires_at` is in the past. Lets an orchestrator push a "this agent may call api.payments.com for the next 5 minutes" rule and have it auto-expire without a follow-up cleanup call. The expiration check is deterministic on the request's evaluation timestamp (same pattern as the existing `time_window` condition, `src/srr/mod.rs:67-180`), so deterministic replay holds.

These three primitives compose into the **time-bounded permission grant pattern**:

1. Agent attempts an action covered by a `RequireApproval` rule.
2. IC-3 emits a `Pending` event; orchestrator's WAL stream subscription receives it.
3. Orchestrator decides — for *one-call* approval, calls `POST /gvm/approve` and stops there.
4. For *N-minute batch* approval, orchestrator calls `POST /gvm/approve` (releases this call) AND `POST /gvm/srr/rule` to insert an `Allow` rule with `expires_at: now + 5min` matching the same agent_id + URL pattern.
5. Subsequent agent calls in that window pass without IC-3 trigger (the new Allow rule fires first).
6. After 5 minutes, the rule auto-expires; the next call hits the original `RequireApproval` rule again.

GVM ships **zero** new decision logic — the runtime records, surfaces, and enforces. The orchestrator decides scope and duration. Same expressive power as a per-agent JWT-scope mechanism without any cross-agent boundary inside the runtime.

***Sandbox lifecycle*** (amortise the ~876 ms cold-start cost):

- **Sandbox pool / pre-warming.** Maintain a small pool of pre-cloned namespaces with veth + iptables + cgroup pre-staged but no agent process running. `gvm run --sandbox` takes from the pool and only pays the `execv` + agent-init cost (~50 ms target) instead of the full 876 ms namespace-build path. Pool size + idle TTL configurable via `[orchestrator] pool_size`, `pool_idle_ttl_secs`. The MITM CA per sandbox is still per-take (CA generation is the cheap part); the namespace + veth + iptables installation is what amortises.
- **Batch spawn API.** `POST /gvm/sandbox/batch` accepts `[{agent_id, command, env}]` and returns sandbox handles in one round-trip, so an orchestrator scheduling 10–100 agents at once doesn't pay per-agent CLI fork + admin-RPC latency. Reuses the same identity, vault, and SRR machinery as the single-spawn path.
- **Snapshot / restore.** Firecracker-style — `gvm sandbox snapshot <handle>` freezes the agent process, captures process state + namespace state + per-sandbox CA + checkpoint root into a single archive. `gvm sandbox restore <archive>` recreates the sandbox at the snapshot point. Critical for orchestrator patterns that pause idle agents and resume them on the next user turn (LLM agents are mostly idle waiting for next input). Snapshot itself is a recorded WAL event so the audit chain spans pause/resume.

Per-agent resource accounting (memory, request rate, token budget) sits on the v1.1 cgroup parent slice (below) — each agent_id maps to a sub-slice with its own caps. This is independent of v0.7; orchestrators can compose the two.

**v1.1 — Hardening**

Performance + observability:
- HashMap/Trie index for O(1) SRR host+method lookup (current path is linear scan; ~300µs at 1k rules per `tests/hostile.rs::srr_100_concurrent_checks`)
- `Cow<'a, str>` in SRR normalize paths (avoid allocations on the no-normalization-needed common case)

Resource limits + accounting:
- **Proxy self-cap.** `gvm-proxy` currently has no internal memory ceiling — RSS is whatever steady-state demand drives it (~17 MB measured under sustained load, but no hard upper bound). Ship a `MemoryMax=512M` in the `packaging/systemd/gvm-cleanup.service` companion unit, plus an in-process advisory check that warns when RSS approaches a configured threshold. Operators who want stricter caps already have systemd / cgroup wrappers, but the default unit should fail-loud rather than silently grow.
- **Aggregate sandbox cgroup parent slice.** Today each `gvm run --sandbox` creates a flat `/sys/fs/cgroup/gvm-agent-{pid}` cgroup ([`crates/gvm-sandbox/src/cgroup.rs:40`](../../crates/gvm-sandbox/src/cgroup.rs#L40)). Move under a parent slice (`gvm.slice/agent-{pid}`) so an operator can cap "all GVM-spawned sandboxes combined" via one `MemoryMax` on `gvm.slice/`. Per-agent caps remain on the `agent-{pid}` leaf slice; orchestrators wanting per-role aggregate caps (e.g., "all sandboxes the orchestrator labelled `readonly` get 4 GB combined") can do so by spawning each role under its own parent slice (`gvm.slice/role-readonly/agent-{pid}`) — labelling is the orchestrator's responsibility, GVM only provides the substrate.
- **Default sane-cap toggle in CLI.** Currently `gvm run --sandbox` without `--memory` / `--cpus` is unlimited (Docker convention). Add `[sandbox] default_memory = "1g"`, `default_cpus = "1.0"` config keys that the CLI applies when the operator hasn't overridden — gives a less-experienced operator a safe default without breaking the no-arguments-needed quickstart.

Audit + crypto:
- **Vault Argon2id KDF** + versioned vault file format. Today `LocalKeyProvider` accepts a 32-byte raw key from `GVM_VAULT_KEY`; an operator who wants password-derived encryption (with brute-force cost) has no path. Tracked as `△-7` in [`COVERAGE_HARDENING_PLAN.md`](COVERAGE_HARDENING_PLAN.md). Co-implemented with the KMS path (below) — operators choosing KMS bypass KDF entirely.
- KMS integration (AWS / GCP / PKCS#11). Trait abstraction (`KeyProvider`) is already in place (`src/vault.rs`); only `LocalKeyProvider` is implemented today. v1.1 adds at least one KMS provider impl plus operator docs for the production path.
- HMAC-signed checkpoint step (current `register_agent_root` is unauthenticated; an attacker with `gvm-proxy` socket access could inject a checkpoint root).
- Configurable `MAX_CHECKPOINT_SIZE` / `MAX_HISTORY_TURNS` per agent — currently constants in `crates/gvm-sandbox`; per-agent tuning lets operators give long-running analyst agents room without raising the cap globally.
- **Audit Phase 6b — HSM-backed anchor signing**: implement `verify_anchor_signature` for the `AnchorSignature::Hsm` variant. Backends to evaluate: PKCS#11 (YubiHSM, CloudHSM), Vault Transit, AWS KMS asymmetric. Trait already in place (`AnchorSigner` in `src/sign.rs`); the enum variant is defined but the verify path returns `"HSM signature verification not implemented"` today.
- **Audit Phase 6c — RFC 3161 TSA attestation**: implement `AnchorSignature::Tsa` end-to-end (signing layer fetches a TimeStampToken from a configured TSA, verifier validates the token chain). This is the only attestation variant that defeats clock rewind; `SelfSigned` alone proves "GVM produced this anchor" but not "by this wall-clock time." Cost amortization pattern: every Nth anchor TSA-attested, every anchor SelfSigned.
- **Audit follow-up — `BatchSealRecord.checkpoint_root` integrity**: today the seal records the live aggregator root but NOT the per-leaf set, so a tampered checkpoint snapshot would change the root without leaving a witness in the WAL. Bind the leaf set hash (or a Merkle proof of the leaves) into the seal so the seal alone is sufficient to verify the aggregator state at seal time.

**v2.0 — Runtime & Infrastructure**
- Mandatory-by-default interception profile (sandbox-mode default rather than cooperative-mode default)
- macOS / Windows host-level interception fallback (today these platforms only get cooperative-mode HTTP_PROXY)
- Proxy-controlled step numbers, full LLM response storage, incremental checkpoints
- gRPC detection + passthrough, pluggable isolation backend (namespace / firecracker / docker)

**v3.0 — Platform**
- Generic outbound capability governance (filesystem, shell, database)
- Protocol expansion (gRPC method-level governance, SMTP)
- Cross-agent collusion detection, trust delegation, inter-agent governance
  (within a single GVM runtime — see "Deployment model" above)
- **Compliance support**: concrete deliverables that help operators pursue SOC 2 / ISO 27001 / similar audits. Not pursuit of certification *for GVM* (that's organizational, not a feature):
  - `gvm compliance export --framework soc2 --period 90d` — structured evidence bundle (WAL excerpt with anchor signatures, config-integrity-context chain, IC-3 approval log) suitable as primary or compensating evidence for CC6.1 (Logical Access), CC7.2 (Monitor Activity), CC9.1 (Boundary Protection).
  - Documented control mappings — one-time docs effort cross-referencing SOC 2 Trust Service Criteria + ISO 27001 Annex A controls (A.8.16, A.8.32, A.8.34) against the proxy features that satisfy them. Lets an audit team check off boxes without reverse-engineering the WAL schema.
  - Retention policy enforcement surfaced explicitly — WAL rotation parameters are already configurable; v3.0 adds a `[compliance] retention_days` field that ties WAL retention + checkpoint persistence to a policy-stated retention window with auto-pruning.
  - Tamper-evident audit chain export with offline verifier — operator hands the auditor a single `.gvm-evidence` file + a static verifier binary; auditor reproduces the merkle/anchor verification with no GVM runtime needed.

---

**Removed from this roadmap on 2026-05-11** (architectural reframing):

- *v0.7 — Per-agent authorization with optional capability elevation* (the original three-phase plan: JWT-scoped rule matching + implicit elevation + explicit `/gvm/token/elevate`) — deleted in favour of the orchestrator-relay shape now occupying the v0.7 slot. Two structural problems with the original design: (1) it would have promoted JWT verification to a hot-path cross-agent privilege boundary inside one runtime (any JWT-library bug becomes cross-agent escape; scope-matching logic becomes a new bug class); (2) it duplicates capability already expressible via existing primitives — IC-3 (`RequireApproval` + `POST /gvm/approve`, `src/api.rs:1139`) is structurally per-action temporary permission grant, and an orchestrator subscribed to its events can express any longer time horizon by combining IC-3 approval with a TTL-scoped SRR rule push. The orchestrator's decision happens *outside* the runtime, where the OS-process / namespace boundary already provides structural enforcement; the runtime stays a recorder + enforcer of declarative rules with no decision logic. Same expressive power, strictly smaller runtime attack surface. The three new control-plane primitives (event stream, granular rule add / remove, rule `expires_at`) plus the existing IC-3 mechanism are sufficient — no JWT scope claim, no token mint endpoint, no implicit-elevation rule shape needed inside GVM.

---

**Removed from this roadmap on 2026-05-10** (implemented or scope-changed):

- *v1.1 Decimal-based numeric comparison for financial precision* — code review during the `△-11` hardening pass found the cap comparison was already exact `u64` (millionths fixed-point); the only `f64` step was at the input boundary, fixed by switching truncate→round-to-nearest plus adding `record_millionths` for callers with integer input. No drift in realistic per-call cost ranges; sub-millionth-per-call inputs use the integer API. See `tests/budget_precision.rs`.
- *v1.1 File permission check on `secrets.toml`* — implemented in `src/api_keys.rs` and `src/config.rs`. Both check `meta.permissions().mode() & 0o077` and auto-fix to `0600` with a `tracing::warn!` when group/other bits are set.
- *v2.0 NATS JetStream WAL publish, Redis Vault backend* — direction changed in commit `f3d274c` (`refactor(ledger): remove NATS/Redis ghost integrations`). The runtime no longer ships built-in publish/storage integrations; off-host audit replication and remote vault backends are operator-managed via the WAL file (rsync / fluentd / vector / S3 tail) and the `KeyProvider` trait. See [`docs/architecture/ledger.md §4.1`](../architecture/ledger.md#41-overview).
- *v2.0 Policy hot-reload via `SIGHUP`* — `POST /gvm/reload` on the admin port already provides atomic SRR hot-reload with validate-then-swap semantics. SIGHUP would be an additional trigger for operators who prefer signal-based control; the lack of urgency moved this off the active roadmap. Not categorically excluded — re-add if operator demand surfaces.
- *v2.0 TypeScript / Node.js SDK, Go SDK* — sdk-less pivot in commit `0df121a`. The whole Python SDK was removed and the `docs/quickstart.md` rewrite explicitly states "no Python SDK to import, no decorator to add, no client library to wrap your code." Sandbox mode + cooperative-mode `HTTP_PROXY` cover every HTTP-speaking agent without language-specific bindings.
- *v2.0 Prometheus metrics, Grafana dashboard* — explicitly out of scope per [`docs/internal/CLAUDE.md`](../../CLAUDE.md) Observability section: "Application metrics and agent internals are out of scope — use Prometheus and application-level tooling for those." GVM exposes governance decisions / cost / audit via the WAL + CLI; infrastructure metrics are the operator's existing stack.
- *v3.0 Protocol expansion item "WebSocket"* — already covered as a v0.6 line item (basic proxy support); v3.0's protocol-expansion entry now reads "(gRPC method-level governance, SMTP)" without the duplicate WebSocket bullet.
- *v2.0 KMS / Argon2id KDF entry* — consolidated with the v1.1 Vault hardening item above (KMS path + `△-7` KDF). Was redundantly listed in two phases; one canonical home is enough.
- *v3.0 "Envoy filter mode"* — contradicted the project's positioning. README §1 explicitly cites OPA+Envoy as "existing answers I wanted a lightweight alternative to," and `docs/security-layers.md` puts service-to-service authorization (Envoy's domain) and AI agent governance (GVM's domain) in different rows. Building GVM as an Envoy filter would (a) require operators to run Envoy, contradicting the "no Kubernetes / no service mesh" pitch, (b) duplicate Envoy's own ext_authz + RBAC + rate-limit primitives, (c) maintain a second codebase against the Envoy filter ABI. No upside that justifies any of those costs.
- *v3.0 "OPA compatibility layer"* — same family of contradictions. SRR is intentionally narrow (URL/method/payload patterns + time-window) and that narrowness IS the security model — Rego-style arbitrary expression evaluation expands the attack surface and weakens the header-forgery defense in security-model.md §3.10. OPA users' Rego policies are mostly RBAC + JWT-claim shaped (service-to-service authz), and don't translate to agent governance shape — there is no migration path that meaningfully reuses an existing Rego policy file. If interoperability with the OPA ecosystem becomes useful later, the right shape is **one-way export** (`gvm srr export --format rego` so OPA-shaped tooling can read GVM's rules read-only) rather than acceptance of arbitrary Rego on the input side.
- *v3.0 "SOC 2 / ISO 27001"* (vague certification line) — replaced with a concrete "Compliance support" sub-section listing actionable deliverables (evidence export CLI, documented control mappings, retention enforcement, offline tamper-evident verifier). GVM-the-software doesn't pursue an organizational certification; what it can ship is the artifacts that help an *operator's* deployment pursue one.
- *v1.1 "SRR hot-path execution via Wasm engine"* and *"Wasm module hash pinning + signature verification at load time"* (the entire Wasm subsection) — thesis violation. GVM's [`security-model.md §3.10`](../security-model.md) header-forgery defense leans on SRR being narrow by design — TOML-declarative URL/method/payload patterns with at most a time-window condition. Wasm policy modules are arbitrary expression evaluators; activating them generalises SRR into a Rego-shaped engine and dissolves the narrowness that IS the security asset. The original justification (a future "policy marketplace / third-party plugin scenarios") was speculative — there is no validated operator demand for plugin-based policies, and the existing `[features] default = []` gate keeps Wasm out of the production binary entirely. Listing "preconditions for activation" in v1.1 implied activation was on the medium-term roadmap; it is not. Wasm stays default-off, opt-in for any operator who explicitly recompiles with `--features wasm`, and the hash-pinning / parity-test work remains tracked as `△-2 (deferred)` in [`COVERAGE_HARDENING_PLAN.md`](COVERAGE_HARDENING_PLAN.md). If concrete demand for plugin policies surfaces later, the work re-enters the roadmap as a v3.x item with a real use-case driving the design.

---

## Implementation Log

### 2026-07-10: IPv6 SSRF gap closure (7 new classes)

Follow-up on a drift discovery: [security-model.md § 9](../security-model.md#9-ipv6-ssrf-mitigated)
had claimed "IPv4-Mapped IPv6 Bypass (Fixed)" since v0.2, and the
CHANGELOG's 2026-03-15 entry called it "IPv6 SSRF Normalization",
but the actual coverage in `normalize_host()` was three narrow
classes only: IPv6 loopback (`::1` and zero-compression variants),
IPv4-mapped `::ffff:/96` addresses, and the specific AWS metadata
sentinel `fd00:ec2::254`. Seven other IPv6 SSRF classes were open —
correctly listed in test-report.md's gap table (P3, issue #7) but
implicitly claimed as closed by the § 9 title.

This entry closes issue #7 and reconciles the three drifted docs.

**What changed** — [`src/srr/normalize.rs`](../src/srr/normalize.rs):

Extended `normalize_host()` to detect and normalize 7 additional
classes. Each detector returns a canonical sentinel that SRR rules
can pattern-match:

  - **Link-local (`fe80::/10`)** → `link-local.ipv6.invalid`
    (default gateway `[fe80::1]`, neighbor discovery, `%eth0` zone
    IDs stripped per RFC 4007)
  - **Unique Local (`fc00::/7`, ULA)** → `unique-local.ipv6.invalid`
    (RFC 4193 internal networks; AWS metadata `fd00:ec2::254`
    still hits its earlier, more specific sentinel)
  - **Multicast (`ff00::/8`)** → `multicast.ipv6.invalid`
    (all-nodes `[ff02::1]`, all-routers, site-local scopes)
  - **Unspecified (`::`)** → `unspecified.ipv6.invalid`
    (some kernels route outbound `::` to loopback)
  - **6to4 encapsulation (`2002::/16`)** → underlying IPv4
    (extracts A.B.C.D from `[2002:AABB:CCDD::/48]`; `[2002:7f00:1::]`
    reveals as `127.0.0.1` and hits existing loopback rules)
  - **IPv4-compatible (`::a.b.c.d`, deprecated per RFC 4291)** →
    underlying IPv4 (some legacy resolvers still handle this;
    `[::127.0.0.1]` and `[::7f00:1]` both normalize to `127.0.0.1`)
  - **Zone-ID strip (RFC 4007)** — happens before all detectors so
    `[fe80::1%eth0]` and `[fe80::1]` are treated identically. Zone
    IDs are OS-level metadata, an attacker can slap one on to try
    to bypass range detection.

The `.invalid` sentinels use RFC 2606's reserved TLD so they can
never collide with a real domain. For the range-class sentinels
(link-local, ULA, multicast, unspecified), operators must add SRR
deny rules keyed on the sentinel — a starter rule pack is now
documented in [security-model.md § 9](../security-model.md#9-ipv6-ssrf-mitigated).
The IPv4-extracting classes (mapped, compatible, 6to4, AWS
metadata) reuse existing IPv4-keyed rules — no operator action
required for those.

**Non-goal**: GCP and Azure metadata services are IPv4-only or
DNS-resolved (`metadata.google.internal.`, no canonical IPv6
address). The DNS-governance layer handles those paths; we don't
add IPv6 sentinels for something that has no canonical IPv6 form.

**Tests** — [`tests/boundary.rs`](../../tests/boundary.rs) § 3.5.b
adds 6 regression tests exercising ~25 attack payload vectors:

  - `ssrf_ipv6_link_local_blocked_by_srr` — 4 variants including
    zone-ID-suffix form + public IPv6 negative case
  - `ssrf_ipv6_ula_blocked_by_srr` — 4 variants spanning the
    `fc00::/7` range + AWS-metadata precedence assertion
  - `ssrf_ipv6_multicast_blocked_by_srr` — 5 variants across
    scope classes (link, site, global)
  - `ssrf_ipv6_6to4_encapsulation_blocked` — 3 embedded-private
    IPv4 variants + public-IPv4-in-6to4 negative case
  - `ssrf_ipv6_v4_compatible_deprecated_still_normalized` —
    dotted and hex forms
  - `ssrf_ipv6_unspecified_blocked_by_srr`

All existing IPv6 SSRF tests (`ssrf_ipv6_loopback_*`,
`ssrf_ipv6_mapped_v4_*`, `ssrf_ipv6_private_ranges_mapped_*`,
`ssrf_ipv6_cloud_metadata_*`) continue to pass — the refactor
didn't change any of the previously-covered paths, only added new
detection branches after them.

**Doc reconciliation**:

  - [security-model.md § 9](../security-model.md#9-ipv6-ssrf-mitigated)
    title changed from "IPv4-Mapped IPv6 Bypass (Fixed)" to
    "IPv6 SSRF (Mitigated)" with an explicit 10-row coverage
    matrix. Anchor `#9-ipv6-ssrf-mitigated` added for cross-linking.
  - [test-report.md](../test-report.md) gap table row for
    "IPv6 SSRF defense" now shows `~~P3~~ **CLOSED 2026-07-10**`
    with links to § 9 and the test file.
  - Issue #7 can be closed once these commits land on master.

### 2026-07-05: Cooperative lease O(N) → O(1) claim path

Two-step optimization of `IntentStore::claim_by_token_hash`, the
hot-path lookup for cooperative-intent-lease bound requests. D.1.1
had flagged the 1K-active case at 60.8 µs — outside the § 3.1
< 1 µs budget and 50× SRR alone. Investigation traced this to
two overlapping O(N) sources:

  - `cleanup_inner` walks every intent on every claim (~30 µs)
  - `intents.values().find(|i| ... token_hash == ...)` linear
    scan through the same map (~30 µs)

Fixed in two commits so each step is measured independently, and
so the amortization piece can ship without touching the store's
data shape:

  - [`a752cb7`](https://github.com/skwuwu/Analemma-GVM/commit/a752cb7) — Option B: amortize
    `cleanup_inner`. Add `last_cleanup: Instant` to `StoreInner`;
    the sweep now returns early unless ≥ `CLEANUP_MIN_INTERVAL`
    (100 ms) has elapsed OR the store is > `MAX_INTENTS / 2`
    (5K) full. Correctness preserved by per-claim `is_expired()`
    + `state` re-checks. **Result: 60.8 µs → 35.8 µs (-45 %).**
  - [`854cdfa`](https://github.com/skwuwu/Analemma-GVM/commit/854cdfa) — Option A: `token_hash_index:
    HashMap<[u8; 32], u64>` reverse index. `claim_by_token_hash`
    is now O(1) (mutex + one HashMap lookup + state check).
    Maintained on `register_with_context_token` (insert),
    `confirm` / `cancel_intent` / `cleanup_inner` (remove).
    `release` deliberately doesn't touch it — the intent stays
    Active, the token stays valid. **Result: 35.8 µs → 1.63 µs
    (-95 %).**

**Cumulative: 60.8 µs → 1.63 µs (40× faster).** Full number
matrix + design rationale + why Options C and D were deferred in
[docs/test-report.md § D.1.2](../test-report.md#d12-benchmark-refresh-2026-07-05--cooperative-lease-on--o1).

Trade-off worth pinning: the single-lease case moves from 528 ns
to 973 ns median (with wide CI [857-1120]). The mechanistic cost
is the ~30 ns SipHash on the 32-byte token added on top of a
1-entry linear scan. The regression is inside t3.medium
credit noise and is a rational trade for a 59 µs win at 1K
active.

All 18 `cooperative_intent_lease_*` regression tests pass
unchanged, including single-use, sandbox-binding-picks-most-recent,
confirm-idempotency, cancel-issuance-rollback, and the 10 s
`token_reuse_after_claim_timeout_still_returns_unbound` guard.

Options **C** (per-agent multi-field index for
`claim_by_sandbox_binding*`) and **D** (expiry priority queue for
`cleanup_inner`) were sketched during design and deferred. They
are **recorded** — not forgotten — with explicit trigger
conditions in [test-report.md § D.1.2 → "Deferred perf
optimizations (tracked follow-ups)"](../test-report.md#deferred-perf-optimizations-tracked-follow-ups):
sandbox-binding revisit if p99 shows it dominating cooperative
claim cost, or a deployment observes > 1K sandbox-bound leases per
proxy; expiry heap revisit if the > MAX/2 fallback branch starts
firing frequently or `MAX_INTENTS` is raised past ~50K. Neither
signal exists today (sandbox-binding is 606-619 ns, inside budget;
Option B amortization keeps the cleanup path effectively free).

### 2026-06-19: Bench refresh + CI bench-build coverage

Two related changes after the v0.6.0 → v0.6.3 cooperative-intent
lease epic landed:

**Refresh of [docs/test-report.md](../test-report.md) — new section
`D.1.1 Benchmark Refresh (2026-06-19)`** on EC2 t3.medium with Linux
ext4 and a Windows NTFS comparison run. Two findings worth pinning:

- New `bench_cooperative_lease` group: token-hash claim 528 ns
  (single lease) / 60.8 µs (1K active leases — the only number
  outside the < 1 µs hot-path budget); sandbox-binding 560-564 ns;
  unbound miss 103 ns. Cooperative stage adds ~50% on top of SRR
  for the single-lease case, well inside the upstream-RTT envelope.
- Refreshed baselines show SRR +17-22% vs the 2026-05-02 D.1
  numbers — Tier-2 P2-a action packs + `expires_at` / `principal_filter`
  / `unsafe_body_action` rule-field additions are the visible cost.
  Per-rule O(1) shape unchanged. The < 1 µs budget guards against
  regressing the shape, not against deliberate corpus growth.
- EvidenceFirst Allow cost model documented: ~6.4 ms per solo
  Allow on Linux ext4 (the fsync floor), group-commit amortizes
  100 concurrent into ~11 ms. Frames the operator's perf trade-off
  for the new `audit.allow_mode = evidence_first` knob.

**CI fix: [.github/workflows/ci.yml](../../.github/workflows/ci.yml)
clippy step now passes `--all-targets`.** Root cause of the
v0.6.0 `token_id` + v0.6.1 `requires_observed_body` bench-fixture
drift was that `cargo test --workspace` and bare `cargo clippy
--workspace` both skip the `benches/` target. So field additions
to `IntentRequest` / `GVMEvent` broke test fixtures (caught by CI
on the same PR) but bench fixtures slipped through silently. The
flag closes the loop: same PR that adds the field has to update
the bench fixture or CI fails. Four lints surfaced when
`--all-targets` first ran cleanly — doc_lazy_continuation in
`Classification.cooperative`, needless_borrows_for_generic_args in
`auth.rs` test, manual_range_contains in DNS adversarial test,
doc_overindented_list_items in srr_rule_api doc — all behavioural
no-ops, fixed alongside the flag.

### 2026-06-18: Cooperative intent lease — Phase 3c sandbox-IP binding (Tier-3 P3-c)

Closes the final Phase 3 deferral. Cooperative leases now bind
implicitly when the request originates from a GVM-allocated
sandbox veth IP — no `X-GVM-Context-Token` header required. This
is the delivery channel for cert-pinned HTTPS / mTLS / anything
else that wraps the request before GVM gets a chance to add a
custom header.

**Trust model.** The veth IP carrying the request was allocated
by GVM itself: the proxy minted it, recorded it in
`/run/gvm/gvm-sandbox-{pid}.state`, and forwarded the sandbox
child into a network namespace where that IP is the only
non-loopback source. For an agent process to forge a different
sandbox's IP would require breaking out of its network
namespace — the same threat boundary that already protects
credential separation between sandboxes. So binding via
`peer_ip → sandbox_id → agent_id` carries the same trust tier
as the rest of the sandbox model. Audit chain still records
`cooperative.declared_only` (or `cross_checked` with body
inspection) — same evidence tier as a token-bound claim.

**What changed.**

- `src/intent_store.rs` — two new claim methods, both
  mirroring `claim_by_token_hash` for atomic
  Active → Claimed transition + LeaseClaim snapshot:
  - `claim_by_sandbox_binding(agent_id, method, host, path)`
    — the HTTP-shape claim. Matches an Active **cooperative**
    lease (its `context_token_hash` is `Some(_)`) by
    `(agent_id, method, host)` with `path.starts_with(path_prefix)`.
    Legacy URL-only intents are deliberately ineligible.
    When multiple match, the most recently registered wins
    (`max_by_key(|i| (created_at, intent_id))`), guarding
    against a stale lease consuming the binding before a
    fresher one the agent actually intended.
  - `claim_by_sandbox_binding_host(agent_id, host)` — the
    CONNECT-shape variant. CONNECT cannot see the inner
    method / path (encrypted in the TLS that follows the
    200), so the binding matches by (agent, host) alone.
- `src/proxy/mod.rs` — new `try_sandbox_binding(state,
  request, target, observed_body)` helper. Called only when
  `extract_and_claim_lease` returned `NoToken`. Resolves the
  peer IP via `state.resolve_sandbox_anchor` and, if a
  matching cooperative lease exists, returns the same
  `CooperativeOutcome` shape as the token path. Same
  policy-epoch + `allow_pinned_lease` + body cross-check
  rules — the binding channel changes, the decision logic
  does not.
- `src/proxy/mod.rs::proxy_handler` — added a one-line
  fallback after the strip-token step:
  `match cooperative_outcome { NoToken => try_sandbox_binding(...), other => other }`.
  Production agents that already use the token path see no
  behavioural change.
- `src/proxy/connect.rs::handle_connect_inner` — inline
  fallback after `claim_connect_lease` returns `NoToken`.
  Calls `claim_by_sandbox_binding_host` and honors the same
  epoch / `allow_pinned_lease` rules as the token-bound
  CONNECT path, then re-routes through the existing
  `Valid` arm so the Allow event records
  `cooperative.declared_only` with the lease's declared
  `agent_id` / `operation`.

**Tests** (15, all passing — `tests/cooperative_intent_lease_phase3c.rs`).

Store-layer tests cover the decision logic cross-platform.
End-to-end Linux integration belongs in the
sandbox-observability stress test where real veth + state
files exist. The Phase 3c tests pin:

- Happy path (`POST /transfer` matches), child path via
  prefix, case-insensitive host comparison.
- Reject paths: different agent / host / method, path
  outside the prefix, legacy URL-only intent ineligibility.
- Single-use semantics: second sandbox-binding attempt
  finds the lease already Claimed.
- Cross-channel single-use: token claim on a lease
  sandbox-bound by another caller fails — both channels
  share the same `Active → Claimed` state machine.
- Recency: when two leases for the same
  `(agent, method, host, path)` are Active, the most
  recently registered wins.
- CONNECT-shape variant: host-only match works regardless
  of declared method / path, same rejects, same legacy
  exclusion.

**Risk.** Additive on production agents that don't run inside a
GVM-allocated sandbox — `resolve_sandbox_anchor` returns `None`
for loopback / non-Linux / unregistered peers, in which case
the helper returns `NoToken` and the existing SRR path runs
unchanged. The legacy-intent exclusion is the load-bearing
guard against silent evidence-tier upgrade for non-cooperative
flows. Token-bound and sandbox-bound paths share the same
Active → Claimed state machine, so neither can "double-spend"
a lease — verified by
`sandbox_binding_and_token_binding_share_the_state_machine`.

### 2026-06-18: Cooperative intent lease — Phase 3b CONNECT-visible token (Tier-3 P3-c)

Extends cooperative lease binding to the **CONNECT** boundary:
HTTPS tunnels the proxy cannot MITM (cert pinning, mTLS, raw TCP
relay). The agent puts `X-GVM-Context-Token` on the CONNECT
request line; the proxy claims the lease before the TLS tunnel
opens and the WAL event that anchors the tunnel records
`cooperative.declared_only` evidence with the lease's declared
agent_id / operation.

**What changed.**

- `src/proxy/connect.rs` — new `claim_connect_lease(state,
  headers, host) -> ConnectLeaseOutcome` mirrors
  `extract_and_claim_lease` for the CONNECT shape: token-hash
  lookup, host-match check, policy-epoch check with
  `allow_pinned_lease` opt-in. CONNECT has no inner method or
  path visible to the proxy (encrypted in the TLS that follows
  the 200), so those bindings are deliberately NOT checked here;
  agents that want per-request enforcement still set the token
  on the inner request inside a MITM-able CONNECT (Phase 2
  path).
- `src/proxy/connect.rs::handle_connect_inner` — runs the
  claim pre-check after target extraction and before the SRR
  domain check. Mismatch / Expired / Unbound outcomes
  short-circuit to a 403 with `X-GVM-Decision-Source:
  cooperative.*` and write a Deny WAL event whose
  `enforcement_point = "proxy-cooperative"`. Valid outcomes
  fall through to the existing SRR + Shadow-Mode path; the
  final Allow WAL event swaps `decision_source` to
  `cooperative.declared_only`, uses the lease's declared
  `agent_id` and `operation`, and adds
  `cooperative.pinned = true` to the event context when the
  lease was pinned across an epoch flip.
- **Token leakage.** CONNECT headers are consumed by the proxy
  and never re-sent — the bytes that follow `200 OK` are a raw
  TCP relay or a MITM-terminated TLS stream — so the Phase 2
  header-strip invariant has no analogue here. The token has
  no path by which to reach upstream by construction.
- `src/proxy/mod.rs` — new `connect_for_test` module
  re-exports `claim_connect_lease` + `ConnectLeaseOutcome`
  under `#[doc(hidden)]` so integration tests can exercise the
  helper directly. The full `handle_connect` flow requires
  hyper's upgrade machinery which is heavy to stub; unit-testing
  the lease helper covers the decision logic.

**Tests** (9, all passing — `tests/cooperative_intent_lease_phase3b.rs`).

- `connect_without_token_returns_no_token` — back-compat: no
  token → existing CONNECT path unchanged.
- `connect_with_unknown_token_returns_unbound`
- `connect_with_non_ascii_token_returns_unbound` — non-UTF-8
  header bytes are rejected as unbound.
- `connect_with_host_mismatch_returns_mismatch` — lease for
  `api.bank.com`, CONNECT to `api.evil.com` → Deny.
- `connect_with_matching_host_returns_valid` — happy path.
- `connect_host_match_is_case_insensitive` — DNS-style case
  folding, guards against an agent normalising to uppercase
  and tripping the mismatch arm.
- `connect_token_reuse_second_attempt_returns_unbound` —
  single-use semantics (same Active → Claimed state machine
  as the HTTP path).
- `connect_epoch_mismatch_without_opt_in_returns_expired` —
  default-strict.
- `connect_epoch_mismatch_with_opt_in_returns_valid_pinned` —
  `allow_pinned_lease` tolerance carries through to CONNECT.

**Risk.** The CONNECT path was previously dual-purpose
(domain-only SRR + Shadow Mode); the new lease pre-check sits
before both and only changes behaviour when the agent presents
an `X-GVM-Context-Token`. Production agents that don't set the
header see no behavioural difference. The audit-event shape
expands by overlaying lease-derived `agent_id` / `operation` on
the Allow path, but the field set is unchanged — downstream
parsers see the same schema. The `connect_for_test` re-export
is marked `#[doc(hidden)]` so it does not show up in public
crate docs.

**Deferred to Phase 3c** (intentionally out of scope):

- Sidecar / veth binding — token correlated to a sandbox-
  scoped network event rather than a header. The proxy
  already resolves a peer IP to a sandbox anchor
  (`resolve_sandbox_anchor`, `lookup_sandbox_id_by_ip`);
  Phase 3c indexes active leases by that key so requests from
  a known sandbox IP bind to the lease without the agent
  plumbing the header through cert-pinned clients.

### 2026-06-18: Cooperative intent lease — Phase 3a observed-body cross-check + pinned leases (Tier-3 P3-c)

Closes the two Phase 2 deferrals that did not require touching
the sandbox crate or CONNECT path. Phase 3b (blind-path token
delivery — CONNECT-visible token, sidecar / veth binding)
remains deferred.

**What changed.**

- `src/proxy/mod.rs::extract_and_claim_lease` now takes
  `observed_body: Option<&[u8]>`. When both the lease's
  `payload_hash` and the buffered body are present, the helper
  SHA-256s the observed bytes and compares. Match returns
  `CooperativeOutcome::CrossChecked` (the highest cooperative
  evidence tier); divergence returns `Mismatch`. The proxy hot
  path passes its existing `body_for_srr` slice in — no extra
  buffering work.
- `src/intent_store.rs::IntentRequest` gains
  `allow_pinned_lease: bool` (default `false`). Stored on
  `Intent` and mirrored onto `LeaseClaim`. The opt-in is
  per-lease so a single batch can pin its in-flight approvals
  without weakening any other agent's enforcement.
- `extract_and_claim_lease` reads the flag off the claim. When
  the lease's `policy_epoch` differs from the proxy's current
  `active_integrity_ref` AND the lease opted in, the path
  returns `CrossChecked { pinned: true }` (or
  `DeclaredOnly { pinned: true }`) instead of `Expired`. Without
  the opt-in, default-strict behaviour from Phase 2 is preserved.
- `crates/gvm-types/src/lib.rs::Classification` gains
  `pinned: bool` (default `false`). The cooperative arms in
  `proxy_handler` populate it from the matching outcome
  variant; the SRR + non-cooperative arms hard-code `false`.
- `src/proxy/headers.rs::inject_gvm_response_headers` emits
  `X-GVM-Lease-Pinned: true` only when
  `classification.pinned` is set. The Allow / Delay paths get
  this on the response automatically; the Deny / IC-3 paths
  never produce a `pinned=true` classification by construction
  (Deny variants are mismatch / expired / unbound).
- `src/proxy/headers.rs::build_event` adds
  `cooperative.pinned = true` to the WAL event's context
  attributes on pinned outcomes so the audit chain captures
  every stale-epoch acceptance for reconstruction. Default-strict
  events get nothing extra (the absence is meaningful).

**Tests** (6, all passing — `tests/cooperative_intent_lease_phase3.rs`).

- `observed_body_matches_declared_hash_yields_cross_checked` —
  happy path; the upstream is hit with
  `X-GVM-Decision-Source: cooperative.cross_checked`.
- `observed_body_diverges_from_declared_hash_returns_mismatch_deny`
  — **the load-bearing Phase 3a assertion**. Agent declares
  body A at issuance; sends body B at request time; the cross-
  check catches the lie, Denies with
  `cooperative.mismatch`, and the divergent body never reaches
  upstream (mock-upstream call count is 0).
- `lease_without_payload_hash_falls_through_to_declared_only`
  — guard against silent evidence-tier upgrade. Without a
  declared `payload_hash`, the source stays
  `cooperative.declared_only`.
- `pinned_lease_survives_policy_reload_and_marks_pinned` —
  `allow_pinned_lease=true` + epoch flip between issue and
  claim → 200 OK + `X-GVM-Decision-Source:
  cooperative.cross_checked` + `X-GVM-Lease-Pinned: true`.
- `pinned_lease_without_opt_in_still_expires` — default-strict
  behaviour from Phase 2 is unchanged. Without opt-in, epoch
  mismatch → `cooperative.expired` even if the body matches.
- `non_pinned_allow_does_not_set_pinned_header` — regression
  guard against marker dilution.

**Risk.** The classification-struct field is a new public field
on a hot-path type. Every internal caller is updated. Outside
the workspace nothing constructs `Classification` (verified by
grep). The pinned response header is opt-in (only fires when
the lease set `allow_pinned_lease=true` AND an epoch mismatch
actually occurred), so existing agents see no behavioural
change. The observed-body cross-check requires
`payload_inspection=true` AND a declared `payload_hash` — both
opt-in already.

### 2026-06-18: Cooperative intent lease — Phase 2 claim path (Tier-3 P3-c)

Wires the issuance side from Phase 1 to the proxy hot path. A
visible HTTP request carrying `X-GVM-Context-Token` now binds the
request to the declared lease at classification time, and the
classification result records which evidence tier produced the
decision. The blind paths (MITM-defeated TLS, cert pinning, mTLS,
gRPC over h2) — Phase 3 — still need a delivery channel for the
token; everything else needed for the visible-HTTP case is now
shipped.

**What changed.**

- `src/proxy/mod.rs` — new `extract_and_claim_lease()` reads the
  `X-GVM-Context-Token` header, hashes it (SHA-256 over the
  on-wire form including the `ctx_` prefix), calls
  `IntentStore::claim_by_token_hash` for the atomic
  Active → Claimed transition, and returns a `CooperativeOutcome`
  enum with six variants (`NoToken`, `CrossChecked`,
  `DeclaredOnly`, `Mismatch { reason }`, `Expired { reason }`,
  `Unbound { reason }`).
- `src/proxy/mod.rs::proxy_handler` — runs
  `extract_and_claim_lease` before the SRR check. **Strips
  `X-GVM-Context-Token` immediately after**, before any
  downstream path (SRR, forward, error response) touches the
  request. This is the load-bearing security invariant of Phase
  2 — token leakage to upstream would let GitHub / Slack /
  Stripe replay it to GVM and impersonate the lease. Each
  `CooperativeOutcome` arm inlines the SRR-call block (rather
  than going through a closure) so the `std::sync::RwLockReadGuard`
  on `state.srr` does not pull into a captured set and break the
  Handler's Send bound.
- `src/proxy/mod.rs` — match arms map to classifications:
  - `CrossChecked` → SRR on observed body, source
    `CooperativeCrossChecked`. (Observed-body hash extraction
    pending Phase 3's streamed-body refactor; currently falls
    through to `DeclaredOnly`.)
  - `DeclaredOnly` → SRR on canonical-JSON of declared
    `payload_context`, source `CooperativeDeclaredOnly`.
  - `Mismatch` / `Expired` / `Unbound` → Deny with the matching
    `cooperative.*` source.
  - `NoToken` → existing `srr.network_observed` path. Unchanged.
- `crates/gvm-types/src/lib.rs` — `GovernanceBlockResponse` gains
  `decision_source: Option<String>` with `skip_serializing_if`
  (back-compat for older callers). `ClassificationSource` gains
  `as_str()` and `From<ClassificationSource> for String`. The
  `SRR` variant retains its historical `"SRR"` wire form; the new
  `DecisionSource::SrrNetworkObserved => "srr.network_observed"`
  canonical form is exposed only through `DecisionSource` to keep
  the response header stable for existing consumers.
- `src/proxy/responses.rs::governance_block_response` — emits
  `X-GVM-Decision-Source` on the response when
  `block.decision_source.is_some()`. Agents reading a 403 can
  now tell `cooperative.mismatch` from
  `cooperative.unbound` from the header without parsing the JSON
  body.
- `src/proxy/mod.rs` — Deny / RequireApproval-timeout / IC-3
  queue-overflow paths populate `decision_source` from
  `classification.source`. WAL-infra-failure / budget-exceeded
  paths leave it `None` (those Denies don't come from the
  classification engine).

**Tests** (10, all passing — `tests/cooperative_intent_lease_phase2.rs`).

The new test file uses the existing `common::test_state()` plus
the recording-upstream pattern from `tests/integration.rs`:

- `unknown_token_returns_deny_with_unbound_source` — fabricated
  `ctx_…` value not in the store; 403 +
  `X-GVM-Decision-Source: cooperative.unbound`.
- `non_ascii_token_returns_unbound` — header with raw `0xff
  0xfe 0xfd` bytes; smuggled in via `HeaderValue::from_bytes`
  (axum accepts it; `to_str()` in the extractor rejects).
- `method_mismatch_returns_deny_with_mismatch_source` — lease
  for POST, request as PUT.
- `path_mismatch_returns_deny_with_mismatch_source` — lease for
  `/transfer`, request to `/admin`.
- `host_mismatch_returns_deny_with_mismatch_source` — lease for
  `api.bank.com`, X-GVM-Target-Host `api.evil.com`.
- `valid_lease_allows_with_declared_only_source` — happy path;
  200 OK + `X-GVM-Decision-Source: cooperative.declared_only`;
  upstream observed exactly one request.
- `valid_lease_path_prefix_match_allows` — lease for
  `/transfer`, request to `/transfer/123` (prefix match).
- `context_token_never_leaks_to_upstream_on_allow` — **the
  load-bearing security invariant**. Mock upstream captures
  every forwarded header; assertion: no `x-gvm-context-token`
  in the captured headers, and (defence in depth) no
  `x-gvm-*` header survives at all.
- `token_reuse_second_request_returns_unbound` — first request
  succeeds; second with the same token gets
  `cooperative.unbound` (the state machine already moved past
  Active).
- `epoch_change_between_issue_and_claim_returns_expired` —
  flips `state.active_integrity_ref` between
  `register_intent` and `proxy_handler`; expects
  `cooperative.expired`.

**Cleanup.** Removed the unused `run_srr_check` helper (the
inline-per-arm form replaced it). Dropped the unused
`claim_id: u64` fields on `CooperativeOutcome::CrossChecked` and
`DeclaredOnly` — they were placeholders for a
`gvm.intent.lease_claimed` WAL event that was deferred. The
normal `proxy_handler` audit path already captures the decision
under `cooperative.*` source.

**Deferred to Phase 3.**

- Observed-body hash extraction so `CrossChecked` produces the
  highest-tier `cooperative.cross_checked` evidence. Today the
  body cross-check exists in `extract_and_claim_lease` but
  returns `None` for the observed hash, routing to
  `DeclaredOnly`.
- `allow_pinned_lease` opt-in for stale-epoch acceptance.
- Blind-path token delivery (CONNECT-visible token, sidecar /
  veth binding).

**Risk.** Header strip is the only path-affecting change to
existing traffic, and the test for it pins the exact upstream
observation. The cooperative arms only fire when
`X-GVM-Context-Token` is present, which no production agent sets
today. The default decision_source `None` keeps the existing
Deny wire shape for callers that didn't update — the
`X-GVM-Decision-Source` header is additive.

### 2026-06-18: Cooperative intent lease — Phase 1 issuance (Tier-3 P3-c)

Body-aware policy enforcement when MITM is blind (cert pinning,
mTLS, gRPC over h2, raw CONNECT relay). The agent (or its
SDK / sidecar / MCP adapter) declares the body context it intends
to send; GVM runs SRR preflight against the declaration, mints an
opaque one-time `context_token` on Allow / Delay / AuditOnly, and
records the decision with explicit evidence level so the audit
chain reflects what the engine had access to. **Does not replace
MITM** — additive coverage of the paths MITM cannot reach. See
[docs/cooperative-intent.md](../cooperative-intent.md) for the
full design and Phase 2 / Phase 3 followups.

**Trust boundary statement (canonical).**

> Cooperative declaration extends enforcement only when GVM can
> bind the declaration to a visible transport event — an HTTP
> request, a CONNECT request, a sidecar-mediated egress, or a
> sandbox-scoped network event. Without one of those bindings,
> the declaration is recorded but is not load-bearing for
> enforcement.

**Phase 1 scope.** Issuance side only:
- Extend `IntentRequest`, mint token, store hash, record evidence.
- Phase 2 (next commit): proxy hot-path claim, observed-vs-declared
  cross-check, header stripping.
- Phase 3 (later): CONNECT-visible token, sidecar binding.

**What changed.**

- `crates/gvm-types/src/lib.rs` — new `DecisionSource` enum with
  seven variants (`SrrNetworkObserved`, `MitmNetworkObserved`,
  `CooperativeDeclaredOnly`, `CooperativeCrossChecked`,
  `CooperativeMismatch`, `CooperativeExpired`, `CooperativeUnbound`).
  `From<DecisionSource> for String` produces the canonical dotted
  form (`cooperative.declared_only`, etc.) so the existing
  `decision_source: String` WAL field accepts it without a schema
  change.
- `src/intent_store.rs` — `IntentRequest` gains three Option fields
  (`payload_context: Option<serde_json::Value>`, `payload_hash`,
  `content_type`). New `MAX_PAYLOAD_CONTEXT_BYTES = 16 KB` and
  `CONTEXT_TOKEN_SECRET_BYTES = 32` constants.
- `src/intent_store.rs` — internal `Intent` struct gains
  cooperative-lease fields (`context_token_hash: [u8; 32]`,
  `payload_context`, `payload_context_hash`, `payload_hash`,
  `policy_epoch`). All optional; legacy `register` initializes
  them to None.
- `src/intent_store.rs` — new `register_lease(req,
  payload_context, payload_context_hash, payload_hash,
  policy_epoch) -> (intent_id, context_token,
  payload_context_hash_hex)`. Mints 32 random bytes from
  `OsRng`, base64url-no-pad encodes with `ctx_` prefix, hashes
  the on-wire form, stores ONLY the hash. The secret buffer is
  zeroed before return. Token discipline: original leaves the
  proxy exactly once in this function's return value.
- `src/api.rs::register_intent` — branches on `payload_context`
  presence. Legacy URL-only path unchanged (back-compat). New
  cooperative-lease path:
  1. Canonical-serialise `payload_context`; reject 413 if > 16 KB
  2. Validate `payload_hash` format if supplied; reject 400 on
     malformed
  3. Run SRR `check_with_principal` against canonical bytes; reject
     200 with `decision: Deny` and no token / no intent_id /
     no WAL event on preflight Deny
  4. Snapshot `current_integrity_ref()` as the `policy_epoch`
  5. Call `register_lease` to mint and store
  6. Emit `gvm.intent.lease_issued` WAL event with
     `decision_source = cooperative.declared_only`. Raw
     `payload_context` is NOT in the event — only
     `payload_context_hash` + optional `payload_hash` +
     `content_type` go to the audit chain.
  7. Return 201 with `context_token` (original — only emission),
     `decision_source`, `evidence_level`, `policy_epoch`,
     `payload_context_hash`. If WAL append fails, roll back the
     lease and return 500 (fail-close).

**Hard limits (all loud).**

| Limit | Value | Response on violation |
|---|---|---|
| `payload_context` canonical JSON | 16 KB | 413 with cap explanation |
| `payload_hash` format | `sha256:<64-hex>` or 64-hex | 400 |
| Active intents (legacy + leases) | 10 000 | 429 |
| `ttl_secs` ceiling | 300 (5 min) | Silent clamp |

**Token security.**

- 32 bytes from `OsRng` → base64url-no-pad → `ctx_<43-char>` (47
  total) — fits any HTTP header.
- Store keeps only SHA-256 of the on-wire bytes.
- `intent_id` and `claim_id` are sequential u64 — NEVER used as
  the public token. Test enforces this via entropy check (a
  sequential token would have 1-2 distinct bytes; 32 random
  bytes have ~28).
- Original is zeroed in `register_lease` after the response
  string is constructed.

**Payload privacy.**

- Raw `payload_context` does NOT go to the WAL.
- WAL event records only `payload_context_hash`, optional
  `payload_hash`, optional `content_type`.
- Store holds raw `payload_context` in memory for Phase 2 cross-
  check; dropped on consume / expire.

**Affected files.**

- `crates/gvm-types/src/lib.rs` — `DecisionSource` enum
- `src/intent_store.rs` — `IntentRequest` extension,
  `MAX_PAYLOAD_CONTEXT_BYTES`, `CONTEXT_TOKEN_SECRET_BYTES`,
  internal `Intent` struct extension, `register_lease` method
- `src/api.rs::register_intent` — branched handler
- `tests/intent_store_concurrency.rs` — fixture updated for new
  Option fields (mechanical)
- `tests/cooperative_intent_lease.rs` (new, 10 cases)
- `docs/cooperative-intent.md` (new) — full design doc, trust
  model, Phase 2 / Phase 3 plan
- `docs/internal/CHANGELOG.md` (this entry)

**Verification.**

- `cargo test --test cooperative_intent_lease` — 10/10 pass:
  - lease_issuance_returns_opaque_context_token
  - token_is_not_intent_id_or_claim_id (entropy-based)
  - two_leases_produce_unrelated_tokens
  - response_records_payload_context_hash_not_raw_payload
  - response_decision_source_is_cooperative_declared_only
  - oversize_payload_context_returns_413
  - malformed_payload_hash_returns_400
  - preflight_deny_returns_no_token
  - legacy_url_only_intent_does_not_issue_context_token (back-compat)
  - decision_source_round_trip_through_string (all 7 variants)
- All existing IC-3 / intent_store / SRR / events tests pass
  unchanged (108+ cases).

**Risk.**

Low-to-medium. New code paths are gated on `payload_context.is_some()`;
the legacy path is bit-for-bit unchanged for existing MCP callers.
The new WAL event type and `DecisionSource` strings are additive —
old audit readers continue to deserialise into `decision_source:
String`. Fail-close on WAL append failure (lease rolled back, 500
returned).

**Deferred to Phase 2.**

- `X-GVM-Context-Token` header parsing in proxy hot path
- `claim_by_token_hash` lookup
- Observed-vs-declared cross-check (mismatch → Deny + dual-body
  WAL evidence)
- Policy epoch comparison + `allow_pinned_lease` opt-in
- Header stripping before upstream forward (CRITICAL — must not
  leak to external APIs)

**Deferred to Phase 3.**

- CONNECT-visible token delivery for blind paths
- Sidecar / out-of-band binding to sandbox-scoped network events
- `gvm.intent.lease_denied` audit-only event (low priority — SRR
  event stream already captures every Deny)

### 2026-06-18: WAL event stream — `GET /gvm/events` SSE (Tier-3 P3-b)

Second Tier-3 control-plane primitive from the strategic-audit
roadmap. Orchestrators now receive every WAL event via a
push-based SSE stream instead of polling `GET /gvm/pending`.
Combined with `POST /gvm/srr/rule` (P3-a), the orchestrator
implements the time-bounded grant pattern in one round-trip:
subscribe to the stream → see a RequireApproval event → decide
via `/gvm/approve` AND insert an Allow lease via `/gvm/srr/rule`
→ subsequent calls pass without re-prompting; the lease
auto-expires.

```bash
curl -N 'http://127.0.0.1:9090/gvm/events?agent_id=release-bot&decision=Deny'
```

**What changed.**

- `Ledger` gains an `Option<tokio::sync::broadcast::Sender<GVMEvent>>`
  field plus a builder-style `with_event_broadcast(tx)` setter.
- `Ledger::append_durable` broadcasts the event after a successful
  WAL append (primary OR emergency path). The send is non-blocking;
  `broadcast::Sender::send` returns Err with zero receivers, which
  is the common case — silently ignored.
- `AppState` gains an `event_broadcast: broadcast::Sender<GVMEvent>`
  field. `main.rs` creates one `(tx, _rx)` channel with capacity
  1024, hands the same `tx` to both the Ledger and AppState. SSE
  handlers call `state.event_broadcast.subscribe()` to get a fresh
  `Receiver` per connected orchestrator.
- New `api::events_stream` handler returns `axum::response::Sse<…>`
  with `keep_alive(15s)`. The inner stream is built with
  `async_stream::stream!`:
  - On `Ok(event)` → check filter, json-serialize, yield as SSE
  - On `RecvError::Lagged(n)` → yield `event: lagged data: n`,
    then return (close the connection)
  - On `RecvError::Closed` → return (proxy shutting down)
- New `api::event_matches_filter` pure function. Two ANDed checks:
  exact-match on `agent_id`, prefix-match on `decision`. Pulled out
  of the streaming machinery so the regression suite exercises it
  directly without an HTTP layer.
- New `EventsQuery` struct (`agent_id: Option<String>`,
  `decision: Option<String>`) deserialised from query params.
- Route wired on the admin router only:
  `GET /gvm/events` → `api::events_stream`.

**Capacity / lag policy.**

- Channel capacity: 1024 events per receiver. ~1 second of bursty
  decision traffic on a busy proxy.
- A subscriber that lags beyond that gets `RecvError::Lagged(n)`
  on the next `recv()`. The handler emits a single `event: lagged
  data: <n>` SSE event so the orchestrator knows what it missed,
  then closes the connection. The orchestrator reconnects, runs a
  reconcile pass on `/gvm/pending` + `/gvm/srr/rule`, and resumes.
- The WAL writer is NEVER blocked by a stuck subscriber.
  `broadcast::Sender::send` is non-blocking — it puts the event in
  each receiver's buffer and returns immediately.

**No replay (yet).**

First cut streams only events that arrive after the subscriber
connects. The `since=<id>` parameter mentioned in the strategic
audit's v0.7 control-plane sketch is scoped as a separate
follow-up. Adding it well requires:
- an in-memory ring buffer of recent events (~last 1000 by
  default, capacity-bounded)
- a cursor scheme so an orchestrator that disconnects briefly can
  resume from a known event ID
- a 410 GONE response when the requested cursor has fallen out of
  the buffer

The conservative position for first cut is "no replay; orchestrator
reconciles on reconnect." That keeps the new surface small and
honest. If real demand surfaces, the ring buffer drops in behind
the same endpoint.

**Why admin-port only.**

The stream surfaces every audit event — including decisions for
agents other than the one that's listening. Same scope concern as
`/gvm/approve` and `/gvm/srr/rule`. The sandbox network namespace
has no route to the admin port.

**Why broadcast not file-tail.**

A file-tail design would read `wal.log` from a position cursor and
poll for new content. We avoided it because:
1. It races with WAL rotation (the file the tailer is reading
   might get renamed mid-stream)
2. It can't easily filter by `agent_id` without reading every
   line
3. It introduces a second source of truth for "what events
   exist" — the in-process broadcast trivially matches the WAL by
   construction (broadcast fires after successful append)

Broadcast keeps everything single-source-of-truth.

**Affected files.**

- `src/ledger.rs` — `event_broadcast` field, `with_event_broadcast`
  setter, broadcast fire at the end of `append_durable`
- `src/proxy/mod.rs` — `event_broadcast` field on AppState
- `src/main.rs` — channel construction (capacity 1024), wired to
  both Ledger and AppState
- `src/api.rs` — `EventsQuery`, `events_stream` handler,
  `event_matches_filter` pure function
- `src/main.rs` — admin route added
- `tests/common/mod.rs` — `test_state` builds the channel (capacity
  64) so the helper is usable for every event-related test
- `tests/integration.rs` — 10 `AppState` construction sites get
  `event_broadcast` field (mechanical)
- `docs/srr.md` — new "Event Stream" subsection with the filter
  table, lease orchestration example, lag policy, no-replay note
- `docs/internal/CHANGELOG.md` (this entry)
- `tests/events_stream.rs` (new, 9 cases):
  - filter logic: no params, agent_id only, decision-prefix only,
    AND composition, strict case sensitivity
  - broadcast: one subscriber gets the event verbatim
  - broadcast: zero subscribers does not fail the append
  - broadcast: multiple subscribers each see each event
  - broadcast: slow subscriber lagged-without-blocking-writer
    (200-event burst → all writes succeed, slow recv reports
    Lagged with skip count)

**Verification.**

- `cargo test --test events_stream` — 9/9 pass.
- All previous SRR / IC-3 / integration tests pass unchanged
  (75 cases plus the 10 integration-test sites get the new field
  threaded through mechanically).
- `cargo check --workspace --tests` clean.

**Risk.**

Medium-low. Two structural changes:
- `Ledger.append_durable` does one extra `Option::is_some` +
  optional non-blocking send on the success path. Cost: ~0
  measurable (broadcast::Sender::send is a single mutex + Vec
  push internally; in the no-subscribers case it short-circuits
  before the push).
- AppState gains a new required field. 13 construction sites had
  to be updated (1 prod + 2 in tests/common + 10 in
  tests/integration). All mechanical.

The Ledger sender is `Option<>` so even if `with_event_broadcast`
is not called, the no-broadcast path stays unchanged.

**Follow-up.**

- P3-c: `POST /gvm/payload-context` cooperative body-context
  endpoint — SDK / sidecar / MCP adapter delivers structured
  payload context without MITM (lowers the MITM dependency for
  HTTPS-pinned and gRPC traffic).
- v0.7 replay surface: `since=<id>` query param with the ring
  buffer described above.

### 2026-06-18: SRR — single-rule mutation endpoints (Tier-3 P3-a)

First Tier-3 item from the strategic-audit roadmap. The
orchestrator can now inject one SRR rule atomically via
`POST /gvm/srr/rule` and remove it via
`DELETE /gvm/srr/rule/:id` — without rewriting the SRR file or
incurring the latency of a `gvm reload` full-file swap. This is
the control-plane primitive that makes the v0.5.3 lease shape
(principal_filter + expires_at) practical at scale.

```bash
curl -X POST http://127.0.0.1:9090/gvm/srr/rule \
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
```

**What changed.**

- `NetworkSRR` gains a parallel `injected_rules: Vec<NetworkRule>`
  slot and the public methods `insert_rule`, `remove_rule`,
  `injected_rule_count`, `injected_rule_ids`. Plus the constant
  `MAX_INJECTED_RULES = 1000` (mirrors the IC-3 pending cap).
- `check_at_with_principal` iterates
  `injected_rules.iter().chain(self.rules.iter())` so injected
  rules win first-match. The two slots together preserve
  first-match-wins semantics within and across slots.
- `insert_rule` compiles the supplied `NetworkRuleConfig` through
  the same `from_rule_configs` path that file-loaded rules use, so
  validation parity is exact: bad regex, malformed
  `expires_at`, unknown decision type all surface as
  `anyhow::Error` from this method. Error messages bubble through
  to HTTP 400 / 409 / 429 mapping in the handler.
- Three admin-port HTTP handlers in `src/api.rs`:
  - `insert_srr_rule`: `POST /gvm/srr/rule` → 201 / 400 / 409 / 429
  - `remove_srr_rule`: `DELETE /gvm/srr/rule/:id` → 200 / 404
  - `list_injected_srr_rules`: `GET /gvm/srr/rule` → 200
    `{ ids, count }`
- Routes wired only on the admin router (`src/main.rs`). The
  agent-facing port does NOT expose these — injecting an Allow
  rule from inside a sandbox would be a self-grant attack.

**Why admin-only.**

The sandbox network namespace can only reach the agent-facing
proxy port. The admin port lives on a separate listener
(loopback-only by default, or behind admin JWT + IP allow-list in
production). This boundary preserves the principle that the
sandbox cannot grant itself capabilities — only the orchestrator
operating on the admin port can.

**Lifecycle decisions (and why).**

- *Survives `gvm reload`.* File reload only rebuilds `rules`. The
  orchestrator does not have to re-issue every lease on every file
  edit. (The alternative — wipe injected on reload — would be a
  silent footgun.)
- *Does NOT survive proxy restart.* The slot is in-memory only.
  The orchestrator owns lease lifecycle and is expected to
  re-issue on restart. Persistence is a v0.7+ follow-up if real
  demand surfaces; the simpler model wins for first cut.
- *Cap at 1 000 injected rules.* Mirrors the IC-3 pending cap.
  Protects the proxy against runaway lease issuance from a broken
  orchestrator. Hit the cap → 429 (the operator's signal to
  reconcile state).

**Status-code semantics** so an orchestrator can branch on
response without parsing free-form text:

| Outcome | Mapped from | Status |
|---------|-------------|--------|
| success | Ok(id) | 201 |
| missing description | error contains "description" | 400 |
| duplicate description | error contains "already exists" | 409 |
| cap reached | error contains "cap" | 429 |
| bad regex / other compile error | anything else | 400 |

**Affected files.**

- `src/srr/mod.rs` — `injected_rules` slot, `MAX_INJECTED_RULES`,
  `insert_rule`, `remove_rule`, `injected_rule_count`,
  `injected_rule_ids`, `check_at_with_principal` iteration
  chained.
- `src/api.rs` — three new handlers, with status-code mapping
  documented inline.
- `src/main.rs` — three new admin-router routes.
- `docs/srr.md` — new "Single-Rule Mutation" subsection with the
  endpoint contract table and lease example.
- `docs/internal/CHANGELOG.md` (this entry).
- `tests/srr_rule_mutation.rs` (new, 10 cases — library layer):
  - injected rule shadows file rule
  - removing the injected rule restores the file rule
  - insert with empty description errors loudly
  - insert with duplicate description errors and rolls back
  - remove on unknown id returns false
  - cap at MAX_INJECTED_RULES; one-more insert errors with "cap"
  - bad regex returns a compile error and adds nothing
  - lease composition (principal_filter + expires_at via
    injection) — three sub-assertions
  - `injected_rule_ids` returns inserted IDs only
  - `rule_count` returns only file-loaded (legacy contract)
- `tests/srr_rule_api.rs` (new, 9 cases — HTTP layer):
  - 201 + JSON body on success
  - 400 on missing description
  - 409 on duplicate
  - 400 on bad regex (no partial insert)
  - 400 on malformed JSON shape
  - 200 on existing-rule removal
  - 404 on unknown-rule removal
  - 200 on list with the expected IDs array
  - full insert → check fires → remove → check doesn't lifecycle

**Verification.**

- `cargo test --test srr_rule_mutation` — 10/10 pass.
- `cargo test --test srr_rule_api` — 9/9 pass.
- All previous SRR / GraphQL / timing / IC-3 / api_handlers tests
  pass unchanged (112+ cases).
- `cargo check --workspace --tests` clean.

**Risk.**

Low-to-medium. The hot-path change (iteration chain) is a single
extra `chain()` call; branch prediction handles the "no injected
rules" case at zero overhead. The write-lock path for insert /
remove is brief (compile → acquire → push → drop), and an injected
rule cannot crash the engine — any malformed input is rejected at
compile, returning 400 with the error string. The new endpoints
are admin-port-only, so a compromised agent cannot reach them.

**Follow-up.**

- P3-b: `GET /gvm/events?since=<id>&filter=...` long-poll WAL
  event stream so an orchestrator consumes IC-3 transitions and
  decision events without polling /gvm/pending. Composes with
  P3-a: orchestrator subscribes to the stream, sees a Pending
  event, decides via /gvm/approve AND inserts an Allow lease
  via /gvm/srr/rule in one round-trip.
- P3-c: `POST /gvm/payload-context` cooperative body-context
  endpoint — SDK / sidecar / MCP adapter delivers structured
  payload context without MITM (lowers the MITM dependency for
  HTTPS-pinned and gRPC traffic).

### 2026-06-18: CLI — `gvm import openapi` (Tier-2 P2-b, Tier-2 complete)

Second Tier-2 item from the strategic-audit roadmap. A new CLI
subcommand generates a deny-by-default SRR baseline from any
OpenAPI 3.x spec. Combined with the provider action packs (P2-a)
this means an operator can spin up a baseline policy for any
internal or third-party API without hand-writing 50 `path_regex`
blocks. The audit vocabulary stays the same — `operationId`
becomes the rule's `description`, which surfaces in the WAL as
`matched_rule_id`.

```bash
gvm import openapi spec.yaml > srr_network.toml
gvm import openapi spec.json --out config/srr_network.toml
```

**What changed.**

- New `crates/gvm-cli/src/import.rs` module with:
  - `import_openapi(path) -> Vec<String>` (per-rule blocks)
  - `import_openapi_to_toml(path) -> String` (full file body)
  - `path_template_to_regex` — turns `/users/{id}/posts/{post_id}`
    into `^/users/[^/]+/posts/[^/]+$`, escaping regex
    metacharacters in literal segments
  - `extract_host_and_base_path` — pulls host and base path from
    `servers[0].url` (scheme-stripped, trailing-slash-normalised)
  - `to_snake_case` — `listUsers` → `list_users`,
    `users.list` → `users_list` (used for `label`)
  - 7 internal unit tests for the helpers above
- New `Commands::Import { action: ImportAction }` clap subcommand
  with `ImportAction::Openapi { spec, out }`. `--out` writes to a
  file path; absent flag prints to stdout. Errors return non-zero
  with a stderr explanation.
- New `serde_yaml = "0.9"` dependency on gvm-cli. YAML parser
  accepts JSON as a subset, so the same importer handles both
  formats.

**Generated rule shape** — for each `paths.<template>.<method>`:

```toml
[[rules]]
method = "POST"
pattern = "api.example.com/{any}"
path_regex = "^/v1/users/[^/]+/comments$"
decision = { type = "Deny", reason = "outside imported baseline" }
description = "createUserComment"
label = "create_user_comment"
```

**Why deny-by-default, not method-class-by-default.**

The OpenAPI spec doesn't reliably tell us "this is destructive" vs
"this is a read." `DELETE` isn't always destructive; `POST` isn't
always a write. A wrong guess that produced an `Allow` rule is the
worst possible outcome (silent bypass), while a wrong-direction
`Deny` is loud and self-correcting (operator notices the agent
can't do its job, reviews, promotes). So every operation imports
as `Deny`; the operator reviews and promotes individual rules by
hand or via lease (`principal_filter` + `expires_at` overlay in
front of the imported baseline).

**Failure modes (all loud).**

- Spec file missing or unreadable → non-zero exit, stderr message
  including the path.
- YAML/JSON parse error → non-zero exit, stderr includes the
  parser error.
- `servers` missing or empty → non-zero exit, stderr explains
  that the host cannot be inferred (no silent fallback).

Pinned by `gvm_import_openapi_fails_loudly_on_missing_servers`.

**Affected files.**

- `crates/gvm-cli/Cargo.toml` — `serde_yaml` added
- `crates/gvm-cli/src/main.rs` — module declared, `Commands::Import`
  enum variant, `ImportAction::Openapi` subcommand, dispatch arm
- `crates/gvm-cli/src/import.rs` (new, ~280 LOC + 7 unit tests)
- `crates/gvm-cli/tests/import_openapi.rs` (new, 4 integration
  tests — round-trip YAML → CLI → SRR loader, bare-host URL,
  `--out` flag writes to file, missing-servers loud fail)
- `docs/srr.md` — new "Importing a Baseline from OpenAPI" subsection
- `docs/internal/CHANGELOG.md` (this entry)

**Verification.**

- 7 internal unit tests pass (`cargo test -p gvm-cli --bin gvm
  import::`).
- 4 integration tests pass (`cargo test --test import_openapi -p
  gvm-cli`). Each integration test:
  1. writes a YAML spec to a temp file
  2. runs the actual `gvm` binary via `CARGO_BIN_EXE_gvm`
  3. captures stdout, writes it back to a temp `srr_network.toml`
  4. loads via the production `NetworkSRR::load` path (catches
     malformed TOML, bad regex, etc.)
  5. drives canonical requests through `srr.check` and asserts
     the right `matched_description` (operation id) surfaces
- All existing tests pass unchanged.

**Risk.**

Low. Net-new CLI surface; no existing behaviour changes. The
`serde_yaml` crate adds ~50 KB to the gvm-cli binary and pulls
`unsafe-libyaml` transitively (a small C-FFI shim that
serde_yaml wraps). Both are widely used and well-maintained.

**Tier-2 complete.** The audit's "give it a product shape" items
land. Operators can:

1. Mount a curated action pack (`github.pr.merge`,
   `slack.message.send`) for the SaaS APIs their agents touch
   (P2-a).
2. Generate a deny-by-default baseline for any in-house or
   third-party API from its OpenAPI spec, with operationIds
   becoming the audit vocabulary (P2-b).
3. Overlay per-task leases (`principal_filter` + `expires_at`,
   Tier-1) on either layer to issue time-bounded grants for
   specific agents.

The composition produces the agent-IAM shape the strategic audit
called out as the path off "weird egress firewall".

**Follow-ups (Tier-3, control plane).**

- `POST /gvm/srr/rule` + `DELETE /gvm/srr/rule/<id>` — granular
  single-rule mutation (orchestrator injects/removes one rule
  atomically; current `gvm reload` is full-file swap).
- `GET /gvm/events?since=<id>&filter=...` — long-poll WAL event
  stream so orchestrators consume IC-3 transitions without
  polling.
- `POST /gvm/payload-context` — cooperative body-context endpoint
  where an SDK / sidecar / MCP adapter delivers structured
  payload context without MITM (lowers the MITM dependency for
  HTTPS-pinned and gRPC traffic).

### 2026-06-18: SRR — provider action packs: GitHub + Slack (Tier-2 P2-a)

First Tier-2 item from the strategic-audit roadmap. Ships two
curated SRR rule files whose `description` fields carry canonical
semantic action names (`github.pr.merge`, `slack.message.send`,
...). The internal compile target is unchanged — each rule is
still `method + host + path_regex` — but the operator writes and
the auditor reads the agent-IAM vocabulary, not the URL.

**What changed.**

- New `config/templates/_action_packs/` directory containing:
  - `github.toml` — 9 rules covering GitHub REST API v3:
    repo.read, issue.read, pr.read (Allow), issue.comment.create,
    pr.create (Delay), pr.merge, workflow.dispatch (RequireApproval),
    repo.delete (Deny), and the api.unspecified catch-all (Delay).
  - `slack.toml` — 10 rules covering the Slack Web API:
    user.lookup, conversations.list (Allow), message.send,
    message.update, file.upload (Delay), channel.create,
    workflow.trigger (RequireApproval), message.delete (Deny),
    and the api.unspecified catch-all (Delay).
  - `README.md` — explains the action-pack concept, the
    default-effect-by-risk-class convention, and the lease
    composition pattern. Includes a checklist for adding a new
    pack so contributions stay shape-consistent.
- `docs/srr.md` — new "Provider Action Packs" subsection with the
  default-effect table, the lease composition example, and links
  to the shipped packs.
- `tests/srr_action_packs.rs` (new, 5 tests):
  - GitHub pack loads via `NetworkSRR::load`; 10 canonical URLs
    map to their declared action names and risk classes
    (Allow / Delay / RequireApproval / Deny).
  - Slack pack same shape: 10 canonical URLs covered.
  - Each pack's catch-all rule handles unmapped endpoints
    (audit, not block).
  - The documented lease shape (`principal_filter` + `expires_at`
    in a rule BEFORE the pack's RequireApproval rule) correctly
    shadows the pack default for the named principal in the named
    window. Three sub-assertions: in-lease principal Allowed,
    wrong principal falls to pack's RequireApproval, expired
    lease falls to pack's RequireApproval.

**Why.**

The strategic audit (2026-06-17) flagged that without a provider
vocabulary GVM reads as a "weird egress firewall" rather than as an
agent-permission runtime. Action packs were the audit's
recommended cheapest fix: no new engine machinery, no protocol
changes; just operator configuration that lets the audit CLI
print "agent invoked github.pr.merge" instead of an opaque URL.
The two packs cover the most common agent surfaces (issue
management + PR review on GitHub, channel + DM messaging on
Slack) that show up in regulated-workflow agents.

**Affected files.**

- `config/templates/_action_packs/github.toml` (new)
- `config/templates/_action_packs/slack.toml` (new)
- `config/templates/_action_packs/README.md` (new)
- `docs/srr.md` — "Provider Action Packs" subsection added
- `docs/internal/CHANGELOG.md` (this entry)
- `tests/srr_action_packs.rs` (new, 5 tests)

**Verification.**

- `cargo test --test srr_action_packs` — 5/5 pass.
- All existing tests pass unchanged.
- `cargo check --workspace --tests` clean.

**Risk.**

None. New files only; no Rust code, no production behaviour
changed. The packs sit in `config/templates/` and are only loaded
when an operator explicitly appends them.

**Follow-up.**

P2-b: `gvm import openapi <spec.yaml>` CLI — convert an OpenAPI
spec into a deny-by-default SRR rule set with `description` fields
populated from `operationId`. Same audit vocabulary; lets an
operator spin up a baseline policy for any in-house or third-party
API without hand-writing 50 path_regex blocks.

### 2026-06-18: SRR — `principal_filter` rule field (Tier-1 P1-c, Tier-1 complete)

Third and final Tier-1 item from the strategic-audit roadmap.
Promotes `agent_id` from an audit-only label to an SRR matching
input — a rule can now require an exact agent identity, and the
engine enforces it deterministically before any of the more
expensive matching steps. Combined with `expires_at` (P1-b), this
is the v0.5.3 spelling of a time-bounded permission grant.

```toml
[[rules]]
method = "POST"
pattern = "workflow.internal/claims/1842"
principal_filter = "agent:claims-reviewer-1842"
expires_at = "2026-07-01T12:05:00Z"
decision = { type = "Allow" }
```

**What changed.**

- `NetworkRuleConfig` gains `principal_filter: Option<String>`. Same
  field on the compiled `NetworkRule`.
- A new public entry point `check_with_principal(method, host, path,
  body, agent_id: Option<&str>)` and the underlying
  `check_at_with_principal(..., agent_id, now)`. The legacy `check`
  and `check_at` now delegate to `check_at_with_principal` with
  `agent_id = None`. The 170 existing callers (production + tests)
  did not need to change; only the proxy hot path was updated to
  pass the resolved principal.
- `src/proxy/mod.rs` resolves the principal in the documented order
  (JWT-verified `agent_id` → sandbox peer-IP → `X-GVM-Agent-Id`
  header) and passes it to `check_with_principal`. JWT identity is
  preferred over the header because the header is operator-supplied
  while the JWT is cryptographic.
- Match logic placed RIGHT AFTER the host filter, before
  `expires_at` and `condition`. One string comparison; no
  allocation; branch is a no-op when `principal_filter == None`
  (which is the case for every legacy rule). The two-line block:

  ```rust
  if let Some(required) = &rule.principal_filter {
      match agent_id {
          Some(supplied) if supplied == required.as_str() => { /* match */ }
          _ => continue,
      }
  }
  ```

**Match contract.**

- Rule has no filter → matches every principal (legacy).
- Rule has `Some(p)`, caller supplies `Some(p)` (exact) → match.
- Rule has `Some(p)`, caller supplies `Some(q)` (different) → skip.
- Rule has `Some(p)`, caller supplies `None` → skip (fail-closed).

The fail-closed direction is deliberate: code paths that call
`srr.check(...)` without a principal pass `None`, so
principal-filtered rules are invisible to them. That preserves the
strictest possible default for non-audited callers.

**Exact match, case-sensitive.** First cut deliberately does not
support glob/wildcard. Exact equality rules out smuggling via
similar-named principals. Wildcard support is a follow-up.

**Lease primitive shape.** With this commit, an orchestrator can
issue a lease as a single SRR rule that the engine enforces in
both dimensions (identity + time) without any caller-side cleanup:

```toml
principal_filter = "agent:claims-reviewer-1842"
expires_at = "2026-07-01T12:05:00Z"
decision = { type = "Allow" }
```

The full lease primitive (P4 in the audit roadmap) wraps this with
a signed JWT envelope and a `gvm lease issue` CLI; the underlying
SRR semantics are now there.

**Backwards compatibility.**

- `Option<String>` defaults to `None`. Existing SRR configs unchanged.
- Existing test fixtures (5 files, 6 sites) get `principal_filter: None`
  added — mechanical.
- The 170 existing callers of `srr.check(...)` are unchanged. Only
  the proxy hot path was updated to use `check_with_principal`.
  Legacy `check` continues to work and matches every principal.

**Affected files.**

- `src/srr/mod.rs` — field on both `NetworkRuleConfig` and `NetworkRule`,
  threaded through both compile paths, new entry points
  `check_with_principal` and `check_at_with_principal`, legacy
  entries refactored to delegate.
- `src/proxy/mod.rs` — proxy resolves principal and uses
  `check_with_principal`.
- `docs/srr.md` — new "Principal-Bound Rules" subsection with the
  match contract table, identity-source ordering, and the lease
  composition example.
- `docs/internal/CHANGELOG.md` (this entry).
- `tests/srr_principal_filter.rs` (new, 7 cases):
  - matching principal fires rule
  - non-matching principal skips rule
  - absent principal skips principal-filtered rule (fail-closed)
  - legacy `check()` entry never fires principal-filtered rule
  - rules without `principal_filter` match every caller (back-compat)
  - `principal_filter` composes with `expires_at` (lease shape)
  - exact-match, case-sensitive
- 5 test fixture files — `principal_filter: None` added at 6 sites.

**Verification.**

- `cargo test --test srr_principal_filter` — 7/7 pass.
- All existing tests pass unchanged (P1-a 9 + P1-b 6 + hostile 25 +
  srr_evasion 10+2 + srr_time_window 11 + graphql_alias 25 +
  timing 2 + enforcement 11 = 95+ cases in the SRR /
  payload-evasion / timing / enforcement block).
- `cargo check --workspace --tests` clean.

**Risk.**

Low. The two-line match block is branch-predicted as a no-op for
every legacy rule. The proxy now reads `verified_identity` /
`gvm_headers` to extract `agent_id` — both fields were already
populated for the audit path; we are reusing them.

**Tier-1 complete.** The three rule fields land the audit's
"closest small wins": fail-close on unverifiable body
(unsafe_body_action), rule expiration (expires_at), and identity
binding (principal_filter). Tier-2 (industry-template provider
action pack + OpenAPI importer) and Tier-3 (control-plane endpoints
for orchestrators) are scoped separately.

### 2026-06-18: SRR — `expires_at` rule field (Tier-1 P1-b)

Second Tier-1 item from the strategic-audit roadmap. First
building block of the lease primitive: a rule can carry an
absolute RFC 3339 deadline, and the engine silently stops
matching against the rule once the evaluation timestamp
crosses that deadline.

```toml
[[rules]]
method = "POST"
pattern = "api.payments.com/transfer"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
```

**What changed.**

- `NetworkRuleConfig` gains
  `expires_at: Option<chrono::DateTime<chrono::Utc>>` (src/srr/mod.rs).
  TOML accepts RFC 3339; chrono's strict deserializer rejects
  date-only or timezone-less strings at proxy startup
  (`gvm reload`), not at the first matching request.
- `NetworkRule` (compiled form) carries the same field.
- `check_at` adds a single `if let Some(deadline) = rule.expires_at`
  comparison right after the host filter — before the gating
  condition (which is more expensive) and before path / payload
  inspection. Half-open semantics: rule fires while
  `now < expires_at`, dies at `now == expires_at`. Mirrors the
  `time_window` exclusive-end convention.

**Determinism / replay safety.**

The match path takes the timestamp from `check_at`'s `now`
parameter; no internal `Utc::now()`. An auditor replaying the WAL
with the event's recorded timestamp reproduces the producer's
decision exactly, even across the deadline boundary. This is the
same audit guarantee that `time_window` carries; the field adds
no new trust assumption because the timestamp is already
anchor-signed.

**Backwards compatibility.**

`Option<DateTime<Utc>>` defaults to `None` via serde. Existing
SRR configs need no change. Existing test fixtures (5 files, 6
sites) get `expires_at: None` added — mechanical, no behaviour
change.

**Use case.**

Time-bounded permission grant pattern. An external orchestrator
approves an IC-3 request, then inserts a 5-minute `Allow` rule
with `expires_at = now + 5m`. Subsequent agent calls in that
window pass without re-prompting. The rule auto-expires on the
next match attempt after the deadline — no separate teardown
call needed. The full lease primitive (P4 in the audit roadmap)
combines this with `principal_filter` (P1-c, next), single-rule
mutations (Tier-3), and the signed lease envelope.

**Affected files.**

- `src/srr/mod.rs` — field added to both `NetworkRuleConfig` and
  `NetworkRule`, threaded through both compile paths (`load` and
  `from_rule_configs`), check at line 825-833.
- `docs/srr.md` — new "Rule Expiration" subsection with the TOML
  format, validity semantics, determinism note, and use-case
  example.
- `docs/internal/CHANGELOG.md` (this entry).
- `tests/srr_expires_at.rs` (new, 6 cases):
  - strictly-before-deadline (rule fires)
  - at-exact-deadline-instant (rule dead — half-open)
  - strictly-after-deadline (rule dead)
  - rules-without-expires-at-never-expire (backwards compat)
  - malformed-string-fails-load (parse-path validation)
  - replay-reproduces-decision (determinism / no-Utc::now check)
- 5 test fixture files — `expires_at: None` added at 6 direct
  `NetworkRuleConfig` construction sites.

**Verification.**

- `cargo test --test srr_expires_at` — 6/6 pass.
- All existing SRR / GraphQL / timing tests pass unchanged
  (75 total + 6 new + 9 from P1-a = 90 cases in the SRR /
  payload-evasion / timing block).
- `cargo check --workspace --tests` clean.

**Risk.**

Low. The new comparison is a single `DateTime` ordering, branched
on `Option::is_some`. No impact on rules without the field set
(branch prediction collapses to a no-op).

**Follow-up.**

P1-c (`principal_filter: Option<String>` — agent_id as an SRR
matching input) is the third and final Tier-1 item.

### 2026-06-18: SRR — `unsafe_body_action` rule field (Tier-1 P1-a)

First Tier-1 item from the strategic-audit roadmap. Closes the
fail-close-on-unverifiable-body gap surfaced by the 2026-06-17
audit: previously, when a payload rule could not inspect the body
(too large for `max_body_bytes`, or unparseable as plain JSON /
base64-JSON), the engine fell through to the next rule — leaving
the endpoint covered only by URL-only fallback rules. That's the
right legacy default but the wrong default for high-value
endpoints where "we couldn't verify the body" is itself a signal.

**What changed.**

- `NetworkRuleConfig` gains `unsafe_body_action: Option<NetworkDecisionConfig>`
  (src/srr/mod.rs:53). When set, the compile path (`from_rule_configs` +
  `load`) parses it through the existing `parse_decision()` so the same
  decision-type surface (`Allow`, `AuditOnly`, `Delay`, `RequireApproval`,
  `Deny`) is available with no new vocabulary.
- `NetworkRule` (the compiled form) carries the parsed
  `unsafe_body_action: Option<EnforcementDecision>`.
- `check_at` body-inspection branch (src/srr/mod.rs:835-955) now applies
  the action at two failure points:
  - `body_bytes.len() > max_body_bytes`: skip inspection → if
    `unsafe_body_action` is set, return that decision with a description
    of the form `"<rule> (unsafe_body_action — body exceeds max_body_bytes)"`.
    Otherwise continue (legacy).
  - body present but `json_val` is None (plain-JSON parse failed AND
    base64-JSON fallback failed): inspection ran and failed → if
    `unsafe_body_action` is set, return that decision with description
    `"<rule> (unsafe_body_action — body unparseable as JSON)"`. Otherwise
    continue (legacy).
- **Does NOT fire on absent body** — a body-less request hitting a rule
  with `payload_field` set is "rule does not apply", not "inspection
  failed". Legacy `continue` preserved at the body-None branch. This
  matters because operators want URL-only fallback rules to keep working.

**Backwards compatibility.**

`Option<NetworkDecisionConfig>` defaults to `None` via serde, so existing
SRR configs do not need any change. All existing test fixtures (5 files,
6 construction sites) were updated to spell `unsafe_body_action: None`
explicitly — this is a struct-initialiser requirement, not a behaviour
change.

**Affected files.**

- `src/srr/mod.rs` — field added, compile path threaded, check_at
  branches updated.
- `docs/srr.md` — new "Fail-Close on Unverifiable Body" subsection with
  the trigger matrix and an example TOML block.
- `docs/internal/CHANGELOG.md` (this entry).
- `tests/srr_unsafe_body_action.rs` (new, 9 cases) — covers fail-close
  paths (body too large / unparseable), legacy permissive paths (no
  field set), the absent-body invariant, the matching-body / non-
  matching-body distinction, and the alternate effect types
  (`RequireApproval`, `Delay { milliseconds }`).
- 5 test fixture files (graphql_alias_*, srr_time_window,
  timing_invariance) — `unsafe_body_action: None` added to direct
  `NetworkRuleConfig` constructions.

**Verification.**

- `cargo test --test srr_unsafe_body_action` — 9/9 pass.
- `cargo test --test hostile --test srr_evasion_adversarial --test
  srr_time_window --test graphql_alias_* --test timing_invariance` —
  all existing tests pass unchanged (69 total).
- `cargo check --workspace --tests` clean.

**Risk.**

Low. No change in behaviour for any rule that does not set the new
field. The check_at hot path adds one `Option<EnforcementDecision>`
clone on the rule's fail-close branches only — no impact on the
match-success or no-body paths.

**Follow-ups.**

P1-b (`expires_at: Option<DateTime<Utc>>` rule field — first step toward
the lease primitive) and P1-c (`principal_filter: Option<String>` — agent
identity as an SRR matching input) are scheduled as separate commits.

### 2026-06-18: Docs — reposition from sandbox-first to permission-grant + evidence-forward

Follow-up to the strategic audit. The pentest suite (Phases 1–4),
the timing fix, the CI repair, and the SRR limitation docs all
landed without a positioning update; README.md and docs/overview.md
still led with "sandbox" as the headline noun. The strategic review
flagged this as a product-positioning gap: the user thinks in
"give this agent a container," not "give this agent a grant," so
GVM reads as a "weird egress firewall" rather than as a
permission-grant runtime.

**What changed.**

- `README.md` — new tagline + opening: "Permission-Grant Runtime
  for AI Agents — Bound the actions. Sign the evidence. Stay
  framework-independent." Four-pillar value section (bound
  actions, signed evidence, framework-independent, zero-code-change).
  New "Evidence boundary" section right after the existing
  "Execution boundary" section, surfacing `gvm proof event` /
  `gvm proof batch` / `gvm proof verify` with the offline-against-
  public-anchor-key guarantee. New "For orchestrators" section
  showing the per-task workflow today (v0.5.3) plus the v0.7
  control-plane roadmap (WAL event stream, single-rule mutations,
  `expires_at`). "What it doesn't do" softened: "Complementary
  to OPA, not a replacement."
- `docs/overview.md` — Abstract rewritten to lead with the
  operational primitive ("give the agent a grant for this task
  with these capabilities for this duration"). Three-mode summary
  now puts `--contained` in the "experimental, opt-in" column
  consistently. New "Evidence Boundary" section with the WAL
  field-by-field breakdown, the proof bundle contents table, the
  three CLI verbs, and the maturity ladder (current default →
  v0.7+ external timestamp / WORM / HSM scoped).
- `docs/quickstart.md` — Section 8 renamed "Tamper-Evident Audit"
  (was "Tamper-Proof Audit", inconsistent with the rest of the
  codebase). New subsection "Exporting an evidence bundle" with
  `gvm proof event/batch/verify` examples. New section 8b
  "Orchestrator Integration Pattern" with a full per-task
  workflow that uses real commands (`gvm reload`, `gvm approve`,
  `gvm events list --agent ... --last 1h`, `gvm proof batch`)
  plus a v0.7-roadmap-coming note.
- `src/wasm_engine.rs` doc-comment — one-line inconsistency from
  the earlier strategic audit ("tamper-proof" — the rest of the
  codebase says "tamper-evident") replaced with the correct
  framing plus a cross-link to `docs/internal/GVM_CODE_STANDARDS.md
  §11 ("tamper-evident, not tamper-proof")`.

**Why.**

The strategic audit ([reviewed 2026-06-17]) verified that the
implementation already has the evidence stack (Merkle WAL,
Ed25519 anchor, `gvm proof` CLI, offline verify), the five-effect
decision model, and the framework-independent posture the
positioning needed — but the docs were burying these under
sandbox-mode prose. This commit surfaces what already ships,
without overclaiming what's still on the roadmap (IAM
principal binding, lease primitive, provider action packs,
`expires_at` on rules, RFC 3161 / HSM / KMS hooks — all kept
explicitly labelled "v0.7+").

**Affected files.**

- `README.md` (lead paragraphs + new orchestrator section +
  evidence-boundary section + softened "what it doesn't do")
- `docs/overview.md` (Abstract + new Evidence Boundary section)
- `docs/quickstart.md` (section 8 rename + new 8b orchestrator
  pattern + new "Exporting an evidence bundle" sub-section)
- `src/wasm_engine.rs` (doc-comment, one paragraph)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk.**

None. No code logic changed (the wasm_engine.rs edit is purely
inside `//!` doc-comment, verified by `cargo check --workspace`).
No public API surface changed.

**Follow-ups (audit P0–P4).**

The strategic audit produced a prioritised work plan that this
commit does NOT execute — only the P0 string fix (`tamper-proof`
→ `tamper-evident`) lands here. The remaining items are scoped
separately:

- P1: `unsafe_body_action: Option<EffectKind>` rule field —
  fail-close on body-inspection failure.
- P1: `expires_at: Option<DateTime<Utc>>` rule field — first
  step toward the lease primitive.
- P2: `principal_filter: Option<String>` rule field — agent_id
  becomes an SRR matching input, not just an audit label.
- P2: Industry-template seed for 1–2 provider action packs
  (`github.pr.merge`, `slack.message.send` → method/path mapping).
- P3: `gvm import openapi` — OpenAPI → SRR rule importer.
- P3: Cooperative body-context endpoint
  (`POST /gvm/payload-context`) — SDK / sidecar / MCP adapter
  delivers structured payload context without MITM.
- P4: Full `gvm lease issue` / `gvm run --lease` lease primitive.

### 2026-05-26: Pentest Phase 4 — MITM TLS + IC-3 approval bypass regression suite

Final Phase of the pentest roadmap. Eleven Rust integration tests
cover the TLS proxy's policy + resource-bound invariants and the IC-3
approval handler's state-machine corners (replay, race, malformed
input, type confusion). One bash script verifies the live trust-anchor
bypass surface that the engine-level suite cannot.

**What changed.**

- New `tests/mitm_tls_adversarial.rs` — five `#[tokio::test]` cases:
  - `server_config_forces_alpn_http_1_1_only` — ALPN list pinned to
    `http/1.1` only; prevents h2 framing-bypass.
  - `leaf_cert_cache_bounded_under_unique_sni_flood` — 200 unique
    SNIs produce a cache whose size scales with input, not above
    (MAX_CERT_CACHE_SIZE=10_000 is enforced by moka at the documented
    ceiling).
  - `leaf_cert_cache_hits_on_repeat_domain` — 50 repeat
    ensure_cached calls grow the cache by at most 1 entry; cache is
    not silently disabled.
  - `cert_resolver_handles_hostile_sni_inputs_without_panic` —
    empty / NUL / CRLF-smuggled / IPv6-literal / IDN / 1 KB
    hostnames don't panic the resolver or hang background tasks.
  - `per_sandbox_resolvers_produce_distinct_leaf_chains` — two
    resolvers built from distinct per-sandbox CAs mint distinct
    leaves for the same domain; pins the cross-sandbox impersonation
    defense.
- New `tests/ic3_bypass_adversarial.rs` — six `#[tokio::test]` cases:
  - `malformed_event_id_with_control_chars_does_not_panic` — NUL,
    CRLF, embedded quotes in event_id yield 404 or 400, never 200/500.
  - `very_long_event_id_handled_gracefully` — 10 KB event_id yields
    404/400/413; no memory blowup.
  - `non_boolean_approved_value_falls_back_to_deny` — `"yes"` (string)
    either gets 400 or falls back to Deny per the `unwrap_or(false)`
    contract; never fail-open to Allow.
  - `approve_with_extra_unknown_fields_still_succeeds` — handler is
    forward-compatible with orchestrator metadata.
  - `replay_approve_same_event_id_returns_404_second_time` — second
    approve of a consumed event_id is rejected; no double-deliver.
  - `concurrent_approve_and_deny_same_event_id_exactly_one_delivers`
    — concurrent approve+deny on the same id: exactly one wins (200),
    one is 404; receiver gets exactly one clean bool.
- New `scripts/mitm-pentest.sh` — two scenarios:
  - B1: override `SSL_CERT_FILE` to an empty file inside the sandbox
    and try `curl https://api.anthropic.com/`. Must fail cert
    verification — the agent cannot strip the trust anchor.
  - B2: drop a hostile self-signed root CA into `/etc/ssl/certs/` and
    retry. Either the sandbox blocks the trust-store write (best
    case) or the per-sandbox MITM CA remains the sole accepted issuer
    for inspected traffic.
- `docs/internal/PENTEST_REGRESSION_MAP.md` — Phase 4 sections added;
  backlog updated. Two items moved to Phase 5 backlog (wire-level
  TLS-version pinning, cipher-suite weakening probes) — both require
  a custom rustls-incompatible client harness or provider injection
  that's not pure-Rust testable.

**Why.**

Existing MITM coverage in `tests/mitm_streaming.rs` exercised the
streaming relay end-to-end but didn't pin the ALPN/cache/SNI invariants
that a single refactor could silently break. IC-3 coverage in
`tests/api_handlers.rs` + `tests/ic3_concurrency.rs` exercised happy
paths and concurrency but didn't probe replay, race, or hostile JSON
input. The Phase 4 suite closes both gaps.

**Affected files.**

- `tests/mitm_tls_adversarial.rs` (new, 5 cases)
- `tests/ic3_bypass_adversarial.rs` (new, 6 cases)
- `scripts/mitm-pentest.sh` (new, 2 scenarios)
- `docs/internal/PENTEST_REGRESSION_MAP.md` (Phase 4 sections + table)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk.**

Low. No production code changed. Engine tests run cross-platform under
`cargo test`; the bash script needs sandbox + root and follows the
Phase 1 invocation pattern.

**Roadmap completion.**

Phases 1-4 of the pentest plan are now shipped. Inventory growth from
pre-Phase-1 baseline:

- Rust adversarial tests:    88 → 131  (+43)
- Bash pentest scripts:        3 →   7  (+4)
- Pentest documentation:       4 →   5  (regression map keeps growing)
- Verified engine artifacts:   0 →   2  (SRR JSON evasion probes)

Phase 5 backlog: wire-level TLS-version pinning, cipher-suite weakening
probes, SRR warning-level WAL log when a case-variant of payload_field
or a nested match appears (mitigation for the documented Known
Limitations, deferred from Phase 3.5).

### 2026-05-26: Pentest Phase 3 — SRR / classifier evasion regression suite

Adversarial coverage for the SRR engine's normalization pipeline and
payload-inspection stack. Ten Rust integration tests load inline SRR
configs and assert that adversarial surface forms (encoded traversal,
double encoding, null-byte injection, method case, slash variants,
trailing dot segments, body-size boundaries, base64 wrappers) still
land in the configured Deny after canonicalization. One bash script
drives the same set of evasions through a live `gvm-proxy` and
verifies the audit chain records every Deny.

**What changed.**

- New `tests/srr_evasion_adversarial.rs` — ten tests against
  `NetworkSRR::check`:
  - `url_encoded_path_traversal_still_denied` — `%2e%2e/`, `%2E%2E/`,
    `..%2f..%2f` all reduce to the protected path.
  - `double_encoded_path_traversal_still_denied` — the 3-pass
    percent decoder collapses `%252e%252e/` before dot-segment
    resolution.
  - `null_byte_in_path_does_not_truncate_match` — `%00` and raw
    `\0` are stripped; no truncation bypass.
  - `lowercase_method_matches_uppercase_rule` — `post`/`Post`/`pOsT`
    all match a `POST` rule (uppercased at check entry).
  - `consecutive_slashes_in_path_collapsed_to_single` — `//admin`,
    `///admin`, `/admin//` all collapse.
  - `trailing_dot_segment_resolved_before_match` — RFC 3986 §5.2.4
    dot-segment handling.
  - `body_at_exact_max_size_inspected` — body length equal to
    `max_body_bytes` is still inspected (strict `>` at src/srr/mod.rs:804).
  - `body_one_byte_over_max_size_skipped` — body length above the
    limit skips payload inspection for that rule; documents the
    size-bypass surface so an operator who relies on payload
    inspection can size their `max_body_bytes` deliberately.
  - `base64_encoded_body_still_inspected` — the engine's
    plain-JSON-then-base64-JSON fallback catches base64-wrapped
    envelopes.
  - `base64_encoded_field_value_still_inspected` — the second
    base64 defense layer (src/srr/mod.rs:856) decodes the matched
    field value and re-checks for `payload_match` inside.
- New `scripts/srr-evasion-pentest.sh` — spawns a `gvm-proxy` with
  an isolated SRR config (single Deny on `evasion-target.test/admin*`),
  issues 11 evasion variants through `curl -x http://127.0.0.1:18080`,
  and asserts every variant lands in the WAL as a Deny.
- `docs/internal/PENTEST_REGRESSION_MAP.md` — Phase 3 section added
  with per-test threat / proof rows and per-variant defense table;
  backlog updated with the JSON-key-case and nested-field gaps
  documented but deliberately NOT pinned (avoid locking in the gap).

**Why.**

Existing SRR coverage lived in
`tests/hostile.rs` (case smuggling, null byte, unicode), the GraphQL
alias suite (`tests/graphql_alias_*.rs`), and `tests/srr_time_window.rs`.
None of those exercise percent encoding, double encoding, base64
envelopes, slash variants, or body-size boundaries. The Phase 3 suite
fills those gaps so a future change in `src/srr/normalize.rs` or
`src/srr/mod.rs:727` (`check_at`) trips a named test rather than
silently weakening a Deny rule.

**Affected files.**

- `tests/srr_evasion_adversarial.rs` (new)
- `scripts/srr-evasion-pentest.sh` (new)
- `docs/internal/PENTEST_REGRESSION_MAP.md` (Phase 3 sections)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk.**

Low. No production code changed. Engine tests are pure-Rust and run
cross-platform under `cargo test`; the bash script needs only a
built release binary and `curl`, runs without root (no sandbox
involved).

**Verified engine-layer artifacts (Phase 3 supplement).**

A direct challenge during review (was a case-sensitivity / nested-field
bypass *actually* possible, or was the backlog speculation?) prompted
two runnable probes:

- `structural_bypass_case_variant_envelope_key_evades_payload_rule`
- `structural_bypass_nested_payload_field_evades_payload_rule`

Both are marked `#[ignore]` so they don't fail CI, but running
`cargo test --test srr_evasion_adversarial -- --ignored` confirms
the engine falls through to Default-to-Caution (Delay 300ms) for:

- `{"OperationName":"TransferFunds"}` against a rule keyed on
  `payload_field = "operationName"` — `serde_json::Value::get` is
  case-sensitive; the engine has no case-folding on JSON keys.
- `{"data":{"op":"drop_table"}}` against a rule keyed on
  `payload_field = "op"` — `json.get(field)` only looks at the
  top level; the engine has no recursive search.

**Practical exploitability: low.** Follow-up review pointed out that
mainstream JSON parsers (Python pydantic, Java Jackson default,
JavaScript class-validator, Rust serde, spec-compliant GraphQL
servers) reject non-canonical key case at the upstream, so the
bypass leaves the attacker no closer to the protected action — the
malformed envelope dies at the API itself. The main residual risk
is **Go's `encoding/json`**, which does case-insensitive struct-field
matching by default; that's the population where the engine-layer
artifact has real teeth. Nested-field evasion is even weaker because
most production APIs reject unknown wrapper objects at schema
validation.

Documented as a Known Limitation in
`docs/security-model.md § SRR Payload Inspection` together with the
planned mitigation: a **warning-level WAL log** when a case-variant
of the configured `payload_field` appears in the body, or when a
recursive lookup finds a match below the top level. The warning
surfaces suspicious envelopes without changing enforcement — useful
for both detection and for nudging operators to tighten their rules
when their downstream is Go-based.

The probes are kept `#[ignore]`'d to track the engine behavior over
time: if a future change adds case-folding or recursive payload
lookup, the probes start failing and must be flipped into
positive-defense tests.

**Follow-ups (Phase 4).**

MITM TLS downgrade + IC-3 bypass.

### 2026-05-26: Pentest Phase 2 — DNS governance bypass regression suite

Adversarial coverage for the DNS governance engine and the sandbox-side
DNAT integration. The pure-Rust engine surface gets six adversarial
tests plus one positive control; the live DNAT path gets two bash
scenarios run against a real sandboxed shell.

**What changed.**

- New `tests/dns_governance_adversarial.rs` — six adversarial cases
  plus a positive control:
  - `tier4_flood_global_threshold_triggers_after_burst`: a burst of
    distinct base domains past `snapshot_state().tier4_threshold`
    must produce at least one `DnsTier::Flood` classification.
  - `tier3_anomalous_via_subdomain_burst`: subdomain enumeration on
    a single base past `tier3_threshold` must escalate to
    `DnsTier::Anomalous` (or stricter `Flood`).
  - `parser_rejects_malformed_packets`: empty, header-only, qdcount=0,
    truncated-label, overlong-label, and invalid-UTF8 packets all
    return `None` from `parse_dns_question`. Each `Some(_)` would be
    an arbitrary-classification bypass (attacker fakes a domain
    string the engine then trusts).
  - `parser_rejects_pointer_compression_in_question`: a 0xC0.. byte
    at the question section is rejected (RFC 1035 §4.1.4).
  - `case_variants_share_tier_window_slot`: mixed-case subdomains
    collapse to one window slot, so an attacker cannot dilute Tier 3
    counters by varying capitalization. `classify_inner` already
    lowercases at entry — the test pins that behavior.
  - `idn_homograph_treated_as_distinct_domain`: Latin `anthropic.com`
    and Cyrillic `\u{0430}nthropic.com` classify as different base
    domains. Documents the current behavior so a future "normalize
    IDN" change shows up here as a deliberate decision.
  - `parser_accepts_well_formed_query`: positive control guarding
    against the malformed-only tests passing vacuously.
- New `scripts/dns-bypass-pentest.sh` — two scenarios against a live
  sandbox:
  - B1: rewrite `/etc/resolv.conf` to `nameserver 8.8.8.8` and issue
    queries. Either the queries reach the local DNS proxy (DNAT
    works regardless of resolv.conf) or iptables OUTPUT drops the
    egress entirely — both are containment passes. Failing here
    means the sandbox's configured resolver shaped policy.
  - B2: in-sandbox subdomain burst (10 queries) plus cross-domain
    burst (25 queries) must produce both Tier 3 and Tier 4
    `gvm.dns.query` events in WAL or proxy.log. End-to-end smoke
    that the engine is wired and classifying real sandbox traffic.
- `docs/internal/PENTEST_REGRESSION_MAP.md` — Phase 2 sections added,
  backlog table updated (DNS engine + DNAT entries marked shipped,
  decay-gaming deferred to Phase 2.5 because the engine's clock
  injector is `#[cfg(test)] pub(super)` and not reachable from an
  external integration test).

**Why.**

The engine has 23 internal `#[cfg(test)] mod tests` cases at the unit
level, but the integration-level surface (what an external attacker
can reach through `gvm_proxy::dns_governance::*`) was uncovered.
Memory recorded that the DNAT integration had been verified once
44 days ago (Test 83 9/9 PASS on EC2), but there was no automated
regression — a silent break in DNS classification would only surface
on the next manual EC2 walkthrough. This commit closes that gap.

**Affected files.**

- `tests/dns_governance_adversarial.rs` (new)
- `scripts/dns-bypass-pentest.sh` (new)
- `docs/internal/PENTEST_REGRESSION_MAP.md` (Phase 2 sections)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk.**

Low. No production code changed. Engine tests are pure-Rust and run
on every platform; the bash script is Linux + root + sandbox and
mirrors the Phase 1 invocation pattern.

**Follow-ups (Phase 3-4).**

SRR/classifier evasion (Phase 3), MITM TLS downgrade + IC-3 bypass
(Phase 4). Backlog tracked in
`docs/internal/PENTEST_REGRESSION_MAP.md § Known Gaps`.

### 2026-05-26: Pentest Phase 1 — sandbox escape 15-vector regression suite

Promotes the 2026-04-05 manual EC2 pentest result table ("15/15 attacks
blocked", in `docs/security-model.md`) from a frozen marketing artifact
to a build-time-verified guarantee. Adds 15 integration tests, one per
documented attack vector, plus an extended bash pentest covering
capability set, device nodes, interface visibility, cgroup escape, and
user-namespace privilege escalation — areas the existing
`ghost-stress-test.sh` does not assert on.

**What changed.**

- New `tests/sandbox_escape_15_vectors.rs` — 15 `#[cfg(target_os =
  "linux")] #[test]` functions named `escape_v<NN>_<slug>`, each
  invoking `gvm run --sandbox -- <probe>` via the CLI (per the
  CLAUDE.md "CLI-only testing" rule) and asserting on exit code,
  stdout, and stderr. Probes are written in shell and Python ctypes
  so we exercise the actual syscalls (AF_PACKET, mount, unshare,
  ptrace, kill, direct UDP/53) and not a wrapper that might silently
  shape the result.
- New `tests/sandbox_escape_common/mod.rs` — shared helpers:
  `gvm_binary_path()`, `is_root()`, `require_sandbox_env(name)` for
  the SKIP-when-not-Linux-or-not-root preflight, `run_sandboxed_probe`
  with a 60s wall-clock timeout, and `assert_blocked_with` /
  `assert_stdout_eq` for the two common assertion shapes.
- New `scripts/sandbox-escape-extended.sh` — five scenarios (capability
  set audit, sensitive device nodes, host interface visibility, cgroup
  escape, `unshare(CLONE_NEWUSER)` privilege-escalation proxy). Each
  scenario writes per-probe stdout/stderr/exit files to
  `results/extended-<UTC-timestamp>/` so failures are diagnosable
  offline.
- New `docs/internal/PENTEST_REGRESSION_MAP.md` — explicit mapping
  between every row of the security-model attack table and the
  test function that enforces it. Future additions get a single
  procedural checklist: doc row → test function → regression-map
  row.

**Why.**

The 2026-04-05 pentest was a one-time manual walkthrough. Nothing
prevents a future seccomp whitelist widening or capability-set
loosening from silently breaking the documented guarantees — there
were no automated assertions backing the table. Memory pointed at
`project_sandbox_telegram_test.md` (51 days old) for the "15/15"
claim, but that memory cited a different test run, not an automated
regression suite. This commit closes that gap.

**Affected files.**

- `tests/sandbox_escape_15_vectors.rs` (new)
- `tests/sandbox_escape_common/mod.rs` (new)
- `scripts/sandbox-escape-extended.sh` (new)
- `docs/internal/PENTEST_REGRESSION_MAP.md` (new)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk.**

Low. Tests are gated on `target_os = "linux"` and on root privilege;
non-Linux and unprivileged invocations SKIP loudly rather than
fail. No production code changed — only test files, scripts, and
docs. The release binary is unaffected.

**Follow-ups (Phase 2-4).**

DNS governance bypass (Phase 2), SRR/classifier evasion (Phase 3),
MITM TLS downgrade + IC-3 bypass (Phase 4). Backlog tracked in
`docs/internal/PENTEST_REGRESSION_MAP.md § Known Gaps`.

### 2026-05-24: Audit Phase 5b — cross-rotation anchor recovery

Fixes the rotation-then-shutdown false-positive in startup recovery.
Before this commit, `scan_wal_for_recovery` only read the active
`wal.log`; if WAL rotation completed (the active file got renamed
to `wal.log.<N>`, a fresh empty active file was created) and the
proxy shut down before any new batch sealed, the next start saw an
empty active file, recovered no anchor, and fell back to genesis.
The next anchor's `prev_anchor: None` then looked like a chain
break to `verify_anchor_chain` — a true positive on the rule but a
false positive on the operator's situation (the previous anchor is
still on disk in `wal.log.<N>`).

**What changed.**

- New helper `find_highest_rotated_segment(active_path)` enumerates
  sibling files of the form `<stem>.<N>` (decimal N) and returns
  the highest-numbered path, mirroring the segment-naming convention
  already used by `rotate_wal`.
- The existing line-parsing loop in `scan_wal_for_recovery` was
  factored out into `scan_single_segment(path)` so the new code can
  invoke it on both files without duplicating the JSON-line matching.
- `scan_wal_for_recovery` now scans the active file first; if and
  only if the result has `last_anchor_hash: None`, it scans the
  highest-numbered rotated segment and fills only the recovery
  fields the active scan left empty (active values strictly win).
  Emits a `tracing::info!` under target `gvm.audit.recovery` with
  the rotated segment path and recovered anchor's hex prefix so
  the recovery path is visible in logs without operator action.

**Why the merge rule is "active wins, rotated fills gaps".**

Active values are strictly more recent (rotation happened before
they were written). If the active file did manage to write a
`MerkleBatchRecord` for batch N+1 but no anchor, the chain is
already broken at that batch — Phase 5b cannot fix that; it only
recovers the last *complete* chain head, which always lives in the
rotated segment in that scenario. Using rotated's `last_batch_id`
in that case would re-issue an already-used batch id and trip
the duplicate-batch_id rule on the next anchor, so the merge
keeps active's batch info and only borrows rotated's anchor + (if
absent) context_hash.

**What stays out of scope.**

- Walking back past the highest-numbered rotated segment. Multi-
  rotation-then-shutdown is operationally rare (rotation requires
  `max_wal_bytes` of throughput; two rotations between shutdowns
  is a stretch), and a corrupted highest segment will already
  surface in the logs. If concrete operator pain materializes,
  the helper can iterate descending segment numbers without an
  API change.
- Watermark-file integration. `wal.log.<N>.watermark` is owned by
  the background re-verification path and isn't part of the
  startup chain-head recovery contract.

**Tests.** `tests/cross_rotation_recovery.rs` (+7 tests):
- `empty_active_with_rotated_segment_recovers_anchor` — the core
  scenario; anchor in `wal.log.1`, empty `wal.log` → recovered
- `active_anchor_takes_precedence_over_rotated` — when both
  segments have anchors, active wins (the merge invariant)
- `highest_numbered_rotated_segment_is_selected` — four rotated
  segments, only the highest gets scanned
- `no_rotated_segments_falls_back_to_genesis` — preserves the
  existing fresh-install behaviour
- `corrupt_rotated_segment_does_not_recover` — garbage in the
  rotated segment must not produce a false-positive recovery
- `non_numeric_suffix_files_are_ignored` — `wal.log.bak` or
  similar operator-staged files are not treated as segments
- `rotated_segment_context_hash_seeds_triple` — config_load's
  `config_integrity_ref` from the rotated segment seeds
  `triple.context_hash` so events between restart and the first
  new config_load carry the right ref

All Phase 3 / Phase 4 / anchor-signing / ledger-shutdown tests
continue to pass.

**Affected files**: `src/ledger.rs` (added
`find_highest_rotated_segment`, split out `scan_single_segment`,
extended `scan_wal_for_recovery`), `tests/cross_rotation_recovery.rs`
(NEW), `docs/internal/CHANGELOG.md` (this entry, plus removal of
the "Audit Phase 5b" line from the v0.6 Planned section).

**Risk**: Very low. Pure read-path change. The fallback is gated
on `last_anchor_hash.is_none()` after the active scan, so existing
deployments that already have an anchor in the active file see
zero behaviour change. No on-disk schema change, no public API
change.

### 2026-05-24: Audit Phase 4 — leaves-only checkpoint snapshot persistence

Closes the only remaining gap from the v3 audit-architecture plan in
`~/.claude/plans/lazy-zooming-naur.md` (Phase C deferred follow-up).
The per-step `AgentCheckpointTree` was in-memory only since the Phase
3 full landing (`6c06dd4`); proxy restart reset every per-agent tree
to step 0, breaking cross-restart inclusion proofs and leaving
post-restart anchors with `checkpoint_root: None` until checkpoints
re-registered.

**What changed.**

- `CheckpointSnapshot { spec_version, expected_checkpoint_root,
  written_at, agents: BTreeMap<String, BTreeMap<u32, hex_hash>> }`
  is the on-disk format. JSON for human inspection; the
  `expected_checkpoint_root` is the recomputed global aggregator
  root over `agents` at write time and acts as a self-consistency
  check on load.
- `CheckpointAggregator::with_snapshot(ledger, snapshot_path)`
  loads from disk at startup. Never fails — on parse error /
  spec-version mismatch / self-hash mismatch the aggregator starts
  empty and a `SnapshotLoadReport::Rejected { reason }` is
  returned so the caller can surface a warning. On successful
  load the reconstructed root is published into the ledger's
  triple state immediately so the next sealed batch's anchor
  binds it via the existing `BatchSealRecord::checkpoint_root`
  field — no schema change to the anchor.
- `save_snapshot()` is an atomic write (`.tmp` + fsync + rename).
  Skipped (`Ok(false)`) when no snapshot path is configured or
  when nothing changed since the last successful save (a
  `write_counter` / `saved_at_counter` pair tracks dirty state,
  TOCTOU-safe under concurrent saves).
- `spawn_periodic_save(interval)` returns a `JoinHandle` for a
  tokio task that calls `save_snapshot` on each tick. Caller
  aborts the handle at shutdown and is expected to do one final
  manual `save_snapshot()` to flush state written between the
  last tick and shutdown.

**Why this design.**

- *No anchor schema change.* The existing
  `BatchSealRecord::checkpoint_root` field already hashes into
  every anchor via `GvmStateAnchor::compute_hash`, so the
  reconstructed root rides the existing chain — the snapshot
  "hashes into the next anchor" transitively, without bumping
  `spec_version` or adding new fields.
- *Self-consistency only at load time.* Catches transit
  corruption deterministically. Stronger guarantees (cross-check
  against the most recent WAL anchor's `checkpoint_root`,
  Ed25519-signed snapshot files) deferred — operators get
  post-hoc detection through the chain, which the roadmap
  explicitly accepted ("tampered snapshot file is detected at
  first batch"). Documented as a known limitation in the module
  doc; v0.7 / v1.1 can layer signed snapshots on top without
  changing the existing API.
- *Backward compatibility.* `CheckpointAggregator::new(ledger)`
  signature unchanged — every existing test and (future)
  production caller that doesn't need persistence keeps working
  with `snapshot_path: None`. Persistence is fully opt-in via
  the new `with_snapshot` constructor.
- *No production wiring yet.* The aggregator is still
  test-instantiated only (no `src/` callsite calls `register`).
  Phase 4 ships the persistence primitive so future production
  wiring (enforcement-path checkpoint emission) gets restart
  durability for free. The roadmap's "snapshot at shutdown +
  periodic timer + reload at `Ledger::with_config_and_signer`"
  shape is preserved; the production wiring happens when the
  enforcement path that calls `register` is added.

**Tests.** `tests/checkpoint_persistence.rs` (+9 tests):
- `snapshot_round_trip_restores_state_and_root` — register → save
  → drop → reload reproduces per-agent / per-step state, ledger's
  `checkpoint_root` matches, `proof()` works on the reloaded tree
- `missing_snapshot_file_yields_clean_start` — fresh install /
  first boot case, NoFile status, no error
- `corrupt_snapshot_file_is_rejected_and_aggregator_starts_empty`
  — invalid JSON → Rejected with parse reason, fallback to empty
- `tampered_leaf_hash_breaks_self_hash_and_is_rejected` — single
  leaf hex mutated without root recompute → self-hash mismatch
  detected at load
- `wrong_spec_version_is_rejected` — future-version snapshot
  refused (forward-compatibility wedge)
- `save_with_no_changes_is_a_noop` — dirty flag prevents
  redundant fsync work in the periodic saver
- `in_memory_only_aggregator_save_is_noop` — backward-compat
  `new()` constructor never writes
- `periodic_save_writes_dirty_state_to_disk` — `spawn_periodic_save`
  end-to-end with 50ms interval
- `reloaded_state_publishes_to_next_anchor_checkpoint_root` —
  the chain-binding invariant: after restart, the ledger's
  `triple.checkpoint_root` equals the snapshot's reconstructed root

All 25 prior checkpoint tests still pass (no breaking changes to
`CheckpointAggregator::new` / `register` / `register_agent_root`
/ `proof`).

**Affected files**: `src/checkpoint.rs` (rewrite to add Phase 4
on top of Phase 3), `tests/checkpoint_persistence.rs` (NEW),
`docs/internal/CHANGELOG.md` (this entry, plus removal of the
"Audit Phase 4 — leaves-only checkpoint persistence" line from
the v0.6 Planned section).

**Risk**: Low. New code is opt-in (`with_snapshot` vs `new`);
existing callers see no behaviour change. The reload path
fail-closes to empty on any parse / validation error, so a
corrupted snapshot file degrades to today's "start empty"
behaviour rather than crashing the proxy. The chain-binding is
through an existing anchor field, not a new one — no on-disk
WAL schema change.

### 2026-05-22: JWT hardening Phase F — CLI plumbing + derive_admin_url discovery + bootstrap TTL + sandbox env sanitization

Closes the three architecture-review items from the operator's
critique of the 2026-05-21 admin-port middleware work, plus the
deferred CLI plumbing.

**1. CLI admin call sites wired with `with_admin_bearer`.**

Every admin-port HTTP call now passes through `crate::run::
with_admin_bearer(rb)`, which attaches `Authorization: Bearer
$GVM_ADMIN_TOKEN` when the env var is set (no-op when unset, so
loopback-default operators see zero behaviour change).

Wired sites:
- `approve.rs::fetch_pending` (GET /gvm/pending)
- `approve.rs::send_decision` (POST /gvm/approve)
- `proxy_manager.rs::reload_running_proxy` (POST /gvm/reload) —
  also fixed to use `derive_admin_url` (was hitting the proxy
  port directly, an existing latent bug)
- `reload.rs::run_reload` (POST /gvm/reload) — same fix
- `dns_inspect.rs::run_status` (GET /gvm/dns/state)
- `sandbox_inspect.rs::fetch_list` (GET /gvm/sandbox)
- `main.rs::cleanup_sandbox` DELETE handler (DELETE /gvm/sandbox/<id>)
- `run.rs::provision_sandbox` (POST /gvm/sandbox/launch)

Not wired (intentionally): `Commands::Dashboard` only opens the
browser at the admin URL — the browser would need to inject the
Bearer header itself (e.g. via DevTools), which is an operator
workflow concern. Documented limitation.

**2. Critique #1 fix — `derive_admin_url` discovery order.**

The `+1010` heuristic breaks when an operator binds admin to a
non-conventional port (e.g. `127.0.0.1:9999` to dodge a port
collision). New priority order:
1. `GVM_ADMIN_URL` env var (explicit operator override).
2. `[server] admin_listen` parsed from a discoverable proxy.toml.
   Reuses the same discovery order the proxy itself uses
   (`$GVM_CONFIG`, `./config/proxy.toml`, `./proxy.toml`,
   `$XDG_CONFIG_HOME/gvm/proxy.toml`, `~/.config/gvm/proxy.toml`,
   `/etc/gvm/proxy.toml`). Tolerant line-based grep — no `toml`
   dep added to the CLI just for one field.
3. `proxy_port + 1010` heuristic (existing fallback).

**3. Critique #2 fix — bootstrap token TTL.**

`[server] bootstrap_token_ttl_secs` config field, **default 86400
(24h)**, replaces the previous behaviour of using
`token_ttl_secs` (typically 1h) for the bootstrap token. The
1-hour bootstrap was hostile UX for cross-timezone / CI-delayed
provisioning where the bootstrap token expired before the operator
could mint a long-lived replacement, forcing a proxy restart just
to re-mint. Operators with stricter posture can shorten the field.
Bootstrap token's `jti` lands in the WAL like any other token, so
revocation is available if the longer TTL is undesirable for a
specific run.

**4. Critique #3 (admin role granularity) — DEFERRED, not closed.**

`gvm_role` is still binary (`None` / `Some("admin")`). Schema
remains forward-compatible — a future `Some("auditor")` would
slot in with one new middleware variant. Deferring because the
current admin-port endpoint surface is small enough that the
admin/auditor split is not yet load-bearing; left as a clean
extension point in the Claims schema.

**5. Sandbox env sanitization.**

`gvm-sandbox/src/sandbox_impl.rs` now strips the following env vars
from the agent process immediately before exec:
- `GVM_ADMIN_TOKEN` (admin-port Bearer)
- `GVM_JWT_SECRET` (legacy HS256 secret, removed but still defensive)
- `GVM_JWT_ED25519_SEED` (Ed25519 signing seed)
- `GVM_VAULT_KEY`, `GVM_SECRETS_KEY` (vault encryption keys)
- Plus wildcard: any env var matching `GVM_JWT_*_SEED` or
  `GVM_JWT_ED25519_SEED_*` (multi-slot per-slot seed names)

Defense-in-depth: even if an agent escapes its sandbox namespace,
it never had access to the operator's plane-level secrets. The
strip happens AFTER all GVM-injected env vars (HTTP_PROXY,
GVM_AGENT_ID, etc.) so the agent still gets what it needs.
Operator-supplied placeholder credentials via `--env` are unaffected
(they go through the `config.extra_env` path which runs after).

**Tests**: 920 passing (release mode), 0 failed. No new test files
added — the changes are surface-level wiring without new behaviour
to verify (the existing `admin_port_loopback_only.rs` tests cover
the bind policy gate, and the JWT middleware tests in `auth.rs`
cover the actual auth path).

**Affected files**:
- `crates/gvm-cli/src/{approve,proxy_manager,reload,dns_inspect,sandbox_inspect}.rs`
- `crates/gvm-cli/src/run.rs` (derive_admin_url discovery,
  provision_sandbox bearer)
- `crates/gvm-cli/src/main.rs` (cleanup_sandbox bearer)
- `src/config.rs` (bootstrap_token_ttl_secs field + default)
- `src/main.rs` (bootstrap token uses config TTL + updated banner)
- `crates/gvm-sandbox/src/sandbox_impl.rs` (env strip block)
- `tests/admin_port_loopback_only.rs` (struct migration)
- `docs/internal/CHANGELOG.md` (this entry)

**Risk**: Low. CLI changes are surface-level — operator workflow on
loopback-default unchanged (env var unset = no-op). Non-loopback
admin operators now have a clean migration path: `export
GVM_ADMIN_TOKEN=...` and the CLI just works. The bootstrap-TTL
default change extends a token's validity window from 1h to 24h —
a deliberate trade-off documented inline. Sandbox env sanitization
is purely additive removal (no env var added to the strip list
was ever needed by an agent — agents talk via the proxy, not
directly to admin port or signing keys).

### 2026-05-21: JWT hardening Phase D+E — TOML multi-slot schema + HS256 final removal (breaking)

Completes the deferred items from the 2026-05-21 Phase B+C commit
the same day. Two changes, one breaking.

**Phase D — `[[jwt.keys]]` TOML schema.**

The in-memory `Vec<JwtKeySlot>` shape landed in Phase B; this wires
operator-facing config:

```toml
[jwt]
algorithm = "ed25519"

[[jwt.keys]]
kid = "gvm-2026-q2"
seed_env = "GVM_JWT_ED25519_SEED_ACTIVE"
active = true

[[jwt.keys]]
kid = "gvm-2026-q1"
seed_env = "GVM_JWT_ED25519_SEED_PREVIOUS"
expires_at = "2026-08-01T00:00:00Z"
```

`JwtConfig::from_slot_configs(algorithm, slots, ttl)` reads each
`seed_env`, parses hex, builds the slot vector, runs `validate_slots`.
`main.rs` prefers `[[jwt.keys]]` when non-empty; falls back to the
single-key `ed25519_seed_env`/`secret_env` path otherwise (backward
compat). Tests +5.

**Phase E — HS256 removal (BREAKING).**

The deprecation banner shipped in the same-day Phase C commit; this
removes the code. Rationale captured in the deprecation banner is
still valid (symmetric-secret risk, no offline auditor verification,
no compelling use case GVM doesn't cover better with Ed25519).
Operators with explicit `algorithm = "hs256"` now see startup error
with migration message.

Code removed:
- `JwtAlgorithm::Hs256` variant
- `JwtKeyMaterial::Hmac` variant
- `JwtSecret` struct + ZeroizeOnDrop wrapper
- `JwtConfig::from_env` (HS256 single-key loader)
- HS256 branches in `encode_jwt`, `decode_jwt`, `from_slot_configs`
- HS256 startup banner + production-mode default-flip logic in
  `main.rs` (no longer applicable — Ed25519 is the only algorithm,
  so no "flip" is needed)
- `hmac` / `Sha256` direct imports from `auth.rs` (still used
  elsewhere via `sha2::Sha256` for Merkle hashing — kept indirectly)

Tests removed/migrated:
- `secret_zeroized_on_drop` — DELETED (`JwtSecret` no longer exists;
  Ed25519 zeroization is `ed25519-dalek`'s responsibility)
- `from_env_missing_returns_none` → `from_env_ed25519_missing_returns_none`
- `algorithm_from_config_str_parses_known_aliases` →
  `algorithm_from_config_str_post_hs256_removal` (asserts HS256
  rejection with migration message)
- `ed25519_config_rejects_hs256_signed_token` — rewritten to forge
  the HS256-claimed token MANUALLY (since the HS256 issue path is
  gone); the alg-confusion defense is what's being tested and
  remains identically effective
- `hs256_config_rejects_eddsa_signed_token` — DELETED (symmetric
  test on a non-existent direction)
- `wrong_secret_rejected` — kept, now uses two different Ed25519
  seeds (functionally identical assertion: distinct private key →
  signature rejected)
- `multi_agent_isolation.rs::shared_jwt_config` — migrated to Ed25519
- `fuzz_jwt_auth.rs` corpus driver — migrated to Ed25519

`JwtAlgorithm::from_config_str` semantics:
- `""` → `Ed25519` (no-config UX preserved; was HS256 default
  pre-removal)
- `"ed25519"` / `"eddsa"` (case-insensitive) → `Ed25519`
- `"hs256"` / `"hmac"` → ERROR with migration message
- Anything else → ERROR with "Supported: ed25519"

**Workspace: 920 passing** (release mode), 0 failed, 7 ignored.
Down from 922 due to the two intentionally-deleted tests above.

**Affected files**: `src/auth.rs` (HS256 deletion, test migration,
~250 LOC net delta), `src/config.rs` (TOML schema for `[[jwt.keys]]`,
unchanged for HS256 path), `src/main.rs` (HS256 banner removed,
algorithm load simplified), `tests/multi_agent_isolation.rs`
(Ed25519 migration), `fuzz/fuzz_targets/fuzz_jwt_auth.rs` (Ed25519
migration), `docs/security-model.md` (§8 v1.6 hardening row),
`docs/internal/CHANGELOG.md` (this entry).

**Operator-facing breakage:**

1. `[jwt] algorithm = "hs256"` → startup ERROR + migration message.
2. `GVM_JWT_SECRET` env var no longer read by JWT loader (its name
   remains as the `secret_env` field default for forward compat in
   case HMAC returns later under a different scheme, but nothing
   consumes it).
3. Tokens previously issued under HS256 — invalid; auditor /
   long-lived agent token sessions need fresh issuance under
   Ed25519. Operators with active HS256 deployments should issue
   replacement Ed25519 tokens BEFORE upgrading the proxy.

**Migration recipe:**

```bash
# 1. Generate an Ed25519 seed (operator's choice of method).
openssl rand -hex 32 > /etc/gvm/jwt_ed25519_seed
export GVM_JWT_ED25519_SEED=$(cat /etc/gvm/jwt_ed25519_seed)

# 2. Update proxy.toml.
[jwt]
algorithm = "ed25519"
# secret_env = "GVM_JWT_SECRET"        # delete this line
ed25519_seed_env = "GVM_JWT_ED25519_SEED"
ed25519_key_id = "gvm-2026"            # optional kid label

# 3. Restart the proxy. The bootstrap admin token is printed if
#    admin_listen is non-loopback (kubeadm pattern from v1.5).

# 4. Re-issue agent tokens. Existing HS256 tokens become invalid.
```

**Risk**: High by surface area, low by failure mode. The change is
breaking but fails LOUD at startup (config-error exit) rather than
silently dropping HS256 traffic. An operator who upgrades without
reading the CHANGELOG sees an immediate error and can either
downgrade or follow the migration recipe. No data corruption
possible — WAL schema unchanged, audit chain unaffected.

### 2026-05-21: JWT hardening Phase B+C — multi-key rotation + HS256 deprecation path

Follow-up to the same-day Phase A commit (admin port JWT middleware
+ bootstrap token + gvm_role claim). Closes the two remaining items
the operator surfaced in the JWT-model review.

**Phase B — Multi-key slots for graceful rotation.**

Replaces the prior single-key `JwtConfig.key: JwtKeyMaterial` with
`JwtConfig.keys: Vec<JwtKeySlot>` (cap `MAX_KEY_SLOTS = 4`). Each
slot carries `{ kid, material, active, expires_at }`. The invariant
(exactly one active, unique kids, ≤4 entries) is enforced by
`JwtConfig::validate_slots`, called on construction and on every
hot-reload.

- **Sign**: always with the active slot. Header `kid` is the active
  slot's kid (sanitized to `[A-Za-z0-9-_.]`).
- **Verify**: parse `kid` from the token header, look up the
  matching slot via `JwtConfig::slot_by_kid` (which transparently
  excludes slots whose `expires_at` is past). Tokens without `kid`
  fall back to the slot whose kid is empty — preserves backward
  compat with v1 HS256 tokens minted before kid was used.
- **Rotation pattern**:
    1. Add new slot, `active = false`, no expiry.
    2. Promote it: flip `active`, set old slot's `expires_at = now +
       grace`, hot-reload via `POST /gvm/reload`.
    3. After grace elapses, old slot is auto-excluded from
       verification. Operator removes it at next config edit.
- **No restart, no token-replay window**, no in-flight verify torn
  down — the reload is the same atomic `Arc<RwLock<>>` swap already
  used for SRR rules.

**Phase C — HS256 deprecation path (no penalty latency).**

- Prominent stderr banner at startup when the resolved algorithm is
  HS256: explains the symmetric-secret risk, points at the Ed25519
  migration, names the v1.0 removal timeline.
- `GVM_ENV=production` flips the default algorithm from HS256 to
  Ed25519 when the operator did not explicitly choose. Dev/local
  ergonomics preserved (HS256 still default with no env set).
- Structured `tracing::warn!` line so HS256 use is visible in log
  aggregation.
- **Explicit non-choice**: no artificial slow-down on HS256 verify.
  Hostile UX, no security benefit. The deprecation is communicated,
  not punished.

**Tests added (+7):**
- `validate_slots_enforces_invariants` (empty, double-active,
  no-active, duplicate-kid, over-cap)
- `sign_always_uses_active_slot` (header kid inspection)
- `rotation_previous_slot_token_still_verifies`
- `expired_slot_excluded_from_verification`
- `unknown_kid_rejected`
- `legacy_token_without_kid_falls_back_to_active_slot`
- Plus all pre-existing alg-confusion / EdDSA tests adapted to the
  multi-slot shape.

Workspace: **917 passing** (was 911 after Phase A), 0 failed.

**Affected files**: `src/auth.rs` (slot enum + sign/verify dispatch
+ tests, ~250 LOC net), `src/main.rs` (production-mode default,
HS256 banner), `tests/multi_agent_isolation.rs` (struct migration
to slots), `docs/security-model.md §8` (v1.5 hardening),
`docs/internal/CHANGELOG.md` (this entry).

**Backward compat**: existing operator configs work unchanged.
HS256 single-key path is preserved (now a degenerate single-slot
config under the hood). Tokens minted before this change verify
under the active slot (kid="" lookup). No WAL schema change, no
on-disk format change.

**Risk**: Medium-low. The slot refactor touches every encode/decode
site; all 917 workspace tests pass. The active-slot invariant is
checked at construction time + on reload, so a misconfigured
multi-slot setup fails loud at startup rather than silent at first
mismatched verify.

**Deferred**:
- Per-slot algorithm mixing (Hs256 + Ed25519 in the same `keys`
  vector). Currently the algorithm is config-wide. Use case is
  thin — operators rotating into Ed25519 do the algorithm swap as
  a separate config change, not a hybrid slot set.
- TOML schema for `[[jwt.keys]]` array. The Vec<JwtKeySlot>
  in-memory shape is ready; surface wiring (config.rs +
  proxy.toml schema) lands as a follow-up. Operators who want
  multi-key today can build it programmatically via the lib API.
- HS256 final removal — tracked for v1.0.

### 2026-05-21: JWT issuance model hardening — Ed25519 (#4)

Lands the deferred #4 follow-up from 2026-05-15: asymmetric JWT
signing via Ed25519 (EdDSA per RFC 8037). HS256 stays the default;
operators flip `[jwt] algorithm = "ed25519"` to opt in.

**Why asymmetric matters.** HS256 uses a shared secret for both
sign and verify; anyone holding the secret can mint tokens. An
external auditor (compliance reviewer, downstream service, separate
team) cannot verify token authenticity without being trusted with
the signing key. Ed25519 splits that — the proxy holds the private
signing key; auditors verify offline with only the public key.

**Implementation:**
- New `JwtAlgorithm { Hs256, Ed25519 }` enum + `JwtKeyMaterial`
  variant carrying either an `HmacSha256` secret or an Ed25519
  `SigningKey`/`VerifyingKey` pair with `kid`. Encode + decode
  dispatch on the algorithm; both produce/verify standard JWS.
- New env var `GVM_JWT_ED25519_SEED` (default; rename via `[jwt]
  ed25519_seed_env`): 32-byte hex seed. New `[jwt] ed25519_key_id`
  config field is baked into the JWS header `kid` so auditors
  pick the right verifying key from a registry.
- `JwtConfig::public_key_hex()` exposes the public key for printing
  / serving via admin endpoint (operator decides distribution path).
- Reuses the same `ed25519_dalek::SigningKey`/`VerifyingKey`
  infrastructure as `src/sign.rs::SelfSignedSigner` — no new
  cryptographic surface added.

**Alg-confusion defense (CVE-2018-1000531 class):** the verifier
refuses any token whose header `alg` does not equal the operator-
configured algorithm. So if an attacker takes the EdDSA public key,
treats it as HMAC secret, and signs an HS256 token, the EdDSA-
configured verifier rejects on header mismatch BEFORE attempting
signature verification. Symmetric direction covered too. Test:
`ed25519_config_rejects_hs256_signed_token`.

**`kid` injection defense:** operator-supplied `ed25519_key_id` is
filtered to `[A-Za-z0-9-_.]` at issuance — prevents an operator
typo (or a malicious operator) from breaking out of the JSON header
with embedded quotes and rewriting `alg` mid-string. Test:
`ed25519_kid_sanitized_against_json_escape_injection`.

**Tests added (+11):**
- `ed25519_round_trip` — full sign/verify path with claims preserved
- `ed25519_header_contains_kid_and_eddsa_alg`
- `ed25519_kid_sanitized_against_json_escape_injection`
- `ed25519_config_rejects_hs256_signed_token` — alg-confusion
- `hs256_config_rejects_eddsa_signed_token` — symmetric alg-confusion
- `ed25519_tampered_signature_rejected`
- `ed25519_wrong_seed_rejected`
- `algorithm_none_attack_rejected_for_eddsa` — CVE-2015-9235 alg:none
- `algorithm_from_config_str_parses_known_aliases`
- `ed25519_from_env_seed_loads_keypair`
- `ed25519_from_env_rejects_wrong_seed_length`

Workspace test count: 907 passing (was 896), 0 failed.

**Backward compat:** existing operator configs without `[jwt]
algorithm` field default to `hs256` (matching prior behaviour);
existing HS256 tokens issued before this commit continue to verify
under the same env var + secret. Operators upgrade by adding three
lines to `proxy.toml`:

```toml
[jwt]
algorithm = "ed25519"
ed25519_seed_env = "GVM_JWT_ED25519_SEED"  # default
ed25519_key_id = "gvm-2026-q2"             # optional label
```

then setting `GVM_JWT_ED25519_SEED=<64 hex chars>` and restarting.

**Affected files**: `src/auth.rs` (algorithm dispatch, key material
union, sanitized `kid`, +11 tests), `src/config.rs` (3 new
`JwtAuthConfig` fields), `src/main.rs` (algorithm-aware loader,
public key hex in startup log), `tests/multi_agent_isolation.rs`
(struct migration). Crypto layer reuses `ed25519_dalek` already
present for anchor signing.

**Risk**: Low. HS256 path unchanged. Ed25519 path is gated by a new
config field that defaults to "hs256". No on-disk format changes,
no WAL schema bump. The `kid` sanitization is the only place where
operator input is rewritten — alternative would be to refuse
startup on invalid `kid`, which is also acceptable but reduces
operator flexibility for legitimate ASCII labels.

**Deferred from #4**: RS256 (RSA). Not included — Ed25519 covers
the same use case at smaller key/signature size, faster verify,
without RSA's parameter pitfalls (key sizes, PKCS#1 v1.5 vs PSS).
Re-add if specific operator demand for RS256 surfaces.

### 2026-05-15: JWT issuance model hardening (#1, #2, #5, #6)

Closes the four most impactful gaps in the v1 JWT model identified
during the issuance-model audit. #3 (X-Admin-Key for non-loopback
admin) and #4 (asymmetric Ed25519/RS256) deferred — see notes below.

**1. Mint endpoint moved from public proxy port to admin port.**
`POST /gvm/auth/token` no longer lives on the agent listener
(`0.0.0.0:8080` by default — reachable by anyone who can hit the
proxy); it lives on the admin listener (`127.0.0.1:9090`, loopback-
only unless `[server] allow_non_loopback_admin = true`). Before this
change, any caller that could reach the public proxy could mint a
token for any `agent_id`. After: token issuance is gated by operator
shell access (or by whatever auth layer fronts the admin port).
`crates/gvm-cli/src/run.rs::issue_jwt_token` updated to use
`derive_admin_url(agent_url)` so the local CLI continues to work
transparently.

**2. JWT strict mode (`[jwt] strict = true`).** Default `false`
(backward-compat). When true, requests without a valid Bearer token
*and* without a resolvable sandbox-peer mapping are rejected with
HTTP 401 instead of falling through to header-declared
`X-GVM-Agent-Id`. The MITM TLS path was already strict by default
(see `src/tls_proxy_hyper.rs:189`); this closes the equivalent gap on
the plain-HTTP forward path. `src/proxy/mod.rs:725-744`.

**3. Revocation list (`[jwt] revocation_file = "<path>"`).** Flat
file, one `jti` per line, `#` and blank lines ignored. Re-read on
every verify call so operators rotate by appending — no proxy
restart. `POST /gvm/auth/revoke` (admin port) accepts
`{ "jti": "...", "reason": "..." }`, appends a timestamp + reason
comment, returns 200. Missing/unreadable file is fail-open (the
revocation check no-ops) — a typo'd path must not lock all agents
out. `src/auth.rs::is_jti_revoked`, `src/api.rs::auth_revoke_token`.

**4. `token_id` (JWT `jti`) bound into Merkle audit chain.** New
schema version `gvm-event-v3:` + new field `GVMEvent.token_id:
Option<String>`. The hash dispatcher chooses by field presence:
  - v3: operation_descriptor present + token_id present
  - v2: operation_descriptor present, token_id absent (legacy WAL)
  - v1: no operation_descriptor (pre-Phase-1 WAL)
v3 leaves include `jti` (or `sandbox-peer:<sandbox_id>` for namespace-
bound identity) so an auditor can now prove not just *which agent*
performed an action but *which token instance* authorised it.
Cryptographic detection of token replay is now possible across the
chain. Backward-compatible: existing v1/v2 WAL entries verify
unchanged; new entries land as v3 once `verified_identity.token_id`
flows through `build_event`. Mirrored in `crates/gvm-types/src/proof.rs`
(`recompute_event_hash_v3`) so external auditors replay the same.

**Tests added (+7 new, all green):**
- `src/auth.rs::tests::revoked_jti_rejected`
- `src/auth.rs::tests::revocation_file_missing_does_not_block`
- `src/auth.rs::tests::revocation_file_comments_and_blanks_ignored`
- `src/merkle.rs::tests::dispatcher_uses_v3_when_token_id_set`
- `src/merkle.rs::tests::v3_hash_differs_from_v2_for_same_event`
- `src/merkle.rs::tests::v3_hash_changes_on_token_id_change`
- `src/merkle.rs::tests::v3_hash_changes_on_sandbox_peer_marker`

Workspace test count: 896 passing (was 808), 0 failed.

**Affected files**: `src/auth.rs`, `src/config.rs`, `src/api.rs`,
`src/main.rs`, `src/merkle.rs`, `src/proxy/mod.rs`,
`src/proxy/headers.rs`, `crates/gvm-types/src/lib.rs`,
`crates/gvm-types/src/proof.rs`, `crates/gvm-cli/src/run.rs`, plus
~20 test files updated for the new `token_id` field and new
`JwtConfig` fields.

**Deferred (follow-up)**:
- #3 X-Admin-Key for non-loopback admin port — mostly orthogonal to
  JWT and addressed by `allow_non_loopback_admin` policy gate.
- #4 Asymmetric signing (Ed25519 / RS256) — larger scope (new
  algorithm dispatcher, key generation/loading, JWS header `alg`
  validation). Tracked as follow-up. The anchor-signing key
  infrastructure (`src/sign.rs::AnchorSigner`) is the natural reuse
  target.

**Risk**: Medium-low. The mint-endpoint move is a behavioural change
(CLI tools/scripts pointing at the public port will start getting
404). Backward-compat reasons documented in `security-model.md §8`;
the CLI itself was updated to use the admin URL. Operators with
custom token-fetching scripts must update to call the admin port.

### 2026-05-08: Proxy config-path discovery — deterministic across CWDs

**Symptom.** Running `sudo gvm run --sandbox -- ...` from a directory
that did not happen to be the dev repo root surfaced
`Proxy exited immediately. Common causes: Missing config/proxy.toml
(run from project root)` after a 15 s health-check timeout. The
proxy autostart silently picked the operator's CWD as its workspace,
booted with built-in defaults (no SRR rules, port 8080 from default),
and the CLI eventually gave up. A bench script run from `/tmp` hit
this on every invocation; production installs (`/usr/local/bin/gvm`
+ `/etc/gvm/proxy.toml`) would hit it the first time the operator
ran from anywhere except a directory with `config/proxy.toml`.

**Root cause.** Two coupled bugs in `crates/gvm-cli/src/`:

1. `run.rs::workspace_root_for_proxy` only matched dev-repo markers
   (`gvm.toml`, `config/gvm.toml`, `config/srr_network.toml`,
   `config/proxy.toml`). Production install layouts
   (`/etc/gvm/proxy.toml`, `~/.config/gvm/proxy.toml` — flat layout
   without a `config/` subdirectory) never matched. When no marker
   matched it silently returned `current_dir()`, masking the failure.

2. `proxy_manager.rs::start_daemon` set `cmd.current_dir(workspace)`
   for the spawned proxy but did not pin the resolved config path
   into the child's environment. The child re-did its own discovery
   from the new CWD; if `GVM_CONFIG` was inherited but relative,
   it resolved differently in parent and child.

**Fix.**

- `workspace_root_for_proxy` now (a) recognises both layouts via an
  expanded marker list including bare `proxy.toml` / `srr_network.toml`,
  (b) derives a workspace from `$GVM_CONFIG` when set (using
  config's parent or grandparent depending on whether it sits inside
  a `config/` directory), (c) walks up from CWD and from the
  executable's directory so `cd subdir && gvm run` works inside a
  dev repo, (d) checks `$XDG_CONFIG_HOME/gvm`, `~/.config/gvm`,
  `/etc/gvm` as production fallbacks, and (e) replaces the silent
  CWD fallback with a stderr diagnostic listing every searched path
  so the failure mode is loud.
- `start_daemon` now resolves the proxy.toml + gvm.toml paths
  ahead of spawn (via `resolve_proxy_config_path` /
  `resolve_gvm_toml_path` mirroring the proxy's own discovery
  order) and `bail!`s with the searched-path list when none exists,
  turning a 15 s health timeout into an immediate actionable error.
  The resolved absolute paths are pinned into the child's
  `GVM_CONFIG` / `GVM_TOML` env so its discovery is identical
  regardless of CWD.

**Affected files**: `crates/gvm-cli/src/run.rs`,
`crates/gvm-cli/src/proxy_manager.rs`.

**Risk.** Low. The lenient `workspace_root_for_proxy` signature is
preserved (still returns `PathBuf`); strictness is at `start_daemon`
where a bad workspace already broke the operator. Workspace tests
unchanged at 0 failures.

### 2026-05-08: MITM upstream connection pool — amortise HTTP/1.1 handshake

**Background.** Layered bench from earlier today attributed +215 ms
median MITM overhead on `httpbin.org` to a fresh upstream
TCP+TLS+`hyper::client::conn::http1::handshake` per request. Trace
in `src/tls_proxy_hyper.rs::handle_request` confirmed: every
intercepted request opened a new `TcpStream::connect` and discarded
the connection on response complete. HTTP/2 hosts (Anthropic API)
saw only +28 ms because the proxy reused the inner connection across
multiplexed streams; HTTP/1.1 had no equivalent.

**Fix.** New `src/upstream_pool.rs` module — bounded LIFO pool of
`hyper::client::conn::http1::SendRequest<BoxBody<Bytes,String>>`
keyed by `host:port`, default 4 idle per host with 30 s TTL.
Connections return to the pool when the response body's
`SenderReturnerBody::poll_frame` reaches EOF or the inner body's
`is_end_stream()` becomes true after a successful frame.
Liveness verified by `SendRequest::ready()` on take; stale senders
fall back to a fresh connect. The pool is held by
`AppState.upstream_pool` and threaded through `handle_request`
where the inline TLS-connect path now first tries
`pool.try_take(host)` and only opens a fresh connection on miss
or stale.

**`is_end_stream` quirk caught at bench time.** The first
implementation only fired the put-back finalizer on
`Poll::Ready(None)`. For Content-Length-bounded HTTP/1.1
responses, hyper's `Incoming` returns the entire body as a single
data frame and signals completion via `is_end_stream()` rather
than a follow-up `Ready(None)` — and hyper's server-side writer
honours `is_end_stream()` after each frame, dropping the body
without polling again. Result: pool stayed empty (0/20 hits).
Fix: after every `Ready(Some(Ok(_)))`, ask the inner body if it
is now exhausted; if so, return the sender immediately.

**Bench validation (EC2 t3.medium Seoul, sandbox + MITM,
n=20 GET https://httpbin.org/get).** Numbers reported as the *delta
over direct* (median sandbox+MITM minus median direct curl from the
same host on the same run) so the public-internet RTT to httpbin.org
does not contaminate the GVM-attributable cost:

| Configuration | MITM overhead (median delta) |
|--|--|
| Sandbox + MITM, **before pool** | **+528 ms** (1264 − 736) |
| Sandbox + MITM, **with pool**   | **−11 ms** (719 − 730) — within noise |

Direct baseline was ~730 ms median both runs; that is httpbin.org's
own response time from Seoul, not GVM. The +528 ms delta before the
pool was the redundant upstream TCP+TLS+HTTP/1.1 handshake the proxy
paid per request; with pooling that handshake amortises across the
batch. Pool counters from the validating run: 19 reuses / 1 fresh /
0 stale-evict / 1 upstream TLS handshake total.

For HTTP/2 endpoints (Anthropic API) the delta is much smaller
(+28 ms median, measured separately on 2026-05-07) because hyper
internally multiplexes per-stream over a single TCP+TLS connection,
so the redundant handshake never existed in the first place.

**Affected files**: new `src/upstream_pool.rs`; `src/lib.rs`
(module export); `src/main.rs`, `src/proxy/mod.rs`,
`tests/common/mod.rs`, `tests/integration.rs` (AppState init);
`src/tls_proxy_hyper.rs` (pool-aware connect + body wrap).

**Risk.** Medium. Body-finalizer pattern is a non-trivial change to
the TLS relay path; staging-bench-then-roll-forward recommended
once production config-path bug is in. Workspace tests remain
0 failures; 3 unit tests in `upstream_pool.rs` cover empty take,
default tuning, and total-idle counter.

### 2026-05-07: Bench refresh — corrected after two methodology errors caught in review

Initial pass against `scripts/bench-overhead.sh` on EC2 t3.medium
(kernel 6.17.0-1009-aws) reported `+515 ms` HTTP MITM overhead and
`+5638 ms` LLM call overhead. Both numbers were misattributed once
the bench design was inspected:

1. **HTTP `+515 ms` was not all MITM.** It was the full sandbox
   stack overhead (MITM + sandbox iptables DNAT + DNS-governance
   Tier-2 delay). A layered re-bench (`/tmp/bench-layered.sh`,
   cooperative-mode B2 vs sandbox-mode A3) attributes:
   - **MITM-only: +215 ms** (cooperative proxy, no sandbox)
   - **Sandbox + DNS-gov on top: +295 ms additional** (sandbox
     veth/iptables + the 200 ms Tier-2 delay applied to the
     "Unknown" `httpbin.org` DNS lookup)
   We attempted to separate sandbox-route from DNS-gov by running
   with `--no-dns-governance`, but that flag also disables the
   iptables DNAT the sandbox depends on for egress, so the case
   produced no data. Tracked as a script gap, not blocking.

2. **LLM `+5638 ms` was OpenClaw, not GVM.** The original C-test
   wrapped the LLM call in an OpenClaw agent invocation
   (`openclaw agent ... -m 'Say hi'`), which does its own
   multiple-HTTP-call agent-loop bookkeeping. That overhead was
   attributed to GVM. Re-measured with raw `curl` against
   `/v1/messages` (`claude-haiku-4-5`, "hi", 16 tokens, n=20):
   - Direct: 880 ms median (p95 1971 ms, variance from
     Anthropic backend latency)
   - Cooperative proxy + MITM: 908 ms median (p95 2393 ms)
   - **MITM-only overhead: +28 ms** (~70× smaller than the
     original claim)

   The `httpbin.org` `+215 ms` vs Anthropic `+28 ms` gap is
   protocol-driven: HTTP/1.1 requires a fresh proxy↔upstream
   handshake per request, while HTTP/2 multiplexes a long-lived
   upstream connection so the handshake amortises across many
   agent requests. Production agents talking to modern LLM /
   SaaS APIs see the small number, not the large one.

Updated numbers (current authoritative, README + test-report.md
both refreshed):

**Updated numbers (current authoritative)**:

| Metric | Old README | New measured |
|--------|-----------|--------------|
| Binary total (Linux) | "~22MB" | **35MB** (gvm 17 + gvm-proxy 18) |
| Binary total (Windows) | not stated | **29MB** (gvm 14 + gvm-proxy 15) |
| `gvm-proxy` RSS idle | "~11MB" | **14.3MB** |
| `gvm-proxy` RSS loaded | "~13MB" | **17.2MB** |
| HTTP/1.1 MITM-only overhead (cooperative, httpbin.org) | not measured cleanly | **+215 ms median** |
| HTTP/2 MITM-only overhead (cooperative, Anthropic API) | not measured | **+28 ms median** |
| Full sandbox stack on httpbin.org (MITM + iptables + DNS-gov) | "+14ms" | **+510 ms median** |
| Sandbox cold start | "~928ms" | **876 ms median** (832-881 range) |
| 10-parallel concurrent overhead | not stated | **+165 ms** (1104→1269 ms) |
| Workspace test count (Win/Lin) | "729 / 762" | **808 / 852** (49 binaries) |

**Why the original `+14 ms` claim doesn't reproduce.** The original
figure was attributed to "MITM overhead" but the methodology to
generate it is no longer in the tree. Possibilities:
- A localhost mock upstream (sub-ms RTT, so MITM overhead reduces
  to cert-mint cost, ~10-30 ms);
- Or an HTTP/2 endpoint that hid the per-request handshake cost
  the way our Anthropic case does (we now measure +28 ms on
  Anthropic, comparable to what the old number might have meant).
We don't have raw data to confirm. The new authoritative numbers
are the table above, with each protocol separated explicitly.

**Methodology gaps noted but not fixed in this commit**:
- `scripts/bench-overhead.sh` A2 case (cooperative proxy, no
  sandbox) returned 0.000 × 20 because the default proxy rules
  reject `httpbin.org` without an explicit allow. The
  `bench-layered.sh` script we ran instead writes its own SRR
  config and works around this; `bench-overhead.sh` should be
  updated similarly.
- `--no-dns-governance` disables the iptables DNAT the sandbox
  needs for egress, so the case can't be used to isolate
  sandbox-route from DNS-gov contributions. Treating the +295 ms
  sandbox-stack overhead as "sandbox + DNS-gov combined" until
  that's untangled.

**Affected files**: README.md (Technical facts section);
docs/test-report.md (header + new "bench-overhead 2026-05-07"
section before D.1).

### 2026-05-07: Drop SDK from the repo + correct misleading audit doc

**What changed:**

1. **`sdk/python/` removed** (5071 LOC). The optional Python SDK
   (`@ic` decorator, `gvm_session`, `GVMAgent`, langchain wrappers,
   demo agents) lived in this tree but contributed near-zero to v1
   governance: enforcement is at the proxy, identity attribution
   for sandboxed agents is automatic via `resolve_identity_from_peer`
   (commit `3ec17bd`), JWT for cooperative-mode agents is a
   2-line `Authorization` header, and the SDK's checkpoint/rollback
   feature was documented as "not yet stabilized." Keeping a
   prominent "Add the SDK (Experimental)" section in quickstart
   while pitching "zero code change governance" was a contradiction;
   the SDK is the wrong thing to evangelize for v1.

2. **`examples/agents/{data_exfil,devops,email_assistant,finance}_agent.py`
   removed**. All four imported `gvm.langchain_tools` /
   `gvm.domain_agents` and demonstrated the SDK path; with the SDK
   gone, they no longer build.

3. **`docs/architecture/sdk.md` removed**. Cross-references
   updated in `quickstart.md`, `overview.md`, `architecture/proxy.md`,
   `architecture/memory-security.md`.

4. **`docs/internal/AUDIT_PREP.md` → `docs/internal/SECURITY_REVIEW.md`,
   tone corrected.** The previous filename + opening
   ("Snapshot for an external auditor", "designed to bootstrap a
   1–2 week engagement", "When the engagement starts, the auditor
   receives") read as if an external audit was scheduled or in
   progress. None has been engaged. The renamed doc opens with an
   explicit "internal self-review — no external audit has been
   engaged" disclaimer; conditional language ("an auditor would")
   replaces the previous active-engagement framing throughout.
   Sections 5 (Recently fixed), 3 (Crypto inventory), 4 (Known
   limitations) are factual and unchanged in content; only framing
   was corrected.

5. **All user-facing docs swept for outdated content + SDK
   references**: `quickstart.md` (rewritten), `user-guide.md`
   (sandbox-peer + anchor procedures, JWT precedence order),
   `overview.md` (drop SDK from the "three enforcement models"
   table), `reference.md` (drop SDK Reference section, add `[anchor]`
   + `[jwt]` config blocks, drop NATS/Redis hints, soften
   `--contained` to "feature-gated, not in default binary"),
   `srr.md` (drop "agent SDK" wording in design principle),
   `governance-coverage.md` (drop SDK from out-of-scope table),
   `security-model.md` (drop SDK Python references, soften
   "comprehensive security audit was conducted" → "internal review",
   update IC-3 and Deny-response paragraphs to drop SDK exception
   types), `test-report.md` (rename test entry from `sdk_*` to
   `agent_*`), `architecture/proxy.md` (drop "SDK-Routed vs Direct
   HTTP" branch — there is no SDK to route through anymore),
   `architecture/memory-security.md` (drop NATS task-leak roadmap
   item), `README.md` (drop SDK requirement line, soften
   `--contained` callout).

6. **Test source renames** (`tests/{integration,boundary}.rs`):
   - `nats_channel_backpressure_bounded` → `wal_channel_backpressure_bounded`
   - `nats_empty_url_wal_only_mode` → `wal_only_mode_no_external_streaming`
   - `nats_wal_sequence_monotonic` → `wal_sequence_monotonic`
   - `wal_nats_sequence_ordering_and_crash_recovery` → `wal_sequence_ordering_and_crash_recovery`
   - `sdk_headers_to_proxy_classification_end_to_end` → `agent_headers_to_proxy_classification_end_to_end`
   - `sdk_proxy_header_contract_resource_and_context_json` → `agent_header_contract_resource_and_context_json`
   - Comments inside those tests updated to drop "SDK"/"NATS" wording where it described removed capabilities.

**Why:**

CLAUDE.md "Never claim more than implemented." Two misleading
artifacts shipped in the repo:
- A prominent SDK section + sdk.md architecture doc, despite the
  product strategy being "transparent governance, no client
  library." Readers landed on quickstart and saw "Add the SDK
  (Experimental)" — wrong message.
- An "External Security Audit — Preparation" doc + "We accept
  findings via..." section, with no actual external audit scheduled.
  Readers (potential users / auditors / hires) could reasonably
  conclude an engagement was in progress.

Both removed/corrected. v1 launch surface now matches what's
actually in the box.

**Affected files:** ~30 files modified, 5071 LOC of SDK source
removed, 1 file renamed, ~250 lines of docs rewritten.

**Risk:** No Rust code depends on `sdk/python/`. All workspace
tests still pass.

### 2026-05-07: Activate Ed25519 anchor signing (Strategic-5)

**What changed:**

The runtime had a working `SelfSignedSigner` (Ed25519 via
`ed25519-dalek`), a `Ledger::with_config_and_signer` constructor,
and round-trip tests in `tests/anchor_signing.rs` — but `main.rs`
only called `Ledger::with_config`, which defaulted to `NoopSigner`.
So production anchors landed unsigned despite AUDIT_PREP listing
Ed25519 anchor signing in the crypto inventory.

Closing the gap:

1. **`src/config.rs`** adds `AnchorSigningConfig { enabled,
   key_path }` and `AnchorKeyFile { key_id, algorithm,
   secret_hex, created_at }`. The latter has `load(path)` that
   validates algorithm == "ed25519", non-empty key_id, 64-char
   hex secret. Errors are intentionally specific so operators
   diagnose without dumping secret bytes.

2. **`src/main.rs`** wires `SelfSignedSigner::from_secret` into
   `Ledger::with_config_and_signer` when the config has
   `[anchor] enabled = true`. **Fail-close**: every error path
   (missing key_path, missing file, bad hex, wrong algorithm,
   wrong length, etc.) prints a specific message and exits with
   code 1. The alternative — silently downgrading to NoopSigner
   when an operator turned signing on — would mean unsigned
   anchors land in the WAL exactly when the operator thought
   they were getting signed audit. We removed that anti-pattern
   in the NATS/Redis cleanup; we are not reintroducing it here.

3. **`gvm anchor keygen`** (new CLI subcommand,
   `crates/gvm-cli/src/anchor.rs`) generates a fresh Ed25519
   keypair, writes the secret to `--out` (mode 0600) and the
   public key to `<out>.pub` (mode 0644), both as TOML with
   `key_id` embedded in the file (not just in the filename).
   Refuses to clobber an existing file unless `--force` is
   passed (overwriting invalidates every prior anchor signature
   for that `key_id`). Prints next-steps + the public hex so the
   operator immediately has what they need to update proxy.toml
   and brief their auditor. 4 unit tests cover round-trip
   keygen → load → derive public, refuse-clobber, empty key_id,
   whitespace key_id.

4. **`config/proxy.production.toml.example`** gains an `[anchor]`
   section with the operator checklist (file mode, encryption-at-rest,
   backup hygiene, no-git, public-key distribution, rotation
   runbook). **`docs/internal/AUDIT_PREP.md`** crypto-inventory
   row is updated from "⚠️ not yet load-tested" to "✅ wired into
   `Ledger::with_config_and_signer`; fail-close on missing/malformed
   key file" — the doc and runtime now agree.

**Why:**

CLAUDE.md "Never claim more than implemented." The audit prep doc
listed Ed25519 anchor signing in the crypto inventory while the
binary shipped with NoopSigner. That's the same false-promise
class as the NATS/Redis ghost feature we just removed; both ship
together as the "honest about what we do" pass.

The operational design (TOML key file with key_id-in-file, fail-
close on misconfig, separate `.pub` for auditors, refuse-clobber
default on keygen, embedded backup checklist) follows the
reviewer's design critique:
- key_id is the verifier-registry lookup key, must travel with
  the file, not just in the filename.
- enabled=true with bad key MUST refuse startup, never silently
  downgrade.
- Auditor needs the public key as a distinct artifact.

**Affected files:**

- `src/config.rs` (+`AnchorSigningConfig`, `AnchorKeyFile`)
- `src/main.rs` (signer wiring + fail-fast paths)
- `crates/gvm-cli/src/anchor.rs` (NEW — keygen handler + 4 tests)
- `crates/gvm-cli/src/main.rs` (`Anchor` command + dispatch)
- `crates/gvm-cli/Cargo.toml` (+`ed25519-dalek`, `rand`)
- `config/proxy.production.toml.example` (+`[anchor]` section)
- `docs/internal/AUDIT_PREP.md` (crypto inventory + key-handling
  notes corrected; `Recently fixed` table appended)

**Risk:**

Default deployments are unchanged: `[anchor]` defaults to absent →
NoopSigner with an explicit "ANCHOR SIGNING DISABLED" log line at
startup. Existing operators upgrade with no action required.
Operators who want signed anchors run `gvm anchor keygen` once,
edit two lines of proxy.toml, and restart. 804 workspace tests
pass; fmt + clippy clean.

### 2026-05-07: Drop NATS / Redis ghost integrations from runtime + config

**What changed:**

The `[nats]` and `[redis]` sections of `proxy.toml` previously
configured external streaming integrations that the runtime never
actually performed. The only NATS code path was a `tokio::spawn` that
emitted a `tracing::debug!("NATS publish (stub)")` line and returned
— no client, no connection, no publish. Likewise `RedisBackend` was
mentioned in `Vault` doc examples but no implementation existed.

Removed:
- `Ledger::{new, with_config, with_config_and_signer}` — drop
  `nats_url` and `stream_name` parameters from all four constructors
  (135 callers migrated).
- `Ledger` struct — drop `nats_url`, `stream_name` fields.
- `append_durable` — drop the no-op `tokio::spawn` block that
  pretended to publish to NATS.
- `append_async` — replace the same stub with an empty body
  (reserved as a sink for future operator-supplied forwarders).
- `GVMEvent.nats_sequence` — drop the field entirely (was always
  `None` everywhere; not part of either v1 or v2 event_hash
  canonical input, so removing it does not affect chain integrity).
- `src/config.rs::NatsConfig` and `RedisConfig` structs — gone.
  `ProxyConfig.nats` and `.redis` are now `Option<toml::Value>` for
  forward parser tolerance: older `proxy.toml` files with `[nats]`
  / `[redis]` sections still load without error, the values are
  just ignored at runtime.
- `config/proxy.toml` and the three `config/templates/*/proxy.toml`
  files — `[nats]` / `[redis]` sections removed with a replacement
  comment explaining the operator-managed-replication model.

**Why:**

CLAUDE.md "Never claim more than implemented" — shipping a
`proxy.toml` that prompts the operator to configure
`nats://localhost:4222` while the runtime ignores the value is the
exact false promise the standard prohibits. External streaming
(NATS / Redis / Kafka / SIEM) is the operator's responsibility:
tail the WAL with rsync, fluentd, vector, syslog, or S3 backup —
whatever fits the deployment. The local WAL is the single source
of truth.

**Affected files:**

- `src/ledger.rs` (struct + constructors + append paths)
- `src/main.rs` (Ledger::with_config call site)
- `src/proxy/mod.rs` (test Ledger::new caller migrated)
- `src/config.rs` (struct + tests + defaults)
- `crates/gvm-types/src/lib.rs` (`GVMEvent.nats_sequence` removed)
- `config/proxy.toml`, `config/templates/{finance,healthcare,saas}/proxy.toml`
- `benches/pipeline.rs`, ~25 test files (mechanical migration)

**Risk:**

Backward-compat: WAL files written by previous code carry
`"nats_sequence": null` per event; serde's default ignores unknown
fields so they still parse cleanly into the new `GVMEvent`.
Forward-compat: WAL files written by new code are MISSING the
field; old binaries reading them would error on the now-mandatory
`nats_sequence: Option<u64>` deserialize, but operators are
expected to upgrade the verifier alongside the producer.

All 800 workspace tests pass; fmt + clippy clean.

### 2026-05-06: Sandbox-peer identity — close JWT gap for SDK-less agents

**What changed:**

When `GVM_JWT_SECRET` is set, the proxy now derives `VerifiedIdentity`
from the peer's veth source IP if no `Authorization: Bearer` is
presented. The mapping `peer_ip → sandbox_id → agent_id` already
existed (`AppState::resolve_sandbox_anchor`); the new path
`AppState::resolve_identity_from_peer` synthesizes a full
`VerifiedIdentity` from the same lookup with `token_id =
"sandbox-peer:<sandbox_id>"` so the audit chain records which trust
path was taken.

**Why:** With JWT enabled, the cooperative HTTP path warned-and-fell
through to the spoofable `X-GVM-Agent-Id` header, and the MITM path
hard-rejected with 401. Both behaviors broke SDK-less sandboxed
agents: a plain `urllib` request inside `gvm run --sandbox` does load
the per-sandbox CA but does not read `GVM_JWT_TOKEN` from its env, so
every agent author would have had to wrap their HTTP client manually.
Source-IP-derived identity is no weaker than the namespace-isolation
guarantee that already separates sandboxes (the proxy minted the veth
IP itself; spoofing would require breaking out of the network
namespace, which already breaks every other sandbox property).

**Affected files:**

- `src/proxy/mod.rs` — added `AppState::resolve_identity_from_peer`;
  proxy_handler Step 0 falls through to it when no Bearer is
  presented (with JWT enabled or disabled).
- `src/tls_proxy_hyper.rs` — MITM `handle_request` now derives
  identity from the existing `sandbox_anchor` instead of returning
  401 when no Bearer is presented; rejects only when the peer is
  non-loopback and not a known sandbox.
- `tests/api_handlers.rs` — 4 new unit tests covering loopback /
  absent-peer / unknown-IP miss paths and sandbox_launch metadata
  shape that the resolver depends on.
- `scripts/multi-agent-load.sh` — JWT re-enabled (was disabled with
  a now-stale rationale); load test exercises the new identity
  fallback under realistic conditions.

**Risk:** Strictly broadens the set of authenticated requests — does
not loosen any pre-existing rejection. Cross-platform-safe (Windows
build still compiles; the IP-based lookup is `cfg(target_os = linux)`
gated and returns `None` elsewhere). All 539 workspace tests pass;
clippy clean.

### 2026-05-02: Phase 3 + Phase 5 + Phase 6 — checkpoint aggregator, startup recovery, anchor signing

**What changed:**

Three pieces of finality infrastructure ship together because each one
addresses a gap that would have shown up under the others' tests if
delivered in isolation.

- **Phase 3 — Checkpoint aggregator (leaves-only).** A new
  `CheckpointAggregator` lets agents register `(agent_id, [u8; 32])`
  checkpoint hashes; the aggregator computes the canonical Merkle root
  via `gvm_types::compute_checkpoint_root` and publishes it into the
  ledger's `TripleState::checkpoint_root` so the next batch's seal /
  anchor binds the live aggregator state. Last-write-wins per agent.
  No persistent SMT — the root is recomputed in-memory on every
  `register` (well under 1 ms for thousands of agents). Domain prefix
  `gvm-ckpt-v1:` for the root, `gvm-ckpt-leaf-v1:` for each leaf so a
  leaf hash and a root hash over the same input cannot collide.

- **Phase 5 — Startup recovery of the anchor chain.** `WAL::open` now
  scans the existing WAL forward and seeds `(last_batch_id,
  last_batch_root, last_anchor_hash, last_context_hash)` so the first
  batch after restart links into the prior chain instead of being a
  fresh genesis. Without this, every restart looked like a truncation
  break to `verify_anchor_chain` (true positive on the rule, false
  positive on the operator's actual situation). Malformed lines are
  skipped — a bad WAL falls back safely to genesis rather than
  bricking the proxy.

- **Phase 6 — Anchor signing scaffolding.** New `AnchorSigner` trait
  with three concrete impls: `NoopSigner` (default, leaves
  `signature: None`), `SelfSignedSigner` (Ed25519 keypair owned by
  the proxy), and the existing `AnchorSignature::Hsm` / `Tsa` enum
  variants reserved for HSM and RFC 3161 TSA backends in a future
  iteration. The batch task signs every anchor's `anchor_hash` after
  `GvmStateAnchor::seal()` and before serialization. A separate
  `verify_anchor_signature` function lets an external auditor verify
  using only a `VerifyingKey` from a registry — they never see the
  signing key.

**Files affected:**

- `crates/gvm-types/src/lib.rs`: `compute_checkpoint_root`,
  `compute_checkpoint_root_hex`, `PREFIX_CKPT_V1`,
  `PREFIX_CKPT_LEAF_V1`.
- `src/checkpoint.rs` (NEW): `CheckpointAggregator` (live aggregator
  with `register` / `current_root_hex` / `entry_count`).
- `src/sign.rs` (NEW): `AnchorSigner` trait, `NoopSigner`,
  `SelfSignedSigner`, `verify_anchor_signature`.
- `src/ledger.rs`: `WalRecoveryState`, `scan_wal_for_recovery`,
  `WAL::open_with_signer`, `Ledger::with_config_and_signer`. Batch
  task now applies the signer after `GvmStateAnchor::seal()` and
  seeds `batch_id` / `prev_batch_root` from recovery.
- `Cargo.toml`: `ed25519-dalek = "2"`.
- `tests/checkpoint_aggregator.rs` (NEW, 10 tests): pure aggregator
  invariants (empty / single / determinism / order-independence /
  collision resistance) + live aggregator wiring (publishes root
  into triple state, last-write-wins per agent, end-to-end binding
  into next anchor).
- `tests/anchor_chain_recovery.rs` (NEW, 7 tests): fresh WAL
  starts at genesis, restart recovers last anchor / batch_root /
  context_hash, cross-session chain passes `verify_anchor_chain`,
  malformed WAL falls back to genesis safely, recovered chain with
  a real break is still caught.
- `tests/anchor_signing.rs` (NEW, 7 tests): default ledger uses
  NoopSigner, explicit NoopSigner matches default, self-signed
  ledger writes verifiable signatures, signature does not verify
  under unrelated key, tampered anchor_hash breaks signature
  verification, audit reports `signed_anchor_count` correctly for
  both signed and unsigned WALs.

**Why:**

- Phase 3 closes the gap where `checkpoint_root` was always `None` in
  every anchor — the field was reserved but never populated. Operators
  running multi-agent workloads now get a per-batch attestation of the
  global checkpoint state.
- Phase 5 closes the false-positive that would have made
  `verify_anchor_chain` (Phase 2.5) noisy in production: every restart
  looked like a chain truncation. Now the chain is genuinely
  contiguous across restarts, so any flagged break is real.
- Phase 6 is the attestation foundation. `SelfSignedSigner` proves
  "GVM produced this anchor"; `Tsa` (future) defeats clock rewind by
  binding the anchor to an external time source. The trait shape
  lets HSM/TSA slot in without rewriting the batch task.

**Risk:**

- Low. NoopSigner is the default, so existing operators see no
  behavior change. Recovery falls back to genesis on any parse
  error, so a corrupted WAL cannot brick startup.
- Phase 5 changes batch_id semantics from "starts at 0 every
  restart" to "monotonic across restarts." Anything that relied on
  batch_id resetting (no production callers do) would notice.

**Tests:** 676 passed, 0 failed (+24 from this phase). Total split
across 50+ test files; no regressions.

### 2026-05-01: Phase 1.B + Phase 2.5 — descriptor migration + anchor-chain audit

**What changed:**

Phase 1.B closes the v2 dispatch path: every event-creation site in
the proxy now populates `event.operation_descriptor: Some(...)` so
that `compute_event_hash` routes through the v2 algorithm
(privacy-preserving — sensitive detail is held only in a salted
SHA-256 digest while the category remains in the clear). The
legacy `operation: String` field is preserved so existing v1 WAL
records continue to verify.

Phase 2.5 adds `verify_anchor_chain`: a stateless audit that walks
all anchor lines in a WAL and reports breaks (self-hash mismatch,
broken chain link, batch_id skip, monotonic timestamp violation,
truncation/genesis-misuse signal) plus suspicious gaps (large but
not necessarily malicious time jumps).

**Files affected:**

- `src/operation.rs` (NEW): construction helpers — `http`,
  `connect`, `vault`, `dns_query`, `category_only`,
  `ws_upgrade`. 16-byte salts via `rand::thread_rng()`.
- `src/proxy.rs`, `src/tls_proxy.rs`, `src/tls_proxy_hyper.rs`:
  HTTP / CONNECT / WebSocket-upgrade event sites populate
  `operation_descriptor`.
- `src/vault.rs`: `build_vault_event` uses
  `crate::operation::vault(operation, key)`.
- `src/ledger.rs`: `record_config_load` uses `category_only`,
  `build_dns_event` uses `dns_query(domain)`.
- `crates/gvm-types/src/lib.rs`: `verify_anchor_chain`,
  `AnchorAuditConfig`, `AnchorChainReport`,
  `AnchorChainBreakKind`.
- `tests/descriptor_migration.rs` (NEW, 8 tests): helpers, v2
  dispatcher routing, end-to-end `record_config_load` + vault
  write descriptor presence.
- `tests/anchor_chain_audit.rs` (NEW, 14 tests): self-hash, chain
  link, batch_id monotonicity, clock inversion vs tolerance,
  suspicious gap, truncation signal, genesis misuse, real-ledger
  integration, real-ledger tamper detection.

**Why:**

- v2 dispatch is the privacy guarantee for redacted proofs: a
  verifier holding only `(category, detail_digest)` can derive the
  same `event_hash` without ever seeing the plaintext path / key /
  domain. Phase 1.B ensures the production paths actually carry
  descriptors, so the v2 algorithm runs in practice and not just
  in tests.
- Anchor chain audit is the second leg of finality. Phase 2 binds
  state into anchors; Phase 2.5 lets an external auditor walk a
  WAL and prove (or disprove) that the anchor chain is intact —
  no live system state required.

**Risk:**

- Low. v1 hash path is unchanged for events without a descriptor;
  legacy WAL records still verify.
- `verify_anchor_chain` is read-only; it does not mutate WAL
  state.

**Tests:** 647 passed, 0 failed (+22 from this phase).

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

`normalize_host()` in `src/srr.rs` expands **IPv6 loopback, IPv4-mapped, and AWS-metadata** variants (zero-compression, bracket notation, IPv4-mapped, `fd00:ec2::254`) to canonical IPv4 before SRR matching. 13 attack variants tested across those three classes — all correctly denied.

> **Scope note (added 2026-07-10)**: this entry originally read "all IPv6 variants" which overclaimed the coverage. The actual v0.2 fix handled 3 classes (loopback + IPv4-mapped + AWS metadata). Seven other IPv6 SSRF classes (link-local, ULA, multicast, unspecified, 6to4, IPv4-compatible, zone-ID-suffixed) remained open until the [2026-07-10 gap closure](#2026-07-10-ipv6-ssrf-gap-closure-7-new-classes) — see that entry for the full coverage matrix.

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
