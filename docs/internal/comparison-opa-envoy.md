# GVM vs OPA+Envoy+Docker — Internal Comparison

> Multi-dimensional benchmark and analysis. Raw methodology + data live here;
> a public summary (audience-facing) lives at [`docs/comparison-opa-envoy.md`](../comparison-opa-envoy.md).

**Status**: Phase 1 (infrastructure committed). Results pending EC2 run.

---

## 1. Why This Comparison

GVM's positioning is that it is a *lightweight alternative* to the OPA+Envoy
stack for the specific use case of AI agent governance. That claim deserves
data. If we are uniformly slower, larger, or more complex than OPA+Envoy,
the positioning is hollow. If we are competitive on some dimensions and
better on others by virtue of bundled scope, the positioning is defensible.

The comparison also tests the deeper thesis question raised on 2026-05-13
(see CHANGELOG `Removed from this roadmap on 2026-05-11` block): is GVM
architecturally distinct from "OPA+sidecar with extra audit," or is the
underlying mechanism so similar that GVM is best understood as a
specialised OPA+Envoy bundle? Data will not fully answer the question
(scope and threat model also matter), but it will rule out the most naive
form of the critique.

## 2. Stacks Under Test

Three stacks, each providing comparable end-to-end functionality (HTTP
intercept + policy decision + workload isolation + audit log):

### Stack A — GVM (this repository)

```
┌────────────┐
│ gvm-proxy  │  ── policy (SRR in-process) + audit (WAL+Merkle+Ed25519)
└─────┬──────┘
      │
┌─────▼──────┐
│ gvm        │  ── sandbox (namespace+veth+iptables+seccomp)
│   sandbox  │
└────────────┘
```

Single binary, in-process SRR evaluation, integrated WAL.

### Stack B — Envoy + OPA-Envoy plugin (ext_authz over gRPC)

```
┌────────────┐    ┌────────────┐
│   Envoy    │───▶│  OPA       │  ── policy (Rego over RPC)
│ (sidecar)  │    │ (gRPC svc) │
└─────┬──────┘    └────────────┘
      │
┌─────▼──────┐
│   Docker   │  ── workload isolation
│ (container)│
└────────────┘
```

Canonical OPA+Envoy deployment. Decision crosses process boundary for
every request. Audit = Envoy access log (no tamper evidence by default).

### Stack C — Envoy + OPA WASM filter (in-process)

```
┌──────────────────┐
│      Envoy       │
│  ┌────────────┐  │
│  │ OPA-WASM   │  │  ── policy (Rego compiled to WASM, in-process eval)
│  └────────────┘  │
└────────┬─────────┘
         │
┌────────▼─────────┐
│      Docker      │  ── workload isolation
└──────────────────┘
```

Performance-optimised OPA+Envoy. In-process eval — the fairest 1:1 latency
comparison vs GVM's in-process SRR. Less commonly deployed in production
(WASM filter is newer + has feature limits), but it is the right
architectural comparison point.

## 3. Equivalent Policy

To compare apples-to-apples we need the same logical policy expressed
in both SRR and Rego. The set is intentionally narrow — three rules — so
we measure the engines under their canonical happy path, not the cost
of complex evaluation. We also run a 10K-rule fallthrough scenario to
test scale.

| Logical rule | SRR (TOML) | Rego |
|---|---|---|
| Allow LLM API | `pattern = "api.anthropic.com/{any}"`, `method = "*"`, decision Allow | `input.host == "api.anthropic.com"` |
| Deny payment endpoint | `pattern = "api.bank.com/transfer"`, `method = "POST"`, decision Deny | `input.host == "api.bank.com"; input.path == "/transfer"; input.method == "POST"` |
| Default Audit-Allow | catch-all, decision AuditOnly | default allow |

The reference artefacts:
- SRR: [`scripts/comparison/srr-bench.toml`](../../scripts/comparison/srr-bench.toml)
- Rego: [`scripts/comparison/policy.rego`](../../scripts/comparison/policy.rego)

Both engines run with **decision caching disabled** on both sides — Envoy
local rate limit / decision cache off, GVM has no decision cache to begin
with. Otherwise the comparison measures cache, not policy evaluation.

## 4. Dimensions Measured

Five dimensions. Each gets a separate section in §6 (Results).

### D1 — Per-request enforcement latency

Hot-path measurement. p50/p95/p99 over `n=1000` curl requests through the
proxy to a local mock upstream. Three scenarios:
- **D1a — Allow path** (first rule match): measures fast path
- **D1b — Deny path** (specific rule match): measures enforcement reaction
- **D1c — 10K-rule fallthrough**: rule-scan cost at scale

Local mock upstream (Python `http.server` returning 200 immediately) so
network jitter and upstream variance do not contaminate the measurement.
Numbers reported as the *delta over a baseline direct-curl-to-upstream*.

### D2 — Cold start to first decision

Wall-clock from `start command issued` to `first successful enforced
request through the stack`. Measured by:
1. Ensure stack is down (proxy stopped, OPA stopped, Envoy stopped, container removed).
2. Start the stack (`gvm run --sandbox -- ...` or `docker compose up + wait`).
3. Loop curl until success.
4. Report time-to-first-200.

This is the operationally honest metric — what an operator waits for to
run their first agent request.

### D3 — Memory footprint

RSS (`ps -o rss=`) of each process, summed across the stack. Measured at:
- **D3a — Idle**: 30 s after stack ready, no traffic
- **D3b — Loaded**: at the end of the D1 benchmark sweep

Both reported. Idle measures resting cost; loaded measures pressure.

### D4 — Distribution size

- Single binary / single image: `stat`/`du` of the production artefact
- Total stack: GVM = single binary; OPA+Envoy = Envoy image + OPA image + dependencies

Reported as "bytes operator must pull to run the stack."

### D5 — Audit visibility

For one denied request, measure:
- **D5a — Decision-to-log latency**: time from policy decision to a log entry being readable by an external auditor (file/socket).
- **D5b — Tamper evidence**: is the log entry cryptographically tamper-evident out-of-the-box? (binary yes/no — not a number.)

For GVM: WAL append + the seal of the batch containing the event.
For OPA+Envoy: Envoy access log stdout/file or OPA decision log stdout/file.

This dimension is intentionally biased toward GVM because it measures
something GVM ships by default and OPA+Envoy does not. The bias is
*the point* — it surfaces a scope difference that would otherwise be
invisible in latency numbers.

## 5. Fairness Rules

1. **Same hardware**: EC2 t3.medium (`Intel Xeon @ 2.5 GHz, 2 vCPU, 4 GB`), Ubuntu 22.04, kernel 6.17.
2. **Same network setup**: local mock upstream (Python `http.server` on `127.0.0.1:9999`).
3. **Same policy semantics**: the three logical rules above, no extras either side.
4. **No decision cache** on either side.
5. **No TLS in D1**: TLS adds variance, both sides handle it equivalently. The MITM/TLS overhead is measured separately in the existing GVM bench (`scripts/bench-overhead.sh`).
6. **Both stacks built from upstream release artefacts**:
   - GVM: `cargo build --release` from current `master`. Print `git rev` + binary mtime at bench start.
   - Envoy: official Docker image `envoyproxy/envoy:v1.32-latest` (pinned at run time).
   - OPA: official `openpolicyagent/opa:0.71.0` (pinned).
7. **Warm-up**: 100 throw-away requests before each measurement window.
8. **Single-host topology**: no multi-node, no service mesh, no orchestrator. Same constraint both sides.

The constraints favour neither stack — they pin the comparison to what
both can do alone, on one host, with declarative policy.

## 6. Results

> Filled after EC2 run. Placeholders below — each subsection becomes a
> table + a one-paragraph reading once data is in.

### D1 — Per-request latency

| Stack | D1a Allow (p50/p95/p99) | D1b Deny (p50/p95/p99) | D1c 10K fallthrough (p50/p95/p99) |
|---|---|---|---|
| GVM (Stack A) | TBD | TBD | TBD |
| Envoy + OPA ext_authz (Stack B) | TBD | TBD | TBD |
| Envoy + OPA-WASM (Stack C) | TBD | TBD | TBD |

### D2 — Cold start

| Stack | Time to first 200 | Notes |
|---|---|---|
| GVM | TBD | sandbox + proxy autostart |
| OPA+Envoy ext_authz | TBD | `docker compose up` + readiness probe |
| OPA+Envoy WASM | TBD | same |

### D3 — Memory footprint

| Stack | Idle RSS (sum) | Loaded RSS (sum) |
|---|---|---|
| GVM | TBD | TBD |
| OPA+Envoy ext_authz | TBD | TBD |
| OPA+Envoy WASM | TBD | TBD |

### D4 — Distribution size

| Stack | Binaries / Images |
|---|---|
| GVM | TBD MB (gvm + gvm-proxy) |
| Envoy + OPA | TBD MB (envoy image + opa image) |

### D5 — Audit visibility

| Stack | D5a decision→log latency | D5b tamper evidence |
|---|---|---|
| GVM | TBD (WAL append + seal) | ✓ Merkle + Ed25519 anchors |
| OPA+Envoy ext_authz | TBD (Envoy access log + OPA decision log) | ✗ not by default |
| OPA+Envoy WASM | TBD | ✗ not by default |

## 7. Analysis

> Filled after results. Sections planned:
>
> - **Where GVM wins**: expected D3 (memory), D4 (size), D5 (audit), possibly D2 (cold start of proxy alone).
> - **Where it's a wash**: expected D1a/D1b (both engines in-process ≈ ns-µs).
> - **Where OPA+Envoy wins (if anywhere)**: possibly D1c (mature index structures vs GVM's linear scan), possibly D2 cold start if container layer caching is in play.
> - **What this means for the thesis**: the orchestrator-friendly v0.7 surface converges on OPA+Envoy in *shape*; the data tests whether it converges in *cost*.

## 8. Reproducibility

- Bench scripts: [`scripts/comparison/`](../../scripts/comparison/)
- Run instructions: [`scripts/comparison/README.md`](../../scripts/comparison/README.md)
- Raw output: `results/comparison-<timestamp>/` (gitignored; archived under
  [`docs/internal/raw/`](raw/) after each run)
- All stacks pin upstream artefact versions (§5.6) so a future operator
  on a different machine reproduces within hardware variance.

## 9. Known Limitations

1. **OPA-WASM filter is less production-deployed** than ext_authz. Stack C
   represents the *theoretical best-case* for OPA+Envoy latency; many
   production deployments do not run it. Stack B (ext_authz) is the
   honest representation of "what most operators have."
2. **No multi-node measurement.** A real production OPA+Envoy deployment
   often has OPA bundle distribution latency, cross-node policy
   propagation delay, Envoy CDS push timing. Single-host comparison
   misses these. They are not relevant to GVM's design space (single
   host is the default), so the omission is intentional but worth noting.
3. **No L7 features that Envoy has and GVM does not.** Envoy is a
   general-purpose proxy — circuit breaking, retries, load balancing,
   gRPC-Web transcoding, JWT validation, mTLS termination. We do not
   benchmark these because GVM does not aim at them. Operators who need
   them have OPA+Envoy as the better choice; this comparison is for
   operators who need the GVM-shaped feature set.
4. **One policy shape per dimension.** Real policy complexity varies.
   We use a narrow shape that both engines handle well to keep the
   comparison about engine cost, not policy complexity.
