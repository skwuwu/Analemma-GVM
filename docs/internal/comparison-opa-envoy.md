# GVM vs OPA+Envoy+Docker — Internal Comparison

> Multi-dimensional benchmark and analysis. Raw methodology + data live here;
> a public summary (audience-facing) lives at [`docs/comparison-opa-envoy.md`](../comparison-opa-envoy.md).

**Status**: methodology v2 committed (full-stack design). Results pending EC2 run.

---

## 0. Design Note — Scope Revision

Phase 1 (committed 2026-05-13) measured **proxy-only** — `gvm-proxy` and
`Envoy + OPA` were each invoked from a host-side `curl`, with no sandbox
or container around the client. That measurement is internally consistent
but represents neither stack as actually deployed. GVM is a vertically
integrated product (sandbox + proxy + audit bundled); measuring its proxy
in isolation strips out the integration that *is* the product. The same
asymmetry holds for OPA+Envoy: the canonical deployment runs the agent
inside an isolation boundary that the proxy intercepts.

Methodology v2 (this document) re-scopes the comparison to **full stack
on both sides**: agent runs inside an isolation boundary (`gvm run
--sandbox` for Stack A, `docker run` for Stack B/C), policy enforces on
egress, audit records the decision. This is what an operator actually
deploys, and it is what should be compared. Proxy-only numbers are still
collectible from the same scripts (commented out in `bench.sh`) for
operators who want them.

---

## 1. Why This Comparison

GVM's positioning is that it is a *lightweight alternative* to the OPA+Envoy
stack for the specific use case of AI agent governance. That claim
deserves data. If we are uniformly slower, larger, or more complex than
OPA+Envoy, the positioning is hollow. If we are competitive on some
dimensions and better on others by virtue of bundled scope, the
positioning is defensible.

The comparison also tests the deeper thesis question raised on 2026-05-13
(see CHANGELOG `Removed from this roadmap on 2026-05-11` block): is GVM
architecturally distinct from "OPA+sidecar with extra audit," or is the
underlying mechanism so similar that GVM is best understood as a
specialised OPA+Envoy bundle? Data will not fully answer the question
(scope and threat model also matter), but it will rule out the most naive
form of the critique.

## 2. Stacks Under Test

Three full-stack configurations providing comparable end-to-end functionality
(workload isolation + HTTP intercept + policy decision + forward + audit log)
on a single EC2 host:

### Stack A — GVM (this repository)

```
┌────────────────────────────────────────┐
│  gvm-proxy (host)                      │  policy (SRR in-process)
│  + WAL (Merkle + Ed25519 anchors)      │  + audit (durable)
└──────────────────▲─────────────────────┘
                   │ iptables DNAT
                   │ (transparent intercept)
┌──────────────────┴─────────────────────┐
│  gvm sandbox                           │
│  ├ network namespace + veth            │  workload isolation
│  ├ seccomp-BPF                         │
│  ├ cgroup v2                           │
│  └ agent process (curl loop)           │
└────────────────────────────────────────┘
```

`gvm run --sandbox -- <agent>` is the production-recommended invocation.
The agent inside the sandbox is unaware of the proxy — all egress is
captured by kernel-level iptables DNAT and routed to `gvm-proxy` on the
host. This is **structural enforcement**: the agent cannot opt out.

### Stack B — Envoy + OPA-Envoy plugin (ext_authz over gRPC)

```
┌────────────────┐   gRPC   ┌────────────────┐
│   Envoy (host) │─────────▶│  OPA (host)    │  policy (Rego over RPC)
└────────────▲───┘          └────────────────┘
             │ HTTP_PROXY (cooperative)
             │
┌────────────┴───────────────────────────┐
│   Docker container                     │
│   ├ network namespace + bridge         │  workload isolation
│   ├ cgroup v2                          │
│   └ agent process (HTTP_PROXY=envoy)   │
└────────────────────────────────────────┘
```

Canonical OPA+Envoy deployment. Decision crosses process boundary for
every request. The agent inside the container is **cooperative** — it
honours `HTTP_PROXY` env var. An adversarial agent could bypass by
ignoring the env var (no iptables redirect inside the container without
extra setup). Audit = Envoy access log (no tamper evidence by default).

### Stack C — Envoy + OPA WASM filter (NOT VIABLE — see methodology note)

Originally planned: Rego compiled to WASM, loaded into Envoy's
`envoy.filters.http.wasm` filter for in-process eval. This would have
been the "fairest" 1:1 comparison vs GVM's in-process SRR.

**Discovered during EC2 verification (2026-05-13)**: `opa build -t wasm`
produces a module that uses OPA's own WASM ABI (`eval`,
`opa_eval_ctx_*`, etc.), NOT the Proxy-Wasm ABI that Envoy's WASM filter
expects. Envoy crit-exits with `Missing or unknown Proxy-Wasm ABI
version`. Loading OPA-WASM into vanilla Envoy is not a supported
canonical deployment. Third-party wrappers exist (e.g., Istio's compiler
emits Proxy-Wasm-compatible OPA modules) but require additional
toolchain that operators of "vanilla OPA + vanilla Envoy" do not have.

Honest implication: the canonical OPA+Envoy production deployment is
Stack B (ext_authz over gRPC), with policy decisions crossing a process
boundary per request. The "in-process OPA inside Envoy" framing in
Phase 1 was based on an incorrect assumption about WASM ABI
compatibility. Stack B is the real comparison point; Stack C is dropped.

### Critical asymmetry: transparent vs cooperative interception

Stack A intercepts at the kernel (iptables DNAT inside the sandbox
netns). Every packet pays a netfilter hook cost. Agent cannot bypass.

Stack B/C intercepts at the application layer (curl honours
`HTTP_PROXY`). No kernel cost. An adversarial agent that ignores the
env var bypasses entirely.

**This is not the same security guarantee.** The benchmark compares
"same deployment shape" (lightweight, single-host, no service mesh),
not "same security level." This asymmetry is *the point*: it shows the
cost of structural enforcement vs cooperative enforcement. Operators
who need structural enforcement on the OPA+Envoy side need to add an
istio-init-style iptables-redirect sidecar (out of scope here — that's
no longer the lightweight deployment).

Result reading: if Stack A is slower on D1, the delta is the cost of
that stronger guarantee. If faster, it's despite paying that cost.

## 3. Equivalent Policy

To compare apples-to-apples we need the same logical policy expressed
in both SRR and Rego. The set is intentionally narrow — two rules — so
we measure the engines under their canonical happy path, not the cost
of complex evaluation. We use **IP-based host matching** so neither
stack depends on DNS hijacking or `/etc/hosts` manipulation; the SRR
and Rego rules match on `"172.31.X.X:9999"` literally (the EC2 host's
primary IP + the mock upstream port). The agent inside isolation
makes HTTP calls to that IP:port; policy decides on host + method + path.

| Logical rule | SRR (TOML) | Rego |
|---|---|---|
| Deny POST /transfer | `pattern = "${HOST_IP}:9999/transfer"`, `method = "POST"`, decision Deny | `host == HOST_IP_PORT; path == "/transfer"; method == "POST"` |
| Allow everything else on bench host | catch-all `${HOST_IP}:9999/{any}`, decision Allow | default allow |

The reference artefacts:
- SRR: [`scripts/comparison/srr-bench.toml`](../../scripts/comparison/srr-bench.toml)
- Rego: [`scripts/comparison/policy.rego`](../../scripts/comparison/policy.rego)

The host IP literal is templated at bench-script start time (the
generated SRR + Rego files are written to `scripts/comparison/build/`).
Both engines run with **decision caching disabled** on both sides.

## 4. Dimensions Measured

Five dimensions. Each gets a separate section in §6 (Results).

### D1 — Steady-state per-request latency (inside isolation)

p50/p95/p99 over `n=1000` requests issued from an agent *inside* the
isolation boundary (sandbox for A, container for B/C). The sandbox/
container is started once; the loop runs 1000 curls inside. Cold start
is excluded (measured separately in D2).

Two scenarios:
- **D1a — Allow path**: GET `${HOST_IP}:9999/v1/messages` (matches catch-all allow rule)
- **D1b — Deny path**: POST `${HOST_IP}:9999/transfer` (matches deny rule)

Mock upstream is a Python `http.server` on `0.0.0.0:9999` so it is
reachable from sandbox + container + host. Times reported as the
*delta over baseline direct-curl* (host-side curl directly to mock
upstream, no proxy) so the loopback RTT does not contaminate the
comparison.

> **D1 disclaimer (kept next to the result table in §6):** Stack A
> includes the cost of kernel-level transparent interception (iptables
> DNAT on every packet); Stack B/C uses application-layer cooperative
> proxy (`HTTP_PROXY` env). Not the same security level — the same
> deployment shape. If A is slower, that is the price of structural
> enforcement.

### D2 — Cold start, split into two sub-measurements

The original D2 conflated workload bring-up with control-plane bring-up.
Splitting clarifies which audience each number serves:

- **D2a — Workload cold start.** Time from `start-an-isolated-agent`
  command to the agent's first successful HTTP request. Measured by:
  1. Control plane already running (gvm-proxy up for A, Envoy+OPA up for B/C).
  2. Issue `gvm run --sandbox -- curl ...` (A) or `docker run --rm ... curl ...` (B/C).
  3. Record time from start to first 200/403 response.
  - Stack A pays: sandbox namespace + veth + iptables rules + seccomp + cgroup + agent exec.
  - Stack B/C pays: container netns + bridge + cgroup + agent exec.
  - Stack A is doing more isolation work; expect a measurable delta.
  
- **D2b — Control-plane cold start.** Time from `start-the-proxy-stack`
  command to the listener accepting connections. Measured by:
  1. All processes stopped.
  2. Start `gvm-proxy` (A) or `docker run envoy + docker run opa` (B/C).
  3. Loop curl until first connect succeeds.
  - Both pay daemon-init cost only; no sandbox/container yet.
  - Useful for operators thinking about "restart the policy plane after a config push."

### D3 — Memory footprint with sandbox/container scaling

RSS (`ps -o rss=`) of every relevant process, summed across the stack,
measured at three load points: **N = 1, 5, 20 idle agents**. Idle agents
are `sleep infinity` inside the isolation boundary so memory cost reflects
isolation overhead, not workload variance.

This dimension is where the asymmetry between vertical-integrated GVM
and composed OPA+Envoy shows most honestly:
- **Stack A** scales: 1 × `gvm-proxy` (constant) + N × (sandbox child + per-sandbox kernel structures + per-sandbox MITM CA in process memory).
- **Stack B/C** scales: 1 × Envoy + 1 × OPA (constant) + N × (container init + cgroup + per-container netns) — but the control-plane RSS does not grow per agent.

If GVM scales worse per-agent, the data tells operators what to expect
when running many agents. If comparable, the bundling has no penalty.

### D4 — Distribution size

- GVM: `stat` the production binaries (`gvm` + `gvm-proxy`).
- OPA+Envoy: Docker image sizes (`docker image inspect`).
- Reported as "bytes operator must pull to run the stack."

### D5 — Audit visibility

For one denied request, measure:
- **D5a — Decision-to-log latency**: time from policy decision to a log entry being readable by an external auditor.
- **D5b — Tamper evidence**: is the log entry cryptographically tamper-evident out-of-the-box? (binary yes/no.)

For GVM: WAL append + the seal of the batch containing the event.
For OPA+Envoy: Envoy access log stdout/file or OPA decision log.

This dimension is intentionally biased toward GVM because it measures
something GVM ships by default and OPA+Envoy does not. The bias is *the
point*: it surfaces a scope difference invisible in latency numbers.

## 5. Fairness Rules

1. **Same hardware**: EC2 t3.medium (`Intel Xeon @ 2.5 GHz, 2 vCPU, 4 GB`), Ubuntu 22.04+, kernel 6.17.
2. **Same network**: mock upstream on `0.0.0.0:9999`, reachable from sandbox/container via the host's primary IP. No `/etc/hosts` hijacking, no synthetic DNS.
3. **Same logical policy**: two rules (Deny POST /transfer, Allow everything else on bench host).
4. **No decision cache** on either side.
5. **Same workload shape**: the same agent script runs inside isolation on both sides — a shell loop issuing `n` curls with `-w '%{time_total}'`.
6. **Same isolation primitive class**: both sides use Linux namespaces + cgroups + their own per-instance network namespace. GVM adds seccomp + transparent iptables redirect; Docker does not (default config). This is a real asymmetry — see §2 "Critical asymmetry" — and is documented next to results, not hidden.
7. **Pinned upstream artefact versions**:
   - GVM: `cargo build --release` from current `master`. Bench prints `git rev` + binary mtime.
   - Envoy: `envoyproxy/envoy:v1.32-latest`.
   - OPA: `openpolicyagent/opa:1.16.2-envoy`.
8. **Warm-up**: 100 throw-away requests before each measurement window.
9. **Single-host topology**: no multi-node, no orchestrator. Same on both sides.

## 6. Results

> Filled after EC2 run.

### D1 — Steady-state per-request latency (inside isolation)

| Stack | D1a Allow (p50/p95/p99 ms) | D1b Deny (p50/p95/p99 ms) | n |
|---|---|---|---|
| GVM (Stack A) | **7.986 / 8.378 / 8.956** | **7.168 / 7.928 / 13.345** | 1000 |
| Envoy + OPA ext_authz (Stack B) | **2.330 / 2.450 / 3.657** | **1.465 / 1.558 / 2.244** | 1000 |
| Envoy + OPA-WASM (Stack C) | — (not viable, see §2) | — | — |

*Reading: Stack A is ~3-5× slower per request — the cost of
kernel-level transparent interception (iptables DNAT inside sandbox
netns) + in-process SRR + forward. Stack B has cooperative
HTTP_PROXY interception + gRPC ext_authz hop to OPA. Different
enforcement guarantees, same deployment shape — see §2 "Critical
asymmetry." Deny is faster than Allow on both stacks because no
upstream forward happens after a deny decision.*

*Reading note: Stack A includes kernel-level transparent interception
cost; Stack B/C uses cooperative HTTP_PROXY. Different security
guarantees, same deployment shape — see §2 "Critical asymmetry."*

### D2a — Workload cold start (control plane already up)

| Stack | Time to first response (ms) |
|---|---|
| GVM (`gvm run --sandbox -- curl`) | TBD |
| Docker + OPA ext_authz (`docker run ... curl`) | TBD |

### D2b — Control plane cold start

| Stack | Time to listener ready (ms) |
|---|---|
| GVM (`gvm-proxy` daemon) | TBD |
| Envoy + OPA ext_authz (`docker run envoy` + `docker run opa`) | TBD |

### D3 — Memory footprint scaling

| Stack | N=1 (kB) | N=5 (kB) | N=10 (kB) |
|---|---|---|---|
| GVM | TBD | TBD | TBD |
| OPA + Envoy ext_authz | TBD | TBD | TBD |

### D4 — Distribution size

| Stack | Binaries / Images |
|---|---|
| GVM | TBD MB (gvm + gvm-proxy) |
| Envoy + OPA | TBD MB (envoy image + opa image) |

### D5 — Audit visibility

| Stack | D5a decision→log (ms) | D5b tamper evidence |
|---|---|---|
| GVM | TBD | ✓ Merkle + Ed25519 anchors |
| Envoy + OPA ext_authz | TBD | ✗ not default |

## 7. Analysis

> Filled after results. Sections planned:
>
> - **Where vertical integration wins**: expected D4 (size), D5 (audit), D2b (control plane cold start).
> - **Where vertical integration costs**: expected D3 (per-agent memory grows), possibly D1 (kernel intercept cost).
> - **Where it's a wash**: expected D1 between A and C (both in-process eval after the intercept hop).
> - **What this means for the thesis**: the orchestrator-friendly v0.7 surface converges on OPA+Envoy in *shape*; the data tests whether it converges in *cost across the dimensions an operator actually cares about*.

## 8. Reproducibility

- Bench scripts: [`scripts/comparison/`](../../scripts/comparison/).
- Run instructions: [`scripts/comparison/README.md`](../../scripts/comparison/README.md).
- Raw output: `results/comparison-<timestamp>/` (gitignored; archived
  under [`docs/internal/raw/`](raw/) after each run).
- All stacks pin upstream artefact versions (§5.7) so a future operator
  on a different machine reproduces within hardware variance.

## 9. Known Limitations

1. **Asymmetric interception** — Stack A intercepts transparently
   (kernel iptables), Stack B/C cooperatively (HTTP_PROXY env). Same
   deployment shape, different security guarantees. Documented next
   to every D1 result, not hidden.
2. **OPA-WASM-in-Envoy is not a viable canonical deployment.**
   Originally planned as Stack C ("fairest 1:1 in-process eval
   comparison"), but `opa build -t wasm` produces a module using OPA's
   own WASM ABI, not the Proxy-Wasm ABI that Envoy's WASM filter
   requires. Envoy fails to load with `Missing or unknown Proxy-Wasm
   ABI version`. Third-party compilers (Istio's, etc.) exist but lie
   outside "vanilla OPA + vanilla Envoy." Stack B (ext_authz over gRPC)
   is the canonical production OPA+Envoy deployment and the real
   comparison point.
3. **No multi-host measurement.** Real OPA+Envoy production often has
   OPA bundle distribution, Envoy CDS push, cross-node policy
   propagation latency. Single-host comparison misses these and
   intentionally so — single-host is GVM's design space.
4. **No L7 features that Envoy has and GVM does not.** Circuit
   breaking, retries, load balancing, gRPC-Web, mTLS termination. GVM
   does not aim at these; operators who need them should use OPA+Envoy.
5. **N=20 ceiling on D3.** EC2 t3.medium has 4 GB RAM; N=50 or N=100
   would test resource exhaustion, not steady-state scaling. The N=1/5/20
   sweep captures the per-agent overhead trend.
