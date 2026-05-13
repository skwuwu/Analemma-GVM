# GVM vs OPA+Envoy+Docker — Comparison

> Public summary. Full methodology, raw data, and analysis live in
> [`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).
> Bench infrastructure: [`scripts/comparison/`](../scripts/comparison/).

**Status**: methodology v2 (full-stack), results pending EC2 run.

## What This Compares

Three end-to-end stacks, each measured as actually deployed — agent
process running *inside* an isolation boundary, egress intercepted by
the policy plane, audit recorded.

- **Stack A — GVM**: `gvm run --sandbox -- agent`. Kernel-level
  transparent interception via iptables. SRR policy in-process. WAL +
  Merkle + Ed25519 audit by default.
- **Stack B — Envoy + OPA ext_authz**: agent in Docker container with
  `HTTP_PROXY=envoy`. Cooperative interception. Envoy consults OPA over
  gRPC per request. Envoy access log audit.
- **Stack C — Envoy + OPA WASM**: same as B but Rego compiled to WASM,
  evaluated inside Envoy's WASM filter. The architecturally fairest
  policy-engine comparison vs GVM's in-process SRR.

## What This Doesn't Compare

This benchmark covers the GVM-shaped feature set on the AI agent
governance use case. It is **not** a comparison of general-purpose
service mesh capabilities — Envoy ships circuit breaking, retries, load
balancing, gRPC-Web transcoding, mTLS termination, none of which GVM
aims at. Operators who need them have OPA+Envoy as the better choice.

## A Note on Fairness

Stack A intercepts at the kernel (every packet hits an iptables hook);
Stack B/C intercepts at the application layer (curl honours
`HTTP_PROXY`). These are **not the same security guarantee** — an
agent in Stack B/C that ignores `HTTP_PROXY` bypasses; an agent in
Stack A cannot. The benchmark holds *deployment shape* constant
(lightweight, single-host, no service mesh) and lets the *cost* of
each enforcement mechanism speak. If GVM is slower on per-request
latency, the gap is the price of structural enforcement; if it is
faster, that is despite paying that cost. Operators who need
transparent interception on OPA+Envoy add an istio-init iptables
sidecar — which is no longer the lightweight deployment this benchmark
holds constant.

## Dimensions Measured

Five dimensions, chosen to make trade-offs visible:

1. **D1 — Steady-state per-request latency** inside isolation, p50/p95/p99 over 1000 calls. Allow path + Deny path.
2. **D2 — Cold start**, split into:
   - **D2a** — workload (start an isolated agent, time to first request)
   - **D2b** — control plane (start the policy plane, time to listener ready)
3. **D3 — Memory footprint at N=1, 5, 20 idle agents** — exposes per-agent overhead asymmetry between vertical-integrated (Stack A) and composed (Stack B/C) stacks.
4. **D4 — Distribution size** — bytes operator pulls/installs.
5. **D5 — Audit visibility** — decision-to-log latency + whether the log entry is tamper-evident by default.

## Results

> Filled after EC2 run. Each dimension becomes a one-line summary plus
> a link to the internal raw table.

| Dimension | GVM (Stack A) | Envoy+OPA ext_authz (B) | Envoy+OPA WASM (C) |
|---|---|---|---|
| D1 latency p50 (Allow) | TBD | TBD | TBD |
| D2a workload cold start | TBD | TBD | TBD |
| D2b control plane cold start | TBD | TBD | TBD |
| D3 memory @ N=20 | TBD | TBD | TBD |
| D4 distribution size | TBD | TBD | TBD |
| D5 tamper-evident audit | ✓ default | ✗ not default | ✗ not default |

## Reading Guide

Read across each dimension rather than picking a winner overall. The
expected pattern (to be confirmed by data):

- **D1**: Stack A may be slower because of kernel-level interception
  cost. The delta is the price of structural enforcement, not the
  price of the SRR engine — both engines are in-process.
- **D2a (workload cold start)**: Stack A is doing more isolation work
  (namespaces + veth + iptables + seccomp + cgroup) vs Docker
  (namespaces + bridge + cgroup). Expect Stack A to pay a higher cold
  start in exchange for stronger isolation.
- **D2b (control plane cold start)**: a single GVM binary vs two
  Docker images. Expect Stack A faster.
- **D3 (memory scaling)**: the most honest dimension. Vertical
  integration may scale per-agent worse than a shared sidecar. The
  numbers tell operators what to expect at 20+ concurrent agents.
- **D4 (distribution size)**: bundled single binary vs two images.
  Expect Stack A smaller.
- **D5 (audit)**: GVM ships tamper-evident audit by default; OPA+Envoy
  ships text access logs. This is a feature gap, not a latency.

The takeaway is not "GVM is faster." It is "GVM is differently shaped
for the AI agent governance use case, and the trade-offs are quantified
here so an operator can pick the right tool."

## Methodology + Reproducibility

Full methodology, including stack diagrams, fairness rules, the
transparent-vs-cooperative asymmetry, and known limitations:
[`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).

Run instructions: [`scripts/comparison/README.md`](../scripts/comparison/README.md).
