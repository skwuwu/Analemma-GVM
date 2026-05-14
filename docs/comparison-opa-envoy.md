# GVM vs OPA+Envoy+Docker — Comparison

> Public summary. Full methodology, raw data, and analysis live in
> [`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).
> Bench infrastructure: [`scripts/comparison/`](../scripts/comparison/).

**Status**: methodology v2 (full-stack), results pending EC2 run.

## What This Compares

Two end-to-end stacks, each measured as actually deployed — agent
process running *inside* an isolation boundary, egress intercepted by
the policy plane, audit recorded.

- **Stack A — GVM**: `gvm run --sandbox -- agent`. Kernel-level
  transparent interception via iptables. SRR policy in-process. WAL +
  Merkle + Ed25519 audit by default.
- **Stack B — Envoy + OPA ext_authz**: agent in Docker container with
  `HTTP_PROXY=envoy`. Cooperative interception. Envoy consults OPA over
  gRPC per request. Envoy access log audit.

A third candidate — "Stack C: OPA-WASM inside Envoy's WASM filter" —
was planned as the architecturally fairest 1:1 in-process eval
comparison. Verification on EC2 (2026-05-13) revealed that
`opa build -t wasm` produces a module using OPA's own WASM ABI, not
the Proxy-Wasm ABI Envoy's filter expects (Envoy refuses to load with
"Missing or unknown Proxy-Wasm ABI version"). The combination is not a
canonical OPA+Envoy deployment; Stack B is the real production point.

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

| Dimension | GVM (Stack A) | Envoy+OPA ext_authz (B) |
|---|---|---|
| D1 latency p50 Allow (ms) | **7.99** | **2.33** |
| D1 latency p50 Deny (ms) | **7.17** | **1.47** |
| D2a workload cold start (ms, median) | **897** | **448** |
| D2b control plane cold start (ms, median) | **1645** | **673** |
| D3 memory @ N=1 (MB) | **42** | **98** |
| D3 memory @ N=10 (MB) | **253** | **107** |
| D3 per-agent delta (MB) | **~23** | **~1** |
| D4 distribution size (MB total) | **35** | **100** |
| D5 tamper-evident audit | ✓ default (Merkle + Ed25519) | ✗ not default |

### Same-work comparison — D6 + D7 (B brought to feature parity)

What happens when Stack B is configured to do the *same work* GVM
does by default (TLS termination + tamper-evident hash-chain audit
via a bolt-on sidecar):

| Variant | Per-request p50 Allow (ms) | Decision→signed-anchor p50 (ms) | LOC bolt-on |
|---|---|---|---|
| B baseline (HTTP, text log) | **2.33** | — (no signed audit) | 0 |
| **B + TLS** (HTTPS at Envoy) | **8.02** | — (no signed audit) | +100 |
| **B + TLS + hash-chain sidecar** | **8.19** | **3345** | ~180 |
| **GVM (Stack A)** | **7.99** | **27** | 0 (bundled) |

**Key reads:**
- Once Stack B does the same TLS + hash-chain work, **per-request
  latency lands at parity with GVM** (~8 ms each). The ~5 ms "gap"
  in D1 is mostly TLS handshake, not structural-enforcement penalty.
- **Audit recording latency stays ~124× different** — GVM signs
  within ~27 ms (in-process WAL); the bolted-on Envoy file→tail→sign
  path waits ~3.3 s for Envoy's default file-log flush window.
- ~180 LOC of bolt-on (Envoy TLS YAML + openssl certs + Python
  sidecar) is the operator cost of audit-equivalence on OPA+Envoy.

## Reading Guide

Read each dimension; pick the tool that matches your workload.

- **D1 (per-request latency)** — GVM is ~5 ms slower per request. That
  delta is the cost of kernel-level transparent interception
  (iptables DNAT inside the sandbox), not a slow policy engine. An
  adversarial agent in Stack B can bypass by ignoring `HTTP_PROXY`; an
  agent in Stack A cannot. Not the same security guarantee.
- **D2a (workload cold start)** — GVM 897 ms vs Docker 448 ms. The
  difference is the sandbox's extra isolation work (seccomp, iptables,
  per-sandbox MITM CA, veth pair).
- **D2b (control plane cold start)** — GVM 1645 ms vs Envoy+OPA 673 ms.
  Counter-intuitive (single binary vs two containers), explained by
  GVM's audit-init richness (WAL recovery, integrity chain, Ed25519
  key, Merkle setup). The price of bundled tamper-evident audit.
- **D3 (memory scaling)** — the most honest dimension. GVM scales
  linearly at ~23 MB / agent (each sandbox is its own world). OPA+Envoy
  scales sub-linearly at ~1 MB / agent (control plane amortised). At
  N≤3 the bundled stack wins on memory; from N≥4, the composed stack
  wins. Tells operators what to expect at scale.
- **D4 (distribution size)** — 35 MB vs 100 MB (~65% smaller). One
  binary pair vs two Docker images.
- **D5 (audit)** — GVM ships Merkle + Ed25519 tamper-evident audit by
  default; OPA+Envoy ships text access logs. To match, an operator on
  Stack B adds a hashing/signing forwarder — that bolt-on is what
  takes the OPA+Envoy stack out of "lightweight deployment."

The takeaway is not "GVM is faster" (it is not on per-request latency).
It is **"GVM is differently shaped for the AI agent governance use
case, and the trade-offs are quantified per-dimension."** For 1-3
long-lived agents on a single host with tamper-evident audit required
out of the box, GVM is the right tool. For many concurrent agents on
a K8s service mesh where you already operate Envoy and OPA, that
stack is the right tool.

## Methodology + Reproducibility

Full methodology, including stack diagrams, fairness rules, the
transparent-vs-cooperative asymmetry, and known limitations:
[`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).

Run instructions: [`scripts/comparison/README.md`](../scripts/comparison/README.md).
