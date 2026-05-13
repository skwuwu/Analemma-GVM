# GVM vs OPA+Envoy+Docker — Comparison

> Public summary. Full methodology, raw data, and analysis live in
> [`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).
> Bench infrastructure: [`scripts/comparison/`](../scripts/comparison/).

**Status**: Phase 1 (infrastructure committed). Results pending.

## What This Compares

Three end-to-end stacks providing comparable functionality (HTTP intercept
+ policy decision + workload isolation + audit log) on a single EC2 host:

- **Stack A — GVM**: `gvm-proxy` (in-process SRR) + `gvm` sandbox (namespace + iptables + seccomp) + WAL (Merkle + Ed25519).
- **Stack B — Envoy + OPA ext_authz**: Envoy sidecar consults OPA over gRPC per request. Workload runs in Docker. Audit = Envoy access log.
- **Stack C — Envoy + OPA WASM**: Same as B, but OPA's Rego policy is compiled to WASM and runs inside Envoy. In-process eval — architecturally the fairest 1:1 latency comparison vs GVM.

## What This Doesn't Compare

This comparison covers the GVM-shaped feature set on the AI agent
governance use case. It is **not** a comparison of general-purpose
service mesh capabilities. Envoy ships circuit breaking, retries, load
balancing, gRPC-Web transcoding, JWT validation, mTLS termination —
GVM does not aim at any of these. Operators who need them have
OPA+Envoy as the better choice. This comparison addresses operators
who want the GVM-shaped feature set and want to know whether the
lightweight integration is worth the missing platform-grade features.

## Dimensions Measured

Five dimensions — chosen to make the trade-offs visible rather than
to favour one stack:

1. **Per-request enforcement latency** — hot path, p50/p95/p99 over 1000 requests, with three rule-shape scenarios (first-match Allow, specific-rule Deny, 10K-rule fallthrough).
2. **Cold start** to first enforced request.
3. **Memory footprint** — RSS sum across the stack, idle and loaded.
4. **Distribution size** — bytes to pull/install.
5. **Audit visibility** — time from decision to externally-readable log entry + whether the entry is tamper-evident by default.

## Results

> Filled after EC2 run. Each dimension becomes a one-line summary plus
> a link to the internal raw table.

| Dimension | GVM | Envoy+OPA ext_authz | Envoy+OPA WASM |
|---|---|---|---|
| D1 latency p50 (Allow) | TBD | TBD | TBD |
| D2 cold start | TBD | TBD | TBD |
| D3 memory (idle) | TBD | TBD | TBD |
| D4 distribution size | TBD | TBD | TBD |
| D5 tamper-evident audit | ✓ default | ✗ not default | ✗ not default |

## Reading Guide

When results land, read across each dimension rather than picking a
winner overall. The expected pattern (to be confirmed by data):

- **Hot-path latency is approximately a wash** between GVM and OPA-WASM (both in-process). OPA-ext_authz is meaningfully slower due to RPC.
- **GVM wins on memory, size, cold start (proxy only)**, and audit visibility because the integration is tighter.
- **OPA+Envoy wins on scale-out scenarios** (multi-host policy distribution, Envoy's mature L7 features) — outside the measurement scope but worth naming.

The takeaway is not "GVM is faster" — it is "GVM is differently shaped
for the AI agent governance use case, and the trade-offs are quantified
here so an operator can pick the right tool."

## Methodology + Reproducibility

Full methodology including stack diagrams, equivalent policy in SRR and
Rego, fairness rules, and known limitations: [`docs/internal/comparison-opa-envoy.md`](internal/comparison-opa-envoy.md).

Run instructions: [`scripts/comparison/README.md`](../scripts/comparison/README.md).
