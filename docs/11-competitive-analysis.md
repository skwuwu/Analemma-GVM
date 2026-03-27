# Part 11: Competitive Analysis — GVM vs OPA+Envoy

**Why GVM exists when OPA+Envoy already works**

---

## 11.1 The Obvious Question

OPA (Open Policy Agent) with Envoy sidecar is the industry standard for service-to-service policy enforcement. If GVM is "just a policy proxy," why not use OPA+Envoy?

**Short answer**: OPA+Envoy assumes honest services. GVM assumes adversarial agents.

The threat model is fundamentally different. Microservices are authored by your own engineers, deployed through your CI pipeline, and behave as coded. AI agents are autonomous, prompt-injectable, and can produce arbitrary HTTP requests that no developer anticipated. This distinction drives every architectural decision in GVM.

---

## 11.2 Threat Model Divergence

| Assumption | OPA+Envoy | GVM |
|-----------|-----------|-----|
| Who writes the code | Your engineers | LLM generates actions at runtime |
| Request predictability | Known API contracts | Arbitrary HTTP to any endpoint |
| Trust in metadata | Headers are trustworthy | **Headers may be forged** |
| Failure mode concern | Misconfiguration | Prompt injection, jailbreak |
| Security boundary | Between services | **Between agent and world** |

OPA asks: "Is this service allowed to call that service?"
GVM asks: "Is this agent allowed to do *that* — and is it telling the truth about what 'that' is?"

---

## 11.3 Architectural Differentiators

### 11.3.1 Lie Detection (Cross-Layer Verification)

**OPA+Envoy**: Policy evaluates the request metadata as-is. If the metadata is wrong, the decision is wrong.

**GVM**: Two independent classification engines evaluate every request. Layer 1 (ABAC) trusts the SDK-declared operation. Layer 2 (SRR) inspects the actual HTTP URL, method, and payload. The final decision is `max_strict(Layer1, Layer2)` — the stricter ruling always wins.

```rust
// src/proxy.rs:70-71 — Cross-layer verification
let final_decision = max_strict(srr_decision.clone(), policy_decision.clone());
```

**Attack scenario**: An agent declares `operation="gvm.storage.read"` but sends `POST api.bank.com/transfer`. Layer 1 (ABAC) sees a read operation and allows it. Layer 2 (SRR) sees a wire transfer URL and denies it. `max_strict(Allow, Deny) = Deny`. The lie is caught.

OPA can achieve similar cross-checking if you pass both the SDK-declared operation and the actual HTTP metadata into Rego input — for example, `deny if input.metadata.operation == "read" and input.request.method == "POST" and contains(input.request.path, "/transfer")`. The difference is that GVM provides this as a built-in architectural primitive (`max_strict`) that cannot be accidentally omitted, whereas in OPA it requires the policy author to explicitly write and maintain the cross-check for every relevant operation. This is a convenience and reliability advantage, not an architectural impossibility.

**Implementation status (2026-03)**:
- Layer 1 decisions in the request hot path are currently evaluated by native `PolicyEngine` (`state.policy.evaluate(...)`).
- The Wasm runtime loader exists, but making Wasm the default hot-path evaluator is tracked as roadmap hardening.

---

### 11.3.2 IC Classification (4-State vs Binary)

**OPA+Envoy**: Binary `allow` / `deny`. Every request is either permitted or blocked.

**GVM**: Four-state enforcement with graduated response:

| IC Level | Decision | Behavior | OPA Equivalent |
|----------|----------|----------|----------------|
| IC-1 | Allow | Immediate forward, async audit | `allow` |
| IC-2 | Delay | WAL write → configurable delay → forward | Requires custom Envoy filter |
| IC-3 | RequireApproval | WAL write → block until human approves | Requires custom Envoy filter + approval queue |
| — | Deny | WAL write → unconditional block | `deny` |

The Delay and RequireApproval states are critical for AI agent governance. A "send email" operation is not clearly allow-or-deny — it depends on content, recipient, and context. IC-2 creates a review window (default 300ms) with a guaranteed audit trail. IC-3 escalates to human judgment.

OPA itself can return arbitrary JSON (including `{"decision": "delay", "delay_ms": 300}`), but Envoy's ext_authz protocol only interprets allow/deny. Implementing delay or approval semantics requires a custom Envoy filter that reads OPA's extended response and acts on it — achievable, but significant engineering effort.

---

### 11.3.3 WAL-First Fail-Close Audit

**OPA+Envoy**: Envoy emits access logs asynchronously. If the log pipeline is down, requests still flow. Audit is best-effort.

**GVM**: For IC-2 and IC-3 paths, the WAL (Write-Ahead Log) record is written and fsynced *before* the request is forwarded. If the WAL write fails, the request is **rejected**. Audit is a hard constraint, not a side effect.

```
IC-2 path:
  1. WAL append (fsync) ← If this fails, request is DENIED
  2. Sleep(delay_ms)
  3. Forward to upstream
  4. Update event status
```

**Why this matters**: For irreversible operations (payments, deletions, external messages), "we allowed it but lost the log" is unacceptable. GVM guarantees that every forwarded IC-2/IC-3 request has a durable audit record. This is the same principle as database WAL — no commit without a log entry.

Event status machine prevents phantom records:

```rust
// crates/gvm-types/src/lib.rs
pub enum EventStatus {
    Pending,           // WAL written, action not yet executed
    Executed,          // Forwarded to upstream
    Confirmed,         // Upstream returned success
    Failed { reason }, // Upstream returned error
    Expired,           // Found Pending after crash recovery
}
```

If the proxy crashes between WAL write and upstream response, the Pending entry is marked `Expired` on recovery — explicitly flagging "this action's outcome is unknown."

---

### 11.3.4 API Key Isolation (Layer 3)

**OPA+Envoy**: Services hold their own credentials (environment variables, mounted secrets, vault sidecar). A compromised service has access to its API keys.

**GVM**: The agent **never** holds API keys. Credentials are loaded by the proxy from `secrets.toml` and injected into the request *after* enforcement passes. The proxy also strips any agent-supplied `Authorization` headers before injecting its own, preventing credential smuggling.

```rust
// src/api_keys.rs:111-112 — Strip agent-supplied auth before injection
// This prevents agents from bypassing Layer 3 by smuggling their own credentials.
headers.remove(AUTHORIZATION);
```

**Security guarantee**: Even if an agent's memory is dumped (via prompt injection, debug endpoint, or core dump), no API credentials are exposed. The agent literally does not have them.

---

### 11.3.5 LLM Thinking Trace Extraction

**OPA+Envoy**: No awareness of LLM response structure. Treats all HTTP responses as opaque bytes.

**GVM**: When the proxy processes an IC-2 response from a known LLM provider (OpenAI, Anthropic, Gemini), it performs transport-aware bounded best-effort extraction of reasoning/thinking content. JSON responses are extracted only when `Content-Length` is known and ≤ 256KB; SSE responses are streamed through immediately with a bounded 1MB tap and persisted as an asynchronous WAL trace update on stream completion. This preserves output continuity while still capturing audit-relevant trace data.

```rust
// src/llm_trace.rs:18-22 — Known LLM providers
const LLM_PROVIDERS: &[(&str, &str)] = &[
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("generativelanguage.googleapis.com", "gemini"),
];
```

| Provider | Thinking Field | Extraction Path |
|----------|---------------|-----------------|
| OpenAI | `reasoning_content` | `choices[0].message.reasoning_content` |
| Anthropic | `thinking` blocks | `content[].type=="thinking"` |
| Gemini | `thought` parts | `candidates[0].content.parts[].thought==true` |

Content is truncated to 2KB (UTF-8 boundary safe) to prevent unbounded WAL growth.

**Governance use cases**:
- Post-incident analysis: "What was the LLM thinking when it decided to transfer $50K?"
- Cost attribution: Token usage per agent, per operation, per tenant
- Model compliance: Verify only approved models are being used

No equivalent exists in OPA or Envoy.

---

### 11.3.6 Hierarchical Monotonic Policy

**OPA+Envoy**: Flat policy namespace. Rego packages can be composed, but there is no structural guarantee that a sub-policy cannot override a parent policy.

**GVM**: Three-layer hierarchy with monotonic strictness:

```
Global (most strict) > Tenant > Agent (cannot weaken parent)
```

```rust
// src/policy.rs:93-94
/// ABAC Policy Engine — evaluates operation metadata against hierarchical rules.
/// Hierarchy: Global > Tenant > Agent (lower layers can only be stricter).
```

Policy files are loaded by naming convention (`global.toml`, `tenant-{name}.toml`, `agent-{name}.toml`). A tenant policy can add restrictions but cannot relax global rules. An agent policy can further restrict but cannot relax tenant rules.

OPA can achieve similar hierarchical enforcement through `data.global` imports and Conftest/Styra DAS policy management. GVM's hierarchy is enforced by the TOML loader's merge logic (lower layers can only add restrictions, never relax parent rules), which is simpler to set up but is ultimately a convention enforced at load time — not fundamentally different from an OPA convention enforced by tooling. Both can be misconfigured.

---

### 11.3.7 Payload Inspection (GraphQL/gRPC Defense)

**OPA+Envoy**: Envoy operates at L7 but does not parse request bodies by default. OPA can inspect headers and URL path, but body inspection requires custom plugins or external processing.

**GVM**: SRR rules can match against request body fields, specifically designed for GraphQL `operationName` defense:

```toml
# config/srr_network.toml
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Dangerous GraphQL mutation" }
```

The `max_body_bytes` field provides graceful degradation — if the body exceeds the limit, the rule is skipped (not crashed) and falls through to the next matching rule or Default-to-Caution. This prevents OOM from adversarial payloads while maintaining security for normal-sized requests.

---

### 11.3.8 Default-to-Caution

**OPA+Envoy**: Default behavior is configurable, but most deployments default to allow (to avoid breaking services). An unconfigured endpoint is typically accessible.

**GVM**: Any request that matches no rule gets `Delay(300ms)` — not Allow, not Deny.

```rust
// src/srr.rs:109 — Default decision for unmatched URLs
default_decision: EnforcementDecision::Delay { milliseconds: 300 },
```

This is the conservative middle ground: unknown operations are not broken (they proceed after delay), but they create a guaranteed audit trail and a temporal window for detection. When deploying a new agent that calls an API you did not anticipate, GVM does not silently allow it — it slows it down and records it.

---

### 11.3.9 Agent Sandboxing (OS-Level Isolation)

**OPA+Envoy**: Envoy is a network proxy. It has no opinion about the process executing the request. Process isolation is someone else's problem (Kubernetes, VM, container runtime).

**GVM**: The `gvm-sandbox` crate provides integrated OS-level isolation:

| Primitive | Function |
|-----------|----------|
| User namespace | Unprivileged container creation |
| PID namespace | Process isolation |
| Mount namespace | `pivot_root` to minimal read-only filesystem |
| Network namespace | veth pair + DNAT proxy path (opt-in, process-scoped in v1) |
| seccomp-BPF | ~111 allowed syscalls (default profile) |

The network namespace is the critical piece: `gvm run --sandbox` injects `HTTP_PROXY`/`HTTPS_PROXY` in the child and configures a veth+DNAT path to the proxy endpoint. This gives stronger containment than cooperative proxy mode, while transparent interception parity (`SO_ORIGINAL_DST`, CONNECT, IPv6 hardening) remains roadmap work.

**Implementation status (2026-03)**: `gvm run --sandbox` (Linux-native) and `gvm run --contained` (Docker) are implemented. Containment is opt-in per launched process; workloads not started via `gvm run` remain in cooperative proxy mode. Sandbox launch is fail-fast gated on critical host prerequisites (`kernel.unprivileged_userns_clone=1`, `CAP_NET_ADMIN`, `ip`, `iptables`, `net.ipv4.ip_forward=1`). `gvm run` also performs proxy readiness checks before launch and auto-starts `gvm-proxy` only for localhost targets when the proxy is unavailable.

---

### 11.3.10 SDK Checkpoint/Rollback

**OPA+Envoy**: When a request is denied, the client receives an error. State recovery is the client's problem.

**GVM SDK**: Automatic state checkpointing before IC-2+ operations. On denial, the agent's state is rolled back to the last approved checkpoint with Merkle-verified integrity. The `GVMRollbackError` provides structured context for LLM agents to choose an alternative path.

```python
class MyAgent(GVMAgent):
    auto_checkpoint = "ic2+"  # Checkpoint before IC-2 and IC-3 operations
```

**Token economics**: Without rollback, a denied operation requires re-executing all prior steps from scratch. With rollback, the agent resumes from the last checkpoint. Actual savings depend entirely on where in the workflow the deny occurs and how many steps preceded it — ranging from 0% (deny at step 1) to near-100% (deny at final step of a long workflow). The reference GVM demo (4-step Finance Agent, deny at step 3) shows ~42% savings, but this is a single synthetic scenario and should not be generalized.

---

### 11.3.11 IPv6 Normalization (SSRF Defense)

**OPA+Envoy**: URL matching is literal. `[::1]` and `localhost` and `127.0.0.1` are three different hosts.

**GVM**: SRR normalizes IPv6 addresses before rule matching to prevent SSRF bypass:

```rust
// src/srr.rs:245-252
/// Normalize IPv6 host addresses to their canonical IPv4 equivalents.
/// This prevents SSRF bypass via IPv6 variants:
/// - `[::1]` → `localhost` (IPv6 loopback)
/// - `[::ffff:127.0.0.1]` → `127.0.0.1` (IPv4-mapped IPv6)
/// - `[fd00:ec2::254]` → `metadata.aws.ipv6` (AWS IPv6 metadata)
```

An agent that sends a request to `[::ffff:169.254.169.254]` to bypass a rule blocking `169.254.169.254` (AWS metadata) will be caught — GVM normalizes both to the same canonical form.

---

### 11.3.12 Asymmetric Response Headers

**OPA+Envoy**: The sidecar returns allow/deny. The client knows the result but not the reasoning.

**GVM**: Every response includes governance metadata headers:

```rust
// src/proxy.rs:301-342
X-GVM-Decision:        "Deny"
X-GVM-Decision-Source: "SRR"
X-GVM-Event-Id:        "uuid"
X-GVM-Trace-Id:        "trace-uuid"
X-GVM-Engine-Ms:       "0.3"
X-GVM-Safety-Delay-Ms: "300"
X-GVM-Matched-Rule:    "rule-id"
```

The SDK uses these headers to make intelligent recovery decisions (e.g., `X-GVM-Decision` triggers rollback, `X-GVM-Safety-Delay-Ms` informs the agent of governance overhead). This creates a structured feedback loop between enforcement and agent behavior.

---

## 11.4 Summary Comparison Table

### Tier 1: Architecturally Unique — Would Require Rebuilding GVM

These capabilities require fundamentally different components that OPA+Envoy's architecture does not include. Replicating them means building new systems, not configuring existing ones.

| Capability | OPA+Envoy | GVM | Why |
|-----------|-----------|-----|-----|
| **LLM thinking trace extraction** | Not in scope | OpenAI/Anthropic/Gemini response parsing | Requires protocol-aware response body parsing for multiple LLM providers — fundamentally outside Envoy's scope (Envoy does not inspect response bodies) |
| **Checkpoint/rollback** | Not in scope | Merkle-verified state restore via SDK | Requires deep SDK integration with agent state management — a proxy alone cannot manage agent-side state |
| **Single binary (~17MB release), no K8s** | K8s + OPA server + Envoy sidecar | `cargo run` | OPA+Envoy is a distributed system by design; GVM is a single process. This is the most practical differentiator for VPS/EC2 deployments |

### Tier 2: Significant Engineering Effort on OPA+Envoy

Achievable with custom Envoy filters + OPA extensions + additional infrastructure, but the integration cost is high.

| Capability | OPA+Envoy | GVM | What It Would Take |
|-----------|-----------|-----|-------------------|
| **Cross-layer verification** | Rego can cross-check metadata vs URL | Built-in `max_strict(ABAC, SRR)` | Possible in Rego (~10 lines per operation), but GVM provides it as a default that cannot be accidentally omitted |
| **Graduated enforcement (IC-2/IC-3)** | OPA can return arbitrary JSON; Envoy only interprets allow/deny | Allow/Delay/RequireApproval/Deny | Custom Envoy filter that reads OPA's extended response + timer + approval queue |
| **Fail-close audit** | Best-effort logs | WAL fsync before forward | Separate WAL system + Envoy filter that blocks until WAL confirms |
| **API key isolation** | Service holds keys (Vault sidecar possible) | Proxy injects post-enforcement + strips agent headers | Custom Envoy filter + secrets manager + header stripping logic |
| **Agent sandboxing** | Not in scope | namespace+seccomp+veth+MITM | Separate process manager + network namespace tooling |

### Tier 3: Additional Benefits — Moderate Effort to Replicate

Genuine advantages, but achievable with existing OPA+Envoy primitives or tooling conventions.

| Capability | OPA+Envoy | GVM | Gap |
|-----------|-----------|-----|-----|
| **Hierarchical monotonic policy** | Rego data imports + Conftest/Styra DAS | Global > Tenant > Agent TOML merge | Both are conventions enforced by tooling; GVM's is simpler to set up |
| **Payload inspection** | Custom plugins | Built-in `payload_field` matching | Built-in vs plugin |
| **Default-to-Caution** | Configurable (usually allow) | `Delay(300ms)` on unknown | Default posture difference |
| **IPv6 SSRF defense** | Literal matching | Canonical normalization | Built-in normalization |
| **Response metadata** | Allow/deny only | 7 governance headers | Structured feedback loop |

### Shared Capabilities

| Capability | OPA+Envoy | GVM |
|-----------|-----------|-----|
| Metadata-based policy | Rego rules | ABAC engine |
| URL/method matching | Envoy route rules | SRR engine |

### OPA+Envoy Advantages

OPA+Envoy has substantial strengths that GVM cannot match at its current stage:

| Advantage | Details |
|-----------|---------|
| **Community & maturity** | CNCF graduated project, years of production use at scale (Netflix, Goldman Sachs, Pinterest). Battle-tested failure modes, extensive documentation, large contributor base. GVM is pre-release with a single developer. |
| **Rego language expressiveness** | Rego is a purpose-built policy language with first-class support for partial evaluation, comprehensions, and complex data joins. GVM's TOML-based rules are simpler but far less expressive for complex policy logic. |
| **Ecosystem integration** | Native Kubernetes admission controller, Terraform provider, Kafka authorizer, SQL row filtering, CI/CD pipeline gates. OPA is a general-purpose policy engine that plugs into dozens of systems. GVM is purpose-built for AI agent HTTP governance only. |
| **Operational tooling** | `opa test`, `opa bench`, `opa fmt`, VS Code extension, Styra DAS for enterprise management. GVM's tooling is minimal (CLI + basic dry-run). |
| **General-purpose flexibility** | OPA handles IAM, RBAC, data filtering, admission control, and any domain expressible in Rego. GVM is intentionally narrow — it governs AI agent I/O and nothing else. |

---

## 11.5 When to Use What

**Use OPA+Envoy when:**
- Governing service-to-service communication between trusted microservices
- You need a general-purpose policy engine for Kubernetes admission, IAM, data filtering
- Maturity and community support are priorities
- The "client" code is authored by your team and behaves deterministically

**Use GVM when:**
- The "client" is an AI agent that generates actions at runtime
- You cannot trust the agent's self-reported metadata (prompt injection risk)
- You need graduated enforcement (delay, human approval) beyond binary allow/deny
- Audit must be a hard constraint, not a side effect
- The agent should never hold API credentials
- You need to record *why* the LLM made a decision (thinking trace)
- You need OS-level process isolation for the agent runtime (`gvm run --sandbox` on Linux, `--contained` on Docker)

**The elevator pitch**: OPA is a policy engine for microservices. GVM is a security kernel for AI agents. They solve different problems that happen to share a surface similarity (proxy + policy evaluation).

---

[← Part 10: Architecture Changes](10-architecture-changes.md) | [Part 0: Overview →](00-overview.md)
