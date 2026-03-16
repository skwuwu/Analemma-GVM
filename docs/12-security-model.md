# Security Model & Known Attack Surface

> **Last updated**: 2026-03-16

## Purpose

GVM's primary threat model targets **accidental misuse by LLM-powered agents** — for example, a prompt-injected agent attempting to wire money or delete data. GVM is **not** designed to defend against a skilled adversary with direct network access who is actively trying to reverse-engineer the policy engine.

This document catalogues known adversarial attack vectors for transparency. Each entry describes the attack, its preconditions, and a planned mitigation path. These are **documented and acknowledged**, not ignored — they will be addressed as the deployment context demands.

---

## Threat Model Boundary

| In scope (v1) | Out of scope (v1) |
|---|---|
| Agent makes unintended API calls due to prompt injection | Attacker has root access to the proxy host |
| Agent tries to exfiltrate data via HTTP to unknown hosts | Attacker modifies proxy binary or config at rest |
| Agent escalates privilege by crafting high-IC operations | Nation-state level side-channel exploitation |
| Misconfigured policy allows overly broad access | Physical access to hardware |

---

## Assumption of Trust

GVM assumes the underlying host OS and filesystem are secure. This is consistent with every infrastructure tool that runs as a userspace process (Envoy, OPA, Nginx, HAProxy).

- **Disk integrity**: WAL and config file protection is handled by OS-level file permissions (`0600`) and disk encryption. GVM detects tampering via Merkle chain but does not prevent filesystem writes.

- **Secret management**: GVM Vault encrypts agent state at rest. Master key management should use KMS/HSM in production. GVM is not a secrets manager.

- **Process isolation**: GVM secures the **Agent-to-World boundary**. Host-to-Proxy security is the infrastructure provider's responsibility.

If an attacker has root access to the host, GVM — like any userspace process — cannot provide security guarantees. This is not a limitation specific to GVM; it is a fundamental property of software-based security. Vulnerabilities that require local privilege escalation or filesystem access are not GVM bugs — they belong to the OS, container runtime, or infrastructure layer.

---

## Known Adversarial Attack Vectors

### 1. Timing Side Channel

**Attack**: An adversary measures response latency to infer the enforcement decision type.

**Actual engine latency** (from benchmarks): Allow ~28 ns, Deny ~63 ns. The difference is ~35 ns — indistinguishable from network jitter (typically 0.1-10 ms). End-to-end response times (3-12 ms in demos) are dominated by upstream I/O and safety delays, not engine processing. The only timing signal distinguishable at the network level is the intentional IC-2 Delay (300+ ms), which is by design visible to the agent as enforcement feedback.

**Practical risk**: Extremely low. The 35 ns engine-level difference is 3-5 orders of magnitude below network noise. An agent would need thousands of measurements with sub-microsecond precision to extract a signal — and the governance layer controls the agent's ability to run such measurement programs.

**Status**: Not constant-time. Practically non-exploitable in the current threat model due to rate limiting and sub-100 ns decision variance. Full constant-time padding is a v2 consideration.

---

### 2. Wasm Module Integrity

**Attack**: If the Wasm extension loading path is compromised, a malicious module could be loaded. Currently, SHA-256 hashes are logged but not verified against a whitelist.

**Preconditions**: Write access to the Wasm module directory or config file.

**Impact**: Arbitrary code execution within the Wasm sandbox boundary.

**Planned mitigation**: Cryptographic signature verification (Ed25519) with a trusted publisher key. Module whitelist in `proxy.toml` with hash pinning. Not implemented in v1 because Wasm extensions are an optional feature and the MVP does not load untrusted modules.

---

### 3. Proxy Bypass via Direct HTTP

**Attack**: If the agent's HTTP client is not forced through the proxy (e.g., environment variable `HTTP_PROXY` unset, or agent uses a raw socket), all GVM enforcement is bypassed.

**Preconditions**: Agent code or runtime environment not properly configured.

**Impact**: Complete policy bypass — no enforcement, no audit trail.

**Current (v1)**: Cooperative model — SDK sets `HTTP_PROXY` via `GVMAgent.create_session()`, but enforcement depends on agent cooperation.

**Planned (v2)**: `gvm run` — mandatory interception via Linux network namespace isolation. The agent process runs in an isolated network namespace where all outbound traffic is iptables-redirected to the proxy. No direct internet access is possible:

```
gvm run my_agent.py
  → unshare(CLONE_NEWNET)          # isolated network namespace
  → veth pair: agent ns ↔ host     # controlled network bridge
  → iptables DNAT: *:80,443 → proxy:8080
  → iptables REJECT: everything else
```

This transitions GVM from "SDK proxy model" to "mandatory interception model" (same pattern as Envoy sidecar + iptables redirect). Cross-platform fallback: Docker `--network=container:gvm-proxy` for macOS/Windows.

---

### 4. ReDoS in Policy Regex

**Attack**: A crafted path pattern in `operation_registry.toml` or `srr_network.toml` could cause catastrophic backtracking in the regex engine, leading to CPU exhaustion.

**Preconditions**: Attacker can influence policy configuration (admin-level access).

**Impact**: Denial of service on the proxy.

**Planned mitigation**: Use a regex engine with linear-time guarantees (Rust's `regex` crate already provides this for most patterns). Add pattern complexity validation at config load time. Low priority because policy files are admin-controlled, not agent-controlled.

---

### 5. Checkpoint Step Authorization

**Attack**: An agent could potentially craft a `restore_step` value to roll back to an arbitrary checkpoint, not just the last approved one.

**Preconditions**: Agent can influence the checkpoint restore logic (requires code-level access or a bug in the SDK).

**Impact**: State rollback to an unintended point, potentially replaying approved operations.

**Current mitigation (v0.2)**: Merkle tree verification on checkpoint restore. Each checkpoint's `SHA-256(plaintext)` is a leaf in a per-agent Merkle tree — the same tree structure used for WAL audit batch verification (`merkle.rs`). On save, the proxy appends the leaf and recomputes the tree root. On restore, the proxy generates an O(log N) Merkle proof for the requested leaf and verifies it against the root via `verify_merkle_proof()`. The SDK performs additional client-side hash verification. Tampering with any checkpoint invalidates the root, detected on any subsequent restore.

**Planned (v2)**: HMAC-signed checkpoint IDs with proxy-held signing key. The current Merkle tree prevents content tampering but does not prevent step ID spoofing (which requires code-level SDK access).

---

### 6. WAL Periodic Re-verification

**Attack**: If the WAL file is tampered with on disk (e.g., events deleted or modified), the Merkle root chain becomes inconsistent, but this is only detected on the next append — not proactively.

**Preconditions**: Write access to the WAL file on disk.

**Impact**: Audit log integrity compromised silently until next write.

**Planned mitigation**: Background periodic WAL integrity scan (verify Merkle chain from genesis). WAL file permissions should be restricted (`0600`). Not implemented in v1 because the MVP runs locally where disk tampering is outside the threat model.

---

### 7. Vault Key Derivation

**Attack**: The current Vault (encrypted agent state cache) encryption key is derived directly from the `VAULT_KEY` environment variable without a key derivation function (KDF). If the key has low entropy, brute-force is feasible.

**Preconditions**: Access to the encrypted Vault data and knowledge that no KDF is applied.

**Impact**: Agent state (checkpoints, conversation history) decrypted. Note: Vault does not store API credentials — those are in `APIKeyStore`.

**Planned mitigation**: Apply PBKDF2 or Argon2id with configurable iteration count before using the key for AES-GCM. Not implemented in v1 because the Vault is a local-development feature and production deployments should use a proper secrets manager. See [Roadmap](13-roadmap.md) for full feature tracking.

---

### 8. Agent Identity

**Current (v1)**: Self-declared `X-GVM-Agent-Id` header. Spoofable on shared networks.

**Planned (v2)**: JWT issued by `gvm run` at agent startup, verified by proxy middleware. The agent cannot forge identity without the signing key. Multi-tenant deployments will require JWT or mTLS.

### 9. IPv4-Mapped IPv6 Bypass (Fixed)

**Attack**: Bypass SSRF deny rules by using IPv6 notation (e.g., `[::ffff:127.0.0.1]` instead of `127.0.0.1`).

**Status**: Fixed in v0.2. `normalize_host()` canonicalizes IPv6 loopback, IPv4-mapped, and cloud metadata addresses before SRR matching.

### 10. GraphQL Alias Bypass

**Attack**: Current SRR payload inspection matches the `operationName` field only. An attacker can omit `operationName` or use GraphQL aliases in the query body to bypass detection. For example, a mutation named `TransferFunds` could be aliased as `t: transferFunds(...)` in the `query` field without setting `operationName`.

**Preconditions**: Agent sends requests to a GraphQL endpoint that has payload-based SRR rules.

**Impact**: High-risk GraphQL operations (e.g., `TransferFunds`, `DeleteAccount`) could bypass the Deny rule and fall through to a less restrictive URL-only rule.

**Planned mitigation (v2)**: GraphQL query parser that inspects the `query` field for mutation names, field names, and aliases. Until then, GraphQL endpoints should be treated as elevated risk — consider Deny-by-default for GraphQL endpoints with allowlisted `operationName` values only.

**Why acceptable now**: Current deployments use the operationName-based rules as defense-in-depth behind ABAC policy layer. The ABAC layer evaluates semantic operation names independently of the HTTP payload, so a GraphQL alias bypass only evades Layer 2 SRR, not Layer 1 policy.

---

## Non-Adversarial Issues

The following issues have been identified and **fixed** as they affect normal operation, not just adversarial scenarios:

| Issue | Fix | Status |
|---|---|---|
| Upstream X-GVM-* header poisoning | Strip all `X-GVM-*` headers from upstream responses before injecting proxy headers | Fixed |
| API key strip scope (only `Authorization`) | Also strip `X-API-Key`, `Cookie`, `ApiKey` headers when injecting credentials | Fixed |
| Thread-unsafe `_gvm_header_setter` global | Replace with per-instance context variable approach | Fixed |
| Mock server runs in production | Add `GVM_ENV` guard to prevent accidental production use | Fixed |
| SRR path traversal via encoding | Path normalization with percent-decode, null-byte strip, dot-segment resolution | Fixed (v0.2) |
| Operation name header injection | Regex validation `[a-zA-Z0-9._-]+` on operation names | Fixed (v0.2) |
| IC-1 Allow path sets Confirmed without checking upstream | Check `response.status().is_success()` before setting EventStatus | Fixed |
| Policy field name typo silently ignored | Validate field names at load time; unknown fields cause load error | Fixed |
| Import chain attack (lazy import in except block) | Move `from gvm.errors import ...` to module top-level in `decorator.py` | Fixed |
| Checkpoint Merkle verification hardcoded `"true"` | Real content hash + chain verification; proxy computes SHA-256 of plaintext and chains with previous checkpoint | Fixed (v0.2) |

---

## Audit Results (2026-03-16)

A comprehensive security audit was conducted covering all Rust proxy modules, Python SDK, and configuration files. The following reported items were analyzed and determined to be **non-issues** in the current architecture:

| Reported Item | Analysis | Why Not a Vulnerability |
|---|---|---|
| AES-GCM nonce reuse | 12-byte random nonce, Birthday bound ~2^48 | At 1000 writes/day, collision takes ~770M years. NIST 2^32 limit = 11.7 years at this rate |
| Unbounded X-GVM-Context header | hyper/axum HTTP parser limits header size (~64KB) | Oversized headers rejected at HTTP layer before deserialization |
| Operation name CRLF injection (proxy-side) | `HeaderValue::to_str()` rejects non-visible ASCII (\\r\\n) | Returns `None` → falls back to "unknown". CRLF cannot reach application logic |
| Checkpoint step u64::MAX | `format!("checkpoint:agent:{}", u64::MAX)` = ~50 byte string | No integer overflow, no memory issue. Normal HashMap key |
| SRR body size bypass | Payload rule skip → next rule continues → Default-to-Caution (Delay) | By design: URL-only rules and fallback catch unmatched requests |
| Vault `list_keys()` cross-agent | No API endpoint exposes this function | Internal method; not callable from outside the proxy |
| SDK credential headers pass-through | Proxy `api_keys.rs` already strips Authorization, Cookie, X-API-Key, ApiKey | Enforcement is at proxy (Layer 3), not SDK. Double stripping unnecessary |
| Rate limiter agent ID spoofing | Same root cause as unauthenticated proxy access | Not a separate vulnerability; addressed by deployment-level authentication |
| WAL event forgery / batch reordering | Requires WAL file write access | Covered by existing item #6 (WAL periodic re-verification) |
| Host override config injection | Requires `proxy.toml` write access | Covered by threat model boundary ("Attacker modifies config at rest" = out of scope) |

---

## Deployment Guide

### ABAC Context Attribute Policy

ABAC policy rules only match when the referenced context attribute exists. If an agent omits a context attribute (e.g., `context.amount`), rules conditioned on that attribute will not fire.

**This is by design** — ABAC evaluates declared attributes. However, Layer 2 (SRR) independently inspects the actual HTTP target URL, so even if Layer 1 (ABAC) is bypassed via attribute omission, SRR catches the real operation:

```
Agent omits context.amount → ABAC rule "amount > 500 → Delay" does not fire → Allow
SRR sees POST api.bank.com/transfer → Deny
max_strict(Allow, Deny) = Deny ← SRR catches it
```

**Recommendation**: For critical operations, write SRR rules matching the target URL/method rather than relying solely on ABAC context attributes. If ABAC-only enforcement is required, add a complementary rule:

```toml
# Deny operations that should declare amount but don't
[[rules]]
id = "missing-amount-deny"
field = "operation"
operator = "StartsWith"
value = "gvm.payment"
decision = { type = "Deny", reason = "Payment operations must declare context.amount" }

# Override: allow if amount is present and within limits
[[rules]]
id = "payment-with-amount"
priority = 1  # higher priority (evaluated first)
field = "context.amount"
operator = "Lte"
value = 500
decision = { type = "Allow" }
```

### Single-Endpoint APIs (GraphQL, gRPC)

Layer 2 (SRR) is not limited to URL-only inspection. For APIs that multiplex operations over a single endpoint (e.g., `POST /graphql`, `POST /grpc`), SRR supports **payload-level inspection** via `payload_field` and `payload_match`:

```toml
# Block dangerous GraphQL mutations at the network layer
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds", "DeleteAccount", "DropDatabase"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Blocked GraphQL mutation" }

# Allow all other GraphQL operations with standard delay
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
decision = { type = "Delay", milliseconds = 300 }
```

The proxy parses the request body as JSON and checks the specified field against the match list. This ensures SRR can enforce governance on GraphQL mutations, gRPC methods, and any JSON-RPC style API — not just REST endpoints with distinct URLs.

**Body size limit**: Each rule has a configurable `max_body_bytes` (default 64 KB). Bodies exceeding this limit skip payload inspection but continue to subsequent rules, where URL-only rules or the Default-to-Caution fallback (Delay 300 ms) apply.

---

### Network Binding

The default proxy configuration binds to `0.0.0.0:8080` (all interfaces) for development convenience. In production or shared-network deployments:

```toml
# config/proxy.toml
[server]
listen = "127.0.0.1:8080"  # localhost only
```

For Kubernetes or multi-tenant environments, additionally apply:
- **NetworkPolicy**: restrict ingress to the proxy pod from agent pods only
- **mTLS**: mutual TLS between agent and proxy for identity verification
- **Service mesh**: Istio/Linkerd sidecar for transparent authentication

Without network-level isolation, any process on the same network can send requests with arbitrary `X-GVM-Agent-Id` headers, bypassing agent identity checks.

---

## Versioning

This document will be updated as:
- New attack vectors are discovered or reported
- Mitigations are implemented (entries move to "Fixed" or are removed)
- The threat model boundary expands (e.g., multi-tenant SaaS deployment)

Each mitigation decision is driven by the deployment context — a local development tool has different security requirements than a production financial services proxy.
