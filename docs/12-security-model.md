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

## Known Adversarial Attack Vectors

### 1. Timing Side Channel

**Attack**: An adversary can distinguish Allow (~1-5 ms), Deny (~20-100 ms), and Delay (~300-500 ms) decisions by measuring response latency, gradually mapping the policy ruleset.

**Preconditions**: Network-level timing visibility to the proxy.

**Impact**: Policy rule enumeration — attacker learns which operations are allowed, delayed, or denied.

**Planned mitigation**: Constant-time decision padding (add jitter so all decisions take a uniform base latency ± random noise). Not implemented in v1 because the primary threat (prompt-injected agents) does not perform timing analysis.

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

**Planned mitigation**: Network-level enforcement (iptables/nftables rules that block outbound HTTP except through the proxy port). Container-level enforcement via network policy. SDK-level enforcement already exists (`GVMAgent.create_session()` pre-configures proxy routing), but cannot prevent bypass by determined code.

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

**Planned mitigation**: Signed checkpoint IDs with HMAC. Checkpoint restore requires the proxy to validate that the requested step was genuinely approved. Not implemented in v1 because checkpoint restore is triggered only by GVM denial errors, not by agent code directly.

---

### 6. WAL Periodic Re-verification

**Attack**: If the WAL file is tampered with on disk (e.g., events deleted or modified), the Merkle root chain becomes inconsistent, but this is only detected on the next append — not proactively.

**Preconditions**: Write access to the WAL file on disk.

**Impact**: Audit log integrity compromised silently until next write.

**Planned mitigation**: Background periodic WAL integrity scan (verify Merkle chain from genesis). WAL file permissions should be restricted (`0600`). Not implemented in v1 because the MVP runs locally where disk tampering is outside the threat model.

---

### 7. Vault Key Derivation

**Attack**: The current Vault encryption key is derived directly from the `VAULT_KEY` environment variable without a key derivation function (KDF). If the key has low entropy, brute-force is feasible.

**Preconditions**: Access to the encrypted Vault data and knowledge that no KDF is applied.

**Impact**: Vault contents (sensitive agent state) decrypted.

**Planned mitigation**: Apply PBKDF2 or Argon2id with configurable iteration count before using the key for AES-GCM. Not implemented in v1 because the Vault is a local-development feature and production deployments should use a proper secrets manager.

---

### 8. Import Chain Attacks (Python SDK)

**Attack**: The Python SDK's `from gvm.errors import ...` inside the `except` block of `decorator.py` means that a malicious `gvm/errors.py` on `PYTHONPATH` could intercept error handling.

**Preconditions**: Attacker can place a file on `PYTHONPATH` before the legitimate `gvm` package.

**Impact**: Error handling subverted — denied operations could be silently allowed.

**Planned mitigation**: Move all imports to module top-level (eliminates lazy import attack surface). Use absolute imports with package verification. Low priority because `PYTHONPATH` manipulation requires environment-level access.

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

---

## Versioning

This document will be updated as:
- New attack vectors are discovered or reported
- Mitigations are implemented (entries move to "Fixed" or are removed)
- The threat model boundary expands (e.g., multi-tenant SaaS deployment)

Each mitigation decision is driven by the deployment context — a local development tool has different security requirements than a production financial services proxy.
