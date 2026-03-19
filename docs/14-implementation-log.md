# Implementation Log

> Records significant code modifications, architectural decisions, and refactoring rationale.

---

## 2026-03-19: Vault Trait Abstraction (KeyProvider + VaultBackend)

### Motivation

The vault had hardcoded AES-256-GCM encryption (`VaultEncryption`) and in-memory HashMap storage. This blocked:
- KMS integration (AWS KMS, GCP KMS) for production key management
- Persistent storage backends (Redis, DynamoDB) for state across restarts
- Testing with mock backends

### Changes

**New traits** (`src/vault.rs`):
- `KeyProvider`: `encrypt(&[u8]) → Vec<u8>`, `decrypt(&[u8]) → Vec<u8>`. Synchronous (KMS impls use `spawn_blocking`).
- `VaultBackend`: `get`, `put`, `delete`, `list_keys`, `len`, `contains_key`. Async methods for storage CRUD.

**Renamed**: `VaultEncryption` → `LocalKeyProvider` (implements `KeyProvider`). All security properties preserved (zeroize, error sanitization, random nonces).

**New**: `InMemoryBackend` (implements `VaultBackend`). Extracted from `Vault`'s inline `RwLock<HashMap>`.

**Vault struct**: `Vault<B: VaultBackend = InMemoryBackend>`. Default type parameter means all existing callers (`Vault::new(ledger)`, `Arc<Vault>`) work unchanged. Custom backends via `Vault::with_backends()`.

### Design Decision: Generics vs Dynamic Dispatch

Chose generics with default type parameter over `Box<dyn VaultBackend>` because:
- `async fn` in traits is not dyn-compatible in stable Rust (would require `async-trait` dependency)
- Default type param `= InMemoryBackend` preserves backward compatibility — no caller changes needed
- Zero-cost abstraction: monomorphized at compile time for the default case

### Test Impact

- All 218 existing tests pass unchanged
- Added 2 new tests: `test_in_memory_backend_crud`, `test_in_memory_backend_list_keys`

---

## 2026-03-19: Security/Audit Layer Code Review & Refactoring

### Review Findings

| # | Finding | Location | Verdict |
|---|---------|----------|---------|
| 1 | AuditOnly double WAL write (Pending → Confirmed) | `proxy.rs:447-464` | **KEEP** — intentional crash recovery semantics (docs/04-ledger.md) |
| 2 | Host port-stripping duplicated 4× | `srr.rs:309`, `proxy.rs:650,982`, `llm_trace.rs:41` | **CONSOLIDATE** |
| 3 | Response status check pattern repeated 4× | `proxy.rs:276-282,324-330,429-435,457-463` | **EXTRACT** helper |
| 4 | seccomp default/strict filter ~90% duplicated syscall list | `seccomp.rs:117-370` | **SHARE** base list |
| 5 | `error_response()` vs `governance_block_response()` | `proxy.rs:1019-1098` | **KEEP** — different SDK contracts |
| 6 | AuditOnly first WAL write | `proxy.rs:447-452` | **KEEP** — crash recovery depends on Pending state |

### Changes Applied

#### Change 2: Port-stripping consolidation
- **Before**: `host.split(':').next()` scattered across 4 files
- **After**: Centralized `strip_port()` utility in Target struct
- **Risk**: None — no tests depend on port presence in `Target.host`

#### Change 3: Response status helper extraction
- **Before**: `if response.status().is_success() { "Confirmed" } else { "Failed" }` repeated 4×
- **After**: `response_status_label()` helper function
- **Risk**: None — pure refactor, no behavioral change

#### Change 4: seccomp syscall list sharing
- **Before**: `build_default_filter()` and `build_strict_filter()` each had full syscall list (~45 entries)
- **After**: Shared `base_syscalls()` function, strict filter excludes networking syscalls
- **Risk**: None — no exact count assertions in tests, doc says "~45" (approximate)

---

## 2026-03-19: README Restructure (Feedback-Driven)

### Feedback Analysis

External review identified 10 issues. Changes applied:

| # | Feedback | Action |
|---|----------|--------|
| 1 | IC-3 = Deny without approval mechanism | Added IC-3 gap callout + webhook planned for v1.1 |
| 2 | WAL limitations weaken Merkle audit claim | WAL hardening grouped as v1.1 priority with honest caveat |
| 3 | Mode positioning unclear (sandbox/contained/default) | Added "When to Use Each Mode" table + security boundary explanation |
| 4 | OpenShell comparison biased | Added honest trade-offs (K8s maturity, NVIDIA backing, solo project) |
| 5 | Roadmap too ambitious ("Agentic OS") | Trimmed to v1.0/v1.1/v2.0 concrete, rest as "long-term vision" one-liner |
| 6 | Too many demos (6) | 2 primary (mock + llm), rest collapsed into one-line reference |
| 7 | Rollback mixed with security features | Separated into "Governance" and "Efficiency" subsections |
| 8 | Checkpoint + Merkle synergy not explicit | Added paragraph explaining checkpoint-as-Merkle-leaf property |
| 9 | Single binary advantage under-highlighted | Added visual stack comparison (LLM WAF+OPA+Envoy+K8s vs cargo run) |
| 10 | No ML trade-off honesty | Added "Trade-offs" section — GVM complementary to LLM WAFs, not replacement |

### Removed
- "The Architectural Shift" section (redundant with Thesis)
- "Toward an Agentic OS" framing (premature for alpha)

### Affected Files
- `README.md` — full restructure

---

## 2026-03-19: README Thesis Restructure (Causal Architecture)

### Rationale

The five core strengths (lightweight, zero dependencies, unbypassable, tamper-proof audit, clean rollback) were presented as independent features. In reality they are all consequences of one architectural decision: "infrastructure control over ML classification." Restructured Thesis section to show this causal chain explicitly.

### Changes
- **Thesis section**: Added 5-row table mapping each strength to its root cause ("No ML model to load" → lightweight, etc.)
- **Framing**: "These are not five separate features. They are five consequences of one architectural choice."
- **Stack comparison**: Visual diagram (LLM WAF+OPA+Envoy+K8s vs `cargo run`) moved into Thesis section
- **Trade-off callout**: Added inline note linking to Trade-offs section — makes the ML trade-off visible early
- **Mode guide**: Added "When to Use Each Mode" table with security boundary column
- **IC-3 gap**: Added explicit callout block explaining functional equivalence to Deny
- **Checkpoint/Rollback**: Separated into "Efficiency" subsection with Merkle-leaf connection
- **OpenShell**: Added honest trade-offs (K8s maturity, NVIDIA backing)
- **WAL limitations**: Grouped as v1.1 priority with operational fragility caveat
- **Demos**: 2 primary + 1-line reference for extras
- **Roadmap**: 3 rows (v1.0/v1.1/v2.0) + 1-line long-term vision

### Affected Files (Thesis Restructure)
- `README.md`

---

## 2026-03-19: Tier 1/Tier 2 Separation (SDK Dependency Disclosure)

### Code Analysis Results

Traced `proxy_handler()` code path when no SDK headers present (`X-GVM-Agent-Id` missing → `parse_gvm_headers()` returns `None`):

| Component | Proxy only (Tier 1) | With SDK (Tier 2) | Code reference |
|-----------|--------------------|--------------------|----------------|
| `parse_gvm_headers()` | Returns `None` | Returns `Some(GVMHeaders)` | `proxy.rs:859-949` |
| Layer 1 ABAC | **Skipped entirely** | Evaluated | `proxy.rs:121-156` |
| Layer 2 SRR | ✓ Works (only layer) | ✓ Combined via `max_strict()` | `proxy.rs:158-173` |
| Layer 3 API key | ✓ Works | ✓ Works | `api_keys.rs:84-149` |
| `max_strict()` | **Never called** | Combines Layer 1+2 | `proxy.rs:137` |
| Rate limiting | Shared "unknown" bucket | Per-agent buckets | `proxy.rs:193` |
| WAL events | agent="unknown", op="unknown" | Per-agent, per-operation | `proxy.rs:533-601` |
| Checkpoint/rollback | Not available | ✓ Via `@ic()` + API | `api.rs:458-590` |

### Changes Applied
- **Thesis section**: Added Tier 1/Tier 2 comparison table
- **Forgery detection example**: Split into two subsections (Tier 1: URL block, Tier 2: cross-layer detection)
- **3-layer table**: Added "Requires SDK?" column
- **Efficiency section**: Marked "SDK only"
- **OpenShell comparison**: Noted SDK dependency on forgery detection and rollback

### Rationale
Forgery detection (the headline feature) requires SDK's `@ic()` decorator to provide Layer 1 semantic data. Without it, `max_strict()` is never called. This was not disclosed in previous README versions, creating a false impression that all features work with zero code changes.

### Affected Files
- `README.md`

---

## 2026-03-19: DX Improvements (Build Time + First-Run Experience)

### Problem
- No pre-built binaries: users must `cargo build` from source (~3-5 min first build with wasmtime)
- No CI/CD pipeline (`.github/` directory did not exist)
- First run with missing config files shows a raw error message instead of guiding the user

### Changes Applied

#### Change 1: GitHub Actions CI + Release Workflow
- **Created**: `.github/workflows/ci.yml` — test, clippy, fmt on every push/PR
- **Created**: `.github/workflows/release.yml` — builds pre-built binaries for 5 targets on tag push:
  - `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
  - `x86_64-apple-darwin`, `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
- Packages include `config/` directory for immediate use after download
- Creates GitHub Release with install instructions

#### Change 2: cargo-binstall Support
- **Modified**: `Cargo.toml`, `crates/gvm-cli/Cargo.toml`
- Added `[package.metadata.binstall]` sections with URL template pointing to GitHub Releases
- Users with `cargo-binstall` can now run `cargo binstall gvm-proxy` to skip compilation entirely

#### Change 3: Startup Governance Summary Banner
- **Modified**: `src/main.rs` — added `print_startup_summary()` function
- **Modified**: `src/srr.rs` — added `SrrSummary` struct and `NetworkSRR::summary()` method
- **Modified**: `src/policy.rs` — added `PolicyEngine::summary()` method
- On every proxy start, prints a human-readable summary:
  - Layer 2 (SRR): rule count by type (Deny/Delay/Allow), default decision, sample blocked endpoints
  - Layer 1 (ABAC): global/tenant/agent rule counts, SDK requirement note
  - Operation Registry: core/custom operation counts
  - Layer 3 (API Key): active/passthrough status
  - Request flow diagram

#### Change 4: First-Run Interactive Setup Prompt
- **Modified**: `src/main.rs` — added `offer_first_run_setup()` function
- When both `operation_registry.toml` and `srr_network.toml` are missing (first run):
  - Detects terminal environment (skips prompt in CI/piped contexts)
  - Offers interactive industry template selection (finance/saas/skip)
  - Copies template files to `config/` directory
  - Creates empty `secrets.toml` placeholder
- Non-interactive environments fall through to existing error messages with `gvm init` hint

#### Change 5: First-Run Auto-Restart (seamless flow)
- **Modified**: `src/main.rs` — `offer_first_run_setup()` now returns `bool`
- After template files are copied, `ProxyConfig::load_or_default()` is called again
  to pick up the template's `proxy.toml` settings
- Config → first-run wizard → file copy → config reload → proxy start happens
  in a single unbroken flow with no manual restart needed

#### Change 6: README Policy Discovery Section
- **Modified**: `README.md`
- Added pre-built binary install option (`cargo binstall`) to Quick Start
- Added first-run wizard example output
- Added "Policy Discovery (`--interactive`)" section explaining
  the recommended workflow: template → run agent → review suggestions → approve rules
- Framed interactive mode as the primary policy authoring workflow, not just a debug tool

### Affected Files
- `.github/workflows/release.yml` (new)
- `.github/workflows/ci.yml` (new)
- `Cargo.toml`
- `crates/gvm-cli/Cargo.toml`
- `src/main.rs`
- `src/srr.rs`
- `src/policy.rs`
- `README.md`

---

## 2026-03-19: SDK Composition Refactor (Remove Inheritance Requirement)

### Problem

SDK required `class MyAgent(GVMAgent)` inheritance for any governance. This conflicted
with existing agent frameworks (CrewAI, AutoGen, OpenAI Agents SDK) that have their own
base classes. "Add GVM" meant restructuring the entire class hierarchy.

### Changes

1. **`session.py` (new)**: Standalone module with `configure()`, `gvm_session()`.
   Thread-local header store for `@ic` → `gvm_session()` header injection pipeline.

2. **`decorator.py` (rewrite)**: `@ic` now works on standalone functions, non-GVMAgent
   methods, and GVMAgent methods. Duck-type detection (`_is_gvm_agent()`) avoids circular
   import. Adds unconsumed-header warning when `gvm_session()` is not used inside `@ic`.

3. **`agent.py` (simplified)**: Removed `_apply_gvm_headers()`, `get_pending_headers()`,
   `_register_header_setter()` legacy plumbing. `create_session()` delegates to
   `gvm_session(proxy_url=self._proxy_url)`. GVMAgent is now optional — only needed for
   auto-checkpoint, VaultField state, and rollback.

4. **`__init__.py`**: Added exports: `gvm_session`, `configure`.

5. **`langchain_tools.py`**: Added `@tool @ic(...)` stacking documentation.

6. **`examples/standalone_agent.py` (new)**: Demonstrates governance with zero inheritance.

### SDK Usage Patterns (After)

```python
# Standalone (no inheritance — works with any framework)
from gvm import ic, gvm_session, configure
configure(agent_id="my-agent")

@ic(operation="gvm.messaging.send")
def send_email(to, subject, body):
    session = gvm_session()
    return session.post(...).json()

# LangChain @tool stacking
@tool
@ic(operation="gvm.messaging.send")
def send_email(to: str, subject: str, body: str):
    """Send an email."""
    ...

# GVMAgent (optional — for checkpoint/rollback/state)
class FinanceAgent(GVMAgent):
    auto_checkpoint = "ic2+"
    state = AgentState(balance=VaultField(default=0, sensitivity="critical"))
```

### Documentation Updated
- `README.md`: Added "SDK Integration" section with standalone pattern, LangChain stacking,
  and GVMAgent comparison table. Updated architecture diagram.
- `docs/07-sdk.md`: Rewrote sections 7.1-7.5 for composition-first approach. Added
  standalone session docs (7.4), unconsumed header warning docs, `@tool` stacking examples.

### Affected Files
- `sdk/python/gvm/session.py` (new)
- `sdk/python/gvm/decorator.py`
- `sdk/python/gvm/agent.py`
- `sdk/python/gvm/__init__.py`
- `sdk/python/gvm/langchain_tools.py`
- `sdk/python/examples/standalone_agent.py` (new)
- `README.md`
- `docs/07-sdk.md`
