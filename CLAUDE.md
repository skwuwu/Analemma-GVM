# CLAUDE.md

## Code Language Policy

- All code must be written in English only: comments, logic descriptions, log messages, error messages, variable names, and any other text within the codebase.

## Debugging & Fix Policy

- Never apply superficial fixes that only address symptoms.
- Always identify and fix the root cause of any issue.
- Understand the architectural design intent before making any modifications.

## Documentation Policy

- After any code modification, all related documentation must be updated immediately to reflect the changes.

## GVM Code Standards

Full specification: `docs/GVM_CODE_STANDARDS.md`

### Security

- **Fail-Close**: Unknown input → Deny or Delay, never Allow
- **No Panic**: Zero `unwrap()` in runtime paths. `Result<T, E>` everywhere. Tests and `main()` only.
- **Error Sanitization**: Internal errors → generic message to caller, details to log only
- **Secret Hygiene**: `zeroize` on drop, no hardcoded keys, no secrets in logs or WAL
- **Input Validation**: All external input (headers, body, config, WAL) is untrusted. Validate at boundary.
- **Crypto**: AES-256-GCM only, SHA-256 only, random 12-byte nonces, domain separation prefix on all hashes

### Error Handling

- **Startup**: `bail!()` on invalid config. Proxy must not start with bad state.
- **Runtime**: `Result<T, E>` always. Graceful degradation (Wasm fails → native fallback with warning).
- **WAL failure**: Reject the request. Never proceed without audit record (fail-close). Use fallback WAL path for resilience. Full disk → auto-rotate. Both paths fail → then reject.
- **Config**: Required settings → startup error. Optional settings → safe default + visible warning.

### Performance

- **Hot path budget**: Policy evaluation < 1µs. No heap alloc, no regex compile, no network calls, no mutex contention on decision path.
- **Amortize**: Pre-compile regex at load. Group commit WAL fsync. Merkle root per batch, not per event.
- **Bound everything**: Channels, caches, response sizes, checkpoint sizes. No unbounded resources in runtime.

### Deterministic Design

- **Same input → same decision**: Policy evaluation is pure. No time/cache/history dependence (except rate limiter, which is explicitly stateful).
- **Layer independence**: ABAC and SRR evaluate independently. Combine only via `max_strict()`. This enables semantic forgery detection.
- **Decision ordering**: Allow(0) < AuditOnly(1) < Throttle(2) < Delay(3) < RequireApproval(4) < Deny(5). Total, deterministic, documented.
- **No hidden state**: Every decision-relevant input must appear in the WAL event.

### Concurrency

- Prefer channel (ownership transfer) > RwLock (read-heavy) > Mutex (write-heavy)
- Mutex poison → fail-closed (return error), never panic
- Never hold `std::sync::Mutex` across `.await` (deadlock risk). Use `tokio::sync::Mutex` if lock must span await, but never on hot path.
- Never hold two locks simultaneously. Never do I/O under lock.
- Shutdown must flush pending WAL batch.

### Testing & Docs

- Every security claim needs a test. Every performance claim needs a benchmark.
- Never claim more than implemented (e.g., "AES-GCM verified" not "Merkle verified" if Merkle isn't wired up).
- Known limitations go in `security-model.md` with attack description + planned mitigation.
