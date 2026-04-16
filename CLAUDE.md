# CLAUDE.md

## Code Language Policy

- All code must be written in English only: comments, logic descriptions, log messages, error messages, variable names, and any other text within the codebase.

## Debugging & Fix Policy

- Never apply superficial fixes that only address symptoms.
- Always identify and fix the root cause of any issue.
- Understand the architectural design intent before making any modifications.

## Documentation Policy

- After any code modification, all related documentation must be updated immediately to reflect the changes.
- When making significant code changes (refactoring, security fixes, architectural modifications), record the change in `docs/internal/CHANGELOG.md` under the Implementation Log section with: date, what changed, why, affected files, and risk.

## GVM Code Standards

Full specification: `docs/internal/GVM_CODE_STANDARDS.md`

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

- **Same input → same decision**: Policy evaluation is pure. No time/cache/history dependence (except token budget, which is explicitly stateful).
- **SRR is the sole enforcement layer**: All governance decisions come from SRR (network pattern matching on actual outbound traffic). No reliance on agent self-declaration.
- **Decision ordering**: Allow(0) < AuditOnly(1) < Delay(2) < RequireApproval(3) < Deny(4). Total, deterministic, documented.
- **No hidden state**: Every decision-relevant input must appear in the WAL event.

### Concurrency

- Prefer channel (ownership transfer) > RwLock (read-heavy) > Mutex (write-heavy)
- Mutex poison → fail-closed (return error), never panic
- Never hold `std::sync::Mutex` across `.await` (deadlock risk). Use `tokio::sync::Mutex` if lock must span await, but never on hot path.
- Never hold two locks simultaneously. Never do I/O under lock.
- Shutdown must flush pending WAL batch.

### Observability

- GVM CLI exposes governance decisions, cost tracking, and audit verification. Application metrics and agent internals are out of scope — use Prometheus and application-level tooling for those.
- **In scope**: Governance decisions (Allow/Delay/Deny, matched rule, decision layer), cost tracking (per-agent LLM token usage, rollback savings, blocked action count), audit (trace chain, WAL integrity verification, event export).
- **Out of scope**: Agent internal state (SDK-only), LLM prompt/response body full text (privacy), infrastructure metrics (CPU/memory — Prometheus/Grafana).
- Every CLI query maps to WAL data — no separate data store required for basic observability.
- Thinking content stored as SHA-256 hash by default (privacy). Raw storage is opt-in only.

### Code Reuse & Anti-Fragmentation

- **Single source of truth**: Before adding new logic, search for existing implementations of the same or similar functionality. Reuse and extend, never duplicate.
- **Enforcement parity**: Any governance logic (SRR, token budget, WAL audit, IC-3 approval) must be implemented in ONE shared function callable from all request paths (HTTP proxy, MITM TLS, future gRPC). Never copy enforcement code between handlers.
- **Interpreter/config detection**: Use shared utility functions (e.g., `detect_interpreter()`, `resolve_host_dns()`). New call sites must call the existing function, not re-implement the logic.
- **Pipeline pattern**: Agent launch flows (cooperative, sandbox, contained) should go through `pipeline.rs` (`pre_launch` → `launch` → `post_exit_audit`). Do not add new launch paths that bypass the pipeline.
- **State file contract**: All sandbox resources (veth, mounts, iptables, cgroups, DNS target) must be recorded in the per-PID state file for deterministic cleanup. Never rely on re-resolving runtime state during cleanup.

### Testing & Docs

- Every security claim needs a test. Every performance claim needs a benchmark.
- Never claim more than implemented (e.g., "AES-GCM verified" not "Merkle verified" if Merkle isn't wired up).
- Known limitations go in `security-model.md` with attack description + planned mitigation.
- **Root cause first**: When a test or feature fails, always diagnose and fix the root cause. Never work around failures with superficial fixes (e.g., retry loops, mode switches, turn-based workarounds that mask the underlying issue). If sandbox mode fails, fix sandbox — don't fall back to cooperative mode and call it "tested".
- **Always test against the latest binary**: Before running any test suite (E2E, stress, sandbox-observability), verify that every Rust artifact is rebuilt from the current source. Stale `target/release/gvm-proxy` or `gvm` binaries from before a recent fix make the test suite measure code that no longer exists in the repo, which produces false failures and wastes hours debugging the wrong layer. The mandatory pre-test ritual on any host (local or remote): (1) `git status` clean or known modifications only, (2) every source file under `src/` and `crates/*/src/` mtime matches the working tree (no missing files from a partial sync), (3) `cargo build --release -p gvm-cli -p gvm-proxy` runs to completion (a `Finished … in 0.0s` line on a host that was supposed to receive new code is a red flag — it means cargo found nothing to compile, usually because a partial scp/tar restore left stale artifacts and missing source). Test scripts should print binary mtime + git rev at startup so a wrong-binary mismatch is loud, not silent.
- **CLI-only testing**: Stress tests and E2E tests must interact with GVM exclusively through CLI commands (`gvm run`, `gvm check`, `gvm reload`, etc.) — never invoke proxy binaries directly, manipulate PID files, or call internal APIs. Tests should simulate real user workflows. Test scripts must never use `tmux`, `nsenter`, `pkill`, or `sudo env` **inside the test script itself** to manage GVM internals — proxy startup, environment setup, and CA management are all handled automatically by `gvm run`. If a test script reimplements GVM internals, it tests the script, not GVM. (This is a hard ban on scripts; the operator running the test **may** use tmux externally to detach the session — see "Long-running sessions" below.)
- **Long-running sessions (EC2 / remote)**: When running `stress-test.sh`, `sandbox-observability-test.sh`, or any pipeline that lasts more than a few minutes on a remote host, **use `tmux`** (or `screen`) to host the shell. Never use `nohup ... &`. `nohup` is banned because we have hit the failure mode repeatedly: SSH disconnect, terminal glitch, or a race at shell exit drops the child before it can install its signal handlers, leaving resources half-configured (`tc netem` rules surviving, `/run/gvm/` stale directories, orphan `gvm-proxy` processes). `tmux` keeps the session alive independently of SSH, lets you reattach to watch progress, and gives a deterministic cleanup path (`tmux kill-session`). `setsid bash ...` is acceptable as a fallback when tmux is unavailable, but tmux is the default for any interactive remote pipeline run.
- **Parent-mount pattern**: Resources that must outlive sandbox child (overlayfs upper layer, staging dirs) must be mounted by the parent before `clone()`. Child inherits via namespace, parent retains access after child exit. Never mount tmpfs inside child namespace for data the parent needs — it is destroyed with the namespace.
- **Transport-layer framing**: MITM relay dispatches on HTTP framing (Content-Length/chunked/EOF), never on Content-Type. SSE, HTML, JSON all use the same chunked parser. Content-Type dispatch caused SSE+chunked streams to hang on keep-alive connections.
- **Keep-alive after enforcement**: Deny / TokenBudget-exceeded responses on MITM keep-alive connections must not close the connection. Agent fallback flows depend on reusing the same TLS session. Break only on systemic errors (classification failure, circuit breaker).
- **Generic solutions over framework-specific fixes**: Never add agent-specific workarounds (e.g., "if OpenClaw then..."). Fix the root cause at the protocol level. If the fix works for any HTTP client, it's correct. If it only works for one agent framework, it's a hack.
