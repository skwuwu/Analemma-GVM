# Implementation Log

> Records significant code modifications, architectural decisions, and refactoring rationale.

---

## 2026-03-28: E2E Mock Server, Security Tests, False-Pass Cleanup

### What Changed

**1. Mock GitHub/httpbin server (scripts/mock-github.py)**
- Created a local HTTP server that simulates GitHub API and httpbin responses.
- Avoids hitting the 60 req/hour unauthenticated GitHub API rate limit during E2E runs.
- Routes: GitHub repos/issues/pulls/actions/contents + httpbin /get and /post echo.
- Proxy host_overrides in proxy.toml are patched at startup to route api.github.com and httpbin.org to the mock; original config is restored in cleanup.

**2. Security tests 61-63 (scripts/ec2-e2e-test.sh)**
- Test 61 (IC-3 Self-Approval Prevention): sandboxed agent attempts TCP connect to admin port 9090. Verifies iptables OUTPUT chain blocks non-proxy ports.
- Test 62 (DNS Exfiltration Logging): sandboxed agent resolves a suspicious domain. Checks WAL/proxy logs for the query. Documents the known gap that DNS (UDP 53) bypasses L7 proxy.
- Test 63 (Config File Manipulation): non-sandboxed agent modifies srr_network.toml (documents cooperative-mode limitation); sandboxed agent verifies config is protected by mount namespace.

**3. Test 17 rewrite (Base64 Exfiltration Detection)**
- Replaced unconditional `pass` with actual proxy-through-WAL test: sends base64 payload to evil-exfil.attacker.com, checks WAL for recorded events, and verifies SRR decision.

**4. False-pass cleanup**
- Changed 7 fallback `pass` calls to `skip` where the underlying assertion did not actually succeed (tests 44e, 46c, 49c, 58c, 60a, 60b, 60d). These previously inflated the pass count.

### Affected Files
- `scripts/mock-github.py` — new file
- `scripts/ec2-e2e-test.sh` — mock server lifecycle, tests 61-63, test 17 rewrite, false-pass fixes
- `config/proxy.toml` — dynamically patched at E2E runtime (backup/restore)

### Risk Assessment
- **Low**: mock server only binds to 127.0.0.1:9999 and is killed on exit. proxy.toml is backed up before modification and restored in cleanup trap. New tests are additive. False-pass-to-skip changes may reduce reported pass count but improve accuracy.

---

## 2026-03-28: E2E Test Reliability Fixes + Enable Overlayfs by Default

### What Changed

Four fixes to improve E2E test reliability and enable overlayfs filesystem governance:

**1. ensure_proxy retry logic (scripts/ec2-e2e-test.sh)**
- Previously, `ensure_proxy` did a single health check after `sleep 3`. If the SRR engine was still loading, tests would fail with confusing errors.
- Fix: Retry up to 10 times (0.5s each), checking both `/gvm/health` and `/gvm/check` (POST with a real SRR request). Proxy is only considered ready when `/gvm/check` returns valid JSON.

**2. Test 50 OSError catch (scripts/ec2-e2e-test.sh)**
- Sandbox filesystem errors surface as `OSError(errno=30)` (read-only filesystem), not `PermissionError`. The Python test blocks for WRITE_SUBDIR and WRITE_SCRIPT only caught generic `Exception`, masking the denied case.
- Fix: All four write test blocks now catch `(PermissionError, OSError)` and print the `_DENIED` variant.

**3. Test 57 admin_listen port conflict (scripts/ec2-e2e-test.sh)**
- The disk-full proxy config omitted `admin_listen`, causing it to bind to the default admin port which conflicts with the main proxy.
- Fix: Added `DISKFULL_ADMIN_PORT` (offset +1010 from DISKFULL_PORT) and `admin_listen` to the config.

**4. Enable overlayfs by default (crates/gvm-cli/src/run.rs)**
- Both `run_binary_sandboxed` and `run_sandboxed` had `fs_policy: None` (legacy mode). This meant `/workspace` was read-only except for `/workspace/output`, which is too restrictive for typical agent workloads.
- Fix: Changed both to `fs_policy: Some(FilesystemPolicy::default())`, enabling overlayfs with Trust-on-Pattern rules on kernel >= 5.11. Falls back to legacy mode on older kernels.

### Affected Files
- `scripts/ec2-e2e-test.sh` — Fixes 1, 2, 3
- `crates/gvm-cli/src/run.rs` — Fix 4

### Risk Assessment
- **Low**: E2E test script changes are non-functional (test reliability only).
- **Medium**: Enabling overlayfs by default changes sandbox behavior. However, `FilesystemPolicy::default()` uses conservative Trust-on-Pattern rules (data files auto-merge, scripts require manual commit, temp files discarded). Falls back gracefully on unsupported kernels.

---

## 2026-03-27: MITM TLS End-to-End Fix — CA Chain, DN Match, Proxy Bypass

### What Changed

Four fixes to make MITM TLS inspection work with `requests`/`curl` in sandbox:

**1. CA Distinguished Name mismatch (Critical)**
- GvmCertResolver reconstructed CA with `CN=GVM Ephemeral CA` but original EphemeralCA had `CN=GVM Ephemeral CA, O=Analemma GVM`. Leaf cert's issuer DN didn't match chain CA's subject → OpenSSL error 20 "unable to get local issuer certificate".
- Fix: Added `O=Analemma GVM` to reconstructed CA's DN.

**2. Original CA cert in TLS chain (Critical)**
- Resolver included its regenerated CA in the chain, but sandbox trust store had the original CA from `/gvm/ca.pem`. Different serial/validity caused mismatch.
- Fix: Parse original CA PEM → DER and include in TLS chain instead of regenerated.

**3. HTTPS_PROXY causes CONNECT bypass (Critical)**
- When `HTTPS_PROXY` is set, Python `requests`/`curl` use CONNECT tunneling → end-to-end TLS → bypasses MITM entirely. Client gets real upstream cert but trust store only has GVM CA.
- Fix: Don't set `HTTPS_PROXY` in sandbox. DNAT 443→8443 handles all HTTPS transparently.

**4. System CA bundle path for certifi (Medium)**
- Python `certifi.where()` returns `/etc/ssl/certs/ca-certificates.crt` which didn't exist in sandbox. Even with `REQUESTS_CA_BUNDLE` set, some internal paths read the default location.
- Fix: Write GVM CA to `ca-certificates.crt` and `cert.pem` in addition to `gvm-ca.crt`.

### Affected Files
- `src/tls_proxy.rs` — DN fix, original CA DER in chain
- `crates/gvm-sandbox/src/sandbox_impl.rs` — remove HTTPS_PROXY
- `crates/gvm-sandbox/src/mount.rs` — system CA bundle paths
- `config/srr_network.toml` — telegram/discord/gmail/AI provider rules added

---

## 2026-03-26: DNS DNAT + MITM TLS Pipeline Complete

### What Changed

**DNS resolution from sandbox now works end-to-end.**

The sandbox's `resolv.conf` points to the veth host IP (10.200.X.1), but no DNS server listens there. Previous attempt to DNAT to `127.0.0.53` (systemd-resolved stub) failed because the stub binds to `lo` only — packets arriving on veth after DNAT are silently dropped.

**Fix**: `resolve_host_dns()` reads `/run/systemd/resolve/resolv.conf` to find the actual upstream DNS server (e.g., 172.31.0.2 on AWS VPC). PREROUTING DNAT redirects sandbox DNS to this upstream resolver. Added FORWARD chain rules for DNS UDP and ESTABLISHED/RELATED responses.

**MITM TLS inspection pipeline verified:**
1. Sandbox → DNS (DNAT to upstream) → IP resolution
2. Sandbox → port 443 → DNAT → host:8443 (TLS MITM listener)
3. TLS termination with ephemeral CA → plaintext HTTP inspection
4. SRR policy evaluation → enforcement decision (Delay/Deny/Allow)
5. Forward to upstream → response back to sandbox

Proxy log confirms: `MITM: inspecting HTTPS request method=GET host=api.github.com path=/`

### Affected Files
- `crates/gvm-sandbox/src/network.rs` — `resolve_host_dns()`, DNS DNAT+MASQUERADE+FORWARD rules, cleanup

### Risk Assessment
- DNS DNAT is restricted to UDP port 53 only. The FORWARD chain allows DNS but drops all other non-proxy traffic.
- `resolve_host_dns()` falls back to 8.8.8.8 if no upstream DNS found.

---

## 2026-03-26: Kernel Panic Fix — Mount Deduplication & Seccomp sendmmsg

### What Changed

Three fixes to resolve sandbox crashes on Linux 6.17.0-1009-aws:

**1. Duplicate bind mount → kernel panic (Critical)**
- **Root cause**: `bind_mount_interpreter()` in the child process (PID 1 of new PID namespace) mounted shared libraries twice when lib-dynload dependencies overlapped with the interpreter's direct `ldd` dependencies (e.g., `libc.so.6`, `libm.so.6`). Mount-on-mount triggers a kernel panic on 6.17.0-1009-aws.
- **Fix**: `mount.rs` — Track mounted paths in a `HashSet<PathBuf>`. Skip any library already mounted. 3 duplicates detected and skipped per sandbox launch.
- **Also**: Moved lib-dynload `ldd` scanning from child PID 1 to parent process via `resolve_dynload_libs()`. The parent resolves all library paths before `clone()` and passes them to the child for bind-mounting. This avoids spawning 47+ `ldd` subprocesses from PID 1 of the new PID namespace.

**2. seccomp blocks sendmmsg → DNS failure (High)**
- **Root cause**: glibc's `getaddrinfo()` uses `sendmmsg()` to batch DNS A/AAAA queries. `sendmmsg` was not in the seccomp whitelist, causing SIGSYS (exit code 159) on any DNS resolution.
- **Fix**: `seccomp.rs` — Added `SYS_sendmmsg` and `SYS_recvmmsg` to the socket operations whitelist. These are batch versions of the already-allowed `sendmsg`/`recvmsg` with identical security properties.

**3. Binary corruption on unclean reboot (Operational)**
- **Symptom**: `gvm-proxy` binary zeroed out (all 0x00 bytes) after kernel panic + reboot. Cargo thought the binary was up-to-date because the deps hardlink still existed.
- **Workaround**: Delete `target/release/deps/gvm_proxy-*` before rebuild. `sync` after build to flush to disk.

### Affected Files
- `crates/gvm-sandbox/src/mount.rs` — `resolve_dynload_libs()` (new), `bind_mount_interpreter()` dedup
- `crates/gvm-sandbox/src/sandbox_impl.rs` — parent-side lib resolution, `extra_lib_paths` plumbing
- `crates/gvm-sandbox/src/seccomp.rs` — `sendmmsg`/`recvmmsg` whitelist

### Risk Assessment
- **Kernel panic fix**: Eliminates a hard crash. HashSet dedup is conservative (skip rather than crash). No security regression — same libraries are mounted, just without duplicates.
- **sendmmsg**: Same security as existing `sendmsg` — socket creation is still AF_restricted, network is still iptables/TC-locked to proxy only.
- **Remaining**: DNS resolution fails because sandbox's DNS target (veth host IP:53) has no listener. Needs DNAT from veth:53 → 127.0.0.53:53 on the host side.

---

## 2026-03-26: Security Audit — Unsafe/FFI, Blocking I/O, Namespace Hardening

### What Changed

Full security audit of 6 vulnerability categories with 4 fixes applied:

**1. eBPF `mem::forget` → RAII guard (Critical)**
- `ebpf.rs`: Removed `mem::forget(guard)`. `EbpfAttachResult::Attached` now returns the `EbpfGuard` to the caller.
- `sandbox_impl.rs`: Holds `_ebpf_guard` for sandbox lifetime. `Drop` detaches TC filter automatically. Explicit `drop()` before veth cleanup ensures correct ordering.

**2. WAL `rotate_wal()` blocking I/O → async (Critical, hot path)**
- `ledger.rs`: `std::fs::read_dir` → `tokio::fs::read_dir().await`, `std::fs::rename` → `tokio::fs::rename().await`, `std::fs::remove_file` → `tokio::fs::remove_file().await` in prune loop.
- Previously: WAL rotation blocked the tokio executor for the duration of directory scan + file operations. All concurrent proxy requests stalled.

**3. `tls_proxy.rs` pointer cast clarity (Warning)**
- `&mut addr as *mut _ as *mut libc::c_void` → `&mut addr as *mut libc::sockaddr_in as *mut libc::c_void`. Explicit intermediate type prevents inference-based UB risks.

**4. `/proc` `hidepid=2` (Defense-in-depth)**
- `mount.rs`: `/proc` mount now includes `hidepid=2` option. Agent can only see its own PID entries.

**5. GVM_CODE_STANDARDS.md — 3 new sections**
- §1.8 Unsafe & FFI Discipline
- §1.9 Namespace & Sandbox Isolation
- §1.10 Async I/O Discipline

### Audit findings (no fix needed)
- `/sys` is NOT mounted in sandbox: SAFE
- eBPF TC race condition: SAFE (filter attached before child signal)
- Certificate backdating: SAFE (24h window)
- SHA-256 in async: acceptable (<1µs, CPU-bound not I/O-bound)
- `openat()` seccomp args: mount namespace provides boundary (seccomp can't filter paths)

### Affected Files
- `crates/gvm-sandbox/src/ebpf.rs` — `EbpfAttachResult` now includes guard, `mem::forget` removed
- `crates/gvm-sandbox/src/sandbox_impl.rs` — RAII guard lifecycle, explicit drop ordering
- `crates/gvm-sandbox/src/mount.rs` — `/proc` with `hidepid=2`
- `src/ledger.rs` — `rotate_wal()` async I/O
- `src/tls_proxy.rs` — explicit pointer cast
- `docs/GVM_CODE_STANDARDS.md` — §1.8, §1.9, §1.10

### Risk Assessment
- **eBPF fix**: Low risk. Guard was already cleaned up manually; now RAII-managed. Drop ordering verified.
- **WAL rotation**: Low risk. Same operations, now async. Rotation is infrequent (100MB threshold).
- **hidepid=2**: Low risk. Defense-in-depth only. May fail on kernels <3.3 (graceful: proc still mounts).
- **All tests pass** (138 + 25 + 17 = 180)

---

## 2026-03-26: MITM CA Key Isolation + Zeroization (Security Fix)

### What Changed

**Vulnerability discovered**: `sandbox_impl.rs` generated its own CA independently from the proxy's CA in `main.rs`. These were two different key pairs — the sandbox trust store had CA-B but the MITM proxy signed with CA-A. This caused HTTPS inspection to silently fail (TLS handshake rejected by agent). While not a key exposure vulnerability (the key never entered the sandbox), it rendered MITM non-functional.

**Fix 1 — Single CA source of truth:**
- Removed CA generation from `sandbox_impl.rs`
- Added `mitm_ca_cert: Option<Vec<u8>>` to `SandboxConfig`
- CLI downloads CA cert from proxy's `GET /gvm/ca.pem` before sandbox launch
- Sandbox only receives the public certificate — private key stays in proxy process

**Fix 2 — CA key zeroization:**
- `EphemeralCA::drop()`: zeroizes cert PEM + serialized key PEM copy
- Proxy shutdown: `Arc::into_inner(mitm_ca_key_pem)` + `zeroize()` on the PEM bytes
- `LeafCert::drop()`: already zeroized cert + key PEM (no change needed)

### Affected Files
- `crates/gvm-sandbox/src/sandbox_impl.rs` — removed CA generation, uses `config.mitm_ca_cert`
- `crates/gvm-sandbox/src/lib.rs` — added `mitm_ca_cert` field to `SandboxConfig`
- `crates/gvm-sandbox/src/ca.rs` — enhanced `Drop` impl with key PEM zeroization
- `crates/gvm-cli/src/run.rs` — `download_mitm_ca_cert()` helper, sandbox configs updated
- `src/main.rs` — CA key PEM zeroize on shutdown
- `docs/12-security-model.md` — Attack vector #21: full CA key flow audit

### Risk Assessment
- **CA mismatch fix**: HTTPS MITM now functional (same CA for signing and trust). Previously silently broken.
- **Zeroize**: defense-in-depth. `rcgen::KeyPair` internal memory still freed by allocator (not zeroized), but PEM serializations are explicitly zeroed.
- **All tests pass** (138 lib + 25 CLI + 17 sandbox)

---

## 2026-03-26: Admin API Port Separation + stdin Isolation (Security Fix)

### What Changed

**Vulnerability discovered**: Agent could self-approve IC-3 requests by calling `POST /gvm/approve` on the same proxy port it uses for HTTP traffic. Additionally, agent inherited stdin from the CLI, enabling stdin race conditions.

**Fix 1 — Admin/proxy port separation:**
- Proxy port (default 8080): agent-facing. Serves proxy handler, health, check, vault, ca.pem, auth/token.
- Admin port (default 9090): operator-facing. Serves approve, pending, reload, info. Never exposed to agent.
- Agent environment only contains `HTTP_PROXY=...:8080` — admin port is not injected.
- In `--sandbox` mode, iptables only allows traffic to proxy port. Admin port is unreachable from agent namespace.
- CLI derives admin URL automatically: proxy port + 1010 (8080 → 9090).

**Fix 2 — stdin isolation:**
- All agent process launches (`run_local`, `run_binary_local`, watch) now use `stdin(Stdio::null())`.
- Agent cannot read from or compete for the operator's terminal input.

### Affected Files
- `src/main.rs` — Router split into agent-facing `app` + operator-facing `admin_app`, separate TcpListener for admin port
- `src/config.rs` — `admin_listen` field in `ServerConfig`
- `crates/gvm-cli/src/run.rs` — `derive_admin_url()`, approval poller uses admin URL, `stdin(Stdio::null())`
- `crates/gvm-cli/src/watch.rs` — reload uses admin URL, `stdin(Stdio::null())`
- `crates/gvm-cli/src/main.rs` — `gvm approve` uses `--admin` flag (default: 9090)
- `docs/12-security-model.md` — Attack vector #20 documented with fix details

### Risk Assessment
- **Breaking change**: CLI tools that called `/gvm/approve` or `/gvm/reload` on port 8080 must now use port 9090. `gvm approve` default updated. `gvm run` handles this automatically.
- **Backward compatible for agents**: Agent-facing proxy port unchanged. No agent code changes needed.
- **All tests pass** (138 lib + 25 CLI + 24 integration + 56 boundary/merkle/stress + 17 sandbox)

---

## 2026-03-25: cgroups v2 Resource Limits for Sandbox

### What Changed

`--sandbox` mode now supports cgroup v2 CPU and memory limits via `--memory` and `--cpus` flags. Same flags that already worked with `--contained` (Docker) now also apply to Linux-native sandbox.

**Usage:**
```bash
gvm run --sandbox --memory 512m --cpus 0.5 agent.py
```

**Implementation:**
- `crates/gvm-sandbox/src/cgroup.rs` — NEW: `CgroupGuard` RAII struct
  - Creates `/sys/fs/cgroup/gvm-agent-{pid}/` directory
  - Writes `memory.max` (bytes) and `cpu.max` (quota/period)
  - Moves agent PID into `cgroup.procs`
  - RAII Drop: kills remaining processes + removes cgroup directory
- `SandboxConfig` gains `memory_limit: Option<u64>` and `cpu_limit: Option<f64>`
- `sandbox_impl.rs`: cgroup created after clone(), before signaling child
- CLI `--memory`/`--cpus` flags updated to work with both `--contained` and `--sandbox`

**Graceful fallback:** cgroup v2 unavailable → warning + continue without limits. This is best-effort — namespace + seccomp remain primary isolation.

### Affected Files
- `crates/gvm-sandbox/src/cgroup.rs` — NEW (~150 lines)
- `crates/gvm-sandbox/src/lib.rs` — `SandboxConfig` fields, module declaration
- `crates/gvm-sandbox/src/sandbox_impl.rs` — cgroup integration point
- `crates/gvm-cli/src/run.rs` — `parse_memory_limit()`, sandbox function signatures
- `crates/gvm-cli/src/main.rs` — flag documentation update
- All test files with SandboxConfig constructors updated

### Risk Assessment
- **Graceful fallback**: cgroup v2 unavailable → no limits, no crash
- **RAII cleanup**: `CgroupGuard::drop()` kills remaining processes + removes directory
- **Linux-only**: `#[cfg(target_os = "linux")]` gated. Non-Linux builds unaffected.
- **All tests pass** (244+ across all crates)

---

## 2026-03-25: SRR Payload Inspection Activation

### What Changed

SRR payload inspection — previously parsed from TOML but never wired to actual request bodies — is now fully active when enabled via config.

**Proxy changes:**
- New body buffering step in `proxy_handler()` before SRR classification
- Body is swapped out of the request via `std::mem::replace`, buffered with `axum::body::to_bytes()`, then re-attached for forwarding
- Respects `max_body_bytes` limit (default 64KB) — Content-Length pre-check avoids buffering oversized requests
- Buffer failure → graceful fallback to host/method/path-only evaluation (logged as debug)

**Configuration:**
```toml
[srr]
payload_inspection = true     # default: false (backward compatible)
max_body_bytes = 65536        # default: 64KB
```

**Design:**
- `payload_inspection = false` (default): identical to previous behavior — body is never touched
- `payload_inspection = true`: body buffered and passed to `srr.check()` which already has full JSON pointer matching logic (`payload_field` / `payload_match` in rules)
- Parse failure in SRR → host/method/path fallback (best_effort, already implemented in srr.rs)
- Body > max_body_bytes → skip payload inspection entirely

### Affected Files
- `src/proxy.rs` — body buffering + re-attach, `mut request`, `payload_inspection`/`max_body_bytes` on AppState
- `src/config.rs` — `SrrConfig` fields: `payload_inspection`, `max_body_bytes`
- `src/main.rs` — AppState construction
- `tests/integration.rs` — AppState test constructors (5 locations)

### Risk Assessment
- **Backward compatible**: `payload_inspection = false` by default — no behavior change unless explicitly enabled
- **Memory**: bounded by `max_body_bytes` (64KB default) + Content-Length pre-check. Large uploads never buffered.
- **Body integrity**: `std::mem::replace` + `Body::from(bytes.clone())` ensures original body is preserved for forwarding
- **138 lib tests pass** (no regressions)

---

## 2026-03-25: IC-3 Blocking Approval — Human-in-the-Loop Enforcement

### What Changed

IC-3 (RequireApproval) now actually holds the HTTP response and waits for human approval, instead of immediately returning 403. This completes GVM's graduated enforcement: Allow → Delay → HumanApproval → Deny.

**Proxy changes:**
- IC-3 handler creates a `tokio::sync::oneshot` channel and suspends the HTTP response
- Pending approval metadata stored in `DashMap<String, PendingApproval>` on `AppState`
- Configurable timeout (`ic3_approval_timeout_secs`, default 300s) — auto-deny on timeout (fail-close)
- Approved → request forwarded to upstream, WAL updated with execution result
- Denied/timeout → 403 returned, WAL records denial
- Proxy restart → all pending channels dropped → auto-denied (fail-close, consistent with design)

**API endpoints:**
- `GET /gvm/pending` — list all pending IC-3 approval requests with metadata
- `POST /gvm/approve` — deliver approval/denial decision by event_id

**CLI changes:**
- `gvm approve` — standalone approval monitor (polls /gvm/pending, interactive y/N prompt)
- `gvm approve --auto-deny` — non-interactive mode for CI
- `gvm run` — auto-polls for pending IC-3 approvals during agent execution (background task)

### Affected Files
- `src/proxy.rs` — IC-3 handler rewritten (oneshot hold + timeout), `PendingApproval` struct, `AppState` fields
- `src/api.rs` — `pending_approvals()` and `approve_request()` endpoints
- `src/main.rs` — route registration, AppState construction
- `src/config.rs` — `ic3_approval_timeout_secs` field
- `crates/gvm-cli/src/approve.rs` — NEW: standalone + background approval polling
- `crates/gvm-cli/src/main.rs` — `Approve` subcommand
- `crates/gvm-cli/src/run.rs` — approval poller integrated into `run_local` and `run_binary_local`
- `tests/integration.rs` — AppState construction updated (5 locations)
- `Cargo.toml` — `dashmap = "6"` dependency added

### Risk Assessment
- **Proxy hold**: oneshot channel is lightweight (no thread blocked). Timeout prevents resource leak.
- **DashMap cleanup**: entries removed on approval delivery or timeout. Proxy restart drops all (fail-close).
- **Backward compatible**: IC-3 with no CLI/approver behaves as before — times out and returns 403.
- **No WAL schema change**: existing events unaffected.

---

## 2026-03-25: `gvm watch` — Observation-Only CLI Command

### What Changed

New `gvm watch` CLI command: observation-only mode that shows what an AI agent does without blocking anything. Designed as the entry point to the GVM funnel: `gvm watch` (observe) → `gvm run --interactive` (discover rules) → `gvm run` (enforce).

**Core features:**
1. **Real-time API call stream** — WAL tailing at 100ms intervals, live display of method/host/path/status/tokens
2. **Session summary report** — host breakdown, LLM token usage, cost estimation, status code distribution, decision sources
3. **Cost estimation** — per-provider/model token pricing (hardcoded, TOML externalization planned)
4. **Anomaly detection** — burst (>10 req/2s), loop (same URL >5x/10s), unknown host warnings
5. **Token usage** — conditional display, only when extractable from LLM provider responses
6. **`--output json`** — JSON output for CI/CD piping and tool integration

**Key design decisions:**
- **Default = allow-all**: `gvm watch` generates a temp SRR config (`{any}/* → Allow`) in a separate temp directory, reloads proxy via `/gvm/reload`, restores original rules on exit. User's existing `srr_network.toml` is never modified.
- **`--with-rules`** = opt-in enforcement while observing (applies existing SRR rules)
- **Output abstraction**: `OutputMode` enum (Text/Json) for future format extensibility
- **RAII cleanup**: `TempConfigGuard` ensures temp config is removed even on panic
- **Zero proxy changes**: All new code is CLI-side only. Proxy unchanged.

**Not included (by design):** thinking trace display, rollback, any blocking behavior in default mode.

### Affected Files
- `crates/gvm-cli/src/watch.rs` — NEW (~600 lines): WalTailer, SessionStats, AnomalyDetector, cost estimation, allow-all config
- `crates/gvm-cli/src/main.rs` — Watch subcommand variant + match arm
- `crates/gvm-cli/src/run.rs` — 5 functions changed from `fn` to `pub(crate) fn` for reuse

### Risk Assessment
- **No proxy changes.** CLI-only. Zero risk to enforcement behavior.
- **Temp config cleanup**: RAII guard ensures cleanup. If process is killed (SIGKILL), temp dir persists in OS temp — harmless, cleaned on next OS temp purge.
- **Proxy reload**: `/gvm/reload` is atomic (parse failure preserves existing rules). Original rules restored on watch exit.
- **All 25 tests pass** (22 existing + 3 ignored + 8 new watch module tests).

---

## 2026-03-24: README Rewrite — Agent Developer Framing

### What Changed

Full README rewrite following 8 strategic directions to reposition GVM from "security proxy" to "agent operations tool":

1. **First impression**: Opening changed from security-focused to agent developer pain points ("See what your agent calls. Block what it shouldn't. Roll back when it fails.")
2. **Target persona**: Added explicit "Who Is This For?" section — primary: agent developers, secondary: security teams
3. **"Why GVM?" reframing**: Replaced security architecture comparison table with real developer pain scenarios (unexpected API calls, cost overruns, key leakage, loops)
4. **Quick Start two steps**: Step 1 (observe with `--interactive`, zero risk) → Step 2 (enforce with rules). Sequential progression: observe → discover → enforce
5. **Demo reorder**: Lead with agent observation, then prompt injection catch. Demo 2 uses realistic `read_storage(bucket, key)` signature with crafted bucket name — avoids "just design the function better" counterargument
6. **Cross-layer forgery**: Reframed from "agent manipulates code" to "prompt injection corrupts LLM judgment, passing crafted inputs through well-designed functions" — the code is correct, the LLM's judgment is the attack surface
7. **OPA+Envoy tone**: Led with respect ("excellent, production-grade infrastructure"), moved honest assessment to section intro instead of conclusion
8. **Works Today vs Roadmap**: Clear separation with status tables. Every feature explicitly marked as Shipping, Loaded-but-Inactive, or Roadmap with target version

### Affected Files
- `README.md` — complete rewrite (~480 lines, down from ~747)

### Risk Assessment
- **No code changes.** Documentation-only. Zero risk to runtime behavior.
- Content accuracy verified against actual codebase implementation state (305+ tests, CLI commands, feature flags).

---

## 2026-03-24: WAL Sequence Persistence + Size-Based Rotation

### What Changed

**WAL sequence persistence**: `wal_sequence` no longer resets to 0 on restart. During `recover_from_wal()`, a pre-scan counts all event lines in the WAL and initializes the atomic counter. This ensures monotonic sequence numbers across restarts — NATS consumers can reconstruct ordering without duplicate sequences.

**WAL size-based rotation**: When the WAL file exceeds `max_wal_bytes` (default 100MB), it is rotated:
1. Current file renamed to `wal.log.<N>` (N = monotonic segment number)
2. Fresh `wal.log` created for new writes
3. `prev_batch_root` carries over — first batch in new segment references last root of old segment, maintaining the Merkle chain across files
4. Old segments pruned beyond `max_wal_segments` (default 10), including their watermark sidecars

**Configuration** (added to `[wal]` in proxy.toml):
- `max_wal_bytes = 104857600` (100MB default)
- `max_wal_segments = 10` (default)

### Affected Files
- `src/ledger.rs` — sequence init in recovery, `rotate_wal()` function, `batch_loop()` rotation check
- `src/config.rs` — `max_wal_bytes`, `max_wal_segments` fields in WalConfig
- `src/main.rs` — pass rotation config to GroupCommitConfig

### Risk Assessment
- **Sequence persistence**: No risk. Read-only scan of existing WAL, atomic store before any new writes.
- **Rotation**: Medium risk. File rename during active writing — mitigated by fsync before rename and atomic new-file creation. If rename fails, continues writing to current file (logged error, not fatal).
- All 313 tests pass.

---

## 2026-03-24: MITM API Key Injection (Layer 3 parity)

### What Changed

Implemented API key injection on the MITM TLS path, closing the gap where `--sandbox` HTTPS traffic bypassed Layer 3 credential isolation.

**Problem**: `handle_tls_connection` forwarded `raw_head` directly to upstream — agent-supplied Authorization headers passed through unmodified. This meant agents needed to hold API keys for HTTPS calls, contradicting the "agent never holds credentials" guarantee.

**Fix**:
- `HttpRequest::inject_credentials()` method in `tls_proxy.rs`: strips all auth headers (Authorization, Cookie, x-api-key, etc.) and injects credentials from `secrets.toml`
- `HttpRequest::rebuild_raw_head()`: reconstructs HTTP head bytes from modified parsed headers
- `APIKeyStore::get_credential()`: public accessor for MITM path to look up host credentials
- Wired into `handle_tls_connection` after SRR check, before upstream forwarding

**Security properties** (same as HTTP path):
- Agent auth headers stripped before injection (prevents credential smuggling)
- Same `AUTH_HEADERS` list as `api_keys.rs` (Authorization, Cookie, x-api-key, apikey, x-auth-token, x-api-token, x-signature, x-hmac, x-credentials)
- No credential if host not in `secrets.toml` → passthrough (same as HTTP path)

### Affected Files
- `src/tls_proxy.rs` — `inject_credentials()`, `rebuild_raw_head()`, `AUTH_HEADERS` const
- `src/api_keys.rs` — `get_credential()` method
- `src/main.rs` — credential injection in `handle_tls_connection`
- `README.md` — HTTPS capability table updated, Known Limitations gap removed

### Risk Assessment
- Low risk. Same logic as HTTP path's `api_keys.inject()`, adapted for raw HTTP bytes
- Header rebuild uses parsed headers (not string manipulation), so no injection risk
- All 313 tests pass

---

## 2026-03-23: MITM Hardening + uprobe Feature Flag + README Honesty Pass

### What Changed

**Task 0: CA Unification (critical bug fix)**
- `main.rs` `start_tls_listener` was generating its own CA, separate from the sandbox CA
- Sandbox trust store had CA-A, MITM listener used CA-B → agent TLS handshake = `certificate verify failed`
- Fix: Single `EphemeralCA::generate()` in `main()`, shared via parameters to TLS listener and via `GET /gvm/ca.pem` endpoint for sandbox download
- New `mitm_ca_pem` field in AppState, new `/gvm/ca.pem` endpoint

**Task 6: Certificate not_before 24h backdate**
- CA cert: `not_before = now - 24h`, `not_after = now + 24h` (was hardcoded 2020-2099)
- Leaf certs (both ca.rs and tls_proxy.rs): same 24h backdate window
- Tolerates clock drift up to 24 hours on EC2/VPS instances
- Added `time` crate dependency to both root and gvm-sandbox Cargo.toml

**Task 7: memfd_create documentation cleanup**
- memfd_create was never actually used — CA injection uses `std::fs::write()` to tmpfs
- Removed false claims from: ca.rs doc comment, 12-security-model.md, 14-implementation-log.md

**Task 5: uprobe feature flag**
- `tls_probe.rs` gated behind `#[cfg(all(target_os = "linux", feature = "uprobe"))]`
- eBPF TC filter (`ebpf.rs`) stays always-on — it's network enforcement, not observation
- `TlsProbeMode` default changed from `Audit` to `Disabled`
- CLI diagnostic messages updated: MITM listed as primary, uprobe omitted by default
- `[features] uprobe = []` added to gvm-sandbox Cargo.toml

**Task 9: README exaggeration removal**
- "Structurally unbypassable" → qualified with `(--sandbox)`
- "Tamper-proof audit" → "Tamper-evident audit"
- "OS isolation" → "Linux namespace isolation"
- "structurally impossible" → qualified with `(with --sandbox)`

**Task 8: HTTPS capability table restructure**
- Columns renamed to "MITM OFF" / "MITM ON"
- API key injection on MITM path honestly marked as "Not yet (planned)"
- Defense Layers diagram updated: API key injection marked as planned

**Task 10: uprobe repositioning**
- Roadmap: "Multi-PID uprobe (experimental, observation-only)"
- tls_probe.rs module doc: marked experimental, gated behind feature flag
- CLI diagnostic: MITM listed as primary inspection mechanism

**Tasks 11-16: EC2 test scripts (6 new tests)**
- Test 35: MITM full pipeline (HTTPS → TLS term → plaintext → SRR → upstream via api.github.com)
- Test 36: 5MB POST through proxy (MTU test)
- Test 37: SIGKILL restart — orphan veth/iptables cleanup
- Test 38: CAP_NET_ADMIN rejection (iptables -F inside sandbox → EPERM)
- Test 39: AppArmor/SELinux compatibility (clone + CA injection on stock Ubuntu AMI)
- Test 40: Clock drift — +23h system clock, TLS handshake with backdated cert

### Affected Files
- `src/main.rs` — CA unification, /gvm/ca.pem endpoint, start_tls_listener signature
- `src/proxy.rs` — mitm_ca_pem field in AppState
- `src/tls_proxy.rs` — leaf cert backdating
- `crates/gvm-sandbox/src/ca.rs` — CA/leaf cert backdating, memfd doc fix, ca_key_pem() method
- `crates/gvm-sandbox/src/lib.rs` — uprobe feature gate, TlsProbeMode default
- `crates/gvm-sandbox/src/sandbox_impl.rs` — uprobe block gated behind feature
- `crates/gvm-sandbox/src/tls_probe.rs` — experimental doc note
- `crates/gvm-sandbox/Cargo.toml` — features section, time dependency
- `crates/gvm-cli/src/run.rs` — TlsProbeMode::Disabled default, MITM diagnostic
- `Cargo.toml` (root) — time dependency
- `README.md` — exaggeration fixes, HTTPS table, uprobe repositioning
- `docs/12-security-model.md` — memfd cleanup
- `scripts/ec2-e2e-test.sh` — 6 new tests (35-40)
- `tests/integration.rs` — mitm_ca_pem field in test AppState

### Risk Assessment
- **CA unification**: Critical fix. Without it, MITM pipeline was fundamentally broken
- **Cert backdating**: Low risk. 24h window is generous. Worst case: cert rejected on extreme drift (>24h)
- **uprobe feature flag**: Zero risk to default builds. `cargo build --features uprobe` restores old behavior
- **README honesty**: No technical risk. Reputational improvement
- All 305 tests pass

---

## 2026-03-23: Runtime Hardening — 4 Structural Vulnerabilities Fixed

### What Changed

Four infrastructure-level vulnerabilities fixed across proxy, TLS, and sandbox:

**1. Tokio worker starvation on TLS cert generation**
- `ResolvesServerCert::resolve()` ran CPU-bound ECDSA keygen synchronously on tokio worker threads
- 50 concurrent new-domain handshakes would block ALL async I/O (WAL, HTTP, policy eval)
- Fix: `peek_sni()` extracts SNI from raw TCP via `stream.peek()`, then `ensure_cached()` offloads keygen to `spawn_blocking` BEFORE the TLS handshake. `resolve()` always hits cache (0ns)
- Files: `src/tls_proxy.rs` (peek_sni, ensure_cached), `src/main.rs` (handle_tls_connection)

**2. HTTP Request Smuggling (CL/TE desync)**
- `read_http_request` in TLS MITM path accepted both Content-Length and Transfer-Encoding headers
- Attacker could hide a second malicious request inside the body of the first, bypassing SRR inspection
- Fix: Zero-tolerance rejection of CL+TE conflict (RFC 7230 §3.3.3) and duplicate CL with differing values
- File: `src/tls_proxy.rs` (read_http_request_inner)

**3. FD exhaustion / Slowloris on TLS listener**
- Port 8443 accepted unlimited connections with no timeout on handshake or read
- Slowloris: 1 byte/sec keeps FD open → WAL writes and HTTP listener starved at ulimit
- Fix: `Semaphore(1024)` bounds concurrent TLS connections, 10s TLS handshake timeout, 30s HTTP read timeout, 60s upstream relay timeout
- File: `src/main.rs` (start_tls_listener, handle_tls_connection)

**4. Sandbox PID 1 zombie accumulation**
- `CLONE_NEWPID` makes agent PID 1, but agent interpreter doesn't reap orphaned children
- `subprocess.Popen()` / `child_process.exec()` exits → zombie → PID table exhaustion
- Fix: `fork()` inside namespace. PID 1 stays as init reaper (`waitpid(-1)` loop), child execs agent. Equivalent to tini/dumb-init without external dependency
- File: `crates/gvm-sandbox/src/sandbox_impl.rs` (child_entry)

### Risk Assessment
- **Cert pre-warm**: Low risk. If peek_sni fails, falls back to sync generation (previous behavior)
- **CL/TE rejection**: May reject exotic but legitimate requests with both headers — RFC 7230 says proxies MUST reject these, so this is correct behavior
- **Timeouts**: 30s/60s are generous. Legitimate agents won't hit them. Could be made configurable later
- **Init reaper**: fork() inside clone'd namespace is well-tested Linux pattern. Agent exit code correctly propagated
- All 287 tests pass

---

## 2026-03-23: Memory Safety — WAL Recovery High Watermark + TLS Cache Bound

### What Changed

Two unbounded memory growth vectors fixed:

**1. WAL Recovery: HashSet → High Watermark (O(N) → O(1))**

`recover_from_wal()` tracked all event_ids in an unbounded `HashSet` to deduplicate Pending/Expired pairs across recoveries. On a WAL with millions of events, this HashSet alone could OOM the proxy at boot.

**Root cause**: The HashSet was needed because previous recoveries append Expired entries, creating duplicate event_ids. Forward scanning encounters Pending first, then Expired — without dedup, the Pending would be re-expired unnecessarily.

**Fix**: Sidecar watermark file (`<wal_path>.watermark`) stores the byte offset where the last recovery completed. Since recovery resolves ALL Pending events before the watermark, subsequent recoveries `seek()` past it and scan only new events. No HashSet, no dedup needed — O(1) memory regardless of WAL size.

- Atomic write: tmp file + rename prevents partial watermark on crash
- Clamp guard: if WAL was manually truncated (watermark > file_len), resets to 0
- Fail-safe: if watermark write fails, next recovery re-scans from old watermark (idempotent — re-expiring is harmless)

Bloom filter was considered but rejected: false positives would permanently lose unresolved financial transactions (Pending events incorrectly classified as "already processed").

**2. TLS SNI Cache: DashMap → moka bounded cache**

`GvmCertResolver` cached leaf certificates per-domain in an unbounded `DashMap`. An attacker could exhaust host memory by requesting unique SNI domains (1.evil.com, 2.evil.com, ..., N.evil.com).

**Fix**: Replaced `DashMap` with `moka::sync::Cache` (concurrent LRU):
- `max_capacity(10_000)` — hard cap on cached certs
- `time_to_idle(1h)` — unused certs auto-evict
- Thread-safe, lock-free reads (same concurrency as DashMap)

Removed `dashmap` dependency entirely (no other usages in codebase).

### Affected Files
- `src/ledger.rs`: `recover_from_wal()` rewritten with watermark strategy
- `src/tls_proxy.rs`: `DashMap` → `moka::sync::Cache` with bounds
- `Cargo.toml`: Added `moka`, removed `dashmap`
- `docs/12-security-model.md`: Updated WAL recovery section to reflect fix

### Risk Assessment
- **WAL watermark**: Low risk. Failure to write watermark degrades to full re-scan (previous behavior). Re-expiry is idempotent.
- **moka cache**: Low risk. Cache miss just regenerates the cert (~0.1ms). Eviction is transparent to callers.
- All 287 tests pass.

---

## 2026-03-23: Documentation Consistency Fix — MITM Status & Numbering

### What Changed

Fixed README and roadmap inconsistencies where transparent MITM (implemented in v0.2 via commits 2b1ceeb, d6663ed, 1a6782c) was still described as "planned v0.3" in multiple sections.

**README.md fixes:**
- Tier table footnote 3: Updated API key injection to reflect HTTPS works in `--sandbox` mode
- Tier 1 description: Removed "HTTPS injection requires v0.3 MITM"
- Defense Layers diagram: Changed MITM from "planned v0.3" to "v0.2"
- HTTPS inspection table: Changed from roadmap format to status format reflecting v0.2 implementation
- Roadmap summary table: Moved MITM to v0.2 Done, updated v0.3 scope to match roadmap.md
- HTTP vs HTTPS capabilities table: Updated column header from "planned v0.3" to "`--sandbox` v0.2"
- Known Limitations: Rewrote HTTPS inspection section to reflect sandbox MITM is working
- WAL hardening note: Removed outdated "WAL exceeding available memory" (streaming recovery is done)
- Documentation table: Fixed [14] duplication, added missing [10], renumbered quickstart→[15] and reference→[16]

**docs/13-roadmap.md fixes:**
- v0.2 Done: Added MITM items (ephemeral CA, sandbox injection, DNAT, TLS listener, SNI cert gen)
- v1.1 Ledger: Checked off streaming WAL recovery (already implemented with BufReader)

**File renames:**
- `14-quickstart.md` → `15-quickstart.md`
- `15-reference.md` → `16-reference.md`
- Updated all cross-references in `00-overview.md`, `15-quickstart.md`, `16-reference.md`

### Why
Multiple sections contradicted each other — some said MITM was implemented (line 450, 665), others said it was planned for v0.3 (lines 477, 484-488, 533, 630). Users reading the README would get conflicting information about what the proxy can actually do.

### Risk Assessment
Documentation-only changes. No code modified. Low risk.

---

## 2026-03-23: Documentation Audit — 20 Issues Fixed Across 13 Documents

### What Changed

Full cross-reference audit of all 18 documentation files against actual codebase. 20 issues found and fixed:

**Critical/High (5 fixes)**
- seccomp syscall count: `~45` → `~111` in 08-memory-security.md, 11-competitive-analysis.md, 12-security-model.md, README.md (4 locations). Actual whitelist has 111 unique syscalls — previous count understated attack surface by 2.5x.
- 05-vault.md: Removed contradictory claim that "WAL stores encrypted ciphertext" (lines 201, 289). WAL actually stores metadata only (hash + size). Same doc line 245 was correct. Unified to "metadata only" everywhere.
- 06-proxy.md: Fixed Tower middleware execution order description. Tower applies layers in reverse declaration order (Concurrency→Body→Panic), not declaration order.
- 06-proxy.md: Removed false claim that LLM trace extraction checks Content-Length header. Code taps all JSON responses up to 256KB regardless of Content-Length.
- README.md: Replaced `uprobe` references in quick-start examples with `eBPF TC` (architectural shift from commit adf5764).

**Medium (8 fixes)**
- 00-overview.md: Test count 250 → 305. Unit test location "src/lib.rs" → "src/*.rs".
- 10-architecture-changes.md: Test summary table — all 11 file counts corrected. Total 199 → 305. Added missing sandbox test category (30 tests).
- 13-roadmap.md: Test count 218 → 305.
- 04-ledger.md: Updated `recover_from_wal()` code snippet from `read_to_string` to `BufReader::lines()` streaming (reflects code change from earlier this session).
- 07-sdk.md: Added `GVMRollbackError` to error hierarchy tree (was implemented but missing from tree).
- 15-reference.md: Added undocumented `semantic_file` config field to SRR section.
- README.md: Removed duplicate v1.0 roadmap row.

### Affected Files
- `docs/00-overview.md`, `docs/04-ledger.md`, `docs/05-vault.md`, `docs/06-proxy.md`, `docs/07-sdk.md`, `docs/08-memory-security.md`, `docs/10-architecture-changes.md`, `docs/11-competitive-analysis.md`, `docs/12-security-model.md`, `docs/13-roadmap.md`, `docs/15-reference.md`, `README.md`

### Risk Assessment
Documentation-only changes. No code impact. All fixes verified against actual source code via automated grep/count and manual review.

---

## 2026-03-23: Security Hardening — WAL OOM, Rate Limiter Determinism, README Honesty

### What Changed

**1. WAL OOM Fix (Critical)**
- `src/ledger.rs`: `recover_from_wal()` replaced `tokio::fs::read_to_string` (loads entire WAL into memory) with `std::io::BufReader::lines()` streaming. Added corrupt-line counter and I/O error handling that stops recovery gracefully instead of panicking.
- `crates/gvm-cli/src/suggest.rs`: `suggest_rules_interactive()` replaced `std::fs::read_to_string` with `std::fs::File::open` + `BufReader` + `Seek` to start_offset. Eliminates OOM risk on large WAL files during interactive rule suggestion.

**2. Rate Limiter Fixed-Point (Non-determinism Fix)**
- `src/rate_limiter.rs`: Complete rewrite from `f64` floating-point to `u64` millitoken fixed-point arithmetic (1 token = 1000 millitokens). Eliminates accumulated floating-point precision errors in long-running rate limiting decisions. All comparisons are now exact integer operations. Uses `saturating_mul`/`saturating_add` for overflow safety.

**3. README Honesty (Architectural Transparency)**
- Replaced "Security Kernel" with "Security Proxy" in title.
- Removed "We are building the kernel" overstatement; replaced with firewall analogy.
- Marked API key injection as "HTTP only" with footnote explaining CONNECT relay limitation.
- Added "HTTP vs HTTPS Capabilities" comparison table showing exactly what works on each protocol in v0.2 vs planned v0.3 MITM.
- Updated Known Limitations table to reflect WAL OOM and Numeric Precision as fixed.
- Changed OPA comparison section from "security kernel" to "governance proxy".

### Affected Files
- `src/ledger.rs`, `src/rate_limiter.rs`, `crates/gvm-cli/src/suggest.rs`, `README.md`

### Risk Assessment
- **WAL recovery**: Behavioral change — corrupt last line now logs warning and continues (previously would fail to parse but still continue). I/O errors now stop recovery instead of propagating through the entire string. Streaming means memory usage is O(line) not O(file).
- **Rate limiter**: Behavioral change — millitoken granularity (1/1000th token) vs f64. For max_per_minute < 60, the integer division `max * 1000 / 60` truncates slightly differently than f64 division. This is strictly more correct (deterministic, no accumulation drift).
- **README**: No code impact. Transparency improvement.

---

## 2026-03-23: Documentation Update — SRR, Proxy, and Reference Guide

### What Changed
- `docs/03-srr.md`: Added sections for Base64 payload decoding (3.6.1), path_regex matching (3.7), and SRR hot-reload (3.8). Renumbered subsequent sections.
- `docs/06-proxy.md`: Added sections for CONNECT tunnel (6.10), Shadow Mode + Intent Store (6.11), and control plane endpoints `/gvm/reload`, `/gvm/intent`, `/gvm/check` (6.12). Renumbered Governance Block Response to 6.14.
- `docs/15-reference.md`: Added proxy API endpoints (reload, intent, check), binary mode documentation, Shadow Mode env var and config, SandboxConfig fields (tls_probe_mode, proxy_url).

### Affected Files
- `docs/03-srr.md`, `docs/06-proxy.md`, `docs/15-reference.md`, `docs/14-implementation-log.md`

### Risk Assessment
None. Documentation-only changes reflecting existing implemented features.

---

## 2026-03-23: Binary Mode, Base64 Decoding, MCP Rulesets, EC2 E2E Tests

### What Changed
- `gvm run` binary mode: `gvm run -- openclaw gateway` with HTTPS_PROXY injection for arbitrary binaries
- `gvm run --sandbox` for arbitrary binaries (namespace + seccomp + uprobe isolation)
- gvm run stdout-to-stderr fix (clean stdout for piping)
- Base64 payload decoding in SRR (body + field value decoding for encoded payloads)
- Telegram ruleset (path_regex for Bot API endpoint matching)
- Discord ruleset: channel/guild delete rules added
- EC2 E2E test suite: 34 scenarios covering proxy enforcement, sandbox, and uprobe paths
- OpenClaw config fix (mcpServers invalid key removal)

### Affected Files
- `crates/gvm-cli/src/main.rs`, `crates/gvm-cli/src/run.rs` (binary mode + stdout fix)
- `src/srr.rs` (Base64 decoding in SRR evaluation)
- `scripts/ec2-e2e-test.sh` (34 E2E test scenarios)
- `rulesets/telegram.toml`, `rulesets/discord.toml` (MCP repo rulesets)

### Risk Assessment
Low-Medium. Binary mode extends existing `gvm run` with HTTPS_PROXY injection -- no changes to core proxy or policy engine. Base64 decoding adds a new SRR evaluation path but is opt-in per rule. E2E tests are test-only additions.

---

## 2026-03-22: Uprobe SRR Policy Enforcement

### What Changed
- Connected uprobe TLS probe to proxy's SRR policy engine via `/gvm/check` HTTP callback
- Added `proxy_url` field to `SandboxConfig` for uprobe→proxy communication
- Added `ureq` dependency for sync HTTP calls from uprobe thread
- Fail-closed design: proxy unreachable or timeout (50ms) → Deny (SIGSTOP)
- `X-GVM-Uprobe-Token` header for basic auth separation

### Why
The uprobe captured HTTPS plaintext but had a hardcoded Allow-all callback. Without SRR integration, the uprobe could log but never enforce path-level HTTPS policies.

### Affected Files
- `crates/gvm-sandbox/src/sandbox_impl.rs`: real policy callback via ureq HTTP
- `crates/gvm-sandbox/src/lib.rs`: `proxy_url` field in SandboxConfig
- `crates/gvm-sandbox/Cargo.toml`: ureq + serde_json deps
- `crates/gvm-cli/src/run.rs`: passes proxy URL to sandbox config
- `docs/linux-e2e-test.md`: Test 6 (uprobe enforcement) + security model table

### Known Limitations
- **Race condition**: SSL_write_ex fires after kernel queues packet. SIGSTOP cannot prevent the first write. This is "immediate session freeze on violation", not "pre-transmission block".
- **Auth**: `X-GVM-Uprobe-Token` is a static string, not cryptographically verified. Sandboxed agents with iptables bypass could forge it.
- **Fail-closed risk**: Proxy transient unavailability freezes the agent (SIGSTOP). Acceptable for security but may surprise users.

### Risk Assessment
Low-Medium. The uprobe is a defense-in-depth layer, not the primary enforcement point. Proxy CONNECT-level enforcement + iptables remain the primary gates.

---

## 2026-03-22: Shadow Mode, Security Patches, Sandbox Improvements

### What Changed

#### 1. Shadow Mode (New Feature)

Implemented a 2-phase intent lifecycle for MCP-compatible governance:

- **Intent Store**: In-memory store with TTL-based expiry, agent_id cross-check, and one-time consumption semantics. Uses atomic operations to prevent TOCTOU races on concurrent intent consumption.
- **`POST /gvm/intent`**: Agents declare intent before making HTTP requests. The proxy validates the intent (claim phase), writes to WAL, then either confirms or releases the intent based on enforcement outcome.
- **`POST /gvm/reload`**: Hot-reload SRR rules without proxy restart. Enables runtime policy updates for Shadow Mode deployments.
- **`GVM_SHADOW_MODE` env var**: Alternative to `[shadow]` config section for enabling Shadow Mode. Accepts `strict` (reject requests without prior intent) or `permissive` (log-only).
- **Intent lifecycle coverage**: All enforcement decision paths (Allow, Delay, Deny, AuditOnly, RequireApproval) now participate in the intent confirm/release lifecycle.

#### 2. Security Patches (11 fixes)

1. **CRITICAL -- IPv6 expand OOB fix** (`srr.rs`): Bounds check for `right.len() > max_segments` before subtraction prevents integer underflow on malformed IPv6 with excessive segments after `::`.
2. **HIGH -- Merkle domain separation** (`merkle.rs`): `gvm-event-v1:` prefix with length-prefixed fields replaces `|` delimiter. `gvm-node-v1:` prefix for internal nodes. Prevents cross-context hash collisions and delimiter-based second preimage attacks.
3. **HIGH -- Wasm pointer bounds validation** (`wasm_engine.rs`): `u32::MAX` overflow check before `len as u32` cast. Explicit memory bounds validation for `input_ptr` and `result_ptr` before read/write.
4. **MEDIUM -- Auth header stripping expanded** (`api_keys.rs`): 4 → 10 stripped headers: added `Proxy-Authorization`, `X-Auth-Token`, `X-Api-Token`, `X-Signature`, `X-HMAC`, `X-Credentials`.
5. **MEDIUM -- Regex pattern length limit** (`srr.rs`, `policy.rs`): 10,000-byte (10KB) limit on `path_regex` and policy regex patterns to prevent DFA memory explosion.
6. **MEDIUM -- agent_id length validation unified** (`api.rs`): 128-byte length check in `validate_vault_identifier()`. Previously only `/gvm/auth/token` enforced length.
7. **LOW -- Intent store TOCTOU fix**: Replaced `unwrap()` with safe `Option` handling in concurrent intent consumption path.
8. **LOW -- First-run wizard config guard**: `offer_first_run_setup()` no longer overwrites existing config files.
9. **LOW -- Docker non-root user**: Dockerfile runs as UID 10001 (non-root) for defense in depth.
10. **LOW -- audit.rs hash synced with merkle.rs**: `compute_event_hash()` in audit.rs now uses the same domain-separated hash format as merkle.rs, preventing verification mismatches.
11. **LOW -- Python SDK proxy URL validation**: SDK validates proxy URL format on `configure()` to fail fast on misconfiguration.

#### 3. Sandbox Improvements

- **`/workspace/output` writable mount**: Sandbox mode now mounts `/workspace/output` as writable, persisting to the host. Agent file output survives container teardown.
- **CWD set to `/workspace/output`**: In sandbox mode, the agent process working directory defaults to `/workspace/output` so relative file writes land in the persistent output directory.
- **Intent lifecycle coverage**: All enforcement decision paths (Allow through Deny) now correctly participate in intent confirm/release when Shadow Mode is active inside sandboxed environments.

#### 4. /gvm/check SRR-Only Decision for Tier-1

`/gvm/check` endpoint now returns SRR-only decisions when no SDK headers are present (Tier-1 mode), rather than returning an error or requiring ABAC context.

### Risk Assessment

- Merkle domain separation is **backwards-incompatible** with pre-existing WAL files (acceptable for v0.x pre-release).
- Shadow Mode is opt-in only; no behavioral change for existing deployments.
- Intent store TTL defaults are conservative (30s). Production deployments may need tuning.
- All 242 tests pass (129 core + 32 CLI + 17 gvm-cli + 28 gvm-engine + 12 sandbox + 12 types + 12 benches).

### Affected Files

**Shadow Mode**: `src/proxy.rs`, `src/intent.rs`, `src/config.rs`, `src/api.rs`, `src/main.rs`
**Security patches**: `src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`, `src/audit.rs`, `Dockerfile`, `sdk/python/gvm/session.py`
**Sandbox**: `src/sandbox.rs`, `src/main.rs`
**Docs**: `README.md`, `docs/14-implementation-log.md`

---

## 2026-03-21: Security Audit — 8 Patches

### What Changed

1. **CRITICAL — IPv6 expand array OOB** (`srr.rs:673`): Added bounds check for `right.len() > max_segments` before subtraction. Malformed IPv6 with excessive segments after `::` caused integer underflow → out-of-bounds array write.

2. **HIGH — Merkle domain separation** (`merkle.rs`): Added `gvm-event-v1:` prefix to event hashes with length-prefixed fields (replaces `|` delimiter). Added `gvm-node-v1:` prefix to internal node hashes. Prevents cross-context hash collisions and delimiter-based second preimage attacks. Updated `compute_merkle_root`, `generate_merkle_proof`, `verify_merkle_proof`, and all test vectors.

3. **HIGH — Wasm pointer safety** (`wasm_engine.rs`): Added `u32::MAX` overflow check before `len as u32` cast. Added explicit memory bounds validation for both `input_ptr` and `result_ptr` before read/write operations.

4. **MEDIUM — Auth header stripping** (`api_keys.rs`): Extended stripped headers from 4 to 10: added `Proxy-Authorization`, `X-Auth-Token`, `X-Api-Token`, `X-Signature`, `X-HMAC`, `X-Credentials`. Prevents agents from smuggling alternative auth headers past Layer 3.

5. **MEDIUM — Regex pattern length limit** (`srr.rs`, `policy.rs`): Added 10,000-byte limit on `path_regex` and policy regex patterns. Prevents DFA memory explosion during compilation from malicious config.

6. **MEDIUM — agent_id length validation** (`api.rs`): Added 128-byte length check to `validate_vault_identifier()`. Previously only `/gvm/auth/token` enforced length; vault endpoints did not.

7. **LOW — IPv6 loopback scheme** (`proxy.rs`): Added `[::1]` and `::1` to local host detection for HTTP scheme selection.

8. **LOW — IPv4-mapped IPv6 parsing** (`srr.rs:581`): Replaced `unwrap_or(0)` with explicit `None` return for missing colon. Prevents potential panic on malformed IPv4-mapped addresses.

### Risk Assessment

- Merkle hash change is **backwards-incompatible**: existing WAL files will fail verification against new hashes. This is acceptable for pre-release (v0.x). Production deployments would need a migration tool.
- All 233 tests pass (120 core + 32 CLI + 17 gvm-cli + 28 gvm-engine + 12 sandbox + 12 types + 12 benches).

### Affected Files

`src/srr.rs`, `src/merkle.rs`, `src/wasm_engine.rs`, `src/api_keys.rs`, `src/policy.rs`, `src/api.rs`, `src/proxy.rs`

---

## 2026-03-20: WAL Batch Window + LLM Trace Streaming Refactor

### What Changed

**WAL batch_window**: Changed default `GroupCommitConfig::batch_window` from `Duration::ZERO` to `Duration::from_millis(2)`. Added `[wal]` section to `ProxyConfig` with `batch_window_ms` and `max_batch_size` fields. `main.rs` now passes config values to `Ledger::with_config()`.

**LLM trace extraction**: Unified SSE and non-SSE response paths into a single tap-stream pattern. Previously, non-SSE responses were fully buffered via `BodyExt::collect()` before forwarding (blocking first byte until entire body was received). Now both paths use the same approach: chunks are forwarded immediately through the stream while a bounded capture buffer accumulates bytes for post-stream trace extraction. Removed the separate `extract_llm_trace_from_sse_stream` function.

**Key behavioral change**: `extract_llm_trace_from_response` now takes `&GVMEvent` instead of `&mut GVMEvent`. The extracted trace is persisted as a separate WAL entry via `tokio::spawn` after stream completion, rather than being set on the caller's event in-place.

### Why

**WAL**: With `batch_window=0`, every IC-2/3 request paid a full fsync even under concurrent load. With 2ms batching, concurrent requests amortize fsync across the batch, yielding 10-50x TPS improvement under load while adding only 2ms worst-case latency for isolated requests. This is critical because WAL fsync was the dominant latency component (1-50ms), dwarfing the sub-microsecond policy evaluation that GVM markets.

**LLM trace**: The previous `collect()` approach buffered up to 256KB per non-SSE LLM response before forwarding the first byte. Under concurrent load (N requests × 256KB), this created both a memory exhaustion risk and an unnecessary latency penalty. The tap-stream approach eliminates both: first byte is forwarded immediately, and memory is bounded by the capture limit regardless of concurrency.

### Affected Files

- `src/ledger.rs` — default batch_window `Duration::ZERO` → `Duration::from_millis(2)`, updated docs
- `src/config.rs` — new `WalConfig` struct with `batch_window_ms` and `max_batch_size`
- `src/main.rs` — `Ledger::new()` → `Ledger::with_config()` with config values
- `src/proxy.rs` — unified tap-stream for SSE and non-SSE, removed `extract_llm_trace_from_sse_stream`, updated 6 unit tests
- `tests/stress.rs` — `vault_10k_encrypt_decrypt_no_leak` uses explicit `batch_window=0` to avoid Windows timer resolution penalty

### Risk Assessment

Medium. Two behavioral changes: (1) WAL writes now wait up to 2ms for more events before flushing — isolated requests see 2ms added latency (15.6ms on Windows due to timer resolution). (2) LLM trace is now a separate WAL entry instead of being embedded in the enforcement decision event — audit queries that join on trace data need to correlate by `event_id`. All 257 tests pass.

### Known Limitation

Windows timer resolution: `tokio::time::timeout(2ms)` resolves to ~15.6ms on Windows due to the default timer granularity. Production deployments on Windows should set `batch_window_ms = 0` in `proxy.toml` or use `timeBeginPeriod(1)` to increase timer resolution. Linux is unaffected.

---

## 2026-03-20: Test Coverage Gap Fill (5 Integration Tests)

### What Changed

Added 5 new integration tests to fill identified coverage gaps:

1. **E2E proxy forwarding** (`e2e_proxy_forwards_to_upstream_and_strips_response_headers`): Spawns a real mock HTTP upstream, builds full AppState with `host_overrides`, verifies end-to-end request forwarding, API key injection, and X-GVM-* response header stripping.

2. **GovernanceBlockResponse fields** (`governance_block_response_contains_all_required_fields`): Sends a Deny-triggering request, verifies the 403 JSON body contains all SDK-contract fields (blocked, decision, event_id, trace_id, operation, reason, mode, next_action, ic_level).

3. **SDK↔Proxy header contract** (`sdk_proxy_header_contract_resource_and_context_json`): Sends SDK-format JSON in X-GVM-Resource and X-GVM-Context headers, verifies ABAC policy evaluates `resource.sensitivity` correctly (Critical→Deny, Medium→Allow), and malformed JSON doesn't crash the proxy.

4. **Policy conflict Regex edge case** (`policy_conflict_regex_vs_startswith_overlap_is_documented_false_negative`): Documents that `values_could_overlap()` returns `false` for Regex vs StartsWith (known heuristic false negative), but `max_strict` still enforces correctly via priority ordering.

5. **Emergency WAL recovery** (`emergency_wal_to_primary_recovery_path`): Tests primary WAL failure → emergency fallback → primary recovery flow. Verifies emergency events have `event_hash` but no `MerkleBatchRecord`, and primary failure counter tracks correctly.

### Why

Test coverage analysis identified these as the highest-priority gaps: no test verified actual HTTP forwarding, no test checked the SDK-facing JSON error contract, and the emergency WAL recovery path was untested.

### Affected Files

- `tests/integration.rs` — 5 new tests (Tests 8-12)
- `docs/09-test-report.md` — test count 252 → 257, integration tests 7 → 12
- `docs/14-implementation-log.md` — this entry

### Risk Assessment

Low. Tests only — no production code changes. All 257 tests pass.

---

## 2026-03-20: Config File Hash Recording in Merkle Chain

### What Changed

Added `record_config_load()` to `Ledger` that records SHA-256 hashes of all loaded config files (SRR, policy, registry) as a `gvm.system.config_load` event in the WAL Merkle chain at proxy startup.

### Why

Policy file tampering between proxy restarts was undetectable. An attacker modifying `global.toml` to weaken rules would leave no trace in the audit trail. By recording config hashes in the same Merkle chain as enforcement events, hash mismatches across restarts become visible to auditors.

### Affected Files

- `src/ledger.rs` — new `record_config_load()` method
- `src/main.rs` — step 7.5: collect config paths and call `record_config_load()` after WAL recovery
- `tests/integration.rs` — 2 new tests (hash correctness + missing file graceful degradation)
- `docs/04-ledger.md` — new Section 4.8 (Config File Hash Recording)
- `docs/12-security-model.md` — new Section 6.1 (Config File Tamper Detection)
- `docs/09-test-report.md` — test count 250 → 252

### Risk Assessment

Low. Non-fatal on failure (proxy logs warning, continues startup). Reuses existing `append_durable()` path — no new WAL format or recovery logic changes. Known limitation: hot-reload re-recording deferred to P3.

---

## 2026-03-20: Security Documentation Reframing (Timing + Fuzzing)

### What Changed

- Reframed timing side-channel analysis from "measured < 10x variance" to "rate limiter prevents statistical attacks; end-to-end timing difference is inherent to all proxy architectures"
- Elevated fuzzing CI pipeline from Medium → High priority (SRR regex + JSON payload parsing are direct adversarial input surfaces)
- Lowered constant-time SRR from Medium → Low priority (rate limiter already mitigates; end-to-end timing is architecturally inherent)

### Why

Previous framing implied GVM was pursuing constant-time matching but falling short. The honest framing is: (1) the engine-level 35 ns variance is unobservable, (2) the end-to-end difference (Deny=fast, Allow=slow) exists in every proxy and is not a vulnerability, (3) rate limiting makes statistical exploitation impractical. This reframing presents an intentional design decision rather than an unfinished mitigation.

Fuzzing priority raised because SRR regex matching and JSON payload parsing are the primary adversarial input surfaces — exactly the code paths where crafted agent payloads land.

### Affected Files

- `docs/08-memory-security.md` — Section 8.4.1 rewritten, checklist row 7 updated, Future Hardening table reordered
- `docs/12-security-model.md` — Section 1 (Timing Side Channel) rewritten

### Risk Assessment

Documentation-only. No code changes.

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
