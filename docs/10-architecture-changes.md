# Part 10: Architecture Modification & Error Record

**Date**: 2026-03-15
**Scope**: Boundary/security tests implementation, bug fixes, test coverage expansion

---

## 10.1 Bug Fixes

### BUG-001: evaluate_json() produces invalid JSON on error paths

**File**: `crates/gvm-engine/src/lib.rs` (lines 172-184)
**Severity**: Medium
**Discovered by**: Boundary test `wasm_malformed_response_does_not_crash`

**Root Cause**: `evaluate_json()` used `format!()` with raw string interpolation for error responses. When serde's error messages contained quote characters (e.g., `invalid type: string "string"`), the output was malformed JSON with unescaped quotes.

**Before (broken)**:
```rust
Err(e) => {
    format!(r#"{{"error":"invalid input: {}"}}"#, e)
}
```

**After (fixed)**:
```rust
Err(e) => {
    let error_msg = format!("invalid input: {}", e);
    serde_json::json!({"error": error_msg}).to_string()
}
```

**Impact**: Any Wasm host reading error responses from `evaluate_json()` would fail to parse JSON if the serde error contained quotes. Fixed in both the error path and the serialization-failure path.

**Verification**: Test `wasm_malformed_response_does_not_crash` sends 10 different malformed inputs and verifies all responses are valid JSON.

---

## 10.2 Architecture Observations

### OBS-001: GVMHeaders struct provides compile-time decision spoofing prevention

The `GVMHeaders` struct does not contain a `decision` field. Even if an attacker sends `X-GVM-Decision: Allow` as a request header, `parse_gvm_headers()` only extracts defined fields. This is a compile-time structural guarantee, not a runtime check.

**Status**: No change needed — correct by design.
**Verified by**: Test `inbound_decision_header_not_in_parsed_gvm_headers`

### OBS-002: IPv6 loopback SSRF defense — RESOLVED

`extract_target()` in `proxy.rs` originally only checked `localhost` and `127.0.0.1`. IPv6 variants like `[::1]`, `[::ffff:127.0.0.1]`, and zero-compressed forms could bypass detection.

**Status**: **Fixed**. `normalize_host()` in `src/srr.rs` now expands all IPv6 variants via `expand_ipv6()` (handles `::` zero-compression, dotted-decimal IPv4-mapped, bracket notation) and normalizes to canonical IPv4 before SRR matching. SRR rules for `localhost`, `127.0.0.1`, `169.254.169.254`, and `metadata.google.internal` catch all IPv6 equivalents.

**Verified by**: 4 fuzzing-style tests in `tests/boundary.rs` covering 13 IPv6 attack variants.

### OBS-003: Wasm engine unknown decision maps to Allow (fail-open)

`WasmEngine::response_to_decision()` maps unknown decision strings to `EnforcementDecision::Allow` (line 227 of `wasm_engine.rs`). This is intentionally fail-open for forward compatibility — new decision types added to the Wasm engine will not break the proxy.

**Status**: Architectural decision. If fail-close is preferred, the default branch should return `Deny` instead.
**Verified by**: Test `wasm_invalid_decision_string_maps_to_allow`

### OBS-004: Vault key collision is by design (last-writer-wins)

Multiple agents writing to the same Vault key results in last-writer-wins semantics. This is the intended behavior for MVP (simple HashMap with RwLock). Production should implement per-agent key namespacing.

**Status**: Documented. No code change needed for MVP.
**Verified by**: Test `vault_key_collision_between_agents`

---

## 10.3 Test Coverage Expansion

### Boundary Tests Added (26 tests)

**File**: `tests/boundary.rs`

| # | Boundary | Test Name | Verification |
|---|----------|-----------|--------------|
| 1 | Wasm↔Host | `wasm_invalid_decision_string_maps_to_allow` | Unknown decision → Allow |
| 2 | Wasm↔Host | `wasm_malformed_response_does_not_crash` | 10 garbage inputs → valid JSON |
| 3 | Wasm↔Host | `wasm_oversized_input_handled_gracefully` | 1MB operation name → no crash |
| 4 | Wasm↔Host | `wasm_unicode_boundary_operation_names` | Korean, null, emoji, RTL → no crash |
| 5 | Wasm↔Host | `wasm_null_bytes_in_string_fields` | Null bytes in all fields → correct matching |
| 6 | Wasm↔Host | `wasm_all_decision_types_roundtrip` | All 6 decision types map correctly |
| 7 | Wasm↔Host | `wasm_concurrent_native_evaluations_no_corruption` | 100 concurrent evals → correct results |
| 8 | Inbound HTTP | `inbound_decision_header_not_in_parsed_gvm_headers` | X-GVM-Decision not parseable |
| 9 | Inbound HTTP | `duplicate_gvm_headers_first_value_wins` | First value used (axum behavior) |
| 10 | Inbound HTTP | `header_injection_newline_rejected` | CR/LF in header value → rejected |
| 11 | Inbound HTTP | `gvm_headers_stripped_before_forwarding` | All 11 GVM headers removed |
| 12 | Outbound API | `ssrf_localhost_blocked_by_srr` | localhost/127.0.0.1 → Deny |
| 13 | Outbound API | `ssrf_cloud_metadata_blocked_by_srr` | 169.254.169.254, metadata.google.internal → Deny |
| 14 | Outbound API | `ssrf_max_strict_srr_deny_overrides_policy_allow` | SRR Deny beats policy Allow |
| 15 | Outbound API | `ssrf_private_ip_ranges_blocked_by_srr` | 10.x, 192.168.x, 172.16.x → Deny |
| 16 | Outbound API | `api_key_not_leaked_via_gvm_headers` | X-GVM-Context stripped |
| 17 | Outbound API | `srr_redirect_target_blocked` | Open redirect endpoint → Deny |
| 18 | NATS | `nats_channel_backpressure_bounded` | 200 events through 32-capacity channel |
| 19 | NATS | `nats_empty_url_wal_only_mode` | WAL-only when NATS URL empty |
| 20 | NATS | `nats_wal_sequence_monotonic` | 50 concurrent → all in WAL |
| 21 | Vault | `vault_large_value_roundtrip` | 1MB encrypt/decrypt |
| 22 | Vault | `vault_key_collision_between_agents` | Last-writer-wins verified |
| 23 | Vault | `vault_tampered_ciphertext_detected` | AES-GCM integrity check |
| 24 | Vault | `vault_concurrent_read_write_same_key` | 20 reads + 20 writes concurrent |
| 25 | Vault | `vault_delete_then_read_returns_none` | Delete → None on read |
| 26 | Vault | `vault_empty_value_roundtrip` | Empty value encrypt/decrypt |

### Infrastructure-Dependent Tests (Documented, Not Yet Implemented)

| Category | Count | Prerequisite |
|----------|-------|--------------|
| NATS Server | 4 | Running NATS JetStream |
| Running Proxy | 4 | Slowloris, request smuggling, chunked timeout, connection flood |
| TLS | 2 | TLS certificate handling |
| DNS | 2 | DNS resolution failure handling |
| Redis | 4 | Running Redis instance |
| Docker | 6 | Docker environment |

---

## 10.4 Architecture Change: Merkle Tree WAL Integrity

**Date**: 2026-03-15
**Scope**: WAL integrity verification via Merkle trees

### Design

```text
Batch N:
  event_1.event_hash ─┐
                       ├─ H(1,2) ─┐
  event_2.event_hash ─┘           │
                                  ├─ merkle_root_N
  event_3.event_hash ─┐           │
                       ├─ H(3,4) ─┘
  event_4.event_hash ─┘

Batch N+1:
  prev_batch_root = merkle_root_N  ← inter-batch chain
```

- **Intra-batch**: Events form a binary Merkle tree. Individual event verification is O(log N).
- **Inter-batch**: Each `MerkleBatchRecord` references the previous batch's root, forming a chain.
- **Event hash**: SHA-256 of canonical fields (event_id, trace_id, agent_id, operation, decision, timestamp, content_hash).

### Modified Files

| File | Change |
|------|--------|
| `crates/gvm-types/src/lib.rs` | Added `event_hash: Option<String>` to `GVMEvent`, added `MerkleBatchRecord` struct |
| `src/merkle.rs` (new) | Merkle tree computation, proof generation/verification, WAL verification |
| `src/ledger.rs` | `WAL::append()` computes event_hash before serialization; `flush_batch_with_merkle()` computes Merkle root and writes batch record; inter-batch chain state tracked in batch loop |
| `src/lib.rs` | Added `pub mod merkle` |

### Performance Impact

| Operation | Added Latency | Relative to WAL fsync (2ms) |
|-----------|--------------|----------------------------|
| SHA-256 per event (~500B) | ~200-500ns | 0.02% |
| Merkle root (100-event batch) | ~20µs | 1% |
| Total overhead | negligible | within measurement noise |

### Verification

12 dedicated tests in `tests/merkle.rs`:
- Event hash embedding, determinism, uniqueness
- Batch record written to WAL, Merkle root recomputable
- Inter-batch chain (prev_batch_root linkage)
- WAL verification (valid, tampered event, broken chain)
- Merkle proof for individual event inclusion
- Concurrent write integrity (50 concurrent writers)

---

## 10.5 Updated Test Summary

| Test File | Count | Category |
|-----------|-------|----------|
| `src/` (unit tests) | 38 | Registry (4), Policy (4), SRR (10), Vault (7), WasmEngine (4), Merkle (9) |
| `tests/hostile.rs` | 11 | Adversarial/concurrency |
| `tests/integration.rs` | 5 | End-to-end pipeline |
| `tests/edge_cases.rs` | 17 | Input boundaries, conflicts |
| `tests/stress.rs` | 12 | Scale, performance |
| `tests/boundary.rs` | 30 | Cross-boundary security (incl. 4 IPv6 SSRF) |
| `tests/merkle.rs` | 12 | Merkle tree integrity |
| **Total** | **125** | **All passing** |

---

## 10.5 Security Property Coverage Matrix (Updated)

| Security Property | Covering Tests |
|-------------------|----------------|
| **SSRF Prevention** | boundary: ssrf_localhost, ssrf_metadata, ssrf_private_ip, max_strict |
| **Header Forgery** | hostile:6, boundary: decision_spoofing, header_injection, gvm_stripped |
| **API Key Leak** | boundary: api_key_not_leaked, gvm_headers_stripped |
| **Wasm Isolation** | boundary: invalid_decision, malformed_response, oversized_input, concurrent |
| **Unicode/Null Safety** | boundary: unicode_boundary, null_bytes; edge: unicode_operation |
| **Fail-Close (WAL)** | hostile:11, stress: wal_1000, wal_10k; boundary: backpressure |
| **Encryption Integrity** | vault unit tests (7), boundary: large_value, tampered, concurrent_rw |
| **Concurrent Safety** | hostile:1-2,4,9; stress:8-10; boundary:7,18,20,24 |
| **OOM Defense** | srr unit tests (1-3), stress: srr_10k, 1mb_toml; boundary: oversized |
| **Decision Correctness** | hostile:5-6; edge: max_strict (6 types); boundary: all_decision_types |
| **Merkle Integrity** | merkle: event_hash_embedded, batch_root_recomputable, inter_batch_chain, wal_verification_valid, detects_tampered, detects_broken_chain, proof_proves_event, concurrent_valid_roots |

---

## 10.6 Architecture Change: WASI Preview1 for Core Wasm Modules

**Date**: 2026-03-15
**Scope**: Fix Wasmtime WASI integration for wasm32-wasip1 core modules

### Problem

The governance engine is compiled as a core Wasm module (`wasm32-wasip1`), which requires WASI preview1 imports for `std::alloc` shims. The initial implementation used `wasmtime_wasi::add_to_linker_sync()`, which targets the Component Model (`wasmtime::component::Linker`), not core modules (`wasmtime::Linker`).

### Fix

| Before (broken) | After (correct) |
|------------------|-----------------|
| `Store<wasmtime_wasi::WasiCtx>` | `Store<wasmtime_wasi::preview1::WasiP1Ctx>` |
| `WasiCtxBuilder::new().build()` | `WasiCtxBuilder::new().build_p1()` |
| `wasmtime_wasi::add_to_linker_sync(&mut linker)` | `wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, \|ctx\| ctx)` |

**File Modified**: `src/wasm_engine.rs`

---

## 10.7 Defense Benchmarks

**Date**: 2026-03-15
**Environment**: Windows 11, Criterion 0.5, release profile (optimized)

### Wasm vs Native Engine Latency

| Benchmark | Latency | Notes |
|-----------|---------|-------|
| `native_deny` | **928 ns** | Direct Rust call with rule matching |
| `native_allow` | **823 ns** | Direct Rust call, no rules matched |
| `wasm_deny` | **6.30 µs** | Wasm sandbox: serialize → alloc → copy → evaluate → read → dealloc → deserialize |
| `wasm_allow` | **6.30 µs** | Wasm sandbox: same FFI overhead regardless of decision |
| `e2e_with_wasm` | **6.37 µs** | Full pipeline: SRR + policy + Wasm engine |
| `e2e_with_native` | **732 ns** | Full pipeline: SRR + policy + native engine |
| `srr_only_baseline` | **88 ns** | SRR pattern matching only (no policy engine) |

### Latency Breakdown Analysis

```text
E2E with Wasm (6.37 µs total):
  ├── SRR matching:       88 ns    (1.4%)
  ├── Policy evaluation:  ~640 ns  (10.0%)
  └── Wasm engine:        5.64 µs  (88.6%)
       ├── JSON serialization:     ~200 ns
       ├── Wasm alloc + memcpy:    ~500 ns
       ├── Wasm evaluate():        ~4.4 µs  (core engine logic in sandbox)
       └── JSON deserialization:   ~540 ns

Wasm overhead vs native: ~5.5 µs (6.8x slower)
Wasm overhead as % of E2E: 88.6%
Wasm overhead as % of HTTP round-trip (~1-50ms): 0.01-0.6%
```

**Conclusion**: Wasm adds ~5.5µs overhead per evaluation. For a proxy that adds 300ms delay (IC-2) or waits for approval (IC-3), this is negligible (0.002%). Even for IC-1 allow decisions, 6µs is well within SLA bounds. The security guarantee of memory isolation justifies the cost.

### Vault fsync P99 Tail Latency

| Benchmark | Latency | Notes |
|-----------|---------|-------|
| `write_only_bytes/1KB` | **2.06 ms** | Single encrypt + fsync |
| `write_only_bytes/4KB` | **2.07 ms** | Encryption scales linearly, fsync dominates |
| `write_only_bytes/16KB` | **2.08 ms** | Still fsync-dominated |
| `write_only_bytes/64KB` | **2.14 ms** | Slight increase from larger memcpy |
| `write_only_bytes/256KB` | **2.50 ms** | Noticeable encryption + write overhead |
| `monolithic_256KB` | **2.46 ms** | Single 256KB write + fsync |
| `chunked_16x16KB` | **32.79 ms** | 16 × (encrypt + write + fsync) |

### Vault Write Amplification Analysis

```text
Value Size    fsync Latency    Observation
1 KB          2.06 ms          fsync dominates (encryption is ~1µs)
4 KB          2.07 ms          Same — encryption still negligible
16 KB         2.08 ms          Same — below page flush threshold
64 KB         2.14 ms          ~4% increase — larger kernel buffer flush
256 KB        2.50 ms          ~21% increase — approaching sequential I/O cost

Monolithic 256KB:  2.46 ms  (1 fsync)
Chunked 16×16KB:  32.79 ms  (16 fsyncs)  → 13.3x slower

Conclusion: fsync is the dominant cost. Chunking increases tail latency
by 13x due to per-chunk fsync. For large values, monolithic write is
preferred unless crash-recovery granularity is critical.
```

**Design Decision**: The current architecture uses monolithic writes per event (single fsync per group-commit batch). This is optimal — the Merkle batch flush writes all events + batch record in a single `write_all()` + `fsync()` call, avoiding chunked write amplification.

### IPv6 SSRF Defense Coverage

| Attack Vector | Variants Tested | Result |
|---------------|----------------|--------|
| IPv6 loopback `[::1]` | `[::1]`, `[0:0:0:0:0:0:0:1]`, `[0000:...:0001]`, `[0::0:0:0:0:0:1]` | All Deny |
| IPv4-mapped `[::ffff:127.0.0.1]` | `[::ffff:127.0.0.1]`, `[0:0:0:0:0:ffff:127.0.0.1]`, `[::ffff:7f00:1]` | All Deny |
| Cloud metadata IPv6 | `[fd00:ec2::254]`, `[::ffff:169.254.169.254]` | All Deny |
| Private ranges mapped | `[::ffff:10.0.0.1]`, `[::ffff:192.168.1.1]` | All Deny |

Defense mechanism: `normalize_host()` in `src/srr.rs` expands all IPv6 variants via `expand_ipv6()` and normalizes to canonical IPv4 form before SRR matching. This prevents bypass through zero-compression, bracket notation, or IPv4-mapped notation.

---

[← Part 9: Test Report](09-test-report.md) | [Overview →](00-overview.md)
