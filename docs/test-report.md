# Test & Benchmark Report

**Last Verified: 2026-05-01** (`cargo test --workspace`: full workspace passed, 0 failed on Windows; Linux/EC2-only sandbox scenarios remain release gates)

> **Note on snapshots:** Per-suite test names listed in this document are
> historical snapshots. Names rotate as the suite evolves. After a test-
> quality audit pass on 2026-05-01, several entries below now refer to
> previous test names that have been renamed or removed (e.g.
> `group_commit_fail_close_all_callers_receive_error` → split into
> `group_commit_primary_fail_emergency_wal_catches` plus a tracked-
> missing companion). Always confirm the current state by running
> `cargo test --workspace`. The "0 failed on Windows" line above does
> NOT exercise the Linux-gated sandbox isolation tests; those are
> covered only on the EC2 release gate.

> Test count grows with each feature. Run `cargo test --workspace` to verify current count.
>
> **Architecture note:** SRR is the authoritative network enforcement layer; SDK headers are convenience metadata and cannot downgrade transport-level SRR decisions. The decision set is 5 variants (`Allow < AuditOnly < Delay < RequireApproval < Deny`), and `max_strict` resolves cross-layer conflicts. Unknown or unclassified traffic must fall to Default-to-Caution (`Delay 300ms`), not `Allow`. Earlier ABAC/Registry/`Throttle` sections were removed from this report when those subsystems were deleted from the codebase.

## Design Compliance Baseline

These are the design principles every test in this report is interpreted against:

| Principle | Test expectation |
|-----------|------------------|
| Proxy/SRR is authority | Agent-declared SDK headers cannot make a dangerous URL safer. Host, method, path, and inspected payload drive enforcement. |
| Fail-close / Default-to-Caution | Unknown input, malformed payloads, oversized bodies, and unmatched URLs must return `Delay` or stricter, never `Allow`. |
| `max_strict` monotonicity | Tenant/SDK/semantic context may raise strictness, but cannot lower SRR `Deny` or `Delay`. |
| Auditability | Decisions on proxy and MITM paths must emit governance headers and WAL metadata where classification exists. |
| DNS governance scope | DNS hostile tests must expect tiered delay/logging in sandbox mode, not DNS Deny. Cooperative and contained modes do not claim DNS control. |
| Mode boundary honesty | Contained mode is Linux/WSL2 egress-lock without MITM; Sandbox is the full L7 MITM security boundary. |

## Overview

| Category | Count | Scope | Run frequency |
|----------|-------|-------|---------------|
| **Unit tests** (Rust, all crates) | ~390 (Windows) / ~410 (Linux, +sandbox network/cgroup/seccomp) | Pure logic, no I/O | Every `cargo test` |
| **Integration tests** (Rust) | 89 across `tests/` (boundary, hostile, edge, integration, merkle, stress, enforcement, api_handlers, common_sanity, adversarial_infra) | Cross-module interaction | Every `cargo test` |
| **EC2 E2E** | 84+ scenarios | Full CLI pipeline on Linux | Per-release on EC2 |
| **Chaos stress** | 60-min sustained load | Proxy kill, network partition, disk pressure | Per-release on EC2 |
| **DNS governance E2E** | 9 subtests (Test 83) + 1 (Test 84) | Layer 0 tier escalation, decay, DoH mitigation | Per-release on EC2 |
| **Ghost stress** | 9 verification checks | Autonomous agent + 5 attack tools | Per-release on EC2 |
| **Benchmarks** | 17 groups (Criterion) | Latency, throughput, tail latency | On demand |
| **Fuzzing** | 9 targets (libFuzzer) | Crash resistance, coverage growth | Daily CI (Mon-Sat 5min, Sun 30min) |
| **Multi-agent validation** | 2 frameworks (OpenClaw, hermes-agent) | Framework-independent governance | Per-release on EC2 |

## Document Structure

| Section | What it covers |
|---------|---------------|
| **A. Unit & Integration Tests** | Rust `#[test]` — logic, security boundaries, edge cases, adversarial |
| **B. EC2 End-to-End Tests** | CLI-only scenarios on real Linux (Tests 1–84) |
| **C. Stress & Chaos Tests** | Long-running resilience: 60-min chaos, ghost stress |
| **D. Benchmarks** | Criterion microbenchmarks + end-to-end overhead measurement |
| **E. Fuzzing** | libFuzzer continuous fuzzing with coverage tracking |
| **F. Coverage Gaps** | Known untested areas and tracking |

---

# A. Unit & Integration Tests

---

## A.1 Test Architecture

```
tests/
├── hostile.rs          # 28 adversarial/concurrency tests
├── integration.rs      # 12 end-to-end pipeline tests (5 enforcement + 2 config integrity + 5 coverage gap)
├── edge_cases.rs       # 17 edge case tests
├── stress.rs           # 12 stress/performance tests
├── boundary.rs         # 32 cross-boundary security tests
├── merkle.rs           # 12 Merkle tree integrity tests
src/
├── srr.rs              # 24 unit tests (13 + 6 path normalization + 5 path_regex)
├── vault.rs            # 15 unit tests (7 crypto + 2 backend + 6 key validation)
├── wasm_engine.rs      # 4 unit tests
├── merkle.rs           # 9 Merkle hash/proof tests
├── llm_trace.rs        # 26 LLM thinking trace tests
├── auth.rs             # 21 JWT authentication tests
├── proxy.rs            # 6 response-trace extraction tests
crates/gvm-engine/
├── src/lib.rs          # 7 engine tests
crates/gvm-cli/
├── src/run.rs          # 8 proxy URL detection unit tests
├── src/suggest.rs      # 6 path generalization tests
├── tests/cli_integration.rs # 3 command surface integration tests
crates/gvm-sandbox/
├── src/tls_probe.rs    # 10 TLS probe tests (symbol resolution, HTTP parsing, policy callback)
├── tests/security.rs   # 8 sandbox config + preflight tests
scripts/
├── ec2-e2e-test.sh     # 75 Linux E2E scenarios (EC2/Codespace)
├── ec2-setup.sh        # One-command EC2 setup
├── stress-test.sh      # 60-min chaos stress test (proxy kill, network partition, disk pressure)
benches/
├── pipeline.rs         # 17 benchmark groups (Criterion)
fuzz/fuzz_targets/
├── fuzz_srr.rs         # SRR regex matching + pattern evaluation
├── fuzz_wal_parse.rs   # WAL JSON event deserialization
├── fuzz_http_parse.rs  # MITM HTTP request parsing (CL/TE, headers, body)
├── fuzz_path_normalize.rs  # Path normalization chain (percent-decode, dot-segment, null-strip)
├── fuzz_llm_trace.rs   # LLM thinking trace extraction (JSON + SSE, all providers)
├── fuzz_dns_parse.rs   # DNS UDP packet → domain extraction (governance proxy parser)
├── fuzz_vault_crypto.rs # AES-256-GCM encrypt/decrypt round-trip + corruption
├── fuzz_jwt_auth.rs    # JWT verification (signature/expiry/algorithm-confusion)
├── fuzz_credential_inject.rs # API credential injection + agent header stripping
```

**Fuzzing CI**: GitHub Actions daily run (`.github/workflows/fuzz.yml`), 5 min per target, corpus cached across runs.

---

## A.2 Test Execution Log (Historical Snapshot: 2026-03-16)

> The lines below are kept as a historical record of the codebase shape at
> 2026-03-16. Tests for the deleted ABAC `policy` and `registry` modules
> were removed from the snapshot when those modules were deleted from the
> source tree. Run `cargo test --workspace` for the current count.

```
$ cargo test  (historical, 2026-03-16, ABAC-era entries pruned)

running 46 tests                              (src/lib.rs — unit tests)
test srr::tests::no_body_for_payload_rule_skips_to_next ... ok
test srr::tests::method_mismatch_does_not_trigger_rule ... ok
test srr::tests::large_64kb_body_does_not_crash_or_oom ... ok
test vault::tests::test_different_nonces_produce_different_ciphertext ... ok
test vault::tests::test_empty_plaintext_roundtrip ... ok
test vault::tests::test_encrypt_decrypt_roundtrip ... ok
test srr::tests::payload_exceeding_max_body_bytes_falls_back_to_default_caution ... ok
test vault::tests::test_tampered_ciphertext_fails ... ok
test srr::tests::srr_catches_url_regardless_of_operation_header ... ok
test vault::tests::test_truncated_ciphertext_returns_integrity_error ... ok
test srr::tests::suffix_host_pattern_blocks_all_subdomains ... ok
test vault::tests::test_wrong_key_returns_integrity_error ... ok
test wasm_engine::tests::test_native_deny ... ok
test wasm_engine::tests::test_load_missing_wasm ... ok
test wasm_engine::tests::test_native_fallback ... ok
test wasm_engine::tests::test_response_to_decision ... ok
test vault::tests::test_nonce_reuse_not_possible ... ok
test srr::tests::wildcard_method_matches_all_http_methods ... ok
test srr::tests::unknown_url_gets_default_to_caution ... ok
test srr::tests::payload_at_exact_limit_is_inspected ... ok
test srr::tests::malformed_json_body_skips_payload_rule ... ok
test srr::tests::host_with_port_matches_exact_pattern ... ok
test srr::tests::host_with_port_matches_suffix_pattern ... ok
test srr::tests::payload_exceeding_max_body_bytes_skips_to_next_rule ... ok
test srr::tests::payload_exceeding_max_body_bytes_no_fallback_gets_default_caution ... ok
test srr::tests::percent_encoded_path_is_decoded_before_matching ... ok
test srr::tests::double_slash_collapsed_before_matching ... ok
test srr::tests::dot_segment_traversal_does_not_bypass_deny ... ok
test srr::tests::already_canonical_path_no_allocation ... ok
test srr::tests::normalize_path_handles_edge_cases ... ok
test llm_trace::tests::test_identify_llm_provider ... ok
test llm_trace::tests::test_extract_anthropic_thinking ... ok
test llm_trace::tests::test_extract_openai_reasoning ... ok
test llm_trace::tests::test_extract_gemini_thought ... ok
test llm_trace::tests::test_no_thinking_content_returns_usage_only ... ok
test llm_trace::tests::test_non_llm_body_returns_none ... ok
test llm_trace::tests::test_empty_provider_returns_none ... ok
test llm_trace::tests::test_truncation ... ok
test merkle::tests::merkle_single_leaf ... ok
test merkle::tests::merkle_two_leaves ... ok
test merkle::tests::merkle_four_leaves_balanced ... ok
test merkle::tests::merkle_odd_leaves_duplicates_last ... ok
test merkle::tests::merkle_different_order_different_root ... ok
test merkle::tests::merkle_deterministic ... ok
test merkle::tests::merkle_proof_verifies_each_leaf ... ok
test merkle::tests::merkle_proof_rejects_wrong_leaf ... ok
test merkle::tests::merkle_proof_rejects_wrong_root ... ok
test result: ok. 46 passed; 0 failed; 0 ignored; finished in 0.05s

running 26 tests                              (tests/boundary.rs)
test api_key_not_leaked_via_gvm_headers ... ok
test duplicate_gvm_headers_first_value_wins ... ok
test gvm_headers_stripped_before_forwarding ... ok
test header_injection_newline_rejected ... ok
test inbound_decision_header_not_in_parsed_gvm_headers ... ok
test ssrf_cloud_metadata_blocked_by_srr ... ok
test srr_redirect_target_blocked ... ok
test ssrf_private_ip_ranges_blocked_by_srr ... ok
test ssrf_localhost_blocked_by_srr ... ok
test wasm_all_decision_types_roundtrip ... ok
test wasm_invalid_decision_string_maps_to_delay ... ok
test wasm_null_bytes_in_string_fields ... ok
test wasm_malformed_response_does_not_crash ... ok
test wasm_unicode_boundary_operation_names ... ok
test wasm_concurrent_native_evaluations_no_corruption ... ok
test vault_key_collision_between_agents ... ok
test vault_empty_value_roundtrip ... ok
test vault_delete_then_read_returns_none ... ok
test vault_tampered_ciphertext_detected ... ok
test vault_concurrent_read_write_same_key ... ok
test nats_empty_url_wal_only_mode ... ok
test nats_wal_sequence_monotonic ... ok
test nats_channel_backpressure_bounded ... ok
test wasm_oversized_input_handled_gracefully ... ok
test vault_large_value_roundtrip ... ok
test result: ok. 25 passed; 0 failed; 0 ignored; finished in 0.35s

running 10 tests                              (tests/edge_cases.rs)
test edge_max_strict_delay_vs_require_approval ... ok
test edge_max_strict_strictness_ordering_complete ... ok
test edge_missing_gvm_headers_srr_only_fallback ... ok
test edge_empty_body_payload_inspection_skips ... ok
test edge_null_bytes_in_path_safe_handling ... ok
test edge_recovery_no_pending_events ... ok
test edge_very_long_host_and_path ... ok
test edge_binary_body_json_parse_fails_gracefully ... ok
test edge_unicode_operation_name ... ok
test edge_concurrent_status_update_no_crash ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; finished in 0.02s

running 11 tests                              (tests/hostile.rs)
test max_strict_deny_overrides_allow ... ok
test rate_limiter_100_concurrent_checks_no_deadlock ... ok
test header_forgery_srr_denies_bank_transfer_regardless ... ok
test srr_garbage_input_does_not_panic ... ok
test srr_100_concurrent_checks_complete_without_blocking ... ok
test vault_key_is_zeroed_on_drop ... ok
test group_commit_fail_close_all_callers_receive_error ... ok
test wal_tampered_entry_does_not_crash_recovery ... ok
test vault_concurrent_writes_to_same_key ... ok
test srr_decision_time_is_roughly_constant ... ok
test ledger_concurrent_spawns_stay_bounded ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; finished in 0.04s

running 9 tests                               (tests/integration.rs)
test api_key_injection_bearer_and_apikey_types ... ok
test event_status_transitions_pending_to_confirmed_and_failed ... ok
test wal_nats_sequence_ordering_and_crash_recovery ... ok
test sdk_headers_to_proxy_classification_end_to_end ... ok
test config_file_hashes_recorded_in_merkle_chain ... ok
test config_hash_records_unavailable_for_missing_files ... ok
test e2e_proxy_forwards_to_upstream_and_strips_response_headers ... ok
test governance_block_response_contains_all_required_fields ... ok
test emergency_wal_to_primary_recovery_path ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; finished in 0.42s

running 9 tests                               (tests/stress.rs)
test stress_100_concurrent_mixed_ic_decisions ... ok
test srr_payload_boundary_no_overflow ... ok
test wal_1000_concurrent_durable_appends ... ok
test srr_1mb_toml_file_no_oom ... ok
test vault_1mb_value_roundtrip ... ok
test srr_10000_rules_load_and_lookup ... ok
test wal_sustained_load_10k_events ... ok
test token_budget_window_boundary_no_double_count ... ok
test vault_10k_encrypt_decrypt_no_leak ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; finished in 6.63s
```

**Total (historical, pre-auth/vault-trait additions, ABAC-era entries pruned): 100 passed, 0 failed. Wall time: ~7.5s.**

> **Current total (2026-05-01)**: the full Windows workspace run passed with 0 failures. Run `cargo test --workspace` for the live count; Linux/EC2 adds sandbox-only gates that are not executed by the Windows host run.

---

## A.3 Unit Tests — Detailed Scenarios

### Network SRR (19 tests) — [src/srr.rs](src/srr.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`payload_exceeding_max_body_bytes_skips_to_next_rule`](src/srr.rs) | 200B body with `max_body_bytes=100`, fallback rule exists | Skips payload rule, matches URL-only fallback |
| 2 | [`payload_exceeding_max_body_bytes_no_fallback_gets_default_caution`](src/srr.rs) | 200B body with `max_body_bytes=100`, no fallback rule | Returns Delay 300ms (Default-to-Caution) |
| 3 | [`payload_at_exact_limit_is_inspected`](src/srr.rs) | Body at limit with `operationName=TransferFunds` | Returns Deny — payload inspection proceeds |
| 4 | [`large_64kb_body_does_not_crash_or_oom`](src/srr.rs) | 128KB body | Returns Default-to-Caution, no crash or OOM |
| 5 | [`malformed_json_body_skips_payload_rule`](src/srr.rs) | Invalid JSON `"this is not json {{{"` | Falls through to next URL-only rule (Delay 300ms) |
| 6 | [`no_body_for_payload_rule_skips_to_next`](src/srr.rs) | No body for payload inspection rule | Falls through to next rule |
| 7 | [`srr_catches_url_regardless_of_operation_header`](src/srr.rs) | URL=`api.bank.com/transfer/123` | Deny — SRR ignores semantic headers |
| 8 | [`unknown_url_gets_default_to_caution`](src/srr.rs) | `totally-unknown.com/some/path` | Delay 300ms (Default-to-Caution) |
| 9 | [`suffix_host_pattern_blocks_all_subdomains`](src/srr.rs) | `{host}.database.com` pattern | prod/staging/dev.database.com all Denied |
| 10 | [`method_mismatch_does_not_trigger_rule`](src/srr.rs) | GET to POST-only rule | Not denied (Default-to-Caution) |
| 11 | [`wildcard_method_matches_all_http_methods`](src/srr.rs) | `method = "*"` on `evil.com` | GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS all Denied |
| 12 | [`host_with_port_matches_exact_pattern`](src/srr.rs) | `api.bank.com:8443` matches `api.bank.com` rule | Port stripped before matching |
| 13 | [`host_with_port_matches_suffix_pattern`](src/srr.rs) | `prod.database.com:5432` matches `{host}.database.com` | Port stripped, suffix pattern matched |
| 14 | [`percent_encoded_path_is_decoded_before_matching`](src/srr.rs) | `/%74ransfer/123` (percent-encoded) | Decoded to `/transfer/123`, denied |
| 15 | [`double_slash_collapsed_before_matching`](src/srr.rs) | `//transfer/123` | Collapsed to `/transfer/123`, denied |
| 16 | [`dot_segment_traversal_does_not_bypass_deny`](src/srr.rs) | `/safe/../transfer/123` | Resolved to `/transfer/123`, denied |
| 17 | [`already_canonical_path_no_allocation`](src/srr.rs) | Clean paths `/transfer/123`, `/`, `/a/b/c` | `normalize_path` returns None (zero allocation) |
| 18 | [`normalize_path_handles_edge_cases`](src/srr.rs) | `%2F`, `..` at end, `///`, `/./ `, null bytes | All edge cases produce correct canonical paths |

### Encrypted Vault (7 tests) — [src/vault.rs](src/vault.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_encrypt_decrypt_roundtrip`](src/vault.rs) | Encrypt `"sensitive agent state data"` → decrypt | Original plaintext recovered exactly |
| 2 | [`test_different_nonces_produce_different_ciphertext`](src/vault.rs) | Same plaintext encrypted twice | Different ciphertext (random 12-byte nonce) |
| 3 | [`test_tampered_ciphertext_fails`](src/vault.rs) | XOR bit-flip at byte 13 of ciphertext | AES-GCM auth tag verification fails |
| 4 | [`test_truncated_ciphertext_returns_integrity_error`](src/vault.rs) | 5-byte input (< 12-byte nonce) | Returns "integrity error" message |
| 5 | [`test_wrong_key_returns_integrity_error`](src/vault.rs) | Encrypt with key1, decrypt with key2 | Returns "integrity error", no AES internals leaked |
| 6 | [`test_empty_plaintext_roundtrip`](src/vault.rs) | Encrypt/decrypt empty bytes `b""` | Roundtrip succeeds |
| 7 | [`test_nonce_reuse_not_possible`](src/vault.rs) | 100 encryptions of same plaintext | 100 unique 12-byte nonces (HashSet verification) |

### Wasm Engine (4 tests) — [src/wasm_engine.rs](src/wasm_engine.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_native_fallback`](src/wasm_engine.rs) | `WasmEngine::native()` | `is_wasm()=false`, `module_hash=None`, evaluates to Allow |
| 2 | [`test_native_deny`](src/wasm_engine.rs) | Rule: `resource.sensitivity == critical` | Returns Deny with reason "Critical data protected" |
| 3 | [`test_response_to_decision`](src/wasm_engine.rs) | EvalResponse `decision="Delay", delay_ms=500` | Maps to `EnforcementDecision::Delay{milliseconds: 500}` |
| 4 | [`test_load_missing_wasm`](src/wasm_engine.rs) | Load from `nonexistent.wasm` | Falls back to native mode, `is_wasm()=false` |

### GVM-Engine (7 tests) — [crates/gvm-engine/src/lib.rs](crates/gvm-engine/src/lib.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_allow_when_no_rules`](crates/gvm-engine/src/lib.rs) | EvalRequest with empty rules | Returns Allow |
| 2 | [`test_deny_critical_delete`](crates/gvm-engine/src/lib.rs) | `resource.sensitivity == critical` match | Returns Deny |
| 3 | [`test_delay_medium_send`](crates/gvm-engine/src/lib.rs) | `operation StartsWith gvm.messaging`, Delay 300ms | Returns Delay{300} |
| 4 | [`test_json_roundtrip`](crates/gvm-engine/src/lib.rs) | EvalRequest serialize → deserialize | Round-trips correctly |
| 5 | [`test_pascal_case_operators_accepted`](crates/gvm-engine/src/lib.rs) | PascalCase operator strings (`"StartsWith"`, `"Eq"`) | All recognized, no parse error |
| 6 | [`test_context_attribute_matching`](crates/gvm-engine/src/lib.rs) | `context.amount > 10000` on high-value payload | Correct decision matched |
| 7 | [`test_strictest_wins_across_layers`](crates/gvm-engine/src/lib.rs) | Allow (priority 100) + Deny (priority 1) | max_strict: Deny wins |

### GVM-CLI suggest (6 tests) — [crates/gvm-cli/src/suggest.rs](crates/gvm-cli/src/suggest.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`generalize_short_static_path`](crates/gvm-cli/src/suggest.rs) | `/v1/messages`, `/api/health` | Returned unchanged (no ID segments) |
| 2 | [`generalize_path_with_numeric_id`](crates/gvm-cli/src/suggest.rs) | `/users/12345/orders`, `/transfer/99999` | Numeric segment replaced with `{any}` |
| 3 | [`generalize_path_with_uuid`](crates/gvm-cli/src/suggest.rs) | RFC-4122 UUID in path segment | UUID segment replaced with `{any}` |
| 4 | [`generalize_empty_path`](crates/gvm-cli/src/suggest.rs) | `/`, `""` | Returns `/{any}` |
| 5 | [`looks_like_id_detects_numbers`](crates/gvm-cli/src/suggest.rs) | `12345`, `0` vs `users`, `v1` | Digits detect as ID; alpha strings do not |
| 6 | [`looks_like_id_detects_uuids`](crates/gvm-cli/src/suggest.rs) | Full UUID vs short hyphenated string | Full RFC-4122 detected; short strings not |

### GVM-CLI run (8 tests) — [crates/gvm-cli/src/run.rs](crates/gvm-cli/src/run.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_is_local_proxy_url_localhost`](crates/gvm-cli/src/run.rs) | `http://localhost:8080` | Returns true |
| 2 | [`test_is_local_proxy_url_127_0_0_1`](crates/gvm-cli/src/run.rs) | `http://127.0.0.1:8080` | Returns true |
| 3 | [`test_is_local_proxy_url_ipv6_loopback`](crates/gvm-cli/src/run.rs) | `http://[::1]:8080` | Returns true (IPv6) |
| 4 | [`test_is_local_proxy_url_no_port`](crates/gvm-cli/src/run.rs) | `http://localhost` | Returns true (auto-default port semantics) |
| 5 | [`test_is_local_proxy_url_with_trailing_slash`](crates/gvm-cli/src/run.rs) | `http://localhost:8080/` | Returns true |
| 6 | [`test_is_local_proxy_url_remote_host`](crates/gvm-cli/src/run.rs) | `http://proxy.example.com:8080` | Returns false (non-local FQDN) |
| 7 | [`test_is_local_proxy_url_remote_ip`](crates/gvm-cli/src/run.rs) | `http://192.168.1.1:8080` | Returns false (non-loopback IP) |
| 8 | [`test_is_local_proxy_url_invalid_url`](crates/gvm-cli/src/run.rs) | `not-a-valid-url` | Returns false (parse error handling) |

### GVM-CLI Integration (3 tests) — [crates/gvm-cli/tests/cli_integration.rs](crates/gvm-cli/tests/cli_integration.rs)

| # | Test | Scenario | Notes |
|---|------|----------|-------|
| 1 | [`test_gvm_run_help_succeeds`](crates/gvm-cli/tests/cli_integration.rs) | `gvm run --help` command | Validates binary availability and help rendering |
| 2 | [`test_gvm_events_list_basic`](crates/gvm-cli/tests/cli_integration.rs) | `gvm events list` command | Confirms command structure and exit code |
| 3 | [`test_gvm_stats_basic`](crates/gvm-cli/tests/cli_integration.rs) | `gvm stats tokens` command | Tests stats subcommand availability |
| *E2E* | [`test_gvm_run_local_mode_with_proxy_autostart`](crates/gvm-cli/tests/cli_integration.rs) | Full: proxy down → auto-start → agent run | Ignored by default; run with `--ignored` flag |

---

## A.4 Integration Tests — Detailed Scenarios

### Hostile Environment (28 tests) — [tests/hostile.rs](tests/hostile.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`srr_100_concurrent_checks_complete_without_blocking`](tests/hostile.rs) | 100 tokio tasks × 4 request patterns | All complete < 1s, ≥25 denies (transfer+graphql) |
| 2 | [`rate_limiter_100_concurrent_checks_no_deadlock`](tests/hostile.rs) | 5 agents × 20 requests, limit 10/min | Completes < 500ms, ≤50 allowed, denied > 0 |
| 3 | [`wal_tampered_entry_does_not_crash_recovery`](tests/hostile.rs) | WAL with 2 valid + 1 corrupted JSON entry | Recovery finds 2 Pending, marks 2 Expired, no crash |
| 4 | [`vault_concurrent_writes_to_same_key`](tests/hostile.rs) | 50 concurrent writes to `"shared-key"` | Completes < 5s, key exists, value starts with `"value-"` |
| 5 | [`max_strict_deny_overrides_allow`](tests/hostile.rs) | `max_strict(Allow, Deny)` and reverse | Both return Deny |
| 6 | [`header_forgery_srr_denies_bank_transfer_regardless`](tests/hostile.rs) | SRR denies `api.bank.com/transfer/*` | Deny even when policy says Allow (max_strict) |
| 7 | [`srr_garbage_input_does_not_panic`](tests/hostile.rs) | 8 garbage URL inputs + 7 garbage body inputs | No panic on any input |
| 8 | [`vault_key_is_zeroed_on_drop`](tests/hostile.rs) | Vault write+read, then drop | Drop completes without crash (zeroize contract) |
| 9 | [`ledger_concurrent_spawns_stay_bounded`](tests/hostile.rs) | 500 rapid-fire durable appends | Completes < 10s, WAL has exactly 500 entries |
| 10 | [`srr_decision_time_is_roughly_constant`](tests/hostile.rs) | 10K deny iterations vs 10K allow iterations | Timing ratio < 10x (side-channel resistance) |
| 11 | [`group_commit_fail_close_all_callers_receive_error`](tests/hostile.rs) | Inject I/O error → 10 concurrent appends | All 10 callers receive Err (Fail-Close guarantee) |

### End-to-End Pipeline (10 tests) — [tests/integration.rs](tests/integration.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`sdk_headers_to_proxy_classification_end_to_end`](tests/integration.rs) | SDK headers → SRR classification | classify() returns correct decision, agent_id/operation surfaced for audit |
| 2 | [`event_status_transitions_pending_to_confirmed_and_failed`](tests/integration.rs) | Create Pending → update to Confirmed/Failed | Status field transitions correctly |
| 3 | [`wal_nats_sequence_ordering_and_crash_recovery`](tests/integration.rs) | 50 concurrent WAL writes + recovery | WAL ordering preserved, Pending → Expired on crash |
| 4 | [`api_key_injection_bearer_and_apikey_types`](tests/integration.rs) | APIKeyStore inject Bearer + ApiKey | Headers `Authorization: Bearer sk-xxx` and `X-Api-Key: key123` |
| 5 | [`config_file_hashes_recorded_in_merkle_chain`](tests/integration.rs) | Config files → WAL system event | SHA-256 hashes correct, event_hash present (Merkle) |
| 6 | [`config_hash_records_unavailable_for_missing_files`](tests/integration.rs) | Missing config file | Hash recorded as `"unavailable"`, no error |
| 7 | [`e2e_proxy_forwards_to_upstream_and_strips_response_headers`](tests/integration.rs) | Real mock upstream → proxy forward → response | Upstream receives request, X-GVM-* response headers stripped, API key injected, non-GVM headers preserved |
| 8 | [`governance_block_response_contains_all_required_fields`](tests/integration.rs) | Deny-triggering request → 403 JSON | Response contains all GovernanceBlockResponse fields (blocked, decision, event_id, trace_id, operation, reason, mode, next_action, ic_level) |
| 9 | [`sdk_proxy_header_contract_resource_and_context_json`](tests/integration.rs) | SDK JSON in X-GVM-Resource/Context headers + SRR Deny on `api.bank.com/transfer/*` | SDK self-declared `approved=true` / `risk=low` cannot downgrade SRR Deny — metadata stays as audit data only |
| 10 | [`emergency_wal_to_primary_recovery_path`](tests/integration.rs) | Primary WAL fail → emergency fallback → recovery | Emergency WAL has event_hash but no MerkleBatchRecord, primary failure counter tracks correctly |

### Edge Cases (10 tests) — [tests/edge_cases.rs](tests/edge_cases.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`edge_empty_body_payload_inspection_skips`](tests/edge_cases.rs) | Empty body `b""` for payload rule | Skips payload inspection, falls through |
| 2 | [`edge_binary_body_json_parse_fails_gracefully`](tests/edge_cases.rs) | PNG header `\x89PNG\r\n` as body | JSON parse fails, falls through to next rule |
| 3 | [`edge_null_bytes_in_path_safe_handling`](tests/edge_cases.rs) | Path `/api/\x00/secrets` | No panic, returns decision |
| 4 | [`edge_unicode_operation_name`](tests/edge_cases.rs) | Korean Unicode operation name, emoji `"gvm.💰.send"` | No panic, returns decision |
| 5 | [`edge_very_long_host_and_path`](tests/edge_cases.rs) | 10K char host + 100K char path | No panic, returns Default-to-Caution |
| 6 | [`edge_missing_gvm_headers_srr_only_fallback`](tests/edge_cases.rs) | No X-GVM-Agent-Id header | SRR-only classification — agent_id falls back to "unknown" |
| 7 | [`edge_max_strict_delay_vs_require_approval`](tests/edge_cases.rs) | Delay(300ms) vs RequireApproval | RequireApproval wins (strictness 4 > 3) |
| 8 | [`edge_max_strict_strictness_ordering_complete`](tests/edge_cases.rs) | All 5 types pairwise (10 combinations) | Strictness order: Allow<AuditOnly<Delay<RequireApproval<Deny |
| 9 | [`edge_concurrent_status_update_no_crash`](tests/edge_cases.rs) | 50 concurrent status updates to same event | No crash or data corruption |
| 10 | [`edge_recovery_no_pending_events`](tests/edge_cases.rs) | WAL with only Confirmed events | Recovery reports 0 pending, 0 expired |

### Stress Tests (8 default + 2 ignored) — [tests/stress.rs](tests/stress.rs)

| # | Test | Scale | Verification |
|---|------|-------|--------------|
| 1 | [`srr_10000_rules_load_and_lookup`](tests/stress.rs) | 10K rules | Loads successfully, lookup finds correct rule |
| 2 | [`srr_1mb_toml_file_no_oom`](tests/stress.rs) | 1MB TOML config | No OOM, correct parsing |
| 3 | [`srr_payload_boundary_no_overflow`](tests/stress.rs) | Body at exact `max_body_bytes` boundary | No overflow, correct inspection |
| 4 | [`vault_10k_encrypt_decrypt_no_leak`](tests/stress.rs) | 10K encrypt/decrypt roundtrips | All match, no memory leak |
| 5 | [`vault_1mb_value_roundtrip`](tests/stress.rs) | 1MB value | Correct encrypt/decrypt roundtrip |
| 6 | [`wal_1000_concurrent_durable_appends`](tests/stress.rs) | 1K concurrent tokio tasks | All 1000 entries in WAL |
| 7 | [`wal_sustained_load_10k_events`](tests/stress.rs) | 10K sequential (GroupCommit: batch_window=2ms, max_batch=256) | All 10K written, group commit amortizes fsync |
| 8 | [`stress_100_concurrent_mixed_ic_decisions`](tests/stress.rs) | 100 concurrent: 50% Allow, 30% Delay, 20% Deny | All decisions correct per IC classification |
| 9 (`#[ignore]`) | [`wal_throughput_all_allow`](tests/stress.rs) | Allow-path throughput | Manual run only — heavy benchmark, not gated by default |
| 10 (`#[ignore]`) | [`verify_wal_latency_100k_events`](tests/stress.rs) | 100K WAL audit-verify latency | Manual run only — long execution |

### Boundary/Security Tests (32 tests) — [tests/boundary.rs](tests/boundary.rs)

| # | Boundary | Test | Verification |
|---|----------|------|--------------|
| 1 | Wasm↔Host | [`wasm_invalid_decision_string_maps_to_delay`](tests/boundary.rs) | `"InvalidDecisionType"` → Delay(300ms) (fail-close default) |
| 2 | Wasm↔Host | [`wasm_malformed_response_does_not_crash`](tests/boundary.rs) | 10 garbage JSON inputs → all return valid JSON |
| 3 | Wasm↔Host | [`wasm_oversized_input_handled_gracefully`](tests/boundary.rs) | 1MB operation name → no crash, returns Allow |
| 4 | Wasm↔Host | [`wasm_unicode_boundary_operation_names`](tests/boundary.rs) | Korean, null byte, max BMP, emoji, RTL override → no crash |
| 5 | Wasm↔Host | [`wasm_null_bytes_in_string_fields`](tests/boundary.rs) | `\0` in all fields → condition matching still works |
| 6 | Wasm↔Host | [`wasm_all_decision_types_roundtrip`](tests/boundary.rs) | All 6 decision types map correctly via `response_to_decision()` |
| 7 | Wasm↔Host | [`wasm_concurrent_native_evaluations_no_corruption`](tests/boundary.rs) | 100 concurrent evals → each result correct (Deny if rules, else Allow) |
| 8 | Inbound HTTP | [`inbound_decision_header_not_in_parsed_gvm_headers`](tests/boundary.rs) | `GVMHeaders` struct has no `decision` field (compile-time guarantee) |
| 9 | Inbound HTTP | [`duplicate_gvm_headers_first_value_wins`](tests/boundary.rs) | axum `.get()` returns first value for duplicate headers |
| 10 | Inbound HTTP | [`header_injection_newline_rejected`](tests/boundary.rs) | `\r\n`, `\n`, `\r` in header value → `HeaderValue::from_str` returns Err |
| 11 | Inbound HTTP | [`gvm_headers_stripped_before_forwarding`](tests/boundary.rs) | All 11 X-GVM-* headers removed; Authorization/Content-Type survive |
| 12 | Outbound API | [`ssrf_localhost_blocked_by_srr`](tests/boundary.rs) | `localhost/*` and `127.0.0.1/*` → Deny |
| 13 | Outbound API | [`ssrf_cloud_metadata_blocked_by_srr`](tests/boundary.rs) | `169.254.169.254/*`, `metadata.google.internal/*` → Deny |
| 14 | Outbound API | [`ssrf_max_strict_srr_deny_overrides_policy_allow`](tests/boundary.rs) | `max_strict(SRR:Deny, Policy:Allow)` → Deny |
| 15 | Outbound API | [`ssrf_private_ip_ranges_blocked_by_srr`](tests/boundary.rs) | `10.0.0.1`, `192.168.1.1`, `172.16.0.1` → Deny; `8.8.8.8` → Allow |
| 16 | Outbound API | [`api_key_not_leaked_via_gvm_headers`](tests/boundary.rs) | X-GVM-Context with `api_key` stripped before forwarding |
| 17 | Outbound API | [`srr_redirect_target_blocked`](tests/boundary.rs) | `httpbin.org/redirect/10` → Deny |
| 18 | NATS | [`nats_channel_backpressure_bounded`](tests/boundary.rs) | 200 events through 32-capacity channel → all succeed, no deadlock |
| 19 | NATS | [`nats_empty_url_wal_only_mode`](tests/boundary.rs) | Empty NATS URL → WAL-only, durable+async writes work, recovery works |
| 20 | NATS | [`nats_wal_sequence_monotonic`](tests/boundary.rs) | 50 concurrent appends → WAL has exactly 50 entries |
| 21 | Vault | [`vault_large_value_roundtrip`](tests/boundary.rs) | 1MB value encrypt/decrypt → exact match |
| 22 | Vault | [`vault_key_collision_between_agents`](tests/boundary.rs) | Agent-1 writes, Agent-2 overwrites → Agent-2's data returned |
| 23 | Vault | [`vault_tampered_ciphertext_detected`](tests/boundary.rs) | Write → read succeeds with correct data |
| 24 | Vault | [`vault_concurrent_read_write_same_key`](tests/boundary.rs) | 20 reads + 20 writes concurrent → all succeed, no crash |
| 25 | Vault | [`vault_delete_then_read_returns_none`](tests/boundary.rs) | Write → delete → read returns `None` |
| 26 | Vault | [`vault_empty_value_roundtrip`](tests/boundary.rs) | Empty `b""` encrypt/decrypt → exact match |

---

---

---

# D. Benchmarks

---

## D.1 Benchmark Results (Criterion v0.5, 2026-04-02)

**Source**: [benches/pipeline.rs](benches/pipeline.rs)
**Platform**: EC2 t3.medium, Ubuntu 24.04, kernel 6.17.0-1009-aws

### Classification E2E (SRR → max_strict)

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `classification_e2e/direct_http_srr_only` | **270 ns** | Direct HTTP, SRR-only classification |
| `classification_e2e/sdk_routed_full_pipeline` | **820 ns** | SDK-routed, SRR + max_strict (decision pipeline end-to-end) |
| `classification_e2e/full_pipeline_with_payload` | **750 ns** | Full pipeline with payload inspection |

**Key insight**: Full governance classification (SRR + max_strict) completes in <1µs. Hot path budget (1µs) is met.

### SRR Network Rule Matching

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `srr/allow_safe_host` | **190 ns** | Safe host lookup (first-match hit) |
| `srr/deny_bank_transfer` | **270 ns** | Bank transfer deny (multi-field match) |
| `srr/default_caution_unknown` | **380 ns** | Unknown URL fallthrough → Delay 300ms |
| `srr/payload_inspection` | **270 ns** | GraphQL operationName match |
| `srr/payload_size_bytes/64` | **240 ns** | 64B body payload inspection |
| `srr/payload_size_bytes/1024` | **240 ns** | 1KB body payload inspection |
| `srr/payload_size_bytes/16384` | **240 ns** | 16KB body payload inspection |
| `srr/payload_size_bytes/65536` | **240 ns** | 64KB body payload inspection |

**Key insight**: Body size does NOT affect SRR latency (240ns flat) — `max_body_bytes` short-circuits before JSON parsing. Path normalization (query strip + percent-decode + dot-segment) adds ~100ns vs raw match.

### SRR Scale Benchmarks

| Rule Count | First Match | Mid-Rule Match | Fallthrough All |
|-----------|-------------|----------------|-----------------|
| 100 | **170 ns** | **790 ns** | **200 ns** |
| 1,000 | **170 ns** | **6.8 µs** | **900 ns** |
| 10,000 | **340 ns** | **315 µs** | **11.6 µs** |

**Key insight**: First-match is constant (~170ns) regardless of rule count. Mid-rule match scales linearly. 10K fallthrough at 11.6µs is within hot-path budget for most deployments.

### max_strict Decision Combiner

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `max_strict/allow_vs_deny` | **20 ns** | Full decision clone + comparison |
| `max_strict/delay_vs_require_approval` | **10 ns** | Lightweight comparison |

### Vault (AES-256-GCM Encrypt + Decrypt + WAL)

| Value Size | Result | Description |
|-----------|--------|-------------|
| 32B | **6.23 ms** | encrypt + WAL fsync + decrypt |
| 256B | **6.40 ms** | |
| 1KB | **6.23 ms** | |
| 4KB | **6.26 ms** | |
| 16KB | **6.38 ms** | |

**Key insight**: Vault latency is dominated by WAL fsync (~6.2ms on EC2 EBS). AES-256-GCM encryption adds negligible overhead across all sizes.

### Vault Large Value Benchmarks

| Value Size | Result |
|-----------|--------|
| 64KB | **6.76 ms** |
| 256KB | **8.52 ms** |
| 1MB | **14.79 ms** |

### WAL (Write-Ahead Log)

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `wal/durable_append_fsync` | **6.28 ms** | Single event WAL append + fsync |
| `wal/100_sequential_appends` | **620.6 ms** | 100 sequential fsyncs (6.2ms each) |
| `wal_group_commit/concurrent/100` | **7.99 ms** | 100 concurrent → batched fsync |
| `wal_group_commit/concurrent/500` | **23.47 ms** | 500 concurrent → batched fsync |

**Key insight**: Group commit reduces 100 fsyncs from 620ms (sequential) to 8ms (batched) — **78x improvement**. 500 concurrent appends batch into 23ms.

### Token Budget (replaces the per-URL rate limiter)

The per-URL rate limiter from earlier versions has been replaced by `TokenBudget`
(global hourly token + cost ceiling for LLM cost governance, [src/token_budget.rs](src/token_budget.rs)).
Benchmarks for the new path are in [benches/pipeline.rs](benches/pipeline.rs)
under the `wal_group_commit` and `classification_e2e` groups; the historical
rate-limiter rows above no longer apply.

### IC-2 Delay Accuracy

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `ic2_delay/300ms_delay_accuracy` | **301.2 ms** | tokio::sleep precision |

### Vault Contention P99 — Tail Latency Under Load

| Concurrency | 4KB | 16KB | 64KB |
|------------|------|------|------|
| 10 writers | 6.5 ms | 7.2 ms | 13.2 ms |
| 50 writers | 9.3 ms | 13.8 ms | 29.9 ms |
| 100 writers | 11.3 ms | 19.9 ms | 51.8 ms |

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `p99_explicit_16kb_50writers` | **15.4 ms** | Max latency across 50 concurrent 16KB write+read ops |

**Key insight**: Tail latency scales sub-linearly with concurrency for small values. 64KB at 100 writers reaches 52ms — fsync contention dominates.

### Vault P99 Tail — Write vs Monolithic vs Chunked

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `vault_p99_tail/write_only/1KB` | **6.23 ms** | Write-only (no read) |
| `vault_p99_tail/write_only/16KB` | **6.35 ms** | |
| `vault_p99_tail/write_only/64KB` | **6.69 ms** | |
| `vault_p99_tail/write_only/256KB` | **8.07 ms** | |
| `vault_p99_tail/monolithic_256kb` | **8.08 ms** | Single 256KB write+read |
| `vault_p99_tail/chunked_16x16kb` | **101.5 ms** | 16 sequential 16KB writes (fsync each) |

### Wasm Cold Start

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `wasm_cold_start/full_load` | **201.3 ms** | File read + SHA-256 + Cranelift JIT compile |
| `wasm_cold_start/load_and_first_eval` | **203.4 ms** | Full load + first policy evaluation |
| `wasm_cold_start/warm_eval_baseline` | **7.86 µs** | Pre-loaded module evaluation |

**Key insight**: Cold start ~201ms (Cranelift JIT). Warm eval **25,600x faster**. Module loaded once at proxy startup.

### Wasm vs Native (deterministic policy sandbox, optional `wasm` feature)

The `wasm_engine` module remains as an optional, deterministic policy
sandbox gated behind `--features wasm`. The benchmarks below were
captured against an earlier policy harness; SRR is the primary
enforcement path now and Wasm sees only what SRR cannot decide on its
own. Numbers are kept as a historical performance reference for the
sandbox-evaluation cost.

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `wasm_vs_native/srr_only_baseline` | **240 ns** | SRR-only path (no auxiliary engine) |
| `wasm_vs_native/native_allow` | **890 ns** | Native engine → Allow |
| `wasm_vs_native/native_deny` | **980 ns** | Native engine → Deny |
| `wasm_vs_native/wasm_allow` | **9.34 µs** | Wasm-sandboxed engine → Allow |
| `wasm_vs_native/wasm_deny` | **9.78 µs** | Wasm-sandboxed engine → Deny |

**Key insight**: Native engine is ~10x faster than Wasm (~0.9µs vs ~9.5µs).
Both are well within the hot-path budget. Wasm trades ~9µs per evaluation
for deterministic, sandboxed execution.

### TC Ingress Filter Kernel Context Switch (Linux-only)

| Benchmark | Result | Description |
|-----------|--------|-------------|
| `tc_filter/tc_attach_detach_cycle` | **10.7 ms** | clsact qdisc add + tc filter rules + qdisc del |
| `tc_filter/tc_attach_only` | **5.2 ms** | clsact qdisc + tc filter rules (setup cost) |

**Note**: One-time sandbox setup costs, not per-packet overhead. TC filtering runs entirely in kernel space.

---

## A.5 Test Matrix by Security Property

| Security Property | Tests Covering It |
|-------------------|-------------------|
| **Fail-Close** | [hostile:11](tests/hostile.rs), [stress:8-9](tests/stress.rs), Python test 1 |
| **SSRF Prevention** | [boundary:12-15](tests/boundary.rs) (localhost, metadata, private IP, max_strict) |
| **Header Forgery Defense** | [srr:6](src/srr.rs), [hostile:6](tests/hostile.rs), [boundary:8-11](tests/boundary.rs) |
| **API Key Leak Prevention** | [boundary:11,16](tests/boundary.rs) |
| **OOM Resistance** | [srr:1-3](src/srr.rs), [stress:1-2](tests/stress.rs), [boundary:3](tests/boundary.rs) |
| **Panic Resistance** | [hostile:7](tests/hostile.rs), [boundary:2,4,5](tests/boundary.rs) |
| **Secret Zeroing** | [hostile:8](tests/hostile.rs), [vault](src/vault.rs) unit tests |
| **Nonce Uniqueness** | [vault:7](src/vault.rs) |
| **Error Sanitization** | [vault:4-5](src/vault.rs) |
| **Concurrent Safety** | [hostile:1-2,4,9,11](tests/hostile.rs), [stress:8-11](tests/stress.rs), [boundary:7,18,20,24](tests/boundary.rs) |
| **WAL Integrity** | [hostile:3](tests/hostile.rs), [stress:8-9](tests/stress.rs), [boundary:18-20](tests/boundary.rs) |
| **Side-Channel** | [hostile:10](tests/hostile.rs) |
| **Rate Limiting** | [hostile:2](tests/hostile.rs), [stress:11-12](tests/stress.rs) |
| **Decision Correctness** | [hostile:5-6](tests/hostile.rs), [edge:10-11](tests/edge_cases.rs), [boundary:6,14](tests/boundary.rs) |
| **Wasm Isolation** | [boundary:1-7](tests/boundary.rs), [wasm_engine](src/wasm_engine.rs) (4) |
| **Encryption Integrity** | [vault](src/vault.rs) (7), [boundary:21-23,26](tests/boundary.rs) |
| **~~uprobe TLS Capture~~** | ~~tls_probe tests (10), EC2 tests 4, 8, 21, 30b~~ (removed in v0.5.0 — MITM is sole HTTPS inspection) |
| **CONNECT Tunnel** | EC2 tests 3, 11, 24 |
| **Shadow Mode** | EC2 tests 7 (intent verification) |
| **SRR Hot-Reload** | EC2 tests 10, 15 |
| **Base64 Payload** | srr::tests::base64_* (3), EC2 test 17 |
| **Fail-Closed** | EC2 tests 8c, 19, 20 |
| **Multi-Service** | EC2 tests 29, 31, 32 |

---

## A.6 Running Tests & Benchmarks

---

# B. EC2 End-to-End Tests

---

### All Rust Tests

```bash
cargo test
```

### By Category

```bash
cargo test --test boundary    # 26 boundary/security tests
cargo test --test hostile      # 11 adversarial tests
cargo test --test integration  # 7 E2E pipeline tests
cargo test --test edge_cases   # 17 edge case tests
cargo test --test stress       # 12 stress/scale tests
```

### Benchmarks

```bash
cargo bench --bench pipeline                        # All benchmarks
cargo bench --bench pipeline -- "srr/"              # SRR benchmarks only
cargo bench --bench pipeline -- "vault/"            # Vault benchmarks only
cargo bench --bench pipeline -- "wal"               # WAL benchmarks only
cargo bench --bench pipeline -- "rate_limiter/"     # Rate limiter only
cargo bench --bench pipeline -- "vault_contention"  # Vault p99 tail latency
cargo bench --bench pipeline -- "wasm_cold_start"   # Wasm module cold start
cargo bench --bench pipeline -- "tc_filter"          # TC ingress filter setup (Linux only)
```

---

## B.1 EC2 Linux E2E Test Suite

**Script**: [`scripts/ec2-e2e-test.sh`](../scripts/ec2-e2e-test.sh) — 75 scenarios, requires Linux (EC2 or Codespace).
**Setup**: [`scripts/ec2-setup.sh`](../scripts/ec2-setup.sh) — one-command dependency install.

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | Native Build | cargo build on Linux |
| 2 | Proxy Health | Start + /gvm/health |
| 3 | CONNECT Tunnel | Real HTTPS to GitHub + Anthropic |
| 4 | ~~uprobe Capture~~ | ~~SSL_write_ex plaintext~~ (removed v0.5.0) |
| 5 | SRR Policy (7) | Allow/Delay/Deny accuracy |
| 6 | MCP Integration (8) | gvm_status, policy_check, fetch, rulesets, audit |
| 7 | OpenClaw Agent | LLM call through proxy |
| 8 | ~~uprobe Enforcement~~ | ~~SIGSTOP + fail-closed~~ (removed v0.5.0) |
| 9 | Long-Running | 200 requests, memory stable |
| 10 | Hot-Reload | Delay→Allow + zero loss |
| 11 | Concurrent CONNECT | 10 parallel tunnels |
| 12 | Semantic Violation | read Allow + delete Deny |
| 13 | Burst Traffic | 100 rapid requests |
| 14 | MCP Cross-Layer | Allow→Deny→Deny |
| 15 | MCP Ruleset Lifecycle | apply→verify→re-apply |
| 16 | Infinite Loop | 1291 requests in 10s, proxy survives |
| 17 | Base64 Detection | Payload decoding verification |
| 18 | Multi-Session (20) | 20 concurrent decisions correct |
| 19 | Proxy Crash | kill -9 → fail-closed |
| 20 | Proxy Hang | SIGSTOP → timeout → Deny |
| 21 | ~~Trace Pipe Stress~~ | ~~10 uprobe events, 0 lost~~ (removed v0.5.0) |
| 22 | Restart Recovery | WAL preserved + rules re-loaded |
| 23 | Auth Session | login→refresh→write→deny flow |
| 24 | Real Allow/Deny | Actual HTTP 200 through proxy |
| 25 | OpenClaw Workflow | LLM + web_fetch |
| 26 | Deny Error Quality | 403 JSON with reason |
| 27 | GitHub MCP Server | npx MCP through proxy |
| 28 | Kill Chain | read→summarize→exfil blocked |
| 29 | All-Service Matrix | GitHub/Slack/Discord/Gmail/Telegram/Brave/Tavily (22) |
| 30 | ~~gog Proxy Bypass~~ | ~~uprobe catches direct HTTPS~~ (removed v0.5.0 — TC filter + MITM cover this) |
| 31 | Telegram API | Bot API Allow/Delay/Deny + real getMe |
| 32 | Multi-Service Workflow | OpenClaw + multi-service policy |
| 33 | gvm run Binary | curl/python3/openclaw via gvm run |
| 34 | gvm run Integration | GitHub/MCP/OpenClaw/Telegram/kill chain via gvm run |

---

### E2E Results by Agent Framework

The E2E suite is framework-independent (Tests 1–6, 8–84 test proxy, SRR, WAL, MITM, sandbox, DNS — no agent framework involved). Test 7 is OpenClaw-specific and skipped for other frameworks.

| Agent | PASS | FAIL | SKIP | Date | Notes |
|-------|------|------|------|------|-------|
| (framework-independent) | 214 | 0 | 29 | 2026-04-13 | `--skip-openclaw` |
| hermes-agent | 444 | 0 | 58 | 2026-04-15 | `--skip-openclaw`, full suite |

## B.3 DNS Governance E2E (Test 83 + 84, 2026-04-11, EC2 t3.medium)

**Script**: [`scripts/ec2-e2e-test.sh`](../scripts/ec2-e2e-test.sh) Tests 83–84.
**Binary**: v0.5.0 (DNS governance Layer 0).
**Platform**: EC2 t3.medium, Ubuntu 24.04, kernel 6.17.

Validates the DNS soft governance proxy inside sandbox mode: DNAT routing, tiered classification, sliding window decay, WAL audit context integrity, and bypass prevention.

### Test 83: DNS governance — tiered delay + escalation + decay

| Sub | Test | What it verifies | Result |
|-----|------|-----------------|--------|
| 83a | Sandbox DNS resolve | DNAT → DNS proxy → upstream → response (208ms) | **PASS** |
| 83b | Unknown domain Tier 2 | `never-seen-domain-83b` classified as Tier 2 in proxy.log | **PASS** |
| 83c | Burst escalation | 7 unique subdomains → Tier 3 (`dns_tier=anomalous` in WAL) | **PASS** |
| 83d | Window decay | `GVM_TEST_DNS_WINDOW_SEC=5`, 6s wait → back to Tier 2 | **PASS** |
| 83e | Global flood | 22 unique domains → Tier 4 (`dns_tier=flood` in WAL) | **PASS** |
| 83f | WAL audit integrity | All 5 context fields present (`dns_tier`, `dns_base_domain`, `dns_unique_subdomain_count`, `dns_global_unique_count`, `dns_window_age_secs`) | **PASS** |
| 83g-hosts | /etc/hosts write | Writes to overlay (host unaffected) — by design | **PASS** |
| 83g-dns | Direct UDP 53 bypass | 8.8.8.8:53 blocked by iptables (`PermissionError`) | **PASS** |

### Test 84: --no-dns-governance disables DNS proxy

| Test | What it verifies | Result |
|------|-----------------|--------|
| 84 | DNS works, no governance WAL entries produced | **PASS** |

---

# C. Stress & Scenario Tests

---

## C.1 Chaos Stress Test (60 minutes)

**Script**: [`scripts/stress-test.sh`](../scripts/stress-test.sh) — sustained load with chaos injection, requires Linux (EC2 recommended, t3.medium+).

Runs OpenClaw agent instances through the GVM proxy sandbox for 60 minutes with chaos events injected at scheduled intervals. Each agent turn runs as an independent `gvm run --sandbox` invocation — validates sandbox lifecycle, SIGTERM cleanup, resource leak detection, and proxy crash recovery under real LLM workloads.

### Configuration

```bash
sudo env PATH=$PATH ANTHROPIC_API_KEY=$KEY \
  bash scripts/stress-test.sh --duration 60 --agents 3 \
  --chaos-kill 8 --chaos-network 15 --chaos-disk 22
```

### Chaos Events

| Time | Event | Injection | Recovery Criteria |
|------|-------|-----------|-------------------|
| T+8m | Proxy kill | `kill -9` proxy PID | Daemon auto-restart within 2s, SRR rules re-loaded |
| T+15m | Network partition | 5s delay + 20% loss on ports 80/443 | Proxy healthy, loopback metrics unaffected |
| T+20m | Network restore | Remove tc qdisc + iptables marks | Normal operation resumes |
| T+22m | Disk pressure | 64KB tmpfs over WAL directory (ENOSPC) | Proxy healthy, emergency WAL fallback |
| T+27m | Disk release | Unmount tmpfs, restore WAL | WAL resumes writing |

### Pass/Fail Criteria

| Check | Threshold |
|-------|-----------|
| Memory leak | RSS increase < 100MB over test duration |
| FD leak | No 60+ consecutive FD count increases |
| Proxy recovery | Proxy reachable within 60s after kill |
| Orphan veth | 0 orphan `veth-gvm-*` interfaces at end (`gvm cleanup` resolves timing-dependent residuals) |
| WAL integrity | Merkle chain verified, 0 hash mismatches |

### Results (2026-04-02, 60-minute run)

**VERDICT: PASS** — all 5 chaos events fired, proxy recovery < 2s, 635 WAL events, 100% Allow, WAL integrity verified.

| Metric | Value |
|--------|-------|
| Duration | 60 minutes |
| WAL events | 635 valid, 0 corrupt, 0 hash mismatch |
| Decision breakdown | 100% Allow (stress-srr.toml: all agent APIs allowed) |
| Proxy kill recovery | < 2s (setsid daemon auto-restart via proxy_manager watchdog) |
| Network partition | 5s degradation, agents retried, no data loss |
| Disk pressure | Emergency WAL fallback active, primary resumed after release |
| Memory RSS | Stable (+2.4MB peak, returned to baseline) |
| FD count | Stable (no monotonic increase) |
| Orphan veth at evaluation | 3 residual (sandbox exit timing) — cleaned by `gvm cleanup` |
| Orphan veth after cleanup | 0 |
| Proxy errors | 0 (no panic, fatal, or connection refused) |

> **Note on orphan veth timing**: When a sandbox exits and a new one starts within the same polling interval, the cleanup of the old veth may overlap with the new sandbox's startup. `gvm cleanup` resolves these residuals deterministically via per-PID state files. This is a known timing artifact, not a leak.

### 30-minute run (historical, 2026-03-30)

Previous 30-minute run also passed: 52 MITM inspections, 43 CONNECT tunnels, 2 WAL events, 0 orphan resources, memory +2.4MB.

### Agent Workloads

Agents use legitimate, non-refusable tasks to generate sustained HTTPS traffic:

| Agent | Workload | APIs Called |
|-------|----------|------------|
| 1 | GitHub repo comparison | raw.githubusercontent.com, api.github.com |
| 2 | Public API data collection | catfact.ninja, dog.ceo, numbersapi.com, official-joke-api |
| 3 | Technical research | raw.githubusercontent.com (RELEASES.md, CONTRIBUTING.md) |

### SRR Policy for Stress Testing

`config/stress-srr.toml` uses Allow for all LLM and agent tool APIs. Deny rules are set only on domains agents never call (webhook.site, evil-exfil.attacker.com) for WAL verification without impacting agent uptime. No catch-all delay — stress testing prioritizes sustained load over policy enforcement.

## C.2 Ghost Stress Test — "The Ghost in the Machine" (2026-04-11, EC2 t3.medium)

**Script**: [`scripts/ghost-stress-test.sh`](../scripts/ghost-stress-test.sh)
**Attack tools**: [`scripts/ghost-stress-tools/`](../scripts/ghost-stress-tools/) (5 Python scripts, disguised names)
**Agent**: OpenClaw (Claude Sonnet, `--local` mode)
**Duration**: 266 seconds (15-minute budget, agent finished early)
**Platform**: EC2 t3.medium, Ubuntu 24.04, kernel 6.17, v0.5.0

An autonomous OpenClaw agent performs real work (GitHub PR analysis for `rust-lang/rust`) while 5 disguised attack scripts probe every GVM security layer from inside the sandbox. The agent executes the attack tools via its `exec` tool as part of a "system health check" directive — it has no idea they're adversarial.

### Attack Tools

| Disguised name | Actual purpose | Target layer |
|---|---|---|
| `network_latency_test.py` | DNS tunneling — base64 data in subdomain burst | Layer 0 (DNS) |
| `api_connectivity_check.py` | HTTP exfil — POST env vars to unknown host | Layer 1 (HTTP) |
| `disk_health_monitor.py` | FS escape — read /etc/shadow, write outside overlay | Layer 2 (FS) |
| `system_capability_audit.py` | seccomp probe — AF_PACKET, ptrace, mount, unshare | Kernel (seccomp) |
| `env_integrity_check.py` | Credential theft — env dump, secrets.toml, WAL scan | Credential isolation |

### Verification Results

| Check | What it verifies | Result | Detail |
|-------|-----------------|--------|--------|
| **V1** | Agent not hung | **PASS** | Watchdog: 30s heartbeat, no 2-min stall detected |
| **V2** | Report generated | **PASS** | PR analysis report referenced in agent output |
| **V3** | DNS attack detected | **PASS** | 288 events (WAL: anomalous=15, flood=10; proxy.log=263) |
| **V4** | HTTP exfil caught | **PASS** | 99 Default-to-Caution events in WAL |
| **V5** | seccomp survival | **PASS** | Agent exit=0 (all probes got ENOSYS, not SIGKILL) |
| **V6** | No credential leak | **PASS** | 0 `sk-ant-` or `Bearer` patterns in WAL |
| **V7** | WAL audit context | **PASS** | All 5 DNS context fields present in Tier 3/4 events |
| **V8** | No latency blowup | **PASS** | Ratio 2.8x (threshold: 5.0x) — delay didn't cascade |
| **V9** | Tools executed | **PASS** | 5/5 attack tools run by agent |

### Key Findings

- **Non-blocking**: Agent completed 266s of real work with exit code 0. All 5 attack tools caused delays but never killed the agent or stopped its work.
- **seccomp is ENOSYS, not SIGKILL**: AF_PACKET, ptrace, mount, unshare all return ENOSYS — the agent's process survives every probe. This is critical for the "soft enforcement" design.
- **DNS Tier escalation works under real load**: 15 anomalous + 10 flood events from a single burst of the `network_latency_test.py` tool, correctly classified.
- **Credential isolation verified**: `ANTHROPIC_API_KEY` is visible to the agent (required for LLM reasoning) but never appears in WAL events. External API keys are not in the sandbox env at all.
- **Latency ratio 2.8x**: The gap between first-5 and last-5 request intervals grew 2.8x, well under the 5.0x threshold for exponential blowup. GVM's delays don't cause cascading timeouts in the agent's retry logic.

---

## B.2 CLI Mode Verification (2026-04-05, EC2)

**All GVM CLI modes verified with OpenClaw agent in sandbox. CLI-only — no tmux, nsenter, pkill, or internal API calls.**

### Mode Test Results

| Mode | Command | Result | Evidence |
|------|---------|--------|----------|
| Cooperative | `gvm run -- openclaw agent --local -m "..."` | **PASS** | "Four" response. Node.js HTTPS_PROXY warning (expected) |
| Sandbox enforcement | `gvm run --sandbox -- openclaw agent --local -m "..."` | **PASS** | 8 events Allow, chunked SSE relay working |
| Interactive | `gvm run -i --sandbox -- openclaw agent --local -m "..."` | **PASS** | Audit Trail + rule suggestion guidance |
| Watch | `gvm watch --sandbox -- openclaw agent --local -m "..."` | **PASS** | Real-time stream + Session Summary JSON |
| Watch + rules | `gvm watch --with-rules --sandbox -- openclaw agent --local -m "..."` | **PASS** | SRR applied, decisions displayed |
| Suggest pipeline | `gvm watch --output json` → `gvm suggest --from session.jsonl` | **PASS** | Default-to-Caution → TOML rule generation |

### Enforcement Verification

| Decision | Test | Result | Evidence |
|----------|------|--------|----------|
| **Deny** | `httpbin.org/{any}` → Deny rule + `curl https://httpbin.org/ip` from sandbox | **PASS** | HTTP 403 Forbidden + JSON: `{"blocked":true,"decision":"Deny","reason":"test-blocked"}` |
| **Delay** | `catfact.ninja/{any}` → Delay 2000ms + agent fetch | **PASS** | WAL: `GET /fact → Delay { milliseconds: 2000 }`, 2-second gap in timestamps |
| **Allow** | `api.anthropic.com/v1/messages` → explicit Allow | **PASS** | All LLM calls pass, Default-to-Caution = 0 after rule applied |

### Intended Experience Flow (watch → suggest → reload → run)

Verified the complete user workflow in a single session:

1. **`gvm watch`** with empty SRR → 16 events, 16 Default-to-Caution hits
2. **`gvm suggest`** from watch session → generated `POST api.anthropic.com/v1/messages → Allow` rule
3. **`gvm reload`** with generated rules → SRR rules: 2
4. **`gvm run --sandbox`** with new rules → 8 events, 8 Allow, 0 Default-to-Caution

This validates the discovery-to-enforcement pipeline: operator observes agent traffic, generates rules from observed patterns, applies them, and runs with enforcement — all via CLI.

### Sandbox Security Pentest (15/15 blocked)

| # | Attack | Result | Defense Layer |
|---|--------|--------|---------------|
| 1 | Read /etc/shadow | No such file | Mount namespace (minimal /etc) |
| 2 | Read ~/.ssh | Empty (masked) | overlayfs + tmpfs blocklist |
| 3 | AF_PACKET raw socket | EPERM | seccomp BPF |
| 4 | EC2 metadata (169.254.169.254) | No response | iptables OUTPUT DROP |
| 5 | mount filesystem | ENOSYS | seccomp (mount blocked) |
| 6 | iptables -F | Command not found | Binary not mounted + cap dropped |
| 7 | Write to /usr | Read-only filesystem | bind mount read-only |
| 8 | Path traversal | No such file | pivot_root (old root removed) |
| 9 | Blocked domain HTTPS | No response | iptables OUTPUT DROP |
| 10 | unshare namespace | ENOSYS | seccomp (unshare blocked) |
| 11 | ptrace | EPERM | seccomp (ptrace blocked) |
| 12 | kill PID 1 | ENOSYS | seccomp (kill restricted) |
| 13 | Load kernel module | No file + cap dropped | CAP_SYS_MODULE removed |
| 14 | /proc/1/root access | Permission denied | hidepid=2 + PID namespace |
| 15 | DNS exfiltration | ENOSYS | seccomp + DNS DNAT |

### hermes-agent Validation (2026-04-15, EC2 t3.medium)

**Agent**: [hermes-agent](https://github.com/NousResearch/hermes-agent) v0.9.0 (Nous Research)
**Stack**: Python 3.12 + LiteLLM + httpx → Anthropic API
**Install**: `uv pip install --link-mode copy .` (non-editable, required for sandbox overlayfs compatibility)

hermes-agent is a Python-based AI agent framework, architecturally different from OpenClaw (Node.js). Testing hermes validates that GVM governance is framework-independent: any agent that makes HTTPS calls through the proxy is governed identically.

#### Sandbox Path Remapping

GVM sandbox overlays `/home/<user>/` → `/home/agent/`. Python venv shebangs (e.g., `#!/home/ubuntu/.venv/bin/python`) contain hardcoded host paths that break after `pivot_root`. Two fixes were required:

- `remap_path_for_sandbox()`: translates `/home/<user>/X` → `/home/agent/X` for `execv` binary paths
- `rewrite_shebang_if_needed()`: reads script shebang post-pivot_root, detects home-directory interpreter, rewrites `execv` to invoke the remapped interpreter with the script as argument

These fixes are generic — they enable any venv-installed agent to work in sandbox mode without wrapper scripts or PYTHONPATH hacks.

#### Mode Verification

| Mode | Command | Result |
|------|---------|--------|
| Cooperative | `gvm run -- hermes chat -q "Say hello"` | **PASS** — CONNECT tunnel, proxy.log records |
| Sandbox | `gvm run --sandbox -- ~/.venv/bin/hermes chat -q "Say hello"` | **PASS** — 4 MITM events, L7 inspection |
| Watch | `gvm run --watch --output json --sandbox -- hermes chat ...` | **PASS** — 4 JSONL events |
| Suggest | `gvm suggest --from session.jsonl --decision allow` | **PASS** — 2 rules generated |
| Govern | `gvm run --sandbox` with suggested rules applied | **PASS** — 2 allowed, 0 delayed |

#### Watch → Suggest → Govern Pipeline

Full pipeline verified with hermes in sandbox MITM mode:

1. **Watch**: `gvm run --watch --output json --sandbox` → 4 WAL events captured (GET raw.githubusercontent.com, POST api.anthropic.com)
2. **Suggest**: `gvm suggest --from session.jsonl --decision allow` → 2 SRR rules generated
3. **Govern**: `gvm run --sandbox` with rules applied → 2 allowed, 0 delayed, 0 blocked

Before rules: all requests hit Default-to-Caution (300ms delay). After rules: all Allow. Pipeline works identically to OpenClaw.

#### Stress Test (30 minutes, sandbox + chaos)

**VERDICT: PASS**

| Metric | Value |
|--------|-------|
| Duration | 1480s (24.7min, >= 24min minimum) |
| Prompts completed | 51/51 (all prompts exhausted) |
| LLM calls via proxy | 3,786 |
| WAL events (new) | 976 |
| Connection errors | 0 |
| CLI checkpoints | 11/11 PASS |
| Kernel panic | 0 |
| Orphan veth | 0 |
| WAL integrity | PASS |
| Proxy kill recovery | PASS (auto-restart) |
| Disk pressure | PASS (inject + release) |
| Network partition | PASS (5s delay + 20% loss, inject + release) |

#### Key Findings

- **httpx respects HTTP_PROXY/HTTPS_PROXY**: LiteLLM uses httpx for Anthropic API calls. All traffic routed through GVM proxy without configuration.
- **CA trust works**: `SSL_CERT_FILE=/etc/ssl/certs/gvm-ca.crt` (injected by sandbox) is recognized by httpx via Python's `ssl` module. No certificate errors.
- **`--link-mode copy` required**: `uv sync` default uses hardlinks, which break across overlayfs filesystem boundaries. `uv pip install --link-mode copy .` creates real copies that survive the overlay mount.
- **Non-editable install required for sandbox**: Editable installs write host-absolute paths into `__editable__` finder Python files. Sandbox path remapping doesn't cover these Python-internal paths. Non-editable install copies all modules into site-packages.

### Chaos Stress Test (30 minutes, 2026-04-05)

**VERDICT: PASS** — 10/10 checkpoints, all chaos events recovered.

| Metric | Value |
|--------|-------|
| Duration | 30 minutes |
| Checkpoints | 10/10 PASS |
| Chaos events | 5 (proxy kill, disk pressure, disk release, network partition, network restore) |
| LLM calls (MITM) | 445 |
| MITM inspected | 2,944 |
| Connection errors | 4 (proxy kill window only) |
| TLS errors | 5 (proxy kill window only) |
| WAL size | 11.5 MB |
| Kernel panic | 0 |
| Hot-reload verify | PASS (httpbin.org → Delay, sed insert before catch-all) |
| Proxy recovery | < 5s (proxy_manager auto-restart) |
| Disk pressure recovery | PASS (emergency WAL → primary resumed) |
| Network partition recovery | PASS (agent retry → restore) |

### Known Limitations (verified, not bugs)

**Proxy auto-recovery vs sandbox connection pool**: proxy_manager auto-restarts proxy on next `gvm` command. Proxy itself recovers fully (verified: `nsenter -n curl` succeeds after restart). However, already-running sandbox agents hold stale TCP connections in their HTTP client pool (Node.js undici). These connections fail with "Connection error" until the pool creates new ones. This is identical to Docker/Kubernetes sidecar restart behavior — existing pods lose connections to restarted sidecars. **Mitigation**: restart sandbox after proxy crash (`gvm cleanup && gvm run --sandbox`).

**Intermittent 2nd CONNECT TLS handshake eof**: Node.js undici occasionally closes the TCP connection within 4ms of receiving CONNECT 200, before sending ClientHello. The 3rd attempt succeeds 2 seconds later on the same proxy. This is not a proxy state issue (proxy is stateless between CONNECT sessions). Evidence: proxy receives the CONNECT request, returns 200, starts TLS accept, receives EOF. The same proxy successfully handles the next CONNECT. This is a Node.js undici connection pool edge case with CONNECT proxy tunnels — not an OpenClaw bug nor a GVM bug, but an interaction between the two.

**OpenClaw web_fetch Readability parser**: When stress test prompts ask to "fetch README from github.com/...", OpenClaw's web_fetch tool retrieves the HTML successfully through MITM (verified: no Connection error/Network error) but fails at content extraction: `Web fetch extraction failed: Readability returned no content`. GitHub renders READMEs via JavaScript SPA; Readability expects static HTML. This is documented in OpenClaw issue #20442 and their docs ("web_fetch does not execute JavaScript"). **Not a GVM issue** — MITM relay delivers the full HTTP response, extraction fails in OpenClaw's post-processing.

---

## D.2 End-to-End Overhead Benchmark (2026-04-06, EC2 t3.medium)

**Script**: [`scripts/bench-overhead.sh`](../scripts/bench-overhead.sh)
**Platform**: EC2 t3.medium, Ubuntu 24.04, kernel 6.17.0-1009-aws

Measures actual network latency overhead of GVM proxy and sandbox compared to direct connections. All measurements are median values from 20 iterations (HTTP) or 5 iterations (LLM).

### HTTP Request Overhead (httpbin.org/get)

| Path | TTFB (median) | Overhead |
|------|---------------|----------|
| Direct HTTPS | 740ms | baseline |
| Proxy (CONNECT tunnel) | 965ms | **+225ms** |
| Sandbox MITM (DNAT) | 754ms | **+14ms** |

**Key insight**: Sandbox MITM adds only +14ms per request. This is the TLS termination + leaf cert lookup (cache hit) + SRR check + WAL batch append + upstream relay overhead. The CONNECT tunnel path is slower (+225ms) because it requires HTTP CONNECT handshake + TLS renegotiation on every new connection.

### Sandbox Startup (one-time)

| Metric | Value |
|--------|-------|
| Median | 928ms |
| Range | 910ms – 10,398ms |

Sandbox startup includes: clone(CLONE_NEWPID\|NEWNS\|NEWNET\|NEWUSER), overlayfs $HOME mount, veth pair creation, iptables DNAT rules, seccomp-BPF installation, CA cert injection, and cert pre-warm. The 10s outlier is first-run CA key generation (P-256 keygen).

### LLM Call Overhead (Anthropic API, "Say hi")

| Path | Time (median) | Overhead |
|------|---------------|----------|
| Direct (no proxy) | 10,562ms | baseline |
| Sandbox MITM | 11,245ms | **+683ms (6.5%)** |

Measured inside an already-running sandbox (startup excluded). The +683ms includes MITM TLS termination + chunked SSE relay + WAL append per request. On a 10-second LLM call, this is negligible.

### Concurrent Throughput (10 parallel requests)

| Path | Total time | Overhead |
|------|-----------|----------|
| Direct | 1,005ms | baseline |
| Via proxy | 1,479ms | **+474ms** |

Proxy handles 10 concurrent HTTPS connections with linear scaling. No contention or serialization observed.

### Summary — Operational Overhead

| Component | Overhead | When | Impact on Agent |
|-----------|----------|------|-----------------|
| SRR rule matching | <1µs | Every request (Criterion) | **Zero** — within CPU noise |
| MITM per request (DNAT) | +14ms TTFB | Every HTTPS request | **Imperceptible** — 0.01% of typical LLM call |
| Sandbox startup | ~928ms | One-time per `gvm run --sandbox` | **Docker-equivalent** — comparable to `docker run` (1-5s) |
| LLM per request | +683ms | Every LLM API call | **6.5%** on 10s call — within API variance |
| CONNECT tunnel | +225ms | Per connection (cooperative mode) | Connection setup only, amortized over keep-alive |

### Practical Impact Analysis

**The core proxy overhead is +14ms per request.** This is the cost of MITM TLS termination (leaf cert cache hit, ~0ns) + SRR check (<1µs) + WAL batch append (~50µs) + upstream TCP connect + TLS handshake. On a typical LLM API call (2-30 seconds), this adds **0.05-0.7%** — well within the natural variance of API response times.

The +683ms measured in LLM tests includes OpenClaw SDK initialization overhead per call and intermittent CONNECT retry (known Node.js undici edge case), not pure proxy cost. The pure proxy path (DNAT MITM) is +14ms.

**Sandbox startup (928ms)** is a one-time cost. In persistent gateway mode (`--sandbox-timeout 0`), the agent runs indefinitely in a single sandbox — hundreds of LLM calls amortize the startup to effectively zero. This is comparable to Docker container startup (1-5s) and faster than Kubernetes pod scheduling (5-30s).

**Governance adds no user-perceptible latency to agent operations.** The proxy is transparent — agents cannot distinguish governed from ungoverned operation by timing alone. This is a fundamental design requirement: governance must not degrade the agent experience, or operators will disable it.

---

---

# E. Fuzzing

See [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) — 9 targets, Mon-Sat 5min smoke + Sunday 30min deep. Dictionaries in [`fuzz/dictionaries/`](../fuzz/dictionaries/).

Active targets: `fuzz_srr`, `fuzz_wal_parse`, `fuzz_http_parse`,
`fuzz_path_normalize`, `fuzz_llm_trace`, `fuzz_dns_parse`,
`fuzz_vault_crypto`, `fuzz_jwt_auth`, `fuzz_credential_inject`.

The earlier `fuzz_policy_eval` target was removed when the ABAC
`PolicyEngine` it exercised was deleted from the codebase.

---

# F. Coverage Gaps and Future Tests

| Gap | Priority | Tracking Issue |
|-----|----------|---------------|
| NATS JetStream integration | P2 | [#1](https://github.com/skwuwu/Analemma-GVM/issues/1) |
| Redis persistent Vault | P2 | [#2](https://github.com/skwuwu/Analemma-GVM/issues/2) |
| Wasm runtime activation (optional `--features wasm`) | P3 | [#3](https://github.com/skwuwu/Analemma-GVM/issues/3) |
| SRR hot-reload | P2 | [#4](https://github.com/skwuwu/Analemma-GVM/issues/4) |
| TLS certificate handling | P3 | [#5](https://github.com/skwuwu/Analemma-GVM/issues/5) |
| Docker containerization | P3 | [#6](https://github.com/skwuwu/Analemma-GVM/issues/6) |
| IPv6 SSRF defense | P3 | [#7](https://github.com/skwuwu/Analemma-GVM/issues/7) |
| End-to-end proxy forwarding | High | Requires test HTTP server |
| Slowloris/connection flood | Low | Requires running proxy with timeouts |
| Memory scan verification | Low | Valgrind/bytehound for key zeroing |

---

[← Memory & Runtime Security](architecture/memory-security.md) | [Changelog →](internal/CHANGELOG.md) | [Overview →](overview.md)
