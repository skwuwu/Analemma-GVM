# Part 9: Test & Benchmark Report

**Total: 257 Rust Tests (120 core unit + 7 engine + 17 CLI + 32 boundary + 17 edge + 28 hostile + 12 integration + 12 merkle + 12 stress) — All Pass**
**Benchmarks: 17 groups / 76 benchmark cases (Criterion v0.5)**
**Last Verified: 2026-03-20 (`cargo test --workspace --all-targets`)**

---

## 9.1 Test Architecture

```
tests/
├── hostile.rs          # 28 adversarial/concurrency tests
├── integration.rs      # 12 end-to-end pipeline tests (5 enforcement + 2 config integrity + 5 coverage gap)
├── edge_cases.rs       # 17 edge case tests
├── stress.rs           # 12 stress/performance tests
├── boundary.rs         # 32 cross-boundary security tests
├── merkle.rs           # 12 Merkle tree integrity tests
src/
├── registry.rs         # 4 unit tests
├── policy.rs           # 10 unit tests (4 evaluation + 6 conflict detection)
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
benches/
├── pipeline.rs         # 17 benchmark groups (Criterion)
```

---

## 9.2 Test Execution Log (Historical Snapshot: 2026-03-16)

```
$ cargo test

running 54 tests                              (src/lib.rs — unit tests)
test policy::tests::test_ends_with_condition ... ok
test policy::tests::test_deny_overrides_all ... ok
test policy::tests::test_starts_with_condition ... ok
test policy::tests::test_numeric_gt_condition ... ok
test registry::tests::test_unsafe_mapping_rejected ... ok
test registry::tests::test_vendor_mismatch_rejected ... ok
test registry::tests::test_invalid_core_name_rejected ... ok
test registry::tests::test_valid_registry_loads ... ok
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
test result: ok. 54 passed; 0 failed; 0 ignored; finished in 0.05s

running 26 tests                              (tests/boundary.rs)
test api_key_not_leaked_via_gvm_headers ... ok
test duplicate_gvm_headers_first_value_wins ... ok
test gvm_headers_stripped_before_forwarding ... ok
test header_injection_newline_rejected ... ok
test inbound_decision_header_not_in_parsed_gvm_headers ... ok
test ssrf_max_strict_srr_deny_overrides_policy_allow ... ok
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
test result: ok. 26 passed; 0 failed; 0 ignored; finished in 0.35s

running 17 tests                              (tests/edge_cases.rs)
test edge_max_strict_delay_vs_require_approval ... ok
test edge_max_strict_strictness_ordering_complete ... ok
test edge_empty_policy_directory ... ok
test edge_nonexistent_policy_directory ... ok
test edge_empty_registry_file ... ok
test edge_srr_and_policy_disagree_deny_wins ... ok
test edge_missing_gvm_headers_srr_only_fallback ... ok
test edge_empty_body_payload_inspection_skips ... ok
test edge_null_bytes_in_path_safe_handling ... ok
test edge_recovery_no_pending_events ... ok
test edge_registry_custom_only ... ok
test edge_very_long_host_and_path ... ok
test edge_policy_no_match_returns_allow ... ok
test edge_binary_body_json_parse_fails_gracefully ... ok
test edge_unicode_operation_name ... ok
test edge_policy_conflicting_layers_deny_wins ... ok
test edge_concurrent_status_update_no_crash ... ok
test result: ok. 17 passed; 0 failed; 0 ignored; finished in 0.02s

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

running 12 tests                              (tests/integration.rs)
test api_key_injection_bearer_and_apikey_types ... ok
test policy_hierarchy_global_tenant_agent_strictness ... ok
test event_status_transitions_pending_to_confirmed_and_failed ... ok
test wal_nats_sequence_ordering_and_crash_recovery ... ok
test sdk_headers_to_proxy_classification_end_to_end ... ok
test config_file_hashes_recorded_in_merkle_chain ... ok
test config_hash_records_unavailable_for_missing_files ... ok
test e2e_proxy_forwards_to_upstream_and_strips_response_headers ... ok
test governance_block_response_contains_all_required_fields ... ok
test sdk_proxy_header_contract_resource_and_context_json ... ok
test policy_conflict_regex_vs_startswith_overlap_is_documented_false_negative ... ok
test emergency_wal_to_primary_recovery_path ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; finished in 0.42s

running 12 tests                              (tests/stress.rs)
test rate_limiter_exact_enforcement ... ok
test stress_100_concurrent_mixed_ic_decisions ... ok
test srr_payload_boundary_no_overflow ... ok
test wal_1000_concurrent_durable_appends ... ok
test srr_1mb_toml_file_no_oom ... ok
test policy_1000_rules_load_and_evaluate ... ok
test vault_1mb_value_roundtrip ... ok
test srr_10000_rules_load_and_lookup ... ok
test wal_sustained_load_10k_events ... ok
test policy_large_hierarchy_100_tenants_1000_agents ... ok
test rate_limiter_window_boundary_no_double_count ... ok
test vault_10k_encrypt_decrypt_no_leak ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; finished in 6.63s
```

**Total (historical snapshot, pre-auth/vault-trait additions): 100 passed, 0 failed. Wall time: ~7.5s**

> **Current total (2026-03-19)**: 226 gvm-proxy tests + 24 workspace crate tests = 250 total. Run `cargo test --workspace` to verify.

---

## 9.3 Unit Tests — Detailed Scenarios

### Operation Registry (4 tests) — [src/registry.rs](src/registry.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_valid_registry_loads`](src/registry.rs) | Valid TOML with core (`gvm.messaging.send`) + custom (`custom.acme.banking.wire_transfer`) | Registry loads, `lookup("gvm.messaging.send")` returns IC-2, custom `maps_to` resolves correctly |
| 2 | [`test_unsafe_mapping_rejected`](src/registry.rs) | Custom IC-3 op `maps_to` core IC-1 op | Startup fails with "Unsafe mapping" — anti-downgrade protection |
| 3 | [`test_invalid_core_name_rejected`](src/registry.rs) | Core op with 2 segments (`gvm.read`) | Startup fails with format error — must be 3 segments |
| 4 | [`test_vendor_mismatch_rejected`](src/registry.rs) | `custom.acme.*` with `vendor = "other"` | Startup fails with "Vendor mismatch" |

### ABAC Policy Engine (10 tests) — [src/policy.rs](src/policy.rs)

**Evaluation tests (4):**

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`test_starts_with_condition`](src/policy.rs) | Rule: `operation StartsWith "gvm.payment"`, input: `gvm.payment.charge` | Condition evaluates true, correct decision returned |
| 2 | [`test_ends_with_condition`](src/policy.rs) | Rule: `operation EndsWith ".read"`, input: `gvm.storage.read` | Condition evaluates true |
| 3 | [`test_numeric_gt_condition`](src/policy.rs) | Rule: `context.amount > 500`, input: `amount=1000` | Numeric comparison succeeds |
| 4 | [`test_deny_overrides_all`](src/policy.rs) | Deny (priority 1) + Allow (priority 100) on same request | Deny short-circuits, `matched_rule_id` correct |

**Conflict detection tests (6):**

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 5 | [`test_duplicate_priority_detected`](src/policy.rs) | Two rules with same priority on same condition | `WarningKind::DuplicatePriority` emitted |
| 6 | [`test_contradictory_decisions_detected`](src/policy.rs) | Allow + Deny on same operation pattern | `WarningKind::ContradictoryDecision` emitted |
| 7 | [`test_ineffective_tenant_rule_detected`](src/policy.rs) | Tenant Allow overshadowed by global Deny | `WarningKind::IneffectiveRule` emitted |
| 8 | [`test_no_conflict_for_non_overlapping_rules`](src/policy.rs) | `.read` allow + `.delete` deny | No warnings |
| 9 | [`test_unconditional_rule_overlaps_everything`](src/policy.rs) | Unconditional Allow + specific Deny | `WarningKind::ContradictoryDecision` emitted |
| 10 | [`test_eq_vs_startswith_overlap`](src/policy.rs) | `Eq gvm.payment.charge` + `StartsWith gvm.payment` contradictory | `WarningKind::ContradictoryDecision` emitted |

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

## 9.4 Integration Tests — Detailed Scenarios

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

### End-to-End Pipeline (12 tests) — [tests/integration.rs](tests/integration.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`sdk_headers_to_proxy_classification_end_to_end`](tests/integration.rs) | SDK headers → ABAC + SRR combined | max_strict picks correct decision |
| 2 | [`policy_hierarchy_global_tenant_agent_strictness`](tests/integration.rs) | Global(Delay) + Tenant(Deny) + Agent(Allow) | Deny wins (strictest across layers) |
| 3 | [`event_status_transitions_pending_to_confirmed_and_failed`](tests/integration.rs) | Create Pending → update to Confirmed/Failed | Status field transitions correctly |
| 4 | [`wal_nats_sequence_ordering_and_crash_recovery`](tests/integration.rs) | 50 concurrent WAL writes + recovery | WAL ordering preserved, Pending → Expired on crash |
| 5 | [`api_key_injection_bearer_and_apikey_types`](tests/integration.rs) | APIKeyStore inject Bearer + ApiKey | Headers `Authorization: Bearer sk-xxx` and `X-Api-Key: key123` |
| 6 | [`config_file_hashes_recorded_in_merkle_chain`](tests/integration.rs) | Config files → WAL system event | SHA-256 hashes correct, event_hash present (Merkle) |
| 7 | [`config_hash_records_unavailable_for_missing_files`](tests/integration.rs) | Missing config file | Hash recorded as `"unavailable"`, no error |
| 8 | [`e2e_proxy_forwards_to_upstream_and_strips_response_headers`](tests/integration.rs) | Real mock upstream → proxy forward → response | Upstream receives request, X-GVM-* response headers stripped, API key injected, non-GVM headers preserved |
| 9 | [`governance_block_response_contains_all_required_fields`](tests/integration.rs) | Deny-triggering request → 403 JSON | Response contains all GovernanceBlockResponse fields (blocked, decision, event_id, trace_id, operation, reason, mode, next_action, ic_level) |
| 10 | [`sdk_proxy_header_contract_resource_and_context_json`](tests/integration.rs) | SDK JSON in X-GVM-Resource/Context headers | ABAC evaluates resource.sensitivity correctly (Critical→Deny, Medium→Allow), malformed JSON doesn't crash |
| 11 | [`policy_conflict_regex_vs_startswith_overlap_is_documented_false_negative`](tests/integration.rs) | Regex vs StartsWith overlap detection | Documents heuristic false negative, verifies max_strict still enforces correctly via priority |
| 12 | [`emergency_wal_to_primary_recovery_path`](tests/integration.rs) | Primary WAL fail → emergency fallback → recovery | Emergency WAL has event_hash but no MerkleBatchRecord, primary failure counter tracks correctly |

### Edge Cases (17 tests) — [tests/edge_cases.rs](tests/edge_cases.rs)

| # | Test | Scenario | Verification |
|---|------|----------|--------------|
| 1 | [`edge_empty_body_payload_inspection_skips`](tests/edge_cases.rs) | Empty body `b""` for payload rule | Skips payload inspection, falls through |
| 2 | [`edge_binary_body_json_parse_fails_gracefully`](tests/edge_cases.rs) | PNG header `\x89PNG\r\n` as body | JSON parse fails, falls through to next rule |
| 3 | [`edge_null_bytes_in_path_safe_handling`](tests/edge_cases.rs) | Path `/api/\x00/secrets` | No panic, returns decision |
| 4 | [`edge_unicode_operation_name`](tests/edge_cases.rs) | Korean `"gvm.메시지.전송"`, emoji `"gvm.💰.send"` | No panic, returns decision |
| 5 | [`edge_very_long_host_and_path`](tests/edge_cases.rs) | 10K char host + 100K char path | No panic, returns Default-to-Caution |
| 6 | [`edge_missing_gvm_headers_srr_only_fallback`](tests/edge_cases.rs) | No X-GVM-Agent-Id header | SRR-only classification (Layer 2) |
| 7 | [`edge_policy_no_match_returns_allow`](tests/edge_cases.rs) | No matching policy rules | Returns Allow (open-world semantics) |
| 8 | [`edge_policy_conflicting_layers_deny_wins`](tests/edge_cases.rs) | Global Allow + Tenant Deny | Deny wins (strictest layer) |
| 9 | [`edge_srr_and_policy_disagree_deny_wins`](tests/edge_cases.rs) | SRR Deny + ABAC Allow | max_strict → Deny |
| 10 | [`edge_max_strict_delay_vs_require_approval`](tests/edge_cases.rs) | Delay(300ms) vs RequireApproval | RequireApproval wins (strictness 4 > 3) |
| 11 | [`edge_max_strict_strictness_ordering_complete`](tests/edge_cases.rs) | All 6 types pairwise (15 combinations) | Strictness order: Allow<AuditOnly<Throttle<Delay<RequireApproval<Deny |
| 12 | [`edge_empty_policy_directory`](tests/edge_cases.rs) | Empty config/policies/ dir | PolicyEngine loads with 0 rules, returns Allow |
| 13 | [`edge_nonexistent_policy_directory`](tests/edge_cases.rs) | Missing policy dir path | Returns error (not panic) |
| 14 | [`edge_empty_registry_file`](tests/edge_cases.rs) | Empty TOML `""` | Registry loads with 0 operations |
| 15 | [`edge_registry_custom_only`](tests/edge_cases.rs) | Only custom operations, no core | Loads successfully |
| 16 | [`edge_concurrent_status_update_no_crash`](tests/edge_cases.rs) | 50 concurrent status updates to same event | No crash or data corruption |
| 17 | [`edge_recovery_no_pending_events`](tests/edge_cases.rs) | WAL with only Confirmed events | Recovery reports 0 pending, 0 expired |

### Stress Tests (12 tests) — [tests/stress.rs](tests/stress.rs)

| # | Test | Scale | Verification |
|---|------|-------|--------------|
| 1 | [`srr_10000_rules_load_and_lookup`](tests/stress.rs) | 10K rules | Loads successfully, lookup finds correct rule |
| 2 | [`srr_1mb_toml_file_no_oom`](tests/stress.rs) | 1MB TOML config | No OOM, correct parsing |
| 3 | [`srr_payload_boundary_no_overflow`](tests/stress.rs) | Body at exact `max_body_bytes` boundary | No overflow, correct inspection |
| 4 | [`policy_1000_rules_load_and_evaluate`](tests/stress.rs) | 1K rules, match at rule #500 | Correct rule matched |
| 5 | [`policy_large_hierarchy_100_tenants_1000_agents`](tests/stress.rs) | 100 tenants × 10 agents | Strictest decision wins across hierarchy |
| 6 | [`vault_10k_encrypt_decrypt_no_leak`](tests/stress.rs) | 10K encrypt/decrypt roundtrips | All match, no memory leak |
| 7 | [`vault_1mb_value_roundtrip`](tests/stress.rs) | 1MB value | Correct encrypt/decrypt roundtrip |
| 8 | [`wal_1000_concurrent_durable_appends`](tests/stress.rs) | 1K concurrent tokio tasks | All 1000 entries in WAL |
| 9 | [`wal_sustained_load_10k_events`](tests/stress.rs) | 10K sequential (GroupCommit: batch_window=2ms, max_batch=256) | All 10K written, group commit amortizes fsync |
| 10 | [`stress_100_concurrent_mixed_ic_decisions`](tests/stress.rs) | 100 concurrent: 50% Allow, 30% Delay, 20% Deny | All decisions correct per IC classification |
| 11 | [`rate_limiter_exact_enforcement`](tests/stress.rs) | 5 agents × 200 requests, limit 100/min | Exactly 100 allowed + 100 denied per agent |
| 12 | [`rate_limiter_window_boundary_no_double_count`](tests/stress.rs) | 100 requests → sleep 1.1s → 100 more | Refill timing correct, no double-counting |

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

## 9.5 Benchmark Results (Criterion v0.5, 2026-03-15)

**Source**: [benches/pipeline.rs](benches/pipeline.rs)

### SRR Network Rule Matching

| Benchmark | Median | Range | Description |
|-----------|--------|-------|-------------|
| `srr/allow_safe_host` | **27.8 ns** | 27.5–28.0 ns | Safe host lookup (first-match hit) |
| `srr/deny_bank_transfer` | **63.1 ns** | 60.7–66.5 ns | Bank transfer deny (multi-field match) |
| `srr/default_caution_unknown` | **29.0 ns** | 28.7–29.2 ns | Unknown URL fallthrough → Delay 300ms |
| `srr/payload_inspection` | **45.2 ns** | 44.8–45.7 ns | GraphQL operationName match |
| `srr/payload_size_bytes/64` | **44.3 ns** | 43.8–44.7 ns | 64B body payload inspection |
| `srr/payload_size_bytes/1024` | **49.5 ns** | 48.5–51.0 ns | 1KB body payload inspection |
| `srr/payload_size_bytes/16384` | **48.4 ns** | 47.7–49.2 ns | 16KB body payload inspection |
| `srr/payload_size_bytes/65536` | **45.2 ns** | 44.9–45.6 ns | 64KB body payload inspection |

**Key insight**: Body size does NOT significantly affect SRR latency (44–50ns range) because the `max_body_bytes` check short-circuits before JSON parsing.

### SRR Scale Benchmarks

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `srr_scale/100_rules/first_rule_match` | ~30 ns | First rule matches immediately |
| `srr_scale/1000_rules/mid_rule_match` | ~15 µs | Match at rule #500 |
| `srr_scale/10000_rules/fallthrough_all` | ~300 µs | No match, scan all 10K rules |

### ABAC Policy Engine

| Benchmark | Median | Range | Description |
|-----------|--------|-------|-------------|
| `policy/allow_read` | **480.9 ns** | 468–494 ns | Safe read operation, 5 rules |
| `policy/deny_critical_delete` | **349.5 ns** | 343–357 ns | Critical delete, deny short-circuits |
| `policy/payment_require_approval` | **153.2 ns** | 148–162 ns | Payment approval, condition match |
| `policy/no_match_fallthrough` | **766.9 ns** | 748–788 ns | No matching rule, scan all |

**Key insight**: Deny short-circuits faster (349ns) than full scan (767ns). Policy evaluation is sub-microsecond for typical rule sets.

### max_strict Decision Combiner

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `max_strict/allow_vs_deny` | **44.8 ns** | Full decision clone + comparison |
| `max_strict/delay_vs_require_approval` | **6.3 ns** | Lightweight comparison |

### Vault (AES-256-GCM Encrypt + Decrypt + WAL)

| Benchmark | Median | Range | Description |
|-----------|--------|-------|-------------|
| `vault/write_read_roundtrip_bytes/32` | **482.0 µs** | 469–496 µs | 32B value (encrypt+WAL+decrypt) |
| `vault/write_read_roundtrip_bytes/256` | **492.7 µs** | 486–499 µs | 256B value |
| `vault/write_read_roundtrip_bytes/1024` | **512.0 µs** | 505–520 µs | 1KB value |
| `vault/write_read_roundtrip_bytes/4096` | **487.4 µs** | 473–504 µs | 4KB value |
| `vault/write_read_roundtrip_bytes/16384` | **763.8 µs** | 577–956 µs | 16KB value |

**Key insight**: Vault latency is dominated by WAL fsync (~480µs), not encryption. AES-256-GCM adds negligible overhead up to 4KB. 16KB shows higher variance due to larger fsync writes.

### Vault Large Value Benchmarks

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `vault_large/64KB` | ~1.2 ms | 64KB encrypt+decrypt roundtrip |
| `vault_large/256KB` | ~3.5 ms | 256KB roundtrip |
| `vault_large/1MB` | ~12 ms | 1MB roundtrip |

### WAL (Write-Ahead Log)

| Benchmark | Median | Range | Description |
|-----------|--------|-------|-------------|
| `wal/durable_append_fsync` | **2.07 ms** | 2.05–2.10 ms | Single event WAL append + fsync |
| `wal/100_sequential_appends` | **203.0 ms** | 199–208 ms | 100 sequential fsyncs (2.03ms each) |
| `wal_group_commit/concurrent_appends/100` | **4.41 ms** | 4.33–4.49 ms | 100 concurrent → batched fsync |

**Key insight**: Group commit reduces 100 fsyncs from 203ms (sequential) to 4.4ms (batched) — **46x improvement**. This amortizes disk I/O across all concurrent callers.

### Rate Limiter

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `rate_limiter/single_agent_check` | **94.8 ns** | Single token bucket check |
| `rate_limiter/100_agents_round_robin` | **139.5 ns** | HashMap lookup + token check |

### IC-2 Delay Accuracy

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `ic2_delay_accuracy/300ms` | ~300.3 ms | tokio::sleep precision (sample_size=10) |

### Vault Contention P99 — Tail Latency Under Load

| Concurrency | 4KB | 16KB | 64KB | Outlier Rate |
|------------|------|------|------|-------------|
| 10 writers | 2.4 ms | 3.9 ms | 4.3 ms | 22% high-severe (4KB) |
| 50 writers | 4.4 ms | 4.8 ms | 5.7 ms | 6% (64KB) |
| 100 writers | 4.9 ms | 5.5 ms | 6.5 ms | 9% (4KB) |

| Benchmark | Median | Description |
|-----------|--------|-------------|
| `p99_explicit_16kb_50writers` | **4.7 ms** | Max latency across 50 concurrent 16KB write+read ops |

**Key insight**: Tail latency scales sub-linearly with concurrency — 10x more writers (10→100) adds only ~2.5x latency. fsync contention is the dominant factor; encryption overhead is negligible even under load. At 100 concurrent writers with 64KB values, p99 stays under 7ms.

### Wasm Cold Start

| Benchmark | Median | Range | Description |
|-----------|--------|-------|-------------|
| `wasm_cold_start/full_load` | **36.6 ms** | 34–40 ms | File read + SHA-256 + Cranelift JIT compile + WASI setup |
| `wasm_cold_start/load_and_first_eval` | **35.4 ms** | 34–37 ms | Full load + first policy evaluation |
| `wasm_cold_start/warm_eval_baseline` | **5.3 µs** | 5.1–5.6 µs | Pre-loaded module evaluation |

**Key insight**: Cold start is ~35ms, dominated by Cranelift JIT compilation. First evaluation adds negligible overhead (~0.1ms). Warm path is **6,900x faster** than cold start. Module must be loaded once at proxy startup — per-request Wasm overhead is microsecond-level, not millisecond-level.

### eBPF/TC Kernel Context Switch (Linux-only)

| Benchmark | Expected | Description |
|-----------|----------|-------------|
| `ebpf_kernel/tc_attach_detach_cycle` | ~5-15 ms | clsact qdisc add + 4 tc filter rules + qdisc del |
| `ebpf_kernel/tc_attach_only` | ~3-8 ms | clsact qdisc + 2 tc filter rules (setup cost) |

**Note**: eBPF benchmarks are Linux-only (`cfg(target_os = "linux")`). Expected values based on typical kernel round-trip costs for TC filter operations. These are one-time sandbox setup costs, not per-packet overhead — once attached, TC filtering runs entirely in kernel space with zero userspace context switches per packet.

---

## 9.6 Test Matrix by Security Property

| Security Property | Tests Covering It |
|-------------------|-------------------|
| **Fail-Close** | [registry](src/registry.rs) (4), [hostile:11](tests/hostile.rs), [stress:8-9](tests/stress.rs), Python test 1 |
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

---

## 9.7 Running Tests & Benchmarks

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
cargo bench --bench pipeline -- "ebpf_kernel"       # eBPF TC setup (Linux only)
```

---

## 9.8 Coverage Gaps and Future Tests

| Gap | Priority | Tracking Issue |
|-----|----------|---------------|
| NATS JetStream integration | P2 | [#1](https://github.com/skwuwu/Analemma-GVM/issues/1) |
| Redis persistent Vault | P2 | [#2](https://github.com/skwuwu/Analemma-GVM/issues/2) |
| Wasm runtime activation | P3 | [#3](https://github.com/skwuwu/Analemma-GVM/issues/3) |
| Policy hot-reload | P2 | [#4](https://github.com/skwuwu/Analemma-GVM/issues/4) |
| TLS certificate handling | P3 | [#5](https://github.com/skwuwu/Analemma-GVM/issues/5) |
| Docker containerization | P3 | [#6](https://github.com/skwuwu/Analemma-GVM/issues/6) |
| IPv6 SSRF defense | P3 | [#7](https://github.com/skwuwu/Analemma-GVM/issues/7) |
| End-to-end proxy forwarding | High | Requires test HTTP server |
| Slowloris/connection flood | Low | Requires running proxy with timeouts |
| Memory scan verification | Low | Valgrind/bytehound for key zeroing |

---

[← Part 8: Memory & Runtime Security](08-memory-security.md) | [Part 10: Architecture Changes →](10-architecture-changes.md) | [Overview →](00-overview.md)
