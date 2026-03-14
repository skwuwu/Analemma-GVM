# Part 9: Test Coverage Report

**Total: 60 Tests (25 lib + 25 bin + 10 integration) — All Pass**

---

## 9.1 Test Architecture

```
tests/
├── hostile.rs          # 10 integration tests (hostile environment)
src/
├── registry.rs         # 4 unit tests
├── policy.rs           # 4 unit tests
├── srr.rs              # 10 unit tests
├── vault.rs            # 7 unit tests
sdk/python/gvm/
├── hostile_demo.py     # 5 adversarial tests (Python, manual)
└── demo.py             # Enforcement pipeline demo
```

---

## 9.2 Unit Tests — Operation Registry (4 tests)

**Source**: `src/registry.rs`

| # | Test Name | Scenario | Assertion |
|---|-----------|----------|-----------|
| 1 | `test_valid_registry_loads` | Valid TOML with core + custom operations | Registry loads, lookup succeeds, maps_to resolves |
| 2 | `test_unsafe_mapping_rejected` | Custom IC-3 maps_to core IC-1 | Startup fails with "Unsafe mapping" error |
| 3 | `test_invalid_core_name_rejected` | Core op with wrong segment count | Startup fails with format error |
| 4 | `test_vendor_mismatch_rejected` | Vendor field doesn't match name segment | Startup fails with "Vendor mismatch" |

**Security coverage**: Anti-downgrade protection, namespace enforcement, Fail-Close at startup.

---

## 9.3 Unit Tests — ABAC Policy Engine (4 tests)

**Source**: `src/policy.rs`

| # | Test Name | Scenario | Assertion |
|---|-----------|----------|-----------|
| 1 | `test_starts_with_condition` | `operation StartsWith "gvm.payment"` | Matches `gvm.payment.charge` |
| 2 | `test_ends_with_condition` | `operation EndsWith ".read"` | Matches `gvm.storage.read` |
| 3 | `test_numeric_gt_condition` | `context.amount > 500` with amount=1000 | Condition evaluates true |
| 4 | `test_deny_overrides_all` | Deny (priority 1) + Allow (priority 100) | Deny short-circuits, correct rule_id returned |

**Security coverage**: ABAC condition evaluation, priority-based matching, Deny short-circuit.

---

## 9.4 Unit Tests — Network SRR (10 tests)

**Source**: `src/srr.rs`

| # | Test Name | Scenario | Assertion |
|---|-----------|----------|-----------|
| 1 | `payload_exceeding_max_body_bytes_falls_back_to_default_caution` | Body > max_body_bytes | Delay 300ms (not Deny, not crash) |
| 2 | `payload_at_exact_limit_is_inspected` | Body at limit with matching operationName | Deny (inspection proceeds) |
| 3 | `large_64kb_body_does_not_crash_or_oom` | 128KB body | Default-to-Caution (no crash) |
| 4 | `malformed_json_body_skips_payload_rule` | Invalid JSON body | Falls through to next rule |
| 5 | `no_body_for_payload_rule_skips_to_next` | No body for payload rule | Falls through to next rule |
| 6 | `srr_catches_url_regardless_of_operation_header` | URL = bank transfer | Deny (ignores headers) |
| 7 | `unknown_url_gets_default_to_caution` | Unknown host/path | Delay 300ms |
| 8 | `suffix_host_pattern_blocks_all_subdomains` | `{host}.database.com` | prod/staging/dev all Denied |
| 9 | `method_mismatch_does_not_trigger_rule` | GET to POST-only rule | Not denied |
| 10 | `wildcard_method_matches_all_http_methods` | `method = "*"` | GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS all matched |

**Security coverage**: OOM defense, payload inspection, header forgery resistance, Default-to-Caution, pattern matching correctness.

---

## 9.5 Unit Tests — Encrypted Vault (7 tests)

**Source**: `src/vault.rs`

| # | Test Name | Scenario | Assertion |
|---|-----------|----------|-----------|
| 1 | `test_encrypt_decrypt_roundtrip` | Encrypt → decrypt | Original plaintext recovered |
| 2 | `test_different_nonces_produce_different_ciphertext` | Same plaintext, two encryptions | Different ciphertext (random nonce) |
| 3 | `test_tampered_ciphertext_fails` | Bit-flip in ciphertext | Decryption fails (AES-GCM auth tag) |
| 4 | `test_truncated_ciphertext_returns_integrity_error` | < 12 bytes input | "integrity error" message |
| 5 | `test_wrong_key_returns_integrity_error` | Decrypt with wrong key | "integrity error", no AES internals |
| 6 | `test_empty_plaintext_roundtrip` | Empty string | Encrypt/decrypt succeeds |
| 7 | `test_nonce_reuse_not_possible` | 100 encryptions | 100 unique nonces |

**Security coverage**: AES-GCM correctness, nonce uniqueness, error sanitization, edge cases.

---

## 9.6 Integration Tests — Hostile Environment (10 tests)

**Source**: `tests/hostile.rs`

| # | Test Name | Category | Assertion |
|---|-----------|----------|-----------|
| 1 | `srr_100_concurrent_checks_complete_without_blocking` | Concurrency | 100 concurrent SRR checks < 1 second |
| 2 | `rate_limiter_100_concurrent_checks_no_deadlock` | Concurrency | No deadlock, rate limits enforced correctly |
| 3 | `wal_tampered_entry_does_not_crash_recovery` | WAL Integrity | Corrupted entry skipped, valid entries processed |
| 4 | `vault_concurrent_writes_to_same_key` | Vault Concurrency | 50 concurrent writes, no deadlock, value exists |
| 5 | `max_strict_deny_overrides_allow` | Decision Logic | Deny always wins regardless of argument order |
| 6 | `header_forgery_srr_denies_bank_transfer_regardless` | Header Forgery | SRR Deny + max_strict → final Deny |
| 7 | `srr_garbage_input_does_not_panic` | Fuzz Resistance | Null bytes, 100K paths, binary → no panic |
| 8 | `vault_key_is_zeroed_on_drop` | Memory Security | VaultEncryption drop with zeroize, no crash |
| 9 | `ledger_concurrent_spawns_stay_bounded` | Backpressure | 500 concurrent appends, all in WAL |
| 10 | `srr_decision_time_is_roughly_constant` | Side-Channel | Deny vs Allow timing < 10x variance |

**Security coverage**: Full adversarial environment simulation covering concurrency, memory safety, fuzz resistance, timing analysis, and crash recovery.

---

## 9.7 Python Tests — Hostile Demo (5 tests)

**Source**: `sdk/python/gvm/hostile_demo.py` (manual execution)

| # | Test Name | Requires | Assertion |
|---|-----------|----------|-----------|
| 1 | Fail-Close | Proxy DOWN | `ConnectionRefused` — no bypass |
| 2 | Header Forgery | Proxy UP | HTTP 403 — SRR catches URL mismatch |
| 3 | Payload OOM | Proxy UP | Proxy survives 128KB body |
| 4 | Secret Isolation | Any | No API keys in `os.environ` |
| 5 | Wrong Operation Name | Proxy UP | Proxy handles gracefully (no crash) |

---

## 9.8 Test Matrix by Security Property

| Security Property | Tests Covering It |
|-------------------|-------------------|
| **Fail-Close** | Registry validation (4), WAL failure rejection, Python test 1 |
| **Header Forgery Defense** | SRR test 6, Integration test 6, Python test 2 |
| **OOM Resistance** | SRR tests 1-3, Python test 3 |
| **Panic Resistance** | Integration test 7 (fuzz), CatchPanicLayer |
| **Secret Zeroing** | Integration test 8, code review of `from_env()` |
| **Nonce Uniqueness** | Vault test 7 |
| **Error Sanitization** | Vault tests 4-5 |
| **Concurrent Safety** | Integration tests 1-2, 4, 9 |
| **WAL Integrity** | Integration test 3 |
| **Side-Channel** | Integration test 10 |
| **Rate Limiting** | Integration test 2 |
| **Decision Correctness** | Integration tests 5-6, Policy test 4 |

---

## 9.9 Running Tests

### Rust Tests (All 60)

```bash
cargo test
```

### Integration Tests Only

```bash
cargo test --test hostile
```

### Python Hostile Demo

```bash
# With proxy DOWN (Fail-Close test):
cd sdk/python
python -m gvm.hostile_demo

# With proxy UP (enforcement tests):
cargo run &
cd sdk/python
python -m gvm.hostile_demo
```

---

## 9.10 Coverage Gaps and Future Tests

| Gap | Priority | Description |
|-----|----------|-------------|
| End-to-end proxy forwarding | High | Full HTTP flow with real upstream (requires test server) |
| Policy file loading | Medium | TOML parsing edge cases (empty files, unicode, huge files) |
| API key injection | Medium | Credential injection for Bearer, OAuth2, ApiKey types |
| Vault API endpoints | Medium | REST API for vault write/read/delete |
| NATS integration | Low | Real NATS JetStream publish/subscribe (requires NATS server) |
| Memory scan verification | Low | Valgrind/bytehound verification of key zeroing |

---

[← Part 8: Memory & Runtime Security](08-memory-security.md) | [Overview →](00-overview.md)
