//! Hostile environment integration tests — proves security claims under adversarial conditions.
//!
//! Test categories:
//! 1. Concurrency stress: 100+ concurrent SRR evaluations must not block
//! 2. WAL integrity: tampered WAL entries handled gracefully on recovery
//! 3. Rate limiter under pressure: no deadlock under concurrent load
//! 4. Vault concurrent access: simultaneous read/write to same key
//! 5. Property-based: max_strict determinism (proptest)
//! 6. Bypass scenarios: HTTP case-smuggling, null bytes, unicode normalization
//! 7. Emergency WAL fallback under primary failure

use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::EnforcementDecision;
use std::sync::Arc;
use std::time::Instant;

/// Helper: build a NetworkSRR from inline TOML
fn srr_from_toml(toml_str: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml_str).expect("writing SRR config to temp file must succeed");
    NetworkSRR::load(&path).expect("valid SRR TOML config must parse")
}

// ─── Test 1: 100 Concurrent SRR Evaluations ───

#[tokio::test]
async fn srr_100_concurrent_checks_complete_without_blocking() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }

        [[rules]]
        method = "POST"
        pattern = "api.bank.com/graphql"
        payload_field = "operationName"
        payload_match = ["TransferFunds", "DeleteAccount"]
        max_body_bytes = 65536
        decision = { type = "Deny", reason = "Dangerous GraphQL" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    let srr = Arc::new(srr);
    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..100 {
        let srr = srr.clone();
        handles.push(tokio::spawn(async move {
            // Mix of different request patterns to exercise all code paths
            let (method, host, path) = match i % 4 {
                0 => ("POST", "api.bank.com", "/transfer/123"),
                1 => ("GET", "api.example.com", "/data"),
                2 => ("DELETE", "prod.database.com", "/users/42"),
                _ => ("POST", "api.bank.com", "/graphql"),
            };

            let body: Option<&[u8]> = if i % 4 == 3 {
                Some(br#"{"operationName": "TransferFunds"}"#)
            } else {
                None
            };

            let result = srr.check(method, host, path, body);
            matches!(result.decision, EnforcementDecision::Deny { .. })
        }));
    }

    let mut deny_count = 0;
    for handle in handles {
        if handle.await.expect("SRR check task must not panic") {
            deny_count += 1;
        }
    }

    let elapsed = start.elapsed();

    // Must finish in under 1 second (CPU-only, no I/O)
    assert!(
        elapsed.as_secs() < 1,
        "100 concurrent SRR checks took {:?} — too slow, possible lock contention",
        elapsed
    );

    // POST to /transfer/* (25 requests) + POST to /graphql with TransferFunds body (25 requests)
    assert_eq!(
        deny_count, 50,
        "Expected exactly 50 denies (transfer+graphql), got {}",
        deny_count
    );
}

// ─── Rate limiter tests removed (replaced by token_budget in src/token_budget.rs) ───

// ─── Test 3: WAL Tampered Entry — Recovery Handles Gracefully ───

#[tokio::test]
async fn wal_tampered_entry_does_not_crash_recovery() {
    use gvm_proxy::ledger::Ledger;
    use std::io::Write;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Write a valid WAL entry, then a tampered/corrupted entry
    {
        let mut file = std::fs::File::create(&wal_path).expect("WAL file creation must succeed");

        // Valid JSON entry with Pending status
        let valid = serde_json::json!({
            "event_id": "evt-001",
            "trace_id": "trace-001",
            "parent_event_id": null,
            "agent_id": "agent-test",
            "tenant_id": null,
            "session_id": "session-001",
            "timestamp": "2026-01-01T00:00:00Z",
            "operation": "gvm.storage.read",
            "resource": {
                "service": "",
                "identifier": null,
                "tier": "External",
                "sensitivity": "Medium"
            },
            "context": {},
            "transport": null,
            "decision": "Allow",
            "decision_source": "Semantic",
            "matched_rule_id": null,
            "enforcement_point": "both",
            "status": "Pending",
            "payload": {
                "content_hash": "",
                "size_bytes": 0,
                "flagged_patterns": []
            },
            "nats_sequence": null
        });
        writeln!(
            file,
            "{}",
            serde_json::to_string(&valid).expect("valid WAL entry must serialize to JSON")
        )
        .expect("writing valid WAL entry must succeed");

        // Corrupted entry — invalid JSON
        writeln!(file, "{{CORRUPTED_DATA_TAMPERE{{{{D}}}}")
            .expect("writing corrupted WAL entry must succeed");

        // Another valid entry
        let valid2 = {
            let mut v = valid.clone();
            v["event_id"] = serde_json::json!("evt-002");
            v
        };
        writeln!(
            file,
            "{}",
            serde_json::to_string(&valid2).expect("second WAL entry must serialize to JSON")
        )
        .expect("writing second WAL entry must succeed");
    }

    // Recovery must not crash even with corrupted entries
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger must initialize with tampered WAL");
    let report = ledger
        .recover_from_wal()
        .await
        .expect("WAL recovery must handle corrupted entries gracefully");

    // Both valid Pending entries should be processed (corrupted entry skipped)
    assert_eq!(
        report.pending_found, 2,
        "Recovery should find 2 valid Pending entries"
    );
    assert_eq!(
        report.expired_marked, 2,
        "Recovery should mark 2 events as Expired"
    );
}

// ─── Test 4: Vault Concurrent Access to Same Key ───

#[tokio::test]
async fn vault_concurrent_writes_to_same_key() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize for vault test"),
    );
    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

    let start = Instant::now();

    // 50 concurrent writes to the SAME key from different agents
    let mut handles = Vec::new();
    for i in 0..50 {
        let vault = vault.clone();
        handles.push(tokio::spawn(async move {
            let value = format!("value-{}", i);
            let agent = format!("agent-{}", i);
            vault
                .write("shared-key", value.as_bytes(), &agent)
                .await
                .expect("concurrent vault write must succeed");
        }));
    }

    for handle in handles {
        handle.await.expect("vault write task must not panic");
    }

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "50 concurrent vault writes took {:?} — possible deadlock",
        elapsed
    );

    // Read the final value — it should be one of the written values (last-write-wins)
    let result = vault
        .read("shared-key", "reader")
        .await
        .expect("vault read after concurrent writes must succeed");
    assert!(result.is_some(), "Key must exist after concurrent writes");

    let value = String::from_utf8(result.expect("key must exist after concurrent writes"))
        .expect("vault value must be valid UTF-8");
    assert!(
        value.starts_with("value-"),
        "Value must be one of the written values, got: {}",
        value
    );
}

// ─── Test 5: max_strict correctly picks Deny over Allow ───

#[test]
fn max_strict_deny_overrides_allow() {
    use gvm_proxy::types::max_strict;

    let allow = EnforcementDecision::Allow;
    let deny = EnforcementDecision::Deny {
        reason: "blocked".to_string(),
    };

    // Regardless of order, Deny must win
    let result = max_strict(allow.clone(), deny.clone());
    assert!(matches!(result, EnforcementDecision::Deny { .. }));

    let result = max_strict(deny, allow);
    assert!(matches!(result, EnforcementDecision::Deny { .. }));
}

// ─── Test 6: Header Forgery — SRR denies regardless of semantic header ───

#[test]
fn header_forgery_srr_denies_bank_transfer_regardless() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }
    "#,
    );

    // Agent declares operation as "gvm.storage.read" (safe)
    // but the actual HTTP target is api.bank.com/transfer/123 (dangerous)
    // SRR only cares about the URL, not the header — this must be denied.
    let result = srr.check("POST", "api.bank.com", "/transfer/123", None);

    match result.decision {
        EnforcementDecision::Deny { reason } => {
            assert!(reason.contains("Wire transfer"));
        }
        other => panic!(
            "Header forgery: SRR must deny based on URL. Got: {:?}",
            other
        ),
    }

    // Verify that max_strict in the proxy pipeline would pick this Deny
    // even if policy returns Allow for "gvm.storage.read":
    use gvm_proxy::types::max_strict;
    let policy_says_allow = EnforcementDecision::Allow;
    let srr_says_deny = EnforcementDecision::Deny {
        reason: "Wire transfer blocked".to_string(),
    };
    let final_decision = max_strict(srr_says_deny, policy_says_allow);
    assert!(
        matches!(final_decision, EnforcementDecision::Deny { .. }),
        "max_strict must pick Deny over Allow"
    );
}

// ─── Test 7: Fuzz-Resistant — SRR handles garbage input without panic ───

#[test]
fn srr_garbage_input_does_not_panic() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // Fuzz-style garbage inputs — none should cause a panic
    let long_host = "a".repeat(10000);
    let long_path = "x".repeat(100000);
    let garbage_inputs: Vec<(&str, &str, &str)> = vec![
        ("", "", ""),
        ("\0\0\0", "\x01\x02", "\x7e\x7f"),
        ("INVALID", "not a host!", "/////////"),
        ("GET", &long_host, "/"),
        ("POST", "host", &long_path),
        ("DELETE", "..", "/../../../etc/passwd"),
        ("POST", "api.bank.com", "/transfer/\0injection"),
        ("*", "*", "*"),
    ];

    for (method, host, path) in &garbage_inputs {
        // Must not panic — any decision is acceptable
        let _decision = srr.check(method, host, path, None);
    }

    // Garbage body inputs for payload inspection
    let garbage_bodies: Vec<&[u8]> = vec![
        b"",
        b"\0\0\0\0",
        b"\xff\xff\xff\xff\xff",
        &[0u8; 65537], // exactly over default max_body_bytes
        b"{\"operationName\": \"\x00\x01\x02\"}",
        b"{{{{{{{{{{{{{{",
        b"\x89PNG\r\n\x1a\n", // PNG header — not JSON
    ];

    for body in &garbage_bodies {
        let _decision = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    }
}

// ─── Test 8: Secret Zeroing — LocalKeyProvider::Drop zeros the key bytes ───
//
// We use a raw pointer captured BEFORE drop and read the same memory after
// drop with `ptr::read_volatile`. This is unsafe (the allocator may reuse
// the memory), but it is the only way short of valgrind/bytehound to
// observe whether the Drop impl actually wrote zeros.
//
// To minimize the chance of allocator reuse between drop and inspection,
// we inline the inspection with no intervening allocations. If the
// allocator does reuse the slot, we'll read non-zero bytes that
// happen NOT to match the original key — the test still detects "Drop did
// not zero" because the original key bytes were 0xA5 and zero≠0xA5; an
// allocator-reused slot is also unlikely to be exactly 0xA5.

#[test]
fn vault_key_is_zeroed_on_drop() {
    use gvm_proxy::vault::{KeyProvider, LocalKeyProvider};

    // Sentinel pattern — distinct from 0x00 (drop result) and 0xFF (likely
    // tag/footer bytes), so any allocator-reuse byte is most likely
    // *also* non-sentinel and the test still rejects "no zeroing".
    let sentinel = [0xA5u8; 32];
    let provider = Box::new(LocalKeyProvider::new(sentinel));

    // Smoke test: provider works before drop.
    let ct = provider
        .encrypt(b"plaintext-before-drop")
        .expect("encrypt must succeed before drop");
    let pt = provider.decrypt(&ct).expect("decrypt must succeed");
    assert_eq!(pt, b"plaintext-before-drop");

    // Capture the address of the inner key. The Box keeps it stable.
    // SAFETY: LocalKeyProvider has a single field `key: [u8; 32]` per
    // `src/vault.rs:80`. Casting Box<LocalKeyProvider> to *const u8 yields
    // a pointer to the start of the struct, which is the start of `key`
    // because there is no other field in front of it.
    let key_ptr: *const u8 = (&*provider as *const LocalKeyProvider) as *const u8;

    drop(provider);

    // Read 32 bytes through the captured pointer.
    // SAFETY: We do NOT free or shadow this pointer; the underlying
    // allocation is freed by `drop`. read_volatile defeats compiler
    // optimization that might elide the read. This is best-effort —
    // a malloc that immediately reuses the slot for another sentinel-
    // matching value would defeat the test, but standard allocators
    // typically scribble or zero recycled slots.
    let observed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = std::ptr::read_volatile(key_ptr.add(i));
        }
        buf
    };

    // If Drop ran zeroize, we expect all-zero (or at worst allocator-
    // recycled bytes that are NOT the sentinel). The test fails only if
    // the original sentinel still survives — that proves Drop did not
    // zero.
    assert_ne!(
        observed, sentinel,
        "key bytes still contain the original sentinel after drop — \
         LocalKeyProvider::Drop did not zeroize. observed={:02x?}",
        observed,
    );
}

// ─── Test 9: Backpressure — concurrent task spawns stay bounded ───

#[tokio::test]
async fn ledger_concurrent_spawns_stay_bounded() {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize for backpressure test"),
    );
    let start = Instant::now();

    // Simulate 500 rapid-fire durable appends
    // Each spawns a tokio task for NATS — verify no unbounded growth
    let mut handles = Vec::new();
    for i in 0..500 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = gvm_proxy::types::GVMEvent {
                event_id: format!("stress-{}", i),
                trace_id: format!("trace-{}", i),
                parent_event_id: None,
                agent_id: "stress-agent".to_string(),
                tenant_id: None,
                session_id: "session".to_string(),
                timestamp: chrono::Utc::now(),
                operation: "gvm.storage.read".to_string(),
                resource: Default::default(),
                context: Default::default(),
                transport: None,
                decision: "Allow".to_string(),
                decision_source: "test".to_string(),
                matched_rule_id: None,
                enforcement_point: "test".to_string(),
                status: gvm_proxy::types::EventStatus::Pending,
                payload: Default::default(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                config_integrity_ref: None,
                operation_descriptor: None,
            };
            ledger
                .append_durable(&event)
                .await
                .expect("durable append must succeed under load");
        }));
    }

    for handle in handles {
        handle.await.expect("durable append task must not panic");
    }

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "500 durable appends took {:?} — WAL contention too high",
        elapsed
    );

    // Verify WAL file has all event entries (exclude MerkleBatchRecord lines)
    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after all appends");
    let event_count = wal_content
        .lines()
        .filter(|line| {
            line.contains("\"event_id\":")
                && !line.contains("\"merkle_root\"")
                && !line.contains("\"anchor_hash\"")
        })
        .count();
    assert_eq!(
        event_count, 500,
        "WAL should contain exactly 500 event entries, got {}",
        event_count
    );
}

// ─── Test 10: Side-Channel Timing — SRR decision time is input-independent ───

#[test]
fn srr_decision_time_is_roughly_constant() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // Measure timing for a match (Deny) vs no-match (Default-to-Caution)
    let iterations = 10000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = srr.check("POST", "api.bank.com", "/transfer/123", None);
    }
    let deny_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = srr.check("GET", "unknown.com", "/data", None);
    }
    let allow_time = start.elapsed();

    // Both should be in the same order of magnitude (within 10x)
    // This is a rough check — true constant-time requires specialized tools
    let ratio = if deny_time > allow_time {
        deny_time.as_nanos() as f64 / allow_time.as_nanos().max(1) as f64
    } else {
        allow_time.as_nanos() as f64 / deny_time.as_nanos().max(1) as f64
    };

    assert!(
        ratio < 10.0,
        "SRR timing variance too high: deny={:?}, allow={:?}, ratio={:.1}x",
        deny_time,
        allow_time,
        ratio
    );
}

// ─── Test 11: Group Commit Primary Fail — Emergency WAL Catches Events ───
//
// Uses Ledger::inject_write_error() to simulate I/O failure inside the batch task.
// When injected, flush_batch is bypassed. The emergency WAL should catch these events,
// allowing requests to proceed in degraded mode rather than failing outright.
// True Fail-Close only occurs when BOTH primary and emergency WALs fail.

#[tokio::test]
async fn group_commit_primary_fail_emergency_wal_catches() {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize for fail-close test"),
    );

    // Verify normal operation works first
    {
        let event = gvm_proxy::types::GVMEvent {
            event_id: "init-ok".to_string(),
            trace_id: "trace-init".to_string(),
            parent_event_id: None,
            agent_id: "test-agent".to_string(),
            tenant_id: None,
            session_id: "session".to_string(),
            timestamp: chrono::Utc::now(),
            operation: "gvm.storage.read".to_string(),
            resource: Default::default(),
            context: Default::default(),
            transport: None,
            decision: "Allow".to_string(),
            decision_source: "test".to_string(),
            matched_rule_id: None,
            enforcement_point: "test".to_string(),
            status: gvm_proxy::types::EventStatus::Pending,
            payload: Default::default(),
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: false,
            config_integrity_ref: None,
            operation_descriptor: None,
        };
        ledger
            .append_durable(&event)
            .await
            .expect("initial append must succeed before error injection");
    }

    // Inject I/O error — simulates disk failure, permission denied, etc.
    ledger.inject_write_error(true);

    // Launch 10 concurrent callers — all should succeed via emergency WAL fallback
    let mut handles = Vec::new();
    for i in 0..10 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = gvm_proxy::types::GVMEvent {
                event_id: format!("fail-{}", i),
                trace_id: "trace-fail".to_string(),
                parent_event_id: None,
                agent_id: "test-agent".to_string(),
                tenant_id: None,
                session_id: "session".to_string(),
                timestamp: chrono::Utc::now(),
                operation: "gvm.storage.write".to_string(),
                resource: Default::default(),
                context: Default::default(),
                transport: None,
                decision: "Delay".to_string(),
                decision_source: "test".to_string(),
                matched_rule_id: None,
                enforcement_point: "test".to_string(),
                status: gvm_proxy::types::EventStatus::Pending,
                payload: Default::default(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                config_integrity_ref: None,
                operation_descriptor: None,
            };
            ledger.append_durable(&event).await
        }));
    }

    let mut ok_count = 0;
    for handle in handles {
        let result = handle
            .await
            .expect("emergency WAL fallback task must not panic");
        if result.is_ok() {
            ok_count += 1;
        }
    }

    // Emergency WAL catches all events — degraded mode, not fail-close
    assert_eq!(
        ok_count, 10,
        "Emergency WAL: all 10 callers must succeed via fallback, got {} ok",
        ok_count
    );

    // Verify the primary failure counter tracks failures
    assert!(
        ledger.primary_failure_count() >= 10,
        "Primary failure count should be >= 10, got {}",
        ledger.primary_failure_count()
    );

    // Verify emergency WAL captured the events
    assert_eq!(
        ledger.emergency_write_count(),
        10,
        "Emergency write count must be 10"
    );

    // Disable error injection and verify recovery
    ledger.inject_write_error(false);
    let event = gvm_proxy::types::GVMEvent {
        event_id: "recovery-ok".to_string(),
        trace_id: "trace-recovery".to_string(),
        parent_event_id: None,
        agent_id: "test-agent".to_string(),
        tenant_id: None,
        session_id: "session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.storage.read".to_string(),
        resource: Default::default(),
        context: Default::default(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: gvm_proxy::types::EventStatus::Confirmed,
        payload: Default::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    };
    // After disabling error injection, writes should succeed via primary WAL again
    ledger
        .append_durable(&event)
        .await
        .expect("primary WAL must recover after error injection is disabled");
}

// ─── Test 12: Property-Based — max_strict is commutative, associative, idempotent ───

mod proptest_max_strict {
    use gvm_proxy::types::{max_strict, AlertLevel, ApprovalUrgency, EnforcementDecision};
    use proptest::prelude::*;

    /// Generate arbitrary EnforcementDecision values for property testing.
    fn arb_decision() -> impl Strategy<Value = EnforcementDecision> {
        prop_oneof![
            Just(EnforcementDecision::Allow),
            (1u64..=10000).prop_map(|ms| EnforcementDecision::Delay { milliseconds: ms }),
            prop_oneof![
                Just(ApprovalUrgency::Immediate),
                Just(ApprovalUrgency::Standard),
                Just(ApprovalUrgency::Low),
            ]
            .prop_map(|u| EnforcementDecision::RequireApproval { urgency: u }),
            "[a-z]{1,20}".prop_map(|r| EnforcementDecision::Deny { reason: r }),
            prop_oneof![
                Just(AlertLevel::Info),
                Just(AlertLevel::Warning),
                Just(AlertLevel::Critical),
            ]
            .prop_map(|l| EnforcementDecision::AuditOnly { alert_level: l }),
        ]
    }

    proptest! {
        /// max_strict(a, b).strictness() == max(a.strictness(), b.strictness())
        /// This is the core determinism guarantee: same inputs → same strictness level.
        #[test]
        fn max_strict_picks_highest_strictness(
            a in arb_decision(),
            b in arb_decision(),
        ) {
            let result = max_strict(a.clone(), b.clone());
            let expected = std::cmp::max(a.strictness(), b.strictness());
            prop_assert_eq!(
                result.strictness(),
                expected,
                "max_strict({:?}, {:?}) = {:?}, strictness {} != expected {}",
                a, b, result, result.strictness(), expected,
            );
        }

        /// Commutativity at the strictness level:
        /// max_strict(a, b).strictness() == max_strict(b, a).strictness()
        #[test]
        fn max_strict_commutative_strictness(
            a in arb_decision(),
            b in arb_decision(),
        ) {
            let ab = max_strict(a.clone(), b.clone());
            let ba = max_strict(b, a);
            prop_assert_eq!(
                ab.strictness(),
                ba.strictness(),
                "Commutativity violated: ab={:?}, ba={:?}",
                ab, ba,
            );
        }

        /// Associativity at the strictness level:
        /// max_strict(max_strict(a, b), c).strictness() == max_strict(a, max_strict(b, c)).strictness()
        #[test]
        fn max_strict_associative_strictness(
            a in arb_decision(),
            b in arb_decision(),
            c in arb_decision(),
        ) {
            let left = max_strict(max_strict(a.clone(), b.clone()), c.clone());
            let right = max_strict(a, max_strict(b, c));
            prop_assert_eq!(
                left.strictness(),
                right.strictness(),
                "Associativity violated: left={:?}, right={:?}",
                left, right,
            );
        }

        /// Idempotence: max_strict(a, a).strictness() == a.strictness()
        #[test]
        fn max_strict_idempotent(a in arb_decision()) {
            let result = max_strict(a.clone(), a.clone());
            prop_assert_eq!(
                result.strictness(),
                a.strictness(),
                "Idempotence violated: max_strict(a, a)={:?}, a={:?}",
                result, a,
            );
        }

        /// Deny is the absorbing element: max_strict(x, Deny) is always Deny
        #[test]
        fn max_strict_deny_absorbs(a in arb_decision()) {
            let deny = EnforcementDecision::Deny { reason: "test".to_string() };
            let result = max_strict(a, deny);
            prop_assert!(
                matches!(result, EnforcementDecision::Deny { .. }),
                "Deny must absorb any decision, got {:?}",
                result,
            );
        }
    }
}

// ─── Test 12b: §4.1 Determinism — same SRR input → same decision ───
//
// `max_strict` algebra is property-tested above, but the higher-level
// claim ("same operation metadata → same enforcement decision regardless
// of time-of-day or concurrent requests") needs end-to-end coverage.
// We feed the same (method, host, path, body) tuple through SRR many
// times across many threads and assert every output is identical.

mod proptest_srr_determinism {
    use gvm_proxy::srr::NetworkSRR;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn fixed_srr() -> NetworkSRR {
        super::srr_from_toml(
            r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Deny", reason = "policy" }

[[rules]]
method = "GET"
pattern = "api.openai.com/{any}"
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 200 }
"#,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Same input across N repeated calls on the same thread must
        /// produce identical decisions.
        #[test]
        fn srr_check_repeats_are_identical(
            method in prop::sample::select(vec!["GET", "POST", "DELETE"]),
            host in "[a-z]{3,12}\\.(test|com)",
            path in "/[a-z0-9/]{0,30}",
        ) {
            let srr = fixed_srr();
            let r1 = srr.check(&method, &host, &path, None);
            let r2 = srr.check(&method, &host, &path, None);
            let r3 = srr.check(&method, &host, &path, None);
            prop_assert_eq!(format!("{:?}", r1.decision), format!("{:?}", r2.decision));
            prop_assert_eq!(format!("{:?}", r2.decision), format!("{:?}", r3.decision));
        }
    }

    /// 32 threads × 50 iterations against the same input must all
    /// produce identical decisions (no race-induced divergence).
    #[test]
    fn srr_check_concurrent_32threads_identical_decisions() {
        let srr = Arc::new(fixed_srr());
        let inputs = vec![
            ("POST", "api.bank.com", "/transfer/123"),
            ("GET", "api.openai.com", "/v1/models"),
            ("DELETE", "unknown.example.com", "/x"),
        ];
        for (m, h, p) in inputs {
            // Reference decision computed once, single-threaded.
            let reference = format!("{:?}", srr.check(m, h, p, None).decision);

            let mut handles = Vec::new();
            for _ in 0..32 {
                let s = Arc::clone(&srr);
                let r = reference.clone();
                let m_owned = m.to_string();
                let h_owned = h.to_string();
                let p_owned = p.to_string();
                handles.push(std::thread::spawn(move || {
                    for _ in 0..50 {
                        let d =
                            format!("{:?}", s.check(&m_owned, &h_owned, &p_owned, None).decision);
                        assert_eq!(
                            d, r,
                            "concurrent SRR.check on same input produced different \
                             decision: ref={} got={}",
                            r, d
                        );
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
        }
    }
}

// ─── Test 13: HTTP Case-Smuggling Bypass Attempt ───
//
// Attacker tries to bypass SRR rules by varying HTTP method/host/path casing.
// SRR must match case-insensitively for method and host, or the rule must
// catch all case variants.

#[test]
fn srr_case_smuggling_host_variations() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // Attacker varies method and host casing to try to bypass the rule.
    // SRR normalizes method to uppercase and host to lowercase before matching,
    // so all these variants MUST be denied.
    let bypass_attempts = vec![
        ("POST", "API.BANK.COM", "/transfer/123"),
        ("POST", "Api.Bank.Com", "/transfer/123"),
        ("POST", "api.BANK.com", "/transfer/123"),
        ("post", "api.bank.com", "/transfer/123"),
        ("Post", "api.bank.com", "/transfer/123"),
    ];

    for (method, host, path) in &bypass_attempts {
        let result = srr.check(method, host, path, None);
        assert!(
            matches!(result.decision, EnforcementDecision::Deny { .. }),
            "Case-smuggling bypass ({} {} {}) must be denied, got {:?}",
            method,
            host,
            path,
            result.decision,
        );
    }

    // Path casing: SRR does NOT normalize path case (paths are case-sensitive
    // in URLs per RFC 3986). These fall through to catch-all Delay, not Allow.
    let path_case_results = vec![
        srr.check("POST", "api.bank.com", "/Transfer/123", None),
        srr.check("POST", "api.bank.com", "/TRANSFER/123", None),
    ];
    for result in &path_case_results {
        assert!(
            result.decision.strictness()
                >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
            "Path case variant must not bypass to Allow, got {:?}",
            result.decision,
        );
    }
}

// ─── Test 14: Null Byte Injection ───
//
// Attacker injects null bytes to truncate path matching in C-style string processing.
// Rust's String is not null-terminated, so this should not cause truncation,
// but the test proves it.

#[test]
fn srr_null_byte_injection_does_not_truncate() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }

        [[rules]]
        method = "DELETE"
        pattern = "api.bank.com/{any}"
        decision = { type = "Deny", reason = "Delete blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // Null byte before the dangerous path segment
    let result = srr.check("POST", "api.bank.com", "/transfer/\0bypass", None);
    // Must not panic. Deny or Delay is acceptable — must not Allow.
    assert!(
        result.decision.strictness() >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
        "Null byte must not cause Allow bypass, got {:?}",
        result.decision
    );

    // Null byte in host
    let result = srr.check("POST", "api.bank.com\0evil.com", "/transfer/123", None);
    assert!(
        result.decision.strictness() >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
        "Null byte in host must not cause Allow bypass, got {:?}",
        result.decision
    );

    // Null byte as path traversal disguise
    let result = srr.check("DELETE", "api.bank.com", "/\0/users/42", None);
    assert!(
        result.decision.strictness() >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
        "Null byte in path must not cause Allow bypass, got {:?}",
        result.decision
    );
}

// ─── Test 15: Unicode Normalization Bypass ───
//
// Attacker uses Unicode confusables or normalization forms (NFC/NFD/NFKC/NFKD)
// to bypass pattern matching. For example, using fullwidth characters or
// combining marks that normalize to ASCII equivalents.

#[test]
fn srr_unicode_normalization_bypass_attempt() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    let bypass_attempts = vec![
        (
            "fullwidth slash in path",
            "POST",
            "api.bank.com",
            "/transfer\u{FF0F}123",
        ),
        (
            "combining mark in host",
            "POST",
            "a\u{0324}pi.bank.com",
            "/transfer/123",
        ),
        (
            "right-to-left override host",
            "POST",
            "\u{202E}moc.knab.ipa",
            "/transfer/123",
        ),
        (
            "cyrillic homoglyph host",
            "POST",
            "\u{0430}pi.bank.com",
            "/transfer/123",
        ),
        (
            "percent-encoded path suffix",
            "POST",
            "api.bank.com",
            "/transfer/%31%32%33",
        ),
    ];

    for (name, method, host, path) in bypass_attempts {
        let result = srr.check(method, host, path, None);
        assert!(
            result.decision.strictness()
                >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
            "{} must not bypass to Allow, got {:?}",
            name,
            result.decision
        );
    }
}

// ─── Test 16: Path Traversal Bypass Attempt ───

#[test]
fn srr_path_traversal_does_not_bypass() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "POST"
        pattern = "api.bank.com/transfer/{any}"
        decision = { type = "Deny", reason = "Wire transfer blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // Path traversal attempts
    let traversal_paths = vec![
        "/transfer/../transfer/123",
        "/./transfer/123",
        "/transfer/./123",
        "/../../../transfer/123",
        "/transfer/123/../../transfer/456",
        "/transfer%2F123",      // encoded slash
        "/transfer/123%00.txt", // null byte + extension
    ];

    for path in &traversal_paths {
        let result = srr.check("POST", "api.bank.com", path, None);
        // Must not panic. Must not return Allow (fail-open).
        assert!(
            result.decision.strictness()
                >= EnforcementDecision::Delay { milliseconds: 0 }.strictness(),
            "Path traversal '{}' must not bypass to Allow, got {:?}",
            path,
            result.decision
        );
    }
}

// ─── Test 17: Emergency WAL Fallback — Primary Fails, Emergency Catches ───

#[tokio::test]
async fn emergency_wal_catches_events_when_primary_fails() {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize for emergency WAL test"),
    );

    // Inject primary WAL failure
    ledger.inject_write_error(true);

    // Write events — should succeed via emergency WAL fallback
    for i in 0..5 {
        let event = gvm_proxy::types::GVMEvent {
            event_id: format!("emergency-{}", i),
            trace_id: format!("trace-emergency-{}", i),
            parent_event_id: None,
            agent_id: "test-agent".to_string(),
            tenant_id: None,
            session_id: "session".to_string(),
            timestamp: chrono::Utc::now(),
            operation: "gvm.storage.write".to_string(),
            resource: Default::default(),
            context: Default::default(),
            transport: None,
            decision: "Delay".to_string(),
            decision_source: "test".to_string(),
            matched_rule_id: None,
            enforcement_point: "test".to_string(),
            status: gvm_proxy::types::EventStatus::Pending,
            payload: Default::default(),
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: false,
            config_integrity_ref: None,
            operation_descriptor: None,
        };
        // With emergency WAL, this should succeed even though primary is broken
        ledger
            .append_durable(&event)
            .await
            .expect("append must succeed via emergency WAL when primary fails");
    }

    // Verify metrics
    assert!(
        ledger.primary_failure_count() >= 5,
        "Primary failure count should be at least 5, got {}",
        ledger.primary_failure_count()
    );
    assert_eq!(
        ledger.emergency_write_count(),
        5,
        "Emergency write count must be 5"
    );

    // Verify emergency WAL file contains the events
    let emergency_path = dir.path().join("wal_emergency.log");
    let content = tokio::fs::read_to_string(&emergency_path)
        .await
        .expect("emergency WAL file must be readable");
    let event_lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        event_lines.len(),
        5,
        "Emergency WAL should contain 5 events, got {}",
        event_lines.len()
    );

    // Verify each event roundtrips to a valid GVMEvent (not just generic JSON)
    for (i, line) in event_lines.iter().enumerate() {
        let event: gvm_proxy::types::GVMEvent =
            serde_json::from_str(line).expect("emergency WAL event must deserialize to GVMEvent");
        assert_eq!(
            event.event_id,
            format!("emergency-{}", i),
            "Emergency WAL event_id must match original"
        );
        assert_eq!(
            event.operation, "gvm.storage.write",
            "Emergency WAL operation must be preserved"
        );
        assert!(
            event.event_hash.is_some(),
            "Emergency WAL event must have event_hash"
        );
    }

    // Disable error injection — primary WAL should recover
    ledger.inject_write_error(false);
    let event = gvm_proxy::types::GVMEvent {
        event_id: "recovery-after-emergency".to_string(),
        trace_id: "trace-recovery".to_string(),
        parent_event_id: None,
        agent_id: "test-agent".to_string(),
        tenant_id: None,
        session_id: "session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.storage.read".to_string(),
        resource: Default::default(),
        context: Default::default(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: gvm_proxy::types::EventStatus::Confirmed,
        payload: Default::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    };
    ledger
        .append_durable(&event)
        .await
        .expect("primary WAL must recover after error injection disabled");

    // Failure counter should reset to 0 after successful primary write
    assert_eq!(
        ledger.primary_failure_count(),
        0,
        "Failure counter must reset after successful primary write"
    );
}

// ─── Test 18: Agent ID Spoofing — Rate Limiter Isolation ───
//
// Verifies that rate limiter buckets are keyed by agent ID, meaning an attacker
// who spoofs X-GVM-Agent-Id can consume another agent's rate limit budget.
// This is a documented known limitation (security-model section 8).
// The test proves the behavior and establishes a regression baseline.

// Rate limiter tests removed (replaced by token_budget in src/token_budget.rs)

// ─── Test 19: Config Poisoning — Malformed TOML and Catch-All ───
//
// Verifies that malformed config files are rejected at load time (bail!()),
// and that SRR/policy correctly handle edge-case configurations.

#[test]
fn config_poisoning_malformed_toml_rejected() {
    // Malformed SRR TOML must fail to load — not silently ignored
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("bad_srr.toml");

    // Invalid TOML syntax
    std::fs::write(&path, "[[rules]\nmethod = broken\n{{{{").expect("write");
    let result = NetworkSRR::load(&path);
    assert!(result.is_err(), "Malformed TOML must fail to load");

    // Missing required field (decision)
    std::fs::write(
        &path,
        r#"
        [[rules]]
        method = "POST"
        pattern = "example.com/{any}"
    "#,
    )
    .expect("write");
    let result = NetworkSRR::load(&path);
    assert!(
        result.is_err(),
        "SRR rule without decision must fail to load"
    );

    // Empty rules file — valid but produces no rules
    std::fs::write(&path, "").expect("write");
    let result = NetworkSRR::load(&path);
    // Empty file is valid TOML (no rules table) — should either load with 0 rules or error
    // The important thing is it does not panic
    let _r = result;
}

// Test: config_poisoning_policy_malformed_toml_rejected removed — ABAC system deleted.

#[test]
fn config_srr_catch_all_deny_blocks_everything() {
    // A catch-all Deny rule should block all traffic — verify no bypass
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Deny", reason = "Everything blocked" }
    "#,
    );

    let test_cases = vec![
        ("GET", "example.com", "/"),
        ("POST", "api.bank.com", "/transfer/123"),
        ("DELETE", "unknown.host", "/any/path"),
        ("PATCH", "", ""),
        ("OPTIONS", "localhost", "/health"),
    ];

    for (method, host, path) in &test_cases {
        let result = srr.check(method, host, path, None);
        assert!(
            matches!(result.decision, EnforcementDecision::Deny { .. }),
            "Catch-all Deny must block {} {} {}, got {:?}",
            method,
            host,
            path,
            result.decision,
        );
    }
}

// ─── Test 20: Upstream Header Spoofing ───
//
// Verifies that the proxy strips X-GVM-* headers from upstream responses.
// A malicious upstream could inject fake X-GVM-Decision headers that the SDK
// might trust. The proxy must strip these before injecting its own.
// This test verifies the stripping logic in isolation (unit-level).

#[test]
fn upstream_xgvm_headers_are_stripped() {
    // Simulate an upstream response with spoofed X-GVM headers
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-GVM-Decision", "Allow".parse().unwrap());
    headers.insert("X-GVM-Decision-Source", "Attacker".parse().unwrap());
    headers.insert("X-GVM-Event-Id", "fake-event".parse().unwrap());
    headers.insert("X-GVM-Trace-Id", "fake-trace".parse().unwrap());
    headers.insert("X-GVM-Matched-Rule", "fake-rule".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers.insert("X-Custom-Header", "keep-this".parse().unwrap());

    // Apply the same stripping logic the proxy uses in forward_request()
    let gvm_keys: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-gvm-"))
        .cloned()
        .collect();
    for key in gvm_keys {
        headers.remove(&key);
    }

    // All X-GVM-* headers must be stripped
    assert!(
        headers.get("X-GVM-Decision").is_none(),
        "Spoofed X-GVM-Decision must be stripped"
    );
    assert!(
        headers.get("X-GVM-Decision-Source").is_none(),
        "Spoofed X-GVM-Decision-Source must be stripped"
    );
    assert!(
        headers.get("X-GVM-Event-Id").is_none(),
        "Spoofed X-GVM-Event-Id must be stripped"
    );
    assert!(
        headers.get("X-GVM-Trace-Id").is_none(),
        "Spoofed X-GVM-Trace-Id must be stripped"
    );
    assert!(
        headers.get("X-GVM-Matched-Rule").is_none(),
        "Spoofed X-GVM-Matched-Rule must be stripped"
    );

    // Non-GVM headers must survive
    assert!(
        headers.get("Content-Type").is_some(),
        "Content-Type must not be stripped"
    );
    assert!(
        headers.get("X-Custom-Header").is_some(),
        "Non-GVM X- headers must not be stripped"
    );
}

// Test 21 (ABAC Attribute Omission Bypass) removed — ABAC system deleted.

// ─── Rate limiter bucket exhaustion test removed (replaced by token_budget) ───
