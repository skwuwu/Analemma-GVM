//! Stress tests — memory safety, concurrency, and scale verification.
//!
//! Categories:
//! 1. Memory safety: large rule sets, large payloads, sustained load
//! 2. Concurrency stress: mixed IC paths, WAL group commit, rate limiter precision
//! 3. Scale: 10K SRR rules

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use gvm_proxy::vault::Vault;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Helpers ───

fn srr_from_toml(toml_str: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml_str).expect("valid TOML string must write to temp file");
    NetworkSRR::load(&path).expect("valid SRR TOML must parse and load")
}

fn make_test_event(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-{}", id),
        trace_id: "trace-stress".to_string(),
        parent_event_id: None,
        agent_id: "stress-agent".to_string(),
        tenant_id: None,
        session_id: "session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.storage.read".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Pending,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// 1. MEMORY SAFETY — SRR
// ═══════════════════════════════════════════════════════════════════

/// Load 10,000 SRR rules and verify lookup still works correctly.
/// Validates that the linear rule list does not OOM or degrade catastrophically.
#[test]
fn srr_10000_rules_load_and_lookup() {
    let mut toml = String::new();

    // Generate 10,000 rules — each blocks a unique host
    for i in 0..10_000 {
        toml.push_str(&format!(
            r#"
[[rules]]
method = "POST"
pattern = "host-{}.example.com/{{any}}"
decision = {{ type = "Deny", reason = "Rule {}" }}
"#,
            i, i
        ));
    }

    // Add catch-all
    toml.push_str(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    );

    let start = Instant::now();
    let srr = srr_from_toml(&toml);
    let load_time = start.elapsed();

    // Loading 10K rules should complete in < 5 seconds
    assert!(
        load_time.as_secs() < 5,
        "Loading 10,000 SRR rules took {:?} — too slow",
        load_time
    );

    // Verify first rule matches
    let d1 = srr.check("POST", "host-0.example.com", "/test", None);
    assert!(
        matches!(d1.decision, EnforcementDecision::Deny { .. }),
        "First rule should match"
    );

    // Verify last rule matches
    let d2 = srr.check("POST", "host-9999.example.com", "/test", None);
    assert!(
        matches!(d2.decision, EnforcementDecision::Deny { .. }),
        "Last rule should match"
    );

    // Verify unknown host falls through to catch-all
    let d3 = srr.check("GET", "unknown.example.com", "/test", None);
    assert!(
        matches!(d3.decision, EnforcementDecision::Delay { .. }),
        "Unknown host should get Default-to-Caution"
    );

    // Measure lookup time with 10K rules.
    // §3.1 hot-path budget: < 1µs. We measure many iterations and
    // assert against a CI-realistic ceiling that is still 50× tighter
    // than the prior 5ms ceiling — anything above the new ceiling
    // indicates a real algorithmic regression, not just CI jitter.
    let start = Instant::now();
    let iterations = 10_000;
    for _ in 0..iterations {
        let _ = srr.check("POST", "host-5000.example.com", "/test", None);
    }
    let lookup_time = start.elapsed();
    let per_lookup_us = lookup_time.as_micros() as f64 / iterations as f64;

    // §3.1 release budget is <1µs; debug builds are ~10–100× slower.
    // CI ceiling: 1000µs/lookup. This is 5× tighter than the prior
    // 5000µs ceiling and still catches a 10× algorithmic regression
    // without flaking on shared CI runners under debug builds.
    // Benches exercise the release-build sub-µs claim separately.
    assert!(
        per_lookup_us < 1000.0,
        "SRR lookup with 10K rules: {:.2}µs/lookup — exceeds CI ceiling \
         of 1000µs (§3.1 release budget is <1µs; benches verify that)",
        per_lookup_us
    );
}

/// Load a ~1MB SRR TOML file without OOM.
#[test]
fn srr_1mb_toml_file_no_oom() {
    let mut toml = String::new();

    // Generate rules with long descriptions to reach ~1MB
    for i in 0..2_000 {
        let long_desc = format!("Rule {i} — {}", "x".repeat(400));
        let reason = format!("Blocked by rule {i}");
        toml.push_str(&format!(
            r#"
[[rules]]
method = "POST"
pattern = "host-{i}.megacorp.internal/api/v1/{{any}}"
decision = {{ type = "Deny", reason = "{reason}" }}
description = "{long_desc}"
"#,
        ));
    }

    assert!(
        toml.len() > 900_000,
        "TOML should be ~1MB, got {} bytes",
        toml.len()
    );

    let start = Instant::now();
    let srr = srr_from_toml(&toml);
    let load_time = start.elapsed();

    assert!(
        load_time.as_secs() < 10,
        "Loading 1MB SRR file took {:?}",
        load_time
    );

    // Verify it works
    let d = srr.check("POST", "host-1000.megacorp.internal", "/api/v1/data", None);
    assert!(matches!(d.decision, EnforcementDecision::Deny { .. }));
}

/// Payload inspection at exact max_body_bytes boundary — no buffer overflow.
#[test]
fn srr_payload_boundary_no_overflow() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.example.com/graphql"
payload_field = "operationName"
payload_match = ["Dangerous"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Blocked" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    );

    // Body at exactly 65536 bytes (limit boundary)
    let mut body_at_limit = br#"{"operationName":"Dangerous"}"#.to_vec();
    body_at_limit.resize(65536, b' ');

    let d = srr.check("POST", "api.example.com", "/graphql", Some(&body_at_limit));
    // At exact limit, inspection should proceed and find the match
    assert!(
        matches!(d.decision, EnforcementDecision::Deny { .. }),
        "Body at exact limit should be inspected"
    );

    // Body at 65537 (one byte over)
    let mut body_over = br#"{"operationName":"Dangerous"}"#.to_vec();
    body_over.resize(65537, b' ');

    let d = srr.check("POST", "api.example.com", "/graphql", Some(&body_over));
    // Over limit should fall through to Default-to-Caution
    assert!(
        matches!(d.decision, EnforcementDecision::Delay { .. }),
        "Body over limit should get Default-to-Caution"
    );
}

// ABAC policy engine stress tests removed — ABAC system deleted.

// ═══════════════════════════════════════════════════════════════════
// 3. MEMORY SAFETY — VAULT
// ═══════════════════════════════════════════════════════════════════

/// Vault encrypt/decrypt 10,000 times without memory leak.
/// Each write goes through WAL (fsync), so we use a count that fits within CI time limits.
/// Uses batch_window=0 to avoid Windows timer resolution penalty (15.6ms) on sequential writes.
#[tokio::test]
async fn vault_10k_encrypt_decrypt_no_leak() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let config = gvm_proxy::ledger::GroupCommitConfig {
        batch_window: std::time::Duration::ZERO,
        ..Default::default()
    };
    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", config)
            .await
            .expect("ledger with valid path must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault with valid ledger must initialize");

    let plaintext = b"test secret value for stress test";

    let start = Instant::now();
    for i in 0..10_000 {
        let key = format!("key-{}", i % 100); // Reuse 100 keys
        vault
            .write(&key, plaintext, "stress-agent")
            .await
            .expect("vault write must succeed for valid key");
        let result = vault
            .read(&key, "stress-agent")
            .await
            .expect("vault read must succeed for existing key");
        assert_eq!(
            result.expect("vault read must return data for existing key"),
            plaintext
        );
    }
    let elapsed = start.elapsed();

    // 10K roundtrips should complete in < 180 seconds.
    // Windows CI runners are ~3x slower than Linux/macOS for crypto operations.
    assert!(
        elapsed.as_secs() < 180,
        "10K vault roundtrips took {:?}",
        elapsed
    );
}

/// Vault handles 1MB plaintext values correctly.
#[tokio::test]
async fn vault_1mb_value_roundtrip() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger with valid path must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault with valid ledger must initialize");

    // 1MB plaintext
    let plaintext: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();

    vault
        .write("big-key", &plaintext, "agent")
        .await
        .expect("vault must handle 1MB write");
    let result = vault
        .read("big-key", "agent")
        .await
        .expect("vault must handle 1MB read");
    assert_eq!(
        result.expect("vault must return 1MB value after write"),
        plaintext,
        "1MB roundtrip must be exact"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 4. CONCURRENCY STRESS — WAL GROUP COMMIT
// ═══════════════════════════════════════════════════════════════════

/// 1,000 concurrent durable appends — all must complete and be recorded.
#[tokio::test]
async fn wal_1000_concurrent_durable_appends() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger with valid path must initialize"),
    );

    let start = Instant::now();

    let mut handles = Vec::with_capacity(1_000);
    for i in 0..1_000 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("concurrent-{}", i));
            ledger
                .append_durable(&event)
                .await
                .expect("concurrent durable append must succeed");
        }));
    }

    for h in handles {
        h.await.expect("concurrent append task must not panic");
    }

    let elapsed = start.elapsed();

    // 1,000 concurrent appends should complete in < 10 seconds
    assert!(
        elapsed.as_secs() < 10,
        "1,000 concurrent WAL appends took {:?}",
        elapsed
    );

    // Verify WAL has exactly 1,000 event entries (exclude MerkleBatchRecord lines)
    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after concurrent writes");
    let event_count = content
        .lines()
        .filter(|line| !line.contains("\"merkle_root\""))
        .count();
    assert_eq!(
        event_count, 1_000,
        "WAL should contain exactly 1,000 event entries, got {}",
        event_count
    );
}

/// Sustained load: 5,000 appends/sec for 2 seconds (10,000 total).
/// Verifies no OOM and WAL file grows linearly.
#[tokio::test]
async fn wal_sustained_load_10k_events() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let config = GroupCommitConfig {
        batch_window: Duration::from_millis(2),
        max_batch_size: 256,
        channel_capacity: 8192,
        ..Default::default()
    };

    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", config)
            .await
            .expect("ledger with valid config must initialize"),
    );

    let total_events = 10_000usize;
    let start = Instant::now();

    // Fire all events as fast as possible with high concurrency
    let mut handles = Vec::with_capacity(total_events);
    for i in 0..total_events {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("sustained-{}", i));
            ledger
                .append_durable(&event)
                .await
                .expect("sustained load append must succeed");
        }));
    }

    for h in handles {
        h.await.expect("sustained load task must not panic");
    }

    let elapsed = start.elapsed();

    // Must complete in < 30 seconds
    assert!(
        elapsed.as_secs() < 30,
        "10K sustained WAL appends took {:?}",
        elapsed
    );

    // Verify WAL has all event entries (exclude MerkleBatchRecord lines)
    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after sustained load");
    let event_count = content
        .lines()
        .filter(|line| !line.contains("\"merkle_root\""))
        .count();
    assert_eq!(
        event_count, total_events,
        "WAL should contain {} event entries, got {}",
        total_events, event_count
    );

    // Verify WAL file size is reasonable (each event ~500 bytes JSON)
    let file_size = tokio::fs::metadata(&wal_path)
        .await
        .expect("WAL file metadata must be accessible")
        .len();
    assert!(
        file_size > 0 && file_size < 100_000_000,
        "WAL file size {} bytes seems unreasonable for {} events",
        file_size,
        total_events
    );
}

// ═══════════════════════════════════════════════════════════════════
// 5. CONCURRENCY STRESS — MIXED IC PATHS
// ═══════════════════════════════════════════════════════════════════

/// 100 concurrent requests with mixed IC decisions (50% Allow, 30% Delay, 20% Deny).
/// All must receive correct decisions without deadlock.
#[tokio::test]
async fn stress_100_concurrent_mixed_ic_decisions() {
    let srr = Arc::new(srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Deny", reason = "Wire transfer blocked" }

[[rules]]
method = "POST"
pattern = "gmail.googleapis.com/{any}"
decision = { type = "Delay", milliseconds = 300 }

[[rules]]
method = "GET"
pattern = "api.internal.dev/{any}"
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    ));

    let start = Instant::now();

    let mut handles = Vec::new();
    for i in 0..100 {
        let srr = srr.clone();
        handles.push(tokio::spawn(async move {
            let (method, host, path) = match i % 10 {
                0..=4 => ("GET", "api.internal.dev", "/data"), // 50% Allow
                5..=7 => ("POST", "gmail.googleapis.com", "/send"), // 30% Delay
                _ => ("POST", "api.bank.com", "/transfer/123"), // 20% Deny
            };
            srr.check(method, host, path, None)
        }));
    }

    let mut allow_count = 0usize;
    let mut delay_count = 0usize;
    let mut deny_count = 0usize;

    for h in handles {
        let result = h.await.expect("mixed IC decision task must not panic");
        match result.decision {
            EnforcementDecision::Allow => allow_count += 1,
            EnforcementDecision::Delay { .. } => delay_count += 1,
            EnforcementDecision::Deny { .. } => deny_count += 1,
            _ => panic!("Unexpected decision: {:?}", result.decision),
        }
    }

    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 1000, "Mixed IC took {:?}", elapsed);
    assert_eq!(allow_count, 50, "Expected 50 allows, got {}", allow_count);
    assert_eq!(delay_count, 30, "Expected 30 delays, got {}", delay_count);
    assert_eq!(deny_count, 20, "Expected 20 denies, got {}", deny_count);
}

// ═══════════════════════════════════════════════════════════════════
// 6. WAL throughput / audit verification (Allow-path regression guards)
// ═══════════════════════════════════════════════════════════════════

/// Allow-only throughput: 10K Allow events must clear group commit
/// quickly. Guards against a regression where switching Allow from
/// `append_async` (NATS stub) to `append_durable` (WAL+fsync) could
/// introduce an unacceptable slowdown in the hot path.
///
/// Ignored by default because a 10K WAL run writes a real file and is
/// slower than a unit test. Run with `cargo test --test stress
/// wal_throughput_all_allow -- --ignored --nocapture` when tuning.
#[tokio::test]
#[ignore]
async fn wal_throughput_all_allow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");

    let config = GroupCommitConfig {
        batch_window: Duration::from_millis(2),
        max_batch_size: 256,
        channel_capacity: 16_384,
        ..Default::default()
    };

    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", config)
            .await
            .expect("ledger init"),
    );

    let total = 10_000usize;
    let start = Instant::now();

    let mut handles = Vec::with_capacity(total);
    for i in 0..total {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let mut event = make_test_event(&format!("allow-{}", i));
            event.decision = "Allow".to_string();
            event.status = EventStatus::Confirmed;
            ledger
                .append_durable(&event)
                .await
                .expect("Allow durable append must succeed");
        }));
    }
    for h in handles {
        h.await.expect("task panic");
    }
    let elapsed = start.elapsed();
    let throughput = total as f64 / elapsed.as_secs_f64();

    eprintln!(
        "wal_throughput_all_allow: {} events in {:?} ({:.0}/s)",
        total, elapsed, throughput
    );

    // Hard ceiling: 60s for 10K events (< 170/s would indicate a severe
    // regression). Baseline on a modern laptop is typically 1000-5000/s.
    assert!(
        elapsed.as_secs() < 60,
        "10K Allow durable appends took {:?} (> 60s ceiling)",
        elapsed
    );
}

/// Measure `verify_wal` latency on a mid-size audit log (100K events) so
/// we can project compliance-check performance for production-scale WALs.
/// Not a pass/fail gate — prints timing for roadmap decisions. Use
/// `--nocapture` to see the measurement.
///
/// Note: 100K events is chosen to keep the test under a minute. A 1GB
/// WAL (target audit-size class) is ~5M events at ~200 bytes each; we
/// linearly extrapolate from the 100K number.
#[tokio::test]
#[ignore]
async fn verify_wal_latency_100k_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");

    let config = GroupCommitConfig {
        batch_window: Duration::from_millis(5),
        max_batch_size: 512,
        channel_capacity: 32_768,
        ..Default::default()
    };

    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", config)
            .await
            .expect("ledger init"),
    );

    let total = 100_000usize;
    let write_start = Instant::now();
    let mut handles = Vec::with_capacity(total);
    for i in 0..total {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let mut event = make_test_event(&format!("audit-{}", i));
            event.decision = if i % 5 == 0 {
                "Delay { milliseconds: 300 }".to_string()
            } else {
                "Allow".to_string()
            };
            event.status = EventStatus::Confirmed;
            ledger.append_durable(&event).await.ok();
        }));
    }
    for h in handles {
        h.await.ok();
    }
    let write_elapsed = write_start.elapsed();
    drop(ledger);

    let wal_size = tokio::fs::metadata(&wal_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);

    // Measure verification
    let verify_start = Instant::now();
    let (valid_links, _broken) = Ledger::check_chain_integrity(&wal_path);
    let verify_elapsed = verify_start.elapsed();

    eprintln!(
        "verify_wal_latency_100k_events:\n  write: {:?} ({:.0}/s)\n  WAL size: {} bytes ({:.1} MB)\n  verify (chain integrity scan): {:?} ({} config_load links)\n  projected 1GB verify: {:?}",
        write_elapsed,
        total as f64 / write_elapsed.as_secs_f64(),
        wal_size,
        wal_size as f64 / 1_048_576.0,
        verify_elapsed,
        valid_links,
        Duration::from_secs_f64(
            verify_elapsed.as_secs_f64() * (1_073_741_824.0 / wal_size.max(1) as f64)
        )
    );

    // Not a hard gate — this test exists to report numbers.
    // Ceiling only to catch catastrophic regression.
    assert!(
        verify_elapsed.as_secs() < 300,
        "verify_wal on {} MB took {:?}",
        wal_size / 1_048_576,
        verify_elapsed
    );
}

// ═══════════════════════════════════════════════════════════════════
// 7. RATE LIMITER — removed (replaced by token_budget in src/token_budget.rs)
// Token budget unit tests are in src/token_budget.rs
