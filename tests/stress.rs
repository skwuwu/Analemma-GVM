//! Stress tests — memory safety, concurrency, and scale verification.
//!
//! Categories:
//! 1. Memory safety: large rule sets, large payloads, sustained load
//! 2. Concurrency stress: mixed IC paths, WAL group commit, rate limiter precision
//! 3. Scale: 10K SRR rules, 1K ABAC rules, 100-tenant hierarchy

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_proxy::policy::PolicyEngine;
use gvm_proxy::rate_limiter::RateLimiter;
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
    }
}

fn make_operation(
    op: &str,
    sensitivity: Sensitivity,
    tier: ResourceTier,
    tenant: Option<&str>,
    agent: &str,
) -> OperationMetadata {
    OperationMetadata {
        operation: op.to_string(),
        resource: ResourceDescriptor {
            service: "test".to_string(),
            identifier: None,
            tier,
            sensitivity,
        },
        subject: SubjectDescriptor {
            agent_id: agent.to_string(),
            tenant_id: tenant.map(|s| s.to_string()),
            session_id: "test-session".to_string(),
        },
        context: OperationContext {
            attributes: HashMap::new(),
        },
        payload: PayloadDescriptor::default(),
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

    // Measure lookup time with 10K rules
    let start = Instant::now();
    let iterations = 1_000;
    for _ in 0..iterations {
        let _ = srr.check("POST", "host-5000.example.com", "/test", None);
    }
    let lookup_time = start.elapsed();
    let per_lookup_us = lookup_time.as_micros() as f64 / iterations as f64;

    // Each lookup should be < 1ms even with 10K rules
    assert!(
        per_lookup_us < 1000.0,
        "SRR lookup with 10K rules: {:.1}us/lookup — too slow",
        per_lookup_us
    );
}

/// Load a ~1MB SRR TOML file without OOM.
#[test]
fn srr_1mb_toml_file_no_oom() {
    let mut toml = String::new();

    // Generate rules with long descriptions to reach ~1MB
    for i in 0..2_000 {
        let long_desc = format!("Rule {} — {}", i, "x".repeat(400));
        toml.push_str(&format!(
            r#"
[[rules]]
method = "POST"
pattern = "host-{}.megacorp.internal/api/v1/{{any}}"
decision = {{ type = "Deny", reason = "{}" }}
description = "{}"
"#,
            i,
            format!("Blocked by rule {}", i),
            long_desc,
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

// ═══════════════════════════════════════════════════════════════════
// 2. MEMORY SAFETY — POLICY ENGINE
// ═══════════════════════════════════════════════════════════════════

/// Load 1,000 ABAC rules and verify evaluation works.
#[test]
fn policy_1000_rules_load_and_evaluate() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir).expect("policies subdirectory must be creatable");

    // Generate 999 specific rules + 1 catch-all
    let mut rules_toml = String::new();
    for i in 0..999 {
        rules_toml.push_str(&format!(
            r#"
[[rules]]
id = "rule-{i}"
priority = {i}
layer = "Global"
description = "Generated rule {i}"
conditions = [
    {{ field = "operation", operator = "Eq", value = "gvm.test.op{i}" }}
]
[rules.decision]
type = "Deny"
reason = "Matched rule {i}"
"#,
        ));
    }

    // Add catch-all
    rules_toml.push_str(
        r#"
[[rules]]
id = "catch-all"
priority = 9999
layer = "Global"
description = "Default allow"
[rules.decision]
type = "Allow"
"#,
    );

    std::fs::write(policy_dir.join("global.toml"), &rules_toml).expect("policy TOML must write to temp file");

    let start = Instant::now();
    let engine = PolicyEngine::load(&policy_dir).expect("valid policy directory must load");
    let load_time = start.elapsed();

    assert!(
        load_time.as_secs() < 5,
        "Loading 1,000 rules took {:?}",
        load_time
    );

    // Verify specific rule matches
    let op = make_operation("gvm.test.op500", Sensitivity::Low, ResourceTier::Internal, None, "agent");
    let (decision, rule_id) = engine.evaluate(&op);
    assert!(matches!(decision, EnforcementDecision::Deny { .. }));
    assert_eq!(rule_id.expect("matching rule must return its ID"), "rule-500");

    // Verify unmatched operation falls through to catch-all
    let op = make_operation("gvm.unknown.action", Sensitivity::Low, ResourceTier::Internal, None, "agent");
    let (decision, _) = engine.evaluate(&op);
    assert!(matches!(decision, EnforcementDecision::Allow));

    // Measure evaluation time with 1K rules
    let start = Instant::now();
    let iterations = 1_000;
    for _ in 0..iterations {
        // Worst case: falls through all 999 rules to catch-all
        let op = make_operation("gvm.nomatch.ever", Sensitivity::Low, ResourceTier::Internal, None, "agent");
        let _ = engine.evaluate(&op);
    }
    let eval_time = start.elapsed();
    let per_eval_us = eval_time.as_micros() as f64 / iterations as f64;

    assert!(
        per_eval_us < 5000.0,
        "Policy eval with 1K rules: {:.1}us/eval — too slow",
        per_eval_us
    );
}

/// Load Global + 100 Tenant + 1,000 Agent policies simultaneously.
#[test]
fn policy_large_hierarchy_100_tenants_1000_agents() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let policy_dir = dir.path().join("policies");
    std::fs::create_dir(&policy_dir).expect("policies subdirectory must be creatable");

    // Global: deny critical deletes
    std::fs::write(
        policy_dir.join("global.toml"),
        r#"
[[rules]]
id = "global-deny-delete"
priority = 1
layer = "Global"
description = "Deny critical deletes"
conditions = [
    { field = "operation", operator = "Eq", value = "gvm.storage.delete" },
    { field = "resource.sensitivity", operator = "Eq", value = "Critical" }
]
[rules.decision]
type = "Deny"
reason = "Critical deletion forbidden"

[[rules]]
id = "global-allow-all"
priority = 999
layer = "Global"
description = "Default allow"
[rules.decision]
type = "Allow"
"#,
    )
    .expect("global policy TOML must write to temp file");

    // Generate 100 tenant configs
    for t in 0..100 {
        let content = format!(
            r#"
[[rules]]
id = "tenant-{t}-delay-write"
priority = 10
layer = "Tenant"
description = "Tenant {t}: delay writes"
conditions = [
    {{ field = "operation", operator = "EndsWith", value = ".write" }}
]
[rules.decision]
type = "Delay"
milliseconds = 300
"#,
        );
        std::fs::write(policy_dir.join(format!("tenant-t{}.toml", t)), &content).expect("tenant policy TOML must write to temp file");
    }

    // Generate 1,000 agent configs (10 per tenant)
    for a in 0..1_000 {
        let content = format!(
            r#"
[[rules]]
id = "agent-{a}-audit"
priority = 5
layer = "Agent"
description = "Agent {a}: audit all"
[rules.decision]
type = "AuditOnly"
alert_level = "Info"
"#,
        );
        std::fs::write(policy_dir.join(format!("agent-a{}.toml", a)), &content).expect("agent policy TOML must write to temp file");
    }

    let start = Instant::now();
    let engine = PolicyEngine::load(&policy_dir).expect("valid policy hierarchy must load");
    let load_time = start.elapsed();

    assert!(
        load_time.as_secs() < 10,
        "Loading 100T+1000A hierarchy took {:?}",
        load_time
    );

    // Verify global deny still works
    let op = make_operation(
        "gvm.storage.delete",
        Sensitivity::Critical,
        ResourceTier::Internal,
        Some("t50"),
        "a500",
    );
    let (decision, _) = engine.evaluate(&op);
    assert!(
        matches!(decision, EnforcementDecision::Deny { .. }),
        "Global deny must override tenant/agent rules"
    );

    // Verify tenant delay works
    let op = make_operation(
        "gvm.storage.write",
        Sensitivity::Low,
        ResourceTier::Internal,
        Some("t50"),
        "unknown-agent",
    );
    let (decision, _) = engine.evaluate(&op);
    // Tenant delay (strictness 3) > Global allow (strictness 0)
    assert!(
        matches!(decision, EnforcementDecision::Delay { .. }),
        "Tenant delay should override global allow for writes"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. MEMORY SAFETY — VAULT
// ═══════════════════════════════════════════════════════════════════

/// Vault encrypt/decrypt 10,000 times without memory leak.
/// Each write goes through WAL (fsync), so we use a count that fits within CI time limits.
#[tokio::test]
async fn vault_10k_encrypt_decrypt_no_leak() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.expect("ledger with valid path must initialize"));
    let vault = Vault::new(ledger).expect("vault with valid ledger must initialize");

    let plaintext = b"test secret value for stress test";

    let start = Instant::now();
    for i in 0..10_000 {
        let key = format!("key-{}", i % 100); // Reuse 100 keys
        vault.write(&key, plaintext, "stress-agent").await.expect("vault write must succeed for valid key");
        let result = vault.read(&key, "stress-agent").await.expect("vault read must succeed for existing key");
        assert_eq!(result.expect("vault read must return data for existing key"), plaintext);
    }
    let elapsed = start.elapsed();

    // 10K roundtrips should complete in < 60 seconds
    assert!(
        elapsed.as_secs() < 60,
        "10K vault roundtrips took {:?}",
        elapsed
    );
}

/// Vault handles 1MB plaintext values correctly.
#[tokio::test]
async fn vault_1mb_value_roundtrip() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.expect("ledger with valid path must initialize"));
    let vault = Vault::new(ledger).expect("vault with valid ledger must initialize");

    // 1MB plaintext
    let plaintext: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();

    vault
        .write("big-key", &plaintext, "agent")
        .await
        .expect("vault must handle 1MB write");
    let result = vault.read("big-key", "agent").await.expect("vault must handle 1MB read");
    assert_eq!(result.expect("vault must return 1MB value after write"), plaintext, "1MB roundtrip must be exact");
}

// ═══════════════════════════════════════════════════════════════════
// 4. CONCURRENCY STRESS — WAL GROUP COMMIT
// ═══════════════════════════════════════════════════════════════════

/// 1,000 concurrent durable appends — all must complete and be recorded.
#[tokio::test]
async fn wal_1000_concurrent_durable_appends() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.expect("ledger with valid path must initialize"));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(1_000);
    for i in 0..1_000 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("concurrent-{}", i));
            ledger.append_durable(&event).await.expect("concurrent durable append must succeed");
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
    let content = tokio::fs::read_to_string(&wal_path).await.expect("WAL file must be readable after concurrent writes");
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
            ledger.append_durable(&event).await.expect("sustained load append must succeed");
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
    let content = tokio::fs::read_to_string(&wal_path).await.expect("WAL file must be readable after sustained load");
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
    let file_size = tokio::fs::metadata(&wal_path).await.expect("WAL file metadata must be accessible").len();
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
// 6. RATE LIMITER PRECISION
// ═══════════════════════════════════════════════════════════════════

/// 5 agents, each with 100/min limit, each sending 200 requests.
/// Exactly 100 should be allowed, 100 denied (within tolerance).
#[test]
fn rate_limiter_exact_enforcement() {
    let limiter = RateLimiter::new();

    for agent_num in 0..5 {
        let agent_id = format!("agent-{}", agent_num);
        let mut allowed = 0u32;
        let mut denied = 0u32;

        for _ in 0..200 {
            if limiter.check(&agent_id, 100) {
                allowed += 1;
            } else {
                denied += 1;
            }
        }

        // First 100 should be allowed (bucket starts full), rest denied
        assert_eq!(
            allowed, 100,
            "Agent {} should have exactly 100 allowed, got {}",
            agent_id, allowed
        );
        assert_eq!(
            denied, 100,
            "Agent {} should have exactly 100 denied, got {}",
            agent_id, denied
        );
    }
}

/// Rate limiter window boundary: verify no double-counting at refill boundaries.
#[test]
fn rate_limiter_window_boundary_no_double_count() {
    let limiter = RateLimiter::new();

    // Exhaust the bucket (10 tokens)
    for _ in 0..10 {
        assert!(limiter.check("boundary-agent", 10));
    }
    // Bucket empty
    assert!(!limiter.check("boundary-agent", 10));

    // Wait for partial refill (100ms = ~1/600th of a minute ≈ 0.017 tokens for 10/min)
    std::thread::sleep(Duration::from_millis(100));

    // After 100ms with 10/min rate = 0.167 tokens/sec, so ~0.017 tokens.
    // Should still be denied (less than 1 token refilled)
    assert!(
        !limiter.check("boundary-agent", 10),
        "Should still be denied after 100ms (insufficient refill)"
    );

    // Wait 6.5 seconds = ~1.08 tokens refilled
    std::thread::sleep(Duration::from_millis(6500));

    // Should now have ~1 token
    assert!(
        limiter.check("boundary-agent", 10),
        "Should be allowed after sufficient refill time"
    );
    // But only 1
    assert!(
        !limiter.check("boundary-agent", 10),
        "Should be denied again after consuming the refilled token"
    );
}
