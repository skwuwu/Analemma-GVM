//! Edge case tests — boundary conditions, missing inputs, conflict resolution.
//!
//! Categories:
//! 1. Input boundaries: empty body, binary body, null bytes, unicode, huge headers
//! 2. Missing/partial GVM headers: Layer 2 fallback behavior
//! 3. Enforcement edge cases: max_strict ordering, SRR disagreement
//! 4. EventStatus transitions: concurrent updates, forward failure simulation

use gvm_proxy::ledger::Ledger;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use std::collections::HashMap;
use std::sync::Arc;

// ─── Helpers ───

fn srr_from_toml(toml_str: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().expect("temp directory creation must succeed");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml_str).expect("writing SRR toml to temp file must succeed");
    NetworkSRR::load(&path).expect("valid SRR toml must parse")
}


// ═══════════════════════════════════════════════════════════════════
// 1. INPUT BOUNDARIES — SRR
// ═══════════════════════════════════════════════════════════════════

/// POST request with empty body — payload inspection must skip safely.
#[test]
fn edge_empty_body_payload_inspection_skips() {
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
method = "POST"
pattern = "api.example.com/{any}"
decision = { type = "Delay", milliseconds = 200 }
"#,
    );

    // Empty body — payload rule should skip, fall through to URL rule
    let d = srr.check("POST", "api.example.com", "/graphql", Some(b""));
    match d.decision {
        EnforcementDecision::Delay { milliseconds } => {
            assert_eq!(milliseconds, 200);
        }
        other => panic!("Empty body should skip payload rule, got: {:?}", other),
    }
}

/// Binary body (image/PNG header) — JSON parsing must fail gracefully.
#[test]
fn edge_binary_body_json_parse_fails_gracefully() {
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
method = "POST"
pattern = "api.example.com/{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    );

    // PNG file header — not JSON, should not crash
    let png_header: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
    let d = srr.check("POST", "api.example.com", "/graphql", Some(png_header));

    // Should fall through to next URL-matching rule (Delay 300ms)
    match d.decision {
        EnforcementDecision::Delay { milliseconds } => {
            assert_eq!(milliseconds, 300);
        }
        other => panic!(
            "Binary body should cause graceful fallthrough, got: {:?}",
            other
        ),
    }
}

/// URL path containing null bytes — must not crash or bypass matching.
#[test]
fn edge_null_bytes_in_path_safe_handling() {
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

    // Path with null byte injection attempt
    let d = srr.check(
        "POST",
        "api.bank.com",
        "/transfer/\0../../../etc/passwd",
        None,
    );

    // The path starts with /transfer/ so it should still be caught by the deny rule
    assert!(
        matches!(d.decision, EnforcementDecision::Deny { .. }),
        "Null byte in path must not bypass deny rule, got: {:?}",
        d.decision
    );
}

// edge_unicode_operation_name removed — ABAC system deleted.

/// SRR with very long host and path — no allocation panic.
#[test]
fn edge_very_long_host_and_path() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    );

    let long_host = "a".repeat(100_000);
    let long_path = format!("/{}", "b".repeat(100_000));

    // Must not panic or OOM
    let d = srr.check("GET", &long_host, &long_path, None);
    assert!(
        matches!(d.decision, EnforcementDecision::Delay { .. }),
        "Long inputs should safely match catch-all"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 2. MISSING/PARTIAL GVM HEADERS
// ═══════════════════════════════════════════════════════════════════

/// Direct HTTP call without any GVM headers — SRR-only fallback.
/// This simulates an agent bypassing the SDK and making raw HTTP calls.
#[test]
fn edge_missing_gvm_headers_srr_only_fallback() {
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

    // No GVM headers — SRR checks URL only
    // Dangerous URL should still be blocked
    let d = srr.check("POST", "api.bank.com", "/transfer/123", None);
    assert!(
        matches!(d.decision, EnforcementDecision::Deny { .. }),
        "SRR must block dangerous URLs even without GVM headers"
    );

    // Safe URL without headers gets Default-to-Caution
    let d = srr.check("GET", "api.safe.com", "/data", None);
    assert!(
        matches!(d.decision, EnforcementDecision::Delay { .. }),
        "Unknown URL without headers should get Default-to-Caution"
    );
}

// ═══════════════════════════════════════════════════════════════════
// 3. POLICY EDGE CASES
// ═══════════════════════════════════════════════════════════════════

// edge_policy_no_match_returns_allow and edge_policy_conflicting_layers_deny_wins
// removed — ABAC system deleted.

/// SRR says Allow, Policy says Deny — max_strict should pick Deny.
#[test]
fn edge_srr_and_policy_disagree_deny_wins() {
    // Simulates the proxy's max_strict(srr_decision, policy_decision) logic
    let srr_allow = EnforcementDecision::Allow;
    let policy_deny = EnforcementDecision::Deny {
        reason: "Policy blocked".to_string(),
    };

    let result = max_strict(srr_allow, policy_deny);
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict(Allow, Deny) must be Deny"
    );

    // Reverse: Policy Allow, SRR Deny
    let srr_deny = EnforcementDecision::Deny {
        reason: "SRR blocked".to_string(),
    };
    let policy_allow = EnforcementDecision::Allow;

    let result = max_strict(srr_deny, policy_allow);
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict(Deny, Allow) must be Deny"
    );
}

/// max_strict: Delay vs RequireApproval — RequireApproval wins.
#[test]
fn edge_max_strict_delay_vs_require_approval() {
    let delay = EnforcementDecision::Delay { milliseconds: 300 };
    let approval = EnforcementDecision::RequireApproval {
        urgency: ApprovalUrgency::Standard,
    };

    let result = max_strict(delay, approval);
    assert!(
        matches!(result, EnforcementDecision::RequireApproval { .. }),
        "RequireApproval (strictness 4) > Delay (strictness 3)"
    );
}

/// max_strict: all pairs — verify transitivity of strictness ordering.
#[test]
fn edge_max_strict_strictness_ordering_complete() {
    let decisions = [
        EnforcementDecision::Allow,
        EnforcementDecision::AuditOnly {
            alert_level: AlertLevel::Info,
        },
        EnforcementDecision::Delay { milliseconds: 300 },
        EnforcementDecision::RequireApproval {
            urgency: ApprovalUrgency::Standard,
        },
        EnforcementDecision::Deny {
            reason: "blocked".to_string(),
        },
    ];

    // Verify each decision beats all less-strict ones
    for i in 0..decisions.len() {
        for j in 0..i {
            let result = max_strict(decisions[j].clone(), decisions[i].clone());
            assert!(
                result.strictness() == decisions[i].strictness(),
                "max_strict(strictness={}, strictness={}) should be strictness={}, got {}",
                decisions[j].strictness(),
                decisions[i].strictness(),
                decisions[i].strictness(),
                result.strictness()
            );
        }
    }
}

// edge_empty_policy_directory and edge_nonexistent_policy_directory
// removed — ABAC system deleted.

// ═══════════════════════════════════════════════════════════════════
// 4. EVENT STATUS EDGE CASES
// ═══════════════════════════════════════════════════════════════════

/// Concurrent status updates to the same event_id — no crash (last-write-wins).
#[tokio::test]
async fn edge_concurrent_status_update_no_crash() {
    let dir = tempfile::tempdir().expect("temp directory creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger initialization must succeed"),
    );

    // Write the same event_id from 10 concurrent tasks
    let mut handles = Vec::new();
    for i in 0..10 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = GVMEvent {
                event_id: "shared-event-001".to_string(),
                trace_id: "trace-concurrent".to_string(),
                parent_event_id: None,
                agent_id: format!("agent-{}", i),
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
                status: if i < 5 {
                    EventStatus::Confirmed
                } else {
                    EventStatus::Failed {
                        reason: "timeout".to_string(),
                    }
                },
                payload: PayloadDescriptor::default(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: false, config_integrity_ref: None,
            };
            ledger
                .append_durable(&event)
                .await
                .expect("concurrent WAL append must succeed");
        }));
    }

    for h in handles {
        h.await.expect("spawned task must complete without panic");
    }

    // WAL should have 10 event entries (exclude MerkleBatchRecord lines)
    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after writes");
    let event_count = content
        .lines()
        .filter(|line| !line.contains("\"merkle_root\""))
        .count();
    assert_eq!(
        event_count, 10,
        "WAL should contain 10 event entries (one per concurrent write)"
    );
}

/// WAL recovery with only Confirmed events — no events should be expired.
#[tokio::test]
async fn edge_recovery_no_pending_events() {
    let dir = tempfile::tempdir().expect("temp directory creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Pre-write a WAL with only Confirmed events
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&wal_path).expect("WAL file creation must succeed");
        for i in 0..5 {
            let event = serde_json::json!({
                "event_id": format!("evt-{}", i),
                "trace_id": "trace-ok",
                "parent_event_id": null,
                "agent_id": "agent",
                "tenant_id": null,
                "session_id": "session",
                "timestamp": "2026-01-01T00:00:00Z",
                "operation": "gvm.storage.read",
                "resource": { "service": "", "identifier": null, "tier": "External", "sensitivity": "Medium" },
                "context": {},
                "transport": null,
                "decision": "Allow",
                "decision_source": "test",
                "matched_rule_id": null,
                "enforcement_point": "test",
                "status": "Confirmed",
                "payload": { "content_hash": "", "size_bytes": 0, "flagged_patterns": [] },
                "nats_sequence": null
            });
            writeln!(
                file,
                "{}",
                serde_json::to_string(&event).expect("event JSON serialization must succeed")
            )
            .expect("writing event to WAL file must succeed");
        }
    }

    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger must initialize from pre-written WAL");
    let report = ledger
        .recover_from_wal()
        .await
        .expect("WAL recovery must succeed with confirmed-only events");

    assert_eq!(report.pending_found, 0, "No Pending events should be found");
    assert_eq!(report.expired_marked, 0, "No events should be expired");
}

// ═══════════════════════════════════════════════════════════════════
// 5. REGISTRY EDGE CASES
// ═══════════════════════════════════════════════════════════════════

// Operation registry tests removed — registry was removed in gvm.toml unification.
// SRR rules handle all governance policy; operations are no longer a separate registry.
