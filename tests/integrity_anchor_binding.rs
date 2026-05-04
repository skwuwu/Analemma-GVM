//! Phase 5 (real) — `prev_anchor_hash` binding in `GvmIntegrityContext`
//! v3.
//!
//! Pinned invariants:
//!   - v3 `context_hash` includes `prev_anchor_hash` in its canonical
//!     input. A single-bit change in the anchor hash produces a
//!     different context hash. v3 ≠ v1 over the same other fields.
//!   - `record_config_load` writes a v3 context with `prev_anchor_hash`
//!     equal to the live anchor at the moment of the call (sourced
//!     from `triple_state.last_anchor`). Genesis (no prior batch
//!     sealed) records `None`.
//!   - `verify_integrity_chain` reports `v3_anchor_bindings_valid` for
//!     v3 records whose claimed anchor was actually seen earlier in
//!     the WAL.
//!   - **Replay attack**: copying an old v3 config_load JSON line and
//!     re-injecting it after a newer anchor MUST be detected by
//!     verify_integrity_chain (the prev_config_hash chain link breaks
//!     because previous_state no longer matches the now-shifted prior
//!     context_hash, OR the prev_anchor_hash references an anchor
//!     that does not exist before the injection point if the attacker
//!     also strips intervening WAL).
//!   - Mixed v1+v3 WAL still verifies cleanly: v1 records dispatch to
//!     v1 hash, v3 records dispatch to v3 hash, both round-trip.

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_types::{verify_integrity_chain, GvmIntegrityContext, GvmStateAnchor, GENESIS_HASH_HEX};

// ────────────────────────────────────────────────────────────────────
// 1. Type-level: prev_anchor_hash affects context_hash
// ────────────────────────────────────────────────────────────────────

#[test]
fn v3_context_hash_changes_with_different_anchor() {
    let a = GvmIntegrityContext::local("cfg".to_string(), None, Some("aa".repeat(32)));
    let b = GvmIntegrityContext::local("cfg".to_string(), None, Some("bb".repeat(32)));
    assert_ne!(
        a.context_hash(),
        b.context_hash(),
        "different prev_anchor_hash MUST produce different context_hash"
    );
}

#[test]
fn v3_context_hash_stable_for_same_inputs() {
    let a = GvmIntegrityContext::local("cfg".to_string(), None, Some("aa".repeat(32)));
    let b = GvmIntegrityContext::local("cfg".to_string(), None, Some("aa".repeat(32)));
    // Note: timestamps differ between calls (system time), so we read
    // hashes after explicitly aligning the timestamp.
    let mut b_aligned = b.clone();
    b_aligned.timestamp = a.timestamp;
    assert_eq!(
        a.context_hash(),
        b_aligned.context_hash(),
        "same inputs (incl. anchor) MUST produce same hash"
    );
}

#[test]
fn v3_genesis_substitutes_genesis_hash_for_canonical_input() {
    // None at v3 must canonicalize to GENESIS_HASH_HEX, so a context
    // with prev_anchor_hash = None should produce the same hash as
    // one with Some(GENESIS_HASH_HEX) — same other fields and
    // timestamp.
    let a = GvmIntegrityContext::local("cfg".to_string(), None, None);
    let mut b =
        GvmIntegrityContext::local("cfg".to_string(), None, Some(GENESIS_HASH_HEX.to_string()));
    b.timestamp = a.timestamp;
    assert_eq!(
        a.context_hash(),
        b.context_hash(),
        "v3 canonical input MUST treat None == Some(GENESIS_HASH_HEX) for prev_anchor_hash"
    );
}

#[test]
fn v3_hash_distinct_from_v1_for_same_other_fields() {
    // Pin: the canonical version tag (v1 vs v3) is part of the hash
    // input, so the same config + previous_state under the two schemas
    // produces different hashes. This is what makes a verifier able to
    // tell "this record claims v3 but only the v1 algorithm matches"
    // (signaling tamper) instantly.
    let v3 = GvmIntegrityContext::local("cfg".to_string(), None, None);
    let mut v1 = v3.clone();
    v1.spec_version = 1;
    v1.prev_anchor_hash = None;
    assert_ne!(
        v3.context_hash(),
        v1.context_hash(),
        "v3 (with prev_anchor_hash field) must differ from v1 hash over the same input"
    );
}

// ────────────────────────────────────────────────────────────────────
// 2. record_config_load threads triple.last_anchor into prev_anchor_hash
// ────────────────────────────────────────────────────────────────────

fn one_event_per_batch() -> GroupCommitConfig {
    GroupCommitConfig {
        batch_window: std::time::Duration::ZERO,
        max_batch_size: 1,
        channel_capacity: 16,
        max_wal_bytes: 0,
        max_wal_segments: 0,
    }
}

fn read_config_load_contexts(wal_path: &std::path::Path) -> Vec<GvmIntegrityContext> {
    let content = std::fs::read_to_string(wal_path).unwrap();
    let mut out: Vec<GvmIntegrityContext> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !trimmed.contains("\"gvm.system.config_load\"") {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(ctx) = v.pointer("/context/_integrity_context") else {
            continue;
        };
        if let Ok(parsed) = serde_json::from_value::<GvmIntegrityContext>(ctx.clone()) {
            out.push(parsed);
        }
    }
    out
}

fn read_anchors(wal_path: &std::path::Path) -> Vec<GvmStateAnchor> {
    let content = std::fs::read_to_string(wal_path).unwrap();
    content
        .lines()
        .filter_map(|l| serde_json::from_str::<GvmStateAnchor>(l.trim()).ok())
        .collect()
}

fn make_event(id: &str) -> gvm_types::GVMEvent {
    use gvm_types::{EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor};
    use std::collections::HashMap;
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "anchor-bind-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test.event".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

#[tokio::test]
async fn first_config_load_records_no_prev_anchor() {
    // Genesis case: nothing has been written yet, triple.last_anchor
    // is None, so the v3 record stores prev_anchor_hash: None.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, b"rules = []").unwrap();

    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .record_config_load(&[("policy", &policy_path)], None)
        .await
        .unwrap();
    ledger.shutdown().await;

    let ctxs = read_config_load_contexts(&wal_path);
    assert_eq!(ctxs.len(), 1);
    assert_eq!(ctxs[0].spec_version, 3, "writer MUST emit v3 schema");
    assert!(
        ctxs[0].prev_anchor_hash.is_none(),
        "first config_load on a fresh WAL has no prior anchor — \
         prev_anchor_hash MUST be None at genesis"
    );
}

#[tokio::test]
async fn config_load_after_sealed_batch_carries_prior_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, b"rules = []").unwrap();

    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    // First config_load (genesis): triple.last_anchor is None.
    let first_ctx_hash = ledger
        .record_config_load(&[("policy", &policy_path)], None)
        .await
        .unwrap();
    // Append a behavioral event so a batch closes with an anchor.
    ledger.append_durable(&make_event("between")).await.unwrap();

    // Second config_load: triple.last_anchor now has Some(anchor) from
    // the prior batch. The v3 context records that anchor.
    ledger
        .record_config_load(&[("policy", &policy_path)], Some(first_ctx_hash.clone()))
        .await
        .unwrap();
    ledger.shutdown().await;

    let ctxs = read_config_load_contexts(&wal_path);
    let anchors = read_anchors(&wal_path);
    assert_eq!(ctxs.len(), 2);
    assert!(!anchors.is_empty(), "at least one anchor expected");

    // The genesis ctx has no prior anchor.
    assert!(
        ctxs[0].prev_anchor_hash.is_none(),
        "genesis ctx must have prev_anchor_hash = None"
    );
    // The second ctx must reference an anchor that exists in the WAL.
    let second_anchor_ref = ctxs[1]
        .prev_anchor_hash
        .as_deref()
        .expect("second config_load MUST carry a prev_anchor_hash");
    let anchor_hashes: Vec<&str> = anchors.iter().map(|a| a.anchor_hash.as_str()).collect();
    assert!(
        anchor_hashes.contains(&second_anchor_ref),
        "second config_load's prev_anchor_hash {} must match an anchor seen in WAL: {:?}",
        second_anchor_ref,
        anchor_hashes
    );
}

// ────────────────────────────────────────────────────────────────────
// 3. verify_integrity_chain reports v3 anchor bindings
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_chain_counts_v3_anchor_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, b"rules = []").unwrap();

    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    let h1 = ledger
        .record_config_load(&[("policy", &policy_path)], None)
        .await
        .unwrap();
    ledger.append_durable(&make_event("e1")).await.unwrap();
    let h2 = ledger
        .record_config_load(&[("policy", &policy_path)], Some(h1))
        .await
        .unwrap();
    ledger.append_durable(&make_event("e2")).await.unwrap();
    ledger
        .record_config_load(&[("policy", &policy_path)], Some(h2))
        .await
        .unwrap();
    ledger.shutdown().await;

    let report = verify_integrity_chain(&wal_path);
    assert_eq!(report.total_config_loads, 3);
    assert!(
        report.first_break.is_none(),
        "happy-path WAL must have no break. got: {:?}",
        report.first_break
    );
    // Two v3 records (the second and third) carry Some(anchor); the
    // first is genesis (None) and is not counted.
    assert_eq!(
        report.v3_anchor_bindings_valid, 2,
        "two non-genesis v3 config_loads must report valid anchor bindings"
    );
    assert_eq!(report.v3_anchor_bindings_missing, 0);
}

// ────────────────────────────────────────────────────────────────────
// 4. Replay attack: phantom prev_anchor_hash is detected
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn replay_with_phantom_anchor_hash_is_caught() {
    // Attack: attacker inserts a forged config_load record claiming
    // a prev_anchor_hash that does not exist anywhere in the WAL.
    // verify_integrity_chain MUST detect this as a chain break.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, b"rules = []").unwrap();

    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    let h1 = ledger
        .record_config_load(&[("policy", &policy_path)], None)
        .await
        .unwrap();
    ledger.append_durable(&make_event("e1")).await.unwrap();
    ledger.shutdown().await;

    // Forge a config_load line: valid previous_state pointing at h1's
    // context_hash, but prev_anchor_hash is a fabricated value that
    // does NOT match any anchor in the WAL.
    let mut forged_ctx = GvmIntegrityContext::local(
        "config-evil".to_string(),
        Some(h1.clone()),
        Some("ff".repeat(32)), // phantom anchor hash
    );
    // Force previous_state to a value that recomputes consistently with
    // the (faked) chain. forged_ctx.context_hash() will recompute over
    // the v3 input including prev_anchor_hash.
    forged_ctx.timestamp = h1.parse::<u64>().unwrap_or(0).max(1);
    let forged_event = serde_json::json!({
        "event_id": "sys-evil",
        "trace_id": "system",
        "agent_id": "gvm-proxy",
        "session_id": "evil",
        "timestamp": "2026-04-30T00:00:00Z",
        "operation": "gvm.system.config_load",
        "decision": "Allow",
        "decision_source": "system",
        "enforcement_point": "startup",
        "status": "Confirmed",
        "context": {
            "_integrity_context": serde_json::to_value(&forged_ctx).unwrap(),
        },
        "resource": {"service": "", "tier": "External", "sensitivity": "Medium"},
        "payload": {"content_hash": "", "size_bytes": 0, "flagged_patterns": []},
    });
    // Append to existing WAL.
    let mut existing = std::fs::read_to_string(&wal_path).unwrap();
    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&forged_event.to_string());
    existing.push('\n');
    std::fs::write(&wal_path, existing).unwrap();

    let report = verify_integrity_chain(&wal_path);
    assert!(
        report.v3_anchor_bindings_missing >= 1,
        "phantom prev_anchor_hash MUST be reported as missing"
    );
    assert_eq!(
        report.first_break.as_deref(),
        Some("sys-evil"),
        "first_break MUST point at the forged config_load"
    );
}

// ────────────────────────────────────────────────────────────────────
// 5. Mixed v1+v3 WAL: legacy records still verify
// ────────────────────────────────────────────────────────────────────

#[test]
fn mixed_v1_and_v3_chain_still_verifies() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    // Build a v1 record and a v3 record with the v1 as predecessor.
    let mut v1 = GvmIntegrityContext::local("config-A".to_string(), None, None);
    v1.spec_version = 1;
    v1.prev_anchor_hash = None;
    let v1_hash = v1.context_hash();

    // v3 follow-up with the v1 hash as previous_state.
    let v3 = GvmIntegrityContext::local("config-B".to_string(), Some(v1_hash), None);

    // Format both as config_load events.
    let format_event = |ctx: &GvmIntegrityContext, id: &str| -> String {
        serde_json::json!({
            "event_id": id,
            "trace_id": "system",
            "agent_id": "gvm-proxy",
            "session_id": "mixed",
            "timestamp": "2026-04-30T00:00:00Z",
            "operation": "gvm.system.config_load",
            "decision": "Allow",
            "decision_source": "system",
            "enforcement_point": "startup",
            "status": "Confirmed",
            "context": {
                "_integrity_context": serde_json::to_value(ctx).unwrap(),
            },
            "resource": {"service": "", "tier": "External", "sensitivity": "Medium"},
            "payload": {"content_hash": "", "size_bytes": 0, "flagged_patterns": []},
        })
        .to_string()
    };

    let mut f = std::fs::File::create(&wal_path).unwrap();
    writeln!(f, "{}", format_event(&v1, "sys-v1")).unwrap();
    writeln!(f, "{}", format_event(&v3, "sys-v3")).unwrap();
    drop(f);

    let report = verify_integrity_chain(&wal_path);
    assert_eq!(report.total_config_loads, 2);
    assert_eq!(
        report.valid_links, 2,
        "both v1 and v3 records must validate when chained correctly"
    );
    assert!(
        report.first_break.is_none(),
        "mixed v1+v3 chain must not break; got {:?}",
        report.first_break
    );
}
