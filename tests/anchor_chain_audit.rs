//! Tests for `verify_anchor_chain` — the dedicated anchor-chain audit
//! that walks every `GvmStateAnchor` in WAL segments and reports four
//! invariants:
//!
//!   1. Self-hash consistency (anchor_hash recomputes from fields)
//!   2. Chain link (anchor[N].prev_anchor == anchor[N-1].anchor_hash)
//!   3. Monotonic batch_id (consecutive +1)
//!   4. Monotonic timestamp (within configurable skew tolerance)
//!
//! Genesis: (None, None) is accepted; (None, Some(_)) flags
//! truncation; (Some, None) after first anchor flags splice. See
//! §4.8 of GVM_CODE_STANDARDS.md.

use chrono::{TimeZone, Utc};
use gvm_proxy::ledger::Ledger;
use gvm_types::{
    verify_anchor_chain, AnchorAuditConfig, AnchorChainReport, BatchSealRecord, EventStatus,
    GVMEvent, GvmStateAnchor, PayloadDescriptor, ResourceDescriptor,
};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn evt(op: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-{}", op.replace(' ', "-")),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "anchor-chain-audit-test".to_string(),
        timestamp: Utc::now(),
        operation: op.to_string(),
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

fn write_anchors(dir: &std::path::Path, anchors: &[GvmStateAnchor]) -> std::path::PathBuf {
    let path = dir.join("wal.log");
    let mut f = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    for a in anchors {
        writeln!(f, "{}", serde_json::to_string(a).unwrap()).unwrap();
    }
    path
}

fn make_seal(
    seal_id: u64,
    sealed_at: chrono::DateTime<Utc>,
    prev_anchor: Option<String>,
) -> BatchSealRecord {
    BatchSealRecord {
        seal_id,
        sealed_at,
        context_hash: "c".repeat(64),
        checkpoint_root: None,
        prev_anchor,
    }
}

// ════════════════════════════════════════════════════════════════════
// Empty / single-anchor / properly-chained
// ════════════════════════════════════════════════════════════════════

#[test]
fn missing_file_returns_empty_report() {
    let report = verify_anchor_chain(
        std::path::Path::new("/nonexistent/wal.log"),
        &AnchorAuditConfig::default(),
    );
    assert_eq!(report.total_anchors, 0);
    assert!(report.first_break.is_none());
}

#[test]
fn single_genesis_anchor_passes() {
    let dir = tempfile::tempdir().unwrap();
    let seal = make_seal(0, Utc::now(), None);
    let anchor = GvmStateAnchor::seal(1, &seal, "r".repeat(64));
    let path = write_anchors(dir.path(), &[anchor]);

    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 1);
    assert_eq!(report.valid_self_hashes, 1);
    assert_eq!(report.valid_chain_links, 1);
    assert!(report.first_break.is_none());
}

#[test]
fn properly_chained_three_anchors_pass() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc.with_ymd_and_hms(2026, 5, 2, 10, 0, 0).unwrap();

    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    let s1 = make_seal(
        1,
        t0 + chrono::Duration::seconds(1),
        Some(a0.anchor_hash.clone()),
    );
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let s2 = make_seal(
        2,
        t0 + chrono::Duration::seconds(2),
        Some(a1.anchor_hash.clone()),
    );
    let a2 = GvmStateAnchor::seal(1, &s2, "r2".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1, a2]);

    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 3);
    assert_eq!(report.valid_self_hashes, 3);
    assert_eq!(report.valid_chain_links, 3);
    assert!(report.first_break.is_none());
    assert!(report.batch_id_skips.is_empty());
    assert!(report.clock_inversions.is_empty());
}

// ════════════════════════════════════════════════════════════════════
// Tamper detection
// ════════════════════════════════════════════════════════════════════

#[test]
fn tampered_anchor_hash_breaks_chain() {
    let dir = tempfile::tempdir().unwrap();
    let s = make_seal(0, Utc::now(), None);
    let mut a = GvmStateAnchor::seal(1, &s, "r".repeat(64));
    a.anchor_hash = "ff".repeat(32);
    let path = write_anchors(dir.path(), &[a]);

    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 1);
    assert_eq!(report.valid_self_hashes, 0);
    assert_eq!(
        report.first_break,
        Some(0),
        "tampered self-hash must break the chain at batch_id 0"
    );
}

#[test]
fn wrong_prev_anchor_breaks_chain() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc::now();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    let s1 = make_seal(1, t0 + chrono::Duration::seconds(1), Some("ff".repeat(32)));
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1]);
    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.first_break, Some(1));
    assert_eq!(
        report.valid_chain_links, 1,
        "only the genesis link is valid"
    );
}

// ════════════════════════════════════════════════════════════════════
// Batch_id monotonic / clock inversions / suspicious gaps
// ════════════════════════════════════════════════════════════════════

#[test]
fn batch_id_skip_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc::now();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    // Skip batch_id 1 — go straight to 2.
    let s2 = make_seal(
        2,
        t0 + chrono::Duration::seconds(1),
        Some(a0.anchor_hash.clone()),
    );
    let a2 = GvmStateAnchor::seal(1, &s2, "r2".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a2]);
    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.batch_id_skips, vec![(1, 2)]);
    assert_eq!(report.first_break, Some(2));
}

#[test]
fn clock_inversion_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc.with_ymd_and_hms(2026, 5, 2, 10, 0, 0).unwrap();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    // a1 has timestamp 60 seconds BEFORE a0 — inversion.
    let s1 = make_seal(
        1,
        t0 - chrono::Duration::seconds(60),
        Some(a0.anchor_hash.clone()),
    );
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1]);
    let report = verify_anchor_chain(
        &path,
        &AnchorAuditConfig {
            max_gap_secs: 3600,
            skew_tolerance_secs: 5,
        },
    );
    assert_eq!(report.clock_inversions, vec![(1, 0)]);
    assert_eq!(report.first_break, Some(1));
}

#[test]
fn clock_skew_within_tolerance_does_not_flag() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc.with_ymd_and_hms(2026, 5, 2, 10, 0, 0).unwrap();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    // a1 timestamp is 2 seconds BEFORE a0 — within 5s tolerance.
    let s1 = make_seal(
        1,
        t0 - chrono::Duration::seconds(2),
        Some(a0.anchor_hash.clone()),
    );
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1]);
    let report = verify_anchor_chain(
        &path,
        &AnchorAuditConfig {
            max_gap_secs: 3600,
            skew_tolerance_secs: 5,
        },
    );
    assert!(
        report.clock_inversions.is_empty(),
        "skew within tolerance must not flag"
    );
    assert!(report.first_break.is_none());
}

#[test]
fn suspicious_gap_recorded_but_not_break() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc.with_ymd_and_hms(2026, 5, 2, 10, 0, 0).unwrap();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    // a1 happens 2 hours later — exceeds default 1-hour max_gap_secs.
    let s1 = make_seal(
        1,
        t0 + chrono::Duration::hours(2),
        Some(a0.anchor_hash.clone()),
    );
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1]);
    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(
        report.suspicious_gaps,
        vec![(1, 7200)],
        "2-hour gap must be reported"
    );
    // Suspicious gap is informational — chain still valid.
    assert!(
        report.first_break.is_none(),
        "suspicious gap alone is not a chain break"
    );
}

// ════════════════════════════════════════════════════════════════════
// Strip-evasion / splice
// ════════════════════════════════════════════════════════════════════

#[test]
fn first_anchor_with_some_prev_is_truncation_signal() {
    let dir = tempfile::tempdir().unwrap();
    // Single anchor, but it claims a prior — truncation evidence.
    let s = make_seal(7, Utc::now(), Some("ff".repeat(32)));
    let a = GvmStateAnchor::seal(1, &s, "r".repeat(64));
    let path = write_anchors(dir.path(), &[a]);

    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 1);
    assert_eq!(
        report.first_break,
        Some(7),
        "(None, Some(_)) form must flag as truncation"
    );
}

#[test]
fn genesis_after_first_anchor_breaks_chain() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Utc::now();
    let s0 = make_seal(0, t0, None);
    let a0 = GvmStateAnchor::seal(1, &s0, "r0".repeat(32));

    // a1 claims it's also genesis (prev=None) — splice attack.
    let s1 = make_seal(1, t0 + chrono::Duration::seconds(1), None);
    let a1 = GvmStateAnchor::seal(1, &s1, "r1".repeat(32));

    let path = write_anchors(dir.path(), &[a0, a1]);
    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(
        report.first_break,
        Some(1),
        "second anchor claiming genesis must break"
    );
}

#[test]
fn signed_anchor_count_is_informational() {
    use gvm_types::AnchorSignature;

    let dir = tempfile::tempdir().unwrap();
    let s = make_seal(0, Utc::now(), None);
    let mut a = GvmStateAnchor::seal(1, &s, "r".repeat(64));
    a.signature = Some(AnchorSignature::SelfSigned {
        key_id: "test-key".to_string(),
        signature: vec![0u8; 64],
    });
    let path = write_anchors(dir.path(), &[a]);

    let report = verify_anchor_chain(&path, &AnchorAuditConfig::default());
    assert_eq!(report.signed_anchor_count, 1);
    // verify_anchor_chain does NOT verify the signature — Phase 6
    // handles vendor-specific verification. Audit still passes
    // structurally.
    assert!(report.first_break.is_none());
}

// ════════════════════════════════════════════════════════════════════
// End-to-end: real Ledger writes + verify_anchor_chain
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn real_ledger_anchors_pass_audit() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    // Three batches separated so each becomes its own anchor.
    ledger.append_durable(&evt("op-1")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    ledger.append_durable(&evt("op-2")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    ledger.append_durable(&evt("op-3")).await.unwrap();
    ledger.shutdown().await;

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert!(report.total_anchors >= 2);
    assert_eq!(report.valid_self_hashes, report.total_anchors);
    assert_eq!(report.valid_chain_links, report.total_anchors);
    assert!(
        report.first_break.is_none(),
        "real ledger output must audit clean"
    );
    assert!(report.batch_id_skips.is_empty());
    assert!(report.clock_inversions.is_empty());
}

#[tokio::test]
async fn tampered_real_ledger_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();
    ledger.append_durable(&evt("op-1")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    ledger.append_durable(&evt("op-2")).await.unwrap();
    ledger.shutdown().await;

    // Read WAL, tamper one anchor's anchor_hash, write back.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let mut new_lines: Vec<String> = Vec::new();
    let mut tampered = false;
    for line in content.lines() {
        if !tampered && line.contains("\"anchor_hash\":") {
            let r: AnchorChainReport;
            let mut a: GvmStateAnchor = serde_json::from_str(line).unwrap();
            a.anchor_hash = "ff".repeat(32);
            new_lines.push(serde_json::to_string(&a).unwrap());
            tampered = true;
            let _ = r;
            continue;
        }
        new_lines.push(line.to_string());
    }
    std::fs::write(&wal_path, new_lines.join("\n") + "\n").unwrap();

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert!(
        report.first_break.is_some(),
        "tampered anchor must produce first_break"
    );
    assert!(
        report.valid_self_hashes < report.total_anchors,
        "tamper must reduce valid_self_hashes count"
    );
}
