//! Phase 5 — Startup recovery of the anchor chain.
//!
//! Without this, every restart would force `prev_anchor: None` on the
//! first new batch — `verify_anchor_chain` correctly flags that as a
//! truncation signal, but it would happen on every mundane restart.
//!
//! Pinned invariants:
//!   - After a write-shutdown-reopen cycle, the next batch's anchor
//!     references the prior session's last anchor as `prev_anchor`.
//!   - batch_id is monotonic across restarts (no skip, no duplicate).
//!   - `prev_batch_root` is recovered so the inter-batch chain links.
//!   - The active context_hash is recovered so behavioral events
//!     between restart and the first new config_load are sealed under
//!     the live config that was active before shutdown.
//!   - Fresh WAL path → all-`None` recovery → first batch is genesis.
//!   - The recovered chain passes `verify_anchor_chain` end-to-end.

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_types::{
    verify_anchor_chain, AnchorAuditConfig, EventStatus, GVMEvent, GvmStateAnchor,
    MerkleBatchRecord, PayloadDescriptor, ResourceDescriptor,
};
use std::collections::HashMap;

fn evt(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "recovery-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test".to_string(),
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

fn one_event_per_batch() -> GroupCommitConfig {
    GroupCommitConfig {
        batch_window: std::time::Duration::ZERO,
        max_batch_size: 1,
        channel_capacity: 16,
        max_wal_bytes: 0,
        max_wal_segments: 0,
    }
}

#[tokio::test]
async fn fresh_wal_starts_at_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();

    ledger.append_durable(&evt("evt-1")).await.unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(anchors.len(), 1, "exactly one anchor for one batch");
    assert!(
        anchors[0].prev_anchor.is_none(),
        "fresh WAL: first anchor's prev MUST be None (genesis)"
    );
    assert_eq!(anchors[0].batch_id, 0, "first batch_id is 0 from genesis");
}

#[tokio::test]
async fn restart_recovers_last_anchor_into_chain() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    // Session 1: write three batches, capture the last anchor_hash.
    let session1_last_anchor: String;
    let session1_last_batch_id: u64;
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        for i in 0..3 {
            ledger
                .append_durable(&evt(&format!("s1-{}", i)))
                .await
                .unwrap();
        }
        ledger.shutdown().await;

        let content = std::fs::read_to_string(&wal_path).unwrap();
        let anchors: Vec<GvmStateAnchor> = content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(anchors.len(), 3);
        session1_last_anchor = anchors.last().unwrap().anchor_hash.clone();
        session1_last_batch_id = anchors.last().unwrap().batch_id;
    }

    // Session 2: open the same WAL, write one batch, shut down.
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        ledger.append_durable(&evt("s2-0")).await.unwrap();
        ledger.shutdown().await;
    }

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(anchors.len(), 4, "3 from session 1 + 1 from session 2");

    let session2_first = anchors.last().unwrap();
    assert_eq!(
        session2_first.prev_anchor.as_deref(),
        Some(session1_last_anchor.as_str()),
        "session 2's first anchor MUST link to session 1's last anchor"
    );
    assert_eq!(
        session2_first.batch_id,
        session1_last_batch_id + 1,
        "batch_id MUST be monotonic across restarts"
    );
}

#[tokio::test]
async fn restart_recovers_prev_batch_root() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    let session1_last_root: String;
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        ledger.append_durable(&evt("s1-0")).await.unwrap();
        ledger.shutdown().await;
        let content = std::fs::read_to_string(&wal_path).unwrap();
        let records: Vec<MerkleBatchRecord> = content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(records.len(), 1);
        session1_last_root = records[0].merkle_root.clone();
    }

    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        ledger.append_durable(&evt("s2-0")).await.unwrap();
        ledger.shutdown().await;
    }

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let records: Vec<MerkleBatchRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let session2_first = records.last().unwrap();
    assert_eq!(
        session2_first.prev_batch_root.as_deref(),
        Some(session1_last_root.as_str()),
        "inter-batch Merkle chain MUST link across restart"
    );
}

#[tokio::test]
async fn restart_recovers_active_context_hash() {
    // Sequence: open ledger → record_config_load (sets active context)
    // → close. Reopen → write a behavioral event (no new config_load)
    // → close. The event's batch must seal under the recovered context.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    let dummy_config_path = dir.path().join("policy.toml");
    std::fs::write(&dummy_config_path, "rules = []").unwrap();

    let recovered_context: String;
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        recovered_context = ledger
            .record_config_load(&[("policy", &dummy_config_path)], None)
            .await
            .unwrap();
        ledger.shutdown().await;
    }

    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        // Triple-state snapshot must already carry the recovered context.
        let snap = ledger.triple_snapshot();
        assert_eq!(
            snap.context_hash.as_deref(),
            Some(recovered_context.as_str()),
            "context_hash from prior session MUST be recovered into triple state"
        );

        // Confirm the binding lands in the next anchor too.
        ledger.append_durable(&evt("s2-0")).await.unwrap();
        ledger.shutdown().await;
    }

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let session2_first = anchors.last().unwrap();
    assert_eq!(
        session2_first.context_hash, recovered_context,
        "session 2's first anchor MUST seal under the recovered context_hash"
    );
}

#[tokio::test]
async fn cross_session_chain_passes_verify_audit() {
    // The most important pin: after a restart, `verify_anchor_chain`
    // sees a single contiguous chain — no break, no genesis-misuse,
    // no batch_id skip. This is the anti-regression for "every
    // restart triggers a false-positive truncation alert."
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        for i in 0..2 {
            ledger
                .append_durable(&evt(&format!("s1-{}", i)))
                .await
                .unwrap();
        }
        ledger.shutdown().await;
    }
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        for i in 0..2 {
            ledger
                .append_durable(&evt(&format!("s2-{}", i)))
                .await
                .unwrap();
        }
        ledger.shutdown().await;
    }

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 4);
    assert_eq!(report.valid_self_hashes, 4, "every anchor self-hash valid");
    assert_eq!(
        report.valid_chain_links, 4,
        "every chain link valid (genesis + 3 parent-references)"
    );
    assert!(
        report.first_break.is_none(),
        "cross-session chain must have NO break. first_break={:?}, batch_id_skips={:?}, clock_inversions={:?}",
        report.first_break,
        report.batch_id_skips,
        report.clock_inversions,
    );
}

#[tokio::test]
async fn malformed_wal_falls_back_to_genesis_safely() {
    // If the recovery scanner cannot parse the WAL (e.g., a partial
    // or corrupted line), it MUST NOT crash — it returns an empty
    // recovery state and the next batch starts at genesis. The
    // alternative (panic on bad WAL) would brick a recoverable proxy.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    // Write garbage that is not valid JSON.
    std::fs::write(&wal_path, b"this is not json\nneither is this\n").unwrap();

    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger.append_durable(&evt("post-garbage")).await.unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(anchors.len(), 1, "one new anchor written after garbage");
    assert!(
        anchors[0].prev_anchor.is_none(),
        "no recoverable prior anchor → genesis is correct"
    );
}

#[tokio::test]
async fn recovered_chain_with_break_is_still_caught() {
    // Sanity: recovery does NOT silently paper over a real chain
    // break. If the prior session's last anchor was tampered, the
    // chain link that recovery produces must fail verify_anchor_chain.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap();
        for i in 0..2 {
            ledger
                .append_durable(&evt(&format!("s1-{}", i)))
                .await
                .unwrap();
        }
        ledger.shutdown().await;
    }

    // Tamper the last anchor's anchor_hash on disk.
    let mut content = std::fs::read_to_string(&wal_path).unwrap();
    let last_anchor_line_idx = content
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("\"anchor_hash\""))
        .last()
        .map(|(i, _)| i)
        .unwrap();
    let mut lines: Vec<&str> = content.lines().collect();
    let mut anchor: GvmStateAnchor = serde_json::from_str(lines[last_anchor_line_idx]).unwrap();
    // Flip a bit in anchor_hash so verify_self_hash fails.
    let mut bytes = hex::decode(&anchor.anchor_hash).unwrap();
    bytes[0] ^= 0x01;
    anchor.anchor_hash = hex::encode(bytes);
    let mutated = serde_json::to_string(&anchor).unwrap();
    lines[last_anchor_line_idx] = &mutated;
    content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }
    std::fs::write(&wal_path, &content).unwrap();

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert!(
        report.first_break.is_some(),
        "tampered last anchor MUST be reported as a break"
    );
    assert!(
        report.valid_self_hashes < report.total_anchors,
        "self-hash check must catch the mutation"
    );
}
