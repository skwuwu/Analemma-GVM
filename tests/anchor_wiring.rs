//! Phase 2 wiring tests — end-to-end batch flush emits seal +
//! batch_record + anchor as three WAL lines, with leaves_blob
//! containing event_hashes plus seal_hash as the last leaf.
//!
//! Pins:
//!   - every batch produces exactly one anchor (§4.6)
//!   - anchor_hash is self-consistent (verify_self_hash returns true)
//!   - prev_anchor chain links: batch N+1's anchor.prev_anchor ==
//!     batch N's anchor_hash
//!   - leaves_blob length = (event_count + 1) * 32 (events + seal)
//!   - seal_hash is the LAST leaf (seal_position == event_count)
//!   - seal.context_hash matches whatever update_context_hash last
//!     published BEFORE the batch sealed
//!   - seal.prev_anchor == previous batch's anchor_hash
//!   - WAL line ordering is events..., seal, batch_record, anchor
//!     (within a batch group)

use chrono::Utc;
use gvm_proxy::ledger::Ledger;
use gvm_types::{
    BatchSealRecord, EventStatus, GVMEvent, GvmStateAnchor, LeavesFormat, MerkleBatchRecord,
    PayloadDescriptor, ResourceDescriptor, GENESIS_HASH_HEX,
};
use std::collections::HashMap;

fn evt(label: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-{}", label),
        trace_id: format!("trace-{}", label),
        parent_event_id: None,
        agent_id: "test-agent".to_string(),
        tenant_id: None,
        session_id: "anchor-wiring".to_string(),
        timestamp: Utc::now(),
        operation: "gvm.test.anchor_wiring".to_string(),
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

/// Read a WAL file and bucket each line into events / seal / batch / anchor.
fn parse_wal(path: &std::path::Path) -> ParsedWal {
    let content = std::fs::read_to_string(path).expect("WAL must read");
    let mut events: Vec<GVMEvent> = Vec::new();
    let mut seals: Vec<BatchSealRecord> = Vec::new();
    let mut batch_records: Vec<MerkleBatchRecord> = Vec::new();
    let mut anchors: Vec<GvmStateAnchor> = Vec::new();
    let mut order: Vec<LineKind> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Disambiguate by trying parsers in a deterministic order.
        // Anchor has unique `anchor_hash`; batch record has `merkle_root`;
        // seal has `seal_id` + `sealed_at` + `context_hash`; event has
        // `event_id`. We probe by serde_json::Value to check fields.
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("anchor_hash").is_some() {
            anchors.push(serde_json::from_value(v).expect("anchor parse"));
            order.push(LineKind::Anchor);
        } else if v.get("merkle_root").is_some() {
            batch_records.push(serde_json::from_value(v).expect("batch_record parse"));
            order.push(LineKind::BatchRecord);
        } else if v.get("seal_id").is_some() && v.get("sealed_at").is_some() {
            seals.push(serde_json::from_value(v).expect("seal parse"));
            order.push(LineKind::Seal);
        } else if v.get("event_id").is_some() {
            events.push(serde_json::from_value(v).expect("event parse"));
            order.push(LineKind::Event);
        }
    }

    ParsedWal {
        events,
        seals,
        batch_records,
        anchors,
        order,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LineKind {
    Event,
    Seal,
    BatchRecord,
    Anchor,
}

struct ParsedWal {
    events: Vec<GVMEvent>,
    seals: Vec<BatchSealRecord>,
    batch_records: Vec<MerkleBatchRecord>,
    anchors: Vec<GvmStateAnchor>,
    order: Vec<LineKind>,
}

// ────────────────────────────────────────────────────────────────────
// 1. Single batch: every line type appears exactly once
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn single_batch_writes_event_seal_batchrecord_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    let mut ledger = Ledger::new(&wal_path, "", "").await.expect("ledger init");
    ledger
        .append_durable(&evt("a"))
        .await
        .expect("append must succeed");
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    assert_eq!(parsed.events.len(), 1, "exactly 1 event line");
    assert_eq!(parsed.seals.len(), 1, "exactly 1 seal line");
    assert_eq!(parsed.batch_records.len(), 1, "exactly 1 batch_record line");
    assert_eq!(parsed.anchors.len(), 1, "exactly 1 anchor line");

    // Order within batch: event, seal, batch_record, anchor.
    assert_eq!(
        parsed.order,
        vec![
            LineKind::Event,
            LineKind::Seal,
            LineKind::BatchRecord,
            LineKind::Anchor,
        ],
        "WAL line order within a batch must be: events, seal, batch_record, anchor"
    );
}

// ────────────────────────────────────────────────────────────────────
// 2. Anchor self-consistency
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anchor_self_hash_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();
    ledger.append_durable(&evt("v")).await.unwrap();
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    let anchor = &parsed.anchors[0];
    assert!(
        anchor.verify_self_hash(),
        "anchor_hash must be self-consistent for a freshly-written batch"
    );
}

// ────────────────────────────────────────────────────────────────────
// 3. leaves_blob length and seal_position
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn leaves_blob_includes_seal_as_last_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    // Three events. Bind the events to locals so they outlive the
    // join! futures' borrows.
    let e1 = evt("1");
    let e2 = evt("2");
    let e3 = evt("3");
    let _ = tokio::join!(
        ledger.append_durable(&e1),
        ledger.append_durable(&e2),
        ledger.append_durable(&e3),
    );
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    // We may have multiple batches depending on scheduling; verify
    // SOME batch contains all expected invariants by checking each.
    let total_events: usize = parsed.batch_records.iter().map(|b| b.event_count).sum();
    assert_eq!(total_events, 3, "all 3 events must be batched");

    for (i, br) in parsed.batch_records.iter().enumerate() {
        // Phase 2 invariant: leaves_blob length == (event_count + 1) * 32
        assert!(
            br.leaves_format == Some(LeavesFormat::Sha256Concat),
            "batch {} format must be Sha256Concat",
            i
        );
        let expected_len = (br.event_count + 1) * 32;
        assert_eq!(
            br.leaves_blob.len(),
            expected_len,
            "batch {}: leaves_blob length {} != expected {} \
             (event_count {} + 1 seal × 32)",
            i,
            br.leaves_blob.len(),
            expected_len,
            br.event_count,
        );
        assert_eq!(
            br.seal_position,
            Some(br.event_count),
            "seal_position must equal event_count (seal is the last leaf)"
        );
        br.validate_leaves_invariant().expect("invariant must hold");
    }
}

// ────────────────────────────────────────────────────────────────────
// 4. Seal hash is the last leaf in leaves_blob
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn seal_hash_matches_last_leaf_in_batch_record() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();
    ledger.append_durable(&evt("seal-leaf")).await.unwrap();
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    assert_eq!(parsed.seals.len(), parsed.batch_records.len());
    for (seal, br) in parsed.seals.iter().zip(parsed.batch_records.iter()) {
        let last_leaf = br.seal_leaf().expect("seal leaf must be present");
        assert_eq!(
            last_leaf,
            &seal.seal_hash()[..],
            "seal record's seal_hash must equal the last 32 bytes of leaves_blob \
             — tamper of seal must propagate to merkle_root"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// 5. prev_anchor chain across batches
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anchor_chain_links_consecutive_batches() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    // Force two distinct batches by awaiting between appends so each
    // append flushes its own batch (batch_window expires).
    ledger.append_durable(&evt("first")).await.unwrap();
    // Sleep just longer than the batch window to ensure separation.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    ledger.append_durable(&evt("second")).await.unwrap();
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    assert!(
        parsed.anchors.len() >= 2,
        "expected at least two batches; got {} anchors",
        parsed.anchors.len()
    );

    // First anchor: prev_anchor MUST be None (genesis).
    assert!(
        parsed.anchors[0].prev_anchor.is_none(),
        "first anchor in a fresh WAL must have prev_anchor = None (genesis); \
         got {:?}",
        parsed.anchors[0].prev_anchor
    );

    // Each subsequent anchor's prev_anchor MUST equal the prior anchor's anchor_hash.
    for i in 1..parsed.anchors.len() {
        let prev = &parsed.anchors[i - 1];
        let curr = &parsed.anchors[i];
        assert_eq!(
            curr.prev_anchor.as_deref(),
            Some(prev.anchor_hash.as_str()),
            "anchor[{}].prev_anchor must equal anchor[{}].anchor_hash",
            i,
            i - 1
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// 6. context_hash flows from update_context_hash → next batch's seal
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn context_hash_published_before_batch_appears_in_seal() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    // Genesis: first event flushes with context_hash = GENESIS_HASH_HEX
    // (no update_context_hash call yet, snapshot reads None →
    // canonical fallback to GENESIS_HASH_HEX in seal).
    ledger.append_durable(&evt("g0")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Publish a new context_hash, then append another event.
    let new_ctx = "abcd".repeat(16); // 64-char hex stand-in
    ledger.update_context_hash(new_ctx.clone());
    ledger.append_durable(&evt("g1")).await.unwrap();
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    assert!(
        parsed.seals.len() >= 2,
        "expected ≥2 seals across two batches; got {}",
        parsed.seals.len()
    );

    // First seal: context_hash must be GENESIS_HASH_HEX (no prior update).
    assert_eq!(
        parsed.seals[0].context_hash, GENESIS_HASH_HEX,
        "first seal in a fresh WAL must canonicalize None → GENESIS_HASH_HEX"
    );

    // Second seal: context_hash must equal the value we published.
    assert_eq!(
        parsed.seals[1].context_hash, new_ctx,
        "second seal's context_hash must match the value published \
         via update_context_hash before the second batch flushed"
    );
}

// ────────────────────────────────────────────────────────────────────
// 7. anchor.context_hash equals seal.context_hash
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anchor_inherits_context_from_seal() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();
    ledger.update_context_hash("ff".repeat(32));
    ledger.append_durable(&evt("inh")).await.unwrap();
    ledger.shutdown().await;

    let parsed = parse_wal(&wal_path);
    for (seal, anchor) in parsed.seals.iter().zip(parsed.anchors.iter()) {
        assert_eq!(
            anchor.context_hash, seal.context_hash,
            "anchor.context_hash MUST be inherited from the seal it commits"
        );
        assert_eq!(anchor.batch_id, seal.seal_id);
        assert_eq!(anchor.timestamp, seal.sealed_at);
        assert_eq!(anchor.checkpoint_root, seal.checkpoint_root);
        assert_eq!(anchor.prev_anchor, seal.prev_anchor);
    }
}

// ────────────────────────────────────────────────────────────────────
// 8. triple_snapshot exposes the live state
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn triple_snapshot_reflects_updates_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    // Initial: all None.
    let snap0 = ledger.triple_snapshot();
    assert!(snap0.context_hash.is_none());
    assert!(snap0.checkpoint_root.is_none());
    assert!(snap0.last_anchor.is_none());

    // Update context.
    ledger.update_context_hash("aa".repeat(32));
    let snap1 = ledger.triple_snapshot();
    assert_eq!(snap1.context_hash.as_deref(), Some("a".repeat(64).as_str()));

    // Update checkpoint.
    ledger.update_checkpoint_root(Some("bb".repeat(32)));
    let snap2 = ledger.triple_snapshot();
    assert_eq!(
        snap2.checkpoint_root.as_deref(),
        Some("b".repeat(64).as_str())
    );
    // Context preserved across updates (RCU correctness).
    assert_eq!(snap2.context_hash.as_deref(), Some("a".repeat(64).as_str()));
}
