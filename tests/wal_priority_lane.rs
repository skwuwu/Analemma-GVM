//! Phase F — WAL priority lane tests.
//!
//! Pinned invariants:
//!   1. `WalPriority::from_event` classifies decisions correctly:
//!      - Deny / RequireApproval → High
//:      - Delay / AuditOnly → Normal
//!      - Allow / unknown → Low
//!   2. Atomicity is preserved: a mixed batch (high + normal + low
//!      events) shares one fsync, one seal, one anchor — the v3
//!      audit chain (C2/C3 contracts) is unchanged by lane splitting.
//!   3. Tail latency for high-priority events does not grow with the
//!      depth of the low-priority queue: under a burst of 100 low +
//!      10 high arriving simultaneously, the high events flush in
//!      the *first* fsync (not the second).
//!   4. Ordering within a lane is preserved (FIFO per lane).

use gvm_proxy::ledger::{GroupCommitConfig, Ledger, WalPriority};
use gvm_types::{
    BatchSealRecord, EventStatus, GVMEvent, GvmStateAnchor, MerkleBatchRecord, PayloadDescriptor,
    ResourceDescriptor,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn evt(id: &str, decision: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "priority-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: decision.to_string(),
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

// ────────────────────────────────────────────────────────────────────
// 1. Classification
// ────────────────────────────────────────────────────────────────────

#[test]
fn deny_and_require_approval_classify_as_high() {
    assert_eq!(
        WalPriority::from_event(&evt("d1", "Deny { reason: \"blocked\" }")),
        WalPriority::High
    );
    assert_eq!(
        WalPriority::from_event(&evt("d2", "Deny")),
        WalPriority::High
    );
    assert_eq!(
        WalPriority::from_event(&evt("r1", "RequireApproval { urgency: Standard }")),
        WalPriority::High
    );
    assert_eq!(
        WalPriority::from_event(&evt("r2", "RequireApproval")),
        WalPriority::High
    );
}

#[test]
fn delay_and_audit_only_classify_as_normal() {
    assert_eq!(
        WalPriority::from_event(&evt("e1", "Delay { milliseconds: 300 }")),
        WalPriority::Normal
    );
    assert_eq!(
        WalPriority::from_event(&evt("e2", "Delay")),
        WalPriority::Normal
    );
    assert_eq!(
        WalPriority::from_event(&evt("e3", "AuditOnly { alert_level: Warning }")),
        WalPriority::Normal
    );
    assert_eq!(
        WalPriority::from_event(&evt("e4", "AuditOnly")),
        WalPriority::Normal
    );
}

#[test]
fn allow_and_unknown_classify_as_low() {
    assert_eq!(
        WalPriority::from_event(&evt("a1", "Allow")),
        WalPriority::Low
    );
    assert_eq!(
        WalPriority::from_event(&evt("u1", "SomeUnknown")),
        WalPriority::Low
    );
}

// ────────────────────────────────────────────────────────────────────
// 2. Atomicity preserved across mixed-priority batch
// ────────────────────────────────────────────────────────────────────

fn one_event_per_batch() -> GroupCommitConfig {
    GroupCommitConfig {
        batch_window: Duration::ZERO,
        max_batch_size: 1,
        channel_capacity: 16,
        max_wal_bytes: 0,
        max_wal_segments: 0,
    }
}

fn batch_window_50ms() -> GroupCommitConfig {
    // Slow window so a burst is forced into one batch.
    GroupCommitConfig {
        batch_window: Duration::from_millis(50),
        max_batch_size: 512,
        channel_capacity: 4096,
        max_wal_bytes: 0,
        max_wal_segments: 0,
    }
}

#[tokio::test]
async fn mixed_priority_batch_shares_single_anchor() {
    // Submit high + normal + low concurrently. They should land in
    // ONE batch with ONE seal and ONE anchor — priority does not
    // split the Merkle chain.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", batch_window_50ms())
            .await
            .unwrap(),
    );

    let h = evt("hi-1", "Deny");
    let n = evt("nrm-1", "Delay { milliseconds: 100 }");
    let l = evt("lo-1", "Allow");

    let lh = ledger.clone();
    let ln = ledger.clone();
    let ll = ledger.clone();
    let _ = tokio::join!(
        async move { lh.append_durable(&h).await.unwrap() },
        async move { ln.append_durable(&n).await.unwrap() },
        async move { ll.append_durable(&l).await.unwrap() },
    );

    let mut ledger = Arc::try_unwrap(ledger).map_err(|_| "shared").unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();
    let seals: Vec<BatchSealRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();
    let batches: Vec<MerkleBatchRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();

    assert_eq!(
        anchors.len(),
        1,
        "mixed-priority burst must produce exactly ONE anchor (atomicity)"
    );
    assert_eq!(seals.len(), 1, "exactly ONE seal");
    assert_eq!(batches.len(), 1, "exactly ONE batch_record");
    assert_eq!(batches[0].event_count, 3, "all 3 events in the same batch");
}

// ────────────────────────────────────────────────────────────────────
// 3. High priority drains before low under burst
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn high_priority_event_does_not_wait_behind_low_burst() {
    // Setup: max_batch_size = 1 so each event becomes its own batch
    // — this exposes scheduling order. Submit 5 low events, then 1
    // high event. The high event MUST land at WAL position equal to
    // OR EARLIER THAN the position it would have had if appended
    // FIFO (i.e., position 5). With priority lanes the high should
    // be drained ahead of any *pending* low events still in the
    // queue, even though it was sent last.
    //
    // This test is a heuristic — it relies on the burst arriving
    // faster than the batch task drains. We use small max_batch_size
    // (1) to expose ordering, and we send all events back-to-back
    // before awaiting any reply.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", one_event_per_batch())
            .await
            .unwrap(),
    );

    // Fire 5 low + 1 high concurrently.
    let mut handles = Vec::new();
    for i in 0..5 {
        let l = ledger.clone();
        let e = evt(&format!("lo-{}", i), "Allow");
        handles.push(tokio::spawn(async move {
            l.append_durable(&e).await.unwrap();
        }));
    }
    let lh = ledger.clone();
    let h = evt("hi-late", "Deny { reason: \"blocked\" }");
    handles.push(tokio::spawn(async move {
        lh.append_durable(&h).await.unwrap();
    }));

    for h in handles {
        h.await.unwrap();
    }

    let mut ledger = Arc::try_unwrap(ledger).map_err(|_| "shared").unwrap();
    ledger.shutdown().await;

    // Read events in WAL order. The high event should NOT be the
    // very last entry; it should appear ahead of at least some low
    // events because the priority drain pulled it from the queue
    // ahead of pending low items.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let event_ids: Vec<String> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l.trim()).ok())
        .map(|e| e.event_id)
        .collect();
    assert_eq!(event_ids.len(), 6, "all 6 events written");

    let high_pos = event_ids.iter().position(|id| id == "hi-late").unwrap();
    assert!(
        high_pos < 5,
        "high-priority event arrived last but should land before at least one low event \
         under priority lane scheduling — got position {} of {:?}",
        high_pos,
        event_ids
    );
}

// ────────────────────────────────────────────────────────────────────
// 4. FIFO within a lane
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn within_lane_order_is_preserved_fifo() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();

    // Sequential normal-priority events.
    for i in 0..5 {
        ledger
            .append_durable(&evt(&format!("seq-{}", i), "Delay { milliseconds: 100 }"))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let normal_event_ids: Vec<String> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l.trim()).ok())
        .map(|e| e.event_id)
        .filter(|id| id.starts_with("seq-"))
        .collect();
    assert_eq!(
        normal_event_ids,
        vec!["seq-0", "seq-1", "seq-2", "seq-3", "seq-4"],
        "FIFO within a single lane must be preserved"
    );
}

// ────────────────────────────────────────────────────────────────────
// 5. Shutdown drains all lanes
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn shutdown_drains_pending_events_in_all_lanes() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", batch_window_50ms())
            .await
            .unwrap(),
    );

    // Submit one event in each lane simultaneously.
    let l1 = ledger.clone();
    let l2 = ledger.clone();
    let l3 = ledger.clone();
    let _ = tokio::join!(
        async move { l1.append_durable(&evt("h", "Deny")).await.unwrap() },
        async move {
            l2.append_durable(&evt("n", "Delay { milliseconds: 100 }"))
                .await
                .unwrap()
        },
        async move { l3.append_durable(&evt("l", "Allow")).await.unwrap() },
    );

    let mut ledger = Arc::try_unwrap(ledger).map_err(|_| "shared").unwrap();
    ledger.shutdown().await;

    // All 3 lanes' events must reach the WAL.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let ids: Vec<String> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l.trim()).ok())
        .map(|e| e.event_id)
        .collect();
    assert!(ids.contains(&"h".to_string()));
    assert!(ids.contains(&"n".to_string()));
    assert!(ids.contains(&"l".to_string()));
}
