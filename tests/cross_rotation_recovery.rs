//! Phase 5b — cross-rotation anchor recovery.
//!
//! Scenario the recovery scanner must handle: a WAL rotation
//! completes (active `wal.log` is renamed to `wal.log.<N>` and a
//! fresh empty `wal.log` is created), then the proxy shuts down
//! before any new batch seals in the new active file. Without
//! Phase 5b the next startup reads only the empty active file,
//! finds no anchor, and treats the next batch as genesis — a
//! false-positive chain break.
//!
//! Phase 5b extends `scan_wal_for_recovery` to fall back to the
//! highest-numbered rotated segment when the active file carries
//! no anchor. The integration tests exercise the behaviour via
//! `Ledger::new` and confirm the published `triple.last_anchor`
//! after open.

use gvm_proxy::ledger::Ledger;
use gvm_types::{
    BatchSealRecord, EventStatus, GVMEvent, GvmStateAnchor, PayloadDescriptor, ResourceDescriptor,
    ResourceTier, Sensitivity,
};
use std::path::PathBuf;
use tempfile::TempDir;

fn make_anchor(batch_id: u64, root_tag: &str) -> GvmStateAnchor {
    let seal = BatchSealRecord {
        seal_id: batch_id,
        sealed_at: chrono::Utc::now(),
        context_hash: format!("ctx-{}-{}", batch_id, "0".repeat(56)),
        checkpoint_root: None,
        prev_anchor: None,
    };
    GvmStateAnchor::seal(1, &seal, format!("{:0>64}", root_tag))
}

async fn write_anchor_line(path: &PathBuf, anchor: &GvmStateAnchor) {
    let line = serde_json::to_string(anchor).unwrap();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.unwrap();
    }
    let mut existing = tokio::fs::read(path).await.unwrap_or_default();
    existing.extend_from_slice(line.as_bytes());
    existing.push(b'\n');
    tokio::fs::write(path, existing).await.unwrap();
}

async fn touch_empty(path: &PathBuf) {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.unwrap();
    }
    tokio::fs::write(path, b"").await.unwrap();
}

#[tokio::test]
async fn empty_active_with_rotated_segment_recovers_anchor() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    let rotated = tmp.path().join("wal.log.1");

    let anchor = make_anchor(7, "abc");
    let expected = anchor.anchor_hash.clone();

    write_anchor_line(&rotated, &anchor).await;
    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert_eq!(
        triple.last_anchor.as_deref(),
        Some(expected.as_str()),
        "rotated segment anchor must be recovered when active is empty"
    );
}

#[tokio::test]
async fn active_anchor_takes_precedence_over_rotated() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    let rotated = tmp.path().join("wal.log.1");

    let old = make_anchor(5, "old");
    let new = make_anchor(6, "new");
    let new_hash = new.anchor_hash.clone();

    write_anchor_line(&rotated, &old).await;
    write_anchor_line(&active, &new).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert_eq!(
        triple.last_anchor.as_deref(),
        Some(new_hash.as_str()),
        "active anchor must win when both segments carry one"
    );
}

#[tokio::test]
async fn highest_numbered_rotated_segment_is_selected() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");

    let mut latest_hash = String::new();
    for n in 1u64..=4 {
        let anchor = make_anchor(n, &format!("seg{}", n));
        latest_hash = anchor.anchor_hash.clone();
        let path = tmp.path().join(format!("wal.log.{}", n));
        write_anchor_line(&path, &anchor).await;
    }
    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert_eq!(
        triple.last_anchor.as_deref(),
        Some(latest_hash.as_str()),
        "must pick the highest-numbered rotated segment (.4), not an older one"
    );
}

#[tokio::test]
async fn no_rotated_segments_falls_back_to_genesis() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert!(
        triple.last_anchor.is_none(),
        "no anchor anywhere → triple.last_anchor must be None (genesis)"
    );
}

#[tokio::test]
async fn corrupt_rotated_segment_does_not_recover() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    let rotated = tmp.path().join("wal.log.1");

    // Garbage in the rotated segment — recovery scanner should not
    // pretend the chain is intact.
    tokio::fs::write(&rotated, b"{not even close to valid json}\n")
        .await
        .unwrap();
    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert!(
        triple.last_anchor.is_none(),
        "corrupt rotated segment without parseable anchor must yield genesis, not a false-positive recovery"
    );
}

#[tokio::test]
async fn non_numeric_suffix_files_are_ignored() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    let bogus = tmp.path().join("wal.log.bak"); // not numeric

    // Write a valid anchor to the bogus file — Phase 5b must ignore
    // it because the suffix isn't `<N>`.
    let anchor = make_anchor(99, "bogus");
    write_anchor_line(&bogus, &anchor).await;
    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert!(
        triple.last_anchor.is_none(),
        "files matching <stem>.<non-numeric> must NOT be treated as rotated segments"
    );
}

#[tokio::test]
async fn rotated_segment_context_hash_seeds_triple() {
    // When the active file has no config_load but the rotated
    // segment does, the recovered context_hash must seed
    // `triple.context_hash` so events sealed between restart and
    // the first new config_load carry the correct ref.
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("wal.log");
    let rotated = tmp.path().join("wal.log.1");

    let anchor = make_anchor(11, "ctx");
    write_anchor_line(&rotated, &anchor).await;

    // Build a real config_load GVMEvent and write it as a WAL line
    // so the recovery scanner's `serde_json::from_str::<GVMEvent>`
    // path actually deserializes.
    let event = GVMEvent {
        event_id: "evt-config-load-1".to_string(),
        trace_id: "trace-config".to_string(),
        parent_event_id: None,
        agent_id: "system".to_string(),
        token_id: None,
        tenant_id: None,
        session_id: "system".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.system.config_load".to_string(),
        resource: ResourceDescriptor {
            service: "system".to_string(),
            identifier: None,
            tier: ResourceTier::External,
            sensitivity: Sensitivity::Low,
        },
        context: std::collections::HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "system".to_string(),
        matched_rule_id: None,
        enforcement_point: "startup".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: Some("feedfeed".repeat(8)),
        operation_descriptor: None,
    };
    let line = serde_json::to_string(&event).unwrap();
    let mut existing = tokio::fs::read(&rotated).await.unwrap();
    existing.extend_from_slice(line.as_bytes());
    existing.push(b'\n');
    tokio::fs::write(&rotated, existing).await.unwrap();

    touch_empty(&active).await;

    let ledger = Ledger::new(&active).await.unwrap();
    let triple = ledger.triple_snapshot();

    assert_eq!(
        triple.last_anchor.as_deref(),
        Some(anchor.anchor_hash.as_str()),
    );
    assert_eq!(
        triple.context_hash.as_deref(),
        Some(&"feedfeed".repeat(8)[..]),
        "context_hash must also be recovered from the rotated segment"
    );
}
