//! Phase 4 — leaves-only checkpoint snapshot persistence.
//!
//! Pins:
//!   - Round-trip: state registered → save → fresh aggregator → load
//!     restores the same per-agent / per-step tree, and the
//!     published `checkpoint_root` survives proxy restart.
//!   - Self-consistency: tampered snapshot file is rejected; the
//!     fresh aggregator starts empty so the system keeps running.
//!   - Operational: missing file is clean start; periodic save
//!     fires; shutdown save flushes the last in-flight state.
//!   - Anchor chain: the reloaded `checkpoint_root` is what gets
//!     bound into the next sealed batch's anchor, so the snapshot
//!     transitively hashes into the chain.

use gvm_proxy::checkpoint::{
    CheckpointAggregator, CheckpointSnapshot, SnapshotLoadStatus, SNAPSHOT_SPEC_VERSION,
};
use gvm_proxy::ledger::Ledger;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

async fn fresh_ledger() -> (TempDir, Arc<Ledger>) {
    let tmp = TempDir::new().unwrap();
    let wal_path = tmp.path().join("wal.log");
    let ledger = Arc::new(Ledger::new(&wal_path).await.unwrap());
    (tmp, ledger)
}

async fn reopen_ledger(tmp: &TempDir) -> Arc<Ledger> {
    Arc::new(Ledger::new(&tmp.path().join("wal.log")).await.unwrap())
}

fn h(seed: u8) -> [u8; 32] {
    [seed; 32]
}

#[tokio::test]
async fn snapshot_round_trip_restores_state_and_root() {
    let (tmp, ledger_a) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    let (agg_a, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger_a), snapshot_path.clone()).await;
    assert!(matches!(report.status, SnapshotLoadStatus::NoFile));

    let r1 = agg_a.register("agent-a", 0, h(0xAA)).await.unwrap();
    let _r2 = agg_a.register("agent-a", 1, h(0xBB)).await.unwrap();
    let r3 = agg_a.register("agent-b", 5, h(0xCC)).await.unwrap();
    let r_final = r3.clone();
    let _ = r1;

    let wrote = agg_a.save_snapshot().await.unwrap();
    assert!(wrote, "first save must actually write");
    assert!(snapshot_path.exists());

    // Drop the first aggregator + ledger; new one loads from disk.
    drop(agg_a);
    drop(ledger_a);
    let ledger_b = reopen_ledger(&tmp).await;

    let (agg_b, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger_b), snapshot_path).await;
    match report.status {
        SnapshotLoadStatus::Loaded { reconstructed_root } => {
            assert_eq!(reconstructed_root, r_final);
        }
        other => panic!("expected Loaded, got {:?}", other),
    }
    assert_eq!(report.agents_loaded, 2);
    assert_eq!(report.steps_loaded, 3);

    // Ledger's published root matches what the snapshot reconstructed.
    let triple = ledger_b.triple_snapshot();
    assert_eq!(triple.checkpoint_root.as_deref(), Some(r_final.as_str()));

    // Reloaded aggregator is fully usable — proof retrieval works.
    let proof = agg_b.proof("agent-a", 1).await.expect("step 1 proof");
    assert_eq!(proof.agent_id, "agent-a");
    assert_eq!(proof.step, 1);
    assert_eq!(proof.checkpoint_hash, hex::encode(h(0xBB)));
}

#[tokio::test]
async fn missing_snapshot_file_yields_clean_start() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("does-not-exist.json");

    let (agg, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path).await;

    assert!(matches!(report.status, SnapshotLoadStatus::NoFile));
    assert_eq!(report.agents_loaded, 0);
    assert!(report.is_ok());
    assert_eq!(agg.entry_count().await, 0);
}

#[tokio::test]
async fn corrupt_snapshot_file_is_rejected_and_aggregator_starts_empty() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");
    tokio::fs::write(&snapshot_path, b"{not valid json at all")
        .await
        .unwrap();

    let (agg, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path).await;

    let ok = report.is_ok();
    match &report.status {
        SnapshotLoadStatus::Rejected { reason } => {
            assert!(reason.contains("parse"), "reason was: {}", reason);
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
    assert!(!ok);
    assert_eq!(agg.entry_count().await, 0);
}

#[tokio::test]
async fn tampered_leaf_hash_breaks_self_hash_and_is_rejected() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    // Write a valid snapshot first.
    {
        let (agg, _) =
            CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path.clone()).await;
        agg.register("agent-x", 0, h(0x11)).await.unwrap();
        agg.save_snapshot().await.unwrap();
    }

    // Mutate one leaf in the on-disk file but leave
    // `expected_checkpoint_root` unchanged.
    let bytes = tokio::fs::read(&snapshot_path).await.unwrap();
    let mut snap: CheckpointSnapshot = serde_json::from_slice(&bytes).unwrap();
    let steps = snap.agents.get_mut("agent-x").unwrap();
    steps.insert(0, hex::encode(h(0x22))); // overwritten leaf, no root update
    tokio::fs::write(&snapshot_path, serde_json::to_vec(&snap).unwrap())
        .await
        .unwrap();

    let (agg, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path).await;

    match report.status {
        SnapshotLoadStatus::Rejected { reason } => {
            assert!(
                reason.contains("self-hash mismatch"),
                "reason was: {}",
                reason
            );
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
    assert_eq!(agg.entry_count().await, 0);
}

#[tokio::test]
async fn wrong_spec_version_is_rejected() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    let mut agents = BTreeMap::new();
    let mut steps = BTreeMap::new();
    steps.insert(0u32, hex::encode(h(0x55)));
    agents.insert("agent-z".to_string(), steps);
    let snap = serde_json::json!({
        "spec_version": SNAPSHOT_SPEC_VERSION + 1,
        "expected_checkpoint_root": "00".repeat(32),
        "written_at": chrono::Utc::now(),
        "agents": agents,
    });
    tokio::fs::write(&snapshot_path, snap.to_string())
        .await
        .unwrap();

    let (_, report) = CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path).await;
    assert!(matches!(report.status, SnapshotLoadStatus::Rejected { .. }));
}

#[tokio::test]
async fn save_with_no_changes_is_a_noop() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    let (agg, _) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path.clone()).await;

    agg.register("agent-1", 0, h(0x01)).await.unwrap();
    let first = agg.save_snapshot().await.unwrap();
    assert!(first, "first save with state should write");

    let second = agg.save_snapshot().await.unwrap();
    assert!(!second, "second save with no new state must be a no-op");

    agg.register("agent-1", 1, h(0x02)).await.unwrap();
    let third = agg.save_snapshot().await.unwrap();
    assert!(third, "save after register should write again");
}

#[tokio::test]
async fn in_memory_only_aggregator_save_is_noop() {
    let (_tmp, ledger) = fresh_ledger().await;
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));
    agg.register("agent-1", 0, h(0x01)).await.unwrap();
    let wrote = agg.save_snapshot().await.unwrap();
    assert!(!wrote, "aggregator with no snapshot_path must never write");
    assert!(agg.snapshot_path().is_none());
}

#[tokio::test]
async fn periodic_save_writes_dirty_state_to_disk() {
    let (tmp, ledger) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    let (agg, _) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger), snapshot_path.clone()).await;
    let agg = Arc::new(agg);

    let handle = agg.spawn_periodic_save(Duration::from_millis(50));

    agg.register("agent-q", 7, h(0xEE)).await.unwrap();

    // Wait long enough for at least one save tick.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !snapshot_path.exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        snapshot_path.exists(),
        "periodic save should have produced a file within 3s"
    );

    handle.abort();
    let _ = handle.await;

    // The written file is loadable and matches the live state.
    let bytes = tokio::fs::read(&snapshot_path).await.unwrap();
    let snap: CheckpointSnapshot = serde_json::from_slice(&bytes).unwrap();
    let steps = snap.agents.get("agent-q").expect("agent-q in snapshot");
    assert_eq!(steps.get(&7), Some(&hex::encode(h(0xEE))));
}

#[tokio::test]
async fn reloaded_state_publishes_to_next_anchor_checkpoint_root() {
    let (tmp, ledger_a) = fresh_ledger().await;
    let snapshot_path = tmp.path().join("checkpoint.json");

    let expected_root = {
        let (agg, _) =
            CheckpointAggregator::with_snapshot(Arc::clone(&ledger_a), snapshot_path.clone()).await;
        let r = agg.register("agent-chain", 3, h(0x77)).await.unwrap();
        agg.save_snapshot().await.unwrap();
        r
    };

    // Simulated restart: drop everything, rebuild ledger from the
    // same wal path, then load the snapshot into a fresh aggregator.
    drop(ledger_a);
    let ledger_b = reopen_ledger(&tmp).await;

    let (_agg_b, report) =
        CheckpointAggregator::with_snapshot(Arc::clone(&ledger_b), snapshot_path).await;
    assert!(matches!(report.status, SnapshotLoadStatus::Loaded { .. }));

    // The reloaded root was published into the ledger triple, so the
    // next sealed batch will record exactly this value in its
    // BatchSealRecord::checkpoint_root → GvmStateAnchor::checkpoint_root.
    // The anchor's `compute_hash` already binds checkpoint_root into
    // `anchor_hash`, so the snapshot transitively hashes into the chain
    // without any schema change.
    let triple = ledger_b.triple_snapshot();
    assert_eq!(
        triple.checkpoint_root.as_deref(),
        Some(expected_root.as_str())
    );
}
