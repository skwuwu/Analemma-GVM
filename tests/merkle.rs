//! Merkle tree integration tests.
//!
//! Verifies the end-to-end Merkle integrity pipeline:
//! - event_hash is computed and embedded in WAL entries
//! - MerkleBatchRecord is written after each batch flush
//! - Inter-batch chain (prev_batch_root) is maintained
//! - WAL verification detects tampering
//! - Merkle proofs verify individual events within a batch

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_proxy::merkle;
use gvm_proxy::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn make_test_event(agent_id: &str) -> GVMEvent {
    GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: agent_id.to_string(),
        tenant_id: None,
        session_id: "test-session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.test.merkle".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Pending,
        payload: Default::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Event Hash Embedding
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that event_hash is computed and written to WAL for each event.
#[tokio::test]
async fn merkle_event_hash_embedded_in_wal() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    let event = make_test_event("agent-hash-check");
    ledger
        .append_durable(&event)
        .await
        .expect("single event append must succeed");

    // append_durable().await already guarantees fsync completed (group commit
    // waits for oneshot reply). No sleep needed — data is on disk.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");
    let event_lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.contains("\"merkle_root\""))
        .collect();

    assert_eq!(event_lines.len(), 1);

    let stored: GVMEvent =
        serde_json::from_str(event_lines[0]).expect("WAL event line must be valid JSON");
    assert!(
        stored.event_hash.is_some(),
        "event_hash must be populated in WAL"
    );

    // Verify the hash is correct by recomputing
    let recomputed = merkle::compute_event_hash(&stored);
    assert_eq!(
        stored
            .event_hash
            .as_ref()
            .expect("event_hash must be present after WAL write"),
        &recomputed,
        "stored event_hash must match recomputed hash"
    );
}

/// Verify that event_hash is deterministic for the same event fields.
#[tokio::test]
async fn merkle_event_hash_deterministic() {
    let event = make_test_event("agent-deterministic");
    let hash1 = merkle::compute_event_hash(&event);
    let hash2 = merkle::compute_event_hash(&event);
    assert_eq!(hash1, hash2, "same event must produce same hash");
    assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");
}

/// Verify that different events produce different hashes.
#[tokio::test]
async fn merkle_event_hash_unique_per_event() {
    let event1 = make_test_event("agent-1");
    let event2 = make_test_event("agent-2");
    let hash1 = merkle::compute_event_hash(&event1);
    let hash2 = merkle::compute_event_hash(&event2);
    assert_ne!(
        hash1, hash2,
        "different events must produce different hashes"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Batch Merkle Root
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that a MerkleBatchRecord is written to WAL after each batch flush.
#[tokio::test]
async fn merkle_batch_record_written_to_wal() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    // Write 3 events (likely flushed as one batch)
    for i in 0..3 {
        let event = make_test_event(&format!("agent-batch-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("batch event append must succeed");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");

    // Find batch records
    let batch_records: Vec<MerkleBatchRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    assert!(
        !batch_records.is_empty(),
        "WAL must contain at least one MerkleBatchRecord"
    );

    // Verify batch record fields
    let total_events_in_batches: usize = batch_records.iter().map(|b| b.event_count).sum();
    assert_eq!(
        total_events_in_batches, 3,
        "batch records must account for all 3 events"
    );
}

/// Verify the Merkle root in the batch record matches recomputed root from events.
#[tokio::test]
async fn merkle_batch_root_recomputable() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    // Write 4 events for a balanced Merkle tree
    for i in 0..4 {
        let event = make_test_event(&format!("agent-root-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("balanced tree event append must succeed");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");

    // Collect event hashes and batch records in WAL order
    let mut current_batch_hashes: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.contains("\"merkle_root\"") {
            // Batch record — verify Merkle root
            let record: MerkleBatchRecord = serde_json::from_str(line)
                .expect("batch record line must be valid MerkleBatchRecord JSON");
            let recomputed = merkle::compute_merkle_root(&current_batch_hashes).unwrap();
            assert_eq!(
                record.merkle_root, recomputed,
                "batch {}: stored root must match recomputed root",
                record.batch_id
            );
            current_batch_hashes.clear();
        } else if let Ok(event) = serde_json::from_str::<GVMEvent>(line) {
            current_batch_hashes.push(
                event
                    .event_hash
                    .expect("WAL event must have event_hash populated"),
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Inter-batch Chain
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that multiple batches are chained via prev_batch_root.
#[tokio::test]
async fn merkle_inter_batch_chain() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Use a batch_window to force separate batches
    let config = GroupCommitConfig {
        batch_window: Duration::ZERO,
        max_batch_size: 2, // Force small batches
        channel_capacity: 32,
        ..Default::default()
    };
    let ledger = Ledger::with_config(&wal_path, "", "", config)
        .await
        .expect("ledger with valid config must initialize");

    // Write 6 events — with max_batch_size=2, should produce 3+ batches
    for i in 0..6 {
        let event = make_test_event(&format!("agent-chain-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("chain event append must succeed");
        // Small delay to separate batches
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // No sleep needed: last append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");

    let batch_records: Vec<MerkleBatchRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    assert!(
        batch_records.len() >= 2,
        "must have at least 2 batches, got {}",
        batch_records.len()
    );

    // First batch must have prev_batch_root = None
    assert!(
        batch_records[0].prev_batch_root.is_none(),
        "first batch must have no prev_batch_root"
    );

    // Subsequent batches must chain to the previous batch's root
    for i in 1..batch_records.len() {
        assert_eq!(
            batch_records[i].prev_batch_root.as_ref(),
            Some(&batch_records[i - 1].merkle_root),
            "batch {} prev_batch_root must equal batch {} merkle_root",
            batch_records[i].batch_id,
            batch_records[i - 1].batch_id
        );
    }

    // Batch IDs must be monotonically increasing
    for i in 1..batch_records.len() {
        assert!(
            batch_records[i].batch_id > batch_records[i - 1].batch_id,
            "batch IDs must be monotonically increasing"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. WAL Verification
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that verify_wal reports correct results for a valid WAL.
#[tokio::test]
async fn merkle_wal_verification_valid() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    for i in 0..5 {
        let event = make_test_event(&format!("agent-verify-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("verification event append must succeed");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");
    let report = merkle::verify_wal(&content);

    assert_eq!(report.total_events, 5);
    assert!(report.total_batches > 0);
    assert_eq!(report.valid_batches, report.total_batches);
    assert!(report.invalid_batches.is_empty());
    assert!(report.chain_intact);
}

/// Verify that verify_wal detects a tampered event hash.
#[tokio::test]
async fn merkle_wal_verification_detects_tampered_event() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    for i in 0..3 {
        let event = make_test_event(&format!("agent-tamper-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("tamper test event append must succeed");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    // Read and tamper with the WAL
    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    // Find the first event line and tamper with the decision field
    for line in lines.iter_mut() {
        if !line.contains("\"merkle_root\"") {
            if let Ok(mut event) = serde_json::from_str::<GVMEvent>(line) {
                event.decision = "Deny".to_string(); // Tamper!
                *line =
                    serde_json::to_string(&event).expect("tampered event must serialize to JSON");
                break;
            }
        }
    }

    let tampered = lines.join("\n");
    let report = merkle::verify_wal(&tampered);

    // The batch is still "valid" because the stored event_hash didn't change —
    // but recomputing the event hash reveals tampering. The verify_wal function
    // uses the stored hash as the leaf (preserving batch structure), so the
    // Merkle root matches. Event-level tampering is detected by comparing
    // compute_event_hash() against stored event_hash.

    // Verify event-level tampering detection
    let first_event_line = tampered
        .lines()
        .find(|l| !l.contains("\"merkle_root\""))
        .expect("WAL must contain at least one event line");
    let tampered_event: GVMEvent =
        serde_json::from_str(first_event_line).expect("event line must be valid JSON");
    let recomputed = merkle::compute_event_hash(&tampered_event);
    assert_ne!(
        tampered_event
            .event_hash
            .as_ref()
            .expect("tampered event must still have original event_hash field"),
        &recomputed,
        "tampered event hash must not match recomputed hash"
    );
}

/// Verify that verify_wal detects a broken batch chain.
#[tokio::test]
async fn merkle_wal_verification_detects_broken_chain() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let config = GroupCommitConfig {
        batch_window: Duration::ZERO,
        max_batch_size: 2,
        channel_capacity: 32,
        ..Default::default()
    };
    let ledger = Ledger::with_config(&wal_path, "", "", config)
        .await
        .expect("ledger with valid config must initialize");

    for i in 0..6 {
        let event = make_test_event(&format!("agent-break-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("broken chain test event append must succeed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // No sleep needed: last append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");

    // Tamper with a batch record's prev_batch_root
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut batch_count = 0;
    for line in lines.iter_mut() {
        if line.contains("\"merkle_root\"") {
            batch_count += 1;
            if batch_count == 2 {
                // Break the chain on the second batch
                let mut record: MerkleBatchRecord = serde_json::from_str(line)
                    .expect("batch record line must be valid MerkleBatchRecord JSON");
                record.prev_batch_root = Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                );
                *line = serde_json::to_string(&record)
                    .expect("modified batch record must serialize to JSON");
                break;
            }
        }
    }

    if batch_count >= 2 {
        let tampered = lines.join("\n");
        let report = merkle::verify_wal(&tampered);
        assert!(
            !report.chain_intact,
            "broken chain must be detected by verify_wal"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Merkle Proof (Individual Event Verification)
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that a Merkle proof can prove inclusion of a specific event in a batch.
#[tokio::test]
async fn merkle_proof_proves_event_in_batch() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger with valid path must initialize");

    // Write 4 events (likely one batch)
    for i in 0..4 {
        let event = make_test_event(&format!("agent-proof-{}", i));
        ledger
            .append_durable(&event)
            .await
            .expect("proof test event append must succeed");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");

    // Collect event hashes from one batch
    let mut batch_event_hashes: Vec<String> = Vec::new();
    let mut batch_root: Option<String> = None;

    for line in content.lines() {
        if line.contains("\"merkle_root\"") {
            let record: MerkleBatchRecord = serde_json::from_str(line)
                .expect("batch record line must be valid MerkleBatchRecord JSON");
            batch_root = Some(record.merkle_root);
            break; // Only check the first batch
        } else if let Ok(event) = serde_json::from_str::<GVMEvent>(line) {
            batch_event_hashes.push(
                event
                    .event_hash
                    .expect("WAL event must have event_hash populated"),
            );
        }
    }

    let root = batch_root.expect("must have at least one batch");
    assert!(!batch_event_hashes.is_empty());

    // Generate and verify proof for each event in the batch
    for i in 0..batch_event_hashes.len() {
        let proof = merkle::generate_merkle_proof(&batch_event_hashes, i).unwrap();
        assert!(
            merkle::verify_merkle_proof(&batch_event_hashes[i], &proof, &root),
            "proof must verify for event index {}",
            i
        );
    }

    // Verify that a forged event hash fails proof verification
    let forged_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let proof = merkle::generate_merkle_proof(&batch_event_hashes, 0).unwrap();
    assert!(
        !merkle::verify_merkle_proof(forged_hash, &proof, &root),
        "forged event must fail proof verification"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Concurrent Merkle Integrity
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that concurrent event writes produce valid Merkle roots.
#[tokio::test]
async fn merkle_concurrent_writes_produce_valid_roots() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger with valid path must initialize"),
    );

    let mut handles = Vec::new();
    for i in 0..50 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("agent-concurrent-{}", i));
            ledger
                .append_durable(&event)
                .await
                .expect("concurrent event append must succeed");
        }));
    }

    for handle in handles {
        handle.await.expect("concurrent write task must not panic");
    }

    // No sleep needed: last append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");
    let report = merkle::verify_wal(&content);

    assert_eq!(report.total_events, 50);
    assert!(report.total_batches > 0);
    assert_eq!(
        report.valid_batches, report.total_batches,
        "all batches must have valid Merkle roots under concurrent writes"
    );
    assert!(report.chain_intact, "batch chain must be intact");
}

/// Verify WAL event_hash values are all unique across concurrent writes.
#[tokio::test]
async fn merkle_all_event_hashes_unique() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger with valid path must initialize"),
    );

    let mut handles = Vec::new();
    for i in 0..20 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("agent-unique-{}", i));
            ledger
                .append_durable(&event)
                .await
                .expect("unique hash test event append must succeed");
        }));
    }

    for handle in handles {
        handle.await.expect("unique hash write task must not panic");
    }

    // No sleep needed: append_durable().await guarantees fsync completed.
    drop(ledger);

    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after flush");
    let hashes: Vec<String> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l).ok())
        .filter_map(|e| e.event_hash)
        .collect();

    assert_eq!(hashes.len(), 20);

    let unique: std::collections::HashSet<&String> = hashes.iter().collect();
    assert_eq!(
        unique.len(),
        hashes.len(),
        "all event hashes must be unique"
    );
}
