//! Phase 4 — `GvmProof` export and offline verification.
//!
//! Pinned invariants:
//!   - `build_proof(wal, event_id) → verify_proof(...)` produces an
//!     all-pass report for a freshly-written event.
//!   - Tampering ANY layer of the proof (event_hash, Merkle path,
//!     batch_root, anchor field, config chain) fails the corresponding
//!     layer in the verifier and aggregates to `all_pass: false`.
//!   - `RedactionLevel::Standard` strips `operation.detail` and
//!     `operation.detail_salt` but preserves `event_hash` recompute.
//!     Privacy invariant of Phase 1.A.
//!   - `RedactionLevel::Strict` additionally strips the legacy
//!     `operation` string from the redacted form.
//!   - `GvmProof` round-trips through serde JSON without losing
//!     fidelity.
//!   - `build_batch_proof` produces a proof whose `events` count
//!     matches the batch and whose anchor binds the same batch_root.

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_types::{
    proof, verify_proof, EventStatus, GVMEvent, GVMEventOrRedacted, GvmProof, OperationDescriptor,
    PayloadDescriptor, RedactionLevel, ResourceDescriptor,
};
use std::collections::HashMap;

fn make_descriptor() -> OperationDescriptor {
    OperationDescriptor::new(
        "http.POST",
        Some("/api/v1/user/12345/delete".to_string()),
        vec![7u8; 16],
    )
}

fn make_event(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "proof-test".to_string(),
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
        operation_descriptor: Some(make_descriptor()),
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

async fn write_one_event(wal_path: &std::path::Path, event_id: &str) {
    let mut ledger = Ledger::with_config(wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger.append_durable(&make_event(event_id)).await.unwrap();
    ledger.shutdown().await;
}

// ────────────────────────────────────────────────────────────────────
// 1. Happy path
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn build_and_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-happy").await;

    let proof = proof::build_proof(&wal_path, "evt-happy", RedactionLevel::None)
        .expect("build_proof must succeed");
    let report = verify_proof(&proof, None);
    assert!(report.event_hash_valid, "event_hash recompute must pass");
    assert!(report.wal_inclusion_valid, "merkle inclusion must pass");
    assert!(report.batch_root_in_anchor, "anchor binds batch_root");
    assert!(report.anchor_self_hash_valid, "anchor self-hash must pass");
    assert!(report.seal_in_batch_root, "seal must be the last leaf");
    assert!(
        report.all_pass,
        "all layers must pass — got {:?}",
        report
    );
}

// ────────────────────────────────────────────────────────────────────
// 2. Tamper detection
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_event_hash_fails_layer() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-tamper-hash").await;

    let mut proof = proof::build_proof(&wal_path, "evt-tamper-hash", RedactionLevel::None).unwrap();
    if let GVMEventOrRedacted::Full(ref mut e) = proof.event {
        e.event_hash = Some("ff".repeat(32));
    }
    let report = verify_proof(&proof, None);
    assert!(
        !report.event_hash_valid,
        "tampered event_hash must fail event_hash layer"
    );
    assert!(!report.all_pass);
}

#[tokio::test]
async fn tampered_merkle_path_fails_inclusion() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-tamper-merkle").await;
    // Need at least 2 leaves to have a non-trivial path. Append two
    // more events to the same WAL so the inclusion path has siblings.
    {
        let mut ledger = Ledger::with_config(&wal_path, "", "", {
            // Force batches of size 4 so all events end up in the same
            // batch with multiple leaves.
            GroupCommitConfig {
                batch_window: std::time::Duration::from_millis(50),
                max_batch_size: 4,
                channel_capacity: 16,
                max_wal_bytes: 0,
                max_wal_segments: 0,
            }
        })
        .await
        .unwrap();
        ledger.append_durable(&make_event("evt-x1")).await.unwrap();
        ledger.append_durable(&make_event("evt-x2")).await.unwrap();
        ledger.shutdown().await;
    }

    let mut proof = proof::build_proof(&wal_path, "evt-x1", RedactionLevel::None).unwrap();
    if !proof.wal_inclusion.path.is_empty() {
        // Mutate the first sibling — the recomputed root will diverge.
        proof.wal_inclusion.path[0].0 = "ff".repeat(32);
    } else {
        // Single-leaf batch — fall back to mutating leaf_hash.
        proof.wal_inclusion.leaf_hash = "ff".repeat(32);
    }
    let report = verify_proof(&proof, None);
    assert!(
        !report.wal_inclusion_valid,
        "tampered Merkle path must fail inclusion layer"
    );
    assert!(!report.all_pass);
}

#[tokio::test]
async fn tampered_anchor_fails_self_hash() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-tamper-anchor").await;

    let mut proof = proof::build_proof(&wal_path, "evt-tamper-anchor", RedactionLevel::None).unwrap();
    proof.anchor.context_hash = "ee".repeat(32);
    let report = verify_proof(&proof, None);
    assert!(
        !report.anchor_self_hash_valid,
        "anchor field tamper must fail self-hash layer"
    );
}

#[tokio::test]
async fn tampered_batch_root_fails_anchor_link() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-tamper-root").await;

    let mut proof = proof::build_proof(&wal_path, "evt-tamper-root", RedactionLevel::None).unwrap();
    // Mutate batch_record.merkle_root — anchor.batch_root won't match.
    proof.batch_record.merkle_root = "aa".repeat(32);
    let report = verify_proof(&proof, None);
    assert!(
        !report.batch_root_in_anchor,
        "mismatched batch_root must fail anchor-link layer"
    );
}

// ────────────────────────────────────────────────────────────────────
// 3. Redaction preserves event_hash recompute
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn standard_redaction_preserves_event_hash() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-redact-std").await;

    let proof = proof::build_proof(&wal_path, "evt-redact-std", RedactionLevel::Standard).unwrap();
    let report = verify_proof(&proof, None);
    assert!(
        report.event_hash_valid,
        "Standard redaction must preserve event_hash recompute"
    );
    assert!(report.all_pass);

    // Privacy assertion: the redacted form must have detail=None and
    // empty detail_salt — no PII leaks despite verifier still passing.
    if let GVMEventOrRedacted::Redacted(r) = proof.event {
        let desc = r
            .operation_descriptor
            .as_ref()
            .expect("descriptor preserved for v2 hash");
        assert!(desc.detail.is_none(), "detail must be stripped");
        assert!(desc.detail_salt.is_empty(), "detail_salt must be stripped");
        assert!(
            !desc.detail_digest.is_empty(),
            "detail_digest must survive — that's how event_hash recomputes"
        );
        assert_eq!(desc.category, "http.POST");
    } else {
        panic!("Standard redaction must wrap event as Redacted variant");
    }
}

#[tokio::test]
async fn strict_redaction_strips_legacy_operation_string() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-redact-strict").await;

    let proof = proof::build_proof(&wal_path, "evt-redact-strict", RedactionLevel::Strict).unwrap();
    let report = verify_proof(&proof, None);
    assert!(report.event_hash_valid);
    assert!(report.all_pass);

    if let GVMEventOrRedacted::Redacted(r) = proof.event {
        // Strict drops the legacy operation string when a descriptor
        // is present (descriptor.category covers the public side).
        assert!(
            r.operation.is_empty(),
            "Strict redaction must drop legacy operation string when descriptor exists; got {:?}",
            r.operation
        );
    } else {
        panic!("Strict redaction must wrap event as Redacted variant");
    }
}

// ────────────────────────────────────────────────────────────────────
// 4. JSON round-trip
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn proof_round_trips_through_json() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-json").await;

    let proof = proof::build_proof(&wal_path, "evt-json", RedactionLevel::Standard).unwrap();
    let json = serde_json::to_string_pretty(&proof).unwrap();
    let parsed: GvmProof = serde_json::from_str(&json).unwrap();

    let report = verify_proof(&parsed, None);
    assert!(
        report.all_pass,
        "round-tripped proof must still verify all-pass"
    );
}

// ────────────────────────────────────────────────────────────────────
// 5. Batch proof
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn batch_proof_bundles_all_events() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::with_config(
        &wal_path,
        "",
        "",
        GroupCommitConfig {
            batch_window: std::time::Duration::from_millis(50),
            max_batch_size: 16,
            channel_capacity: 16,
            max_wal_bytes: 0,
            max_wal_segments: 0,
        },
    )
    .await
    .unwrap();
    // Concurrent appends — group-commit bundles them into one batch.
    let e1 = make_event("batch-evt-0");
    let e2 = make_event("batch-evt-1");
    let e3 = make_event("batch-evt-2");
    let _ = tokio::join!(
        ledger.append_durable(&e1),
        ledger.append_durable(&e2),
        ledger.append_durable(&e3),
    );
    let mut ledger = ledger;
    ledger.shutdown().await;

    // Find the batch with 3 events — scan all batch records.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let batches: Vec<gvm_types::MerkleBatchRecord> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .collect();
    assert!(!batches.is_empty(), "expected at least one batch");

    // Pick the largest batch (the one bundling our concurrent writes).
    let target = batches.iter().max_by_key(|b| b.event_count).unwrap();
    let batch_id = target.batch_id;

    let bp = proof::build_batch_proof(&wal_path, batch_id, RedactionLevel::Standard)
        .expect("batch proof");
    assert_eq!(
        bp.events.len(),
        target.event_count,
        "batch proof events count must match batch_record.event_count"
    );
    assert!(
        !bp.events.is_empty(),
        "batch must bundle at least one event"
    );
    assert_eq!(
        bp.batch_record.merkle_root, bp.anchor.batch_root,
        "batch_root must match anchor"
    );
    assert!(bp.anchor.verify_self_hash());
}

// ────────────────────────────────────────────────────────────────────
// 6. Missing event
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn missing_event_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-exists").await;

    let result = proof::build_proof(&wal_path, "evt-does-not-exist", RedactionLevel::None);
    assert!(result.is_err(), "missing event_id must return an error");
}

// ────────────────────────────────────────────────────────────────────
// 7. Genesis proof (no config_load yet)
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn genesis_proof_anchored_at_genesis_hash() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-genesis").await;

    let proof = proof::build_proof(&wal_path, "evt-genesis", RedactionLevel::None).unwrap();
    // No config_load was recorded, so the anchor's context_hash is
    // GENESIS_HASH_HEX and the chain is empty.
    assert_eq!(
        proof.anchor.context_hash,
        gvm_types::GENESIS_HASH_HEX,
        "genesis run: anchor.context_hash must equal GENESIS_HASH_HEX"
    );
    assert!(
        proof.config_short_chain.is_empty(),
        "genesis proof: config short chain is empty"
    );
    let report = verify_proof(&proof, None);
    // Empty chain anchored to GENESIS_HASH_HEX is treated as anchored.
    assert!(report.config_chain_valid);
    assert!(report.config_chain_anchored);
    assert!(report.all_pass);
}

// ────────────────────────────────────────────────────────────────────
// 8. Tampered seal hash detection
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_seal_fails_seal_in_batch_root() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    write_one_event(&wal_path, "evt-seal").await;

    let mut proof = proof::build_proof(&wal_path, "evt-seal", RedactionLevel::None).unwrap();
    // Mutate seal context_hash so seal_hash() recomputes to something
    // other than the last leaf in leaves_blob.
    proof.seal.context_hash = "ee".repeat(32);
    let report = verify_proof(&proof, None);
    assert!(
        !report.seal_in_batch_root,
        "seal field tamper must fail the seal-in-batch-root layer"
    );
}
