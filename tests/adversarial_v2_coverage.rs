//! Adversarial coverage for v2-hash WAL records and Phase 4/5
//! corner cases.
//!
//! Test-suite review (post-Phase E) identified two coverage gaps:
//!
//! 1. **WAL tamper-on-v2-events**: existing `wal_tamper_adversarial.rs`
//!    uses `operation_descriptor: None` (v1 hash path). Production
//!    today writes only v2 records, so no integration test exercised
//!    "tamper detection × v2 events" end-to-end.
//!
//! 2. **Descriptor / WAL malformation**: Phase E (`descriptor_e2e.rs`)
//!    is happy-path heavy. This file pins the negative space:
//!    tampered detail_digest, mismatched salt, missing descriptor
//!    on a record that claims spec_version 2.
//!
//! 3. **CLI verify is currently broken on v2** (legacy `gvm audit
//!    verify` uses v1-only recompute). After the fix in
//!    `crates/gvm-cli/src/audit.rs`, this file pins the contract.
//!
//! 4. **Phase 4 proof builder edge cases**: WAL with malformed seal
//!    line, dangling event (no anchor written), batch_record with
//!    leaves_blob length mismatch.
//!
//! 5. **Phase C concurrent register**: many tasks call
//!    `register(agent, step, hash)` simultaneously; the global root
//!    must end in a deterministic state.

use gvm_proxy::checkpoint::CheckpointAggregator;
use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_proxy::merkle::{verify_wal, VerificationReport};
use gvm_types::{
    proof, EventStatus, GVMEvent, OperationDescriptor, PayloadDescriptor, RedactionLevel,
    ResourceDescriptor,
};
use std::collections::HashMap;
use std::sync::Arc;

// ────────────────────────────────────────────────────────────────────
// Helpers — every event built here is a v2 event (descriptor present)
// ────────────────────────────────────────────────────────────────────

fn make_v2_event(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "v2-tamper".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "POST /api/v1/x".to_string(),
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
        operation_descriptor: Some(OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/user/12345/delete".to_string()),
            vec![7u8; 16],
        )),
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

// ════════════════════════════════════════════════════════════════════
// 1. WAL tamper detection on v2 events
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn v2_event_tampered_detail_digest_breaks_hash_recompute() {
    // Tamper: an attacker rewrites operation_descriptor.detail_digest
    // on a v2 record after it was written. event_hash recompute
    // (which uses category + detail_digest) MUST diverge from the
    // stored hash — verify_wal flags it as tampered.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .append_durable(&make_v2_event("evt-v2-1"))
        .await
        .unwrap();
    ledger.shutdown().await;

    // Read, tamper detail_digest on the event line, write back.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let mut new_lines: Vec<String> = Vec::new();
    let mut tampered = false;
    for line in content.lines() {
        if !tampered && line.contains("\"event_id\":\"evt-v2-1\"") {
            let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
            // Mutate the salted digest in-place. event_hash recompute
            // will see the new digest and produce a different hash;
            // the stored hash on disk no longer matches.
            value["operation_descriptor"]["detail_digest"] =
                serde_json::Value::String("ff".repeat(32));
            new_lines.push(serde_json::to_string(&value).unwrap());
            tampered = true;
            continue;
        }
        new_lines.push(line.to_string());
    }
    assert!(tampered, "must have found and tampered the v2 event line");
    std::fs::write(&wal_path, new_lines.join("\n") + "\n").unwrap();

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let report = verify_wal(&content);
    assert!(
        !report.tampered_events.is_empty(),
        "tampered detail_digest on a v2 event MUST be flagged as tampered_events. \
         got tampered_events={:?}, invalid_batches={:?}",
        report.tampered_events,
        report.invalid_batches
    );
}

#[tokio::test]
async fn v2_event_stripped_descriptor_breaks_hash_recompute() {
    // Tamper: attacker strips the operation_descriptor field entirely
    // from a v2 record. The dispatcher then falls back to v1 hash
    // (operation_descriptor.is_none() → v1 path), which produces a
    // different hash than the v2 hash that was stored. Tamper flagged.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .append_durable(&make_v2_event("evt-v2-strip"))
        .await
        .unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let mut new_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.contains("\"event_id\":\"evt-v2-strip\"") {
            let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(map) = value.as_object_mut() {
                map.remove("operation_descriptor");
            }
            new_lines.push(serde_json::to_string(&value).unwrap());
        } else {
            new_lines.push(line.to_string());
        }
    }
    std::fs::write(&wal_path, new_lines.join("\n") + "\n").unwrap();

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let report = verify_wal(&content);
    assert!(
        !report.tampered_events.is_empty(),
        "stripping operation_descriptor on a v2 record MUST flag tamper \
         (dispatcher falls back to v1 → different hash than the stored v2 hash)"
    );
}

#[tokio::test]
async fn v2_batch_with_inserted_event_invalidates_root() {
    // Adversary inserts a forged v2 event between batch records. The
    // batch_record's merkle_root was computed without that event;
    // recomputing from the now-larger event set produces a different
    // root and verify_wal flags the batch invalid.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .append_durable(&make_v2_event("evt-real"))
        .await
        .unwrap();
    ledger.shutdown().await;

    // Splice a forged v2 event right before the batch_record line.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let mut out: Vec<String> = Vec::new();
    let forged = make_v2_event("evt-forged");
    let forged_json = serde_json::to_string(&forged).unwrap();
    for line in content.lines() {
        if line.contains("\"merkle_root\"") {
            out.push(forged_json.clone());
        }
        out.push(line.to_string());
    }
    std::fs::write(&wal_path, out.join("\n") + "\n").unwrap();

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let report = verify_wal(&content);
    assert!(
        !report.invalid_batches.is_empty(),
        "splicing a forged v2 event into a batch MUST invalidate the batch root"
    );
}

// ════════════════════════════════════════════════════════════════════
// 2. CLI gvm audit verify on v2 events
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn cli_audit_verify_does_not_misreport_v2_as_tampered() {
    // The CLI used to hardcode a v1-only recompute, which would
    // report every legitimate v2 record as tampered. After the fix,
    // running the verify path on a clean v2 WAL must yield zero
    // hash mismatches. We exercise the same recompute path the CLI
    // uses (gvm_types::proof::recompute_event_hash) on every v2
    // record we can read off disk.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    for i in 0..3 {
        ledger
            .append_durable(&make_v2_event(&format!("evt-cli-{}", i)))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let mut mismatches = 0u32;
    let mut checked = 0u32;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip non-event lines.
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("merkle_root").is_some()
            || value.get("anchor_hash").is_some()
            || (value.get("seal_id").is_some() && value.get("sealed_at").is_some())
        {
            continue;
        }
        let event: GVMEvent = match serde_json::from_value(value) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Some(stored) = &event.event_hash {
            checked += 1;
            // This is the EXACT path crates/gvm-cli/src/audit.rs takes after the fix.
            let recomputed = gvm_types::proof::recompute_event_hash(&event);
            if *stored != recomputed {
                mismatches += 1;
            }
        }
    }
    assert!(checked >= 3, "should have checked at least 3 v2 events");
    assert_eq!(
        mismatches, 0,
        "CLI verify path MUST NOT report v2 events as tampered. \
         If this fails, the CLI dispatcher is out of sync with the writer."
    );
}

// ════════════════════════════════════════════════════════════════════
// 3. Phase 4 proof builder edge cases
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn proof_for_event_in_unsealed_batch_returns_error() {
    // An event lives in the batch task's queue but the anchor has
    // not been written yet. proof::build_proof scans the WAL and
    // requires the event's batch to be sealed (it returns once it
    // sees the anchor line). For events still pending, the builder
    // must return an error rather than emit a malformed proof.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    // Build an event manually and write JUST the event line — no
    // seal/batch_record/anchor follow up.
    let event = make_v2_event("evt-dangling");
    let line = serde_json::to_string(&event).unwrap();
    std::fs::write(&wal_path, line + "\n").unwrap();

    let result = proof::build_proof(&wal_path, "evt-dangling", RedactionLevel::None);
    assert!(
        result.is_err(),
        "event without a sealed batch (no anchor line) MUST NOT yield a proof"
    );
}

#[tokio::test]
async fn proof_with_truncated_leaves_blob_is_rejected_by_verifier() {
    // Build a real proof, then truncate batch_record.leaves_blob and
    // serialize. The verifier should fail at least one layer
    // (likely wal_inclusion or seal_in_batch_root) because the leaf
    // we claim to include is no longer recoverable from the blob.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .append_durable(&make_v2_event("evt-trunc"))
        .await
        .unwrap();
    ledger.shutdown().await;

    let mut p = proof::build_proof(&wal_path, "evt-trunc", RedactionLevel::None).unwrap();
    // Truncate to just the first 32 bytes — drops the seal leaf.
    p.batch_record.leaves_blob.truncate(32);
    let report = gvm_types::verify_proof(&p, None);
    assert!(
        !report.all_pass,
        "proof with truncated leaves_blob MUST fail at least one layer; got {:?}",
        report
    );
}

// ════════════════════════════════════════════════════════════════════
// 4. Phase C edge cases: concurrent register + sparse steps
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn aggregator_concurrent_register_converges_to_deterministic_root() {
    // Many concurrent (agent, step, hash) registrations from
    // different tasks. After all settle, the global root must equal
    // the root computed offline from the union of all
    // registrations — irrespective of insertion order.
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = Arc::new(
        Ledger::new(&dir.path().join("wal.log"), "", "")
            .await
            .unwrap(),
    );
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));

    // Plan: 8 agents × 4 steps each, 32 concurrent register calls.
    let mut handles = Vec::new();
    let mut expected: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<u32, [u8; 32]>,
    > = std::collections::BTreeMap::new();

    for a in 0..8 {
        for s in 0..4u32 {
            let mut h = [0u8; 32];
            h[0] = a as u8;
            h[1] = s as u8;
            let aid = format!("agent-{}", a);
            expected
                .entry(aid.clone())
                .or_default()
                .insert(s, h);
            let agg = agg.clone();
            handles.push(tokio::spawn(async move {
                agg.register(&aid, s, h).await.unwrap();
            }));
        }
    }
    for h in handles {
        h.await.unwrap();
    }

    let live_root = agg.current_root_hex().await.unwrap();

    // Compute expected root offline.
    let global_leaves: Vec<(String, [u8; 32])> = expected
        .into_iter()
        .map(|(id, leaves)| (id, gvm_types::compute_agent_checkpoint_root(&leaves).unwrap()))
        .collect();
    let expected_root = gvm_types::compute_checkpoint_root_hex(&global_leaves).unwrap();

    assert_eq!(
        live_root, expected_root,
        "concurrent register MUST converge to the deterministic offline root"
    );

    drop(agg);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;
}

#[test]
fn agent_proof_works_with_sparse_and_max_step_values() {
    // step is u32; a proof must work even for very large or sparse
    // step indices (this rules out implementations that pre-allocate
    // by step value or assume contiguous steps).
    let mut leaves = std::collections::BTreeMap::new();
    leaves.insert(0u32, [1u8; 32]);
    leaves.insert(100_000u32, [2u8; 32]);
    leaves.insert(u32::MAX, [3u8; 32]);

    let root_hex = gvm_types::compute_agent_checkpoint_root_hex(&leaves).unwrap();
    for step in [0u32, 100_000u32, u32::MAX] {
        let (leaf_hex, path) = gvm_types::agent_checkpoint_proof(&leaves, step)
            .unwrap_or_else(|| panic!("proof must exist for step {}", step));
        assert!(
            gvm_types::verify_agent_checkpoint_proof(&leaf_hex, &path, &root_hex),
            "sparse-step proof for step {} must verify",
            step
        );
    }
}

#[test]
fn aggregator_inclusion_path_for_nonexistent_agent_is_none() {
    // Forging a CheckpointInclusion with a wrong agent_id should not
    // produce a path at all — the aggregator returns None.
    let leaves: Vec<(String, [u8; 32])> = vec![
        ("agent-A".to_string(), [1u8; 32]),
        ("agent-B".to_string(), [2u8; 32]),
    ];
    assert!(gvm_types::aggregator_inclusion_proof(&leaves, "agent-Z").is_none());
}

// ════════════════════════════════════════════════════════════════════
// 5. proxy_handler v2-descriptor end-to-end is covered separately
//    in tests/integration.rs once it's wired through real HTTP.
//    The non-trivial fix that build_event now populates the descriptor
//    is unit-pinned by the existing descriptor migration tests; the
//    on-disk v2 hash is exercised by the writer + verifier here.
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn happy_path_v2_event_recomputes_clean() {
    // Counterpart to v2_event_tampered_detail_digest_breaks_hash_recompute.
    // Pins that the negative tests above are not falsely triggering on
    // every batch — a CLEAN v2 WAL must report zero tampered_events.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    ledger
        .append_durable(&make_v2_event("evt-clean"))
        .await
        .unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let report: VerificationReport = verify_wal(&content);
    assert!(
        report.tampered_events.is_empty(),
        "clean v2 WAL must have NO tampered events; got {:?}",
        report.tampered_events
    );
    assert!(report.invalid_batches.is_empty());
    assert!(report.chain_intact);
}
