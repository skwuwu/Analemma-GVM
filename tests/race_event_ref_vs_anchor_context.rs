//! Phase D — Race 1 regression test (§4.7 contract).
//!
//! §4.7 says: "Behavioral events carry the `config_integrity_ref`
//! they observed at request handling time. Batch anchors carry the
//! `context_hash` observed at seal time. These two values MAY
//! legitimately differ within a single batch when reload happens
//! during the batch window. This is documented behavior, NOT a bug."
//!
//! This test pins the contract by constructing a deterministic race:
//!   1. Open a ledger with a slow batch_window (50ms).
//!   2. Seed the triple state with `update_context_hash(OLD_CTX)`.
//!   3. Build an event whose `config_integrity_ref` carries OLD_CTX
//!      (simulating a handler that captured the ref before reload).
//!   4. Concurrently: kick off `append_durable(event)` AND
//!      `update_context_hash(NEW_CTX)` so the new context lands in
//!      the triple state BEFORE the batch task seals.
//!   5. Shutdown forces the final flush.
//!   6. Read WAL: the event's `config_integrity_ref` MUST be OLD_CTX
//!      (event captured before reload), while the seal/anchor
//!      `context_hash` MUST be NEW_CTX (snapshot at seal time).
//!   7. Both values are valid attestations of different facts:
//!      - event.config_integrity_ref attests "the config the handler
//!        saw when it built the event"
//!      - anchor.context_hash attests "the active config at the
//!        moment the batch sealed"
//!
//! Without this test, a future change that "fixes" the divergence
//! by re-reading the active context inside the batch task would pass
//! existing tests but break the §4.7 contract — which is exactly
//! what the design says we MUST preserve.

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_types::{
    BatchSealRecord, EventStatus, GVMEvent, GvmStateAnchor, PayloadDescriptor, ResourceDescriptor,
};
use std::collections::HashMap;

const OLD_CTX: &str = "11111111111111111111111111111111\
                       11111111111111111111111111111111";
const NEW_CTX: &str = "22222222222222222222222222222222\
                       22222222222222222222222222222222";

fn make_event_with_ref(id: &str, ref_hash: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "race-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test.race".to_string(),
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
        config_integrity_ref: Some(ref_hash.to_string()),
        operation_descriptor: None,
    }
}

#[tokio::test]
async fn event_ref_and_anchor_context_can_diverge_within_one_batch() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    // Slow batch window — gives us time to fire update_context_hash
    // between the event arriving in the queue and the batch task
    // running its drain → seal sequence.
    let mut ledger = Ledger::with_config(
        &wal_path,
        "",
        "",
        GroupCommitConfig {
            batch_window: std::time::Duration::from_millis(80),
            max_batch_size: 16,
            channel_capacity: 16,
            max_wal_bytes: 0,
            max_wal_segments: 0,
        },
    )
    .await
    .unwrap();

    // Seed: OLD_CTX is the active context as the handler builds the event.
    ledger.update_context_hash(OLD_CTX.to_string());

    // Build the event under OLD_CTX. The handler-time snapshot lives
    // on the event itself.
    let event = make_event_with_ref("evt-race", OLD_CTX);

    // Race: we want the update_context_hash to happen AFTER the event
    // lands in the queue but BEFORE the batch task drains it. The
    // batch_task is waiting for batch_window to elapse before draining
    // and sealing — that's our race window.
    //
    // This is timing-dependent, so we retry up to 5 attempts. Capped
    // because if it fails persistently, the scheduler is too noisy on
    // this host and a non-test fix is needed (the production behavior
    // is fine — we're just trying to stage a deterministic
    // observation).
    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > 5 {
            panic!(
                "race-1 test could not stage divergence after 5 retries — \
                 investigate scheduler timing on this host"
            );
        }

        // Each attempt: append the event in a sub-task while the test
        // task fires update_context_hash inside the batch window.
        let evt = event.clone();
        let new_ctx = NEW_CTX.to_string();
        let pre_sleep = std::time::Duration::from_millis(15);

        let append_handle = ledger.append_durable(&evt);
        let race_handle = async {
            tokio::time::sleep(pre_sleep).await;
            ledger.update_context_hash(new_ctx);
        };
        let (append_result, _) = tokio::join!(append_handle, race_handle);
        append_result.expect("append must succeed");

        if verify_divergence(&wal_path) {
            break;
        }
        // Failed to stage the divergence this attempt — reset and retry.
        std::fs::write(&wal_path, b"").unwrap();
        ledger.update_context_hash(OLD_CTX.to_string());
    }

    ledger.shutdown().await;

    // Final assertion (after shutdown) — make sure the divergence we
    // observed mid-test is also visible in the post-shutdown WAL.
    assert!(
        verify_divergence(&wal_path),
        "post-shutdown WAL must still show event.config_integrity_ref == OLD \
         while seal/anchor.context_hash == NEW"
    );
}

/// Read WAL, return true iff at least one batch shows the §4.7
/// divergence: event.config_integrity_ref == OLD_CTX while the seal
/// (and anchor) for that batch carry context_hash == NEW_CTX.
fn verify_divergence(wal_path: &std::path::Path) -> bool {
    let content = match std::fs::read_to_string(wal_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Walk the WAL grouping events with the seal that follows.
    let mut group_events: Vec<GVMEvent> = Vec::new();
    let mut last_seal: Option<BatchSealRecord> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("\"anchor_hash\"") && trimmed.contains("\"batch_root\"") {
            // Anchor closes a batch; check divergence here.
            let anchor: GvmStateAnchor = match serde_json::from_str(trimmed) {
                Ok(a) => a,
                Err(_) => continue,
            };
            if let Some(seal) = last_seal.take() {
                let event_old = group_events
                    .iter()
                    .any(|e| e.config_integrity_ref.as_deref() == Some(OLD_CTX));
                let seal_new = seal.context_hash == NEW_CTX;
                let anchor_new = anchor.context_hash == NEW_CTX;
                if event_old && seal_new && anchor_new {
                    return true;
                }
            }
            group_events.clear();
            continue;
        }
        if trimmed.contains("\"merkle_root\"") && trimmed.contains("\"batch_id\"") {
            // Skip batch records — we use seal + anchor.
            continue;
        }
        if trimmed.contains("\"seal_id\"") && trimmed.contains("\"sealed_at\"") {
            if let Ok(s) = serde_json::from_str::<BatchSealRecord>(trimmed) {
                last_seal = Some(s);
                continue;
            }
        }
        if let Ok(e) = serde_json::from_str::<GVMEvent>(trimmed) {
            group_events.push(e);
        }
    }
    false
}

#[tokio::test]
async fn no_race_event_ref_and_anchor_match_when_no_reload() {
    // Sanity — when no reload happens, the event ref and anchor
    // context match. This pins that the divergence is genuinely
    // caused by the race, not by some always-on differential.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(
        &wal_path,
        "",
        "",
        GroupCommitConfig {
            batch_window: std::time::Duration::ZERO,
            max_batch_size: 1,
            channel_capacity: 16,
            max_wal_bytes: 0,
            max_wal_segments: 0,
        },
    )
    .await
    .unwrap();

    ledger.update_context_hash(OLD_CTX.to_string());
    let event = make_event_with_ref("evt-no-race", OLD_CTX);
    ledger.append_durable(&event).await.unwrap();
    ledger.shutdown().await;

    // Read WAL — both event ref and seal/anchor context_hash must equal OLD_CTX.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let event_line = content
        .lines()
        .find(|l| l.contains("\"evt-no-race\""))
        .expect("event line");
    let parsed: GVMEvent = serde_json::from_str(event_line).unwrap();
    assert_eq!(parsed.config_integrity_ref.as_deref(), Some(OLD_CTX));

    let anchor: GvmStateAnchor = content
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .next()
        .expect("anchor line");
    assert_eq!(anchor.context_hash, OLD_CTX);
}
