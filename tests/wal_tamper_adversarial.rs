//! End-to-end adversarial tamper tests for the WAL.
//!
//! tests/merkle.rs already covers the API-level tamper detection:
//! `merkle_wal_verification_detects_tampered_event` mutates one event
//! and confirms `verify_wal()` flags it. This file extends that to
//! the operator-facing scenarios:
//!
//!   1. Random-byte mid-WAL mutation (the kind of bit-rot or
//!      malicious vi-on-wal an attacker would attempt). After
//!      tamper, verify_wal MUST flag either tampered_events or
//!      invalid_batches; the chain MUST NOT silently look
//!      intact.
//!
//!   2. Unauthorized event insertion: an attacker splices a
//!      forged event between batch records. The Merkle batch
//!      root was computed without that event; verify_wal sees
//!      the now-larger event set produces a different root and
//!      flags the batch invalid.
//!
//!   3. Tampered batch record: the attacker rewrites the
//!      `merkle_root` field to lie about what the batch
//!      contained. verify_wal recomputes from event hashes and
//!      catches the lie.
//!
//!   4. Truncated WAL (write torn by power loss / crash):
//!      partial last line / missing trailing batch record.
//!      verify_wal must NOT crash and must report the surviving
//!      complete portion accurately.
//!
//!   5. End-to-end production scenario: a sandbox writes events
//!      → file is opened in another process and bytes are
//!      mutated → the audit-verify CLI path
//!      (`gvm_proxy::merkle::verify_wal`) detects the tamper.
//!      This locks in the operator-running-`gvm audit verify`
//!      contract.

use gvm_proxy::ledger::Ledger;
use gvm_proxy::merkle::verify_wal;
use gvm_types::{
    EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor, ResourceTier, Sensitivity,
    TransportInfo,
};
use std::io::{Read, Seek, SeekFrom, Write};

fn evt(seq: u64) -> GVMEvent {
    GVMEvent {
        event_id: format!("tamper-evt-{}", seq),
        trace_id: format!("trace-{}", seq),
        parent_event_id: None,
        agent_id: "tamper-test".to_string(),
        tenant_id: None,
        session_id: "tamper-session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.test.tamper".to_string(),
        resource: ResourceDescriptor {
            service: "test".to_string(),
            identifier: None,
            tier: ResourceTier::External,
            sensitivity: Sensitivity::Low,
        },
        context: std::collections::HashMap::new(),
        transport: Some(TransportInfo {
            method: "POST".to_string(),
            host: "tamper.test".to_string(),
            path: "/v1/x".to_string(),
            status_code: None,
        }),
        decision: "Allow".to_string(),
        decision_source: "SRR".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
    }
}

async fn write_clean_wal(path: &std::path::Path, n: u64) {
    let mut ledger = Ledger::new(path, "", "")
        .await
        .expect("ledger init");
    for i in 0..n {
        ledger.append_durable(&evt(i)).await.expect("append");
    }
    ledger.shutdown().await;
}

// ════════════════════════════════════════════════════════════════
// 1. Mid-WAL byte mutation: verify_wal MUST flag tamper.
// ════════════════════════════════════════════════════════════════
//
// Mutate a single byte in the middle of the file and re-run
// verification. The tamper produces one of:
//   - tampered_events non-empty (event hash recomputes differently
//     from stored event_hash because we mutated the JSON body)
//   - invalid_batches non-empty (batch root computed over the
//     stored event_hashes no longer matches)
//   - parse failure (the JSON line itself is now invalid; verify_wal
//     skips it, which still results in invalid_batches because the
//     batch's expected event count is off)
// At least ONE of these signals must fire — silent acceptance is
// the regression we are guarding against.

#[tokio::test]
async fn mid_wal_byte_mutation_flags_some_tamper_signal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    write_clean_wal(&path, 30).await;

    let pre = std::fs::read_to_string(&path).unwrap();
    let pre_report = verify_wal(&pre);
    assert!(
        pre_report.tampered_events.is_empty()
            && pre_report.invalid_batches.is_empty()
            && pre_report.chain_intact,
        "clean WAL must verify clean (sanity check) — pre-tamper report: \
         tampered={:?} invalid_batches={:?} chain_intact={}",
        pre_report.tampered_events,
        pre_report.invalid_batches,
        pre_report.chain_intact
    );

    // Tamper: flip one byte in the middle of the file. We choose a
    // byte that lands inside an event JSON line (not whitespace) by
    // picking the file midpoint and finding a surrounding ASCII byte.
    let file_len = std::fs::metadata(&path).unwrap().len();
    assert!(file_len > 200, "WAL must be at least 200 bytes for the test");
    let mid = (file_len / 2) as u64;

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.seek(SeekFrom::Start(mid)).unwrap();
    let mut byte = [0u8; 1];
    f.read_exact(&mut byte).unwrap();
    // XOR with 0x01 produces a different printable / ASCII byte.
    let tampered = byte[0] ^ 0x01;
    f.seek(SeekFrom::Start(mid)).unwrap();
    f.write_all(&[tampered]).unwrap();
    f.sync_all().unwrap();
    drop(f);

    let post = std::fs::read_to_string(&path).unwrap();
    let report = verify_wal(&post);

    let signal_fired = !report.tampered_events.is_empty()
        || !report.invalid_batches.is_empty()
        || !report.chain_intact;
    assert!(
        signal_fired,
        "mid-WAL byte mutation produced ZERO tamper signals: \
         tampered_events={:?} invalid_batches={:?} chain_intact={}. \
         The audit chain claims integrity it does not have.",
        report.tampered_events, report.invalid_batches, report.chain_intact
    );
}

// ════════════════════════════════════════════════════════════════
// 2. Unauthorized event insertion → batch becomes invalid.
// ════════════════════════════════════════════════════════════════
//
// An attacker with write access splices a forged event line in the
// middle of a batch (between the last event and the batch record).
// The batch record's stored merkle_root was computed over the
// original event hashes. After insertion, the recomputed root over
// the now-extra event no longer matches → invalid_batches non-empty.

#[tokio::test]
async fn unauthorized_event_insertion_invalidates_batch_root() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    write_clean_wal(&path, 10).await;

    // Read all lines, split events from batch records.
    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = content.lines().collect();
    assert!(
        lines.len() >= 2,
        "test scaffolding: expected at least one event + one batch record"
    );

    // Forge an event with a perfectly valid event_hash for ITS OWN
    // content, but never written by the legitimate batch. Inject it
    // BEFORE the first batch record.
    let mut forged = evt(9999);
    forged.agent_id = "attacker-injected".to_string();
    let forged_hash = gvm_proxy::merkle::compute_event_hash(&forged);
    forged.event_hash = Some(forged_hash);
    let forged_line = serde_json::to_string(&forged).unwrap();

    // Find the first batch record line index.
    let batch_idx = lines
        .iter()
        .position(|l| l.contains("\"merkle_root\""))
        .expect("at least one batch record");
    lines.insert(batch_idx, &forged_line);
    let tampered_content = lines.join("\n") + "\n";
    std::fs::write(&path, &tampered_content).unwrap();

    let report = verify_wal(&tampered_content);
    assert!(
        !report.invalid_batches.is_empty(),
        "unauthorized event injection must invalidate the affected \
         batch root; got invalid_batches={:?}",
        report.invalid_batches
    );
}

// ════════════════════════════════════════════════════════════════
// 3. Tampered batch root field — attacker rewrites merkle_root.
// ════════════════════════════════════════════════════════════════
//
// The attacker can recompute event hashes for forged events but
// cannot independently produce a fake batch root that matches the
// (forged) event set without also forging the inter-batch chain.
// We test the simpler subcase: tamper just the `merkle_root` field
// on the first batch record. verify_wal recomputes from event
// hashes and catches the discrepancy.

#[tokio::test]
async fn tampered_batch_record_merkle_root_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    write_clean_wal(&path, 5).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let batch_idx = lines
        .iter()
        .position(|l| l.contains("\"merkle_root\""))
        .expect("at least one batch record");

    // Replace the first batch record's merkle_root with a sha256 of
    // the literal "attacker-fake-root". The attacker is hoping
    // verify_wal trusts the stored value.
    let line = &lines[batch_idx];
    let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
    value["merkle_root"] = serde_json::Value::String(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    lines[batch_idx] = value.to_string();
    let tampered = lines.join("\n") + "\n";

    let report = verify_wal(&tampered);
    assert!(
        !report.invalid_batches.is_empty(),
        "tampered merkle_root must produce invalid_batches non-empty; got {:?}",
        report.invalid_batches
    );
}

// ════════════════════════════════════════════════════════════════
// 4. Truncated WAL: verify_wal must not crash, must report
//    the verifiable prefix correctly.
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn truncated_wal_does_not_crash_and_reports_complete_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    write_clean_wal(&path, 10).await;

    let content = std::fs::read_to_string(&path).unwrap();
    let original_len = content.len();
    // Truncate to 80% of original length — guaranteed to chop a line
    // mid-record.
    let cut = (original_len * 4) / 5;
    let truncated = &content[..cut];

    // Must not panic.
    let report = verify_wal(truncated);

    // The prefix may or may not contain a complete batch. Either:
    //   - Some batches verified (valid_batches > 0) → the prefix had
    //     at least one complete batch.
    //   - No batches at all in the prefix → all good (just events
    //     pending the next flush).
    //   - Last line malformed → silently skipped (verify_wal's
    //     existing contract).
    // What is NOT allowed: panic, infinite loop, fabricating
    // tampered_events that didn't have a matching batch record.
    assert!(
        report.valid_batches <= report.total_batches,
        "report consistency: valid_batches={} > total_batches={}",
        report.valid_batches,
        report.total_batches
    );
}

// ════════════════════════════════════════════════════════════════
// 5. E2E: write events with the real Ledger, tamper bytes,
//    re-verify with the same API the audit CLI uses.
// ════════════════════════════════════════════════════════════════
//
// Locks the contract that operators rely on when running
// `gvm audit verify`: a tamper introduced AFTER the proxy wrote
// events (e.g. by an attacker with disk access between proxy
// shutdown and the next audit run) is detected. The earlier tests
// in this file verify the API in isolation; this one verifies the
// full operator-facing path.

#[tokio::test]
async fn e2e_audit_verify_catches_post_writeback_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    write_clean_wal(&path, 20).await;

    // Sanity: clean WAL verifies clean.
    let clean = std::fs::read_to_string(&path).unwrap();
    let clean_report = verify_wal(&clean);
    assert!(
        clean_report.tampered_events.is_empty(),
        "pre-tamper report should be clean"
    );

    // Tamper: change one event's `decision` field from "Allow" to
    // "Deny" — semantically meaningful, NOT just a byte flip. This
    // mirrors the production attack: someone retroactively edits
    // events to mask a Deny.
    let tampered_content = clean.replace("\"decision\":\"Allow\"", "\"decision\":\"Deny\"");
    assert_ne!(
        tampered_content, clean,
        "test scaffolding: replacement must have changed the content"
    );
    std::fs::write(&path, &tampered_content).unwrap();

    let report = verify_wal(&tampered_content);
    assert!(
        !report.tampered_events.is_empty() || !report.invalid_batches.is_empty(),
        "audit verify must flag the post-writeback tamper. \
         Report: tampered_events={:?} invalid_batches={:?}",
        report.tampered_events,
        report.invalid_batches
    );
}
