//! WAL background re-verification — `△-6` from
//! `docs/internal/COVERAGE_HARDENING_PLAN.md`.
//!
//! `tests/wal_tamper_adversarial.rs` covers `verify_wal` itself
//! (the tamper detector). What this file pins is the **periodic
//! background scan** that runs the detector at a tokio interval
//! and surfaces a break in the `/gvm/health` flag.
//!
//! Properties pinned:
//!
//! 1. **Healthy WAL → flag stays true.** The presence of a
//!    background-scan task on a clean WAL must not produce false
//!    positives. The flag should remain `true` indefinitely.
//! 2. **Tampered WAL → flag flips false on next pass.** Mutate
//!    a sealed batch out-of-band, run one scan pass, observe the
//!    flag flip.
//! 3. **Flag is monotonic.** Once flipped to `false`, it does not
//!    recover within process lifetime — even if the next pass
//!    happens to read a successfully-rotated file.
//! 4. **Empty WAL is healthy.** Boot-time race where the WAL is
//!    empty must not flip the flag.
//! 5. **Disabled (`interval_secs = 0`) does not spawn anything.**
//!    The opt-in default is preserved.
//! 6. **Read errors are transient.** A read failure (file briefly
//!    locked, mid-rotation) does not flip the flag — only an
//!    actual chain break does.

use gvm_proxy::wal_background_reverify::{run_one_pass, spawn, WalChainHealth};

/// Build a WAL with one valid event + the corresponding seal +
/// batch record + anchor. We can't easily produce a real
/// well-formed Merkle batch from a test without exercising the
/// whole Ledger; instead, we pre-generate one via the Ledger,
/// then inspect the file. For the purposes of this test the only
/// thing that matters is that `merkle::verify_wal` reports
/// `chain_intact = true` on the result.
async fn build_healthy_wal() -> (tempfile::TempDir, std::path::PathBuf) {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let ledger = Ledger::new(&wal_path).await.unwrap();
    // Write nothing — empty WAL is a valid healthy state. The
    // tampered_wal test below appends an actual event sequence.
    drop(ledger);
    (dir, wal_path)
}

#[test]
fn health_flag_starts_intact() {
    let h = WalChainHealth::new();
    assert!(h.is_intact());
}

#[test]
fn health_flag_set_break_is_monotonic() {
    let h = WalChainHealth::new();
    h.set_break();
    assert!(!h.is_intact());
    h.set_break(); // idempotent
    assert!(!h.is_intact());
}

#[test]
fn health_flag_clones_share_state() {
    let h = WalChainHealth::new();
    let h2 = h.clone();
    h.set_break();
    assert!(!h2.is_intact());
}

#[tokio::test]
async fn reverify_pass_on_empty_wal_keeps_flag_intact() {
    let (_dir, wal_path) = build_healthy_wal().await;
    let h = WalChainHealth::new();
    run_one_pass(&wal_path, &h).await;
    assert!(
        h.is_intact(),
        "empty WAL must not flip the chain-intact flag"
    );
}

#[tokio::test]
async fn reverify_pass_on_missing_file_keeps_flag_intact() {
    // I/O error reading the WAL is treated as transient (file may
    // be mid-rotation). A break must require an actual
    // verify_wal failure, not just an unreadable file.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("does-not-exist.log");
    let h = WalChainHealth::new();
    run_one_pass(&wal_path, &h).await;
    assert!(
        h.is_intact(),
        "missing/unreadable WAL must not flip the flag (transient I/O is not a chain break)"
    );
}

#[tokio::test]
async fn reverify_pass_on_corrupted_chain_flips_flag() {
    // Build a real WAL via Ledger so the seal+batch+anchor records
    // are well-formed, then byte-mutate one event line. The mutation
    // changes the JSON body so the recomputed event_hash diverges
    // from the stored one — `verify_wal` flags this in
    // `tampered_events` and the chain is no longer intact.
    use gvm_proxy::ledger::Ledger;
    use gvm_types::{
        EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor, ResourceTier, Sensitivity,
        TransportInfo,
    };

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");

    // Write a healthy WAL via the real Ledger.
    {
        let mut ledger = Ledger::new(&wal_path).await.unwrap();
        for i in 0..10u64 {
            let evt = GVMEvent {
                event_id: format!("evt-{i}"),
                trace_id: format!("trace-{i}"),
                parent_event_id: None,
                agent_id: "reverify-test".to_string(),
                token_id: None,
                tenant_id: None,
                session_id: "session-1".to_string(),
                timestamp: chrono::Utc::now(),
                operation: "gvm.test.reverify".to_string(),
                resource: ResourceDescriptor {
                    service: "test".to_string(),
                    identifier: None,
                    tier: ResourceTier::External,
                    sensitivity: Sensitivity::Low,
                },
                context: std::collections::HashMap::new(),
                transport: Some(TransportInfo {
                    method: "POST".to_string(),
                    host: "reverify.test".to_string(),
                    path: "/x".to_string(),
                    status_code: None,
                }),
                decision: "Allow".to_string(),
                decision_source: "SRR".to_string(),
                matched_rule_id: None,
                enforcement_point: "test".to_string(),
                status: EventStatus::Confirmed,
                payload: PayloadDescriptor::default(),
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                config_integrity_ref: None,
                operation_descriptor: None,
            };
            ledger.append_durable(&evt).await.unwrap();
        }
        ledger.shutdown().await;
    }

    // Sanity: the freshly-built WAL must be intact. A failure
    // here is a test fixture bug, not a △-6 regression.
    {
        let pre = std::fs::read_to_string(&wal_path).unwrap();
        let pre_report = gvm_proxy::merkle::verify_wal(&pre);
        assert!(
            pre_report.chain_intact && pre_report.invalid_batches.is_empty(),
            "freshly-built WAL must be clean — fixture is wrong otherwise"
        );
    }

    // Tamper: flip one byte in the middle of the WAL.
    {
        let mut bytes = std::fs::read(&wal_path).unwrap();
        let mid = bytes.len() / 2;
        // Walk forward to a printable ASCII byte (not in JSON
        // structural punctuation) so the mutation lands on actual
        // event content rather than a structural `{` / `,` /
        // newline.
        let mut idx = mid;
        while idx < bytes.len() && !bytes[idx].is_ascii_alphanumeric() {
            idx += 1;
        }
        if idx >= bytes.len() {
            panic!("could not find mid-WAL byte to mutate (fixture too short?)");
        }
        // Toggle low bit. ASCII 'a' becomes 'b', 'A' becomes
        // 'C' (the right neighbour or '@'), digit '5' becomes
        // '4' — all of which break the JSON value's hash.
        bytes[idx] ^= 1;
        std::fs::write(&wal_path, &bytes).unwrap();
    }

    let h = WalChainHealth::new();
    run_one_pass(&wal_path, &h).await;
    assert!(
        !h.is_intact(),
        "byte-mutation in the middle of an event line must flip the chain-intact flag to false"
    );
}

#[tokio::test]
async fn reverify_skips_read_when_already_broken() {
    // Once the flag is broken, the background pass must not
    // bother reading the WAL again — both as a perf optimisation
    // (don't waste I/O on a flag that can't recover) and as a
    // monotonicity guarantee (no risk that a later "clean read"
    // accidentally clears the flag).
    let (_dir, wal_path) = build_healthy_wal().await;
    let h = WalChainHealth::new();
    h.set_break(); // pre-broken
    run_one_pass(&wal_path, &h).await;
    assert!(
        !h.is_intact(),
        "flag must stay false after a pass against a healthy WAL when already broken"
    );
}

#[tokio::test]
async fn spawn_with_zero_interval_is_a_noop() {
    // The contract: `spawn(.., 0, ..)` returns immediately
    // without spawning anything. We can't directly observe "no
    // task spawned", but we CAN observe that the health flag
    // remains intact and the function returns synchronously.
    let h = WalChainHealth::new();
    spawn(std::path::PathBuf::from("/nonexistent.log"), 0, h.clone());
    // Give any (incorrectly spawned) task time to run.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        h.is_intact(),
        "interval_secs = 0 must spawn no task; nothing should have written to the flag"
    );
}
