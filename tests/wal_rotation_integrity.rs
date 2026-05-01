//! WAL rotation + cross-segment integrity verification.
//!
//! Production audit requirement: `gvm audit verify` (which calls
//! `gvm_types::verify_integrity_chain`) must traverse the FULL
//! chain of `gvm.system.config_load` events, not just the events
//! in the currently-active WAL file. Real proxies rotate the WAL
//! at 100 MB; an audit run after a rotated session must still see
//! every config_load in the operator's history.
//!
//! Before this commit, `verify_integrity_chain(path)` opened only
//! `path` and ignored `path.1`, `path.2`, … so any integrity
//! context that landed in a rotated segment was invisible to the
//! verifier. The chain looked broken at the segment boundary.
//!
//! These tests run against the real ledger with max_wal_bytes set
//! low enough to force rotation, then assert verify_integrity_chain
//! reports the full population.
//!
//! Coverage:
//!   1. After rotation, every config_load event written to ANY
//!      segment is counted by verify_integrity_chain.
//!   2. The chain links across the rotation boundary verify
//!      cleanly (previous_state in segment N+1's first entry
//!      matches segment N's last config_hash).

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use std::time::Duration;

fn force_rotation_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    (dir, path)
}

// ════════════════════════════════════════════════════════════════
// 1. Cross-segment integrity verification observes ALL config_loads.
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn integrity_chain_spans_rotated_segments() {
    let (_dir, wal_path) = force_rotation_path();
    // Tiny rotation threshold so a few config_load events trip it.
    let config = GroupCommitConfig {
        batch_window: Duration::from_millis(1),
        max_batch_size: 16,
        channel_capacity: 1024,
        max_wal_bytes: 2_048,
        max_wal_segments: 100,
    };
    let mut ledger = Ledger::with_config(&wal_path, "", "", config)
        .await
        .expect("ledger init");

    // Write enough config_load events to span at least 2 rotated
    // segments + the active. Each config_load embeds an integrity
    // context with previous_state linking to the prior config_hash.
    // The ledger's record_config_load builds the chain for us.
    let cfg_a = std::env::temp_dir().join(format!("gvm-test-cfg-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(&cfg_a, "key=\"value\"").unwrap();
    let cfg_files = vec![("test_cfg".to_string(), cfg_a.clone())];
    let cfg_refs: Vec<(&str, &std::path::Path)> = cfg_files
        .iter()
        .map(|(l, p)| (l.as_str(), p.as_path()))
        .collect();

    let mut last_hash: Option<String> = None;
    const TOTAL: usize = 30;
    for _ in 0..TOTAL {
        let h = ledger
            .record_config_load(&cfg_refs, last_hash.clone())
            .await
            .expect("record_config_load must succeed");
        last_hash = Some(h);
        // Pad with junk events to bloat the WAL fast and force rotation.
        for _ in 0..3 {
            let evt = mk_evt();
            ledger.append_durable(&evt).await.ok();
        }
    }
    ledger.shutdown().await;

    // Confirm rotation actually happened: there must be at least one
    // wal.log.<N> file alongside the active wal.log.
    let parent = wal_path.parent().unwrap();
    let stem = wal_path.file_name().unwrap().to_string_lossy().into_owned();
    let mut rotated = 0usize;
    for entry in std::fs::read_dir(parent).unwrap().flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if s.starts_with(&format!("{}.", stem)) && s != stem {
            rotated += 1;
        }
    }
    assert!(
        rotated >= 1,
        "test could not force WAL rotation — adjust GVM_WAL_MAX_BYTES or \
         add more events. Found {} rotated segments.",
        rotated
    );

    // Two contracts the rotation-spanning verifier must honour:
    //   (a) total_config_loads observes every config_load across
    //       segments — proves segment scan works.
    //   (b) valid_links == total — proves the chain semantics
    //       (compare claimed_prev to previous event's context_hash,
    //       NOT its config_hash) match what production callers
    //       actually write into the WAL.
    let report = gvm_types::verify_integrity_chain(&wal_path);
    assert_eq!(
        report.total_config_loads, TOTAL,
        "verify_integrity_chain saw {} config_loads but {} were written; \
         rotated segments were not scanned. Active segment alone holds \
         only the most recent N events.",
        report.total_config_loads, TOTAL
    );
    assert_eq!(
        report.valid_links,
        TOTAL,
        "every link must validate across the rotation boundary (1 first + \
         {} chained); got {} valid links. previous_state ↔ context_hash \
         comparison may have drifted.",
        TOTAL - 1,
        report.valid_links
    );
    assert!(
        report.first_break.is_none(),
        "no chain break expected, got first_break = {:?}",
        report.first_break
    );

    let _ = std::fs::remove_file(cfg_a);
}

fn mk_evt() -> gvm_types::GVMEvent {
    gvm_types::GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: "rot-test".to_string(),
        tenant_id: None,
        session_id: "rot".to_string(),
        timestamp: chrono::Utc::now(),
        // Pad operation/path so each event is at least a few hundred bytes.
        operation: "gvm.test.padding.event.for.rotation".to_string(),
        resource: gvm_types::ResourceDescriptor {
            service: "padding-service-with-a-very-long-name-to-bloat-the-wal".to_string(),
            identifier: Some("padding-id-also-very-long-to-help-rotation-fire-quickly".into()),
            tier: gvm_types::ResourceTier::External,
            sensitivity: gvm_types::Sensitivity::Low,
        },
        context: std::collections::HashMap::new(),
        transport: Some(gvm_types::TransportInfo {
            method: "POST".to_string(),
            host: "padding-host-with-a-long-fqdn-to-bloat-the-wal.example.com".to_string(),
            path: "/v1/long/padding/path/to/help/rotation/fire/sooner".to_string(),
            status_code: None,
        }),
        decision: "Allow".to_string(),
        decision_source: "SRR".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: gvm_types::EventStatus::Confirmed,
        payload: gvm_types::PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}
