//! Phase E — End-to-end production-callsite descriptor coverage.
//!
//! `tests/descriptor_migration.rs` already pins that the helper
//! builders (`operation::http`, `operation::connect`, `operation::vault`,
//! `operation::dns_query`, `operation::ws_upgrade`,
//! `operation::category_only`) return correctly-shaped descriptors,
//! and that vault_write end-to-end writes a v2 record with the right
//! category. This file extends the end-to-end coverage to:
//!
//!   - DNS: `build_dns_event` → WAL line carries `gvm.dns.query`
//!     category and the queried domain as detail
//!   - Vault: `write` / `read` / `delete` / `list_keys` paths each
//!     emit a WAL line whose descriptor matches the operation
//!   - The redacted form (Standard) still recomputes the same
//!     event_hash as the unredacted form for every path — privacy
//!     invariant of Phase 1.A holds against real WAL records
//!   - The CheckpointInclusion is wired all the way to the JSON
//!     proof via `build_proof_with_checkpoint`
//!
//! HTTP / CONNECT / WebSocket-upgrade event paths are unit-tested in
//! `tests/descriptor_migration.rs` against the descriptor builder, and
//! E2E coverage requires spinning up the proxy (out of scope for an
//! integration-test pin — see `tests/integration.rs` and
//! `tests/mitm_streaming.rs` for real-traffic coverage).

use gvm_proxy::ledger::Ledger;
use gvm_types::{
    proof, redact_event, GVMEvent, GVMEventOrRedacted, OperationDescriptor, RedactionLevel,
};
use gvm_types::proof::recompute_event_hash_either;

fn read_events_with_op(wal_path: &std::path::Path, op: &str) -> Vec<GVMEvent> {
    let content = std::fs::read_to_string(wal_path).unwrap_or_default();
    content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l.trim()).ok())
        .filter(|e| e.operation == op)
        .collect()
}

// ────────────────────────────────────────────────────────────────────
// 1. DNS — build_dns_event populates a v2 descriptor
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dns_event_carries_descriptor_with_domain_as_detail() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    let event = gvm_proxy::ledger::build_dns_event(
        "customer-12345.attacker.example",
        "Suspicious",
        std::time::Duration::from_secs(2),
        7,
        42,
        300,
        "attacker.example",
    );
    ledger.append_durable(&event).await.unwrap();
    ledger.shutdown().await;

    let events = read_events_with_op(&wal_path, "gvm.dns.query");
    assert_eq!(events.len(), 1, "exactly 1 DNS event");
    let desc = events[0]
        .operation_descriptor
        .as_ref()
        .expect("DNS event MUST carry a v2 descriptor");
    assert_eq!(desc.category, "gvm.dns.query");
    assert_eq!(
        desc.detail.as_deref(),
        Some("customer-12345.attacker.example"),
        "DNS detail is the queried domain (subdomain may be PII)"
    );
    assert_eq!(desc.detail_salt.len(), 16, "salt must be 16 random bytes");
    assert!(desc.verify_digest(), "detail_digest must round-trip");
}

// ────────────────────────────────────────────────────────────────────
// 2. Vault — every operation emits a v2 descriptor
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vault_write_and_delete_carry_descriptors_in_durable_wal() {
    use gvm_proxy::vault::Vault;
    use std::sync::Arc;

    // NB: only write + delete go through `append_durable` (Merkle
    // chain). read + list_keys use `append_async` (NATS-only path,
    // doesn't reach the local WAL in MVP). Test pins the durable
    // path's descriptor presence; the async path's descriptor
    // construction is unit-pinned in tests/descriptor_migration.rs.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Vault::new(Arc::clone(&ledger)).expect("vault init");

    vault
        .write("agent-1:secret:0", b"plaintext", "agent-1")
        .await
        .expect("vault write");
    vault
        .delete("agent-1:secret:0", "agent-1")
        .await
        .expect("vault delete");

    drop(vault);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let events: Vec<GVMEvent> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l.trim()).ok())
        .filter(|e| e.operation.starts_with("gvm.vault."))
        .collect();

    // Expect exactly 2 durable events: write + delete.
    assert_eq!(events.len(), 2, "write + delete go through durable WAL");

    // Every vault event MUST carry a v2 descriptor with gvm.vault.* category.
    let mut saw_write = false;
    let mut saw_delete = false;
    for e in &events {
        let desc = e
            .operation_descriptor
            .as_ref()
            .expect("vault event MUST carry descriptor");
        assert!(
            desc.category.starts_with("gvm.vault."),
            "vault category must be gvm.vault.* (got {})",
            desc.category
        );
        assert_eq!(
            desc.detail.as_deref(),
            Some("agent-1:secret:0"),
            "vault detail is the key id"
        );
        assert_eq!(desc.detail_salt.len(), 16);
        assert!(desc.verify_digest());
        if desc.category == "gvm.vault.vault_write" {
            saw_write = true;
        }
        if desc.category == "gvm.vault.vault_delete" {
            saw_delete = true;
        }
    }
    assert!(saw_write, "vault_write descriptor present");
    assert!(saw_delete, "vault_delete descriptor present");
}

// ────────────────────────────────────────────────────────────────────
// 3. config_load — category-only descriptor with no detail leak
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn config_load_descriptor_is_category_only() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();
    ledger
        .record_config_load(&[], None)
        .await
        .expect("record_config_load");
    ledger.shutdown().await;

    let events = read_events_with_op(&wal_path, "gvm.system.config_load");
    assert_eq!(events.len(), 1);
    let desc = events[0]
        .operation_descriptor
        .as_ref()
        .expect("config_load event MUST carry a v2 descriptor");
    assert_eq!(desc.category, "gvm.system.config_load");
    assert!(
        desc.detail.is_none(),
        "config_load is category-only — no sensitive detail to leak"
    );
    assert!(
        desc.detail_salt.is_empty(),
        "category-only descriptor must have empty salt"
    );
}

// ────────────────────────────────────────────────────────────────────
// 4. Redaction privacy invariant — recompute survives strip
// ────────────────────────────────────────────────────────────────────

#[test]
fn redaction_preserves_event_hash_recompute_for_every_descriptor_kind() {
    // Build five sample events covering the descriptor kinds the
    // proxy actually writes: HTTP, CONNECT, WS upgrade, DNS, Vault,
    // category-only (config_load).
    let cases: Vec<(&str, OperationDescriptor)> = vec![
        ("http", gvm_proxy::operation::http("POST", "/api/v1/user/12345/delete")),
        ("connect", gvm_proxy::operation::connect("api.openai.com:443")),
        ("ws", gvm_proxy::operation::ws_upgrade("GET", "/v1/messages?stream=1")),
        ("dns", gvm_proxy::operation::dns_query("customer.example.com")),
        ("vault", gvm_proxy::operation::vault("vault_write", "agent-1:k:0")),
        ("category_only", gvm_proxy::operation::category_only("gvm.system.config_load")),
    ];

    for (label, descriptor) in cases {
        let event = build_canonical_event(&format!("evt-{}", label), descriptor);
        // Compute event_hash from the full form.
        let full_hash = recompute_event_hash_either(&GVMEventOrRedacted::Full(event.clone()));

        for level in [RedactionLevel::Standard, RedactionLevel::Strict] {
            let redacted = redact_event(&event, level);
            let redacted_hash = recompute_event_hash_either(&redacted);
            assert_eq!(
                full_hash, redacted_hash,
                "{} @ {:?}: redaction MUST preserve event_hash recompute",
                label, level
            );

            // Privacy assertion: redacted form has no detail/salt.
            if let GVMEventOrRedacted::Redacted(r) = redacted {
                if let Some(desc) = &r.operation_descriptor {
                    assert!(
                        desc.detail.is_none(),
                        "{} @ {:?}: detail MUST be stripped",
                        label,
                        level
                    );
                    assert!(
                        desc.detail_salt.is_empty(),
                        "{} @ {:?}: detail_salt MUST be stripped",
                        label,
                        level
                    );
                }
            }
        }
    }
}

fn build_canonical_event(id: &str, descriptor: OperationDescriptor) -> GVMEvent {
    use gvm_types::{EventStatus, PayloadDescriptor, ResourceDescriptor};
    use std::collections::HashMap;
    let mut event = GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "e2e-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test.op".to_string(),
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
        operation_descriptor: Some(descriptor),
    };
    // event_hash field is required for redacted-form recompute paths
    // that may consult it; populate explicitly.
    event.event_hash = Some(recompute_event_hash_either(&GVMEventOrRedacted::Full(event.clone())));
    event
}

// ────────────────────────────────────────────────────────────────────
// 5. CheckpointInclusion ships through the JSON proof
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn checkpoint_inclusion_round_trips_in_proof_json() {
    use gvm_proxy::checkpoint::CheckpointAggregator;
    use gvm_proxy::ledger::GroupCommitConfig;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Arc::new(
        Ledger::with_config(
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
        .unwrap(),
    );
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));

    // Register the agent's per-step checkpoint so the proof can carry inclusion.
    agg.register("agent", 0, [1u8; 32]).await.unwrap();
    agg.register("agent", 1, [2u8; 32]).await.unwrap();

    // Write an event under that agent so we have an event to bundle.
    let event = build_canonical_event("evt-ckpt-incl", gvm_proxy::operation::http("GET", "/x"));
    ledger.append_durable(&event).await.unwrap();

    let proof = gvm_proxy::proof::build_proof_with_checkpoint(
        &wal_path,
        "evt-ckpt-incl",
        RedactionLevel::Standard,
        &agg,
        1,
    )
    .await
    .expect("build_proof_with_checkpoint");

    drop(agg);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;

    // The proof carries a CheckpointInclusion. Round-trip via JSON.
    let json = serde_json::to_string_pretty(&proof).unwrap();
    let parsed: gvm_types::GvmProof = serde_json::from_str(&json).unwrap();
    let inc = parsed
        .checkpoint_inclusion
        .as_ref()
        .expect("proof must carry CheckpointInclusion when aggregator has it");
    assert_eq!(inc.agent_id, "agent");
    assert_eq!(inc.step, 1);
    assert_eq!(inc.checkpoint_hash.len(), 64);
    assert!(!inc.agent_path.is_empty(), "agent_path has at least one node");
    assert!(
        proof::verify_proof(&parsed, None).all_pass,
        "round-tripped proof with checkpoint inclusion must still verify all-pass"
    );
}
