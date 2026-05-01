//! Production-callsite migration tests for `OperationDescriptor`.
//!
//! After this migration, every event-creation path in the proxy
//! populates `event.operation_descriptor: Some(...)` so that
//! `compute_event_hash` dispatches to the v2 algorithm. The
//! legacy `operation: String` field is preserved for v1-hash
//! backward compat (existing WAL records continue to verify), but
//! NEW events use v2 — privacy-preserving for redacted proofs.
//!
//! What this file pins:
//!   - HTTP fail-close events carry category="http.{METHOD}",
//!     detail=path
//!   - CONNECT Allow/Deny events carry category="http.CONNECT",
//!     detail=host
//!   - vault write/delete/read/list events carry
//!     category="gvm.vault.{op}", detail=key
//!   - DNS query events carry category="gvm.dns.query",
//!     detail=domain
//!   - config_load events carry category="gvm.system.config_load"
//!     (category-only — no sensitive detail)
//!   - For events with operation_descriptor=Some, compute_event_hash
//!     dispatches to v2 (different prefix, different output from v1)

use chrono::Utc;
use gvm_proxy::ledger::Ledger;
use gvm_types::{EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor};
use std::collections::HashMap;

// ────────────────────────────────────────────────────────────────────
// Common helper
// ────────────────────────────────────────────────────────────────────

fn evt(op: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-{}", op.replace(' ', "-")),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "descriptor-migration-test".to_string(),
        timestamp: Utc::now(),
        operation: op.to_string(),
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
        operation_descriptor: None,
    }
}

// ════════════════════════════════════════════════════════════════════
// Helper builders produce well-formed v2 descriptors
// ════════════════════════════════════════════════════════════════════

#[test]
fn http_helper_produces_v2_descriptor() {
    let d = gvm_proxy::operation::http("POST", "/api/v1/user/1234/delete");
    assert_eq!(d.category, "http.POST");
    assert_eq!(d.detail.as_deref(), Some("/api/v1/user/1234/delete"));
    assert_eq!(d.detail_salt.len(), 16);
    assert!(d.verify_digest());
}

#[test]
fn connect_helper_targets_host_as_detail() {
    let d = gvm_proxy::operation::connect("api.openai.com:443");
    assert_eq!(d.category, "http.CONNECT");
    assert_eq!(d.detail.as_deref(), Some("api.openai.com:443"));
}

#[test]
fn vault_helper_uses_key_as_detail() {
    let d = gvm_proxy::operation::vault("vault_write", "agent-1:checkpoint:7");
    assert_eq!(d.category, "gvm.vault.vault_write");
    assert_eq!(d.detail.as_deref(), Some("agent-1:checkpoint:7"));
}

#[test]
fn dns_query_helper_treats_domain_as_detail() {
    // Subdomains may carry PII (customer-12345.x.com). Redacted
    // proofs must NOT leak this — but verifier must still derive
    // event_hash from category + digest only.
    let d = gvm_proxy::operation::dns_query("customer-12345.attacker.example");
    assert_eq!(d.category, "gvm.dns.query");
    assert_eq!(d.detail.as_deref(), Some("customer-12345.attacker.example"));
}

#[test]
fn category_only_helper_has_empty_salt() {
    let d = gvm_proxy::operation::category_only("gvm.system.config_load");
    assert_eq!(d.category, "gvm.system.config_load");
    assert!(d.detail.is_none());
    assert!(d.detail_salt.is_empty());
}

// ────────────────────────────────────────────────────────────────────
// Dispatcher routes through v2 when descriptor is present
// ────────────────────────────────────────────────────────────────────

#[test]
fn dispatcher_uses_v2_when_event_has_http_descriptor() {
    let mut e = evt("POST /api/v1/x");
    e.operation_descriptor = Some(gvm_proxy::operation::http("POST", "/api/v1/x"));

    // Dispatcher (auto) versus explicit v2 must match.
    let dispatched = gvm_proxy::merkle::compute_event_hash(&e);
    let desc = e.operation_descriptor.as_ref().unwrap();
    let v2_explicit = gvm_proxy::merkle::compute_event_hash_v2(&e, desc);
    assert_eq!(dispatched, v2_explicit, "dispatcher must route to v2");

    // Confirm v2 produces a distinct value from v1 (so v2 was
    // actually used, not a coincidental same-bytes outcome).
    let mut e_v1 = e.clone();
    e_v1.operation_descriptor = None;
    let v1 = gvm_proxy::merkle::compute_event_hash(&e_v1);
    assert_ne!(dispatched, v1, "v2 must differ from v1 (prefix discipline)");
}

// ════════════════════════════════════════════════════════════════════
// Production paths emit v2 events end-to-end
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn config_load_writes_category_only_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::new(&wal_path, "", "").await.unwrap();

    ledger
        .record_config_load(&[], None)
        .await
        .expect("record_config_load must succeed");
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let event_lines: Vec<&str> = content
        .lines()
        .filter(|l| {
            l.contains("\"event_id\":")
                && !l.contains("\"merkle_root\"")
                && !l.contains("\"anchor_hash\"")
                && l.contains("config_load")
        })
        .collect();
    assert_eq!(event_lines.len(), 1, "exactly 1 config_load event");

    let event: GVMEvent = serde_json::from_str(event_lines[0]).unwrap();
    let desc = event
        .operation_descriptor
        .as_ref()
        .expect("config_load events MUST carry a descriptor");
    assert_eq!(desc.category, "gvm.system.config_load");
    assert!(
        desc.detail.is_none(),
        "config_load is category-only — no sensitive detail to redact"
    );
}

#[tokio::test]
async fn vault_write_writes_descriptor_with_key_as_detail() {
    use gvm_proxy::vault::Vault;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Vault::new(Arc::clone(&ledger)).expect("vault init");

    vault
        .write("agent-1:secret:0", b"plaintext", "agent-1")
        .await
        .expect("vault write must succeed");

    drop(vault);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let event_lines: Vec<&str> = content
        .lines()
        .filter(|l| {
            l.contains("\"event_id\":")
                && !l.contains("\"merkle_root\"")
                && !l.contains("\"anchor_hash\"")
                && l.contains("vault_write")
        })
        .collect();
    assert_eq!(event_lines.len(), 1, "exactly 1 vault_write event");

    let event: GVMEvent = serde_json::from_str(event_lines[0]).unwrap();
    let desc = event
        .operation_descriptor
        .as_ref()
        .expect("vault events MUST carry a descriptor");
    assert_eq!(desc.category, "gvm.vault.vault_write");
    assert_eq!(
        desc.detail.as_deref(),
        Some("agent-1:secret:0"),
        "vault key id is the detail"
    );
    assert_eq!(desc.detail_salt.len(), 16, "salt must be 16 bytes");
}
