//! Phase 6 — Anchor signing.
//!
//! Pinned invariants:
//!   - `NoopSigner` (default): every anchor in the WAL has
//!     `signature: None`. Pre-Phase-6 ledgers behave identically.
//!   - `SelfSignedSigner`: every anchor in the WAL has
//!     `signature: Some(SelfSigned { key_id, signature })` and the
//!     signature verifies against the signer's `VerifyingKey`.
//!   - The signature is over `anchor_hash` (32 bytes) — tampering
//!     anchor fields breaks `verify_self_hash` first, so signature
//!     verification need only reproduce that the bytes signed match
//!     the bytes the auditor sees.
//!   - A signature signed by key A does NOT verify under key B
//!     (rejected via `verify_anchor_signature`).
//!   - `verify_anchor_chain` reports a non-zero `signed_anchor_count`
//!     when the WAL was written by a signing ledger. The chain itself
//!     remains valid in either signed or unsigned mode (signature is
//!     additive, not load-bearing for chain integrity).

use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_proxy::sign::{verify_anchor_signature, NoopSigner, SelfSignedSigner};
use gvm_types::{
    verify_anchor_chain, AnchorAuditConfig, AnchorSignature, EventStatus, GVMEvent, GvmStateAnchor,
    PayloadDescriptor, ResourceDescriptor,
};
use std::collections::HashMap;
use std::sync::Arc;

fn evt(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent".to_string(),
        tenant_id: None,
        session_id: "signing-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test".to_string(),
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

fn one_event_per_batch() -> GroupCommitConfig {
    GroupCommitConfig {
        batch_window: std::time::Duration::ZERO,
        max_batch_size: 1,
        channel_capacity: 16,
        max_wal_bytes: 0,
        max_wal_segments: 0,
    }
}

#[tokio::test]
async fn default_ledger_uses_noop_signer_no_signatures_in_wal() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    for i in 0..3 {
        ledger
            .append_durable(&evt(&format!("e{}", i)))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(anchors.len(), 3);
    for a in &anchors {
        assert!(
            a.signature.is_none(),
            "default ledger (NoopSigner) MUST leave signature: None"
        );
    }
}

#[tokio::test]
async fn explicit_noop_signer_matches_default_behavior() {
    // Pin: passing NoopSigner explicitly must be observationally
    // identical to omitting the signer.
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config_and_signer(
        &wal_path,
        "",
        "",
        one_event_per_batch(),
        Arc::new(NoopSigner),
    )
    .await
    .unwrap();
    ledger.append_durable(&evt("e1")).await.unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchor: GvmStateAnchor = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap();
    assert!(anchor.signature.is_none());
}

#[tokio::test]
async fn self_signed_ledger_writes_verifiable_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let signer = SelfSignedSigner::generate("gvm-test-key");
    let verifying_key = signer.verifying_key();

    let mut ledger =
        Ledger::with_config_and_signer(&wal_path, "", "", one_event_per_batch(), Arc::new(signer))
            .await
            .unwrap();
    for i in 0..3 {
        ledger
            .append_durable(&evt(&format!("e{}", i)))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchors: Vec<GvmStateAnchor> = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(anchors.len(), 3);

    for a in &anchors {
        let sig = a
            .signature
            .as_ref()
            .expect("self-signed ledger MUST attach signature to every anchor");
        match sig {
            AnchorSignature::SelfSigned { key_id, signature } => {
                assert_eq!(key_id, "gvm-test-key");
                assert_eq!(signature.len(), 64, "Ed25519 signatures are 64 bytes");
            }
            other => panic!("expected SelfSigned, got {:?}", other),
        }

        // Verify each signature against the public key the operator
        // would have stored in their auditor's registry.
        let anchor_hash_bytes: [u8; 32] = hex::decode(&a.anchor_hash).unwrap().try_into().unwrap();
        verify_anchor_signature(&anchor_hash_bytes, sig, &verifying_key)
            .expect("anchor signature must verify against the signer's public key");
    }
}

#[tokio::test]
async fn signature_does_not_verify_under_unrelated_key() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let signer_a = SelfSignedSigner::generate("a");
    let signer_b = SelfSignedSigner::generate("b");

    let mut ledger = Ledger::with_config_and_signer(
        &wal_path,
        "",
        "",
        one_event_per_batch(),
        Arc::new(signer_a),
    )
    .await
    .unwrap();
    ledger.append_durable(&evt("e1")).await.unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchor: GvmStateAnchor = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap();
    let sig = anchor.signature.as_ref().unwrap();
    let anchor_hash_bytes: [u8; 32] = hex::decode(&anchor.anchor_hash)
        .unwrap()
        .try_into()
        .unwrap();

    let result = verify_anchor_signature(&anchor_hash_bytes, sig, &signer_b.verifying_key());
    assert!(
        result.is_err(),
        "signature signed by key A must NOT verify under key B"
    );
}

#[tokio::test]
async fn tampered_anchor_hash_breaks_signature_verification() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let signer = SelfSignedSigner::generate("k");
    let verifying_key = signer.verifying_key();

    let mut ledger =
        Ledger::with_config_and_signer(&wal_path, "", "", one_event_per_batch(), Arc::new(signer))
            .await
            .unwrap();
    ledger.append_durable(&evt("e1")).await.unwrap();
    ledger.shutdown().await;

    let content = std::fs::read_to_string(&wal_path).unwrap();
    let anchor: GvmStateAnchor = content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap();
    let sig = anchor.signature.as_ref().unwrap();

    // Mutate the hash bytes — the signature was over the unmodified hash.
    let mut tampered_hash: [u8; 32] = hex::decode(&anchor.anchor_hash)
        .unwrap()
        .try_into()
        .unwrap();
    tampered_hash[0] ^= 0xff;

    assert!(
        verify_anchor_signature(&tampered_hash, sig, &verifying_key).is_err(),
        "signature must NOT verify against a mutated hash"
    );
}

#[tokio::test]
async fn audit_reports_signed_anchor_count_after_signing_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let signer = SelfSignedSigner::generate("k");

    let mut ledger =
        Ledger::with_config_and_signer(&wal_path, "", "", one_event_per_batch(), Arc::new(signer))
            .await
            .unwrap();
    for i in 0..4 {
        ledger
            .append_durable(&evt(&format!("e{}", i)))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 4);
    assert_eq!(
        report.signed_anchor_count, 4,
        "every anchor was signed → signed_anchor_count must equal total_anchors"
    );
    assert!(
        report.first_break.is_none(),
        "signed chain must still verify clean. first_break={:?}",
        report.first_break,
    );
}

#[tokio::test]
async fn audit_reports_zero_signed_count_for_noop_signer() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Ledger::with_config(&wal_path, "", "", one_event_per_batch())
        .await
        .unwrap();
    for i in 0..2 {
        ledger
            .append_durable(&evt(&format!("e{}", i)))
            .await
            .unwrap();
    }
    ledger.shutdown().await;

    let report = verify_anchor_chain(&wal_path, &AnchorAuditConfig::default());
    assert_eq!(report.total_anchors, 2);
    assert_eq!(
        report.signed_anchor_count, 0,
        "NoopSigner WAL: signed_anchor_count must be 0"
    );
}
