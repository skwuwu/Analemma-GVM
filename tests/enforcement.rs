//! Tests for the unified governance classification pipeline (enforcement.rs).
//!
//! `classify()` is the single enforcement entry point shared by proxy_handler
//! and MITM TLS. These tests verify SRR integration, GVM header parsing,
//! catch-all detection, and error handling.

mod common;

use gvm_proxy::enforcement::{classify, ClassifyInput};
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use std::collections::HashMap;

// ── Helper: load SRR from inline TOML ──

fn srr_from_toml(toml: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml).unwrap();
    NetworkSRR::load(&path).unwrap()
}

// ═══════════════════════════════════════════════════════════════
// 1. Basic SRR classification
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn classify_allow_rule_returns_allow() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.github.com/repos/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.github.com",
        path: "/repos/test",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).expect("classify must succeed");
    assert!(matches!(
        output.classification.decision,
        EnforcementDecision::Allow
    ));
    assert!(!output.is_default_caution);
}

#[tokio::test]
async fn classify_deny_rule_returns_deny() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "DELETE"
pattern = "{host}.database.com/*"
[rules.decision]
type = "Deny"
reason = "Data deletion prohibited"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "DELETE",
        host: "prod.database.com",
        path: "/tables/users",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    assert!(matches!(
        output.classification.decision,
        EnforcementDecision::Deny { .. }
    ));
}

#[tokio::test]
async fn classify_delay_rule_preserves_milliseconds() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.slack.com/api/*"
[rules.decision]
type = "Delay"
milliseconds = 500
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "POST",
        host: "api.slack.com",
        path: "/api/chat.postMessage",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    match &output.classification.decision {
        EnforcementDecision::Delay { milliseconds } => assert_eq!(*milliseconds, 500),
        other => panic!("expected Delay, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════
// 2. Catch-all / Default-to-Caution detection
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn classify_catch_all_sets_default_caution_flag() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
description = "Catch-all"
[rules.decision]
type = "Delay"
milliseconds = 300
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "POST",
        host: "unknown-api.example.com",
        path: "/anything",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    assert!(
        output.is_default_caution,
        "catch-all match must set is_default_caution"
    );
}

#[tokio::test]
async fn classify_specific_rule_does_not_set_default_caution() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.github.com/*"
[rules.decision]
type = "Allow"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Delay"
milliseconds = 300
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.github.com",
        path: "/repos/test",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    assert!(
        !output.is_default_caution,
        "specific rule match must NOT set is_default_caution"
    );
}

// ═══════════════════════════════════════════════════════════════
// 3. GVM header extraction → OperationMetadata
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn classify_with_gvm_headers_populates_operation_metadata() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.openai.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let mut context = HashMap::new();
    context.insert("risk".to_string(), serde_json::json!("low"));

    let headers = GVMHeaders {
        operation: "gvm.llm.chat".to_string(),
        agent_id: "finance-bot".to_string(),
        tenant_id: Some("acme-corp".to_string()),
        session_id: Some("sess-123".to_string()),
        trace_id: "trace-abc".to_string(),
        event_id: "evt-1".to_string(),
        parent_event_id: None,
        rate_limit: None,
        resource: Some(ResourceDescriptor {
            service: "openai".to_string(),
            identifier: None,
            tier: ResourceTier::External,
            sensitivity: Sensitivity::Medium,
        }),
        context,
    };

    let input = ClassifyInput {
        method: "POST",
        host: "api.openai.com",
        path: "/v1/chat/completions",
        body: None,
        gvm_headers: Some(&headers),
    };

    let output = classify(&state, &input).unwrap();
    assert_eq!(output.agent_id, "finance-bot");

    let op = output
        .classification
        .operation
        .expect("operation metadata must be present");
    assert_eq!(op.operation, "gvm.llm.chat");
    assert_eq!(op.subject.agent_id, "finance-bot");
    assert_eq!(op.subject.tenant_id.as_deref(), Some("acme-corp"));
    assert_eq!(op.subject.session_id, "sess-123");
    assert_eq!(op.resource.service, "openai");
    assert!(matches!(op.resource.sensitivity, Sensitivity::Medium));
    assert_eq!(
        op.context.attributes.get("risk").and_then(|v| v.as_str()),
        Some("low")
    );
}

#[tokio::test]
async fn classify_sdk_metadata_cannot_downgrade_srr_deny() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/*"
[rules.decision]
type = "Deny"
reason = "wire transfers require out-of-band approval"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Delay"
milliseconds = 300
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let mut context = HashMap::new();
    context.insert("approved".to_string(), serde_json::json!(true));
    context.insert("risk".to_string(), serde_json::json!("low"));

    let headers = GVMHeaders {
        operation: "gvm.storage.read".to_string(),
        agent_id: "self-declared-safe-agent".to_string(),
        tenant_id: Some("tenant-a".to_string()),
        session_id: Some("session-a".to_string()),
        trace_id: "trace-a".to_string(),
        event_id: "event-a".to_string(),
        parent_event_id: None,
        rate_limit: None,
        resource: Some(ResourceDescriptor {
            service: "readonly-reporting".to_string(),
            identifier: Some("claimed-safe-resource".to_string()),
            tier: ResourceTier::Internal,
            sensitivity: Sensitivity::Low,
        }),
        context,
    };

    let input = ClassifyInput {
        method: "POST",
        host: "api.bank.com",
        path: "/transfer/123",
        body: None,
        gvm_headers: Some(&headers),
    };

    let output = classify(&state, &input).expect("classify must succeed");
    match &output.classification.decision {
        EnforcementDecision::Deny { reason } => assert!(
            reason.contains("wire transfers"),
            "SRR deny reason must be preserved"
        ),
        other => panic!("SDK metadata must not downgrade SRR Deny, got {:?}", other),
    }

    let op = output
        .classification
        .operation
        .expect("SDK metadata remains available for audit");
    assert_eq!(op.operation, "gvm.storage.read");
    assert_eq!(op.resource.service, "readonly-reporting");
    assert_eq!(
        op.context
            .attributes
            .get("approved")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn classify_without_gvm_headers_defaults_agent_id_to_unknown() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.github.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.github.com",
        path: "/repos/test",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    assert_eq!(output.agent_id, "unknown");
    assert!(
        output.classification.operation.is_none(),
        "no GVM headers => no operation metadata"
    );
}

#[tokio::test]
async fn classify_session_id_falls_back_to_trace_id() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.example.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let headers = GVMHeaders {
        operation: "test.op".to_string(),
        agent_id: "bot".to_string(),
        tenant_id: None,
        session_id: None, // not provided
        trace_id: "trace-fallback".to_string(),
        event_id: "evt-2".to_string(),
        parent_event_id: None,
        rate_limit: None,
        resource: None,
        context: HashMap::new(),
    };

    let input = ClassifyInput {
        method: "GET",
        host: "api.example.com",
        path: "/test",
        body: None,
        gvm_headers: Some(&headers),
    };

    let output = classify(&state, &input).unwrap();
    let op = output.classification.operation.unwrap();
    assert_eq!(
        op.subject.session_id, "trace-fallback",
        "session_id must fall back to trace_id"
    );
}

// ═══════════════════════════════════════════════════════════════
// 4. Classification source is always SRR
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn classify_source_is_always_srr() {
    let (state, _wal) = common::test_state().await;

    let input = ClassifyInput {
        method: "GET",
        host: "any.example.com",
        path: "/",
        body: None,
        gvm_headers: None,
    };

    let output = classify(&state, &input).unwrap();
    assert!(matches!(
        output.classification.source,
        ClassificationSource::SRR
    ));
}

// ═══════════════════════════════════════════════════════════════
// 5. SRR lock poisoned → error
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn classify_poisoned_srr_returns_error() {
    let (state, _wal) = common::test_state().await;

    // Poison the lock by panicking inside a write guard
    let srr_clone = state.srr.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = srr_clone.write().unwrap();
        panic!("intentional poison");
    }));

    let input = ClassifyInput {
        method: "GET",
        host: "any.com",
        path: "/",
        body: None,
        gvm_headers: None,
    };

    let result = classify(&state, &input);
    assert!(result.is_err(), "poisoned SRR lock must return Err");
    let err = result.err().unwrap();
    assert!(
        err.contains("poisoned"),
        "error should mention poisoned: {}",
        err
    );
}
