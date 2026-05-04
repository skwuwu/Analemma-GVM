//! Tests for API handlers: /gvm/reload, /gvm/approve, /gvm/health.
//!
//! These exercise the handler functions directly with test AppState,
//! without starting a real HTTP server.

mod common;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use gvm_proxy::proxy::PendingApproval;
use gvm_proxy::srr::NetworkSRR;
use http_body_util::BodyExt;

// ── Helpers ──

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn srr_file(toml: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("srr_network.toml");
    std::fs::write(&path, toml).unwrap();
    (dir, path.to_string_lossy().into_owned())
}

// ═══════════════════════════════════════════════════════════════
// POST /gvm/reload
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn reload_srr_from_file_succeeds() {
    let (mut state, _wal) = common::test_state().await;

    // Write a valid SRR file and point state at it
    let (_dir, srr_path) = srr_file(
        r#"
[[rules]]
method = "GET"
pattern = "api.github.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    state.srr_config_path = srr_path;

    let resp = gvm_proxy::api::reload_srr(State(state.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["reloaded"], true);
    assert_eq!(json["srr_rules"], 1);

    // Side-effect assertion: the in-memory SRR has actually been
    // swapped — classify against the new rule and assert Allow. A
    // handler that returns 200 but never writes the lock would fail
    // this. (Without this, the reported `srr_rules == 1` could come
    // from any 1-rule set, including a stale one.)
    let result = state
        .srr
        .read()
        .unwrap()
        .check("GET", "api.github.com", "/repos", None);
    assert!(
        matches!(result.decision, gvm_types::EnforcementDecision::Allow),
        "after reload, the new Allow rule must apply; got {:?}",
        result.decision
    );
}

#[tokio::test]
async fn reload_srr_malformed_file_returns_bad_request() {
    let (mut state, _wal) = common::test_state().await;

    let (_dir, srr_path) = srr_file("this is {{ not valid toml");
    state.srr_config_path = srr_path;

    let resp = gvm_proxy::api::reload_srr(State(state)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["reloaded"], false);
    assert!(json["error"].as_str().unwrap().contains("SRR parse failed"));
}

#[tokio::test]
async fn reload_srr_missing_file_returns_bad_request() {
    let (mut state, _wal) = common::test_state().await;
    state.srr_config_path = "/nonexistent/srr.toml".to_string();

    let resp = gvm_proxy::api::reload_srr(State(state)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reload_srr_preserves_old_rules_on_failure() {
    // Start with 1 rule
    let (_dir1, srr_path1) = srr_file(
        r#"
[[rules]]
method = "GET"
pattern = "api.github.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let initial_srr = NetworkSRR::load(std::path::Path::new(&srr_path1)).unwrap();
    let (mut state, _wal) = common::test_state_with_srr(initial_srr).await;

    // Point at a bad file for reload
    let (_dir2, bad_path) = srr_file("not valid {{ toml");
    state.srr_config_path = bad_path;

    let resp = gvm_proxy::api::reload_srr(State(state.clone())).await;

    // Strong contract: failed reload must NOT return 200. A handler
    // that swallowed the parse error and returned 200 with empty
    // rules would silently regress.
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "failed reload must surface a 4xx, not silently succeed"
    );
    let json = body_json(resp).await;
    assert_eq!(json["reloaded"], false);

    // Original rules count must be preserved.
    let rule_count = state.srr.read().unwrap().rule_count();
    assert_eq!(
        rule_count, 1,
        "original rules must be preserved on failed reload"
    );

    // Original rule MUST still apply — pin the actual pattern, not
    // just count. Empty-rules-set with count==1 (somehow) would fail
    // here because the original Allow no longer applies.
    let result = state
        .srr
        .read()
        .unwrap()
        .check("GET", "api.github.com", "/repos", None);
    assert!(
        matches!(result.decision, gvm_types::EnforcementDecision::Allow),
        "post-failed-reload, original Allow rule for api.github.com/* must still apply; got {:?}",
        result.decision
    );
}

// ═══════════════════════════════════════════════════════════════
// POST /gvm/approve
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn approve_missing_event_id_returns_bad_request() {
    let (state, _wal) = common::test_state().await;

    let body = serde_json::json!({ "approved": true });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert!(json["error"].as_str().unwrap().contains("event_id"));
}

#[tokio::test]
async fn approve_unknown_event_id_returns_not_found() {
    let (state, _wal) = common::test_state().await;

    let body = serde_json::json!({
        "event_id": "nonexistent-123",
        "approved": true,
    });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_delivers_approval_to_pending_request() {
    let (state, _wal) = common::test_state().await;

    // Simulate a pending IC-3 request
    let (tx, rx) = tokio::sync::oneshot::channel();
    let event_id = "test-event-001".to_string();
    state.pending_approvals.insert(
        event_id.clone(),
        PendingApproval {
            sender: tx,
            event_id: event_id.clone(),
            operation: "test.op".to_string(),
            host: "api.example.com".to_string(),
            path: "/test".to_string(),
            method: "POST".to_string(),
            agent_id: "bot".to_string(),
            timestamp: chrono::Utc::now(),
        },
    );

    let body = serde_json::json!({
        "event_id": event_id,
        "approved": true,
    });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["decision"], "approved");

    // Verify the receiver got the decision
    let decision = rx.await.unwrap();
    assert!(decision, "receiver must get true for approval");
}

#[tokio::test]
async fn approve_delivers_denial_to_pending_request() {
    let (state, _wal) = common::test_state().await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let event_id = "test-event-002".to_string();
    state.pending_approvals.insert(
        event_id.clone(),
        PendingApproval {
            sender: tx,
            event_id: event_id.clone(),
            operation: "test.op".to_string(),
            host: "api.example.com".to_string(),
            path: "/test".to_string(),
            method: "POST".to_string(),
            agent_id: "bot".to_string(),
            timestamp: chrono::Utc::now(),
        },
    );

    let body = serde_json::json!({
        "event_id": event_id,
        "approved": false,
    });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["decision"], "denied");

    let decision = rx.await.unwrap();
    assert!(!decision, "receiver must get false for denial");
}

#[tokio::test]
async fn approve_default_is_deny_when_approved_field_missing() {
    let (state, _wal) = common::test_state().await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let event_id = "test-event-003".to_string();
    state.pending_approvals.insert(
        event_id.clone(),
        PendingApproval {
            sender: tx,
            event_id: event_id.clone(),
            operation: "test.op".to_string(),
            host: "api.example.com".to_string(),
            path: "/test".to_string(),
            method: "POST".to_string(),
            agent_id: "bot".to_string(),
            timestamp: chrono::Utc::now(),
        },
    );

    // No "approved" field → defaults to false (deny)
    let body = serde_json::json!({ "event_id": event_id });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let decision = rx.await.unwrap();
    assert!(
        !decision,
        "missing approved field must default to deny (fail-close)"
    );
}

#[tokio::test]
async fn approve_after_agent_disconnect_returns_gone() {
    let (state, _wal) = common::test_state().await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let event_id = "test-event-004".to_string();
    state.pending_approvals.insert(
        event_id.clone(),
        PendingApproval {
            sender: tx,
            event_id: event_id.clone(),
            operation: "test.op".to_string(),
            host: "api.example.com".to_string(),
            path: "/test".to_string(),
            method: "POST".to_string(),
            agent_id: "bot".to_string(),
            timestamp: chrono::Utc::now(),
        },
    );

    // Simulate agent disconnect by dropping the receiver
    drop(rx);

    let body = serde_json::json!({
        "event_id": event_id,
        "approved": true,
    });
    let resp = gvm_proxy::api::approve_request(State(state), axum::Json(body)).await;
    assert_eq!(resp.status(), StatusCode::GONE);

    let json = body_json(resp).await;
    assert_eq!(json["error"], "agent_disconnected");
}
