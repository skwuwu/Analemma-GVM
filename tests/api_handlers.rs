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

// ═══════════════════════════════════════════════════════════════
// POST /gvm/sandbox/launch  +  GET /gvm/sandbox/:id/ca.pem
// +  DELETE /gvm/sandbox/:id   (CA-3 — per-sandbox MITM CA)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sandbox_launch_provisions_ca_and_returns_pem() {
    let (state, _wal) = common::test_state().await;

    let req = serde_json::json!({
        "sandbox_id": "sb-launch-test-1",
        "agent_id": "agent-x",
    });
    let resp = gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["sandbox_id"], "sb-launch-test-1");
    let pem = json["ca_pem"].as_str().expect("ca_pem string");
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "ca_pem must be a real PEM cert, got: {}",
        &pem[..pem.len().min(60)]
    );
    let pubkey_hash = json["ca_pubkey_hash"].as_str().expect("hash present");
    assert_eq!(pubkey_hash.len(), 64, "SHA-256 hex");
    assert!(json["launch_event_id"].is_string());
    assert!(json["ca_not_after"].is_string());

    // Registry now holds this sandbox's CA.
    assert!(state.ca_registry.lookup("sb-launch-test-1").is_some());
}

#[tokio::test]
async fn sandbox_launch_rejects_empty_ids() {
    let (state, _wal) = common::test_state().await;

    let req = serde_json::json!({
        "sandbox_id": "",
        "agent_id": "agent",
    });
    let resp = gvm_proxy::api::sandbox_launch(
        State(state),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sandbox_ca_pem_returns_same_cert_after_launch() {
    let (state, _wal) = common::test_state().await;

    // Launch.
    let launch_req = serde_json::json!({
        "sandbox_id": "sb-pem-test",
        "agent_id": "agent",
    });
    let launch_resp = gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(launch_req).unwrap()),
    )
    .await;
    assert_eq!(launch_resp.status(), StatusCode::OK);
    let launch_json = body_json(launch_resp).await;
    let launch_pem = launch_json["ca_pem"].as_str().unwrap().to_string();
    let launch_hash = launch_json["ca_pubkey_hash"].as_str().unwrap().to_string();

    // Re-fetch via GET. Same bytes, same hash header.
    let resp = gvm_proxy::api::sandbox_ca_pem(
        axum::extract::Path("sb-pem-test".to_string()),
        State(state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("X-GVM-CA-Pubkey-Hash").unwrap(),
        launch_hash.as_str()
    );

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8_lossy(&bytes), launch_pem);
}

#[tokio::test]
async fn sandbox_ca_pem_404_for_unknown_sandbox() {
    let (state, _wal) = common::test_state().await;
    let resp = gvm_proxy::api::sandbox_ca_pem(
        axum::extract::Path("sb-does-not-exist".to_string()),
        State(state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sandbox_revoke_removes_from_registry() {
    let (state, _wal) = common::test_state().await;

    let launch_req = serde_json::json!({
        "sandbox_id": "sb-revoke-test",
        "agent_id": "agent",
    });
    gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(launch_req).unwrap()),
    )
    .await;
    assert!(state.ca_registry.lookup("sb-revoke-test").is_some());

    let resp = gvm_proxy::api::sandbox_revoke(
        axum::extract::Path("sb-revoke-test".to_string()),
        State(state.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["revoked"], true);

    // Subsequent lookup misses.
    assert!(state.ca_registry.lookup("sb-revoke-test").is_none());
}

#[tokio::test]
async fn sandbox_revoke_is_idempotent_for_unknown_sandbox() {
    let (state, _wal) = common::test_state().await;
    // No launch — revoke should still 200 OK.
    let resp = gvm_proxy::api::sandbox_revoke(
        axum::extract::Path("sb-never-existed".to_string()),
        State(state),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── #1 visibility: actionable error headers on block responses ──

#[tokio::test]
async fn governance_block_response_emits_matched_rule_header() {
    use gvm_proxy::types::{BlockResponseMode, GovernanceBlockResponse};

    let block = GovernanceBlockResponse {
        blocked: true,
        decision: "Deny".to_string(),
        event_id: "evt-1".to_string(),
        trace_id: "trace-1".to_string(),
        operation: "POST api.bank.com/transfer".to_string(),
        reason: "above transfer limit".to_string(),
        mode: BlockResponseMode::Halt,
        next_action: "Contact admin".to_string(),
        retry_after_secs: None,
        rollback_hint: None,
        matched_rule_id: Some("finance-002".to_string()),
        policy_link: Some("https://gvm-console/rules/finance-002".to_string()),
        ic_level: 4,
    };
    // Round-trip via the JSON body — confirms Serialize emits both
    // new fields and the older shape stays compatible.
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["matched_rule_id"], "finance-002");
    assert_eq!(json["policy_link"], "https://gvm-console/rules/finance-002");

    // Schema regression: with policy_link=None and matched_rule_id=None,
    // both fields are skipped in serialization (strict-JSON-schema
    // consumers shouldn't see literal nulls).
    let block_minimal = GovernanceBlockResponse {
        matched_rule_id: None,
        policy_link: None,
        ..block
    };
    let json_min = serde_json::to_value(&block_minimal).unwrap();
    assert!(json_min.get("matched_rule_id").is_none());
    assert!(json_min.get("policy_link").is_none());
}

#[test]
fn build_policy_link_substitutes_rule_id() {
    use gvm_proxy::test_helpers::build_policy_link_for_test;
    assert_eq!(
        build_policy_link_for_test(Some("https://console/rules/{rule_id}"), Some("finance-002")),
        Some("https://console/rules/finance-002".to_string()),
    );
}

#[test]
fn build_policy_link_returns_none_without_template() {
    use gvm_proxy::test_helpers::build_policy_link_for_test;
    assert!(build_policy_link_for_test(None, Some("finance-002")).is_none());
}

#[test]
fn build_policy_link_returns_none_without_rule_id() {
    use gvm_proxy::test_helpers::build_policy_link_for_test;
    assert!(build_policy_link_for_test(Some("https://x/{rule_id}"), None).is_none());
}

// ── CA-6 part 2: parent_event_id auto-wiring ──

#[tokio::test]
async fn resolve_sandbox_anchor_returns_none_for_loopback() {
    let (state, _wal) = common::test_state().await;
    // Loopback peer is the cooperative-mode signature — never a sandbox.
    let anchor = state.resolve_sandbox_anchor(Some("127.0.0.1".parse().unwrap()));
    assert!(anchor.is_none());
}

#[tokio::test]
async fn resolve_sandbox_anchor_returns_none_when_peer_unknown() {
    // Non-loopback IP that doesn't match any state file → None.
    // Caller falls back to the legacy unverified-identity path.
    let (state, _wal) = common::test_state().await;
    let anchor = state.resolve_sandbox_anchor(Some("10.200.99.99".parse().unwrap()));
    assert!(anchor.is_none());
}

#[tokio::test]
async fn resolve_sandbox_anchor_uses_per_sandbox_metadata() {
    // The Linux-only path goes through gvm_sandbox::lookup_sandbox_id_by_ip
    // which scans /run/gvm/*.state files — those don't exist in test
    // setup. So we can't exercise the *full* lookup path in a unit
    // test. What we CAN verify here is that, given metadata is
    // present in the registry, the AppState helper composes correctly:
    // the metadata stored at sandbox_launch time is the same shape
    // resolve_sandbox_anchor reads back.
    let (state, _wal) = common::test_state().await;
    let req = serde_json::json!({"sandbox_id": "sb-anchor", "agent_id": "agent-anchor"});
    gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;

    // Read metadata directly to verify the shape that resolve_sandbox_anchor
    // would compose for a Linux peer hit. The agent_id and launch_event_id
    // are what get stamped on subsequent enforcement events.
    let metadata = state
        .per_sandbox_metadata
        .get("sb-anchor")
        .expect("metadata recorded by sandbox_launch");
    assert_eq!(metadata.agent_id, "agent-anchor");
    assert!(metadata.launch_event_id.len() > 8); // UUID-ish
                                                 // (launched_at is a chrono::DateTime — presence implied by struct
                                                 // construction, no further assertion needed.)
}

// ── CA-7: gvm sandbox list ──

#[tokio::test]
async fn sandbox_list_empty_when_no_launches() {
    let (state, _wal) = common::test_state().await;
    let resp = gvm_proxy::api::sandbox_list(State(state)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["active"], 0);
    assert!(json["sandboxes"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn sandbox_list_includes_launched_sandboxes_with_metadata() {
    let (state, _wal) = common::test_state().await;

    // Launch two sandboxes — they should both appear.
    for (sid, aid) in [("sb-list-1", "analyst"), ("sb-list-2", "coder")] {
        let req = serde_json::json!({"sandbox_id": sid, "agent_id": aid});
        let resp = gvm_proxy::api::sandbox_launch(
            State(state.clone()),
            axum::Json(serde_json::from_value(req).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let resp = gvm_proxy::api::sandbox_list(State(state.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["active"], 2);

    let sandboxes = json["sandboxes"].as_array().unwrap();
    let by_id: std::collections::HashMap<&str, &serde_json::Value> = sandboxes
        .iter()
        .map(|v| (v["sandbox_id"].as_str().unwrap(), v))
        .collect();

    let entry_1 = by_id.get("sb-list-1").expect("sb-list-1 present");
    assert_eq!(entry_1["agent_id"], "analyst");
    assert_eq!(entry_1["ca_pubkey_hash"].as_str().unwrap().len(), 64);
    assert!(entry_1["launch_event_id"].as_str().unwrap().len() > 8);
    assert!(entry_1["launched_at"].as_str().unwrap().contains("T")); // RFC 3339

    let entry_2 = by_id.get("sb-list-2").expect("sb-list-2 present");
    assert_eq!(entry_2["agent_id"], "coder");
    assert_ne!(
        entry_1["ca_pubkey_hash"], entry_2["ca_pubkey_hash"],
        "each sandbox has its own CA — pubkey hashes must differ (CA-7 inspect surface for the property CA-4 enforces)"
    );
}

#[tokio::test]
async fn sandbox_list_drops_revoked_sandboxes() {
    let (state, _wal) = common::test_state().await;
    let req = serde_json::json!({"sandbox_id": "sb-temp", "agent_id": "x"});
    gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;

    state.revoke_sandbox("sb-temp");

    let resp = gvm_proxy::api::sandbox_list(State(state)).await;
    let json = body_json(resp).await;
    assert_eq!(json["active"], 0);
    assert!(json["sandboxes"].as_array().unwrap().is_empty());
}

// ── CA-4: per-sandbox TLS bundle routing ──

#[tokio::test]
async fn tls_bundle_for_sandbox_returns_none_for_unregistered() {
    let (state, _wal) = common::test_state().await;
    assert!(
        state.tls_bundle_for_sandbox("sb-not-launched").is_none(),
        "no CA registered for this sandbox → fallback to legacy path"
    );
    assert!(state.per_sandbox_tls.is_empty());
}

#[tokio::test]
async fn tls_bundle_for_sandbox_lazy_builds_and_caches() {
    let (state, _wal) = common::test_state().await;

    // Provision via the launch endpoint so the audit chain is honored.
    let req = serde_json::json!({
        "sandbox_id": "sb-tls-cache",
        "agent_id": "agent",
    });
    let resp = gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // First call: cache miss → builds resolver + ServerConfig.
    let (r1, sc1) = state
        .tls_bundle_for_sandbox("sb-tls-cache")
        .expect("registered sandbox returns Some");
    assert_eq!(state.per_sandbox_tls.len(), 1);

    // Second call: cache hit → same Arcs.
    let (r2, sc2) = state
        .tls_bundle_for_sandbox("sb-tls-cache")
        .expect("cached");
    assert!(
        std::sync::Arc::ptr_eq(&r1, &r2),
        "cached resolver Arc must be reused (same allocation)"
    );
    assert!(
        std::sync::Arc::ptr_eq(&sc1, &sc2),
        "cached ServerConfig Arc must be reused"
    );
}

#[tokio::test]
async fn revoke_sandbox_clears_tls_bundle_cache() {
    let (state, _wal) = common::test_state().await;

    let req = serde_json::json!({
        "sandbox_id": "sb-revoke-cache",
        "agent_id": "agent",
    });
    gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;
    // Populate the bundle cache.
    let _ = state
        .tls_bundle_for_sandbox("sb-revoke-cache")
        .expect("present");
    assert_eq!(state.per_sandbox_tls.len(), 1);

    // Revoke through the AppState helper — drops both registry and cache.
    state.revoke_sandbox("sb-revoke-cache");
    assert!(state.ca_registry.lookup("sb-revoke-cache").is_none());
    assert!(
        state.per_sandbox_tls.is_empty(),
        "revoke must clear the per-sandbox TLS bundle cache so a \
         later provision with the same sandbox_id cannot serve a leaf \
         signed by the previous CA"
    );

    // After revoke, lookup misses (cache empty + registry empty).
    assert!(state.tls_bundle_for_sandbox("sb-revoke-cache").is_none());
}

#[tokio::test]
async fn per_sandbox_resolvers_have_distinct_ca_pubkey_hashes() {
    // The promised property of CA-4: two sandboxes get cryptographically
    // independent CAs, and the resolver each uses to sign leaves is
    // bound to the right one.
    let (state, _wal) = common::test_state().await;

    for id in ["sb-iso-A", "sb-iso-B"] {
        let req = serde_json::json!({"sandbox_id": id, "agent_id": "agent"});
        let resp = gvm_proxy::api::sandbox_launch(
            State(state.clone()),
            axum::Json(serde_json::from_value(req).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Different SandboxCAs imply different pubkey hashes (already
    // covered in the gvm-sandbox unit tests). Here we additionally
    // assert that the lazy bundle build produces *different*
    // ServerConfig Arcs for different sandboxes — i.e. they are not
    // accidentally pulling from the legacy shared resolver.
    let (_r_a, sc_a) = state.tls_bundle_for_sandbox("sb-iso-A").unwrap();
    let (_r_b, sc_b) = state.tls_bundle_for_sandbox("sb-iso-B").unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&sc_a, &sc_b),
        "per-sandbox ServerConfigs must be distinct allocations \
         (otherwise sandbox B's TLS handshake would be served by \
         sandbox A's CA — exactly the blast-radius bug CA-4 prevents)"
    );

    let ca_a = state.ca_registry.lookup("sb-iso-A").unwrap();
    let ca_b = state.ca_registry.lookup("sb-iso-B").unwrap();
    assert_ne!(
        ca_a.pubkey_hash(),
        ca_b.pubkey_hash(),
        "fresh keypair per sandbox"
    );
}

#[tokio::test]
async fn sandbox_launch_writes_durable_audit_event() {
    let (state, wal_path) = common::test_state().await;

    let req = serde_json::json!({
        "sandbox_id": "sb-audit-test",
        "agent_id": "agent-audit",
    });
    let resp = gvm_proxy::api::sandbox_launch(
        State(state.clone()),
        axum::Json(serde_json::from_value(req).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let event_id = json["launch_event_id"].as_str().unwrap().to_string();
    let pubkey_hash = json["ca_pubkey_hash"].as_str().unwrap().to_string();

    // Drop state so the ledger flushes its batch on shutdown.
    drop(state);
    // Small wait for the batch loop to drain. The default batch
    // window is short; `drop(state)` triggers shutdown which fsyncs
    // pending events. A 200ms wait is conservative.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read WAL and find a record with our event_id.
    let content = std::fs::read_to_string(&wal_path).unwrap();

    let found = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["event_id"] == event_id.as_str());
    let event = found.expect("sandbox launch event must be in WAL");

    assert_eq!(event["operation"], "gvm.sandbox.launch");
    assert_eq!(event["agent_id"], "agent-audit");
    assert_eq!(event["session_id"], "sb-audit-test");
    assert_eq!(event["context"]["sandbox_id"], "sb-audit-test");
    assert_eq!(event["context"]["ca_pubkey_hash"], pubkey_hash);
    assert_eq!(event["context"]["tls_inspection"], "active");
    assert!(event["parent_event_id"].is_null(), "launch is chain root");
}
