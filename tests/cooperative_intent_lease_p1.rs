//! Cooperative intent lease — P1 follow-up regression suite.
//!
//! Pins the four P1 items from the regulated-target review:
//!
//!   - **H5** `requires_observed_body`: lease opts in to strict
//!     cross-check. Visible HTTP request without an observed body
//!     (chunked / oversized / inspection disabled / MITM-blind)
//!     MUST Deny rather than fall through to declared-only.
//!   - **H6** lease metadata propagation: the final HTTP-decision
//!     WAL event's `context` map carries `cooperative.intent_id`,
//!     `cooperative.claim_id`, `cooperative.payload_context_hash`,
//!     and (on cross-checked) `cooperative.observed_payload_hash`
//!     so an auditor can correlate this decision back to the
//!     earlier `gvm.intent.lease_issued` event.
//!   - **H7** `gvm.intent.lease_denied` WAL event: preflight Deny
//!     leaves a durable audit row instead of being silently dropped.
//!   - **H8** claim-time principal binding: a token presented under
//!     a different agent_id than the one in the lease MUST Deny
//!     as `cooperative.mismatch`. Closes the "token-theft" angle
//!     where agent A sniffs / receives agent B's token.
//!
//! The lifecycle / Phase tests cover the happy-path machinery;
//! this file only exercises the new P1 behaviours.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gvm_proxy::intent_store::IntentRequest;
use std::sync::Arc;
use tower::ServiceExt;

// ─── Helpers ─────────────────────────────────────────────────────────────

async fn spawn_recording_upstream() -> std::net::SocketAddr {
    let upstream_app = axum::Router::new().fallback(|_req: Request<Body>| async move {
        axum::http::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"upstream_received":true}"#))
            .expect("upstream response must build")
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().expect("upstream local_addr");
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });
    addr
}

async fn issue_lease(state: &gvm_proxy::proxy::AppState, req: IntentRequest) -> String {
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::Json;
    let resp =
        gvm_proxy::api::register_intent(State(state.clone()), HeaderMap::new(), Json(req)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = common::body_json(resp).await;
    json["context_token"]
        .as_str()
        .expect("response must carry context_token")
        .to_string()
}

fn proxy_app(
    state: gvm_proxy::proxy::AppState,
    upstream_addr: std::net::SocketAddr,
    payload_inspection: bool,
) -> (Router, gvm_proxy::proxy::AppState) {
    let mut state = state;
    state.host_overrides.insert(
        "api.bank.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );
    state.payload_inspection = payload_inspection;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state.clone());
    (app, state)
}

fn lease(
    agent_id: &str,
    payload_hash: Option<String>,
    requires_observed_body: bool,
) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: agent_id.to_string(),
        ttl_secs: Some(60),
        payload_context: Some(serde_json::json!({"amount": 100, "currency": "USD"})),
        payload_hash,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body,
    }
}

fn proxy_request(method: &str, path: &str, token: Option<&str>, agent_id: &str) -> Request<Body> {
    let body_bytes = br#"{"amount":100,"currency":"USD"}"#;
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("X-GVM-Agent-Id", agent_id)
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-p1")
        .header("X-GVM-Event-Id", "evt-p1")
        .header("Content-Type", "application/json")
        .header("Content-Length", body_bytes.len().to_string());
    if let Some(t) = token {
        builder = builder.header("X-GVM-Context-Token", t);
    }
    builder
        .body(Body::from(&body_bytes[..]))
        .expect("request must build")
}

fn decision_source(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("X-GVM-Decision-Source")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn hash_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    format!("sha256:{}", hex::encode(h.finalize()))
}

// ─── H8: claim-time principal binding ──────────────────────────────────

#[tokio::test]
async fn h8_token_presented_under_wrong_agent_id_denies_mismatch() {
    // Agent A registers a lease; agent B sniffs the token and sends
    // a request under their own X-GVM-Agent-Id header. Without the
    // H8 check, B would inherit A's authorization. The fix Denies
    // with `cooperative.mismatch`.
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, false);
    let token = issue_lease(&state, lease("agent-A", None, false)).await;

    // B presents A's token under B's own agent_id.
    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token), "agent-B"))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        decision_source(&resp),
        "cooperative.mismatch",
        "token presented under a different agent_id must Deny"
    );
}

#[tokio::test]
async fn h8_token_presented_under_correct_agent_id_allows() {
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, false);
    let token = issue_lease(&state, lease("agent-A", None, false)).await;

    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token), "agent-A"))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp), "cooperative.declared_only");
}

// ─── H5: requires_observed_body ────────────────────────────────────────

#[tokio::test]
async fn h5_requires_observed_body_with_inspection_off_denies() {
    // Lease opts in to `requires_observed_body` AND declares a
    // payload_hash. Proxy has payload_inspection=false so it
    // CANNOT buffer the body. Must Deny with `cooperative.mismatch`,
    // not fall to declared-only.
    let body = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, /* payload_inspection */ false);
    let token = issue_lease(
        &state,
        lease(
            "agent-strict",
            Some(hash_hex(body)),
            /* requires_observed_body */ true,
        ),
    )
    .await;

    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some(&token),
            "agent-strict",
        ))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        decision_source(&resp),
        "cooperative.mismatch",
        "requires_observed_body + no observation must Deny — \
         the chunked/streaming evasion the review flagged"
    );
}

#[tokio::test]
async fn h5_requires_observed_body_with_inspection_on_succeeds() {
    let body = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, /* payload_inspection */ true);
    let token = issue_lease(&state, lease("agent-strict", Some(hash_hex(body)), true)).await;

    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some(&token),
            "agent-strict",
        ))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        decision_source(&resp),
        "cooperative.cross_checked",
        "with inspection enabled and matching body, cross-check upgrades to cross_checked"
    );
}

#[tokio::test]
async fn h5_without_opt_in_inspection_off_falls_to_declared_only() {
    // Default-strict behaviour unchanged: WITHOUT requires_observed_body,
    // inspection off + payload_hash declared → DeclaredOnly (the
    // operator chose not to require cross-check).
    let body = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, false);
    let token = issue_lease(
        &state,
        lease(
            "agent-default",
            Some(hash_hex(body)),
            /* opt-in */ false,
        ),
    )
    .await;

    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some(&token),
            "agent-default",
        ))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        decision_source(&resp),
        "cooperative.declared_only",
        "no opt-in → declared-only is the legitimate fallback"
    );
}

// ─── H6: lease metadata propagation ──────────────────────────────────────

#[tokio::test]
async fn h6_final_wal_event_carries_lease_metadata() {
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr, false);
    let token = issue_lease(&state, lease("agent-meta", None, false)).await;

    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some(&token),
            "agent-meta",
        ))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);

    // The response body is the upstream JSON, not the WAL event. To
    // verify metadata propagated, dump the WAL directly. The WAL is
    // a JSON-lines file at the test wal_path.
    let wal_bytes = std::fs::read_to_string(&state.wal_path).expect("read WAL");
    let final_event = wal_bytes
        .lines()
        .rev()
        .find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            // The final HTTP-decision event has decision_source
            // "cooperative.declared_only" and operation that ISN'T
            // `gvm.intent.lease_issued`.
            if v["decision_source"] == "cooperative.declared_only"
                && v["operation"] != "gvm.intent.lease_issued"
            {
                Some(v)
            } else {
                None
            }
        })
        .expect("WAL must contain final HTTP-decision event");

    let ctx = &final_event["context"];
    assert!(
        ctx["cooperative.intent_id"].as_u64().is_some(),
        "final WAL event must carry cooperative.intent_id (audit link to lease_issued)"
    );
    assert!(
        ctx["cooperative.claim_id"].as_u64().is_some(),
        "final WAL event must carry cooperative.claim_id"
    );
    assert!(
        ctx["cooperative.payload_context_hash"]
            .as_str()
            .unwrap_or("")
            .starts_with("sha256:"),
        "final WAL event must carry cooperative.payload_context_hash"
    );
    // observed_payload_hash is None for declared-only path → field
    // omitted in the context map.
}

// ─── H7: lease_denied WAL event ──────────────────────────────────────────

#[tokio::test]
async fn h7_preflight_deny_emits_lease_denied_event() {
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::Json;

    let (state, _wal) = common::test_state().await;
    // Inject a Deny rule for the lease's target.
    let cfg = gvm_proxy::srr::NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/transfer".to_string(),
        decision: gvm_proxy::srr::NetworkDecisionConfig {
            decision_type: "Deny".to_string(),
            milliseconds: None,
            reason: Some("h7-deny-test".to_string()),
        },
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        unsafe_body_action: None,
        description: Some("h7".to_string()),
        label: None,
        condition: None,
        expires_at: None,
        principal_filter: None,
    };
    state.srr.write().unwrap().insert_rule(cfg).unwrap();

    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        HeaderMap::new(),
        Json(lease("agent-deny", None, false)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = common::body_json(resp).await;
    assert_eq!(json["decision"], "Deny");
    assert!(json.get("context_token").is_none());

    // The Deny path now emits a `gvm.intent.lease_denied` WAL event.
    let wal_bytes = std::fs::read_to_string(&state.wal_path).expect("read WAL");
    let denied = wal_bytes.lines().find_map(|l| {
        let v: serde_json::Value = serde_json::from_str(l).ok()?;
        if v["operation"] == "gvm.intent.lease_denied" {
            Some(v)
        } else {
            None
        }
    });
    assert!(
        denied.is_some(),
        "preflight Deny must emit a gvm.intent.lease_denied WAL event \
         (H7 — audit completeness on attempted privilege escalation)"
    );
    let denied = denied.unwrap();
    assert_eq!(denied["agent_id"], "agent-deny");
    assert_eq!(denied["decision"], "Deny");
    assert!(
        denied["context"]["payload_context_hash"]
            .as_str()
            .unwrap_or("")
            .starts_with("sha256:"),
        "lease_denied event must record payload_context_hash (privacy)"
    );
    // Raw payload context must NOT appear.
    assert!(
        denied["context"].get("payload_context").is_none(),
        "raw payload context must NOT be in the lease_denied WAL event"
    );
}

// Force-import Arc to silence the unused-import warning.
#[allow(dead_code)]
fn _force_arc_link() -> Arc<()> {
    Arc::new(())
}
