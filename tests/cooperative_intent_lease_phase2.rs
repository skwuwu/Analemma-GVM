//! Cooperative intent lease — Tier-3 P3-c Phase 2 regression suite.
//!
//! Phase 2 wires the proxy hot path to honour the lease issued in
//! Phase 1. The invariants exercised here are the ones a security
//! reviewer would name first:
//!
//!   1. **Unbound token denies.** A `X-GVM-Context-Token` that does
//!      not match any active lease MUST end in Deny tagged
//!      `cooperative.unbound`. Forgery / replay / re-use all land
//!      here.
//!   2. **Shape mismatch denies.** Method / host / path that disagree
//!      with the declared lease MUST end in Deny tagged
//!      `cooperative.mismatch`. The agent declared X and sent Y.
//!   3. **Declared-only happy path.** Valid token + matching shape +
//!      no observed-body cross-check available → Allow under
//!      `cooperative.declared_only`. SRR was fed the declared
//!      payload context.
//!   4. **Header strip (CRITICAL).** Regardless of outcome, the
//!      `X-GVM-Context-Token` header MUST NOT survive into the
//!      upstream request. Leaking it to GitHub / Slack / Stripe
//!      would let those endpoints replay it to GVM and impersonate
//!      the lease. This is THE security-relevant invariant of the
//!      whole phase.
//!   5. **Token re-use denies.** A token is single-use. The second
//!      request with the same token MUST end in `cooperative.unbound`
//!      (the first claim transitioned it out of Active).
//!   6. **Policy epoch mismatch.** If the active integrity ref
//!      changes between lease issue and claim, the lease is stale
//!      and MUST end in `cooperative.expired`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gvm_proxy::intent_store::IntentRequest;
use std::sync::Arc;
use tower::ServiceExt;

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Spawn a mock upstream that records request headers on each call.
/// Returns the listening address and a shared handle the test can read
/// to inspect what headers the proxy forwarded.
async fn spawn_recording_upstream() -> (
    std::net::SocketAddr,
    Arc<std::sync::Mutex<Vec<axum::http::HeaderMap>>>,
) {
    let captured: Arc<std::sync::Mutex<Vec<axum::http::HeaderMap>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured_for_app = captured.clone();

    let upstream_app = axum::Router::new().fallback(move |req: Request<Body>| {
        let captured = captured_for_app.clone();
        async move {
            captured.lock().unwrap().push(req.headers().clone());
            axum::http::Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"upstream_received":true}"#))
                .expect("upstream response must build")
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().expect("upstream local_addr");
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });
    (addr, captured)
}

/// Issue a body-aware lease through the in-process API and return its
/// opaque `ctx_…` token plus the intent_id. Uses the same call path
/// the SDK would: `POST /gvm/intent` → `register_intent` handler.
async fn issue_lease(state: &gvm_proxy::proxy::AppState, req: IntentRequest) -> (String, u64) {
    use axum::extract::State;
    use axum::Json;
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(req),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "lease registration must succeed for the test fixture"
    );
    let json = common::body_json(resp).await;
    let token = json["context_token"]
        .as_str()
        .expect("response must carry context_token")
        .to_string();
    let intent_id = json["intent_id"].as_u64().expect("intent_id");
    (token, intent_id)
}

/// Build a proxy app wired to forward to the given upstream addr
/// under the SDK-routed `api.bank.com` host. The host override does
/// the rewrite the operator would normally do in production.
fn proxy_app(
    state: gvm_proxy::proxy::AppState,
    upstream_addr: std::net::SocketAddr,
) -> (Router, gvm_proxy::proxy::AppState) {
    let mut state = state;
    state.host_overrides.insert(
        "api.bank.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state.clone());
    (app, state)
}

fn lease_body() -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: "agent-phase2".to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"amount": 100, "currency": "USD"})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
    }
}

fn proxy_request(method: &str, path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("X-GVM-Agent-Id", "agent-phase2")
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-phase2-001")
        .header("X-GVM-Event-Id", "evt-phase2-001")
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        builder = builder.header("X-GVM-Context-Token", t);
    }
    builder
        .body(Body::from(r#"{"amount":100,"currency":"USD"}"#))
        .expect("request must build")
}

fn decision_source(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("X-GVM-Decision-Source")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn decision(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("X-GVM-Decision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ─── 1. Unbound token denies ─────────────────────────────────────────────

#[tokio::test]
async fn unknown_token_returns_deny_with_unbound_source() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, _state) = proxy_app(state, addr);

    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some("ctx_this-token-was-never-issued"),
        ))
        .await
        .expect("proxy must handle request");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unbound token must deny (fail-close)"
    );
    assert_eq!(decision_source(&resp), "cooperative.unbound");
    assert_eq!(decision(&resp), "Deny");
    // The reason ends up in the JSON body, not the header.
    let body = common::body_json(resp).await;
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("does not bind to any active lease"),
        "Deny body must explain why the token did not bind, got: {:?}",
        body["reason"]
    );
}

#[tokio::test]
async fn non_ascii_token_returns_unbound() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, _state) = proxy_app(state, addr);

    // Smuggle non-ASCII bytes via `from_bytes` (axum's HeaderValue
    // accepts them but `to_str()` in extract_and_claim_lease fails).
    let bad = axum::http::HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("X-GVM-Agent-Id", "a")
        .header("X-GVM-Operation", "op")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "t")
        .header("X-GVM-Event-Id", "e")
        .header("X-GVM-Context-Token", bad)
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.unbound");
}

// ─── 2. Shape mismatch denies ─────────────────────────────────────────────

#[tokio::test]
async fn method_mismatch_returns_deny_with_mismatch_source() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    // Lease was for POST; request is PUT.
    let resp = app
        .oneshot(proxy_request("PUT", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.mismatch");
}

#[tokio::test]
async fn path_mismatch_returns_deny_with_mismatch_source() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    // Lease was for /transfer prefix; request is /admin.
    let resp = app
        .oneshot(proxy_request("POST", "/admin", Some(&token)))
        .await
        .expect("proxy must handle");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.mismatch");
}

#[tokio::test]
async fn host_mismatch_returns_deny_with_mismatch_source() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    // Note: host_overrides only remaps api.bank.com here, but
    // x-gvm-target-host for this test points at api.evil.com, which
    // the proxy will never reach upstream because the mismatch arm
    // fires first. We still install the bank.com override so the
    // app's plumbing is the same shape as the other tests.
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("X-GVM-Agent-Id", "agent-phase2")
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.evil.com") // different host
        .header("X-GVM-Trace-Id", "trace")
        .header("X-GVM-Event-Id", "evt")
        .header("X-GVM-Context-Token", &token)
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.mismatch");
}

// ─── 3. Declared-only happy path ─────────────────────────────────────────

#[tokio::test]
async fn valid_lease_allows_with_declared_only_source() {
    let (state, _wal) = common::test_state().await;
    let (addr, captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid lease must reach upstream (empty SRR → Allow)"
    );
    assert_eq!(decision_source(&resp), "cooperative.declared_only");
    assert_eq!(captured.lock().unwrap().len(), 1, "upstream must be hit");
}

#[tokio::test]
async fn valid_lease_path_prefix_match_allows() {
    let (state, _wal) = common::test_state().await;
    let (addr, captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    // Lease was for /transfer; request to /transfer/123 — a child
    // path. The prefix check in extract_and_claim_lease accepts this.
    let resp = app
        .oneshot(proxy_request("POST", "/transfer/123", Some(&token)))
        .await
        .expect("proxy must handle");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp), "cooperative.declared_only");
    assert_eq!(captured.lock().unwrap().len(), 1);
}

// ─── 4. Header strip (CRITICAL) ─────────────────────────────────────────

#[tokio::test]
async fn context_token_never_leaks_to_upstream_on_allow() {
    let (state, _wal) = common::test_state().await;
    let (addr, captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);

    // The mock upstream captured every header. Walk them and assert
    // the cooperative token never reaches the wire. This is the
    // load-bearing security invariant of Phase 2.
    let recorded = captured.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    let headers = &recorded[0];
    assert!(
        headers.get("x-gvm-context-token").is_none(),
        "CRITICAL: X-GVM-Context-Token leaked to upstream — \
         bearer material would be replayable by any upstream"
    );
    // Defence in depth: NO `X-GVM-*` header may survive either; this
    // is already covered by other tests but a regression here would
    // be just as load-bearing.
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        assert!(
            !lower.starts_with("x-gvm-"),
            "GVM internal header `{name}` leaked to upstream"
        );
    }
}

// ─── 5. Token re-use denies ─────────────────────────────────────────────

#[tokio::test]
async fn token_reuse_second_request_returns_unbound() {
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    // First request consumes the lease. The proxy_handler in Phase 2
    // claims but does not yet `confirm()` after WAL on the
    // cooperative path; the claim moves the lease out of Active
    // either way, which is what makes the second request unbound.
    let resp1 = app
        .clone()
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");
    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp1), "cooperative.declared_only");

    // Second request with the same token must NOT find an Active
    // lease — the state machine has already moved past Active.
    let resp2 = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp2), "cooperative.unbound");
}

// ─── 6. Policy epoch mismatch ───────────────────────────────────────────

#[tokio::test]
async fn epoch_change_between_issue_and_claim_returns_expired() {
    let (state, _wal) = common::test_state().await;
    // Seed an integrity ref so the lease issuance binds the lease to
    // it. This simulates a proxy that has finished startup.
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());

    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let (token, _) = issue_lease(&state, lease_body()).await;

    // Simulate a config reload between issue and claim by flipping
    // the active integrity ref.
    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());

    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.expired");
}
