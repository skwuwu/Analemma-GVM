//! Cooperative intent lease — Tier-3 P3-c Phase 3a regression suite.
//!
//! Phase 3a wires two deferred Phase 2 items:
//!
//!   1. **Observed-body cross-check.** When the proxy buffered the
//!      request body (payload inspection enabled) AND the lease
//!      carries an operator-supplied `payload_hash`, the hot path
//!      SHA-256s the buffered body and compares against the
//!      declared hash. Match → `cooperative.cross_checked` (the
//!      highest cooperative evidence tier). Mismatch → Deny tagged
//!      `cooperative.mismatch`.
//!   2. **`allow_pinned_lease` opt-in.** The agent / orchestrator
//!      can declare at issuance that the lease should remain valid
//!      across a mid-flight policy reload. The claim path tolerates
//!      the epoch mismatch, marks `Classification::pinned = true`,
//!      and the audit chain captures `cooperative.pinned = true` +
//!      the `X-GVM-Lease-Pinned: true` response header so the
//!      reviewer can see every stale-epoch enforcement.
//!
//! The Phase 2 invariants (token strip, unbound / mismatch denies,
//! single-use, default-strict epoch behaviour) are still pinned in
//! `tests/cooperative_intent_lease_phase2.rs` — this file only
//! exercises behaviour that becomes observable in Phase 3a.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use gvm_proxy::intent_store::IntentRequest;
use std::sync::Arc;
use tower::ServiceExt;

// ─── Helpers ─────────────────────────────────────────────────────────────

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

async fn issue_lease(state: &gvm_proxy::proxy::AppState, req: IntentRequest) -> String {
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
        "lease registration must succeed"
    );
    let json = common::body_json(resp).await;
    json["context_token"]
        .as_str()
        .expect("response must carry context_token")
        .to_string()
}

fn proxy_app(
    state: gvm_proxy::proxy::AppState,
    upstream_addr: std::net::SocketAddr,
) -> (Router, gvm_proxy::proxy::AppState) {
    let mut state = state;
    state.host_overrides.insert(
        "api.bank.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );
    // Phase 3a needs payload inspection ON so the proxy buffers the
    // body and feeds it to extract_and_claim_lease for the SHA-256
    // cross-check. The default test_state() has it off.
    state.payload_inspection = true;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state.clone());
    (app, state)
}

fn lease_with_hash(payload_hash: Option<String>, allow_pinned: bool) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: "agent-phase3".to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"amount": 100, "currency": "USD"})),
        payload_hash,
        content_type: None,
        allow_pinned_lease: allow_pinned,
        requires_observed_body: false,
    }
}

fn proxy_request_with_body(body: &'static [u8], token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("X-GVM-Agent-Id", "agent-phase3")
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-phase3")
        .header("X-GVM-Event-Id", "evt-phase3")
        .header("X-GVM-Context-Token", token)
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len().to_string())
        .body(Body::from(body))
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

// ─── 1. Observed-body cross-check ─────────────────────────────────────────

#[tokio::test]
async fn observed_body_matches_declared_hash_yields_cross_checked() {
    let body: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let (addr, captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_with_hash(Some(hash_hex(body)), false)).await;

    let resp = app
        .oneshot(proxy_request_with_body(body, &token))
        .await
        .expect("proxy must handle request");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "happy path must reach upstream"
    );
    assert_eq!(
        decision_source(&resp),
        "cooperative.cross_checked",
        "matching observed body must upgrade evidence to cross_checked"
    );
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn observed_body_diverges_from_declared_hash_returns_mismatch_deny() {
    // The agent presents a token whose lease declared `body_A`,
    // but on the wire the proxy observes `body_B`. The cross-check
    // catches the lie and Denies. This is the highest-value
    // assertion of Phase 3a: the lease evidence is only as good as
    // the cross-check that catches the agent who declares one body
    // and sends another.
    let declared: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let observed: &[u8] = br#"{"amount":999999,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let (addr, captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_with_hash(Some(hash_hex(declared)), false)).await;

    let resp = app
        .oneshot(proxy_request_with_body(observed, &token))
        .await
        .expect("proxy must handle request");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        decision_source(&resp),
        "cooperative.mismatch",
        "body divergence from declared payload_hash must Deny as mismatch"
    );
    assert_eq!(
        captured.lock().unwrap().len(),
        0,
        "mismatched body must not reach upstream"
    );
}

#[tokio::test]
async fn lease_without_payload_hash_falls_through_to_declared_only() {
    // No declared `payload_hash` → no cross-check input → the path
    // must still produce `cooperative.declared_only`, NOT
    // `cross_checked`. Otherwise an agent that just omits
    // `payload_hash` would silently upgrade its own evidence tier.
    let body: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_with_hash(None, false)).await;

    let resp = app
        .oneshot(proxy_request_with_body(body, &token))
        .await
        .expect("proxy must handle request");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        decision_source(&resp),
        "cooperative.declared_only",
        "no declared payload_hash → must NOT silently upgrade to cross_checked"
    );
}

// ─── 2. allow_pinned_lease ────────────────────────────────────────────────

#[tokio::test]
async fn pinned_lease_survives_policy_reload_and_marks_pinned() {
    let body: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(
        &state,
        lease_with_hash(Some(hash_hex(body)), /* allow_pinned */ true),
    )
    .await;

    // Simulate a config reload between issue and claim.
    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());

    let resp = app
        .oneshot(proxy_request_with_body(body, &token))
        .await
        .expect("proxy must handle request");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "allow_pinned_lease must tolerate epoch mismatch, got: {:?}",
        resp.status()
    );
    assert_eq!(
        decision_source(&resp),
        "cooperative.cross_checked",
        "evidence source must still reflect the cross-check, not the pinning"
    );
    assert_eq!(
        resp.headers()
            .get("X-GVM-Lease-Pinned")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "pinned acceptance must surface X-GVM-Lease-Pinned: true so the agent and \
         auditor can both see the lease ran against a stale epoch"
    );
}

#[tokio::test]
async fn pinned_lease_without_opt_in_still_expires() {
    // Defence in depth: confirm the default-strict behaviour is
    // unchanged from Phase 2. Without `allow_pinned_lease=true`,
    // an epoch mismatch must still Deny — even if the lease
    // happens to carry a matching payload_hash.
    let body: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(
        &state,
        lease_with_hash(Some(hash_hex(body)), /* allow_pinned */ false),
    )
    .await;

    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());

    let resp = app
        .oneshot(proxy_request_with_body(body, &token))
        .await
        .expect("proxy must handle request");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.expired");
    assert!(
        resp.headers().get("X-GVM-Lease-Pinned").is_none(),
        "non-pinned Deny must NOT advertise pinned=true"
    );
}

#[tokio::test]
async fn non_pinned_allow_does_not_set_pinned_header() {
    // Regression guard: the pinned header / event flag must ONLY
    // surface when a stale-epoch lease was tolerated. A normal
    // happy-path Allow must NOT carry the marker, otherwise the
    // audit chain would dilute its signal.
    let body: &[u8] = br#"{"amount":100,"currency":"USD"}"#;
    let (state, _wal) = common::test_state().await;
    let (addr, _captured) = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_with_hash(Some(hash_hex(body)), false)).await;

    let resp = app
        .oneshot(proxy_request_with_body(body, &token))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp), "cooperative.cross_checked");
    assert!(
        resp.headers().get("X-GVM-Lease-Pinned").is_none(),
        "non-pinned happy-path Allow must NOT advertise pinned=true"
    );
}
