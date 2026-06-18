//! Cooperative intent lease — claim lifecycle regression suite.
//!
//! Phase 2's "token re-use returns Unbound" test was time-window
//! dependent: it called the same token twice in quick succession,
//! observed Unbound on the second call (because the lease was in
//! `Claimed` state), and called it good. That left a gap — without
//! `confirm()` being called after the request completed, the lease
//! sat in `Claimed` until `CLAIM_TIMEOUT` (10s) elapsed and then got
//! auto-released back to `Active` by `cleanup_inner`. After that
//! window the same token could re-bind, defeating single-use.
//!
//! This file fixes that gap by asserting through the proxy hot path
//! that:
//!
//!   1. After a successful (Allow) request that consumed a lease,
//!      the lease is REMOVED from the store (confirm was called).
//!   2. After a Deny request (Mismatch / Expired) that consumed a
//!      lease, the lease is ALSO removed — bad use of a claim is
//!      still use of a claim. Otherwise an attacker can probe with
//!      a mismatching shape, wait out CLAIM_TIMEOUT, and try again
//!      with the right shape.
//!   3. After Unbound (no lease was claimed in the first place),
//!      the store is untouched.
//!
//! The store's `active_count()` is the load-bearing observable: it
//! reports the number of leases in `Active` OR `Claimed` state.
//! `confirm()` removes the lease entirely → count drops to 0.
//! `release()` puts it back to Active → count stays the same. Any
//! cooperative outcome that consumed a claim and didn't pair
//! confirm/release at proxy_handler level would show as a stuck
//! count of 1 forever (until TTL expiry).

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
        agent_id: "agent-lifecycle".to_string(),
        ttl_secs: Some(300),
        payload_context: Some(serde_json::json!({"amount": 100, "currency": "USD"})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    }
}

fn proxy_request(method: &str, path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("X-GVM-Agent-Id", "agent-lifecycle")
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-lifecycle")
        .header("X-GVM-Event-Id", "evt-lifecycle")
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

// ─── 1. Allow consumes the lease ─────────────────────────────────────────

#[tokio::test]
async fn allow_consumes_lease_confirm_is_called() {
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_body()).await;

    assert_eq!(
        state.intent_store.active_count(),
        1,
        "store must hold the registered lease"
    );

    let resp = app
        .clone()
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp), "cooperative.declared_only");

    // The CRITICAL assertion: after a successful Allow request, the
    // lease MUST be removed from the store (confirm called). Without
    // this, the lease would sit in Claimed for 10s then auto-release
    // to Active and the same token could re-bind.
    assert_eq!(
        state.intent_store.active_count(),
        0,
        "Allow path must call confirm() on the cooperative lease — \
         single-use is defeated if the lease can be re-used after \
         CLAIM_TIMEOUT auto-release"
    );

    // Defence in depth: a second request with the same token must be
    // Unbound. (Combined with active_count==0, this proves the
    // lease is truly gone, not just sitting in Claimed.)
    let resp2 = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp2), "cooperative.unbound");
}

// ─── 2. Deny (Mismatch / Expired) also consumes the lease ───────────────

#[tokio::test]
async fn deny_mismatch_consumes_lease_confirm_is_called() {
    // Mismatch / Expired produce Deny but DID claim the lease. Without
    // confirm, the lease sits in Claimed and re-releases after
    // CLAIM_TIMEOUT — attacker probes with wrong shape, waits 10s,
    // retries with right shape and the lease binds. This test pins
    // the fix: a bad claim is still a claim, must be consumed.
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_body()).await;

    let resp = app
        .clone()
        .oneshot(proxy_request("PUT", "/transfer", Some(&token))) // wrong method
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.mismatch");

    assert_eq!(
        state.intent_store.active_count(),
        0,
        "Mismatch Deny must STILL consume the cooperative lease — \
         otherwise a probe-then-wait attack defeats single-use"
    );

    // Replay with the correct shape — must be Unbound, not Allow.
    let resp2 = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        decision_source(&resp2),
        "cooperative.unbound",
        "the lease must be gone — a probe-then-retry attack must fail"
    );
}

#[tokio::test]
async fn deny_expired_consumes_lease_confirm_is_called() {
    // Same shape as the Mismatch test but for the Expired arm:
    // epoch mismatch without allow_pinned_lease → Deny but claim
    // was taken → must be consumed so the same token cannot be
    // re-used after CLAIM_TIMEOUT.
    let (state, _wal) = common::test_state().await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease_body()).await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());

    let resp = app
        .oneshot(proxy_request("POST", "/transfer", Some(&token)))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.expired");

    assert_eq!(
        state.intent_store.active_count(),
        0,
        "Expired Deny must STILL consume the cooperative lease"
    );
}

// ─── 3. Unbound leaves the store alone ───────────────────────────────────

#[tokio::test]
async fn unbound_does_not_touch_unrelated_leases() {
    // An Unbound request (token doesn't match any active lease) must
    // NOT consume any OTHER lease that happens to be active. The
    // Unbound arm explicitly never had a claim, so confirm/release
    // would be a no-op anyway, but this test guards against a future
    // refactor accidentally calling confirm on a stale claim_id.
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);

    // Register a real lease and keep its token in our pocket.
    let _real_token = issue_lease(&state, lease_body()).await;
    assert_eq!(state.intent_store.active_count(), 1);

    // Send a request with a FAKE token. Expect Unbound.
    let resp = app
        .oneshot(proxy_request(
            "POST",
            "/transfer",
            Some("ctx_never-issued-by-anyone"),
        ))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(decision_source(&resp), "cooperative.unbound");

    // The real lease must STILL be in the store.
    assert_eq!(
        state.intent_store.active_count(),
        1,
        "Unbound rejection must not touch unrelated active leases"
    );
}

// ─── 4. NoToken (standard SRR path) doesn't touch leases ────────────────

#[tokio::test]
async fn no_token_request_does_not_consume_lease() {
    // A request with no X-GVM-Context-Token header must not consume
    // any active lease, regardless of how many are sitting in the
    // store. This guards against a regression where try_sandbox_binding
    // would silently claim a lease the request did not authenticate
    // against.
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);

    let _token = issue_lease(&state, lease_body()).await;
    assert_eq!(state.intent_store.active_count(), 1);

    // Request without the token header.
    let resp = app
        .oneshot(proxy_request("POST", "/transfer", None))
        .await
        .expect("proxy must handle request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        decision_source(&resp),
        "SRR",
        "without token, the standard SRR network-observed path runs"
    );

    assert_eq!(
        state.intent_store.active_count(),
        1,
        "NoToken request must NOT consume any active lease"
    );
}

// ─── 5. WAL failure releases the lease (allows retry) ───────────────────
//
// The WAL-failure path releases the claim back to Active so the
// agent's retry can re-claim and try the WAL write again. This is
// the opposite of the Deny path which confirms (= deletes) — Deny
// is a recorded governance decision; WAL failure is an
// infrastructure error.
//
// Direct end-to-end testing requires injecting a failing ledger,
// which is heavy. The store-level invariant (release puts it back
// to Active) is already covered by tests/intent_store_concurrency.rs;
// this comment documents the contract so future readers see it.

// Use ::Arc to silence the unused-import warning in this binary.
#[allow(dead_code)]
fn _force_arc_link() -> Arc<()> {
    Arc::new(())
}
