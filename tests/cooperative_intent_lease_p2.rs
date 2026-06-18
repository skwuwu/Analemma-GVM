//! Cooperative intent lease — P2 follow-up regression suite.
//!
//! Pins the items called out in the post-v0.6.2 review:
//!
//!   - **EvidenceFirst Allow audit**: when
//!     `state.allow_audit_mode == EvidenceFirst`, the Allow path
//!     MUST write a Pending WAL event durably BEFORE forwarding
//!     upstream. Verifying by reading the WAL after a happy-path
//!     Allow shows TWO events for the same event_id: one Pending
//!     (initial reservation) and one final status.
//!   - **CONNECT lease metadata**: `ConnectLeaseOutcome::Valid` now
//!     carries `CooperativeMeta`. Verified at the helper layer
//!     since the full CONNECT flow needs hyper upgrade plumbing.
//!   - **Strict identity guard**: when
//!     `require_verified_intent_identity = true`, `/gvm/intent`
//!     with neither a verified JWT nor a sandbox peer-IP returns
//!     401 — body-trust fallback is refused.
//!   - **Single-use across CLAIM_TIMEOUT**: a successful token
//!     claim that completes the proxy hot path MUST permanently
//!     consume the lease. Waiting longer than `CLAIM_TIMEOUT`
//!     (10s) and re-presenting the same token returns
//!     `cooperative.unbound`. This catches a regression where the
//!     timed-out auto-release would resurrect a consumed lease.
//!   - **Sandbox-bound final agent_id**: when a request binds via
//!     peer-IP sandbox identity, the final WAL event records the
//!     sandbox-derived `agent_id`, not the header-supplied one.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use gvm_proxy::intent_store::IntentRequest;
use gvm_proxy::proxy::AuditMode;
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
    let resp =
        gvm_proxy::api::register_intent(State(state.clone()), HeaderMap::new(), None, Json(req))
            .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = common::body_json(resp).await;
    json["context_token"].as_str().unwrap().to_string()
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

fn lease(agent_id: &str) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: agent_id.to_string(),
        ttl_secs: Some(60),
        payload_context: Some(serde_json::json!({"amount": 100})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    }
}

fn proxy_request(token: Option<&str>, agent_id: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("X-GVM-Agent-Id", agent_id)
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-p2")
        .header("X-GVM-Event-Id", "evt-p2")
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        b = b.header("X-GVM-Context-Token", t);
    }
    b.body(Body::from(r#"{"amount":100}"#))
        .expect("request must build")
}

fn decision_source(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get("X-GVM-Decision-Source")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ─── 1. EvidenceFirst Allow writes Pending before forwarding ─────────────

#[tokio::test]
async fn evidence_first_allow_writes_pending_then_confirmed() {
    // EvidenceFirst Allow flow: WAL Pending (durable) → forward →
    // WAL Confirmed/Failed. Both events share the same event_id.
    // The legacy Performance path only writes ONE event (the final
    // status) after the upstream responds.
    let (mut state, _wal) = common::test_state().await;
    state.allow_audit_mode = AuditMode::EvidenceFirst;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);

    let resp = app
        .oneshot(proxy_request(None, "agent-ef"))
        .await
        .expect("proxy must handle");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "happy-path Allow under evidence_first must still 200 OK"
    );

    // Find the request's event_id from the response header, then
    // count how many WAL lines carry it.
    let event_id = resp
        .headers()
        .get("X-GVM-Event-Id")
        .and_then(|v| v.to_str().ok())
        .expect("response must carry X-GVM-Event-Id")
        .to_string();

    // Allow a moment for any async WAL append to complete.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let wal_text = std::fs::read_to_string(&state.wal_path).expect("read WAL");
    let occurrences = wal_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event_id"] == event_id)
        .count();

    assert!(
        occurrences >= 2,
        "evidence_first Allow must write Pending + final status events \
         (saw {} occurrences of event_id={})",
        occurrences,
        event_id
    );
}

// ─── 2. CONNECT helper outcome carries CooperativeMeta ───────────────────

#[tokio::test]
async fn connect_valid_outcome_carries_lease_metadata() {
    use gvm_proxy::proxy::connect_for_test::{claim_connect_lease, ConnectLeaseOutcome};
    let (state, _wal) = common::test_state().await;
    let token = issue_lease(&state, lease("agent-conn-meta")).await;

    let mut headers = HeaderMap::new();
    headers.insert("X-GVM-Context-Token", token.parse().unwrap());

    let outcome = claim_connect_lease(&state, &headers, "api.bank.com");
    match outcome {
        ConnectLeaseOutcome::Valid { meta, .. } => {
            assert!(
                meta.intent_id > 0,
                "Valid outcome must carry intent_id linking back to lease_issued event"
            );
            assert!(
                meta.claim_id > 0,
                "Valid outcome must carry claim_id for the confirm/release lifecycle"
            );
            assert!(
                meta.payload_context_hash.is_some(),
                "Valid outcome must carry payload_context_hash for audit-chain traversal"
            );
            assert!(
                meta.observed_payload_hash.is_none(),
                "CONNECT cannot observe body — observed_payload_hash must be None"
            );
        }
        other => panic!(
            "expected ConnectLeaseOutcome::Valid, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ─── 3. Strict identity guard ────────────────────────────────────────────

#[tokio::test]
async fn strict_identity_no_jwt_no_sandbox_returns_401() {
    use axum::extract::State;
    use axum::Json;

    let (mut state, _wal) = common::test_state().await;
    // JWT not configured; no peer_ip extension; strict guard active.
    state.require_verified_intent_identity = true;
    assert!(state.jwt_config.is_none());

    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        HeaderMap::new(),
        None,
        Json(lease("agent-strict")),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "require_verified_intent_identity=true must refuse body-trust fallback"
    );
    assert_eq!(
        state.intent_store.active_count(),
        0,
        "401 rejection must leave the store untouched"
    );
}

// ─── 4. Single-use across CLAIM_TIMEOUT ──────────────────────────────────

#[tokio::test]
#[ignore = "10s wait — run explicitly with `cargo test -- --ignored`"]
async fn token_reuse_after_claim_timeout_still_returns_unbound() {
    // The Phase 2 token_reuse test calls the token twice within ~ms,
    // which only proves the in-flight Claimed state machine. This
    // test waits PAST CLAIM_TIMEOUT (10s + slack) and confirms the
    // confirm()-deleted lease cannot be resurrected by the
    // cleanup_inner timeout-release path.
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;
    let (app, state) = proxy_app(state, addr);
    let token = issue_lease(&state, lease("agent-timeout")).await;

    let resp1 = app
        .clone()
        .oneshot(proxy_request(Some(&token), "agent-timeout"))
        .await
        .expect("proxy must handle");
    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(decision_source(&resp1), "cooperative.declared_only");

    // Wait past CLAIM_TIMEOUT (10s). The legacy bug auto-released
    // Claimed leases here; the H8-era fix confirms them so the
    // lease is permanently deleted.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    let resp2 = app
        .oneshot(proxy_request(Some(&token), "agent-timeout"))
        .await
        .expect("proxy must handle");
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        decision_source(&resp2),
        "cooperative.unbound",
        "after CLAIM_TIMEOUT, a consumed token must STILL be unbound — \
         not resurrected by cleanup_inner's timeout-release"
    );
}

// ─── 5. Sandbox-bound request final WAL agent_id ─────────────────────────

#[tokio::test]
async fn sandbox_bound_request_writes_sandbox_agent_id_to_final_wal() {
    use gvm_proxy::proxy::SandboxMetadata;
    let (state, _wal) = common::test_state().await;
    let addr = spawn_recording_upstream().await;

    // Wire sandbox metadata + populate the peer_ip cache to
    // simulate a real sandbox launch. Cache hit is cross-platform.
    state.per_sandbox_metadata.insert(
        "sb-final".to_string(),
        SandboxMetadata {
            agent_id: "agent-sandbox-final".to_string(),
            launch_event_id: "launch-final".to_string(),
            launched_at: chrono::Utc::now(),
        },
    );
    let peer: std::net::IpAddr = "10.42.0.99".parse().unwrap();
    state
        .peer_ip_to_sandbox_id
        .insert(peer, "sb-final".to_string());

    // Register lease bound to the sandbox's agent_id so the
    // sandbox-binding path can claim it.
    let _ = issue_lease(&state, lease("agent-sandbox-final")).await;

    let (app, state) = proxy_app(state, addr);

    // Build a request WITHOUT a token (so try_sandbox_binding
    // fires) and with a different X-GVM-Agent-Id header (so we
    // can prove the sandbox-derived identity wins).
    let req = Request::builder()
        .method("POST")
        .uri("/transfer")
        .header("X-GVM-Agent-Id", "attacker-claimed-via-header")
        .header("X-GVM-Operation", "bank.transfer.create")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-sb-final")
        .header("X-GVM-Event-Id", "evt-sb-final")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"amount":100}"#))
        .expect("request must build");

    // Inject peer_ip into the request extensions (mirrors what
    // serve_connection does in main.rs).
    let mut req = req;
    req.extensions_mut().insert(peer);

    let resp = app.oneshot(req).await.expect("proxy must handle");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        decision_source(&resp),
        "cooperative.declared_only",
        "sandbox-binding must have fired (no token, but peer IP resolves to lease holder)"
    );

    // Final WAL event must record the sandbox-derived agent_id,
    // NOT the attacker-claimed header.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let wal_text = std::fs::read_to_string(&state.wal_path).expect("read WAL");
    let final_event = wal_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| {
            v["decision_source"] == "cooperative.declared_only"
                && v["operation"] != "gvm.intent.lease_issued"
        })
        .expect("WAL must contain final request event");

    assert_eq!(
        final_event["agent_id"], "agent-sandbox-final",
        "final WAL agent_id must come from the sandbox identity, not the header"
    );
    assert_ne!(
        final_event["agent_id"], "attacker-claimed-via-header",
        "the attacker-supplied header must NOT determine the audit-recorded agent_id"
    );
}

// Force-import Arc to silence the unused-import warning.
#[allow(dead_code)]
fn _force_arc_link() -> Arc<()> {
    Arc::new(())
}
