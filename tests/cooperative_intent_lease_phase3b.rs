//! Cooperative intent lease — Tier-3 P3-c Phase 3b regression suite.
//!
//! Phase 3b extends the cooperative lease to **blind-path CONNECT**:
//! HTTPS tunnels the proxy cannot MITM (cert pinning, mTLS, raw TCP).
//! The agent presents `X-GVM-Context-Token` on the CONNECT line
//! itself. The proxy claims the lease before the TLS tunnel opens,
//! verifies the declared host matches the CONNECT target, and records
//! `decision_source = cooperative.declared_only` on the audit event
//! that anchors the entire tunnel.
//!
//! CONNECT has no inner method or path visible to the proxy, so only
//! **host** and **policy_epoch** are checked at this layer. Path /
//! method / body bindings are deferred to per-request leases on the
//! HTTP path inside the tunnel (Phase 2 model), which agents wanting
//! end-to-end enforcement can still layer on top.
//!
//! The token is never forwarded into the tunnel — CONNECT headers are
//! consumed by the proxy and the relay that follows is raw bytes — so
//! the Phase 2 header-strip invariant has no analogue here.

mod common;

use axum::http::HeaderMap;
use gvm_proxy::intent_store::IntentRequest;
use gvm_proxy::proxy::connect_for_test::{claim_connect_lease, ConnectLeaseOutcome};

// ─── Helpers ─────────────────────────────────────────────────────────────

async fn issue_lease(state: &gvm_proxy::proxy::AppState, req: IntentRequest) -> String {
    use axum::extract::State;
    use axum::http::StatusCode;
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

fn lease_body(allow_pinned: bool) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: "agent-phase3b".to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"amount": 100, "currency": "USD"})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: allow_pinned,
        requires_observed_body: false,
    }
}

fn headers_with_token(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("X-GVM-Context-Token", token.parse().unwrap());
    h
}

// ─── 1. NoToken — pass through ───────────────────────────────────────────

#[tokio::test]
async fn connect_without_token_returns_no_token() {
    let (state, _wal) = common::test_state().await;
    let headers = HeaderMap::new();
    let outcome = claim_connect_lease(&state, &headers, "api.bank.com");
    assert!(
        matches!(outcome, ConnectLeaseOutcome::NoToken),
        "CONNECT without X-GVM-Context-Token must fall through to the legacy domain-only path"
    );
}

// ─── 2. Unbound denies ────────────────────────────────────────────────────

#[tokio::test]
async fn connect_with_unknown_token_returns_unbound() {
    let (state, _wal) = common::test_state().await;
    let headers = headers_with_token("ctx_this-token-was-never-issued");
    let outcome = claim_connect_lease(&state, &headers, "api.bank.com");
    match outcome {
        ConnectLeaseOutcome::Unbound { reason } => {
            assert!(
                reason.contains("does not bind to any active lease"),
                "unbound reason must explain why the token did not match, got: {reason}"
            );
        }
        other => panic!("expected Unbound, got {:?}", std::mem::discriminant(&other)),
    }
}

#[tokio::test]
async fn connect_with_non_ascii_token_returns_unbound() {
    let (state, _wal) = common::test_state().await;
    let mut headers = HeaderMap::new();
    let bad = axum::http::HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap();
    headers.insert("X-GVM-Context-Token", bad);
    let outcome = claim_connect_lease(&state, &headers, "api.bank.com");
    assert!(matches!(outcome, ConnectLeaseOutcome::Unbound { .. }));
}

// ─── 3. Host mismatch denies ─────────────────────────────────────────────

#[tokio::test]
async fn connect_with_host_mismatch_returns_mismatch() {
    let (state, _wal) = common::test_state().await;
    let token = issue_lease(&state, lease_body(false)).await;
    // Lease was for api.bank.com; CONNECT target is api.evil.com.
    let outcome = claim_connect_lease(&state, &headers_with_token(&token), "api.evil.com");
    match outcome {
        ConnectLeaseOutcome::Mismatch { reason, .. } => {
            assert!(
                reason.contains("host mismatch")
                    && reason.contains("api.bank.com")
                    && reason.contains("api.evil.com"),
                "mismatch reason must name both hosts, got: {reason}"
            );
        }
        other => panic!(
            "expected Mismatch, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ─── 4. Valid happy path ─────────────────────────────────────────────────

#[tokio::test]
async fn connect_with_matching_host_returns_valid() {
    let (state, _wal) = common::test_state().await;
    let token = issue_lease(&state, lease_body(false)).await;
    let outcome = claim_connect_lease(&state, &headers_with_token(&token), "api.bank.com");
    match outcome {
        ConnectLeaseOutcome::Valid {
            agent_id,
            operation,
            pinned,
            ..
        } => {
            assert_eq!(agent_id, "agent-phase3b");
            assert_eq!(operation, "bank.transfer.create");
            assert!(!pinned);
        }
        other => panic!("expected Valid, got {:?}", std::mem::discriminant(&other)),
    }
}

#[tokio::test]
async fn connect_host_match_is_case_insensitive() {
    // Hosts in DNS are case-insensitive; the lease stored its host
    // lowercased. A CONNECT to the same host in different case must
    // still bind.
    let (state, _wal) = common::test_state().await;
    let token = issue_lease(&state, lease_body(false)).await;
    let outcome = claim_connect_lease(&state, &headers_with_token(&token), "API.BANK.COM");
    assert!(
        matches!(outcome, ConnectLeaseOutcome::Valid { .. }),
        "host comparison must be case-insensitive"
    );
}

// ─── 5. Token re-use denies ──────────────────────────────────────────────

#[tokio::test]
async fn connect_token_reuse_second_attempt_returns_unbound() {
    let (state, _wal) = common::test_state().await;
    let token = issue_lease(&state, lease_body(false)).await;
    let first = claim_connect_lease(&state, &headers_with_token(&token), "api.bank.com");
    assert!(matches!(first, ConnectLeaseOutcome::Valid { .. }));
    let second = claim_connect_lease(&state, &headers_with_token(&token), "api.bank.com");
    assert!(
        matches!(second, ConnectLeaseOutcome::Unbound { .. }),
        "second use of a one-shot lease must be unbound"
    );
}

// ─── 6. Policy epoch ─────────────────────────────────────────────────────

#[tokio::test]
async fn connect_epoch_mismatch_without_opt_in_returns_expired() {
    let (state, _wal) = common::test_state().await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());
    let token = issue_lease(&state, lease_body(/* allow_pinned */ false)).await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());
    let outcome = claim_connect_lease(&state, &headers_with_token(&token), "api.bank.com");
    match outcome {
        ConnectLeaseOutcome::Expired { reason, .. } => {
            assert!(
                reason.contains("epoch mismatch"),
                "expired reason must name the epoch mismatch, got: {reason}"
            );
        }
        other => panic!("expected Expired, got {:?}", std::mem::discriminant(&other)),
    }
}

#[tokio::test]
async fn connect_epoch_mismatch_with_opt_in_returns_valid_pinned() {
    let (state, _wal) = common::test_state().await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-A".to_string());
    let token = issue_lease(&state, lease_body(/* allow_pinned */ true)).await;
    *state.active_integrity_ref.write().unwrap() = Some("epoch-B".to_string());
    let outcome = claim_connect_lease(&state, &headers_with_token(&token), "api.bank.com");
    match outcome {
        ConnectLeaseOutcome::Valid { pinned, .. } => {
            assert!(
                pinned,
                "allow_pinned_lease must surface pinned=true so the audit chain captures \
                 every stale-epoch tunnel"
            );
        }
        other => panic!(
            "expected Valid with pinned=true, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}
