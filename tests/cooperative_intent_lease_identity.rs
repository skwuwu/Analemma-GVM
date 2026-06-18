//! Cooperative intent lease — identity binding regression suite (Blocker 3).
//!
//! `POST /gvm/intent` previously trusted `body.agent_id` verbatim
//! and passed it as the SRR `principal_filter` evaluation principal.
//! On JWT-enabled deployments this let agent A issue a lease for
//! agent B by simply writing "agent-B" in the request body —
//! inheriting B's authorization surface under principal_filter
//! rules. The fix is `resolve_cooperative_intent_identity`: if a
//! valid JWT is presented and its subject disagrees with
//! `body.agent_id`, the issuance is rejected with `403`.
//!
//! What this file pins:
//!
//!   1. JWT configured + valid JWT for agent A + body.agent_id=A
//!      → 201 CREATED (happy path).
//!   2. JWT configured + valid JWT for agent A + body.agent_id=B
//!      → 403 (the Blocker 3 attack).
//!   3. JWT configured + invalid / expired JWT → 401.
//!   4. JWT configured + no Bearer token → trust body (legacy /
//!      orchestrator path, warning logged). This matches the
//!      existing `resolve_vault_agent_id` behaviour and is the
//!      least disruptive choice; deployments wanting stricter
//!      semantics can flip this to 401 in a follow-up.
//!   5. JWT NOT configured → trust body (operator did not enable
//!      identity verification).
//!
//! Sandbox peer-IP identity binding is out of scope for this fix —
//! it requires ConnectInfo<SocketAddr> wiring on the agent-facing
//! router. The JWT path is the primary lever and is sufficient to
//! close the immediate self-declared-agent_id attack.

mod common;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use common::body_json;
use gvm_proxy::intent_store::IntentRequest;
use std::sync::Arc;

fn lease_body(agent_id: &str) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: agent_id.to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"amount": 100})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    }
}

fn jwt_config_for_test() -> Arc<gvm_proxy::auth::JwtConfig> {
    use ed25519_dalek::SigningKey;
    use gvm_proxy::auth::{JwtAlgorithm, JwtConfig, JwtKeyMaterial, JwtKeySlot};
    let signing = SigningKey::from_bytes(&[0xAB; 32]);
    let verifying = signing.verifying_key();
    Arc::new(JwtConfig {
        algorithm: JwtAlgorithm::Ed25519,
        keys: vec![JwtKeySlot {
            kid: String::new(),
            material: JwtKeyMaterial::Ed25519 { signing, verifying },
            active: true,
            expires_at: None,
        }],
        token_ttl_secs: 3600,
        strict: false,
        revocation_file: None,
    })
}

fn issue_test_jwt(jwt: &gvm_proxy::auth::JwtConfig, agent_id: &str) -> String {
    // issue_token (not issue_admin_token) — admin tokens prefix
    // the agent_id with "admin:" which would change the value the
    // body has to match against.
    gvm_proxy::auth::issue_token(jwt, agent_id, None, "proxy")
        .expect("test JWT issuance must succeed")
}

fn auth_header(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("valid Bearer header"),
    );
    h
}

// ─── 1. Happy path — JWT subject matches body.agent_id ───────────────────

#[tokio::test]
async fn jwt_match_body_agent_id_returns_created() {
    let (mut state, _wal) = common::test_state().await;
    let jwt = jwt_config_for_test();
    state.jwt_config = Some(jwt.clone());

    let token = issue_test_jwt(&jwt, "agent-A");
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        auth_header(&token),
        Json(lease_body("agent-A")),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "JWT subject matches body.agent_id — issuance must succeed"
    );
}

// ─── 2. The Blocker 3 attack — JWT for A but body claims B ──────────────

#[tokio::test]
async fn jwt_mismatch_body_agent_id_returns_403() {
    let (mut state, _wal) = common::test_state().await;
    let jwt = jwt_config_for_test();
    state.jwt_config = Some(jwt.clone());

    // Agent A presents its valid JWT but tries to issue a lease
    // under agent B's identity. THIS is the attack the fix closes.
    let token_for_a = issue_test_jwt(&jwt, "agent-A");
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        auth_header(&token_for_a),
        Json(lease_body("privileged-release-bot")),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "JWT subject (agent-A) disagrees with body.agent_id \
         (privileged-release-bot) — issuance MUST be rejected"
    );
    // The lease must NOT have been registered.
    assert_eq!(
        state.intent_store.active_count(),
        0,
        "rejected issuance must leave the store untouched — \
         no ghost lease for the misrepresented agent_id"
    );
    let body = body_json(resp).await;
    assert!(
        body["error"].as_str().unwrap_or("").contains("must match"),
        "403 error body must explain the identity mismatch, got: {:?}",
        body["error"]
    );
}

// ─── 3. Invalid JWT → 401 ─────────────────────────────────────────────────

#[tokio::test]
async fn invalid_jwt_returns_401() {
    let (mut state, _wal) = common::test_state().await;
    state.jwt_config = Some(jwt_config_for_test());

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_static("Bearer this-is-not-a-valid-jwt"),
    );

    let resp =
        gvm_proxy::api::register_intent(State(state.clone()), headers, Json(lease_body("agent-A")))
            .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "invalid JWT must be rejected with 401"
    );
    assert_eq!(
        state.intent_store.active_count(),
        0,
        "401 rejection must leave the store untouched"
    );
}

// ─── 4. JWT configured + missing Bearer — legacy / orchestrator path ────

#[tokio::test]
async fn jwt_configured_but_no_bearer_falls_back_to_body() {
    // This is the "operator runs JWT-enabled but the orchestrator
    // path does not carry a Bearer" case. We mirror the existing
    // resolve_vault_agent_id behaviour: trust body with a warning.
    // A future deployment-policy flag can flip this to 401.
    let (mut state, _wal) = common::test_state().await;
    state.jwt_config = Some(jwt_config_for_test());

    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        HeaderMap::new(), // no Authorization header
        Json(lease_body("agent-orchestrator")),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "no Bearer → trust body (legacy / orchestrator fallback, warning only)"
    );
}

// ─── 5. JWT not configured — trust body ─────────────────────────────────

#[tokio::test]
async fn no_jwt_config_trusts_body_agent_id() {
    let (state, _wal) = common::test_state().await;
    assert!(state.jwt_config.is_none());

    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        HeaderMap::new(),
        Json(lease_body("anything-i-want")),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "JWT not configured — body.agent_id is trusted as-is"
    );
}
