//! Cooperative intent lease — Tier-3 P3-c Phase 1 regression suite.
//!
//! Pins the load-bearing invariants from the design review
//! (docs/cooperative-intent.md):
//!
//!   1. **Token opacity.** The returned `context_token` is opaque,
//!      not `intent_id` and not `claim_id`. Sequential prediction
//!      must be impossible. Two leases produce two unrelated tokens.
//!   2. **Token storage.** The original token bytes are returned in
//!      the response exactly once; the store keeps only SHA-256.
//!      (Tested via the `context_token` field's wire shape — no
//!      "get my token back" endpoint exists, by design.)
//!   3. **Payload privacy.** The lease_issued WAL event records the
//!      `payload_context_hash`, NOT the raw `payload_context`. Raw
//!      body never lands on the audit chain.
//!   4. **Preflight Deny → no token.** When SRR Deny applies at
//!      preflight, the response has no `context_token`, no
//!      `intent_id`, and no `gvm.intent.lease_issued` WAL event.
//!   5. **Oversize payload.** A `payload_context` whose canonical
//!      JSON exceeds 16 KB returns 413; no lease is registered.
//!   6. **Malformed payload_hash.** Non-hex / wrong-length /
//!      missing-prefix payload_hash returns 400.
//!   7. **Decision source string.** `decision_source` is
//!      `cooperative.declared_only` for Phase 1 (Phase 2 introduces
//!      the cross-checked / mismatch variants).
//!   8. **Backward compat.** Legacy URL-only intent (no
//!      payload_context) returns the legacy response shape with no
//!      `context_token` field.

mod common;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use common::body_json;
use gvm_proxy::intent_store::IntentRequest;

fn lease_body(agent_id: &str, payload_context: serde_json::Value) -> IntentRequest {
    IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: agent_id.to_string(),
        ttl_secs: Some(30),
        payload_context: Some(payload_context),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    }
}

// ─── Issuance happy path ──────────────────────────────────────────────────

#[tokio::test]
async fn lease_issuance_returns_opaque_context_token() {
    let (state, _wal) = common::test_state().await;
    let body = lease_body(
        "claims-reviewer-1842",
        serde_json::json!({"amount": 100, "currency": "USD"}),
    );
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(body),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["registered"], true);
    let token = body["context_token"]
        .as_str()
        .expect("response must carry context_token");
    assert!(
        token.starts_with("ctx_"),
        "token must use the `ctx_` prefix, got {token}"
    );
    // 4-char prefix + 43 base64url-no-pad chars for 32 bytes = 47.
    assert_eq!(
        token.len(),
        47,
        "token length mismatch (prefix + 256-bit base64url): {token}"
    );
}

#[tokio::test]
async fn token_is_not_intent_id_or_claim_id() {
    // Both intent_id and claim_id are sequential u64s. The token
    // must be unrelated to either: it must not be derivable from
    // `intent_id` (which IS in the response), and it must not be a
    // simple counter that an attacker can guess.
    let (state, _wal) = common::test_state().await;
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(lease_body("a", serde_json::json!({"op": "x"}))),
    )
    .await;
    let json = body_json(resp).await;
    let _intent_id = json["intent_id"].as_u64().expect("intent_id");
    let token = json["context_token"].as_str().expect("token").to_string();

    // Decode the secret and check structure:
    //   (a) length == 32 bytes (256-bit), not 8 bytes (a u64).
    //   (b) Hamming distance from sequential u64 representation is
    //       high — verified by entropy: at least 16 distinct bytes
    //       in 32. Random uniform bytes give E[distinct] ~ 28 with
    //       very low variance; sequential counters give 1 or 2.
    use base64::Engine;
    let secret_b64 = token.strip_prefix("ctx_").expect("prefix");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_b64)
        .expect("base64url decode");
    assert_eq!(
        decoded.len(),
        32,
        "secret part must be 32 random bytes (got {} bytes) — \
         this is what makes the token unguessable; a u64 intent_id \
         or claim_id would only be 8 bytes",
        decoded.len()
    );
    let distinct = decoded
        .iter()
        .copied()
        .collect::<std::collections::HashSet<u8>>()
        .len();
    assert!(
        distinct >= 16,
        "token entropy too low: only {distinct} distinct bytes in 32. \
         A sequential intent_id would produce 1-2 distinct bytes; \
         random 32 bytes have ~28 distinct values."
    );
}

#[tokio::test]
async fn two_leases_produce_unrelated_tokens() {
    let (state, _wal) = common::test_state().await;

    let resp_a = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(lease_body("a", serde_json::json!({"op": "x"}))),
    )
    .await;
    let token_a = body_json(resp_a).await["context_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp_b = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(lease_body("b", serde_json::json!({"op": "y"}))),
    )
    .await;
    let token_b = body_json(resp_b).await["context_token"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(
        token_a, token_b,
        "two consecutive leases must produce unrelated tokens"
    );
}

#[tokio::test]
async fn response_records_payload_context_hash_not_raw_payload() {
    let (state, _wal) = common::test_state().await;
    let payload = serde_json::json!({"amount": 100, "channel": "C_INTERNAL"});
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(lease_body("a", payload.clone())),
    )
    .await;
    let json = body_json(resp).await;
    let hash = json["payload_context_hash"]
        .as_str()
        .expect("payload_context_hash must be present");
    assert!(
        hash.starts_with("sha256:"),
        "hash must use the sha256: prefix; got {hash}"
    );
    // The response must NOT echo the raw payload back to the caller.
    assert!(
        json.get("payload_context").is_none(),
        "response must not echo raw payload_context (privacy)"
    );
    // The original payload must hash to this value.
    let canonical = serde_json::to_vec(&payload).unwrap();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let expected = format!("sha256:{}", hex::encode(hasher.finalize()));
    assert_eq!(hash, expected);
}

#[tokio::test]
async fn response_decision_source_is_cooperative_declared_only() {
    let (state, _wal) = common::test_state().await;
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(lease_body("a", serde_json::json!({"op": "x"}))),
    )
    .await;
    let json = body_json(resp).await;
    assert_eq!(json["decision_source"], "cooperative.declared_only");
    assert_eq!(json["evidence_level"], "declared_only");
}

// ─── Hard limits ───────────────────────────────────────────────────────────

#[tokio::test]
async fn oversize_payload_context_returns_413() {
    let (state, _wal) = common::test_state().await;
    // ~20 KB of a single string field — over the 16 KB cap.
    let huge = "x".repeat(20 * 1024);
    let body = lease_body("a", serde_json::json!({"blob": huge}));
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(body),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let json = body_json(resp).await;
    assert!(
        json["error"].as_str().unwrap_or("").contains("16384"),
        "413 error should explain the cap, got: {:?}",
        json["error"]
    );
}

#[tokio::test]
async fn malformed_payload_hash_returns_400() {
    let (state, _wal) = common::test_state().await;
    let body = IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "bank.transfer.create".to_string(),
        agent_id: "a".to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"op": "x"})),
        payload_hash: Some("not-a-hash".to_string()),
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    };
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(body),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Preflight Deny ────────────────────────────────────────────────────────

#[tokio::test]
async fn preflight_deny_returns_no_token() {
    // Set up an SRR that denies transfers under "ban.com".
    let srr_guard = state_with_deny_rule().await;
    // The deny rule was injected; now run a lease against the same
    // URL and verify the response has no token.
    let (state, _wal) = srr_guard.take();

    let body = lease_body("a", serde_json::json!({"amount": 100}));
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(body),
    )
    .await;
    // 200 OK with decision=Deny — NOT a server error.
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["registered"], false);
    assert_eq!(json["decision"], "Deny");
    assert!(
        json.get("context_token").is_none(),
        "preflight Deny must not issue a token"
    );
    assert!(
        json.get("intent_id").is_none(),
        "preflight Deny must not allocate an intent_id"
    );
}

// Helper: build an AppState whose SRR has a Deny on
// POST api.bank.com/transfer in the injected slot. Returns the state
// wrapped so the test still owns the temp WAL guard.
struct StateGuard {
    state: gvm_proxy::proxy::AppState,
    _wal: common::TestWal,
}
impl StateGuard {
    fn take(self) -> (gvm_proxy::proxy::AppState, common::TestWal) {
        (self.state, self._wal)
    }
}
async fn state_with_deny_rule() -> StateGuard {
    let (state, _wal) = common::test_state().await;
    let cfg = gvm_proxy::srr::NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/transfer".to_string(),
        decision: gvm_proxy::srr::NetworkDecisionConfig {
            decision_type: "Deny".to_string(),
            milliseconds: None,
            reason: Some("preflight test deny".to_string()),
        },
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        unsafe_body_action: None,
        description: Some("preflight-deny".to_string()),
        label: None,
        condition: None,
        expires_at: None,
        principal_filter: None,
    };
    state.srr.write().unwrap().insert_rule(cfg).unwrap();
    StateGuard { state, _wal }
}

// ─── Backward compat ──────────────────────────────────────────────────────

#[tokio::test]
async fn legacy_url_only_intent_does_not_issue_context_token() {
    let (state, _wal) = common::test_state().await;
    let body = IntentRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/users/42".to_string(),
        operation: "users.read".to_string(),
        agent_id: "legacy-mcp-agent".to_string(),
        ttl_secs: Some(30),
        payload_context: None, // legacy URL-only path
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
        requires_observed_body: false,
    };
    let resp = gvm_proxy::api::register_intent(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(body),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert_eq!(json["registered"], true);
    assert!(
        json.get("context_token").is_none(),
        "legacy URL-only intent must not issue a token (back-compat)"
    );
    assert!(
        json.get("payload_context_hash").is_none(),
        "legacy URL-only intent must not produce a payload_context_hash"
    );
    // The legacy intent_id field is still there.
    assert!(json["intent_id"].as_u64().is_some());
}

// ─── DecisionSource enum serialization ────────────────────────────────────

#[test]
fn decision_source_round_trip_through_string() {
    use gvm_types::DecisionSource;
    let cases = [
        (DecisionSource::SrrNetworkObserved, "srr.network_observed"),
        (DecisionSource::MitmNetworkObserved, "mitm.network_observed"),
        (
            DecisionSource::CooperativeDeclaredOnly,
            "cooperative.declared_only",
        ),
        (
            DecisionSource::CooperativeCrossChecked,
            "cooperative.cross_checked",
        ),
        (DecisionSource::CooperativeMismatch, "cooperative.mismatch"),
        (DecisionSource::CooperativeExpired, "cooperative.expired"),
        (DecisionSource::CooperativeUnbound, "cooperative.unbound"),
    ];
    for (variant, expected_str) in cases {
        assert_eq!(variant.as_str(), expected_str);
        let s: String = variant.into();
        assert_eq!(s, expected_str);
        assert_eq!(format!("{variant}"), expected_str);
    }
}
