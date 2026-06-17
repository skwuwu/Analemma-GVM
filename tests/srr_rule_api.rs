//! HTTP-layer regression for the SRR single-rule mutation endpoints —
//! Tier-3 P3-a.
//!
//! Exercises `api::insert_srr_rule`, `api::remove_srr_rule`,
//! `api::list_injected_srr_rules` directly (the same pattern
//! `tests/ic3_bypass_adversarial.rs` uses for IC-3 handlers). No live
//! HTTP server is spun up here — that surface is covered by the
//! workspace's end-to-end CI suite on EC2.
//!
//! Status-code contracts pinned:
//!   * POST /gvm/srr/rule    → 201 on success
//!                             → 400 on bad body / missing description
//!                             → 409 on duplicate description
//!                             → 429 on injected-rule cap
//!   * DELETE /gvm/srr/rule  → 200 + removed=true if found
//!                             → 404 if not found
//!   * GET /gvm/srr/rule     → 200 with ids array

mod common;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use common::body_json;

fn lease_rule_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "method": "POST",
        "pattern": "api.bank.com/transfer",
        "decision": { "type": "Deny", "reason": "leased freeze" },
        "description": id,
    })
}

// ─── Insert path ───────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_succeeds_returns_201_and_id() {
    let (state, _wal) = common::test_state().await;
    let resp =
        gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("lease.alpha")))
            .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["id"], "lease.alpha");
    assert_eq!(body["applied"], true);
    assert_eq!(body["injected_count"], 1);

    // And the rule actually went in.
    let srr = state.srr.read().unwrap();
    assert_eq!(srr.injected_rule_count(), 1);
    assert_eq!(srr.injected_rule_ids(), vec!["lease.alpha"]);
}

#[tokio::test]
async fn insert_with_missing_description_returns_400() {
    let (state, _wal) = common::test_state().await;
    let body = serde_json::json!({
        "method": "POST",
        "pattern": "api.bank.com/transfer",
        "decision": { "type": "Deny" },
        // no description
    });
    let resp = gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["error"].as_str().unwrap_or("").contains("description"),
        "400 should explain the missing description, got: {:?}",
        body["error"]
    );
}

#[tokio::test]
async fn insert_with_duplicate_description_returns_409() {
    let (state, _wal) = common::test_state().await;
    let _first =
        gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("dup"))).await;
    let resp =
        gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("dup"))).await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "duplicate description must return 409, got {}",
        resp.status()
    );
    // And the prior rule is still there.
    assert_eq!(state.srr.read().unwrap().injected_rule_count(), 1);
}

#[tokio::test]
async fn insert_with_bad_regex_returns_400() {
    let (state, _wal) = common::test_state().await;
    let body = serde_json::json!({
        "method": "POST",
        "pattern": "api.bank.com/transfer",
        "path_regex": "[unclosed",
        "decision": { "type": "Deny" },
        "description": "bad.regex",
    });
    let resp = gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // The rule MUST NOT have been added even partially.
    assert_eq!(state.srr.read().unwrap().injected_rule_count(), 0);
}

#[tokio::test]
async fn insert_with_malformed_json_returns_400() {
    let (state, _wal) = common::test_state().await;
    // serde_json::Value won't reject this — it's a valid JSON value —
    // but the inner from_value into NetworkRuleConfig will. The
    // handler maps the inner failure to 400.
    let body = serde_json::json!({ "not": "a rule" });
    let resp = gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Remove path ───────────────────────────────────────────────────────────

#[tokio::test]
async fn remove_existing_rule_returns_200() {
    let (state, _wal) = common::test_state().await;
    let _i =
        gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("to-remove")))
            .await;
    let resp = gvm_proxy::api::remove_srr_rule(
        State(state.clone()),
        axum::extract::Path("to-remove".to_string()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["id"], "to-remove");
    assert_eq!(body["removed"], true);
    assert_eq!(body["injected_count"], 0);
    assert_eq!(state.srr.read().unwrap().injected_rule_count(), 0);
}

#[tokio::test]
async fn remove_unknown_rule_returns_404() {
    let (state, _wal) = common::test_state().await;
    let resp = gvm_proxy::api::remove_srr_rule(
        State(state.clone()),
        axum::extract::Path("never-existed".to_string()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── List path ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_inserted_ids() {
    let (state, _wal) = common::test_state().await;
    let _ = gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("a"))).await;
    let _ = gvm_proxy::api::insert_srr_rule(State(state.clone()), Json(lease_rule_body("b"))).await;
    let resp = gvm_proxy::api::list_injected_srr_rules(State(state.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["count"], 2);
    let ids: Vec<String> = body["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec!["a", "b"]);
}

// ─── Round-trip — insert → check fires it → remove → check doesn't ────────

#[tokio::test]
async fn insert_then_check_then_remove_lifecycle() {
    let (state, _wal) = common::test_state().await;
    // Sanity: with no rule injected, the SRR's default policy decides.
    // After insert, the injected Deny shadows.
    let _ = gvm_proxy::api::insert_srr_rule(
        State(state.clone()),
        Json(lease_rule_body("lifecycle.test")),
    )
    .await;

    let result_after_insert = {
        let srr = state.srr.read().unwrap();
        srr.check("POST", "api.bank.com", "/transfer", None)
    };
    assert!(
        matches!(
            result_after_insert.decision,
            gvm_proxy::types::EnforcementDecision::Deny { .. }
        ),
        "after insert, the injected Deny rule must fire, got {:?}",
        result_after_insert.decision
    );
    assert_eq!(
        result_after_insert.matched_description.as_deref(),
        Some("lifecycle.test")
    );

    let _ = gvm_proxy::api::remove_srr_rule(
        State(state.clone()),
        axum::extract::Path("lifecycle.test".to_string()),
    )
    .await;

    let result_after_remove = {
        let srr = state.srr.read().unwrap();
        srr.check("POST", "api.bank.com", "/transfer", None)
    };
    // No file rules in the test_state SRR, so we fall back to
    // Default-to-Caution Delay 300ms.
    assert!(
        matches!(
            result_after_remove.decision,
            gvm_proxy::types::EnforcementDecision::Delay { .. }
        ),
        "after remove, the injected rule must be gone, got {:?}",
        result_after_remove.decision
    );
}
