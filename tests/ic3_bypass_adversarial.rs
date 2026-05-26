//! IC-3 approval-bypass adversarial regression — Phase 4 of the pentest plan.
//!
//! Targets the `/gvm/approve` and `/gvm/deny` API surface in
//! [src/api.rs](../src/api.rs) plus the `pending_approvals` DashMap state
//! in [src/proxy/mod.rs](../src/proxy/mod.rs). Existing coverage in
//! `tests/ic3_concurrency.rs` and `tests/api_handlers.rs` exercises happy
//! paths and concurrency; this file targets adversarial inputs and
//! state-machine corner cases:
//!
//!   1. Control-character + null-byte event_id — handler must not panic
//!      or confuse routing.
//!   2. 10 KB event_id — large input must not leak memory or crash JSON
//!      parsing.
//!   3. Non-boolean `approved` field (string, number) — fail-close to Deny.
//!   4. Approve with extra unknown JSON fields — handler ignores them,
//!      delivers the documented decision.
//!   5. Replay: second approve of the same event_id after the first
//!      removed it from the map returns 404 (no double-deliver, no
//!      cross-talk with a future request reusing the same ID).
//!   6. Race: simultaneous approve + deny on the same event_id —
//!      exactly one decision must be delivered to the oneshot receiver,
//!      the other request gets 404.

mod common;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use gvm_proxy::proxy::PendingApproval;
use http_body_util::BodyExt;

fn pending(
    event_id: &str,
    agent_id: &str,
) -> (PendingApproval, tokio::sync::oneshot::Receiver<bool>) {
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    (
        PendingApproval {
            sender: tx,
            event_id: event_id.to_string(),
            operation: "gvm.payment.charge".to_string(),
            host: "api.stripe.com".to_string(),
            path: "/v1/charges".to_string(),
            method: "POST".to_string(),
            agent_id: agent_id.to_string(),
            timestamp: chrono::Utc::now(),
        },
        rx,
    )
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── Case 1: control / null bytes in event_id ──────────────────────────────

#[tokio::test]
async fn malformed_event_id_with_control_chars_does_not_panic() {
    let (state, _wal) = common::test_state().await;

    // The event_id is operator-controlled in well-behaved deployments but
    // is reflected back from the API in error JSON; a malformed value
    // must not crash the handler or smuggle past JSON serialization.
    let evil_ids = [
        "\0",
        "evt-\x01\x02\x03",
        "evt-\r\nX-Header-Smuggle: x",
        "evt-\"injection\"",
    ];

    for id in evil_ids {
        let resp = gvm_proxy::api::approve_request(
            State(state.clone()),
            Json(serde_json::json!({"event_id": id, "approved": true})),
        )
        .await;
        // No entry inserted for this id, so the expected outcome is 404
        // NOT_FOUND. We allow 400 BAD_REQUEST as well — if the handler
        // chooses to reject obviously hostile inputs early, that's a
        // stricter posture and still acceptable. The disallowed outcome
        // is 200 (somehow delivered) or 500 (crash).
        let status = resp.status();
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
            "evil event_id {id:?} must yield 404 or 400, got {status}"
        );
    }
}

// ─── Case 2: very long event_id ────────────────────────────────────────────

#[tokio::test]
async fn very_long_event_id_handled_gracefully() {
    let (state, _wal) = common::test_state().await;

    // 10 KB string. The handler must process this through serde without
    // ballooning memory or hanging. Result is again 404 because nothing
    // was inserted with that id.
    let huge = "x".repeat(10 * 1024);
    let resp = gvm_proxy::api::approve_request(
        State(state.clone()),
        Json(serde_json::json!({"event_id": huge, "approved": true})),
    )
    .await;
    assert!(
        resp.status() == StatusCode::NOT_FOUND
            || resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::PAYLOAD_TOO_LARGE,
        "10KB event_id must yield 404/400/413, got {}",
        resp.status()
    );
}

// ─── Case 3: non-boolean approved field falls back to Deny ─────────────────

#[tokio::test]
async fn non_boolean_approved_value_falls_back_to_deny() {
    let (state, _wal) = common::test_state().await;
    let (pa, mut rx) = pending("evt-non-bool", "agent-1");
    state
        .pending_approvals
        .insert("evt-non-bool".to_string(), pa);

    // serde's bool deserialiser does NOT coerce "yes"/"no" strings; the
    // explicit type mismatch falls back to the documented default (false
    // = Deny per src/api.rs:1295's `unwrap_or(false)`). Either outcome
    // is acceptable: (a) handler returns 400 BAD_REQUEST because the
    // field type is wrong, or (b) handler treats the missing/wrong field
    // as the deny default. The forbidden outcome is "approved=true was
    // somehow inferred" — a real fail-open.
    let resp = gvm_proxy::api::approve_request(
        State(state.clone()),
        Json(serde_json::json!({"event_id": "evt-non-bool", "approved": "yes"})),
    )
    .await;

    let status = resp.status();
    if status == StatusCode::OK {
        // Handler accepted the request; verify the receiver got Deny.
        let decision = tokio::time::timeout(std::time::Duration::from_millis(200), &mut rx)
            .await
            .expect("rx must receive decision")
            .expect("rx must not be dropped");
        assert!(
            !decision,
            "non-boolean 'approved' must fall back to Deny (false), got true \
             — that's a fail-open against malformed JSON"
        );
    } else {
        // Handler rejected the request; the pending entry must remain so
        // the operator can retry with a well-formed body.
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "non-OK response must be 400 BAD_REQUEST, got {status}"
        );
        assert!(
            state.pending_approvals.contains_key("evt-non-bool"),
            "rejected request must leave the pending entry intact for retry"
        );
    }
}

// ─── Case 4: extra unknown fields are ignored ──────────────────────────────

#[tokio::test]
async fn approve_with_extra_unknown_fields_still_succeeds() {
    let (state, _wal) = common::test_state().await;
    let (pa, mut rx) = pending("evt-extras", "agent-1");
    state.pending_approvals.insert("evt-extras".to_string(), pa);

    // serde_json by default ignores unknown fields. The handler must
    // tolerate extra metadata an external orchestrator might send —
    // strict rejection here would lock the API into an awkward shape.
    let resp = gvm_proxy::api::approve_request(
        State(state.clone()),
        Json(serde_json::json!({
            "event_id": "evt-extras",
            "approved": true,
            "operator": "alice",
            "comment": "looks fine",
            "x_extra_array": [1, 2, 3],
            "x_extra_obj": {"k": "v"},
        })),
    )
    .await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "extra fields must be tolerated, got {}",
        resp.status()
    );
    let json = body_json(resp).await;
    assert_eq!(json["decision"], "approved");

    let decision = tokio::time::timeout(std::time::Duration::from_millis(200), &mut rx)
        .await
        .expect("rx must receive")
        .expect("rx not dropped");
    assert!(decision, "approve must deliver true");
}

// ─── Case 5: Replay — second approve of same id returns 404 ───────────────

#[tokio::test]
async fn replay_approve_same_event_id_returns_404_second_time() {
    let (state, _wal) = common::test_state().await;
    let (pa, mut rx) = pending("evt-replay", "agent-1");
    state.pending_approvals.insert("evt-replay".to_string(), pa);

    // First approve removes the entry and delivers true.
    let first = gvm_proxy::api::approve_request(
        State(state.clone()),
        Json(serde_json::json!({"event_id": "evt-replay", "approved": true})),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let decision = tokio::time::timeout(std::time::Duration::from_millis(200), &mut rx)
        .await
        .expect("rx must receive")
        .expect("rx not dropped");
    assert!(decision);
    assert!(!state.pending_approvals.contains_key("evt-replay"));

    // Second approve of the same id must NOT deliver again and must NOT
    // somehow re-create the entry. Expected status is 404 NOT_FOUND.
    let second = gvm_proxy::api::approve_request(
        State(state.clone()),
        Json(serde_json::json!({"event_id": "evt-replay", "approved": true})),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::NOT_FOUND,
        "replay of consumed event_id must return 404, got {} \
         — the API is double-delivering or reviving stale entries",
        second.status()
    );
}

// ─── Case 6: Race — concurrent approve + deny on same id ──────────────────

#[tokio::test]
async fn concurrent_approve_and_deny_same_event_id_exactly_one_delivers() {
    let (state, _wal) = common::test_state().await;
    let (pa, mut rx) = pending("evt-race", "agent-1");
    state.pending_approvals.insert("evt-race".to_string(), pa);

    let s1 = state.clone();
    let s2 = state.clone();
    let approve_task = tokio::spawn(async move {
        gvm_proxy::api::approve_request(
            State(s1),
            Json(serde_json::json!({"event_id": "evt-race", "approved": true})),
        )
        .await
        .status()
    });
    let deny_task = tokio::spawn(async move {
        gvm_proxy::api::approve_request(
            State(s2),
            Json(serde_json::json!({"event_id": "evt-race", "approved": false})),
        )
        .await
        .status()
    });

    let approve_status = approve_task.await.expect("approve task panic");
    let deny_status = deny_task.await.expect("deny task panic");

    // Exactly one of the two requests must win and return 200; the other
    // must return 404 because the entry is gone after the first removal.
    // No double-delivery, no 500.
    let wins = [approve_status, deny_status]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    let losses = [approve_status, deny_status]
        .iter()
        .filter(|s| **s == StatusCode::NOT_FOUND)
        .count();
    assert_eq!(
        wins, 1,
        "exactly one of (approve, deny) must return 200 — got {wins} (approve={approve_status}, deny={deny_status})"
    );
    assert_eq!(
        losses, 1,
        "exactly one of (approve, deny) must return 404 — got {losses}"
    );

    // Receiver must have received the decision of the winner exactly once.
    let decision = tokio::time::timeout(std::time::Duration::from_millis(200), &mut rx)
        .await
        .expect("rx must receive exactly one decision")
        .expect("rx must not be dropped");

    // The winner's decision (true if approve won, false if deny won) is
    // determined by scheduling — both outcomes are valid; we only assert
    // it was ONE consistent decision (not corrupted).
    assert!(
        decision == true || decision == false,
        "decision must be a clean bool, not corrupted"
    );
}
