//! WAL event broadcast + SSE filter regression — Tier-3 P3-b.
//!
//! Two layers:
//!
//!   1. **Broadcast fan-out** — the `Ledger`'s broadcast Sender (held
//!      identically by `AppState.event_broadcast`) fires on every
//!      successful `append_durable`. A subscriber attached to the
//!      same Sender via `subscribe()` must receive the event verbatim.
//!      This is the core wiring that makes `GET /gvm/events` work.
//!
//!   2. **Filter logic** — `api::event_matches_filter` is the
//!      stand-alone function the SSE handler calls per event. We
//!      exercise its `agent_id` and `decision` branches directly so
//!      regressions surface here, not inside the streaming machinery.
//!
//! The HTTP / SSE plumbing (chunked transfer, keep-alive, lagged
//! event emission) is hard to drive in a pure-Rust test and is
//! covered by the EC2 end-to-end suite. What this test pins:
//!   - the channel is wired
//!   - the filter is correct
//!   - subscribers receive every event the WAL accepts
//!   - WAL writer is never blocked by a lagged subscriber

mod common;

use gvm_proxy::api::{event_matches_filter, EventsQuery};
use gvm_types::{EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor};
use std::collections::HashMap;

/// Minimal GVMEvent with overridable agent_id + decision so each test
/// reads as a one-line setup. Mirrors the helper in
/// `tests/anchor_wiring.rs`; kept local to avoid a public test
/// helper module that other suites would need to import.
fn evt(label: &str, agent_id: &str, decision: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-{label}"),
        trace_id: format!("trace-{label}"),
        parent_event_id: None,
        agent_id: agent_id.to_string(),
        token_id: None,
        tenant_id: None,
        session_id: format!("sess-{label}"),
        timestamp: chrono::Utc::now(),
        operation: "gvm.test.events_stream".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: decision.to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

// ─── Filter logic ──────────────────────────────────────────────────────────

fn no_filter() -> EventsQuery {
    EventsQuery {
        agent_id: None,
        decision: None,
    }
}

#[test]
fn filter_with_no_params_matches_every_event() {
    let e = evt("a", "any", "Allow");
    assert!(event_matches_filter(&e, &no_filter()));
}

#[test]
fn filter_by_agent_id_excludes_other_agents() {
    let alpha = evt("a", "claims-reviewer-1842", "Allow");
    let beta = evt("b", "release-bot", "Allow");
    let params = EventsQuery {
        agent_id: Some("claims-reviewer-1842".to_string()),
        decision: None,
    };
    assert!(event_matches_filter(&alpha, &params));
    assert!(!event_matches_filter(&beta, &params));
}

#[test]
fn filter_by_decision_uses_prefix_match() {
    // Production WAL events store the decision as a string like
    // "Delay(300ms)" or "Deny" — the filter accepts a prefix so
    // `decision=Delay` catches every Delay variant regardless of
    // the embedded milliseconds.
    let delay_event = evt("d", "any", "Delay(300ms)");
    let deny_event = evt("D", "any", "Deny");
    let params_delay = EventsQuery {
        agent_id: None,
        decision: Some("Delay".to_string()),
    };
    assert!(event_matches_filter(&delay_event, &params_delay));
    assert!(!event_matches_filter(&deny_event, &params_delay));
}

#[test]
fn filter_combines_agent_and_decision_as_and() {
    let target = evt("t", "agent-X", "Deny");
    let wrong_agent = evt("u", "agent-Y", "Deny");
    let wrong_decision = evt("v", "agent-X", "Allow");

    let params = EventsQuery {
        agent_id: Some("agent-X".to_string()),
        decision: Some("Deny".to_string()),
    };
    assert!(event_matches_filter(&target, &params));
    assert!(!event_matches_filter(&wrong_agent, &params));
    assert!(!event_matches_filter(&wrong_decision, &params));
}

#[test]
fn filter_is_case_sensitive_on_decision() {
    // First cut is strict exact-prefix. A future relaxation should
    // come with an explicit operator opt-in, not silent case-folding
    // (which would let "deny" smuggle past a strict "Deny" subscriber).
    let event = evt("c", "agent", "Deny");
    let params = EventsQuery {
        agent_id: None,
        decision: Some("deny".to_string()),
    };
    assert!(!event_matches_filter(&event, &params));
}

// ─── Broadcast fan-out — Ledger → subscriber ──────────────────────────────

#[tokio::test]
async fn append_durable_fans_out_to_subscribers() {
    // `test_state()` builds an AppState whose Ledger holds the same
    // broadcast Sender as `state.event_broadcast`. Subscribe BEFORE
    // appending so the receiver sees the event in its buffer.
    let (state, _wal) = common::test_state().await;
    let mut rx = state.event_broadcast.subscribe();

    let event = evt("fan-out", "agent-007", "Allow");
    state.ledger.append_durable(&event).await.expect("append");

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for broadcast")
        .expect("broadcast channel closed");
    assert_eq!(received.event_id, "evt-fan-out");
    assert_eq!(received.agent_id, "agent-007");
    assert_eq!(received.decision, "Allow");
}

#[tokio::test]
async fn append_with_no_subscribers_does_not_fail() {
    // With zero receivers, `broadcast::Sender::send` returns Err — the
    // Ledger silently ignores that. A WAL append MUST succeed even
    // when nobody is listening.
    let (state, _wal) = common::test_state().await;
    let event = evt("solo", "agent", "Allow");
    let result = state.ledger.append_durable(&event).await;
    assert!(
        result.is_ok(),
        "append must succeed regardless of subscriber count, got {:?}",
        result
    );
}

#[tokio::test]
async fn multiple_subscribers_each_receive_each_event() {
    let (state, _wal) = common::test_state().await;
    let mut rx1 = state.event_broadcast.subscribe();
    let mut rx2 = state.event_broadcast.subscribe();

    let event = evt("multi", "agent", "Allow");
    state.ledger.append_durable(&event).await.expect("append");

    let r1 = tokio::time::timeout(std::time::Duration::from_secs(1), rx1.recv())
        .await
        .expect("rx1 timeout")
        .expect("rx1 closed");
    let r2 = tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv())
        .await
        .expect("rx2 timeout")
        .expect("rx2 closed");
    assert_eq!(r1.event_id, "evt-multi");
    assert_eq!(r2.event_id, "evt-multi");
}

#[tokio::test]
async fn slow_subscriber_lags_without_blocking_writer() {
    // `test_state()`'s channel capacity is 64. We append a burst of
    // 200 events while a "slow" subscriber holds its Receiver
    // without reading. The writes MUST all succeed. The slow
    // subscriber's next `recv()` returns `RecvError::Lagged(n)` so
    // the SSE handler can close the connection cleanly — this is
    // the backpressure contract.
    let (state, _wal) = common::test_state().await;
    let mut slow_rx = state.event_broadcast.subscribe();

    for i in 0..200u32 {
        let event = evt(&format!("burst-{i}"), "agent", "Allow");
        state
            .ledger
            .append_durable(&event)
            .await
            .expect("append must succeed even with a lagged subscriber");
    }

    // First recv should report Lagged with a positive skip count.
    match slow_rx.recv().await {
        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
            assert!(
                skipped > 0,
                "Lagged report must say how many events were skipped"
            );
        }
        other => panic!("expected Lagged(_), got {other:?}"),
    }
}
