//! HTTP error and governance-block response builders.
//!
//! Extracted from src/proxy.rs during the LOC cleanup pass. Three
//! response shapes share the same module:
//!   - `error_response` / `error_response_detailed` — generic JSON
//!     errors with optional GVM headers.
//!   - `governance_block_response` — the canonical block response
//!     contract every blocked request returns; agents (Python SDK,
//!     OpenClaw) parse this exact JSON shape.
//!   - `append_proxy_wal_event` — best-effort WAL append for
//!     enforcement decisions reached from proxy_handler / CONNECT.

use crate::types::*;
use axum::body::Body;
use axum::http::{Response, StatusCode};

use super::AppState;

/// Substitute `{rule_id}` in `template` with `matched_rule_id` to
/// produce the URL surfaced as `X-GVM-Policy-Link`. Returns None
/// when either input is absent — the link header is then omitted.
///
/// Why this lives here rather than as a method on `GovernanceBlockResponse`:
/// the type is in `gvm-types` and must not depend on operator
/// configuration. Building the link is a proxy-side concern that
/// reads `enforcement.policy_link_template` from `AppState`, so the
/// helper sits next to the response builder.
pub fn build_policy_link(template: Option<&str>, matched_rule_id: Option<&str>) -> Option<String> {
    let tmpl = template?;
    let rule_id = matched_rule_id?;
    Some(tmpl.replace("{rule_id}", rule_id))
}

/// Build a JSON error response with optional actionable details.
pub(super) fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    error_response_detailed(status, message, None, None, None, None)
}

/// Best-effort WAL append for enforcement decisions in proxy_handler / CONNECT.
/// Every governance decision (Deny, classification error) must be audited.
pub(super) fn append_proxy_wal_event(
    state: &AppState,
    method: &str,
    host: &str,
    path: &str,
    agent_id: &str,
    decision: &str,
    status_code: u16,
) {
    let event = gvm_types::GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: agent_id.to_string(),
        tenant_id: None,
        session_id: host.to_string(),
        timestamp: chrono::Utc::now(),
        operation: format!("{} {}", method, path),
        resource: gvm_types::ResourceDescriptor {
            service: host.to_string(),
            identifier: Some(path.to_string()),
            tier: gvm_types::ResourceTier::External,
            sensitivity: gvm_types::Sensitivity::Medium,
        },
        context: std::collections::HashMap::new(),
        transport: Some(gvm_types::TransportInfo {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            status_code: Some(status_code),
        }),
        decision: decision.to_string(),
        decision_source: "fail-close".to_string(),
        matched_rule_id: None,
        enforcement_point: "proxy".to_string(),
        status: gvm_types::EventStatus::Confirmed,
        payload: gvm_types::PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: state.current_integrity_ref(),
        operation_descriptor: Some(crate::operation::http(method, path)),
    };
    // Spawn background task for durable WAL write. Called from a sync
    // context (middleware/panic handler) where we cannot .await directly.
    // The spawned task calls append_durable to ensure the event reaches
    // the WAL file and Merkle chain.
    let ledger = state.ledger.clone();
    let decision_owned = decision.to_string();
    tokio::spawn(async move {
        if let Err(e) = ledger.append_durable(&event).await {
            tracing::error!(error = %e, decision = %decision_owned, "Proxy: enforcement WAL append FAILED");
        }
    });
}

pub(super) fn error_response_detailed(
    status: StatusCode,
    message: &str,
    decision: Option<&str>,
    event_id: Option<&str>,
    next_action: Option<&str>,
    retry_after: Option<u64>,
) -> Response<Body> {
    let mut body = serde_json::json!({
        "error": message,
        "status": status.as_u16(),
    });

    if let Some(d) = decision {
        body["decision"] = serde_json::Value::String(d.to_string());
    }
    if let Some(id) = event_id {
        body["event_id"] = serde_json::Value::String(id.to_string());
    }
    if let Some(action) = next_action {
        body["next_action"] = serde_json::Value::String(action.to_string());
    }
    if let Some(secs) = retry_after {
        body["retry_after"] = serde_json::Value::Number(secs.into());
    }

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json");

    // Include GVM metadata headers on error responses too,
    // so SDK clients can read enforcement details from headers.
    if let Some(d) = decision {
        builder = builder.header("X-GVM-Decision", d);
    }
    if let Some(id) = event_id {
        builder = builder.header("X-GVM-Event-Id", id);
    }
    if let Some(secs) = retry_after {
        builder = builder.header("Retry-After", secs.to_string());
    }

    builder
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .expect("fallback 500 response with empty body cannot fail")
        })
}

/// Build a structured governance block response.
///
/// Returns the standard `GovernanceBlockResponse` JSON body with appropriate
/// HTTP headers for SDK consumption. This is the contract between the proxy
/// and all agent SDKs — every blocked request uses this format.
pub(super) fn governance_block_response(
    status: StatusCode,
    block: GovernanceBlockResponse,
) -> Response<Body> {
    let body = serde_json::to_string(&block).unwrap_or_else(|_| {
        // Serialization of GovernanceBlockResponse should never fail,
        // but if it does, return a minimal valid JSON.
        r#"{"blocked":true,"error":"internal serialization error"}"#.to_string()
    });

    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("X-GVM-Decision", &block.decision)
        .header(
            "X-GVM-Block-Mode",
            match &block.mode {
                BlockResponseMode::Halt => "halt",
                BlockResponseMode::SoftPivot => "soft_pivot",
                BlockResponseMode::Rollback => "rollback",
            },
        );

    if !block.event_id.is_empty() {
        builder = builder.header("X-GVM-Event-Id", &block.event_id);
    }
    if !block.trace_id.is_empty() {
        builder = builder.header("X-GVM-Trace-Id", &block.trace_id);
    }
    if let Some(ref hint) = block.rollback_hint {
        builder = builder.header("X-GVM-Rollback-Hint", hint.as_str());
    }
    // Surface the matched rule and (optional) policy URL on block
    // responses too, not only on Allow paths. Without these headers
    // the agent gets `403 Forbidden` and the developer has to grep
    // proxy logs to know WHY the block fired — the failure mode the
    // visibility audit explicitly named "no actionable error".
    if let Some(ref rule_id) = block.matched_rule_id {
        if let Ok(v) = axum::http::HeaderValue::from_str(rule_id) {
            builder = builder.header("X-GVM-Matched-Rule", v);
        }
    }
    if let Some(ref link) = block.policy_link {
        if let Ok(v) = axum::http::HeaderValue::from_str(link) {
            builder = builder.header("X-GVM-Policy-Link", v);
        }
    }
    if let Some(secs) = block.retry_after_secs {
        builder = builder.header("Retry-After", secs.to_string());
    }

    builder.body(Body::from(body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .expect("fallback 500 response with empty body cannot fail")
    })
}
