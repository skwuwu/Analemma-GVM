//! Per-request header / event helpers.
//!
//! Extracted from src/proxy.rs during the LOC cleanup pass:
//!   - `parse_gvm_headers` — parse SDK-routed `X-GVM-*` headers, override
//!     identity from a verified JWT.
//!   - `extract_target` — derive the upstream Target from the request.
//!   - `remove_gvm_headers` — strip `X-GVM-*` before forwarding upstream.
//!   - `inject_gvm_response_headers` — stamp every response with decision
//!     metadata for SDK introspection.
//!   - `build_operation_metadata` — assemble OperationMetadata for events.
//!   - `build_event` — construct the audit-bound GVMEvent for the current
//!     request.

use crate::auth;
use crate::types::*;
use axum::body::Body;
use axum::http::Request;

/// Inject GVM metadata headers into the response so clients can inspect
/// the enforcement decision without parsing the body.
pub(super) fn inject_gvm_response_headers(
    headers: &mut axum::http::HeaderMap,
    event: &GVMEvent,
    classification: &Classification,
    engine_ms: f64,
    safety_delay_ms: u64,
) {
    let decision_str = format!("{:?}", classification.decision);
    let source_str = match classification.source {
        ClassificationSource::SRR => "SRR",
    };

    // Always inject these headers
    if let Ok(v) = axum::http::HeaderValue::from_str(&decision_str) {
        headers.insert("X-GVM-Decision", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(source_str) {
        headers.insert("X-GVM-Decision-Source", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&event.event_id) {
        headers.insert("X-GVM-Event-Id", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&event.trace_id) {
        headers.insert("X-GVM-Trace-Id", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("{:.1}", engine_ms)) {
        headers.insert("X-GVM-Engine-Ms", v);
    }
    if safety_delay_ms > 0 {
        if let Ok(v) = axum::http::HeaderValue::from_str(&safety_delay_ms.to_string()) {
            headers.insert("X-GVM-Safety-Delay-Ms", v);
        }
    }
    if let Some(ref rule_id) = classification.matched_rule_id {
        if let Ok(v) = axum::http::HeaderValue::from_str(rule_id) {
            headers.insert("X-GVM-Matched-Rule", v);
        }
    }
}

/// Build OperationMetadata from SDK headers for audit trail recording.
pub(super) fn build_operation_metadata(
    headers: &GVMHeaders,
    _target: &Target,
) -> OperationMetadata {
    OperationMetadata {
        operation: headers.operation.clone(),
        resource: headers.resource.clone().unwrap_or_default(),
        subject: SubjectDescriptor {
            agent_id: headers.agent_id.clone(),
            tenant_id: headers.tenant_id.clone(),
            session_id: headers
                .session_id
                .clone()
                .unwrap_or_else(|| headers.trace_id.clone()),
        },
        context: OperationContext {
            attributes: headers.context.clone(),
        },
        payload: PayloadDescriptor::default(),
    }
}

/// Build a GVMEvent for ledger recording.
pub(super) fn build_event(
    classification: &Classification,
    gvm_headers: &Option<GVMHeaders>,
    target: &Target,
) -> GVMEvent {
    let (agent_id, trace_id, event_id, parent_event_id, operation, session_id, tenant_id) =
        match gvm_headers {
            Some(h) => (
                h.agent_id.clone(),
                h.trace_id.clone(),
                h.event_id.clone(),
                h.parent_event_id.clone(),
                h.operation.clone(),
                h.session_id
                    .clone()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                h.tenant_id.clone(),
            ),
            None => (
                "unknown".to_string(),
                uuid::Uuid::new_v4().to_string(),
                uuid::Uuid::new_v4().to_string(),
                None,
                "unknown".to_string(),
                uuid::Uuid::new_v4().to_string(),
                None,
            ),
        };

    GVMEvent {
        event_id,
        trace_id,
        parent_event_id,
        agent_id,
        tenant_id,
        session_id,
        timestamp: chrono::Utc::now(),
        operation,
        resource: classification
            .operation
            .as_ref()
            .map(|o| o.resource.clone())
            .unwrap_or_default(),
        context: classification
            .operation
            .as_ref()
            .map(|o| o.context.attributes.clone())
            .unwrap_or_default(),
        transport: Some(TransportInfo {
            method: "".to_string(), // Populated by proxy_handler after build_event
            host: target.host.clone(),
            path: target.path.clone(),
            status_code: None,
        }),
        decision: format!("{:?}", classification.decision),
        decision_source: format!("{:?}", classification.source),
        matched_rule_id: classification.matched_rule_id.clone(),
        enforcement_point: match classification.source {
            ClassificationSource::SRR => "proxy".to_string(),
        },
        status: EventStatus::Pending,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None, // Computed by Ledger during WAL write
        llm_trace: None,
        default_caution: false, // Set by caller after build_event
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

/// Parse GVM-specific headers from an SDK-routed request.
/// When a verified JWT identity is provided, it overrides the self-declared
/// X-GVM-Agent-Id and X-GVM-Tenant-Id headers for spoofing prevention.
pub(super) fn parse_gvm_headers(
    request: &Request<Body>,
    verified: Option<&auth::VerifiedIdentity>,
) -> Option<GVMHeaders> {
    // If JWT-verified identity exists, use it; otherwise fall back to header
    let agent_id = if let Some(v) = verified {
        v.agent_id.clone()
    } else {
        request
            .headers()
            .get("X-GVM-Agent-Id")?
            .to_str()
            .ok()?
            .to_string()
    };

    let operation = request
        .headers()
        .get("X-GVM-Operation")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let trace_id = request
        .headers()
        .get("X-GVM-Trace-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let event_id = request
        .headers()
        .get("X-GVM-Event-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let parent_event_id = request
        .headers()
        .get("X-GVM-Parent-Event-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let resource = request
        .headers()
        .get("X-GVM-Resource")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str(s).ok());

    let context = request
        .headers()
        .get("X-GVM-Context")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let session_id = request
        .headers()
        .get("X-GVM-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let tenant_id = if let Some(v) = verified {
        v.tenant_id.clone()
    } else {
        request
            .headers()
            .get("X-GVM-Tenant-Id")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };

    let rate_limit = request
        .headers()
        .get("X-GVM-Rate-Limit")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    Some(GVMHeaders {
        agent_id,
        trace_id,
        parent_event_id,
        event_id,
        operation,
        resource,
        context,
        session_id,
        tenant_id,
        rate_limit,
    })
}

/// Extract the forwarding target from the request.
/// Priority: X-GVM-Target-Host header > Host header
pub(super) fn extract_target(request: &Request<Body>) -> Option<Target> {
    let host = request
        .headers()
        .get("X-GVM-Target-Host")
        .or_else(|| request.headers().get("Host"))
        .and_then(|v| v.to_str().ok())?
        .to_string();

    let path = request.uri().path().to_string();
    let query = request.uri().query().map(String::from);

    // Use the request's actual scheme if present (absolute-form URI: http://host/path).
    // Fall back to https for external hosts, http for localhost.
    let scheme = request
        .uri()
        .scheme_str()
        .map(String::from)
        .unwrap_or_else(|| {
            let stripped = gvm_types::strip_port(&host);
            let is_local = stripped == "localhost"
                || stripped == "127.0.0.1"
                || stripped == "[::1]"
                || stripped == "::1";
            if is_local { "http" } else { "https" }.to_string()
        });

    Some(Target {
        scheme,
        host,
        path,
        query,
    })
}

/// Remove GVM-specific headers before forwarding to upstream.
///
/// Public so integration tests can verify the actual prefix list
/// (rather than re-implementing it and giving false coverage).
pub fn remove_gvm_headers(headers: &mut axum::http::HeaderMap) {
    let gvm_prefixes = [
        "x-gvm-agent-id",
        "x-gvm-trace-id",
        "x-gvm-parent-event-id",
        "x-gvm-event-id",
        "x-gvm-operation",
        "x-gvm-resource",
        "x-gvm-context",
        "x-gvm-session-id",
        "x-gvm-tenant-id",
        "x-gvm-rate-limit",
        "x-gvm-target-host",
    ];

    for prefix in &gvm_prefixes {
        headers.remove(*prefix);
    }
}
