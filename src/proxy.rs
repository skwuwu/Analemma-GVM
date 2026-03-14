use crate::api_keys::APIKeyStore;
use crate::ledger::Ledger;
use crate::policy::PolicyEngine;
use crate::rate_limiter::RateLimiter;
use crate::registry::OperationRegistry;
use crate::srr::NetworkSRR;
use crate::types::*;
use crate::vault::Vault;
use crate::wasm_engine::WasmEngine;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use std::collections::HashMap;
use std::sync::Arc;

/// Shared application state passed to all handlers
#[derive(Clone)]
pub struct AppState {
    pub srr: Arc<NetworkSRR>,
    pub policy: Arc<PolicyEngine>,
    pub registry: Arc<OperationRegistry>,
    pub api_keys: Arc<APIKeyStore>,
    pub ledger: Arc<Ledger>,
    pub vault: Arc<Vault>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Layer 1: Wasm governance engine (immutable policy sandbox)
    pub wasm_engine: Arc<WasmEngine>,
    pub http_client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Body,
    >,
    /// Dev-only: remap external hostnames to local addresses for forwarding.
    /// SRR matching uses the original host; only forwarding is redirected.
    pub host_overrides: HashMap<String, String>,
}

/// Main proxy handler — all requests route here via axum fallback.
/// Implements the 3-layer security pipeline (PART 5.2).
pub async fn proxy_handler(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response<Body> {
    // ── Step 1: Parse request ──
    let gvm_headers = parse_gvm_headers(&request);
    let target = match extract_target(&request) {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Missing or invalid target host. Use X-GVM-Target-Host header or Host header.",
            );
        }
    };

    // ── Step 2: Classify (IC determination) ──
    let classification = if let Some(ref headers) = gvm_headers {
        // SDK-routed: Layer 1 Semantic classification via ABAC policy engine
        let operation = build_operation_metadata(headers, &target);
        let (policy_decision, matched_rule) = state.policy.evaluate(&operation);

        // Also check network SRR (Deny in SRR overrides policy)
        let srr_decision = state.srr.check(
            request.method().as_str(),
            &target.host,
            &target.path,
            None,
        );

        // Determine which layer won (max_strict picks the strictest)
        let final_decision = max_strict(srr_decision.clone(), policy_decision.clone());
        let source = if srr_decision.strictness() > policy_decision.strictness() {
            ClassificationSource::SRR
        } else {
            ClassificationSource::ABAC
        };

        Classification {
            decision: final_decision,
            source,
            operation: Some(operation),
            matched_rule_id: matched_rule,
        }
    } else {
        // Direct HTTP: Layer 2 Network SRR classification
        let network_decision = state.srr.check(
            request.method().as_str(),
            &target.host,
            &target.path,
            None,
        );

        Classification {
            decision: network_decision,
            source: ClassificationSource::SRR,
            operation: None,
            matched_rule_id: None,
        }
    };

    let agent_id = gvm_headers
        .as_ref()
        .map(|h| h.agent_id.as_str())
        .unwrap_or("unknown");

    tracing::info!(
        method = %request.method(),
        host = %target.host,
        path = %target.path,
        agent = %agent_id,
        source = ?classification.source,
        decision = ?classification.decision,
        rule = ?classification.matched_rule_id,
        "Request classified"
    );

    // ── Step 3: Rate Limit check ──
    if let EnforcementDecision::Throttle { max_per_minute } = &classification.decision {
        if !state.rate_limiter.check(agent_id, *max_per_minute) {
            return error_response_detailed(
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                Some("Throttle"),
                None,
                Some("Wait and retry after the rate limit window resets"),
                Some(60),
            );
        }
    }

    // ── Step 4: Enforcement with EventStatus lifecycle ──
    let mut event = build_event(&classification, &gvm_headers, &target);

    // Measure engine processing time (classification was already done above)
    let engine_start = std::time::Instant::now();

    match &classification.decision {
        EnforcementDecision::Allow => {
            // Fast path: forward immediately, async ledger (IC-1, loss tolerated)
            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;
            event.status = EventStatus::Confirmed;
            state.ledger.append_async(event.clone()).await;
            inject_gvm_response_headers(
                response.headers_mut(), &event, &classification, engine_ms, 0,
            );
            response
        }

        EnforcementDecision::Delay { milliseconds } => {
            // IC-2: WAL-first durable write → delay → forward
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed — rejecting request (Fail-Close)");
                return error_response_detailed(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Audit log unavailable — request rejected for safety",
                    None,
                    None,
                    Some("Check proxy logs. The WAL ledger may be full or the disk may be unavailable."),
                    None,
                );
            }

            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
            let mut response = forward_request(&state, request, &target).await;

            // Update event status based on upstream response
            if response.status().is_success() {
                event.status = EventStatus::Confirmed;
            } else {
                event.status = EventStatus::Failed {
                    reason: format!("HTTP {}", response.status()),
                };
            }
            // Best-effort status update to WAL
            let _ = state.ledger.append_durable(&event).await;
            inject_gvm_response_headers(
                response.headers_mut(), &event, &classification, engine_ms, *milliseconds,
            );
            response
        }

        EnforcementDecision::RequireApproval { urgency } => {
            // IC-3: block and record. Do not forward.
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for IC-3 event");
            }

            tracing::warn!(
                host = %target.host,
                path = %target.path,
                urgency = ?urgency,
                "Request requires approval — blocked"
            );
            error_response_detailed(
                StatusCode::FORBIDDEN,
                &format!(
                    "IC-3: Administrator approval required (urgency: {:?})",
                    urgency
                ),
                Some("RequireApproval"),
                Some(&event.event_id),
                Some("Submit approval request to your GVM administrator"),
                None,
            )
        }

        EnforcementDecision::Deny { reason } => {
            event.status = EventStatus::Failed {
                reason: format!("Denied: {}", reason),
            };
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for Deny event");
            }

            tracing::warn!(
                host = %target.host,
                path = %target.path,
                reason = %reason,
                "Request denied by policy"
            );
            error_response_detailed(
                StatusCode::FORBIDDEN,
                reason,
                Some("Deny"),
                Some(&event.event_id),
                Some("This operation is blocked by policy. Contact your GVM administrator to review the rule."),
                None,
            )
        }

        EnforcementDecision::Throttle { .. } => {
            // Rate limit already checked above. If we reach here, request is allowed.
            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;
            event.status = EventStatus::Confirmed;
            state.ledger.append_async(event.clone()).await;
            inject_gvm_response_headers(
                response.headers_mut(), &event, &classification, engine_ms, 0,
            );
            response
        }

        EnforcementDecision::AuditOnly { alert_level } => {
            // Allow execution but elevate audit priority
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for AuditOnly event");
            }

            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;

            event.status = if response.status().is_success() {
                EventStatus::Confirmed
            } else {
                EventStatus::Failed {
                    reason: format!("HTTP {}", response.status()),
                }
            };
            let _ = state.ledger.append_durable(&event).await;

            if matches!(alert_level, AlertLevel::Critical) {
                tracing::warn!(
                    event_id = %event.event_id,
                    "Critical audit event — operator notification required"
                );
            }
            inject_gvm_response_headers(
                response.headers_mut(), &event, &classification, engine_ms, 0,
            );
            response
        }
    }
}

/// Inject GVM metadata headers into the response so clients can inspect
/// the enforcement decision without parsing the body.
fn inject_gvm_response_headers(
    headers: &mut axum::http::HeaderMap,
    event: &GVMEvent,
    classification: &Classification,
    engine_ms: f64,
    safety_delay_ms: u64,
) {
    let decision_str = format!("{:?}", classification.decision);
    let source_str = match classification.source {
        ClassificationSource::ABAC => "ABAC",
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

/// Build OperationMetadata from SDK headers for ABAC policy evaluation.
fn build_operation_metadata(headers: &GVMHeaders, target: &Target) -> OperationMetadata {
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
fn build_event(
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
            method: "".to_string(), // Populated post-forward
            host: target.host.clone(),
            path: target.path.clone(),
            status_code: None,
        }),
        decision: format!("{:?}", classification.decision),
        decision_source: format!("{:?}", classification.source),
        matched_rule_id: classification.matched_rule_id.clone(),
        enforcement_point: match classification.source {
            ClassificationSource::ABAC => "both".to_string(),
            ClassificationSource::SRR => "proxy".to_string(),
        },
        status: EventStatus::Pending,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None, // Computed by Ledger during WAL write
    }
}

/// Forward the request to the target with API key injection (Layer 3).
async fn forward_request(
    state: &AppState,
    request: Request<Body>,
    target: &Target,
) -> Response<Body> {
    let (mut parts, body) = request.into_parts();

    // Inject API credentials (Layer 3: Capability Token)
    if let Err(e) = state.api_keys.inject(&mut parts.headers, &target.host) {
        tracing::error!(error = %e, "Failed to inject API key");
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Credential injection failed",
        );
    }

    // Remove proxy-specific headers before forwarding
    remove_gvm_headers(&mut parts.headers);

    // Build the outbound URI (apply dev host override if configured)
    let forward_host = state
        .host_overrides
        .get(&target.host)
        .unwrap_or(&target.host);
    let forward_scheme = {
        let h = forward_host.split(':').next().unwrap_or(forward_host);
        if h == "localhost" || h == "127.0.0.1" {
            "http"
        } else {
            &target.scheme
        }
    };
    let query_part = target
        .query
        .as_ref()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let uri_str = format!(
        "{}://{}{}{}",
        forward_scheme, forward_host, target.path, query_part
    );

    let uri: Uri = match uri_str.parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(uri = %uri_str, error = %e, "Invalid forward URI");
            return error_response(StatusCode::BAD_GATEWAY, "Invalid upstream URI");
        }
    };
    parts.uri = uri;

    let outbound = Request::from_parts(parts, body);

    // Forward to upstream
    match state.http_client.request(outbound).await {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            let body_stream = http_body_util::BodyDataStream::new(body);
            Response::from_parts(parts, Body::from_stream(body_stream))
        }
        Err(e) => {
            tracing::error!(error = %e, "Upstream request failed");
            error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream error: {}", e),
            )
        }
    }
}

/// Parse GVM-specific headers from an SDK-routed request.
fn parse_gvm_headers(request: &Request<Body>) -> Option<GVMHeaders> {
    let agent_id = request
        .headers()
        .get("X-GVM-Agent-Id")?
        .to_str()
        .ok()?
        .to_string();

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

    let tenant_id = request
        .headers()
        .get("X-GVM-Tenant-Id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

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
fn extract_target(request: &Request<Body>) -> Option<Target> {
    let host = request
        .headers()
        .get("X-GVM-Target-Host")
        .or_else(|| request.headers().get("Host"))
        .and_then(|v| v.to_str().ok())?
        .to_string();

    let path = request.uri().path().to_string();
    let query = request.uri().query().map(String::from);

    // Select scheme based on target host.
    // Note: IPv6 loopback ([::1]) is not handled here for MVP.
    // Production should use a proper scheme negotiation (e.g. X-GVM-Target-Scheme header).
    let host_without_port = host.split(':').next().unwrap_or(&host);
    let scheme = if host_without_port == "localhost" || host_without_port == "127.0.0.1" {
        "http".to_string()
    } else {
        "https".to_string()
    };

    Some(Target {
        scheme,
        host,
        path,
        query,
    })
}

/// Remove GVM-specific headers before forwarding to upstream
fn remove_gvm_headers(headers: &mut axum::http::HeaderMap) {
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

/// Build a JSON error response with optional actionable details.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    error_response_detailed(status, message, None, None, None, None)
}

fn error_response_detailed(
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
                .unwrap()
        })
}
