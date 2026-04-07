use crate::api_keys::APIKeyStore;
use crate::auth;
use crate::config::OnBlockConfig;
use crate::ledger::Ledger;
use crate::llm_trace;
use crate::policy::PolicyEngine;
use crate::rate_limiter::RateLimiter;
use crate::registry::OperationRegistry;
use crate::srr::NetworkSRR;
use crate::types::*;
use crate::vault::Vault;
#[cfg(feature = "wasm")]
use crate::wasm_engine::WasmEngine;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;

// ─── IC-3 Pending Approval ───

/// A pending IC-3 approval request held by the proxy.
/// The proxy creates a oneshot channel and waits for the decision.
#[derive(Debug)]
pub struct PendingApproval {
    /// Oneshot sender — deliver `true` (approve) or `false` (deny)
    pub sender: tokio::sync::oneshot::Sender<bool>,
    /// Event metadata for display in CLI/API
    pub event_id: String,
    pub operation: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub agent_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ─── Circuit Breaker Configuration ───

/// Number of consecutive primary WAL failures before the circuit breaker opens.
/// When open, IC-2/3 requests are rejected with 503 to prevent cascading failures.
const CIRCUIT_BREAKER_THRESHOLD: u64 = 5;

/// Retry-After header value (seconds) sent in 503 responses when the circuit breaker is open.
const CIRCUIT_BREAKER_RETRY_SECS: u64 = 30;

/// Shared application state passed to all handlers
#[derive(Clone)]
pub struct AppState {
    pub srr: Arc<std::sync::RwLock<NetworkSRR>>,
    pub policy: Arc<std::sync::RwLock<PolicyEngine>>,
    pub registry: Arc<std::sync::RwLock<OperationRegistry>>,
    pub api_keys: Arc<APIKeyStore>,
    pub ledger: Arc<Ledger>,
    pub vault: Arc<Vault>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Layer 1: Wasm governance engine (immutable policy sandbox).
    /// Only available when compiled with --features wasm.
    #[cfg(feature = "wasm")]
    pub wasm_engine: Arc<WasmEngine>,
    /// Checkpoint Merkle tree registry — tracks plaintext content hashes
    /// as leaves for O(log N) Merkle proof verification on restore.
    pub checkpoint_registry: crate::api::CheckpointRegistry,
    pub http_client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Body,
    >,
    /// Per-decision block response mode configuration.
    /// Controls how agents should react to blocked operations.
    pub on_block: OnBlockConfig,
    /// Dev-only: remap external hostnames to local addresses for forwarding.
    /// SRR matching uses the original host; only forwarding is redirected.
    pub host_overrides: HashMap<String, String>,
    /// JWT authentication config (None = disabled, header-based identity).
    pub jwt_config: Option<Arc<auth::JwtConfig>>,
    /// Shadow Mode: intent verification store.
    pub intent_store: Arc<crate::intent_store::IntentStore>,
    /// Shadow Mode configuration.
    pub shadow_config: crate::intent_store::ShadowConfig,
    /// SRR config file path (for hot-reload).
    pub srr_config_path: String,
    /// ABAC policy directory path (for hot-reload).
    pub policy_dir: String,
    /// Operation registry file path (for hot-reload).
    pub registry_path: String,
    /// MITM CA certificate PEM (for sandbox trust store download via GET /gvm/ca.pem).
    /// None when TLS MITM is not active.
    pub mitm_ca_pem: Option<Arc<Vec<u8>>>,
    /// SRR payload inspection: buffer request body for JSON field matching.
    pub payload_inspection: bool,
    /// Maximum body bytes to buffer for payload inspection.
    pub max_body_bytes: usize,
    /// IC-3 pending approval queue.
    /// Key: event_id. Value: oneshot sender for approval decision (true = approve, false = deny).
    /// When IC-3 is triggered, the proxy holds the HTTP response and waits for
    /// POST /gvm/approve to deliver the decision via this channel.
    pub pending_approvals: Arc<dashmap::DashMap<String, PendingApproval>>,
    /// IC-3 approval timeout in seconds.
    pub ic3_approval_timeout_secs: u64,
    /// TLS MITM resolver for CONNECT handler inline inspection.
    /// Shared with the port-8443 TLS listener for a single cert cache.
    pub mitm_resolver: Option<std::sync::Arc<crate::tls_proxy::GvmCertResolver>>,
    /// Pre-built rustls ServerConfig for agent-facing TLS termination.
    pub mitm_server_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// Pre-built rustls ClientConfig for upstream TLS connections.
    pub mitm_client_config: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// TLS MITM cert cache pre-warm complete. False until all known domain
    /// certs are generated. Health endpoint includes this so proxy_manager
    /// can wait for TLS readiness before starting sandbox agents.
    pub tls_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Process start time — surfaced as `uptime_secs` in `/gvm/health`.
    pub start_time: std::time::Instant,
    /// Total proxied requests since start. Incremented at the top of
    /// `proxy_handler` and surfaced as `total_requests` in `/gvm/health`.
    /// `Relaxed` is sufficient — we never branch on this value.
    pub request_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Days until the MITM CA certificate expires (computed at startup from
    /// `not_after`). `None` when MITM is not active.
    pub ca_expires_days: Option<i64>,
}

/// Derive event status from upstream HTTP response.
fn event_status_from_response(response: &Response<Body>) -> EventStatus {
    if response.status().is_success() {
        EventStatus::Confirmed
    } else {
        EventStatus::Failed {
            reason: format!("HTTP {}", response.status()),
        }
    }
}

/// Main proxy handler — all requests route here via axum fallback.
/// Implements the 3-layer security pipeline (PART 5.2).
pub async fn proxy_handler(
    State(state): State<AppState>,
    mut request: Request<Body>,
) -> Response<Body> {
    // Bump the request counter for `/gvm/health` observability.
    // Relaxed is sufficient — we never branch on this value.
    state
        .request_counter
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // ── Step 0: Verify JWT identity (if configured) ──
    let verified_identity = if let Some(ref jwt) = state.jwt_config {
        match auth::extract_bearer_token(request.headers()) {
            Some(token) => match auth::verify_token(jwt, token) {
                Ok(identity) => {
                    tracing::debug!(
                        agent = %identity.agent_id,
                        token_id = %identity.token_id,
                        "JWT identity verified"
                    );
                    Some(identity)
                }
                Err(e) => {
                    tracing::warn!("JWT verification failed — rejecting request");
                    tracing::debug!(error = %e, "JWT verification error detail");
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "Invalid or expired authentication token",
                    );
                }
            },
            None => {
                tracing::warn!("No JWT token provided — using unverified X-GVM-Agent-Id header");
                None
            }
        }
    } else {
        None
    };

    // ── Step 1: Parse request ──
    let gvm_headers = parse_gvm_headers(&request, verified_identity.as_ref());
    let target = match extract_target(&request) {
        Some(t) => t,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "Missing or invalid target host. Use X-GVM-Target-Host header or Host header.",
            );
        }
    };

    // Capture the HTTP method before classification (request may be consumed later)
    let request_method = request.method().to_string();

    // ── Step 1.5: Buffer request body for SRR payload inspection (if enabled) ──
    // Body is buffered once, then re-attached to the request for forwarding.
    let body_bytes: Option<Bytes> = if state.payload_inspection {
        // Check Content-Length to avoid buffering oversized requests
        let content_length = request
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        if content_length > 0 && content_length <= state.max_body_bytes {
            // Swap body out of request, buffer it, then re-attach
            let body = std::mem::replace(request.body_mut(), Body::empty());
            match axum::body::to_bytes(body, state.max_body_bytes).await {
                Ok(bytes) if !bytes.is_empty() => Some(bytes),
                Ok(_) => None,
                Err(e) => {
                    tracing::debug!(error = %e, "Failed to buffer request body for payload inspection — skipping");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let body_for_srr: Option<&[u8]> = body_bytes.as_deref();

    // Re-attach buffered body to request so forward_request can send it upstream.
    // If body was consumed by to_bytes(), we replace it with the buffered copy.
    if let Some(ref bytes) = body_bytes {
        *request.body_mut() = Body::from(bytes.clone());
    }

    // ── Step 2: Classify (IC determination) ──
    let (mut classification, mut is_default_caution) = if let Some(ref headers) = gvm_headers {
        // SDK-routed: Layer 1 Semantic classification via ABAC policy engine
        let operation = build_operation_metadata(headers, &target);
        let (policy_decision, matched_rule) = match state.policy.read() {
            Ok(p) => p.evaluate(&operation),
            Err(_) => {
                tracing::error!("Policy lock poisoned — denying (fail-close)");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal governance error — request denied (fail-close)",
                );
            }
        };

        // Also check network SRR (Deny in SRR overrides policy)
        let srr = match state.srr.read() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("SRR lock poisoned — denying request (fail-close)");
                append_proxy_wal_event(
                    &state,
                    request.method().as_str(),
                    &target.host,
                    &target.path,
                    "unknown",
                    "Deny (SRR lock poisoned)",
                    500,
                );
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal governance error — request denied (fail-close)",
                );
            }
        };
        let srr_result = srr.check(
            request.method().as_str(),
            &target.host,
            &target.path,
            body_for_srr,
        );
        drop(srr);

        // Determine which layer won (max_strict picks the strictest)
        let final_decision = max_strict(srr_result.decision.clone(), policy_decision.clone());
        let srr_won = srr_result.decision.strictness() > policy_decision.strictness();
        let source = if srr_won {
            ClassificationSource::SRR
        } else {
            ClassificationSource::ABAC
        };

        // Use SRR description as matched_rule_id when SRR produced the stricter decision
        let rule_id = if srr_won {
            srr_result.matched_description.clone()
        } else {
            matched_rule
        };

        (
            Classification {
                decision: final_decision,
                source,
                operation: Some(operation),
                matched_rule_id: rule_id,
            },
            srr_result.is_catch_all,
        )
    } else {
        // Direct HTTP: Layer 2 Network SRR classification
        let srr = match state.srr.read() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("SRR lock poisoned — denying request (fail-close)");
                append_proxy_wal_event(
                    &state,
                    request.method().as_str(),
                    &target.host,
                    &target.path,
                    "unknown",
                    "Deny (SRR lock poisoned)",
                    500,
                );
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal governance error — request denied (fail-close)",
                );
            }
        };
        let srr_result = srr.check(
            request.method().as_str(),
            &target.host,
            &target.path,
            body_for_srr,
        );
        drop(srr);

        let is_catch_all = srr_result.is_catch_all;
        (
            Classification {
                decision: srr_result.decision,
                source: ClassificationSource::SRR,
                operation: None,
                matched_rule_id: srr_result.matched_description,
            },
            is_catch_all,
        )
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

    // ── Step 2.5: Shadow Mode — 2-phase intent verification ──
    //
    // Phase 1: claim() — mark intent as Claimed (not deleted)
    // Phase 2: after WAL write → confirm() (delete) or release() (restore)
    //
    // Invariant: intent deletion occurs ONLY on confirm().
    // This ensures: no decision without audit, no audit without decision.
    let shadow_claim = if state.shadow_config.mode != crate::intent_store::ShadowMode::Disabled {
        let claim =
            state
                .intent_store
                .claim(&request_method, &target.host, &target.path, Some(agent_id));

        if claim.verified {
            // ABAC re-evaluation with declared operation from intent
            if let Some(ref operation_name) = claim.operation {
                let shadow_agent_id = claim.agent_id.as_deref().unwrap_or(agent_id);
                let shadow_op = OperationMetadata {
                    operation: operation_name.clone(),
                    resource: ResourceDescriptor::default(),
                    subject: SubjectDescriptor {
                        agent_id: shadow_agent_id.to_string(),
                        tenant_id: None,
                        session_id: shadow_agent_id.to_string(),
                    },
                    context: OperationContext {
                        attributes: Default::default(),
                    },
                    payload: PayloadDescriptor::default(),
                };
                let (abac_decision, abac_rule) = match state.policy.read() {
                    Ok(p) => p.evaluate(&shadow_op),
                    Err(_) => (
                        EnforcementDecision::Deny {
                            reason: "Policy lock poisoned".into(),
                        },
                        None,
                    ),
                };

                let combined = max_strict(classification.decision.clone(), abac_decision.clone());
                if combined.strictness() > classification.decision.strictness() {
                    tracing::warn!(
                        operation = %operation_name,
                        abac_decision = ?abac_decision,
                        srr_decision = ?classification.decision,
                        combined = ?combined,
                        "Shadow ABAC re-evaluation upgraded decision"
                    );
                    classification = Classification {
                        decision: combined,
                        source: ClassificationSource::ABAC,
                        operation: Some(shadow_op),
                        matched_rule_id: abac_rule,
                    };
                    is_default_caution = false;
                }
            }
            Some(claim) // Pass to WAL write for confirm/release
        } else {
            match state.shadow_config.mode {
                crate::intent_store::ShadowMode::Strict => {
                    tracing::warn!(
                        method = %request_method,
                        host = %target.host,
                        path = %target.path,
                        agent = %agent_id,
                        "Shadow STRICT: no intent — DENY"
                    );
                    append_proxy_wal_event(
                        &state,
                        &request_method,
                        &target.host,
                        &target.path,
                        agent_id,
                        "Deny (Shadow STRICT: no intent)",
                        403,
                    );
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "Shadow verification failed: no intent declared for this request. \
                         Call gvm_declare_intent before making API requests.",
                    );
                }
                crate::intent_store::ShadowMode::Cautious => {
                    let delay = state.shadow_config.cautious_delay_ms;
                    tracing::warn!(
                        method = %request_method, host = %target.host,
                        path = %target.path, agent = %agent_id,
                        delay_ms = delay,
                        "Shadow CAUTIOUS: no intent — delaying {}ms", delay
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                crate::intent_store::ShadowMode::Permissive => {
                    tracing::warn!(
                        method = %request_method, host = %target.host,
                        path = %target.path, agent = %agent_id,
                        "Shadow PERMISSIVE: no intent — allowing with warning"
                    );
                }
                crate::intent_store::ShadowMode::Disabled => unreachable!(),
            }
            None
        }
    } else {
        None
    };

    // ── Step 3: Rate Limit check ──
    if let EnforcementDecision::Throttle { max_per_minute } = &classification.decision {
        if !state.rate_limiter.check(agent_id, *max_per_minute) {
            // Release claimed intent
            if let Some(ref claim) = shadow_claim {
                state.intent_store.release(claim.claim_id);
            }
            let operation_name = gvm_headers
                .as_ref()
                .map(|h| h.operation.as_str())
                .unwrap_or("unknown");
            append_proxy_wal_event(
                &state,
                &request_method,
                &target.host,
                &target.path,
                agent_id,
                &format!("Throttle (rate limit exceeded: {}/min)", max_per_minute),
                429,
            );
            return governance_block_response(
                StatusCode::TOO_MANY_REQUESTS,
                GovernanceBlockResponse {
                    blocked: true,
                    decision: "Throttle".to_string(),
                    event_id: String::new(),
                    trace_id: gvm_headers
                        .as_ref()
                        .map(|h| h.trace_id.clone())
                        .unwrap_or_default(),
                    operation: operation_name.to_string(),
                    reason: format!(
                        "Rate limit exceeded: {} requests/min maximum",
                        max_per_minute
                    ),
                    mode: state.on_block.throttle.clone(),
                    next_action: "Wait and retry after the rate limit window resets".to_string(),
                    retry_after_secs: Some(60),
                    rollback_hint: None,
                    matched_rule_id: classification.matched_rule_id.clone(),
                    ic_level: 2,
                },
            );
        }
    }

    // ── Step 3.5: Circuit Breaker — WAL health check ──
    // If the primary WAL has too many consecutive failures, reject IC-2
    // requests early with 503 + Retry-After to prevent cascading failures.
    // IC-1 (Allow) is unaffected — it uses async append (loss tolerated).
    // Deny and RequireApproval are NOT gated — they block the request
    // regardless, so WAL durability is not required for safety.
    let wal_failures = state.ledger.primary_failure_count();
    if wal_failures >= CIRCUIT_BREAKER_THRESHOLD {
        match &classification.decision {
            EnforcementDecision::Delay { .. } => {
                // Release claimed intent — WAL unavailable, no audit possible
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.release(claim.claim_id);
                }
                tracing::error!(
                    consecutive_failures = wal_failures,
                    "Circuit breaker OPEN — rejecting IC-2/3 request (WAL degraded)"
                );
                return governance_block_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "CircuitBreakerOpen".to_string(),
                        event_id: String::new(),
                        trace_id: gvm_headers
                            .as_ref()
                            .map(|h| h.trace_id.clone())
                            .unwrap_or_default(),
                        operation: gvm_headers
                            .as_ref()
                            .map(|h| h.operation.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        reason: "Audit subsystem degraded — durable write unavailable".to_string(),
                        mode: state.on_block.infrastructure_failure.clone(),
                        next_action: "Retry after the audit subsystem recovers".to_string(),
                        retry_after_secs: Some(CIRCUIT_BREAKER_RETRY_SECS),
                        rollback_hint: None,
                        matched_rule_id: None,
                        ic_level: 0,
                    },
                );
            }
            _ => {
                // IC-1 (Allow, AuditOnly, Throttle) — proceed despite WAL issues
            }
        }
    }

    // ── Step 4: Enforcement with EventStatus lifecycle ──
    let mut event = build_event(&classification, &gvm_headers, &target);
    event.default_caution = is_default_caution;
    // Populate transport.method (build_event cannot access the request)
    if let Some(ref mut t) = event.transport {
        t.method = request_method.clone();
    }

    // Measure engine processing time (classification was already done above)
    let engine_start = std::time::Instant::now();

    match &classification.decision {
        EnforcementDecision::Allow => {
            // Fast path: forward immediately, async ledger (IC-1, loss tolerated)
            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;

            event.status = event_status_from_response(&response);
            state.ledger.append_async(event.clone()).await;
            // Allow uses async WAL (loss tolerated) — confirm intent immediately
            if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }
            inject_gvm_response_headers(
                response.headers_mut(),
                &event,
                &classification,
                engine_ms,
                0,
            );
            response
        }

        EnforcementDecision::Delay { milliseconds } => {
            // IC-2: WAL-first durable write → delay → forward
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed — rejecting request (Fail-Close)");
                // Release claimed intent — WAL failed, intent must be restorable
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.release(claim.claim_id);
                }
                return governance_block_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "InfrastructureFailure".to_string(),
                        event_id: event.event_id.clone(),
                        trace_id: event.trace_id.clone(),
                        operation: event.operation.clone(),
                        reason: "Audit log unavailable — request rejected for safety".to_string(),
                        mode: state.on_block.infrastructure_failure.clone(),
                        next_action: "Check proxy logs. The WAL ledger may be full or the disk may be unavailable.".to_string(),
                        retry_after_secs: None,
                        rollback_hint: Some(event.trace_id.clone()),
                        matched_rule_id: None,
                        ic_level: 2,
                    },
                );
            }

            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
            let llm_provider = llm_trace::identify_llm_provider(&target.host);
            let mut response = forward_request(&state, request, &target).await;

            event.status = event_status_from_response(&response);

            // Extract LLM thinking trace if this is a known LLM provider response.
            // Trace extraction is deferred to stream completion via tap-stream;
            // the trace is persisted as a separate WAL entry by tokio::spawn.
            if let Some(provider) = llm_provider {
                if response.status().is_success() {
                    response = extract_llm_trace_from_response(
                        response,
                        provider,
                        &event,
                        state.ledger.clone(),
                    )
                    .await;
                }
            }

            // Best-effort status update to WAL
            let _ = state.ledger.append_durable(&event).await;
            // Phase 2a: WAL succeeded → confirm intent deletion
            if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }
            inject_gvm_response_headers(
                response.headers_mut(),
                &event,
                &classification,
                engine_ms,
                *milliseconds,
            );
            response
        }

        EnforcementDecision::RequireApproval { urgency } => {
            // IC-3: hold request and wait for human approval.
            // The proxy suspends the HTTP response until POST /gvm/approve delivers
            // a decision, or the approval timeout expires (fail-close → auto-deny).
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for IC-3 event");
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.release(claim.claim_id);
                }
            } else if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }

            let event_id = event.event_id.clone();
            let method_str = request.method().to_string();

            tracing::warn!(
                host = %target.host,
                path = %target.path,
                urgency = ?urgency,
                event_id = %event_id,
                "IC-3: Request held — waiting for approval"
            );

            // Create oneshot channel for approval decision
            let (tx, rx) = tokio::sync::oneshot::channel::<bool>();

            // Register pending approval with metadata for CLI/API display
            state.pending_approvals.insert(
                event_id.clone(),
                PendingApproval {
                    sender: tx,
                    event_id: event_id.clone(),
                    operation: event.operation.clone(),
                    host: target.host.clone(),
                    path: target.path.clone(),
                    method: method_str,
                    agent_id: event.agent_id.clone(),
                    timestamp: event.timestamp,
                },
            );

            // Wait for approval decision or timeout
            let timeout_duration = std::time::Duration::from_secs(state.ic3_approval_timeout_secs);
            let approved = match tokio::time::timeout(timeout_duration, rx).await {
                Ok(Ok(decision)) => decision,
                Ok(Err(_)) => {
                    // Sender dropped (proxy shutting down) → deny
                    tracing::warn!(event_id = %event_id, "IC-3: Approval channel closed — auto-denied");
                    false
                }
                Err(_) => {
                    // Timeout → auto-deny (fail-close)
                    tracing::warn!(event_id = %event_id, "IC-3: Approval timeout — auto-denied");
                    state.pending_approvals.remove(&event_id);
                    false
                }
            };

            if approved {
                tracing::info!(event_id = %event_id, host = %target.host, "IC-3: Request APPROVED — forwarding");
                let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
                let mut response = forward_request(&state, request, &target).await;
                event.status = event_status_from_response(&response);
                // Update WAL with execution result
                state.ledger.append_async(event.clone()).await;
                inject_gvm_response_headers(
                    response.headers_mut(),
                    &event,
                    &classification,
                    engine_ms,
                    0,
                );
                response
            } else {
                tracing::warn!(event_id = %event_id, host = %target.host, "IC-3: Request DENIED by approver or timeout");
                governance_block_response(
                    StatusCode::FORBIDDEN,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "RequireApproval".to_string(),
                        event_id: event.event_id.clone(),
                        trace_id: event.trace_id.clone(),
                        operation: event.operation.clone(),
                        reason: format!(
                            "IC-3: Approval denied or timed out (urgency: {:?})",
                            urgency
                        ),
                        mode: state.on_block.require_approval.clone(),
                        next_action: "Request was not approved within the timeout window."
                            .to_string(),
                        retry_after_secs: None,
                        rollback_hint: Some(event.trace_id.clone()),
                        matched_rule_id: classification.matched_rule_id.clone(),
                        ic_level: 3,
                    },
                )
            }
        }

        EnforcementDecision::Deny { reason } => {
            event.status = EventStatus::Failed {
                reason: format!("Denied: {}", reason),
            };
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for Deny event");
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.release(claim.claim_id);
                }
            } else if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }

            tracing::warn!(
                host = %target.host,
                path = %target.path,
                reason = %reason,
                "Request denied by policy"
            );
            governance_block_response(
                StatusCode::FORBIDDEN,
                GovernanceBlockResponse {
                    blocked: true,
                    decision: "Deny".to_string(),
                    event_id: event.event_id.clone(),
                    trace_id: event.trace_id.clone(),
                    operation: event.operation.clone(),
                    reason: reason.clone(),
                    mode: state.on_block.deny.clone(),
                    next_action: "This operation is blocked by policy. Contact your GVM administrator to review the rule.".to_string(),
                    retry_after_secs: None,
                    rollback_hint: Some(event.trace_id.clone()),
                    matched_rule_id: classification.matched_rule_id.clone(),
                    ic_level: 4,
                },
            )
        }

        EnforcementDecision::Throttle { .. } => {
            // Rate limit already checked above. If we reach here, request is allowed.
            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;
            event.status = event_status_from_response(&response);
            state.ledger.append_async(event.clone()).await;
            if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }
            inject_gvm_response_headers(
                response.headers_mut(),
                &event,
                &classification,
                engine_ms,
                0,
            );
            response
        }

        EnforcementDecision::AuditOnly { alert_level } => {
            // Allow execution but elevate audit priority
            event.status = EventStatus::Pending;
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::error!(error = %e, "WAL write failed for AuditOnly event");
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.release(claim.claim_id);
                }
            }

            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;

            event.status = event_status_from_response(&response);
            let _ = state.ledger.append_durable(&event).await;
            // Confirm after second WAL write (best-effort status update)
            if let Some(ref claim) = shadow_claim {
                state.intent_store.confirm(claim.claim_id);
            }

            if matches!(alert_level, AlertLevel::Critical) {
                tracing::warn!(
                    event_id = %event.event_id,
                    "Critical audit event — operator notification required"
                );
            }
            inject_gvm_response_headers(
                response.headers_mut(),
                &event,
                &classification,
                engine_ms,
                0,
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
fn build_operation_metadata(headers: &GVMHeaders, _target: &Target) -> OperationMetadata {
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
            method: "".to_string(), // Populated by proxy_handler after build_event
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
        llm_trace: None,
        default_caution: false, // Set by caller after build_event
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
    // MVP default: Passthrough (no credential = forward as-is).
    // Production should use Deny to enforce Layer 3 isolation.
    let credential_policy = crate::api_keys::MissingCredentialPolicy::default();
    if let Err(e) = state
        .api_keys
        .inject(&mut parts.headers, &target.host, &credential_policy)
    {
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
        let h = gvm_types::strip_port(forward_host);
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
            let (mut parts, body) = resp.into_parts();

            // Strip any X-GVM-* headers from the upstream response to prevent
            // header poisoning — a malicious upstream could inject fake
            // X-GVM-Decision headers that the SDK might trust.
            let gvm_keys: Vec<_> = parts
                .headers
                .keys()
                .filter(|k| k.as_str().starts_with("x-gvm-"))
                .cloned()
                .collect();
            for key in gvm_keys {
                parts.headers.remove(&key);
            }

            let body_stream = http_body_util::BodyDataStream::new(body);
            Response::from_parts(parts, Body::from_stream(body_stream))
        }
        Err(e) => {
            // Log full error for operators, but return sanitized message to clients.
            // Don't leak internal topology (hostnames, ports, connection details).
            tracing::error!(error = %e, debug = ?e, "Upstream request failed");
            error_response_detailed(
                StatusCode::BAD_GATEWAY,
                "Upstream service unavailable",
                None,
                None,
                Some(&format!(
                    "The proxy could not reach the upstream server for {}. Check if the target host is correct and reachable.",
                    target.host
                )),
                None,
            )
        }
    }
}

/// Buffer or tap response body to extract LLM thinking trace.
/// Called only for IC-2 paths targeting known LLM providers.
///
/// Both SSE and non-SSE responses use the same tap-stream pattern:
/// chunks are forwarded immediately (no full buffering before first byte),
/// while a bounded capture accumulates bytes for post-stream trace extraction.
/// This prevents memory exhaustion under concurrent load (N requests × buffer_size)
/// and eliminates the latency penalty of full buffering before forwarding.
const MAX_JSON_TRACE_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_SSE_TRACE_CAPTURE_BYTES: usize = 1024 * 1024;

/// Trace extraction is deferred to stream completion. The extracted trace
/// is persisted as a separate WAL entry via `tokio::spawn`, so the caller's
/// `event` is not modified in-place. The caller should still persist the
/// original event (without llm_trace) for the enforcement decision record.
async fn extract_llm_trace_from_response(
    response: Response<Body>,
    provider: &str,
    event: &GVMEvent,
    ledger: Arc<Ledger>,
) -> Response<Body> {
    let (parts, body) = response.into_parts();

    // Detect SSE streaming from content-type header
    let is_sse = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(llm_trace::is_sse_content_type)
        .unwrap_or(false);

    let capture_limit = if is_sse {
        MAX_SSE_TRACE_CAPTURE_BYTES
    } else {
        MAX_JSON_TRACE_CAPTURE_BYTES
    };

    // Unified tap-stream: forward chunks immediately, capture bounded bytes
    // for post-stream trace extraction. Same pattern for SSE and JSON responses.
    let provider_name = provider.to_string();
    let trace_event = event.clone();
    let mut upstream_stream = http_body_util::BodyDataStream::new(body);

    let tapped_stream = async_stream::stream! {
        let mut capture = Vec::with_capacity(16 * 1024);
        let mut capture_overflow = false;
        let mut stream_failed = false;

        while let Some(next) = upstream_stream.next().await {
            match next {
                Ok(chunk) => {
                    if capture.len() < capture_limit {
                        let remaining = capture_limit - capture.len();
                        let take_len = remaining.min(chunk.len());
                        capture.extend_from_slice(&chunk[..take_len]);
                        if take_len < chunk.len() {
                            capture_overflow = true;
                        }
                    } else {
                        capture_overflow = true;
                    }

                    yield Ok::<Bytes, axum::Error>(chunk);
                }
                Err(err) => {
                    stream_failed = true;
                    tracing::warn!(
                        provider = provider_name.as_str(),
                        error = %err,
                        "Upstream stream interrupted during trace tap"
                    );
                    yield Err(err);
                    break;
                }
            }
        }

        if stream_failed {
            return;
        }

        // Extract trace from captured bytes after stream completes
        let mut trace = if is_sse {
            match llm_trace::extract_thinking_trace_from_sse(provider_name.as_str(), &capture) {
                Some(trace) => trace,
                None => return,
            }
        } else {
            match llm_trace::extract_thinking_trace(provider_name.as_str(), &capture) {
                Some(trace) => trace,
                None => return,
            }
        };

        if capture_overflow {
            trace.truncated = true;
        }

        tracing::info!(
            provider = provider_name.as_str(),
            model = ?trace.model,
            has_thinking = trace.thinking.is_some(),
            truncated = trace.truncated,
            streaming = is_sse,
            "LLM thinking trace extracted"
        );

        let mut trace_event = trace_event;
        trace_event.llm_trace = Some(trace);

        tokio::spawn(async move {
            if let Err(e) = ledger.append_durable(&trace_event).await {
                tracing::warn!(error = %e, "Failed to persist LLM trace update");
            }
        });
    };

    Response::from_parts(parts, Body::from_stream(tapped_stream))
}

// extract_llm_trace_from_sse_stream removed: unified into extract_llm_trace_from_response
// using the same tap-stream pattern for both SSE and non-SSE responses.

/// Parse GVM-specific headers from an SDK-routed request.
/// When a verified JWT identity is provided, it overrides the self-declared
/// X-GVM-Agent-Id and X-GVM-Tenant-Id headers for spoofing prevention.
fn parse_gvm_headers(
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
fn extract_target(request: &Request<Body>) -> Option<Target> {
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

/// Best-effort WAL append for enforcement decisions in proxy_handler / CONNECT.
/// Every governance decision (Deny, Throttle, classification error) must be audited.
fn append_proxy_wal_event(
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
    };
    // Spawn background task for durable WAL write. Cannot .await in sync fn context,
    // and append_async only writes to NATS (not WAL file). tokio::spawn ensures the
    // event reaches the WAL file even without NATS configured.
    let ledger = state.ledger.clone();
    let decision_owned = decision.to_string();
    tokio::spawn(async move {
        if let Err(e) = ledger.append_durable(&event).await {
            tracing::error!(error = %e, decision = %decision_owned, "Proxy: enforcement WAL append FAILED");
        }
    });
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
                .expect("fallback 500 response with empty body cannot fail")
        })
}

/// Build a structured governance block response.
///
/// Returns the standard `GovernanceBlockResponse` JSON body with appropriate
/// HTTP headers for SDK consumption. This is the contract between the proxy
/// and all agent SDKs — every blocked request uses this format.
fn governance_block_response(status: StatusCode, block: GovernanceBlockResponse) -> Response<Body> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use std::time::{Duration, Instant};

    async fn make_test_ledger() -> (Arc<Ledger>, std::path::PathBuf) {
        let wal_path =
            std::env::temp_dir().join(format!("gvm-proxy-test-{}.wal", uuid::Uuid::new_v4()));
        let ledger = Ledger::new(&wal_path, "", "gvm_test")
            .await
            .expect("ledger init should succeed");
        (Arc::new(ledger), wal_path)
    }

    fn make_event() -> GVMEvent {
        GVMEvent {
            event_id: "evt-test-1".to_string(),
            trace_id: "trace-test-1".to_string(),
            parent_event_id: None,
            agent_id: "agent-test".to_string(),
            tenant_id: None,
            session_id: "session-test".to_string(),
            timestamp: chrono::Utc::now(),
            operation: "gvm.messaging.send".to_string(),
            resource: ResourceDescriptor::default(),
            context: HashMap::new(),
            transport: None,
            decision: "Delay".to_string(),
            decision_source: "ABAC".to_string(),
            matched_rule_id: None,
            enforcement_point: "proxy".to_string(),
            status: EventStatus::Pending,
            payload: PayloadDescriptor::default(),
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: false,
        }
    }

    #[tokio::test]
    async fn llm_trace_skip_when_content_length_missing_preserves_body() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "reasoning_content": "secret reasoning"
                }
            }],
            "model": "o1-preview"
        })
        .to_string();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .expect("response build should succeed");

        let (ledger, _wal_path) = make_test_ledger().await;
        let event = make_event();
        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;

        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collect should succeed")
            .to_bytes();

        // Body must be preserved regardless of trace extraction
        assert_eq!(bytes, body.as_bytes());
    }

    #[tokio::test]
    async fn llm_trace_extract_when_content_length_bounded() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "reasoning_content": "explain transfer review path"
                }
            }],
            "model": "o1-preview",
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            }
        })
        .to_string();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .expect("response build should succeed");

        let (ledger, wal_path) = make_test_ledger().await;
        let mut event = make_event();
        event.event_id = format!("evt-json-trace-{}", uuid::Uuid::new_v4());

        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;

        // Body must be forwarded immediately via tap-stream
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collect should succeed")
            .to_bytes();
        assert_eq!(bytes, body.as_bytes());

        // Trace is persisted asynchronously to WAL after stream completes
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut persisted_trace = None;

        while Instant::now() < deadline {
            let wal = tokio::fs::read_to_string(&wal_path)
                .await
                .unwrap_or_default();

            for line in wal.lines() {
                if !line.contains(&event.event_id) || !line.contains("\"llm_trace\"") {
                    continue;
                }
                if let Ok(parsed) = serde_json::from_str::<GVMEvent>(line) {
                    if let Some(trace) = parsed.llm_trace {
                        persisted_trace = Some(trace);
                        break;
                    }
                }
            }

            if persisted_trace.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let trace =
            persisted_trace.expect("bounded JSON body should produce trace persisted to WAL");
        assert_eq!(trace.provider, "openai");
    }

    #[tokio::test]
    async fn llm_trace_skip_when_content_length_exceeds_limit() {
        let body = "x".repeat(300_001);
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.clone()))
            .expect("response build should succeed");

        let (ledger, _wal_path) = make_test_ledger().await;
        let event = make_event();
        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;

        // Body must be preserved (streamed through) even if oversized
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collect should succeed")
            .to_bytes();

        assert_eq!(bytes, body.as_bytes());
    }

    #[tokio::test]
    async fn llm_trace_collect_error_returns_explicit_error_response() {
        // With tap-stream, upstream errors propagate through the stream
        // rather than returning a 502 response. The stream yields Err.
        let failing_stream = async_stream::stream! {
            yield Err::<Bytes, std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "stream aborted",
            ));
        };

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Body::from_stream(failing_stream))
            .expect("response build should succeed");

        let (ledger, _wal_path) = make_test_ledger().await;
        let event = make_event();
        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;

        // The response status is preserved (200 OK from upstream headers).
        // The body stream itself will yield the error when consumed.
        assert_eq!(response.status(), StatusCode::OK);
        let result = http_body_util::BodyExt::collect(response.into_body()).await;
        assert!(
            result.is_err(),
            "stream error must propagate to the consumer"
        );
    }

    #[tokio::test]
    async fn llm_trace_sse_passthrough_returns_immediately() {
        let first_event =
            "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"think\"}}],\"model\":\"o1-preview\"}\n\n";
        let done_event = "data: [DONE]\n\n";
        let expected = format!("{}{}", first_event, done_event);

        let slow_stream = async_stream::stream! {
            tokio::time::sleep(Duration::from_millis(200)).await;
            yield Ok::<Bytes, std::io::Error>(Bytes::from(first_event.to_string()));
            tokio::time::sleep(Duration::from_millis(200)).await;
            yield Ok::<Bytes, std::io::Error>(Bytes::from(done_event.to_string()));
        };

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(slow_stream))
            .expect("response build should succeed");

        let (ledger, _wal_path) = make_test_ledger().await;
        let event = make_event();

        let start = Instant::now();
        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;
        assert!(
            start.elapsed() < Duration::from_millis(150),
            "tap-stream extraction must not block on upstream stream completion"
        );

        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collect should succeed")
            .to_bytes();
        assert_eq!(bytes, expected.as_bytes());
    }

    #[tokio::test]
    async fn llm_trace_sse_large_stream_preserves_body_and_persists_trace() {
        let reasoning_fragment = "r".repeat(512);
        let sse_event = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"reasoning_content\":\"{}\"}}}}],\"model\":\"o1-preview\"}}\n\n",
            reasoning_fragment
        );
        let repetitions = (MAX_SSE_TRACE_CAPTURE_BYTES / sse_event.len()) + 128;

        let mut body = sse_event.repeat(repetitions);
        body.push_str("data: [DONE]\n\n");

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(body.clone()))
            .expect("response build should succeed");

        let (ledger, wal_path) = make_test_ledger().await;
        let mut event = make_event();
        event.event_id = format!("evt-test-{}", uuid::Uuid::new_v4());

        let response = extract_llm_trace_from_response(response, "openai", &event, ledger).await;

        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body collect should succeed")
            .to_bytes();
        assert_eq!(bytes, body.as_bytes());

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut persisted_trace = None;

        while Instant::now() < deadline {
            let wal = tokio::fs::read_to_string(&wal_path)
                .await
                .unwrap_or_default();

            for line in wal.lines() {
                if !line.contains(&event.event_id) || !line.contains("\"llm_trace\"") {
                    continue;
                }

                if let Ok(parsed) = serde_json::from_str::<GVMEvent>(line) {
                    if let Some(trace) = parsed.llm_trace {
                        persisted_trace = Some(trace);
                        break;
                    }
                }
            }

            if persisted_trace.is_some() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let trace = persisted_trace
            .expect("large SSE response should persist a bounded trace update asynchronously");
        assert_eq!(trace.provider, "openai");
        assert!(
            trace.truncated,
            "bounded capture should mark large SSE trace as truncated"
        );
    }
}

// ─── CONNECT Tunnel (HTTPS Proxy) ────────────────────────────────────────────
//
// Blind relay: CONNECT host:port → domain-level policy check → TCP relay.
// TLS content is not inspected (no MITM). Policy enforcement is domain + port only.
// Path/method/body level enforcement requires TLS inspection (v0.2).

pub async fn handle_connect(
    state: AppState,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let result = handle_connect_inner(state, request).await;
    Ok(result)
}

async fn handle_connect_inner(
    state: AppState,
    request: Request<hyper::body::Incoming>,
) -> Response<Body> {
    // Extract target host:port from CONNECT request URI
    let target = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            request.uri().host().map(|h| {
                let port = request.uri().port_u16().unwrap_or(443);
                format!("{}:{}", h, port)
            })
        })
        .unwrap_or_default();

    if target.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "CONNECT: missing target host");
    }

    let host = target.split(':').next().unwrap_or(&target);
    let port = target
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    // Domain-level policy: CONNECT only cares "is this domain allowed?"
    // If ANY rule exists for this host (regardless of method/path), Allow the tunnel.
    // If only Deny rules exist, Deny the tunnel.
    // If no rules at all, Default-to-Caution (Delay 300ms).
    let (srr_result_decision, srr_result_matched, srr_result_catch_all) = {
        let srr = match state.srr.read() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!(
                    "SRR lock poisoned in CONNECT handler — denying tunnel (fail-close)"
                );
                append_proxy_wal_event(
                    &state,
                    "CONNECT",
                    host,
                    "/",
                    "unknown",
                    "Deny (SRR lock poisoned in CONNECT)",
                    500,
                );
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal governance error — request denied (fail-close)",
                );
            }
        };
        let (decision, matched, catch_all) = srr.check_domain(host);
        (decision, matched, catch_all)
    };

    let decision = &srr_result_decision;

    tracing::info!(
        method = "CONNECT",
        host = %host,
        port = port,
        decision = ?decision,
        rule = ?srr_result_matched,
        "CONNECT tunnel request"
    );

    // Shadow Mode check for CONNECT
    if state.shadow_config.mode != crate::intent_store::ShadowMode::Disabled {
        let claim = state.intent_store.claim("CONNECT", host, "/", None);
        if !claim.verified {
            if state.shadow_config.mode == crate::intent_store::ShadowMode::Strict {
                tracing::warn!(host = %host, "Shadow STRICT: CONNECT without intent — DENY");
                append_proxy_wal_event(
                    &state,
                    "CONNECT",
                    host,
                    "/",
                    "unknown",
                    "Deny (Shadow STRICT: CONNECT without intent)",
                    403,
                );
                return error_response(
                    StatusCode::FORBIDDEN,
                    "Shadow verification failed for CONNECT tunnel",
                );
            }
        } else {
            // Confirm immediately for CONNECT (no WAL for tunneled content)
            state.intent_store.confirm(claim.claim_id);
        }
    }

    // Enforce decision
    match decision {
        EnforcementDecision::Deny { reason } => {
            tracing::warn!(host = %host, reason = %reason, "CONNECT denied");

            // WAL record for denied CONNECT
            let event = GVMEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                trace_id: uuid::Uuid::new_v4().to_string(),
                agent_id: "unknown".to_string(),
                operation: format!("connect:{}", host),
                decision: "Deny".to_string(),
                decision_source: "SRR".to_string(),
                status: EventStatus::Failed {
                    reason: reason.clone(),
                },
                enforcement_point: "proxy".to_string(),
                timestamp: chrono::Utc::now(),
                payload: PayloadDescriptor::default(),
                transport: Some(TransportInfo {
                    method: "CONNECT".to_string(),
                    host: host.to_string(),
                    path: format!(":{}", port),
                    status_code: None,
                }),
                resource: ResourceDescriptor::default(),
                context: Default::default(),
                matched_rule_id: srr_result_matched.clone(),
                nats_sequence: None,
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                tenant_id: None,
                parent_event_id: None,
                session_id: String::new(),
            };
            state.ledger.append_async(event).await;

            return error_response(
                StatusCode::FORBIDDEN,
                &format!("CONNECT denied: {}", reason),
            );
        }
        _ => {
            // Allow, Delay, etc. — proceed with tunnel
        }
    }

    // WAL record for allowed CONNECT (async, loss tolerated)
    let event = GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        agent_id: "unknown".to_string(),
        operation: format!("connect:{}", host),
        decision: format!("{:?}", decision),
        decision_source: "SRR".to_string(),
        status: EventStatus::Confirmed,
        enforcement_point: "proxy".to_string(),
        timestamp: chrono::Utc::now(),
        payload: PayloadDescriptor::default(),
        transport: Some(TransportInfo {
            method: "CONNECT".to_string(),
            host: host.to_string(),
            path: format!(":{}", port),
            status_code: None,
        }),
        resource: ResourceDescriptor::default(),
        context: Default::default(),
        matched_rule_id: srr_result_matched.clone(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: srr_result_catch_all,
        tenant_id: None,
        parent_event_id: None,
        session_id: String::new(),
    };
    state.ledger.append_async(event).await;

    // MITM TLS inspection on CONNECT tunnel.
    // Apply MITM for connections from isolated environments (sandbox or Docker)
    // where the GVM CA is injected into the trust store.
    // Cooperative mode (127.0.0.1) uses blind relay — no CA injection, would fail.
    let peer_ip = request.extensions().get::<std::net::IpAddr>().copied();
    tracing::debug!(peer = ?peer_ip, "CONNECT MITM: checking peer IP");
    // MITM for any non-loopback connection. Isolated environments (sandbox,
    // Docker) have the GVM CA injected, so MITM verification succeeds.
    // Only loopback (127.0.0.1) cooperative mode is excluded — no CA injection.
    let is_isolated = peer_ip.is_some_and(|ip| !ip.is_loopback());

    let host_owned = host.to_string();
    let target_addr = format!("{}:{}", host, port);
    let mitm_resolver = if is_isolated {
        state.mitm_resolver.clone()
    } else {
        None
    };
    let mitm_sc = if is_isolated {
        state.mitm_server_config.clone()
    } else {
        None
    };
    let mitm_cc = if is_isolated {
        state.mitm_client_config.clone()
    } else {
        None
    };
    let connect_state = state.clone();

    tokio::task::spawn(async move {
        let upgraded = match hyper::upgrade::on(request).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(error = %e, "CONNECT: upgrade failed");
                return;
            }
        };

        // MITM path: TLS termination + L7 inspection
        if let (Some(resolver), Some(sc), Some(cc)) = (mitm_resolver, mitm_sc, mitm_cc) {
            // Pre-warm cert cache on blocking thread (avoids stalling tokio)
            if resolver.ensure_cached(host_owned.clone()).await.is_none() {
                tracing::warn!(host = %host_owned, "CONNECT MITM: cert generation failed, falling back to tunnel");
                blind_relay(upgraded, &target_addr).await;
                return;
            }

            // TLS accept on the upgraded connection
            let acceptor = tokio_rustls::TlsAcceptor::from(sc);
            let tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(hyper_util::rt::TokioIo::new(upgraded)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    // Debug level: intermittent TLS handshake eof is normal with
                    // Node.js undici — client occasionally resets the connection
                    // before sending ClientHello, then retries successfully.
                    tracing::debug!(
                        host = %host_owned, error = %e,
                        "CONNECT MITM: TLS handshake failed (client may retry)"
                    );
                    return;
                }
                Err(_) => {
                    tracing::debug!(host = %host_owned, "CONNECT MITM: TLS handshake timed out");
                    return;
                }
            };

            if let Err(e) =
                crate::tls_proxy::handle_mitm_stream(tls_stream, &host_owned, cc, &connect_state)
                    .await
            {
                tracing::debug!(host = %host_owned, error = %e, "CONNECT MITM: stream handling error");
            }
        } else {
            // Legacy fallback: blind TCP relay (no MITM configured)
            blind_relay(upgraded, &target_addr).await;
        }
    });

    // Return 200 to signal tunnel is established.
    // Connection: close forces client to open a new TCP connection for the
    // next CONNECT. After upgrade, the HTTP/1.1 connection is a raw TCP tunnel —
    // reusing it for new HTTP requests after the tunnel ends is undefined behavior.
    // Without this, clients that pipeline CONNECT on a keep-alive connection get
    // "tls handshake eof" because the previous upgrade's state contaminates the stream.
    Response::builder()
        .status(StatusCode::OK)
        .header("Connection", "close")
        .body(Body::empty())
        .unwrap_or_default()
}

/// Blind TCP relay fallback (when MITM is not configured).
async fn blind_relay(upgraded: hyper::upgrade::Upgraded, target_addr: &str) {
    match tokio::net::TcpStream::connect(target_addr).await {
        Ok(upstream) => {
            let (mut client_read, mut client_write) =
                tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

            let c2s = tokio::io::copy(&mut client_read, &mut upstream_write);
            let s2c = tokio::io::copy(&mut upstream_read, &mut client_write);

            tokio::select! {
                r = c2s => { if let Err(e) = r { tracing::debug!(error = %e, "CONNECT relay client→upstream ended"); } }
                r = s2c => { if let Err(e) = r { tracing::debug!(error = %e, "CONNECT relay upstream→client ended"); } }
            }
        }
        Err(e) => {
            tracing::error!(target = %target_addr, error = %e, "CONNECT: failed to connect to upstream");
        }
    }
}
