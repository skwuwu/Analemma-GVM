//! Hyper-based MITM request handler.
//!
//! Replaces the custom HTTP parser + relay functions with hyper's HTTP/1.1
//! server and client. hyper manages chunked encoding, content-length,
//! keep-alive, and connection framing — eliminating all manual framing bugs.
//!
//! Architecture:
//!   Client TLS stream → hyper server (parse request)
//!                     → classify (SRR)
//!                     → hyper client (forward to upstream, stream response)
//!                     → hyper server (relay response to client)

use anyhow::Result;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::sync::Arc;

use crate::tls_proxy::HttpRequest;

// Use String as error type to avoid lifetime issues with Box<dyn Error> in hyper service.
// hyper's serve_connection requires the body error type to be 'static without higher-ranked
// lifetime bounds, which Box<dyn Error + 'static> technically satisfies but Rust's trait
// solver can't prove for all lifetimes in the service closure.
type BoxErr = String;
type MitmBody = BoxBody<Bytes, BoxErr>;

/// Wrap bytes into a BoxBody (for error responses).
fn full_body(data: impl Into<Bytes>) -> MitmBody {
    Full::new(data.into())
        .map_err(|_: std::convert::Infallible| -> String { unreachable!() })
        .boxed()
}

/// Stamp the proxy's governance observability headers onto a response
/// header map. Same contract as the cooperative HTTP path: every
/// response carrying agent-visible bytes also carries
/// `X-GVM-Decision` and `X-GVM-Event-Id` so SDKs can correlate audit
/// log entries to the HTTP transactions they instrumented.
///
/// Best-effort: header value parsing failures are logged at debug and
/// skipped — never panic out of the response path.
fn stamp_governance_headers(headers: &mut hyper::HeaderMap, event_id: &str, decision: &str) {
    if let Ok(v) = hyper::header::HeaderValue::from_str(decision) {
        headers.insert("x-gvm-decision", v);
    } else {
        tracing::debug!(decision, "MITM: decision string not header-safe");
    }
    if let Ok(v) = hyper::header::HeaderValue::from_str(event_id) {
        headers.insert("x-gvm-event-id", v);
    } else {
        tracing::debug!(event_id, "MITM: event_id not header-safe");
    }
}

/// Entry point: serve MITM HTTP/1.1 on a TLS stream using hyper.
/// Replaces the old manual keep-alive loop + custom relay.
pub async fn serve_mitm<S>(
    tls_stream: tokio_rustls::server::TlsStream<S>,
    host_hint: String,
    client_config: Arc<rustls::ClientConfig>,
    state: crate::proxy::AppState,
    sandbox_anchor: Option<(String, String)>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper::server::conn::http1;

    let io = hyper_util::rt::TokioIo::new(tls_stream);

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let cc = client_config.clone();
        let hint = host_hint.clone();
        let anchor = sandbox_anchor.clone();
        async move { handle_request(req, &hint, cc, &state, anchor).await }
    });

    let conn = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades();

    tokio::pin!(conn);

    if let Err(e) = conn.as_mut().await {
        tracing::debug!(error = %e, "MITM hyper: connection closed");
    }
    Ok(())
}

/// Handle a single MITM-intercepted request.
/// Classification → enforcement → upstream forward → streaming response.
async fn handle_request(
    req: Request<Incoming>,
    host_hint: &str,
    client_config: Arc<rustls::ClientConfig>,
    state: &crate::proxy::AppState,
    sandbox_anchor: Option<(String, String)>,
) -> Result<Response<MitmBody>, String> {
    // Extract metadata before consuming body.
    //
    // path_and_query() preserves the query string (?per_page=10&page=2). The
    // older path() variant silently dropped it, breaking every paginated /
    // filtered API call routed through the MITM.
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let original_headers = req.headers().clone();

    // ── JWT verification (Phase G4: identity enforcement on MITM path) ──
    // The cooperative HTTP path (proxy_handler) verifies JWT in Step 0.
    // The MITM path historically did not — meaning HTTPS traffic could
    // forge `X-GVM-Agent-Id` via SDK headers and bypass identity checks
    // that the proxy_handler enforced. Close that hole here so identity
    // enforcement is parity across both transports.
    //
    // Convert axum::HeaderMap (auth::extract_bearer_token signature) from
    // the hyper::HeaderMap we have. They share the same underlying type
    // crate (`http`) so transmute via re-construction is unnecessary —
    // we just call extract directly on the hyper map.
    let verified_identity = if let Some(ref jwt) = state.jwt_config {
        // Inline Bearer extraction (avoids axum::HeaderMap conversion).
        let bearer = original_headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| !s.is_empty());
        match bearer {
            Some(token) => match crate::auth::verify_token(jwt, token) {
                Ok(identity) => {
                    tracing::debug!(
                        agent = %identity.agent_id,
                        token_id = %identity.token_id,
                        "MITM: JWT identity verified"
                    );
                    Some(identity)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "MITM: JWT verification failed — rejecting");
                    return Ok(Response::builder()
                        .status(401)
                        .header("Content-Type", "application/json")
                        .header("X-GVM-Block-Reason", "Invalid or expired JWT")
                        .body(full_body(
                            r#"{"blocked":true,"decision":"Unauthorized","reason":"Invalid or expired authentication token"}"#,
                        ))
                        .expect("static response builder"));
                }
            },
            None => {
                // JWT enabled + no Bearer token: try the sandbox-peer
                // identity path before rejecting. The original design
                // hard-rejected here on the theory that a sandboxed
                // agent has explicitly trusted our CA and so cannot
                // claim "legacy non-SDK client". That theory missed
                // the SDK-less-but-sandboxed case: a bare `urllib`
                // request from a `gvm run --sandbox` Python script
                // does load our CA (so MITM works) but does NOT
                // auto-attach the JWT we issued — the env var
                // `GVM_JWT_TOKEN` exists but the stdlib client never
                // reads it. Rather than force every agent author to
                // wrap their HTTP client, derive identity from the
                // veth source IP. The proxy itself allocated that IP,
                // so the trust path is at least as strong as the
                // namespace isolation guarantee.
                //
                // We still reject loud when neither path succeeds:
                // a missing JWT from a non-sandbox HTTPS client IS
                // operator misconfiguration.
                if let Some((agent_id, launch_event_id)) = sandbox_anchor.as_ref() {
                    let identity = crate::auth::VerifiedIdentity {
                        agent_id: agent_id.clone(),
                        tenant_id: None,
                        token_id: format!("sandbox-peer:{}", launch_event_id),
                    };
                    tracing::debug!(
                        agent = %identity.agent_id,
                        token_id = %identity.token_id,
                        "MITM: identity derived from sandbox peer IP (no JWT presented)"
                    );
                    Some(identity)
                } else {
                    tracing::warn!(
                        "MITM: no Bearer token, peer is not a known sandbox — rejecting"
                    );
                    return Ok(Response::builder()
                        .status(401)
                        .header("Content-Type", "application/json")
                        .header("X-GVM-Block-Reason", "Missing JWT")
                        .body(full_body(
                            r#"{"blocked":true,"decision":"Unauthorized","reason":"Bearer token required but not provided"}"#,
                        ))
                        .expect("static response builder"));
                }
            }
        }
    } else {
        // JWT disabled — still derive sandbox-peer identity from the
        // anchor so per-agent attribution works in dev. The anchor
        // is `Some` exactly when the CONNECT-handler resolved the
        // peer IP to a registered sandbox.
        sandbox_anchor.as_ref().map(
            |(agent_id, launch_event_id)| crate::auth::VerifiedIdentity {
                agent_id: agent_id.clone(),
                tenant_id: None,
                token_id: format!("sandbox-peer:{}", launch_event_id),
            },
        )
    };

    // Real upstream host comes from the TLS handshake SNI (host_hint), not
    // from the agent-supplied Host header. Inside a sandbox the agent's
    // Host is the proxy's veth IP (e.g. 10.200.0.1:8080), so trusting it
    // would have the proxy connect back to itself — exactly the hang we
    // observed. SNI is set by the agent's TLS stack from the original
    // upstream URL and is reliable. Fall back to the client Host only when
    // SNI is empty (HTTP/1.0, IP-only access — rare).
    let host = if !host_hint.is_empty() {
        host_hint.split(':').next().unwrap_or(host_hint).to_string()
    } else {
        original_headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string()
    };

    tracing::info!(method = %method, host = %host, path = %path, "MITM: inspecting HTTPS request");

    // Collect request body for SRR payload inspection (bounded by max_body_bytes)
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::debug!(error = %e, "MITM: body collect failed");
            Bytes::new()
        }
    };

    // ── Classification ──
    let body_ref = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.as_ref())
    };
    let classify_input = crate::enforcement::ClassifyInput {
        method: &method,
        host: &host,
        path: &path,
        body: body_ref,
        gvm_headers: None,
    };
    let mut classify_output = match crate::enforcement::classify(state, &classify_input) {
        Ok(o) => o,
        Err(err_msg) => {
            tracing::error!(error = %err_msg, "MITM classification failed (fail-close)");
            // SAFETY: Response::builder() with static status + header + body never
            // returns Err — the only failure mode is an invalid header name/value,
            // and these are compile-time constants.
            return Ok(Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(full_body(
                    r#"{"blocked":true,"decision":"Deny","reason":"Internal governance error"}"#,
                ))
                .expect("static response builder"));
        }
    };

    // Override classify_output.agent_id with verified JWT identity when
    // available — otherwise fall back to the (unverified) X-GVM-Agent-Id
    // header. This ensures every downstream consumer (WAL, per-agent
    // budget, telemetry) sees the cryptographically verified agent_id
    // when JWT is enforced.
    if let Some(ref id) = verified_identity {
        classify_output.agent_id = id.agent_id.clone();
    } else if classify_output.agent_id == "unknown" {
        // No JWT, no SDK headers — try the raw X-GVM-Agent-Id as a
        // last resort (parity with proxy_handler when JWT is disabled).
        if let Some(hdr) = original_headers
            .get("X-GVM-Agent-Id")
            .and_then(|v| v.to_str().ok())
        {
            classify_output.agent_id = hdr.to_string();
        }
    }

    let decision = &classify_output.classification.decision;
    let is_default_caution = classify_output.is_default_caution;
    tracing::info!(decision = ?decision, host = %host, path = %path, "MITM: SRR decision");

    // ── Enforcement ──
    match decision {
        gvm_types::EnforcementDecision::Deny { reason } => {
            let body = serde_json::json!({
                "blocked": true, "decision": "Deny", "reason": reason,
                "method": method, "host": host, "path": path,
                "next_action": format!("Blocked by SRR rule. To allow: add an Allow rule for {} {} in config/srr_network.toml and run POST /gvm/reload.", method, host),
            });
            tracing::warn!(host = %host, path = %path, reason = %reason, "MITM: request DENIED");
            let http_req = HttpRequest {
                method: method.clone(),
                path: path.clone(),
                host: host.clone(),
                headers: vec![],
                body: vec![],
                raw_head: vec![],
            };
            crate::tls_proxy::append_enforcement_event(
                &state.ledger,
                &classify_output,
                &host,
                &http_req,
                &format!("Deny {{ reason: {:?} }}", reason),
                Some(403),
                false,
                sandbox_anchor.as_ref().map(|(_, parent)| parent.clone()),
            )
            .await;
            // Keep-alive: no Connection: close — agent can retry on same connection
            return Ok(Response::builder()
                .status(403)
                .header("Content-Type", "application/json")
                .body(full_body(body.to_string()))
                .expect("static response builder"));
        }
        gvm_types::EnforcementDecision::Delay { milliseconds } => {
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
        }
        _ => {} // Allow, AuditOnly
    }

    // ── Token budget check (LLM providers only) ──
    // Shared two-tier (per-agent then global) via
    // `enforcement::check_and_reserve_token_budget`. Same single source
    // of truth as proxy_handler — the order, rollback, and short-circuit
    // are guaranteed identical between cooperative HTTP and MITM HTTPS.
    let is_llm = crate::llm_trace::identify_llm_provider(&host).is_some();
    if is_llm {
        let agent_id = classify_output.agent_id.as_str();
        match crate::enforcement::check_and_reserve_token_budget(state, agent_id) {
            crate::enforcement::BudgetCheckOutcome::Allowed => {}
            crate::enforcement::BudgetCheckOutcome::PerAgentDenied(exceeded) => {
                let reason = if exceeded.tokens_limit == 0 && exceeded.cost_limit_millionths == 0 {
                    "Per-agent budget admission rejected (quota table full)".to_string()
                } else {
                    format!(
                        "Per-agent budget exceeded for {}: {}/{} tokens/hr (${:.2}/${:.2})",
                        agent_id,
                        exceeded.tokens_used,
                        exceeded.tokens_limit,
                        exceeded.cost_used_usd(),
                        exceeded.cost_limit_usd(),
                    )
                };
                return Ok(Response::builder()
                    .status(429)
                    .header("Content-Type", "application/json")
                    .header("X-GVM-Block-Reason", "Per-agent budget exceeded")
                    .header("Retry-After", "60")
                    .body(full_body(
                        serde_json::json!({
                            "blocked": true,
                            "decision": "PerAgentBudgetExceeded",
                            "agent_id": agent_id,
                            "reason": reason,
                        })
                        .to_string(),
                    ))
                    .expect("static response builder"));
            }
            crate::enforcement::BudgetCheckOutcome::GlobalDenied(exceeded) => {
                let reason = format!(
                    "Token budget exceeded: {}/{} tokens/hr (${:.2}/${:.2})",
                    exceeded.tokens_used,
                    exceeded.tokens_limit,
                    exceeded.cost_used_usd(),
                    exceeded.cost_limit_usd(),
                );
                return Ok(Response::builder()
                    .status(429)
                    .header("Content-Type", "application/json")
                    .header("X-GVM-Block-Reason", "Token budget exceeded")
                    .header("Retry-After", "60")
                    .body(full_body(
                        serde_json::json!({
                            "blocked": true,
                            "decision": "BudgetExceeded",
                            "reason": reason,
                            "next_action": "wait for budget window to slide"
                        })
                        .to_string(),
                    ))
                    .expect("static response builder"));
            }
        }
    }

    // ── WAL audit (Pending — updated after response) ──
    let wal_event = gvm_types::GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        // CA-6 part 2: anchor every L7 event in this sandbox to the
        // sandbox's launch event, so a chain walker traversing back
        // from any decision can recover the cryptographic root + agent
        // identity without joining external state.
        parent_event_id: sandbox_anchor.as_ref().map(|(_, parent)| parent.clone()),
        agent_id: classify_output.agent_id.clone(),
        token_id: None,
        tenant_id: None,
        session_id: host.clone(),
        timestamp: chrono::Utc::now(),
        operation: format!("{} {}", method, path),
        resource: gvm_types::ResourceDescriptor {
            service: host.clone(),
            identifier: Some(path.clone()),
            tier: gvm_types::ResourceTier::External,
            sensitivity: gvm_types::Sensitivity::Medium,
        },
        context: std::collections::HashMap::new(),
        transport: Some(gvm_types::TransportInfo {
            method: method.clone(),
            host: host.clone(),
            path: path.clone(),
            status_code: None,
        }),
        decision: format!("{:?}", classify_output.classification.decision),
        decision_source: format!("{:?}", classify_output.classification.source),
        matched_rule_id: classify_output.classification.matched_rule_id.clone(),
        enforcement_point: "mitm".to_string(),
        status: gvm_types::EventStatus::Pending,
        payload: gvm_types::PayloadDescriptor::default(),
        event_hash: None,
        llm_trace: None,
        default_caution: is_default_caution,
        // Phase 5 (v3) §4.7: every behavioral event must record the
        // active integrity-context that governed the handler decision,
        // so an external auditor can resolve this event back to the
        // `gvm.system.config_load` record in the WAL chain. The MITM
        // path was previously logging None here, breaking traceability
        // for HTTPS traffic specifically (HTTP through proxy_handler
        // already populated this — see src/proxy.rs:511).
        config_integrity_ref: state.current_integrity_ref(),
        operation_descriptor: Some(crate::operation::http(&method, &path)),
    };
    match state.ledger.append_durable(&wal_event).await {
        Ok(()) => tracing::info!(host = %host, path = %path, "MITM WAL event recorded (Pending)"),
        Err(e) => tracing::error!(error = %e, "MITM WAL append FAILED"),
    }

    // ── Forward to upstream ──
    let upstream_host = host.split(':').next().unwrap_or(&host);
    tracing::info!(upstream_host, "MITM: forwarding to upstream");

    // Dev mode host override
    if let Some(local_addr) = state.host_overrides.get(upstream_host) {
        let addr = if local_addr.contains(':') {
            local_addr.clone()
        } else {
            format!("{}:80", local_addr)
        };
        // Apply credential injection on the dev path too — agents that
        // talk to host_override targets must not be able to smuggle
        // their own Authorization to bypass Layer 3. The TLS-upstream
        // branch below does the same; without this call here, the dev
        // branch was a credential-bypass.
        let mut dev_headers = original_headers.clone();
        let credential_policy = crate::api_keys::MissingCredentialPolicy::default();
        if let Err(e) = state
            .api_keys
            .inject(&mut dev_headers, &host, &credential_policy)
        {
            tracing::warn!(error = %e, host = %host,
                "MITM dev: credential injection failed (passthrough)");
        }
        // Synthesise an event_id + decision string for the dev path so
        // governance headers can be stamped on the response — same
        // observability anchor the production TLS path provides.
        let dev_event_id = uuid::Uuid::new_v4().to_string();
        let dev_decision = format!("{:?}", classify_output.classification.decision);
        let mut resp =
            forward_http(&addr, &method, &path, &dev_headers, &body_bytes, &host).await?;
        stamp_governance_headers(resp.headers_mut(), &dev_event_id, &dev_decision);
        return Ok(resp);
    }

    // Production: TLS upstream — try pool first, fall through to fresh
    // TCP+TLS+HTTP/1.1 handshake on miss or stale pooled sender.
    //
    // Without pooling, every MITM-intercepted request paid a fresh
    // upstream TCP+TLS handshake (~+200ms median against `httpbin.org`
    // from EC2 Seoul). With pooling the hot path collapses to just
    // sending the request on an existing keep-alive connection.
    // See `crate::upstream_pool` for the LIFO + body-finalizer design.
    let upstream_addr = format!("{}:443", upstream_host);
    let pool_key = upstream_addr.clone();

    let pooled = state.upstream_pool.try_take(&pool_key);
    let pool_hit = pooled.is_some();
    let mut maybe_sender: Option<crate::upstream_pool::SendRequestT> = if let Some(mut s) = pooled {
        // Sender came from pool — verify the underlying connection is
        // still alive. `ready().await` returns Err if the upstream
        // (or our driver task) dropped the connection while it was
        // idle. On Err we drop the sender and fall through to fresh.
        match s.ready().await {
            Ok(_) => {
                tracing::info!(host = %upstream_host, "MITM: reusing pooled upstream connection");
                Some(s)
            }
            Err(e) => {
                tracing::debug!(host = %upstream_host, error = %e, "MITM: pooled sender stale — falling back to fresh");
                None
            }
        }
    } else {
        None
    };

    if maybe_sender.is_none() {
        let _ = pool_hit; // (no-op — kept for potential future metrics)
        let connector = tokio_rustls::TlsConnector::from(client_config);
        tracing::info!(upstream_addr = %upstream_addr, "MITM: connecting to upstream TCP (no pool hit)");

        // Bound the TCP connect — DNS hangs and unreachable hosts would otherwise
        // sit here for the OS default (~2 minutes) and the agent's client timeout
        // would fire first, masking the proxy as the cause.
        const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let upstream_tcp = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(&upstream_addr),
        )
        .await
        {
            Ok(Ok(tcp)) => {
                tracing::info!(upstream_addr = %upstream_addr, "MITM: TCP connected");
                tcp
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream connect failed");
                return Ok(Response::builder()
                    .status(502)
                    .body(full_body(format!("Upstream connect failed: {}", e)))
                    .expect("static response builder"));
            }
            Err(_) => {
                tracing::warn!(
                    host = %upstream_host,
                    timeout_secs = CONNECT_TIMEOUT.as_secs(),
                    "MITM: upstream TCP connect timed out"
                );
                return Ok(Response::builder()
                    .status(504)
                    .body(full_body(format!(
                        "Upstream {} TCP connect timed out after {}s",
                        upstream_host,
                        CONNECT_TIMEOUT.as_secs()
                    )))
                    .expect("static response builder"));
            }
        };

        let server_name = match rustls::pki_types::ServerName::try_from(upstream_host.to_string()) {
            Ok(sn) => sn,
            Err(e) => {
                return Ok(Response::builder()
                    .status(502)
                    .body(full_body(format!("Invalid server name: {}", e)))
                    .expect("static response builder"));
            }
        };

        tracing::info!(host = %upstream_host, "MITM: starting upstream TLS handshake");
        const TLS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
        let upstream_tls =
            match tokio::time::timeout(TLS_TIMEOUT, connector.connect(server_name, upstream_tcp))
                .await
            {
                Ok(Ok(tls)) => {
                    tracing::info!(host = %upstream_host, "MITM: upstream TLS handshake complete");
                    tls
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream TLS failed");
                    return Ok(Response::builder()
                        .status(502)
                        .body(full_body(format!("Upstream TLS failed: {}", e)))
                        .expect("static response builder"));
                }
                Err(_) => {
                    tracing::warn!(
                        host = %upstream_host,
                        timeout_secs = TLS_TIMEOUT.as_secs(),
                        "MITM: upstream TLS handshake timed out"
                    );
                    return Ok(Response::builder()
                        .status(504)
                        .body(full_body(format!(
                            "Upstream {} TLS handshake timed out after {}s",
                            upstream_host,
                            TLS_TIMEOUT.as_secs()
                        )))
                        .expect("static response builder"));
                }
            };

        let io = hyper_util::rt::TokioIo::new(upstream_tls);
        tracing::info!(host = %upstream_host, "MITM: starting HTTP/1.1 handshake");
        let (sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(parts) => {
                tracing::info!(host = %upstream_host, "MITM: HTTP/1.1 handshake complete");
                parts
            }
            Err(e) => {
                tracing::warn!(error = %e, host = %upstream_host, "MITM: HTTP handshake failed");
                return Ok(Response::builder()
                    .status(502)
                    .body(full_body(format!("Upstream HTTP handshake failed: {}", e)))
                    .expect("static response builder"));
            }
        };

        // Drive upstream connection in background.
        // Log the driver's outcome at INFO so a silent failure here is visible —
        // a dropped driver makes sender.send_request() hang indefinitely.
        let driver_host = upstream_host.to_string();
        tokio::spawn(async move {
            match conn.await {
                Ok(()) => {
                    tracing::info!(host = %driver_host, "MITM: upstream conn driver ended cleanly")
                }
                Err(e) => {
                    tracing::warn!(error = %e, host = %driver_host, "MITM: upstream conn driver errored")
                }
            }
        });
        maybe_sender = Some(sender);
    }

    let mut sender = maybe_sender
        .expect("sender must be set by either pool hit path or fresh-connect path above");

    // Build upstream request with original headers.
    //
    // We must rewrite the Host header to the real upstream host. The agent
    // sent us its proxy address (e.g. 10.200.0.1:8080 inside the sandbox)
    // as Host, which would cause GitHub/Cloudflare/etc to reject or stall
    // the request. The hyper http1 client also relies on us setting Host
    // explicitly — without it the upstream sees an empty Host header and
    // may close the connection mid-response, surfacing as
    // "connection closed before message completed" in our error path.
    // Inject API credentials from secrets.toml (same as proxy.rs Layer 3).
    // Strips agent-supplied auth headers and replaces with proxy-managed credentials.
    let mut injected_headers = original_headers.clone();
    let credential_policy = crate::api_keys::MissingCredentialPolicy::default();
    if let Err(e) = state
        .api_keys
        .inject(&mut injected_headers, &host, &credential_policy)
    {
        tracing::warn!(error = %e, host = %host, "MITM: credential injection failed (passthrough)");
    }

    let mut upstream_req = Request::builder().method(method.as_str()).uri(&path);

    for (k, v) in injected_headers.iter() {
        let name = k.as_str().to_lowercase();
        // Skip hop-by-hop headers per RFC 7230 §6.1, plus:
        //   host             — rewritten below to the real upstream
        //   content-length   — body was re-collected into Full<Bytes>; hyper
        //                      sets content-length itself, and the original
        //                      value is stale if the agent re-chunked
        //   transfer-encoding — same reason
        if matches!(
            name.as_str(),
            "connection"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "keep-alive"
                | "te"
                | "upgrade"
                | "host"
        ) {
            continue;
        }
        upstream_req = upstream_req.header(k, v);
    }
    // Always set Host to the actual upstream — the original was the proxy.
    upstream_req = upstream_req.header("host", upstream_host);

    let body_len = body_bytes.len();
    let upstream_req = upstream_req
        .body(
            Full::new(body_bytes)
                .map_err(|_: std::convert::Infallible| -> String { unreachable!() })
                .boxed(),
        )
        .expect("Request::builder with validated method/uri/headers infallible");

    // Dump exactly what we send so a 10s graceful close from upstream is
    // attributable to *our* request, not guesswork. Logs every header that
    // hyper will put on the wire — confirms Host rewrite, no duplicates,
    // User-Agent presence, etc.
    {
        let dbg_method = upstream_req.method().clone();
        let dbg_uri = upstream_req.uri().clone();
        let dbg_headers: Vec<String> = upstream_req
            .headers()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<binary>")))
            .collect();
        tracing::info!(
            host = %upstream_host,
            method = %dbg_method,
            uri = %dbg_uri,
            body_bytes = body_len,
            headers = ?dbg_headers,
            "MITM: upstream request dump"
        );
    }

    tracing::info!(host = %upstream_host, "MITM: sending upstream request");
    // Bound the upstream wait. Without this, a stalled GitHub/Cloudflare
    // origin keeps the connection open indefinitely and the agent observes
    // a hang instead of an actionable 504. 60s matches the typical CDN
    // upstream timeout.
    const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let send_fut = sender.send_request(upstream_req);
    let send_result = match tokio::time::timeout(UPSTREAM_TIMEOUT, send_fut).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                host = %upstream_host,
                timeout_secs = UPSTREAM_TIMEOUT.as_secs(),
                "MITM: upstream request timed out"
            );
            return Ok(Response::builder()
                .status(504)
                .body(full_body(format!(
                    "Upstream {} timed out after {}s",
                    upstream_host,
                    UPSTREAM_TIMEOUT.as_secs()
                )))
                .expect("static response builder"));
        }
    };

    match send_result {
        Ok(resp) => {
            let resp_status = resp.status().as_u16();
            tracing::info!(status = resp_status, host = %upstream_host, "MITM: upstream response");

            // WAL status update (second write — Pending → Confirmed/Failed)
            let mut updated = wal_event.clone();
            updated.status = if resp.status().is_success() {
                gvm_types::EventStatus::Confirmed
            } else {
                gvm_types::EventStatus::Failed {
                    reason: format!("HTTP {}", resp_status),
                }
            };
            if let Some(ref mut t) = updated.transport {
                t.status_code = Some(resp_status);
            }
            let _ = state.ledger.append_durable(&updated).await;

            // Wrap the upstream body so that when the agent finishes
            // reading the response (or the body errors), the sender
            // is returned to the upstream pool — see
            // `crate::upstream_pool::SenderReturnerBody`. This is the
            // signal that the underlying HTTP/1.1 connection is back
            // to a reusable state; without it the sender would be
            // dropped here and the connection torn down.
            let (mut parts, body) = resp.into_parts();
            let body = crate::upstream_pool::SenderReturnerBody::new(
                body,
                sender,
                state.upstream_pool.clone(),
                pool_key.clone(),
            );

            // LLM trace extraction via tap-stream (non-blocking, no TTFB penalty)
            let llm_provider = crate::llm_trace::identify_llm_provider(&host);
            if let Some(provider) = llm_provider {
                if parts.status.is_success() {
                    stamp_governance_headers(
                        &mut parts.headers,
                        &wal_event.event_id,
                        &wal_event.decision,
                    );
                    let is_sse = parts
                        .headers
                        .get(hyper::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(crate::llm_trace::is_sse_content_type)
                        .unwrap_or(false);

                    // Detect content-encoding for transparent decompression
                    // of the capture buffer (agent receives original compressed bytes)
                    let encoding = parts
                        .headers
                        .get(hyper::header::CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| {
                            if v.contains("gzip") {
                                crate::llm_trace::ContentEncoding::Gzip
                            } else {
                                crate::llm_trace::ContentEncoding::Identity
                            }
                        })
                        .unwrap_or(crate::llm_trace::ContentEncoding::Identity);

                    use futures_util::StreamExt;

                    // Convert wrapped body → Stream<Result<Bytes, String>>;
                    // the SenderReturnerBody finalizer fires when this
                    // stream observes EOF.
                    let body_stream = http_body_util::BodyDataStream::new(body)
                        .map(|r| r.map_err(|e| e.to_string()));

                    let tapped = crate::llm_trace::tap_response_stream(
                        body_stream,
                        provider,
                        is_sse,
                        encoding,
                        updated,
                        state.ledger.clone(),
                        Some(state.token_budget.clone()),
                    );

                    // Wrap tapped stream back into BoxBody for hyper response
                    let tapped_body = BodyExt::boxed(http_body_util::StreamBody::new(
                        tapped.map(|r| r.map(hyper::body::Frame::data)),
                    ));
                    return Ok(Response::from_parts(parts, tapped_body));
                }
            }

            // Non-LLM or non-2xx: forward as-is. SenderReturnerBody
            // returns the sender to the pool when the body completes.
            stamp_governance_headers(&mut parts.headers, &wal_event.event_id, &wal_event.decision);
            let boxed = body.map_err(|e| e.to_string()).boxed();
            Ok(Response::from_parts(parts, boxed))
        }
        Err(e) => {
            // WAL: mark as Failed on connection error
            let mut failed = wal_event;
            failed.status = gvm_types::EventStatus::Failed {
                reason: format!("upstream error: {}", e),
            };
            let _ = state.ledger.append_durable(&failed).await;

            tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream request failed");
            Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Upstream request failed: {}", e)))
                .expect("static response builder"))
        }
    }
}

/// Forward to HTTP upstream (dev mode, no TLS).
async fn forward_http(
    addr: &str,
    method: &str,
    path: &str,
    headers: &hyper::HeaderMap,
    body: &Bytes,
    host: &str,
) -> Result<Response<MitmBody>, String> {
    let tcp = match tokio::net::TcpStream::connect(addr).await {
        Ok(tcp) => tcp,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Dev connect failed: {}", e)))
                .expect("static response builder"));
        }
    };

    let io = hyper_util::rt::TokioIo::new(tcp);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Dev handshake failed: {}", e)))
                .expect("static response builder"));
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers.iter() {
        let name = k.as_str().to_lowercase();
        // Same skip list as the HTTPS path: hop-by-hop + host + body framing.
        if matches!(
            name.as_str(),
            "connection"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "keep-alive"
                | "te"
                | "upgrade"
                | "host"
        ) {
            continue;
        }
        req = req.header(k, v);
    }
    req = req.header("host", host);
    let req = req
        .body(
            Full::new(body.clone())
                .map_err(|_: std::convert::Infallible| -> String { unreachable!() })
                .boxed(),
        )
        .expect("Request::builder with validated method/uri/headers infallible");

    const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let send_result = match tokio::time::timeout(UPSTREAM_TIMEOUT, sender.send_request(req)).await {
        Ok(r) => r,
        Err(_) => {
            return Ok(Response::builder()
                .status(504)
                .body(full_body(format!(
                    "Dev upstream {} timed out after {}s",
                    host,
                    UPSTREAM_TIMEOUT.as_secs()
                )))
                .expect("static response builder"));
        }
    };

    match send_result {
        Ok(resp) => {
            let (parts, body) = resp.into_parts();
            Ok(Response::from_parts(
                parts,
                body.map_err(|e| e.to_string()).boxed(),
            ))
        }
        Err(e) => Ok(Response::builder()
            .status(502)
            .body(full_body(format!("Dev upstream failed: {}", e)))
            .expect("static response builder")),
    }
}
