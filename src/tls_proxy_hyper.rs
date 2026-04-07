//! Hyper-based MITM request handler.
//!
//! Replaces the custom HTTP parser + relay functions with hyper's HTTP/1.1
//! server and client. hyper manages chunked encoding, content-length,
//! keep-alive, and connection framing — eliminating all manual framing bugs.
//!
//! Architecture:
//!   Client TLS stream → hyper server (parse request)
//!                     → classify (SRR + ABAC)
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

/// Entry point: serve MITM HTTP/1.1 on a TLS stream using hyper.
/// Replaces the old manual keep-alive loop + custom relay.
pub async fn serve_mitm<S>(
    tls_stream: tokio_rustls::server::TlsStream<S>,
    host_hint: String,
    client_config: Arc<rustls::ClientConfig>,
    state: crate::proxy::AppState,
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
        async move { handle_request(req, &hint, cc, &state).await }
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
    let classify_output = match crate::enforcement::classify(state, &classify_input) {
        Ok(o) => o,
        Err(err_msg) => {
            tracing::error!(error = %err_msg, "MITM classification failed (fail-close)");
            return Ok(Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(full_body(
                    r#"{"blocked":true,"decision":"Deny","reason":"Internal governance error"}"#,
                ))
                .unwrap());
        }
    };

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
            )
            .await;
            // Keep-alive: no Connection: close — agent can retry on same connection
            return Ok(Response::builder()
                .status(403)
                .header("Content-Type", "application/json")
                .body(full_body(body.to_string()))
                .unwrap());
        }
        gvm_types::EnforcementDecision::Delay { milliseconds } => {
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
        }
        gvm_types::EnforcementDecision::Throttle { max_per_minute } => {
            if !state
                .rate_limiter
                .check(&classify_output.agent_id, *max_per_minute)
            {
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
                    "Throttle (rate limit exceeded)",
                    Some(429),
                    false,
                )
                .await;
                return Ok(Response::builder()
                    .status(429)
                    .header("Content-Type", "application/json")
                    .header("Retry-After", "60")
                    .body(full_body(
                        r#"{"blocked":true,"decision":"Throttle","reason":"Rate limit exceeded"}"#,
                    ))
                    .unwrap());
            }
        }
        _ => {} // Allow, AuditOnly
    }

    // ── WAL audit ──
    {
        let event = gvm_types::GVMEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            parent_event_id: None,
            agent_id: classify_output.agent_id.clone(),
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
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: is_default_caution,
        };
        match state.ledger.append_durable(&event).await {
            Ok(()) => tracing::info!(host = %host, path = %path, "MITM WAL event recorded"),
            Err(e) => tracing::error!(error = %e, "MITM WAL append FAILED"),
        }
    }

    // ── Forward to upstream ──
    let upstream_host = host.split(':').next().unwrap_or(&host);

    // Dev mode host override
    if let Some(local_addr) = state.host_overrides.get(upstream_host) {
        let addr = if local_addr.contains(':') {
            local_addr.clone()
        } else {
            format!("{}:80", local_addr)
        };
        return forward_http(&addr, &method, &path, &original_headers, &body_bytes, &host).await;
    }

    // Production: TLS upstream
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let upstream_addr = format!("{}:443", upstream_host);

    let upstream_tcp = match tokio::net::TcpStream::connect(&upstream_addr).await {
        Ok(tcp) => tcp,
        Err(e) => {
            tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream connect failed");
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Upstream connect failed: {}", e)))
                .unwrap());
        }
    };

    let server_name = match rustls::pki_types::ServerName::try_from(upstream_host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Invalid server name: {}", e)))
                .unwrap());
        }
    };

    let upstream_tls = match connector.connect(server_name, upstream_tcp).await {
        Ok(tls) => tls,
        Err(e) => {
            tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream TLS failed");
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Upstream TLS failed: {}", e)))
                .unwrap());
        }
    };

    let io = hyper_util::rt::TokioIo::new(upstream_tls);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(parts) => parts,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Upstream HTTP handshake failed: {}", e)))
                .unwrap());
        }
    };

    // Drive upstream connection in background
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "MITM: upstream conn driver ended");
        }
    });

    // Build upstream request with original headers.
    //
    // We must rewrite the Host header to the real upstream host. The agent
    // sent us its proxy address (e.g. 10.200.0.1:8080 inside the sandbox)
    // as Host, which would cause GitHub/Cloudflare/etc to reject or stall
    // the request. The hyper http1 client also relies on us setting Host
    // explicitly — without it the upstream sees an empty Host header and
    // may close the connection mid-response, surfacing as
    // "connection closed before message completed" in our error path.
    let mut upstream_req = Request::builder().method(method.as_str()).uri(&path);

    for (k, v) in original_headers.iter() {
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

    let upstream_req = upstream_req
        .body(
            Full::new(body_bytes)
                .map_err(|_: std::convert::Infallible| -> String { unreachable!() })
                .boxed(),
        )
        .unwrap();

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
                .unwrap());
        }
    };

    match send_result {
        Ok(resp) => {
            tracing::debug!(status = %resp.status(), host = %upstream_host, "MITM: upstream response");
            // Stream response directly to client — hyper handles framing.
            // No buffering, no custom chunked parser, no manual content-length.
            let (parts, body) = resp.into_parts();
            let boxed = body.map_err(|e| e.to_string()).boxed();
            Ok(Response::from_parts(parts, boxed))
        }
        Err(e) => {
            tracing::warn!(error = %e, host = %upstream_host, "MITM: upstream request failed");
            Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Upstream request failed: {}", e)))
                .unwrap())
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
                .unwrap());
        }
    };

    let io = hyper_util::rt::TokioIo::new(tcp);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(Response::builder()
                .status(502)
                .body(full_body(format!("Dev handshake failed: {}", e)))
                .unwrap());
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
        .unwrap();

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
                .unwrap());
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
            .unwrap()),
    }
}
