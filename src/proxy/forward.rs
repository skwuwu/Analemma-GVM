//! Upstream forwarding + LLM trace extraction.
//!
//! Extracted from src/proxy.rs during the LOC cleanup pass:
//!   - `event_status_from_response` — map upstream HTTP status to EventStatus.
//!   - `forward_request` — proxy the request to its upstream and return the
//!     response (with API-key injection).
//!   - `extract_llm_trace_from_response` — tap the upstream response body to
//!     capture LLM thinking trace into the pending event (IC-2/IC-3 only).

use crate::ledger::Ledger;
use crate::llm_trace;
use crate::types::*;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, Uri};
use futures_util::StreamExt;
use std::sync::Arc;

use super::headers::remove_gvm_headers;
use super::responses::{error_response, error_response_detailed};
use super::AppState;

/// Derive event status from upstream HTTP response.
pub(super) fn event_status_from_response(response: &Response<Body>) -> EventStatus {
    if response.status().is_success() {
        EventStatus::Confirmed
    } else {
        EventStatus::Failed {
            reason: format!("HTTP {}", response.status()),
        }
    }
}

/// Forward the request to the target with API key injection (Layer 3).
pub(super) async fn forward_request(
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
/// Wrap an LLM provider response with trace extraction tap-stream.
/// Delegates to the shared `llm_trace::tap_response_stream()`.
/// Returns the response with a tapped body that extracts traces post-stream.
pub(super) async fn extract_llm_trace_from_response(
    response: Response<Body>,
    provider: &str,
    event: &GVMEvent,
    ledger: Arc<Ledger>,
    token_budget: Arc<crate::token_budget::TokenBudget>,
) -> Response<Body> {
    let (parts, body) = response.into_parts();

    let is_sse = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(llm_trace::is_sse_content_type)
        .unwrap_or(false);

    // Convert axum Body to Stream<Item=Result<Bytes, String>> for the shared tap function
    let body_stream =
        http_body_util::BodyDataStream::new(body).map(|r| r.map_err(|e| e.to_string()));

    let tapped = llm_trace::tap_response_stream(
        body_stream,
        provider,
        is_sse,
        llm_trace::ContentEncoding::Identity, // axum auto-decompresses
        event.clone(),
        ledger,
        Some(token_budget),
    );

    Response::from_parts(
        parts,
        Body::from_stream(
            tapped.map(|r| r.map_err(|e| axum::Error::new(std::io::Error::other(e)))),
        ),
    )
}
