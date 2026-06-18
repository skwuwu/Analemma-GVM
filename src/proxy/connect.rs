//! CONNECT tunnel handler — domain-level policy + TCP blind relay.
//!
//! Extracted from src/proxy.rs during the LOC cleanup pass. The
//! cooperative HTTP path stays in `super::proxy_handler`; this module
//! owns CONNECT specifically because TLS content is not inspected here
//! (HTTPS MITM is in `crate::tls_proxy_hyper`).

use crate::types::*;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};

use super::responses::{append_proxy_wal_event, error_response};
use super::AppState;

/// Outcome of the cooperative-lease pre-check on a CONNECT request.
/// CONNECT has no inner method or path visible to the proxy (both are
/// encrypted inside the TLS tunnel that follows the CONNECT 200), so
/// the bindings checked here are reduced compared with
/// [`super::CooperativeOutcome`]:
///
///   - **host** — must match the lease's declared host.
///   - **policy_epoch** — same strict-vs-`allow_pinned_lease` rule
///     as the HTTP path.
///
/// On `Valid`, the tunnel proceeds and the WAL event records
/// `decision_source = cooperative.declared_only` — the lease made the
/// agent's intent visible to the audit chain, but the proxy never
/// sees the body so cross-check is not possible.
pub enum ConnectLeaseOutcome {
    /// No `X-GVM-Context-Token` on the CONNECT — fall through to the
    /// existing domain-only SRR path.
    NoToken,
    /// Lease bound and host matches. The fields populated here flow
    /// into the WAL audit event so the audit chain captures the
    /// declared agent and operation. `pinned` is true when the
    /// lease was accepted across an epoch flip via
    /// `allow_pinned_lease`.
    Valid {
        agent_id: String,
        operation: String,
        pinned: bool,
    },
    /// Token bound but CONNECT host does not match the lease's
    /// declared host. Always Deny.
    Mismatch { reason: String },
    /// Token bound but the lease's `policy_epoch` differs from the
    /// proxy's current integrity ref AND the lease did NOT opt in to
    /// `allow_pinned_lease`. Always Deny.
    Expired { reason: String },
    /// Token presented but no matching active lease. Re-use, forgery,
    /// or replay. Always Deny.
    Unbound { reason: String },
}

/// Pull `X-GVM-Context-Token` off a CONNECT request, hash it, claim
/// the matching lease, and return the CONNECT-shaped outcome. Mirrors
/// `super::extract_and_claim_lease` for HTTP, with the reduced set of
/// bindings appropriate for CONNECT (host + epoch only).
///
/// The header is NOT stripped here — CONNECT requests are consumed by
/// the proxy and never re-sent upstream, so there is no leak risk
/// equivalent to the HTTP-path concern in Phase 2.
pub fn claim_connect_lease(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    host: &str,
) -> ConnectLeaseOutcome {
    use sha2::{Digest, Sha256};

    let Some(token_val) = headers.get("x-gvm-context-token") else {
        return ConnectLeaseOutcome::NoToken;
    };
    let Ok(token_str) = token_val.to_str() else {
        return ConnectLeaseOutcome::Unbound {
            reason: "X-GVM-Context-Token contains non-ASCII bytes".to_string(),
        };
    };

    let mut hasher = Sha256::new();
    hasher.update(token_str.as_bytes());
    let token_hash: [u8; 32] = hasher.finalize().into();

    let Some(claim) = state.intent_store.claim_by_token_hash(&token_hash) else {
        return ConnectLeaseOutcome::Unbound {
            reason: "context token does not bind to any active lease (re-use, forgery, or replay)"
                .to_string(),
        };
    };

    // Host is the only declared field the proxy can verify on a
    // CONNECT (method and path are inside the TLS the proxy is not
    // about to see).
    if !host.eq_ignore_ascii_case(&claim.host) {
        return ConnectLeaseOutcome::Mismatch {
            reason: format!(
                "host mismatch: declared {}, CONNECT target {}",
                claim.host, host
            ),
        };
    }

    // Policy epoch: same rule as the HTTP path. `allow_pinned_lease`
    // is the opt-in introduced in Phase 3a.
    let current_epoch = state.current_integrity_ref().unwrap_or_default();
    let pinned = if let Some(issued_epoch) = &claim.policy_epoch {
        if !issued_epoch.is_empty() && issued_epoch != &current_epoch {
            if claim.allow_pinned_lease {
                tracing::info!(
                    intent_id = claim.intent_id,
                    issued_epoch = %issued_epoch,
                    current_epoch = %current_epoch,
                    "CONNECT cooperative lease pinned across policy reload (allow_pinned_lease)"
                );
                true
            } else {
                return ConnectLeaseOutcome::Expired {
                    reason: format!(
                        "policy reloaded since CONNECT lease was issued (epoch mismatch); \
                         set allow_pinned_lease=true at issuance to tolerate"
                    ),
                };
            }
        } else {
            false
        }
    } else {
        false
    };

    ConnectLeaseOutcome::Valid {
        agent_id: claim.agent_id,
        operation: claim.operation,
        pinned,
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

    // ── Tier-3 P3-c Phase 3b: cooperative lease on CONNECT ──
    //
    // If the agent presented an `X-GVM-Context-Token` on the CONNECT
    // itself, attempt to bind the lease at the tunnel boundary. The
    // outcomes that short-circuit:
    //   - Mismatch / Expired / Unbound → Deny outright with the
    //     matching `cooperative.*` decision_source.
    //   - Valid → fall through to the existing SRR domain check; the
    //     final WAL audit event swaps `decision_source` to
    //     `cooperative.declared_only` and uses the lease's declared
    //     agent_id / operation (these are higher-fidelity than the
    //     veth-resolved anchor).
    //   - NoToken → proceed as before.
    let connect_lease = claim_connect_lease(&state, request.headers(), host);
    let (lease_agent_id, lease_operation, lease_pinned, lease_active) = match &connect_lease {
        ConnectLeaseOutcome::NoToken => (None, None, false, false),
        ConnectLeaseOutcome::Valid {
            agent_id,
            operation,
            pinned,
        } => (
            Some(agent_id.clone()),
            Some(operation.clone()),
            *pinned,
            true,
        ),
        ConnectLeaseOutcome::Mismatch { reason }
        | ConnectLeaseOutcome::Expired { reason }
        | ConnectLeaseOutcome::Unbound { reason } => {
            let (source_str, decision_source) = match &connect_lease {
                ConnectLeaseOutcome::Mismatch { .. } => ("Mismatch", "cooperative.mismatch"),
                ConnectLeaseOutcome::Expired { .. } => ("Expired", "cooperative.expired"),
                ConnectLeaseOutcome::Unbound { .. } => ("Unbound", "cooperative.unbound"),
                _ => unreachable!(),
            };
            let peer_ip_for_anchor = request.extensions().get::<std::net::IpAddr>().copied();
            let (anchor_agent_id, anchor_parent_event_id) =
                match state.resolve_sandbox_anchor(peer_ip_for_anchor) {
                    Some((agent, launch)) => (agent, Some(launch)),
                    None => ("unknown".to_string(), None),
                };
            tracing::warn!(host = %host, source = source_str, reason = %reason,
                "CONNECT cooperative lease rejected — denying tunnel");
            let event = GVMEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                trace_id: uuid::Uuid::new_v4().to_string(),
                agent_id: anchor_agent_id.clone(),
                token_id: None,
                operation: format!("connect:{}", host),
                decision: "Deny".to_string(),
                decision_source: decision_source.to_string(),
                status: EventStatus::Failed {
                    reason: reason.clone(),
                },
                enforcement_point: "proxy-cooperative".to_string(),
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
                matched_rule_id: Some(decision_source.to_string()),
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                config_integrity_ref: state.current_integrity_ref(),
                operation_descriptor: Some(crate::operation::connect(host)),
                tenant_id: None,
                parent_event_id: anchor_parent_event_id,
                session_id: String::new(),
            };
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "CONNECT cooperative Deny: WAL durable write failed"
                );
            }
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("X-GVM-Decision", "Deny")
                .header("X-GVM-Decision-Source", decision_source)
                .body(Body::from(format!("CONNECT denied: {}", reason)))
                .unwrap_or_else(|_| {
                    error_response(StatusCode::FORBIDDEN, "CONNECT cooperative deny")
                });
        }
    };

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

    // CA-6 part 2: resolve the connecting peer to its sandbox launch
    // anchor BEFORE building either the Deny or Allow event, so both
    // share the same identity attribution + parent_event_id chain
    // link. Capturing peer_ip here (vs the original site below) is
    // an additive change — the legacy site still uses `peer_ip` for
    // MITM gating later.
    let peer_ip_for_anchor = request.extensions().get::<std::net::IpAddr>().copied();
    let (anchor_agent_id, anchor_parent_event_id) =
        match state.resolve_sandbox_anchor(peer_ip_for_anchor) {
            Some((agent, launch)) => (agent, Some(launch)),
            None => ("unknown".to_string(), None),
        };

    // Enforce decision
    match decision {
        EnforcementDecision::Deny { reason } => {
            tracing::warn!(host = %host, reason = %reason, "CONNECT denied");

            // WAL record for denied CONNECT
            let event = GVMEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                trace_id: uuid::Uuid::new_v4().to_string(),
                agent_id: anchor_agent_id.clone(),
                token_id: None,
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
                event_hash: None,
                llm_trace: None,
                default_caution: false,
                config_integrity_ref: state.current_integrity_ref(),
                operation_descriptor: Some(crate::operation::connect(host)),
                tenant_id: None,
                parent_event_id: anchor_parent_event_id.clone(),
                session_id: String::new(),
            };
            // CONNECT Deny is a governance decision and must be durably
            // audited. (Pre-existing bug: this path previously used
            // append_async which did not write to WAL at all, so Deny
            // decisions for HTTPS tunnels were silently lost.)
            if let Err(e) = state.ledger.append_durable(&event).await {
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "CONNECT Deny: WAL durable write failed"
                );
            }

            return error_response(
                StatusCode::FORBIDDEN,
                &format!("CONNECT denied: {}", reason),
            );
        }
        _ => {
            // Allow, Delay, etc. — proceed with tunnel
        }
    }

    // WAL record for allowed CONNECT. Durable: Allow on a tunnel is the
    // audit anchor for everything that flows inside — must reach Merkle chain.
    //
    // Phase 3b: when the agent presented a valid `X-GVM-Context-Token`
    // on the CONNECT, swap `decision_source` to
    // `cooperative.declared_only` and overlay the lease's declared
    // `agent_id` / `operation` onto the audit event. The veth-resolved
    // anchor is still used as the fallback when no lease was present.
    let (event_agent_id, event_operation, event_source, event_enforcement_point) = if lease_active {
        (
            lease_agent_id.unwrap_or_else(|| anchor_agent_id.clone()),
            lease_operation.unwrap_or_else(|| format!("connect:{}", host)),
            "cooperative.declared_only".to_string(),
            "proxy-cooperative".to_string(),
        )
    } else {
        (
            anchor_agent_id.clone(),
            format!("connect:{}", host),
            "SRR".to_string(),
            "proxy".to_string(),
        )
    };
    let mut allow_context: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    if lease_pinned {
        allow_context.insert(
            "cooperative.pinned".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    let event = GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        agent_id: event_agent_id,
        token_id: None,
        operation: event_operation,
        decision: format!("{:?}", decision),
        decision_source: event_source,
        status: EventStatus::Confirmed,
        enforcement_point: event_enforcement_point,
        timestamp: chrono::Utc::now(),
        payload: PayloadDescriptor::default(),
        transport: Some(TransportInfo {
            method: "CONNECT".to_string(),
            host: host.to_string(),
            path: format!(":{}", port),
            status_code: None,
        }),
        resource: ResourceDescriptor::default(),
        context: allow_context,
        matched_rule_id: srr_result_matched.clone(),
        event_hash: None,
        llm_trace: None,
        default_caution: srr_result_catch_all,
        config_integrity_ref: state.current_integrity_ref(),
        operation_descriptor: Some(crate::operation::connect(host)),
        tenant_id: None,
        parent_event_id: anchor_parent_event_id.clone(),
        session_id: String::new(),
    };
    if let Err(e) = state.ledger.append_durable(&event).await {
        tracing::warn!(
            event_id = %event.event_id,
            error = %e,
            "CONNECT Allow: WAL durable write failed"
        );
    }

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

    // CA-4 routing: if the peer's veth IP maps to a registered sandbox_id
    // (via the per-PID state file), prefer that sandbox's per-sandbox CA.
    // Otherwise we fall back to the legacy shared `mitm_resolver` +
    // `mitm_server_config`, which is the right behavior for sandboxes
    // provisioned before CA-3 and for Docker-mode launches not yet wired
    // to /gvm/sandbox/launch.
    //
    // The lookup is Linux-only because state files live under /run/gvm,
    // a Linux-specific tmpfs. On other platforms the helper is absent
    // and we always use the legacy path — fine, since Windows/macOS
    // builds don't run sandboxes anyway.
    type PerSandboxBundle = (
        std::sync::Arc<crate::tls_proxy::GvmCertResolver>,
        std::sync::Arc<rustls::ServerConfig>,
    );
    #[cfg(target_os = "linux")]
    let per_sandbox: Option<PerSandboxBundle> = {
        peer_ip
            .filter(|ip| !ip.is_loopback())
            .and_then(|ip| gvm_sandbox::lookup_sandbox_id_by_ip(&ip.to_string()))
            .and_then(|sandbox_id| {
                tracing::debug!(
                    sandbox = %sandbox_id,
                    "CONNECT MITM: routing to per-sandbox CA (CA-4)"
                );
                state.tls_bundle_for_sandbox(&sandbox_id)
            })
    };
    #[cfg(not(target_os = "linux"))]
    let per_sandbox: Option<PerSandboxBundle> = None;

    let host_owned = host.to_string();
    let target_addr = format!("{}:{}", host, port);
    let (mitm_resolver, mitm_sc) = if is_isolated {
        match per_sandbox {
            // Per-sandbox path — both Arcs from the same bundle. Pre-warm
            // hits the per-sandbox resolver's leaf cache, not the legacy
            // shared one, so the handshake's `resolve()` call is a 0ns
            // cache hit signed by the right CA.
            Some((r, sc)) => (Some(r), Some(sc)),
            // Legacy fallback: shared CA. Same behavior as before CA-4.
            None => (
                state.mitm_resolver.clone(),
                state.mitm_server_config.clone(),
            ),
        }
    } else {
        (None, None)
    };
    let mitm_cc = if is_isolated {
        state.mitm_client_config.clone()
    } else {
        None
    };
    let connect_state = state.clone();
    // Bundle the resolved anchor so every L7 event served inside this
    // tunnel inherits the same (agent_id, launch_event_id) parent
    // link. Resolved once per CONNECT instead of per-request, since
    // the peer/sandbox binding is fixed for the tunnel's lifetime.
    let anchor_for_stream: Option<(String, String)> = anchor_parent_event_id
        .clone()
        .map(|launch_id| (anchor_agent_id.clone(), launch_id));

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

            if let Err(e) = crate::tls_proxy::handle_mitm_stream(
                tls_stream,
                &host_owned,
                cc,
                &connect_state,
                anchor_for_stream,
            )
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
