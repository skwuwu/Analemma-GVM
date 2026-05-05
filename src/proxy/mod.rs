// ─── Submodules (post-LOC-cleanup split) ───
//
// proxy.rs grew past 2.3k LOC during v0.5. Four logically-cohesive
// blocks are now their own files:
//   - `responses` — error / governance-block JSON builders + WAL hook
//   - `connect`   — CONNECT tunnel handler (HTTPS blind relay)
//   - `headers`   — `X-GVM-*` parse / inject + GVMEvent construction
//   - `forward`   — upstream request forwarding + LLM trace tap
// `proxy_handler` (the cooperative HTTP entry) and `AppState` stay
// here; CONNECT handler is re-exported so external callers
// (`crate::proxy::handle_connect`, `::remove_gvm_headers`) see no
// API change.

mod connect;
mod forward;
mod headers;
mod responses;

/// Test-only re-export of the responses helpers. Production code MUST
/// keep using the `pub(super) use responses::{...}` import below; this
/// alias exists so `crate::test_helpers` (which integration tests
/// consume) can reach `build_policy_link` without making the whole
/// `responses` module `pub`. Compiled out of release builds because
/// only the doc tests / integration tests reference the alias.
#[doc(hidden)]
pub mod responses_for_test {
    pub use super::responses::build_policy_link;
}

pub use connect::handle_connect;
pub use headers::remove_gvm_headers;

use crate::api_keys::APIKeyStore;
use crate::auth;
use crate::config::OnBlockConfig;
use crate::ledger::Ledger;
use crate::llm_trace;
use crate::srr::NetworkSRR;
use crate::token_budget::TokenBudget;
use crate::types::*;
use crate::vault::Vault;
#[cfg(feature = "wasm")]
use crate::wasm_engine::WasmEngine;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;

use forward::{event_status_from_response, extract_llm_trace_from_response, forward_request};
use headers::{
    build_event, build_operation_metadata, extract_target, inject_gvm_response_headers,
    parse_gvm_headers,
};
use responses::{append_proxy_wal_event, error_response, governance_block_response};

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

/// RAII guard that removes a pending IC-3 approval entry from the
/// shared map when the proxy handler future is dropped.
///
/// **Why this exists**: hyper cancels in-flight handler futures when
/// the agent disconnects (HTTP client timeout, Ctrl-C in the agent,
/// closed TCP). When that happens mid-`tokio::time::timeout(rx)` the
/// `rx` is dropped, but the matching `tx` was already moved into the
/// `pending_approvals` DashMap and would otherwise sit there until
/// the much-longer proxy IC-3 timeout (default 5 min) elapsed.
///
/// During that window, `gvm approve` would list the entry as if it
/// were live, and the operator's `(y)es` would deliver to a closed
/// receiver — the operator sees "Approved" but nothing happens. The
/// guard closes the race by removing the entry the moment the
/// handler is cancelled.
///
/// On the happy path the guard is `disarm()`'d before the function
/// returns, so the entry is consumed by `pending_approvals.remove()`
/// in the API handler, not by us.
struct ApprovalGuard {
    event_id: String,
    map: Arc<dashmap::DashMap<String, PendingApproval>>,
    armed: bool,
}

impl ApprovalGuard {
    /// Create a guard that will remove `event_id` from `map` on drop
    /// unless `disarm()` is called first.
    fn new(event_id: String, map: Arc<dashmap::DashMap<String, PendingApproval>>) -> Self {
        Self {
            event_id,
            map,
            armed: true,
        }
    }

    /// Mark the guard as no longer responsible for cleanup. Call this
    /// once the approval flow has consumed the entry through normal
    /// channels (operator decision, IC-3 timeout) so the guard does
    /// not double-remove on drop.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ApprovalGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.map.remove(&self.event_id).is_some() {
            tracing::debug!(
                event_id = %self.event_id,
                "IC-3: pending approval removed by guard (handler cancelled \
                 — agent disconnected before approval arrived)"
            );
        }
    }
}

// ─── Circuit Breaker Configuration ───

/// Number of consecutive primary WAL failures before the circuit breaker opens.
/// When open, IC-2/3 requests are rejected with 503 to prevent cascading failures.
const CIRCUIT_BREAKER_THRESHOLD: u64 = 5;

/// Retry-After header value (seconds) sent in 503 responses when the circuit breaker is open.
const CIRCUIT_BREAKER_RETRY_SECS: u64 = 30;

/// Per-sandbox `(GvmCertResolver, ServerConfig)` cache (CA-4 routing).
/// Aliased so the `AppState` field reads cleanly and clippy's
/// `type_complexity` lint is satisfied without a per-field allow.
pub type PerSandboxTlsCache = Arc<
    dashmap::DashMap<
        String,
        (
            Arc<crate::tls_proxy::GvmCertResolver>,
            Arc<rustls::ServerConfig>,
        ),
    >,
>;

/// Per-sandbox metadata captured at launch and read on every event
/// emitted from that sandbox. Public because `gvm sandbox list`
/// (CA-7) serializes it as JSON for the admin API response.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SandboxMetadata {
    /// Stable agent identity that is running inside this sandbox.
    pub agent_id: String,
    /// `event_id` of the durable `gvm.sandbox.launch` event in the
    /// audit chain. Subsequent enforcement events stamp this as
    /// their `parent_event_id` (CA-6 part 2).
    pub launch_event_id: String,
    /// Wall-clock launch time. Used by `gvm sandbox list` for the
    /// "uptime" column.
    pub launched_at: chrono::DateTime<chrono::Utc>,
}

/// Shared application state passed to all handlers
#[derive(Clone)]
pub struct AppState {
    /// SRR rule set, swapped atomically on `POST /gvm/reload`.
    ///
    /// CRITICAL: This is a `std::sync::RwLock`, not `tokio::sync::RwLock`.
    /// NEVER hold either guard across an `.await` point — doing so
    /// deadlocks a worker thread and fails the axum Handler Send bound
    /// at compile time. Deliberately synchronous because every request
    /// takes the read lock on the hot path; `tokio::sync::RwLock`'s
    /// ~10x overhead (~100-200ns vs ~20ns) is measurable at realistic
    /// RPS. Safe pattern: read-clone-drop in a tight scope, e.g.
    /// `state.srr.read().ok().map(|g| g.some_field.clone())`.
    pub srr: Arc<std::sync::RwLock<NetworkSRR>>,
    pub api_keys: Arc<APIKeyStore>,
    pub ledger: Arc<Ledger>,
    pub vault: Arc<Vault>,
    pub token_budget: Arc<TokenBudget>,
    /// Per-agent quota — independent budget instance per agent_id.
    /// One agent exhausting its share does NOT block other agents.
    /// Composes with `token_budget` (the org-wide ceiling): both
    /// must pass for an LLM request to proceed.
    pub per_agent_budgets: Arc<crate::token_budget::PerAgentBudgets>,
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
    /// Path to gvm.toml (for hot-reload). Empty if using legacy config.
    pub gvm_toml_path: Option<String>,
    /// MITM CA certificate PEM (for sandbox trust store download via GET /gvm/ca.pem).
    /// None when TLS MITM is not active.
    pub mitm_ca_pem: Option<Arc<Vec<u8>>>,
    /// Per-sandbox MITM CA registry (CA-2). Holds one `SandboxCA` per
    /// active sandbox keyed by `sandbox_id`. Provisioned by the
    /// `POST /gvm/sandbox/launch` admin endpoint, looked up by the
    /// MITM resolver during TLS handshake (CA-4 wiring), revoked on
    /// sandbox exit (CA-5).
    ///
    /// Populated unconditionally at proxy startup — the registry is
    /// just an empty `DashMap` until the first launch. The legacy
    /// `mitm_ca_pem` (single shared CA) coexists during the migration
    /// window and is removed at CA-5.
    pub ca_registry: Arc<gvm_sandbox::ca::CARegistry>,
    /// Per-sandbox cached `(GvmCertResolver, ServerConfig)` (CA-4 routing).
    ///
    /// Both Arcs are stored together because the TLS handshake path
    /// needs both: the resolver for `ensure_cached()` pre-warm (blocks
    /// only the spawn_blocking thread, never the tokio runtime), and
    /// the `ServerConfig` for `TlsAcceptor::from(_)`. Building one
    /// without the other would defeat the pre-warm purpose — a
    /// fresh-on-handshake resolver would hit `issue_and_cache`
    /// synchronously inside `resolve()`, blocking a tokio worker.
    ///
    /// Each entry's resolver is bound to exactly one sandbox's CA.
    /// The moka leaf-cert cache inside is therefore also per-sandbox:
    /// a leaf cert minted for sandbox A is never served to a TLS
    /// client owned by sandbox B (which would fail chain validation
    /// anyway, since B's trust store carries B's CA cert and not A's).
    ///
    /// Lifecycle: populated lazily on first MITM CONNECT for a given
    /// sandbox_id, cleared by [`AppState::revoke_sandbox`] when the
    /// sandbox exits. The dropped entry's Arcs are freed once the
    /// last in-flight handshake using them finishes — same Arc-based
    /// liveness rule as `CARegistry`.
    pub per_sandbox_tls: PerSandboxTlsCache,
    /// Per-sandbox metadata for audit + operator inspection (CA-7).
    ///
    /// Recorded by `api::sandbox_launch` alongside `ca_registry.provision`.
    /// Cleared by `revoke_sandbox`. Holds the agent_id + launch_event_id
    /// + launched_at so:
    ///   1. `GET /gvm/sandbox` (CA-7) can list active sandboxes with
    ///      enough context for the operator to identify each one.
    ///   2. The proxy hot path (CA-6 part 2) can fetch
    ///      `launch_event_id` for any sandbox_id and stamp it as
    ///      `parent_event_id` on the GVMEvents emitted from that
    ///      sandbox — anchoring every enforcement decision back to
    ///      the sandbox's launch event in the Merkle chain.
    ///
    /// `CARegistry` deliberately doesn't store these fields because
    /// it lives in `gvm-sandbox` and must not depend on audit types.
    /// Keeping the metadata here, in the proxy crate, preserves that
    /// dependency direction.
    pub per_sandbox_metadata: Arc<dashmap::DashMap<String, SandboxMetadata>>,
    /// `enforcement.policy_link_template` from gvm.toml. When `Some`,
    /// every block response gets an `X-GVM-Policy-Link` header with
    /// `{rule_id}` substituted. None disables the header. See
    /// [`crate::config::EnforcementConfig::policy_link_template`].
    pub policy_link_template: Option<String>,
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
    /// DNS governance engine (None when `--no-dns-governance` or `dns.enabled = false`).
    pub dns_governance: Option<Arc<crate::dns_governance::DnsGovernance>>,
    /// WAL file path for dashboard read-only access.
    pub wal_path: String,
    /// Active integrity context hash. Updated on config load/reload.
    /// Behavioral events reference this to map "which config version
    /// was active when this event happened" without per-event overhead.
    ///
    /// CRITICAL: This is a `std::sync::RwLock`. NEVER hold this guard
    /// across an `.await` point — it causes cross-task deadlocks that
    /// are nearly impossible to diagnose. Read-then-drop pattern only:
    /// `state.current_integrity_ref()` below does this correctly.
    ///
    /// The same rule applies to `srr: Arc<std::sync::RwLock<NetworkSRR>>`
    /// above. Both are on the request hot path; `tokio::sync::RwLock`
    /// is rejected here because its ~10x overhead over `std::sync` at
    /// ~tens of thousands of RPS is measurable.
    pub active_integrity_ref: Arc<std::sync::RwLock<Option<String>>>,
}

impl AppState {
    /// Snapshot the current integrity context hash. Takes the read lock,
    /// clones the `Option<String>`, and drops the guard immediately —
    /// safe to call before an `.await` in an event-creation path.
    ///
    /// Returns `None` if the lock is poisoned or no config has been
    /// loaded yet (pre-startup, tests).
    pub fn current_integrity_ref(&self) -> Option<String> {
        self.active_integrity_ref
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    /// Resolve (and lazily build) the per-sandbox TLS bundle for the
    /// given `sandbox_id`. Hot path — called once per CONNECT before
    /// TLS accept(). Returns the resolver (for pre-warm) and the
    /// `ServerConfig` (for `TlsAcceptor::from`) as a paired tuple.
    ///
    /// Cache hit: clones both `Arc`s (cheap).
    /// Cache miss: looks up the sandbox's CA from `ca_registry`,
    /// builds a `GvmCertResolver` from it, wraps in a `ServerConfig`
    /// (HTTP/1.1 ALPN forced, same as the legacy shared resolver),
    /// inserts both into the cache, returns the pair.
    /// Returns `None` only if the sandbox is not registered (revoked
    /// or never provisioned) — caller should fall back to the legacy
    /// `mitm_resolver` + `mitm_server_config`.
    pub fn tls_bundle_for_sandbox(
        &self,
        sandbox_id: &str,
    ) -> Option<(
        Arc<crate::tls_proxy::GvmCertResolver>,
        Arc<rustls::ServerConfig>,
    )> {
        // Fast path: cache hit.
        if let Some(entry) = self.per_sandbox_tls.get(sandbox_id) {
            let (r, sc) = entry.value();
            return Some((Arc::clone(r), Arc::clone(sc)));
        }

        // Slow path: build from CA. Bail if no CA is registered.
        let ca = self.ca_registry.lookup(sandbox_id)?;
        let resolver = match crate::tls_proxy::GvmCertResolver::from_sandbox_ca(&ca) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                tracing::error!(
                    sandbox = %sandbox_id,
                    error = %e,
                    "per-sandbox resolver build failed — falling through to legacy CA"
                );
                return None;
            }
        };
        let server_config = match crate::tls_proxy::build_server_config(Arc::clone(&resolver)) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!(
                    sandbox = %sandbox_id,
                    error = %e,
                    "per-sandbox ServerConfig build failed — falling through to legacy CA"
                );
                return None;
            }
        };
        // Insert if absent (a concurrent caller may have raced us; either
        // pair is fine, both are bound to the same `SandboxCA`).
        self.per_sandbox_tls
            .entry(sandbox_id.to_string())
            .or_insert_with(|| (Arc::clone(&resolver), Arc::clone(&server_config)));
        Some((resolver, server_config))
    }

    /// Resolve a connecting peer's IP back to its sandbox metadata
    /// (CA-6 part 2). Returns `(agent_id, launch_event_id)` when the
    /// peer's veth IP maps to a registered sandbox via the per-PID
    /// state file (Linux) AND that sandbox has audit metadata recorded.
    ///
    /// **Used to anchor every enforcement event in a sandbox to its
    /// launch event** — by stamping `parent_event_id =
    /// launch_event_id` and `agent_id = <real identity>` on the
    /// emitted GVMEvent, a chain walker traversing backward from any
    /// decision can recover the launch context (CA pubkey hash,
    /// agent_id, mode) without joining external state.
    ///
    /// Returns `None` for: loopback peers (cooperative mode — no
    /// sandbox), peers with no matching state file (legacy launch
    /// path), and on non-Linux builds where state files don't exist.
    /// Callers MUST treat `None` as "fall through to legacy
    /// agent_id='unknown' + parent_event_id=None" — this resolver is
    /// strictly additive.
    pub fn resolve_sandbox_anchor(
        &self,
        peer_ip: Option<std::net::IpAddr>,
    ) -> Option<(String, String)> {
        let ip = peer_ip?;
        if ip.is_loopback() {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            let sandbox_id = gvm_sandbox::lookup_sandbox_id_by_ip(&ip.to_string())?;
            let metadata = self.per_sandbox_metadata.get(&sandbox_id)?;
            Some((metadata.agent_id.clone(), metadata.launch_event_id.clone()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ip; // avoid unused-var lint on Windows
            None
        }
    }

    /// Revoke a sandbox: clear all derived state (TLS bundle cache,
    /// metadata), then drop its CA from the registry. Order matters
    /// — clear derived caches first so a concurrent
    /// `tls_bundle_for_sandbox` or metadata reader cannot resurrect
    /// a stale entry from the still-present CA.
    pub fn revoke_sandbox(&self, sandbox_id: &str) {
        self.per_sandbox_tls.remove(sandbox_id);
        self.per_sandbox_metadata.remove(sandbox_id);
        self.ca_registry.revoke(sandbox_id);
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

    // ── Step 2: Classify (IC determination) via SRR ──
    let (classification, is_default_caution) = {
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
        // srr guard dropped at end of block — ensures future is Send

        let operation = gvm_headers
            .as_ref()
            .map(|headers| build_operation_metadata(headers, &target));

        (
            Classification {
                decision: srr_result.decision,
                source: ClassificationSource::SRR,
                operation,
                matched_rule_id: srr_result.matched_description,
            },
            srr_result.is_catch_all,
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
                // SAFETY: This branch is unreachable because the enclosing
                // if-block checks `mode != Disabled` at line 422. However,
                // Code Standard 1.2 prohibits unreachable!() in runtime paths.
                // Fail-closed with a warning instead of panicking the proxy.
                crate::intent_store::ShadowMode::Disabled => {
                    tracing::error!("Shadow mode Disabled reached in intent check — logic error, failing closed");
                }
            }
            None
        }
    } else {
        None
    };

    // ── Step 3: Circuit Breaker — WAL health check ──
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
                        policy_link: None,
                        ic_level: 0,
                    },
                );
            }
            _ => {
                // IC-1 (Allow, AuditOnly) — proceed despite WAL issues
            }
        }
    }

    // ── Step 4: Enforcement with EventStatus lifecycle ──
    let mut event = build_event(&classification, &gvm_headers, &target);
    event.default_caution = is_default_caution;
    // Bind this event to the config version that was active when the
    // decision was made. Later auditors can resolve this ref back to the
    // `gvm.system.config_load` record in the Merkle chain and prove which
    // policy governed the action.
    event.config_integrity_ref = state.current_integrity_ref();
    // Populate transport.method (build_event cannot access the request)
    if let Some(ref mut t) = event.transport {
        t.method = request_method.clone();
    }
    // Phase 1.B: every event reaching the WAL must carry the v2
    // descriptor so external proofs can be redacted without breaking
    // event_hash recompute. build_event is shared between Allow /
    // Delay / Deny paths through proxy_handler; populate here once
    // request_method is known.
    event.operation_descriptor = Some(crate::operation::http(&request_method, &target.path));

    // ── Step 4: Token budget check (LLM providers only) ──
    // Two-tier (per-agent then global) is implemented in
    // `enforcement::check_and_reserve_token_budget` — single source of
    // truth shared with the MITM path so the order, rollback, and
    // disabled-tier short-circuit stay identical across transports.
    let is_llm = llm_trace::identify_llm_provider(&target.host).is_some();
    if is_llm {
        let effective_agent_id = gvm_headers
            .as_ref()
            .map(|h| h.agent_id.as_str())
            .unwrap_or("unknown");
        match crate::enforcement::check_and_reserve_token_budget(&state, effective_agent_id) {
            crate::enforcement::BudgetCheckOutcome::Allowed => {}
            crate::enforcement::BudgetCheckOutcome::PerAgentDenied(exceeded) => {
                let reason = if exceeded.tokens_limit == 0 && exceeded.cost_limit_millionths == 0 {
                    "Per-agent budget admission rejected (quota table full)".to_string()
                } else {
                    format!(
                        "Per-agent budget exceeded for {}: {}/{} tokens/hr (${:.2}/${:.2})",
                        effective_agent_id,
                        exceeded.tokens_used,
                        exceeded.tokens_limit,
                        exceeded.cost_used_usd(),
                        exceeded.cost_limit_usd(),
                    )
                };
                let operation = gvm_headers
                    .as_ref()
                    .map(|h| h.operation.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                return governance_block_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "PerAgentBudgetExceeded".to_string(),
                        event_id: event.event_id.clone(),
                        trace_id: event.trace_id.clone(),
                        operation,
                        reason,
                        mode: state.on_block.deny.clone(),
                        next_action: "wait for per-agent budget window to slide".to_string(),
                        retry_after_secs: Some(60),
                        rollback_hint: None,
                        matched_rule_id: None,
                        policy_link: None,
                        ic_level: 2,
                    },
                );
            }
            crate::enforcement::BudgetCheckOutcome::GlobalDenied(exceeded) => {
                let reason = format!(
                    "Token budget exceeded: {}/{} tokens/hr (${:.2}/${:.2})",
                    exceeded.tokens_used,
                    exceeded.tokens_limit,
                    exceeded.cost_used_usd(),
                    exceeded.cost_limit_usd(),
                );
                let operation = gvm_headers
                    .as_ref()
                    .map(|h| h.operation.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                return governance_block_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "BudgetExceeded".to_string(),
                        event_id: event.event_id.clone(),
                        trace_id: event.trace_id.clone(),
                        operation,
                        reason,
                        mode: state.on_block.deny.clone(),
                        next_action: "wait for budget window to slide".to_string(),
                        retry_after_secs: Some(60),
                        rollback_hint: None,
                        matched_rule_id: None,
                        policy_link: None,
                        ic_level: 2,
                    },
                );
            }
        }
    }

    // Measure engine processing time (classification was already done above)
    let engine_start = std::time::Instant::now();

    match &classification.decision {
        EnforcementDecision::Allow => {
            // Forward first, then WAL via group commit. Allow is a governance
            // decision and MUST be in the Merkle audit chain for compliance
            // and notarization. Group commit (~2ms batch window) keeps the
            // overhead negligible against a 50-500ms upstream round-trip.
            let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
            let mut response = forward_request(&state, request, &target).await;

            event.status = event_status_from_response(&response);
            if let Err(e) = state.ledger.append_durable(&event).await {
                // Response has already been returned upstream; we cannot
                // retroactively reject. Log the WAL miss so operators can
                // investigate audit gaps.
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "Allow: WAL durable write failed (primary + emergency both down)"
                );
            }
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
                        policy_link: None,
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
                        state.token_budget.clone(),
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

            // Capacity guard: reject new approvals if the queue is full.
            // Prevents unbounded DashMap growth from a flood of IC-3 requests.
            const MAX_PENDING_APPROVALS: usize = 1_000;
            if state.pending_approvals.len() >= MAX_PENDING_APPROVALS {
                tracing::error!(
                    pending = state.pending_approvals.len(),
                    "IC-3 approval queue full ({}) — rejecting request (fail-close)",
                    MAX_PENDING_APPROVALS,
                );
                return governance_block_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    GovernanceBlockResponse {
                        blocked: true,
                        decision: "Deny".to_string(),
                        event_id: event_id.clone(),
                        trace_id: event.trace_id.clone(),
                        operation: event.operation.clone(),
                        reason: "IC-3 approval queue capacity exceeded".to_string(),
                        mode: state.on_block.require_approval.clone(),
                        next_action: "Reduce concurrent RequireApproval requests or increase approval throughput".to_string(),
                        retry_after_secs: Some(10),
                        rollback_hint: Some(event.trace_id.clone()),
                        matched_rule_id: classification.matched_rule_id.clone(),
                        policy_link: responses::build_policy_link(
                            state.policy_link_template.as_deref(),
                            classification.matched_rule_id.as_deref(),
                        ),
                        ic_level: 3,
                    },
                );
            }

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

            // Arm a Drop-guard against agent disconnect. If hyper cancels
            // this handler future (agent's HTTP client timed out, TCP
            // closed, etc.), the guard removes our entry from
            // `pending_approvals` so the operator's next `gvm approve`
            // does not see a ghost request that can never be delivered.
            // We disarm the guard on every normal exit (decision arrived,
            // timeout fired, sender dropped) so the API handler can
            // consume the entry through `remove()` without a double-pop.
            let guard = ApprovalGuard::new(event_id.clone(), state.pending_approvals.clone());

            // Wait for approval decision or timeout
            let timeout_duration = std::time::Duration::from_secs(state.ic3_approval_timeout_secs);
            let approved = match tokio::time::timeout(timeout_duration, rx).await {
                Ok(Ok(decision)) => {
                    // Operator delivered a decision via /gvm/approve. The
                    // API handler already pop'd the entry, so we disarm
                    // the guard to avoid a no-op double-remove warning.
                    guard.disarm();
                    decision
                }
                Ok(Err(_)) => {
                    // Sender dropped (proxy shutting down or some other
                    // unexpected map clear). The entry is already gone;
                    // disarm to avoid logging a misleading "cancelled"
                    // message on shutdown.
                    tracing::warn!(event_id = %event_id, "IC-3: Approval channel closed — auto-denied");
                    guard.disarm();
                    false
                }
                Err(_) => {
                    // IC-3 timeout fired before any decision → fail-close.
                    // We pop the entry ourselves and disarm so the guard
                    // does not log a stale "cancellation" reason.
                    tracing::warn!(event_id = %event_id, "IC-3: Approval timeout — auto-denied");
                    state.pending_approvals.remove(&event_id);
                    guard.disarm();
                    false
                }
            };

            if approved {
                tracing::info!(event_id = %event_id, host = %target.host, "IC-3: Request APPROVED — forwarding");
                let engine_ms = engine_start.elapsed().as_secs_f64() * 1000.0;
                let mut response = forward_request(&state, request, &target).await;
                event.status = event_status_from_response(&response);
                // IC-3 human-approved execution is a high-value audit record;
                // must reach the Merkle chain.
                if let Err(e) = state.ledger.append_durable(&event).await {
                    tracing::warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "IC-3 APPROVED: WAL durable write failed"
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
                        policy_link: responses::build_policy_link(
                            state.policy_link_template.as_deref(),
                            classification.matched_rule_id.as_deref(),
                        ),
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
                    policy_link: responses::build_policy_link(
                        state.policy_link_template.as_deref(),
                        classification.matched_rule_id.as_deref(),
                    ),
                    ic_level: 4,
                },
            )
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

// Response builders — see `mod responses;`.

// CONNECT tunnel handler — see `mod connect;`.

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
            decision_source: "SRR".to_string(),
            matched_rule_id: None,
            enforcement_point: "proxy".to_string(),
            status: EventStatus::Pending,
            payload: PayloadDescriptor::default(),
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: false,
            config_integrity_ref: None,
            operation_descriptor: None,
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
        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;

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

        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;

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
        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;

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
        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;

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
        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;
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
        let repetitions = (crate::llm_trace::TAP_MAX_SSE_BYTES / sse_event.len()) + 128;

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

        let response = extract_llm_trace_from_response(
            response,
            "openai",
            &event,
            ledger,
            std::sync::Arc::new(crate::token_budget::TokenBudget::new(0, 0.0, 0)),
        )
        .await;

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

    // ─── ApprovalGuard regression tests ───
    //
    // These are pure logic tests that do not need a full proxy stack.
    // They lock in two invariants:
    //   1. When the IC-3 handler future is cancelled (rx dropped), the
    //      guard removes its entry from `pending_approvals`. This is
    //      the fix for the agent-disconnect ghost-approval bug.
    //   2. When the handler completes normally and `disarm()` is
    //      called, the guard does NOT remove a (possibly already
    //      reused) map entry. This locks in the no-double-pop
    //      contract that lets api.rs own the consumption side.

    fn make_pending(event_id: &str) -> (PendingApproval, tokio::sync::oneshot::Receiver<bool>) {
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let pending = PendingApproval {
            sender: tx,
            event_id: event_id.to_string(),
            operation: "test.op".to_string(),
            host: "example.com".to_string(),
            path: "/x".to_string(),
            method: "POST".to_string(),
            agent_id: "test-agent".to_string(),
            timestamp: chrono::Utc::now(),
        };
        (pending, rx)
    }

    #[test]
    fn approval_guard_removes_entry_on_drop_when_armed() {
        let map: Arc<dashmap::DashMap<String, PendingApproval>> = Arc::new(dashmap::DashMap::new());
        let event_id = "evt-cancel-1".to_string();
        let (pending, _rx) = make_pending(&event_id);
        map.insert(event_id.clone(), pending);

        {
            let _guard = ApprovalGuard::new(event_id.clone(), map.clone());
            assert_eq!(map.len(), 1, "entry must be present while guard is armed");
            // Simulate hyper cancelling the handler future: guard goes
            // out of scope without disarm().
        }

        assert_eq!(
            map.len(),
            0,
            "guard drop must remove the leaked pending approval entry"
        );
    }

    #[test]
    fn approval_guard_keeps_entry_when_disarmed() {
        // When the operator delivers a decision, api.rs pops the entry
        // via `pending_approvals.remove(&event_id)`. The proxy's
        // approval-handler future then disarms the guard before exit.
        // The guard must NOT remove an entry that has been re-inserted
        // for an unrelated event with the same id (shouldn't happen,
        // but the contract is "disarm == hands off").
        let map: Arc<dashmap::DashMap<String, PendingApproval>> = Arc::new(dashmap::DashMap::new());
        let event_id = "evt-normal-1".to_string();
        let (pending, _rx) = make_pending(&event_id);
        map.insert(event_id.clone(), pending);

        let guard = ApprovalGuard::new(event_id.clone(), map.clone());
        // Simulate api.rs popping the entry through the normal channel.
        let _popped = map.remove(&event_id);
        // And then proxy.rs disarming because the decision was delivered.
        // `disarm()` consumes the guard by value: armed flag is cleared
        // and Drop runs immediately as the binding goes out of scope.
        guard.disarm();

        // Re-insert a fresh entry for the same id. The disarmed guard
        // is already gone (consumed by disarm above), so the freshly
        // inserted entry is owned solely by `map`.
        let (pending2, _rx2) = make_pending(&event_id);
        map.insert(event_id.clone(), pending2);
        assert_eq!(
            map.len(),
            1,
            "disarmed guard must not interfere with subsequent inserts"
        );
    }
}
