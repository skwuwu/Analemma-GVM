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

/// Test-only re-export of CONNECT-side helpers so integration tests
/// can exercise the cooperative-lease pre-check directly. The helper
/// is unit-testable in isolation; the full `handle_connect` flow
/// requires hyper's upgrade machinery which is heavy to stub.
#[doc(hidden)]
pub mod connect_for_test {
    pub use super::connect::{claim_connect_lease, ConnectLeaseOutcome};
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

/// Spawn a background task that periodically sweeps `pending_approvals`
/// for entries that have outlived `2 * timeout_secs` — defense-in-depth
/// against the narrow race between `pending_approvals.insert` and
/// `ApprovalGuard::new` in `proxy_handler`.
///
/// The guard already covers the dominant failure mode (handler future
/// dropped after the guard is on the stack). The remaining hole is:
/// the handler future is dropped between `insert` and the `let guard =
/// ...` line — a sync stack-frame window with no `.await`, so it can
/// only fire if a parent task explicitly cancels the handler. Rare,
/// but the consequence (a "ghost" approval that `gvm approve` sees but
/// can never deliver to) is bad enough to warrant a periodic sweep.
///
/// The sweep is also a generic safety net for any future bug that
/// leaks entries — proxy never accumulates pending entries indefinitely
/// even if a new code path forgets to install the guard.
pub fn spawn_pending_approval_sweeper(
    pending_approvals: std::sync::Arc<dashmap::DashMap<String, PendingApproval>>,
    timeout_secs: u64,
) {
    // Run every 60s — finer cadence is wasteful (entries are bounded
    // to MAX_PENDING_APPROVALS = 1000 and naturally evicted by the
    // per-entry timeout); coarser cadence delays cleanup of leaked
    // entries but doesn't lose correctness.
    let interval = std::time::Duration::from_secs(60);
    // Anything older than 2x the per-entry timeout is definitely
    // unreachable from the original handler — the inner timeout has
    // long since expired and the entry should have been removed.
    // Keep a generous safety multiplier so we don't fight the normal
    // expiry path under clock skew.
    let stale_after = chrono::Duration::seconds((timeout_secs * 2) as i64);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let swept =
                sweep_stale_pending_approvals(&pending_approvals, chrono::Utc::now(), stale_after);
            if swept > 0 {
                tracing::warn!(
                    swept,
                    stale_after_secs = stale_after.num_seconds(),
                    "pending_approvals sweeper removed stale entries — \
                     these are typically handler futures that were cancelled \
                     between insert and the ApprovalGuard installation. \
                     Rare race; investigate if non-zero counts persist."
                );
            }
        }
    });
}

/// Pure-function core of the pending-approvals sweeper. Returns the
/// number of entries removed. Caller supplies `now` so tests can
/// drive the sweep against a synthetic clock without
/// `tokio::time::pause`. Two-phase iteration (collect keys, then
/// remove) keeps the dashmap shard locks free during the scan so
/// concurrent inserts/removes don't stall.
pub fn sweep_stale_pending_approvals(
    pending_approvals: &dashmap::DashMap<String, PendingApproval>,
    now: chrono::DateTime<chrono::Utc>,
    stale_after: chrono::Duration,
) -> usize {
    let stale_keys: Vec<String> = pending_approvals
        .iter()
        .filter(|entry| now.signed_duration_since(entry.value().timestamp) > stale_after)
        .map(|entry| entry.key().clone())
        .collect();
    let mut swept = 0;
    for key in stale_keys {
        if pending_approvals.remove(&key).is_some() {
            swept += 1;
        }
    }
    swept
}

/// Spawn a background task that periodically revokes per-sandbox CA +
/// TLS-bundle entries whose `launched_at` is older than `max_age_secs`.
///
/// `revoke_sandbox` is normally driven by:
///   1. `DELETE /gvm/sandbox/{id}` from the CLI on normal sandbox exit
///   2. `gvm cleanup` (GAP-13) when an orphan state file is processed
///
/// Neither covers the case where a sandbox was launched but its
/// parent process was SIGKILLed / OOM-killed before `gvm cleanup` ever
/// ran on this host. `per_sandbox_metadata` and `ca_registry` would
/// keep the dead sandbox's entries until the proxy itself restarts —
/// under high churn the unbounded growth becomes a slow RAM leak.
///
/// The sweeper enforces a wall-clock TTL: a sandbox that's been
/// registered for longer than `max_age_secs` (default 6h) is
/// unconditionally revoked. This isn't a tight liveness check — a
/// long-running but legitimate sandbox would also be evicted. That's
/// acceptable because:
///   - Typical agent sandboxes are short-lived (minutes, not hours).
///   - A revoked sandbox's next request gets `UnknownIssuer` and the
///     CLI re-launches with a fresh CA — the failure mode is "noisy
///     reconnect", not "broken governance".
///   - Operators can override the TTL via `GVM_SANDBOX_METADATA_TTL_SECS`
///     for unusual deployments.
///
/// A future enhancement: extend `SandboxLaunchRequest` with the
/// parent PID so the sweep can use `is_pid_alive` for tighter
/// detection. Until then TTL is the floor.
pub fn spawn_sandbox_metadata_sweeper(state: AppState, max_age_secs: u64) {
    // Sweep every 5 minutes — entries are bounded by sandbox-launch
    // throughput times TTL, so a coarser cadence is fine. Even a
    // 100-launch/min storm produces only ~30k entries over the TTL
    // window, and DashMap iteration is O(n) per shard.
    let interval = std::time::Duration::from_secs(300);
    let max_age = chrono::Duration::seconds(max_age_secs as i64);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now();
            // Two-phase to avoid holding shard locks across revoke calls
            // (revoke_sandbox touches three DashMaps + ca_registry).
            let stale: Vec<String> = state
                .per_sandbox_metadata
                .iter()
                .filter(|entry| now.signed_duration_since(entry.value().launched_at) > max_age)
                .map(|entry| entry.key().clone())
                .collect();
            let count = stale.len();
            for sandbox_id in stale {
                state.revoke_sandbox(&sandbox_id);
            }
            if count > 0 {
                tracing::warn!(
                    swept = count,
                    ttl_secs = max_age_secs,
                    "Sandbox metadata sweeper revoked stale entries — \
                     parent process likely died before normal cleanup ran. \
                     Investigate if non-zero counts persist."
                );
            }
        }
    });
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
    /// Upstream HTTPS connection pool used by the MITM relay
    /// (`tls_proxy_hyper::handle_request`). Without this, every
    /// MITM-intercepted request triggers a fresh TCP+TLS+HTTP/1.1
    /// handshake to the upstream — which added ~200ms to every
    /// HTTP/1.1 request before it was wired in. See
    /// `crate::upstream_pool` for the LIFO + body-finalizer design.
    pub upstream_pool: crate::upstream_pool::UpstreamPool,
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
    /// Reverse index: peer veth IP → `sandbox_id`. Populated lazily
    /// on the first successful `resolve_sandbox_anchor` for a given
    /// IP and invalidated implicitly on sandbox revoke (the
    /// downstream `per_sandbox_metadata.get(sandbox_id)` miss makes
    /// the entry self-correct).
    ///
    /// Without this cache, the cooperative-lease HTTP hot path
    /// (`try_sandbox_binding`) and the CONNECT handler do a
    /// per-request `lookup_sandbox_id_by_ip` — a `read_dir` over
    /// `/run/gvm/` plus N JSON parses per active sandbox. That
    /// violates the §3.1 hot-path budget ("no filesystem I/O during
    /// policy evaluation"). The cache keeps the first request from
    /// each peer at the same cost as before; every subsequent
    /// request is O(1).
    pub peer_ip_to_sandbox_id: Arc<dashmap::DashMap<std::net::IpAddr, String>>,
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
    /// Background-reverify WAL chain health flag (`△-6`).
    /// Read by `/gvm/health`; written by the background task in
    /// `crate::wal_background_reverify`. Always-`true` when the
    /// background task is disabled (`background_reverify_interval_secs = 0`).
    pub wal_chain_health: crate::wal_background_reverify::WalChainHealth,
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
    /// Tier-3 P3-b: in-process event fan-out for the
    /// `GET /gvm/events` SSE endpoint. The Ledger holds the same
    /// `Sender` (it broadcasts on every successful WAL append) and
    /// the SSE handler calls `event_broadcast.subscribe()` to get
    /// a fresh `Receiver` per connected orchestrator.
    ///
    /// Capacity is 1024 — a slow subscriber gets `RecvError::Lagged`
    /// after that much backlog, the SSE stream sends a `lagged`
    /// event, and the connection is closed so the orchestrator
    /// reconciles via `GET /gvm/pending` (and `GET /gvm/srr/rule`).
    /// The WAL writer is NEVER blocked by a stuck subscriber.
    pub event_broadcast: tokio::sync::broadcast::Sender<gvm_types::GVMEvent>,
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
        let sandbox_id = self.peer_ip_to_sandbox_id_cached(ip)?;
        let metadata = self.per_sandbox_metadata.get(&sandbox_id)?;
        Some((metadata.agent_id.clone(), metadata.launch_event_id.clone()))
    }

    /// Synthesize a `VerifiedIdentity` for a sandboxed peer when the
    /// agent did not present a JWT Bearer token. Source-IP-based
    /// identity for traffic that originates inside a GVM-allocated
    /// sandbox namespace.
    ///
    /// **Why this is sound.** The veth IP carrying the request is
    /// allocated by GVM itself (the proxy minted it, recorded it in
    /// `/run/gvm/gvm-sandbox-{pid}.state`, and forwarded the sandbox
    /// child into a network namespace where that IP is the only
    /// non-loopback source). For an agent process to spoof a
    /// different agent's IP would require breaking out of its
    /// network namespace — which is the same threat boundary that
    /// already protects credential separation between sandboxes.
    /// In other words, an attacker capable of forging the source IP
    /// is already capable of bypassing every other sandbox guarantee,
    /// so trusting `peer_ip → sandbox_id → agent_id` is no weaker
    /// than the rest of the model.
    ///
    /// **Why we still set `token_id` to a synthetic marker.** The
    /// audit chain records `token_id` from the `VerifiedIdentity`
    /// for forensics. Real JWTs carry a UUID `jti`; for IP-derived
    /// identities we emit `sandbox-peer:<sandbox_id>` so a downstream
    /// reader can tell at a glance that this event was authenticated
    /// by namespace topology, not by an HMAC-signed token. This
    /// preserves the auditability of which trust path was taken.
    ///
    /// Returns `None` when the peer IP cannot be resolved to a
    /// registered sandbox — caller falls through to the
    /// header-based or "unknown" identity path, matching the
    /// existing behavior of `resolve_sandbox_anchor`.
    pub fn resolve_identity_from_peer(
        &self,
        peer_ip: Option<std::net::IpAddr>,
    ) -> Option<auth::VerifiedIdentity> {
        let ip = peer_ip?;
        if ip.is_loopback() {
            return None;
        }
        let sandbox_id = self.peer_ip_to_sandbox_id_cached(ip)?;
        let metadata = self.per_sandbox_metadata.get(&sandbox_id)?;
        Some(auth::VerifiedIdentity {
            agent_id: metadata.agent_id.clone(),
            tenant_id: None,
            token_id: format!("sandbox-peer:{}", sandbox_id),
            gvm_role: None,
        })
    }

    /// Cached `peer_ip → sandbox_id` lookup. Cache hit works on
    /// every platform — the lookup is a plain DashMap read. Cache
    /// miss falls back to scanning `/run/gvm/*.state` files which
    /// is Linux-only; on other platforms a miss returns `None`.
    ///
    /// Tests can populate the cache directly via
    /// `state.peer_ip_to_sandbox_id.insert(ip, sandbox_id)` to
    /// exercise the resolver without standing up real veth state
    /// files. Production paths reach the FS fallback the first
    /// time each peer IP is seen, then ride the cache.
    fn peer_ip_to_sandbox_id_cached(&self, ip: std::net::IpAddr) -> Option<String> {
        if let Some(entry) = self.peer_ip_to_sandbox_id.get(&ip) {
            let cached = entry.value().clone();
            // Verify the cache entry still corresponds to an active
            // sandbox; stale entries (sandbox revoked) self-correct.
            if self.per_sandbox_metadata.contains_key(&cached) {
                return Some(cached);
            }
            drop(entry);
            self.peer_ip_to_sandbox_id.remove(&ip);
        }
        #[cfg(target_os = "linux")]
        {
            let sandbox_id = gvm_sandbox::lookup_sandbox_id_by_ip(&ip.to_string())?;
            // Only cache if the metadata is present too — otherwise a
            // race between FS-scan and revoke would poison the cache.
            if self.per_sandbox_metadata.contains_key(&sandbox_id) {
                self.peer_ip_to_sandbox_id.insert(ip, sandbox_id.clone());
            }
            Some(sandbox_id)
        }
        #[cfg(not(target_os = "linux"))]
        {
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
        // Drop every peer_ip → sandbox_id cache entry that targets
        // this sandbox. Stale entries would self-correct on the next
        // hot-path lookup (the downstream `per_sandbox_metadata.get`
        // would miss), but proactively clearing makes the invariant
        // "cache only contains live sandboxes" hold exactly. Linear
        // scan over the DashMap is fine — revoke is not a hot path
        // and the map is bounded by active-sandbox count.
        self.peer_ip_to_sandbox_id
            .retain(|_ip, sid| sid != sandbox_id);
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
    //
    // Two trust paths produce a `VerifiedIdentity`:
    //   (1) Agent-presented Bearer JWT (HMAC-signed; cryptographic).
    //   (2) Source-IP → sandbox mapping for traffic that originates
    //       inside a GVM-allocated network namespace (topological).
    //
    // (2) is what makes JWT-enabled deployments work for SDK-less
    // agents (e.g. plain urllib in a sandbox) without forcing every
    // agent author to manually add an Authorization header. The
    // proxy minted the veth IP itself, so resolving peer-IP →
    // sandbox_id → agent_id is no weaker than the namespace
    // isolation that already separates sandboxes from each other.
    // See `AppState::resolve_identity_from_peer` for the soundness
    // argument.
    let peer_ip_for_identity = request.extensions().get::<std::net::IpAddr>().copied();
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
            None => match state.resolve_identity_from_peer(peer_ip_for_identity) {
                Some(identity) => {
                    tracing::debug!(
                        agent = %identity.agent_id,
                        token_id = %identity.token_id,
                        "Identity derived from sandbox peer IP (no JWT presented)"
                    );
                    Some(identity)
                }
                None => {
                    if jwt.strict {
                        tracing::warn!("Strict-mode reject: no JWT token, no sandbox-peer mapping");
                        return error_response(
                            StatusCode::UNAUTHORIZED,
                            "Authentication required: present a Bearer JWT or run inside a GVM sandbox",
                        );
                    }
                    tracing::warn!(
                        "No JWT token provided and peer is not a known sandbox — \
                         falling back to unverified X-GVM-Agent-Id header"
                    );
                    None
                }
            },
        }
    } else {
        // JWT disabled globally — still try sandbox-peer mapping so
        // namespace-derived identity works in dev workflows that ran
        // without a JWT secret. Falls through to header path on miss.
        state.resolve_identity_from_peer(peer_ip_for_identity)
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

    // ── Step 1.6: Cooperative intent lease claim (Tier-3 P3-c Phase 2) ──
    //
    // If the agent's request carries an `X-GVM-Context-Token`, this is
    // a body-aware lease the agent registered via `POST /gvm/intent`.
    // The token is hashed and looked up; the lease snapshots what the
    // agent declared. Three outcomes that change classification:
    //
    //   (a) Token present, lease found, declared matches observed →
    //       `CooperativeCrossChecked`. Run SRR on the observed body
    //       as usual; the cross-check just upgrades the evidence label.
    //   (b) Token present, lease found, observed body unavailable
    //       (MITM blind / no body / oversized) → `CooperativeDeclaredOnly`.
    //       Run SRR on the declared payload context instead.
    //   (c) Token present, mismatch / expired / unknown → Deny outright
    //       with the corresponding `Cooperative*` source.
    //
    // CRITICAL: regardless of outcome, the `X-GVM-Context-Token` header
    // is STRIPPED before the request is forwarded upstream. The token
    // is bearer material; leaking it to GitHub / Slack / Stripe would
    // let those endpoints replay it to GVM and impersonate the lease.
    // The request's effective principal: JWT subject if a verified
    // JWT identity exists, otherwise the X-GVM-Agent-Id header value.
    // `extract_and_claim_lease` H8 check compares this against
    // `claim.agent_id` and Denies (`cooperative.mismatch`) on
    // disagreement, defeating the "agent A presents agent B's token"
    // attack. Passing `None` skips the check — same legacy behaviour
    // as before H8, used by deployments that haven't wired JWT yet.
    let request_principal: Option<&str> = verified_identity
        .as_ref()
        .map(|v| v.agent_id.as_str())
        .or_else(|| gvm_headers.as_ref().map(|h| h.agent_id.as_str()));

    let cooperative_outcome = extract_and_claim_lease(
        &state,
        &mut request,
        &target,
        body_for_srr,
        request_principal,
    );

    // Strip the GVM-internal cooperative header NOW so every downstream
    // path (SRR check, upstream forward, error response) sees the
    // sanitised request. The header value is already consumed by the
    // claim step above; nothing else needs it.
    request.headers_mut().remove("x-gvm-context-token");

    // ── Step 1.7: Phase 3c sandbox-IP fallback ──
    //
    // No `X-GVM-Context-Token` was presented, but the peer might be
    // a GVM-allocated sandbox whose agent already registered a
    // matching lease via `POST /gvm/intent`. Resolve the peer IP →
    // agent_id; if there's a fresh cooperative lease for this
    // (agent_id, method, host, path), claim it implicitly. This is
    // the binding channel for cert-pinned clients that cannot set
    // custom HTTP headers — the lease registration happens through
    // GVM's controlled API, then subsequent requests bind via the
    // sandbox's network namespace.
    let cooperative_outcome = match cooperative_outcome {
        CooperativeOutcome::NoToken => try_sandbox_binding(&state, &request, &target, body_for_srr),
        other => other,
    };

    // Lift the lease's claim_id (if any was taken) BEFORE the match
    // below moves `cooperative_outcome`. Each EnforcementDecision arm
    // pairs this with `confirm()` (success / Deny + WAL ok) or
    // `release()` (WAL failure) — same lifecycle the existing
    // `shadow_claim` follows. Without this, every cooperative claim
    // sits in `Claimed` state until `CLAIM_TIMEOUT` (10s) elapses
    // and is then released back to `Active`, defeating the
    // single-use invariant the Phase 2 / 3a / 3b tests pin (those
    // tests all complete inside 10s, so they miss the regression).
    let cooperative_claim_id: Option<u64> = cooperative_outcome.claim_id();

    // ── Step 2: Classify (IC determination) via SRR + cooperative fold-in ──
    //
    // Each Cooperative* arm picks its body source (observed vs declared)
    // and tags the classification with the matching evidence label. We
    // inline the SRR-call block per arm rather than a helper closure
    // because the closure form pulls the std::sync::RwLockReadGuard
    // into the captured set, breaking the Handler's Send bound.
    let (classification, is_default_caution) = match cooperative_outcome {
        CooperativeOutcome::CrossChecked { meta, pinned } => {
            let srr_result = {
                let srr = match state.srr.read() {
                    Ok(g) => g,
                    Err(_) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal governance error — request denied (fail-close)",
                        );
                    }
                };
                let principal: Option<&str> = verified_identity
                    .as_ref()
                    .map(|v| v.agent_id.as_str())
                    .or_else(|| gvm_headers.as_ref().map(|h| h.agent_id.as_str()));
                srr.check_with_principal(
                    request.method().as_str(),
                    &target.host,
                    &target.path,
                    body_for_srr,
                    principal,
                )
            };
            let operation = gvm_headers
                .as_ref()
                .map(|headers| build_operation_metadata(headers, &target));
            (
                Classification {
                    decision: srr_result.decision,
                    source: ClassificationSource::CooperativeCrossChecked,
                    operation,
                    matched_rule_id: srr_result.matched_description,
                    pinned,
                    cooperative: Some(meta),
                },
                srr_result.is_catch_all,
            )
        }
        CooperativeOutcome::DeclaredOnly {
            meta,
            declared_body,
            pinned,
        } => {
            let srr_result = {
                let srr = match state.srr.read() {
                    Ok(g) => g,
                    Err(_) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal governance error — request denied (fail-close)",
                        );
                    }
                };
                let principal: Option<&str> = verified_identity
                    .as_ref()
                    .map(|v| v.agent_id.as_str())
                    .or_else(|| gvm_headers.as_ref().map(|h| h.agent_id.as_str()));
                srr.check_with_principal(
                    request.method().as_str(),
                    &target.host,
                    &target.path,
                    Some(&declared_body),
                    principal,
                )
            };
            let operation = gvm_headers
                .as_ref()
                .map(|headers| build_operation_metadata(headers, &target));
            (
                Classification {
                    decision: srr_result.decision,
                    source: ClassificationSource::CooperativeDeclaredOnly,
                    operation,
                    matched_rule_id: srr_result.matched_description,
                    pinned,
                    cooperative: Some(meta),
                },
                srr_result.is_catch_all,
            )
        }
        CooperativeOutcome::Mismatch { meta, reason } => (
            Classification {
                decision: gvm_types::EnforcementDecision::Deny { reason },
                source: ClassificationSource::CooperativeMismatch,
                operation: gvm_headers
                    .as_ref()
                    .map(|headers| build_operation_metadata(headers, &target)),
                matched_rule_id: Some("cooperative.mismatch".to_string()),
                pinned: false,
                cooperative: Some(meta),
            },
            false,
        ),
        CooperativeOutcome::Expired { meta, reason } => (
            Classification {
                decision: gvm_types::EnforcementDecision::Deny { reason },
                source: ClassificationSource::CooperativeExpired,
                operation: gvm_headers
                    .as_ref()
                    .map(|headers| build_operation_metadata(headers, &target)),
                matched_rule_id: Some("cooperative.expired".to_string()),
                pinned: false,
                cooperative: Some(meta),
            },
            false,
        ),
        CooperativeOutcome::Unbound { reason } => (
            Classification {
                decision: gvm_types::EnforcementDecision::Deny { reason },
                source: ClassificationSource::CooperativeUnbound,
                operation: gvm_headers
                    .as_ref()
                    .map(|headers| build_operation_metadata(headers, &target)),
                matched_rule_id: Some("cooperative.unbound".to_string()),
                pinned: false,
                cooperative: None,
            },
            false,
        ),
        CooperativeOutcome::NoToken => {
            let srr_result = {
                let srr = match state.srr.read() {
                    Ok(g) => g,
                    Err(_) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal governance error — request denied (fail-close)",
                        );
                    }
                };
                let principal: Option<&str> = verified_identity
                    .as_ref()
                    .map(|v| v.agent_id.as_str())
                    .or_else(|| gvm_headers.as_ref().map(|h| h.agent_id.as_str()));
                srr.check_with_principal(
                    request.method().as_str(),
                    &target.host,
                    &target.path,
                    body_for_srr,
                    principal,
                )
            };
            let operation = gvm_headers
                .as_ref()
                .map(|headers| build_operation_metadata(headers, &target));
            (
                Classification {
                    decision: srr_result.decision,
                    source: ClassificationSource::SRR,
                    operation,
                    matched_rule_id: srr_result.matched_description,
                    pinned: false,
                    cooperative: None,
                },
                srr_result.is_catch_all,
            )
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
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.release(cid);
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
                        decision_source: None,
                    },
                );
            }
            _ => {
                // IC-1 (Allow, AuditOnly) — proceed despite WAL issues
            }
        }
    }

    // ── Step 4: Enforcement with EventStatus lifecycle ──
    let mut event = build_event(
        &classification,
        &gvm_headers,
        &target,
        verified_identity.as_ref().map(|id| id.token_id.clone()),
    );
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
                        decision_source: None,
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
                        decision_source: None,
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
            if let Some(cid) = cooperative_claim_id {
                state.intent_store.confirm(cid);
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
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.release(cid);
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
                        decision_source: None,
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
            if let Some(cid) = cooperative_claim_id {
                state.intent_store.confirm(cid);
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
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.release(cid);
                }
            } else {
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.confirm(claim.claim_id);
                }
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.confirm(cid);
                }
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
                        decision_source: Some(classification.source.into()),
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
                        decision_source: Some(classification.source.into()),
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
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.release(cid);
                }
            } else {
                if let Some(ref claim) = shadow_claim {
                    state.intent_store.confirm(claim.claim_id);
                }
                // Confirm (= delete) the cooperative lease even on
                // Deny. A consumed lease is consumed regardless of
                // outcome: a Mismatch / Expired Deny must not leave
                // the lease alive for a second attempt with the same
                // token after `CLAIM_TIMEOUT`. This is the load-
                // bearing single-use invariant.
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.confirm(cid);
                }
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
                    decision_source: Some(classification.source.into()),
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
                if let Some(cid) = cooperative_claim_id {
                    state.intent_store.release(cid);
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
            if let Some(cid) = cooperative_claim_id {
                state.intent_store.confirm(cid);
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

// ─── Cooperative intent lease helpers (Tier-3 P3-c Phase 2) ───────────────
//
// Pure functions / a thin enum that wrap the cooperative-lease claim
// path so `proxy_handler` stays readable. The logic lives here rather
// than as private impls on `AppState` because all of the state we
// touch is borrowed from `AppState` for the duration of the claim and
// nothing here needs to outlive the request.

/// Outcome of the cooperative-lease pre-check at the start of
/// `proxy_handler`. The variants correspond 1:1 to the
/// `ClassificationSource::Cooperative*` cases plus a "no token
/// presented" pass-through for the standard SRR path.
enum CooperativeOutcome {
    /// No `X-GVM-Context-Token` header — proceed with the standard
    /// network-observed enforcement path. No claim taken; no
    /// confirm/release work for the caller.
    NoToken,
    /// Token claimed AND observed body matched the declared
    /// `payload_hash`. Run SRR on the observed body; tag the
    /// classification as cross-checked. `pinned` is true when the
    /// lease was accepted under `allow_pinned_lease` despite an
    /// epoch mismatch. `claim_id` MUST be passed to
    /// `intent_store.confirm()` after a successful WAL write, or
    /// `release()` on WAL failure — otherwise the lease sits in
    /// `Claimed` until `CLAIM_TIMEOUT` and is then released back
    /// to `Active`, defeating single-use.
    CrossChecked {
        meta: gvm_types::CooperativeMeta,
        pinned: bool,
    },
    /// Token claimed but no observed body (MITM-blind, no payload
    /// inspection enabled, or oversized buffer). Run SRR on the
    /// declared `payload_context` instead. Same `meta` lifecycle
    /// rule as `CrossChecked`.
    DeclaredOnly {
        meta: gvm_types::CooperativeMeta,
        declared_body: Bytes,
        pinned: bool,
    },
    /// Token claimed but observed body's hash did NOT match the
    /// declared `payload_hash`. Always Deny. `meta.claim_id` MUST
    /// still be confirmed (= deleted) so the bad lease cannot be
    /// re-used after CLAIM_TIMEOUT — a bad claim is still a claim.
    Mismatch {
        meta: gvm_types::CooperativeMeta,
        reason: String,
    },
    /// Token claimed but the lease's `policy_epoch` differs from
    /// the current integrity ref (the proxy reloaded since the
    /// lease was issued) and the lease did NOT opt in via
    /// `allow_pinned_lease`. Always Deny. Same `meta` lifecycle
    /// rule as `Mismatch`.
    Expired {
        meta: gvm_types::CooperativeMeta,
        reason: String,
    },
    /// Token presented but no matching active lease found in the
    /// store. Re-use, forgery, or replay. No claim was taken
    /// (lookup returned None), so no confirm/release work.
    Unbound { reason: String },
}

impl CooperativeOutcome {
    /// Extract the lease's `claim_id` when one was taken. Returns
    /// `None` for `NoToken` (no lookup) and `Unbound` (lookup
    /// returned None). For every other variant the caller MUST
    /// pair this with `confirm()` (on Allow/Delay/Deny success) or
    /// `release()` (on WAL failure) — see the variant docs.
    fn claim_id(&self) -> Option<u64> {
        self.meta().map(|m| m.claim_id)
    }

    /// H6 audit metadata. Returns `None` for `NoToken` / `Unbound`.
    /// The proxy hot path threads this into
    /// `Classification.cooperative` so `build_event` writes
    /// `cooperative.intent_id` / `payload_context_hash` /
    /// `observed_payload_hash` into the WAL event context — the
    /// link-back fields a forensic auditor needs to connect this
    /// decision to the earlier `gvm.intent.lease_issued` event.
    fn meta(&self) -> Option<&gvm_types::CooperativeMeta> {
        match self {
            CooperativeOutcome::CrossChecked { meta, .. }
            | CooperativeOutcome::DeclaredOnly { meta, .. }
            | CooperativeOutcome::Mismatch { meta, .. }
            | CooperativeOutcome::Expired { meta, .. } => Some(meta),
            CooperativeOutcome::NoToken | CooperativeOutcome::Unbound { .. } => None,
        }
    }
}

/// Pull `X-GVM-Context-Token` off the request, hash it, claim the
/// matching lease, and decide what classification the proxy hot path
/// should use. The caller MUST remove the header before forwarding —
/// this function reads but does not strip (separation of concerns;
/// the test surface here is the decision, not the header mutation).
///
/// `observed_body` is the buffered request body, when payload
/// inspection is enabled and the body is small enough to materialise.
/// `None` means MITM-blind / inspection disabled / oversize. Present
/// alongside the lease's `payload_hash` enables the
/// `cooperative.cross_checked` evidence tier (Phase 3a).
fn extract_and_claim_lease(
    state: &AppState,
    request: &mut axum::http::Request<axum::body::Body>,
    target: &Target,
    observed_body: Option<&[u8]>,
    request_principal: Option<&str>,
) -> CooperativeOutcome {
    use sha2::{Digest, Sha256};

    let Some(token_val) = request.headers().get("x-gvm-context-token") else {
        return CooperativeOutcome::NoToken;
    };
    let Ok(token_str) = token_val.to_str() else {
        return CooperativeOutcome::Unbound {
            reason: "X-GVM-Context-Token contains non-ASCII bytes".to_string(),
        };
    };

    // Hash the on-wire token (including the `ctx_` prefix). The store
    // hashes the same bytes at register time, so equality after SHA-256
    // is the binding check.
    let mut hasher = Sha256::new();
    hasher.update(token_str.as_bytes());
    let token_hash: [u8; 32] = hasher.finalize().into();

    // Step 1: lookup. Atomically transitions the lease to Claimed if
    // found and Active; returns None for expired / unknown / already
    // claimed (the latter losing a concurrent race).
    let Some(claim) = state.intent_store.claim_by_token_hash(&token_hash) else {
        return CooperativeOutcome::Unbound {
            reason: "context token does not bind to any active lease (re-use, forgery, or replay)"
                .to_string(),
        };
    };

    // Step 2: confirm the request shape matches what the agent declared.
    // The proxy already canonicalised the method; the lease stored the
    // declared form. Mismatch here is the classic "agent declared X,
    // sent Y" lie.
    let request_method = request.method().as_str();
    if !request_method.eq_ignore_ascii_case(&claim.method) {
        return CooperativeOutcome::Mismatch {
            meta: claim.to_audit_meta(None),
            reason: format!(
                "method mismatch: declared {}, observed {}",
                claim.method, request_method
            ),
        };
    }
    if !target.host.eq_ignore_ascii_case(&claim.host) {
        return CooperativeOutcome::Mismatch {
            meta: claim.to_audit_meta(None),
            reason: format!(
                "host mismatch: declared {}, observed {}",
                claim.host, target.host
            ),
        };
    }
    if !target.path.starts_with(&claim.path_prefix) {
        return CooperativeOutcome::Mismatch {
            meta: claim.to_audit_meta(None),
            reason: format!(
                "path mismatch: declared prefix {}, observed {}",
                claim.path_prefix, target.path
            ),
        };
    }

    // Step 2.5: principal binding (H8 from the regulated-target
    // review). The lease was issued under `claim.agent_id`. If the
    // request's effective principal (JWT subject > GVM-Agent-Id
    // header) disagrees, this is the "agent A steals agent B's
    // token" attack. Reject. We only enforce this when the request
    // carries SOME principal — anonymous traffic doesn't get a
    // free pass to consume someone else's lease, but agent-facing
    // deployments that haven't wired JWT yet would otherwise see
    // every request fail. The principal-less case is treated like
    // a method/host/path-only match (legacy behaviour).
    if let Some(req_principal) = request_principal {
        if req_principal != claim.agent_id {
            return CooperativeOutcome::Mismatch {
                meta: claim.to_audit_meta(None),
                reason: format!(
                    "principal mismatch: lease issued for {}, request principal is {}",
                    claim.agent_id, req_principal
                ),
            };
        }
    }

    // Step 3: policy epoch check via the shared helper (single
    // source of truth for the strict-vs-`allow_pinned_lease` rule).
    let current_epoch = state.current_integrity_ref().unwrap_or_default();
    let pinned = match claim.check_policy_epoch(&current_epoch) {
        crate::intent_store::LeaseEpochCheck::Match => false,
        crate::intent_store::LeaseEpochCheck::PinnedAcrossReload => {
            tracing::info!(
                intent_id = claim.intent_id,
                "Cooperative lease pinned across policy reload (allow_pinned_lease)"
            );
            true
        }
        crate::intent_store::LeaseEpochCheck::Stale => {
            return CooperativeOutcome::Expired {
                meta: claim.to_audit_meta(None),
                reason: "policy reloaded since lease was issued (epoch mismatch); \
                         set allow_pinned_lease=true at issuance to tolerate"
                    .to_string(),
            };
        }
    };

    // Step 4: optional body cross-check. Phase 3a wires the observed
    // body in from the proxy hot path. Two inputs:
    //   - `payload_hash` on the lease (operator-supplied at register
    //     time, optional)
    //   - `observed_body`, if the proxy buffered one (controlled by
    //     `state.payload_inspection`)
    // Both present and matching → CrossChecked. Lease provides hash
    // but observed body unavailable → DeclaredOnly (unless H5
    // `requires_observed_body` was set, then Mismatch Deny). Lease
    // has neither → DeclaredOnly. Hash provided but observed
    // mismatches → Mismatch.
    let observed_body_hash: Option<[u8; 32]> = observed_body.map(|bytes| {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    });
    if let (Some(declared_hash), Some(observed_hash)) = (claim.payload_hash, observed_body_hash) {
        if declared_hash != observed_hash {
            return CooperativeOutcome::Mismatch {
                meta: claim.to_audit_meta(Some(observed_hash)),
                reason: "observed body hash does not match declared payload_hash".to_string(),
            };
        }
        return CooperativeOutcome::CrossChecked {
            meta: claim.to_audit_meta(Some(observed_hash)),
            pinned,
        };
    }

    // H5 strict path: lease declared `payload_hash` AND opted in to
    // `requires_observed_body`, but the proxy couldn't observe the
    // body (chunked encoding without Content-Length, oversized
    // buffer, MITM-blind path, or payload_inspection disabled).
    if claim.requires_observed_body && claim.payload_hash.is_some() && observed_body_hash.is_none()
    {
        return CooperativeOutcome::Mismatch {
            meta: claim.to_audit_meta(None),
            reason: "lease required observed-body cross-check but the proxy could not buffer \
                     the request body (chunked / streaming / oversized / inspection disabled)"
                .to_string(),
        };
    }

    // Step 5: declared-only path. Serialize the projected
    // payload_context as canonical JSON bytes so SRR's payload-rule
    // matcher sees the same shape it would have seen on the wire if
    // the proxy could observe the body.
    let declared_body = match claim
        .payload_context
        .as_ref()
        .and_then(|v| serde_json::to_vec(v).ok())
    {
        Some(b) => Bytes::from(b),
        None => Bytes::new(),
    };
    CooperativeOutcome::DeclaredOnly {
        meta: claim.to_audit_meta(None),
        declared_body,
        pinned,
    }
}

/// Tier-3 P3-c Phase 3c: attempt to bind the request to a
/// cooperative lease by sandbox-IP identity. Called when the
/// HTTP path's `extract_and_claim_lease` returned `NoToken`
/// (no `X-GVM-Context-Token` header). Resolves the peer IP to a
/// sandbox-allocated `agent_id` via `state.resolve_sandbox_anchor`,
/// then looks for an Active cooperative lease matching the
/// request's method / host / path.
///
/// Returns the same `CooperativeOutcome` shape as the token path
/// so downstream classification arms do not branch on the binding
/// channel — only on the evidence tier. Returns
/// `CooperativeOutcome::NoToken` when there is nothing to bind
/// (no peer IP, loopback, no matching lease).
///
/// On Allow paths this is purely additive: a request that would
/// have classified as plain `srr.network_observed` now classifies
/// as `cooperative.cross_checked` or `cooperative.declared_only`,
/// depending on whether body inspection is enabled and a
/// `payload_hash` was declared. On Deny paths nothing changes —
/// the lease evidence cannot override an SRR Deny.
fn try_sandbox_binding(
    state: &AppState,
    request: &axum::http::Request<axum::body::Body>,
    target: &Target,
    observed_body: Option<&[u8]>,
) -> CooperativeOutcome {
    use sha2::{Digest, Sha256};

    let peer_ip = request.extensions().get::<std::net::IpAddr>().copied();
    let Some((agent_id, _launch_id)) = state.resolve_sandbox_anchor(peer_ip) else {
        return CooperativeOutcome::NoToken;
    };

    let Some(claim) = state.intent_store.claim_by_sandbox_binding(
        &agent_id,
        request.method().as_str(),
        &target.host,
        &target.path,
    ) else {
        return CooperativeOutcome::NoToken;
    };

    // Policy epoch check via the shared helper — same rule as the
    // token path, different reason wording for the audit log.
    let current_epoch = state.current_integrity_ref().unwrap_or_default();
    let pinned = match claim.check_policy_epoch(&current_epoch) {
        crate::intent_store::LeaseEpochCheck::Match => false,
        crate::intent_store::LeaseEpochCheck::PinnedAcrossReload => {
            tracing::info!(
                intent_id = claim.intent_id,
                "Sandbox-bound lease pinned across policy reload (allow_pinned_lease)"
            );
            true
        }
        crate::intent_store::LeaseEpochCheck::Stale => {
            return CooperativeOutcome::Expired {
                meta: claim.to_audit_meta(None),
                reason: "policy reloaded since sandbox-bound lease was issued (epoch mismatch); \
                         set allow_pinned_lease=true at issuance to tolerate"
                    .to_string(),
            };
        }
    };

    // Body cross-check, identical to the token path.
    let observed_body_hash: Option<[u8; 32]> = observed_body.map(|bytes| {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    });
    if let (Some(declared_hash), Some(observed_hash)) = (claim.payload_hash, observed_body_hash) {
        if declared_hash != observed_hash {
            return CooperativeOutcome::Mismatch {
                meta: claim.to_audit_meta(Some(observed_hash)),
                reason: "observed body hash does not match declared payload_hash \
                         (sandbox-bound lease)"
                    .to_string(),
            };
        }
        return CooperativeOutcome::CrossChecked {
            meta: claim.to_audit_meta(Some(observed_hash)),
            pinned,
        };
    }

    // H5 strict path on sandbox-binding: same rule as the token
    // path. Lease asked for body cross-check; proxy can't observe.
    if claim.requires_observed_body && claim.payload_hash.is_some() && observed_body_hash.is_none()
    {
        return CooperativeOutcome::Mismatch {
            meta: claim.to_audit_meta(None),
            reason: "lease required observed-body cross-check but the proxy could not buffer \
                     the request body (sandbox-bound)"
                .to_string(),
        };
    }

    let declared_body = match claim
        .payload_context
        .as_ref()
        .and_then(|v| serde_json::to_vec(v).ok())
    {
        Some(b) => Bytes::from(b),
        None => Bytes::new(),
    };
    CooperativeOutcome::DeclaredOnly {
        meta: claim.to_audit_meta(None),
        declared_body,
        pinned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use std::time::{Duration, Instant};

    async fn make_test_ledger() -> (Arc<Ledger>, std::path::PathBuf) {
        let wal_path =
            std::env::temp_dir().join(format!("gvm-proxy-test-{}.wal", uuid::Uuid::new_v4()));
        let ledger = Ledger::new(&wal_path)
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
            token_id: None,
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
