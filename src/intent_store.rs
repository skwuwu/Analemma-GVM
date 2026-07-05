//! Shadow Mode Intent Store — 2-Phase Transactional Lifecycle
//!
//! Intent lifecycle:
//!   Active → Claimed → Consumed (deleted)
//!                ↓
//!           Released → Active (restored)
//!
//! Invariant: Intent deletion occurs ONLY on confirm().
//! Claimed intents that timeout are released (returned to Active), never deleted.
//!
//! Architecture:
//!   MCP gvm_declare_intent → POST /gvm/intent → IntentStore::register()
//!   Proxy request:
//!     1. claim()    — mark intent as Claimed (not deleted)
//!     2. WAL write
//!     3a. confirm() — WAL succeeded → delete intent
//!     3b. release() — WAL failed → restore to Active
//!
//! This ensures: no decision without audit, no audit without decision.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Shadow verification mode — controls what happens to unverified requests.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShadowMode {
    /// Unverified requests are denied (production recommended).
    Strict,
    /// Unverified requests are delayed + audit logged.
    Cautious,
    /// Unverified requests are allowed + audit warning (onboarding).
    Permissive,
    /// Shadow verification disabled — proxy behaves as before.
    #[default]
    Disabled,
}

impl ShadowMode {
    /// Parse from environment variable (used by proxy startup).
    pub fn from_env() -> Option<Self> {
        match std::env::var("GVM_SHADOW_MODE")
            .ok()?
            .to_lowercase()
            .as_str()
        {
            "strict" => Some(ShadowMode::Strict),
            "cautious" => Some(ShadowMode::Cautious),
            "permissive" => Some(ShadowMode::Permissive),
            "disabled" => Some(ShadowMode::Disabled),
            _ => None,
        }
    }
}

/// Shadow mode configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowConfig {
    #[serde(default)]
    pub mode: ShadowMode,
    #[serde(default = "default_intent_ttl_secs")]
    pub intent_ttl_secs: u64,
    #[serde(default = "default_cautious_delay_ms")]
    pub cautious_delay_ms: u64,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            mode: ShadowMode::Disabled,
            intent_ttl_secs: 30,
            cautious_delay_ms: 5000,
        }
    }
}

fn default_intent_ttl_secs() -> u64 {
    30
}
fn default_cautious_delay_ms() -> u64 {
    5000
}

// ── Intent State Machine ─────────────────────────────────────────────────────

/// Intent lifecycle state.
#[derive(Debug, Clone)]
enum IntentState {
    /// Ready to be claimed by a request.
    Active,
    /// Claimed by a request, pending WAL write.
    /// Contains the claim_id for confirm/release matching.
    Claimed { claim_id: u64, at: Instant },
}

/// A declared intent with TTL and lifecycle state.
#[derive(Debug, Clone)]
struct Intent {
    intent_id: u64,
    method: String,
    host: String,
    path_prefix: String,
    operation: String,
    agent_id: String,
    created_at: Instant,
    ttl: Duration,
    state: IntentState,

    // ── Cooperative lease fields (Tier-3 P3-c Phase 1) ──
    //
    // None for legacy URL-only declarations (no token issued).
    // Some for body-aware declarations: the lease carries the
    // hashed context token, the projected payload context, and
    // the policy epoch active at issuance. Phase 2 (claim path)
    // uses these for cross-check; Phase 1 only writes them.
    /// SHA-256 of the raw bearer token bytes. The token original
    /// is returned to the caller exactly once and never stored or
    /// logged. Compare against this on claim by hashing the
    /// presented token. None = legacy intent without a token.
    context_token_hash: Option<[u8; 32]>,
    /// Projected payload context (operator-supplied, NOT raw body).
    /// Phase 2 uses this for cross-check against the observed body.
    payload_context: Option<serde_json::Value>,
    /// SHA-256 of the canonical JSON of `payload_context`. Always
    /// present when `payload_context` is — pre-computed at
    /// register time so Phase 2 doesn't re-serialize on hot path.
    payload_context_hash: Option<[u8; 32]>,
    /// Optional SHA-256 of the actual body the agent declared it
    /// will send (forward-compat for Phase 2 strict cross-check).
    /// Format on the wire: `"sha256:<hex>"`. Stored as bytes here.
    payload_hash: Option<[u8; 32]>,
    /// Policy epoch (config integrity context hash) at issuance.
    /// Phase 2 compares with the current epoch on claim; mismatch
    /// → `CooperativeExpired` Deny unless `allow_pinned_lease`
    /// is set. Encoded as the same hex string the WAL already
    /// uses for `config_integrity_ref`.
    policy_epoch: Option<String>,
    /// Phase 3 opt-in: when true, the claim path accepts an
    /// epoch mismatch and tags the decision as pinned in the
    /// audit record rather than denying. Default false.
    allow_pinned_lease: bool,
    /// H5 opt-in: when true AND `payload_hash` is set, the claim
    /// path Denies (`cooperative.mismatch`) if the proxy could
    /// not observe the body to cross-check. Default false.
    requires_observed_body: bool,
}

impl Intent {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    fn is_active(&self) -> bool {
        matches!(self.state, IntentState::Active) && !self.is_expired()
    }

    fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        self.is_active()
            && self.method.eq_ignore_ascii_case(method)
            && self.host.eq_ignore_ascii_case(host)
            && path.starts_with(&self.path_prefix)
    }

    /// Project the internal `Intent` into the public `LeaseClaim`
    /// snapshot returned by every `claim_by_*` method. The 12-field
    /// copy was repeated verbatim in three places (`claim_by_token_hash`,
    /// `claim_by_sandbox_binding`, `claim_by_sandbox_binding_host`);
    /// keeping it in one helper makes adding a new lease field a
    /// single-line edit instead of three.
    fn to_lease_claim(&self, claim_id: u64) -> LeaseClaim {
        LeaseClaim {
            claim_id,
            intent_id: self.intent_id,
            method: self.method.clone(),
            host: self.host.clone(),
            path_prefix: self.path_prefix.clone(),
            agent_id: self.agent_id.clone(),
            operation: self.operation.clone(),
            payload_context: self.payload_context.clone(),
            payload_context_hash: self.payload_context_hash,
            payload_hash: self.payload_hash,
            policy_epoch: self.policy_epoch.clone(),
            allow_pinned_lease: self.allow_pinned_lease,
            requires_observed_body: self.requires_observed_body,
        }
    }
}

/// Lookup index key: (METHOD, host, path_prefix)
type IndexKey = (String, String, String);

fn make_key(method: &str, host: &str, path: &str) -> IndexKey {
    (method.to_uppercase(), host.to_lowercase(), path.to_string())
}

/// Single Mutex guards both intents and index (no lock ordering issues).
struct StoreInner {
    intents: HashMap<u64, Intent>,
    index: HashMap<IndexKey, Vec<u64>>,
    /// Last time `cleanup_inner` ran a full sweep. Used to amortize
    /// the O(N) sweep across many claims — a Claim on a hot store
    /// checks this timestamp and skips the sweep unless it's been
    /// > CLEANUP_MIN_INTERVAL since the last one OR the store is
    /// past half its cap. See `cleanup_inner`.
    last_cleanup: Instant,
}

/// Minimum time between full sweeps. Chosen as 100 ms: shorter
/// than CLAIM_TIMEOUT (10 s) by two orders of magnitude, so timed-out
/// Claims still get released within one CLAIM_TIMEOUT window; longer
/// than any single request's proxy hot path, so a happy-path claim
/// almost never triggers a sweep on a warm store.
const CLEANUP_MIN_INTERVAL: Duration = Duration::from_millis(100);

// ── Public Types ─────────────────────────────────────────────────────────────

/// Result of intent claim (Phase 1).
#[derive(Debug, Clone, Serialize)]
pub struct ClaimResult {
    pub verified: bool,
    /// Unique claim ID — use for confirm() or release(). Distinct from intent_id.
    pub claim_id: u64,
    pub operation: Option<String>,
    pub agent_id: Option<String>,
}

/// Result of intent verification (legacy API, wraps claim).
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub operation: Option<String>,
    pub agent_id: Option<String>,
}

/// Snapshot returned by [`IntentStore::claim_by_token_hash`].
///
/// Contains everything the proxy hot path needs to run cross-check
/// without re-acquiring the store lock. Fields mirror the lease as
/// stored (raw `payload_context` is included so the hot path can
/// feed it to SRR when MITM body is unavailable).
#[derive(Debug, Clone)]
pub struct LeaseClaim {
    pub claim_id: u64,
    pub intent_id: u64,
    pub method: String,
    pub host: String,
    pub path_prefix: String,
    pub agent_id: String,
    pub operation: String,
    pub payload_context: Option<serde_json::Value>,
    pub payload_context_hash: Option<[u8; 32]>,
    pub payload_hash: Option<[u8; 32]>,
    pub policy_epoch: Option<String>,
    /// Phase 3 opt-in flag mirrored from the lease — when true,
    /// the claim path tolerates `policy_epoch` mismatch and tags
    /// the decision as pinned. The hot path reads this off the
    /// claim instead of re-locking the store.
    pub allow_pinned_lease: bool,
    /// H5 opt-in flag mirrored from the lease. When true AND
    /// `payload_hash` is set, the claim path Denies if the proxy
    /// could not observe the body to cross-check (declared-only
    /// is not acceptable for this lease).
    pub requires_observed_body: bool,
}

/// Outcome of [`LeaseClaim::check_policy_epoch`]. Three states are
/// possible at the boundary between an issued lease and the current
/// proxy config: the epoch matches (`Match`); the epoch differs but
/// the lease opted in to outliving config reloads (`PinnedAcrossReload`);
/// or the epoch differs and the lease did not opt in (`Stale`). The
/// last is fatal — the caller MUST Deny with `cooperative.expired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseEpochCheck {
    /// `policy_epoch` matches the current `active_integrity_ref`,
    /// or the lease was issued without an epoch (legacy / startup).
    Match,
    /// Epoch differs and `allow_pinned_lease=true` — proceed but
    /// tag the audit event so the stale-epoch enforcement is
    /// reconstructible from the WAL.
    PinnedAcrossReload,
    /// Epoch differs and the lease did NOT opt in. Caller must Deny.
    Stale,
}

impl LeaseClaim {
    /// H6: build the audit metadata snapshot the proxy hot path
    /// will carry from `extract_and_claim_lease` through to
    /// `build_event`. `observed_payload_hash` is set only on the
    /// `CrossChecked` path where the proxy actually buffered and
    /// hashed the body — for `DeclaredOnly` / `Mismatch` / `Expired`
    /// it's `None` and the audit chain shows "no observation".
    pub fn to_audit_meta(
        &self,
        observed_payload_hash: Option<[u8; 32]>,
    ) -> gvm_types::CooperativeMeta {
        gvm_types::CooperativeMeta {
            intent_id: self.intent_id,
            claim_id: self.claim_id,
            payload_context_hash: self.payload_context_hash,
            observed_payload_hash,
        }
    }

    /// Compare the lease's `policy_epoch` against the proxy's current
    /// integrity ref, honoring the lease's `allow_pinned_lease`
    /// opt-in. Single source of truth for the epoch-check logic that
    /// previously lived in four near-identical copies across
    /// `proxy/mod.rs` (`extract_and_claim_lease`,
    /// `try_sandbox_binding`) and `proxy/connect.rs` (`claim_connect_lease`,
    /// CONNECT sandbox-binding fallback). The caller emits the
    /// "Expired" `reason` string with context-appropriate wording.
    pub fn check_policy_epoch(&self, current_epoch: &str) -> LeaseEpochCheck {
        match &self.policy_epoch {
            Some(issued) if !issued.is_empty() && issued != current_epoch => {
                if self.allow_pinned_lease {
                    LeaseEpochCheck::PinnedAcrossReload
                } else {
                    LeaseEpochCheck::Stale
                }
            }
            _ => LeaseEpochCheck::Match,
        }
    }
}

/// Request body for POST /gvm/intent.
///
/// Tier-3 P3-c Phase 1 added three optional fields for the
/// "cooperative intent lease" extension: `payload_context`,
/// `payload_hash`, `content_type`. They turn the legacy URL-only
/// preflight into a body-aware preflight without changing the
/// endpoint's URL or breaking existing callers. See
/// [docs/cooperative-intent.md](../../docs/cooperative-intent.md)
/// for the full trust model and the Phase 2 / Phase 3 followups.
#[derive(Debug, Deserialize)]
pub struct IntentRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub operation: String,
    #[serde(default = "default_agent")]
    pub agent_id: String,
    pub ttl_secs: Option<u64>,

    /// Projected, policy-relevant fields of the body the agent
    /// intends to send. NOT the full body — operators are expected
    /// to project only what `payload_field` rules read (e.g.
    /// `{"channel": "C_INTERNAL", "case_id": "1842"}`), not the
    /// full Slack message. See cooperative-intent.md §"Payload
    /// privacy" for the rationale.
    ///
    /// Hard cap: `MAX_PAYLOAD_CONTEXT_BYTES` (16 KB) on the
    /// serialized canonical form. Larger contexts return 413 from
    /// the HTTP handler.
    #[serde(default)]
    pub payload_context: Option<serde_json::Value>,

    /// Optional SHA-256 hash of the actual body the agent will
    /// send. Used at Phase 2 claim time to cross-check the
    /// observed body when GVM CAN see it. Format:
    /// `"sha256:<lowercase-hex-64>"`. Validated at register time.
    #[serde(default)]
    pub payload_hash: Option<String>,

    /// Optional MIME type the agent declares for the body
    /// (`application/json`, `application/grpc+proto`, etc.).
    /// Used to pick the right canonical form during cross-check.
    #[serde(default)]
    pub content_type: Option<String>,

    /// Phase 3 opt-in: accept this lease even after the proxy has
    /// reloaded its config (policy epoch mismatch). Default is
    /// `false` (strict: epoch mismatch → `cooperative.expired`
    /// Deny). Operators set this when the orchestrator has
    /// independently approved the action and the TTL alone is the
    /// guard — e.g. a long-running batch where a mid-flight
    /// config refresh shouldn't invalidate in-flight approvals.
    /// When set, the claim path tags the source
    /// `cooperative.declared_only` (or `cross_checked` when the
    /// body matches) but ALSO writes a `pinned: true` flag the
    /// WAL preserves for audit.
    #[serde(default)]
    pub allow_pinned_lease: bool,

    /// H5 opt-in: require the proxy to actually OBSERVE the request
    /// body and confirm its SHA-256 matches `payload_hash`. When
    /// set AND `payload_hash` is declared, the claim path will
    /// `cooperative.mismatch` Deny if the proxy could not buffer
    /// the body (chunked / streaming / oversized / MITM-blind).
    /// Default `false` for back-compat: declared-only path is
    /// allowed when no observation is possible.
    ///
    /// Use case: high-assurance leases on visible-HTTP paths where
    /// the operator wants to guarantee cross-check happened, not
    /// trust the declared payload context alone. Without this
    /// flag, a malicious agent could declare a safe
    /// payload_context, send the request as chunked encoding to
    /// dodge the body buffer, and ride through on declared-only
    /// evidence.
    #[serde(default)]
    pub requires_observed_body: bool,
}

fn default_agent() -> String {
    "mcp-agent".to_string()
}

/// Hard cap on serialized canonical `payload_context` bytes.
/// 16 KB is small enough that an attacker can't OOM the proxy
/// with declarations but large enough to fit realistic projected
/// field bundles (channel + topic + 5 KB text excerpt + metadata).
pub const MAX_PAYLOAD_CONTEXT_BYTES: usize = 16 * 1024;

/// Length in bytes of the opaque context token's secret part
/// (32 bytes = 256-bit). Encoded URL-safe-base64 produces 43
/// characters. With the `ctx_` prefix the on-wire form is 47
/// characters — fits comfortably in any HTTP header.
pub const CONTEXT_TOKEN_SECRET_BYTES: usize = 32;

// ── Intent Store ─────────────────────────────────────────────────────────────

/// Hard cap on stored intents.
const MAX_INTENTS: usize = 10_000;
/// Claim timeout: 2x typical WAL fsync time (prevent orphaned claims).
const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

pub struct IntentStore {
    inner: Mutex<StoreInner>,
    default_ttl: Duration,
    next_intent_id: AtomicU64,
    next_claim_id: AtomicU64,
}

impl IntentStore {
    pub fn new(default_ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                intents: HashMap::new(),
                index: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            default_ttl: Duration::from_secs(default_ttl_secs),
            next_intent_id: AtomicU64::new(1),
            next_claim_id: AtomicU64::new(1_000_000), // Distinct namespace from intent_id
        }
    }

    /// Register a new intent (Active state).
    pub fn register(&self, req: &IntentRequest) -> Result<u64, String> {
        let mut store = self
            .inner
            .lock()
            .map_err(|_| "Intent store lock poisoned — fail-closed".to_string())?;

        // Cleanup: expired Active intents + timed-out Claims → release
        self.cleanup_inner(&mut store);

        if store.intents.len() >= MAX_INTENTS {
            return Err(format!(
                "Intent store full ({} intents). Wait for TTL expiration.",
                MAX_INTENTS
            ));
        }

        let ttl = req
            .ttl_secs
            .map(|s| Duration::from_secs(s.min(300)))
            .unwrap_or(self.default_ttl);

        let intent_id = self.next_intent_id.fetch_add(1, Ordering::Relaxed);
        let key = make_key(&req.method, &req.host, &req.path);

        let intent = Intent {
            intent_id,
            method: req.method.to_uppercase(),
            host: req.host.to_lowercase(),
            path_prefix: req.path.clone(),
            operation: req.operation.clone(),
            agent_id: req.agent_id.clone(),
            created_at: Instant::now(),
            ttl,
            state: IntentState::Active,
            // Legacy URL-only register: no cooperative lease.
            context_token_hash: None,
            payload_context: None,
            payload_context_hash: None,
            payload_hash: None,
            policy_epoch: None,
            allow_pinned_lease: false,
            requires_observed_body: false,
        };

        store.index.entry(key).or_default().push(intent_id);
        store.intents.insert(intent_id, intent);

        tracing::info!(
            intent_id,
            method = %req.method,
            host = %req.host,
            path = %req.path,
            operation = %req.operation,
            agent = %req.agent_id,
            ttl_secs = ttl.as_secs(),
            "Intent registered"
        );

        Ok(intent_id)
    }

    /// Tier-3 P3-c Phase 1: register a cooperative intent lease.
    ///
    /// Same intent shape as [`register`] PLUS the caller supplies
    /// the projected `payload_context`, its canonical hash, the
    /// optional `payload_hash` (actual body forward-commit), and
    /// the current `policy_epoch`. In return the store mints a
    /// fresh opaque bearer token. The token original is returned
    /// EXACTLY ONCE in this function's return value and never
    /// stored — internally only the SHA-256 of the token bytes is
    /// kept. Phase 2 verifies a presented token by hashing it and
    /// comparing.
    ///
    /// The on-wire token form is `ctx_<base64url-no-pad>` where
    /// the inner secret is `CONTEXT_TOKEN_SECRET_BYTES` (32) of
    /// cryptographically random bytes from the OS RNG. Token IDs
    /// are DELIBERATELY NOT derived from `intent_id` or
    /// `claim_id` — those are sequential and would be guessable.
    ///
    /// Returns `(intent_id, context_token, payload_context_hash_hex)`
    /// on success. The HTTP handler is responsible for emitting
    /// the `gvm.intent.lease_issued` WAL event with the chosen
    /// `DecisionSource::CooperativeDeclaredOnly` source (Phase 1
    /// is declared-only by definition; cross-check happens on
    /// claim in Phase 2).
    #[allow(clippy::too_many_arguments)]
    pub fn register_lease(
        &self,
        req: &IntentRequest,
        payload_context: serde_json::Value,
        payload_context_hash: [u8; 32],
        payload_hash: Option<[u8; 32]>,
        policy_epoch: String,
    ) -> Result<(u64, String, String), String> {
        use base64::Engine;
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let mut store = self
            .inner
            .lock()
            .map_err(|_| "Intent store lock poisoned — fail-closed".to_string())?;

        self.cleanup_inner(&mut store);

        if store.intents.len() >= MAX_INTENTS {
            return Err(format!(
                "Intent store full ({} intents). Wait for TTL expiration.",
                MAX_INTENTS
            ));
        }

        // Mint the opaque token: 32 bytes from the OS RNG,
        // base64url-no-pad encoded, prefixed with `ctx_` for
        // grep-ability in operator logs. We never serialise the
        // raw bytes anywhere else.
        let mut secret = [0u8; CONTEXT_TOKEN_SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let token_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let context_token = format!("ctx_{token_b64}");

        // Hash the on-wire token (with prefix) so a future claim
        // path hashes the same bytes the caller sees.
        let mut hasher = Sha256::new();
        hasher.update(context_token.as_bytes());
        let token_hash: [u8; 32] = hasher.finalize().into();

        let ttl = req
            .ttl_secs
            .map(|s| Duration::from_secs(s.min(300)))
            .unwrap_or(self.default_ttl);

        let intent_id = self.next_intent_id.fetch_add(1, Ordering::Relaxed);
        let key = make_key(&req.method, &req.host, &req.path);

        let intent = Intent {
            intent_id,
            method: req.method.to_uppercase(),
            host: req.host.to_lowercase(),
            path_prefix: req.path.clone(),
            operation: req.operation.clone(),
            agent_id: req.agent_id.clone(),
            created_at: Instant::now(),
            ttl,
            state: IntentState::Active,
            context_token_hash: Some(token_hash),
            payload_context: Some(payload_context),
            payload_context_hash: Some(payload_context_hash),
            payload_hash,
            policy_epoch: Some(policy_epoch),
            allow_pinned_lease: req.allow_pinned_lease,
            requires_observed_body: req.requires_observed_body,
        };

        store.index.entry(key).or_default().push(intent_id);
        store.intents.insert(intent_id, intent);

        // Zeroize the local copy of the secret bytes before
        // returning — the only surviving copies are the hashed
        // store entry and the string we hand back to the HTTP
        // handler (which writes it once into the response body and
        // drops it).
        secret.iter_mut().for_each(|b| *b = 0);

        let payload_context_hash_hex = hex::encode(payload_context_hash);

        tracing::info!(
            intent_id,
            method = %req.method,
            host = %req.host,
            path = %req.path,
            operation = %req.operation,
            agent = %req.agent_id,
            ttl_secs = ttl.as_secs(),
            payload_context_hash = %payload_context_hash_hex,
            "Cooperative intent lease registered"
        );

        Ok((intent_id, context_token, payload_context_hash_hex))
    }

    /// Phase 1: Claim an intent (mark as Claimed, do NOT delete).
    /// Returns ClaimResult with a unique claim_id for confirm/release.
    pub fn claim(
        &self,
        method: &str,
        host: &str,
        path: &str,
        request_agent_id: Option<&str>,
    ) -> ClaimResult {
        let mut store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => {
                tracing::error!("Intent store lock poisoned — fail-closed");
                return ClaimResult {
                    verified: false,
                    claim_id: 0,
                    operation: None,
                    agent_id: None,
                };
            }
        };

        // Search for matching Active intent (newest first by intent_id)
        let mut candidates: Vec<_> = store
            .intents
            .values()
            .filter(|i| {
                if !i.matches(method, host, path) {
                    return false;
                }
                if let Some(req_id) = request_agent_id {
                    if req_id != "unknown" && !i.agent_id.eq_ignore_ascii_case(req_id) {
                        tracing::warn!(
                            intent_agent = %i.agent_id,
                            request_agent = %req_id,
                            "Intent agent_id mismatch — possible spoofing"
                        );
                        return false;
                    }
                }
                true
            })
            .collect();
        candidates.sort_by_key(|b| std::cmp::Reverse(b.intent_id)); // newest first
        let matched = candidates.first().map(|i| i.intent_id);

        match matched {
            Some(intent_id) => {
                let claim_id = self.next_claim_id.fetch_add(1, Ordering::Relaxed);
                let intent = match store.intents.get_mut(&intent_id) {
                    Some(i) => i,
                    None => {
                        // Intent was removed between candidate search and claim — race lost
                        tracing::warn!(
                            intent_id,
                            "Intent disappeared during claim — returning unverified"
                        );
                        return ClaimResult {
                            verified: false,
                            claim_id: 0,
                            operation: None,
                            agent_id: None,
                        };
                    }
                };
                let operation = intent.operation.clone();
                let agent_id = intent.agent_id.clone();

                // Transition: Active → Claimed
                intent.state = IntentState::Claimed {
                    claim_id,
                    at: Instant::now(),
                };

                tracing::debug!(
                    intent_id,
                    claim_id,
                    method, host, path,
                    operation = %operation,
                    "Intent claimed (pending WAL)"
                );

                ClaimResult {
                    verified: true,
                    claim_id,
                    operation: Some(operation),
                    agent_id: Some(agent_id),
                }
            }
            None => {
                tracing::warn!(method, host, path, "No matching intent — UNVERIFIED");
                ClaimResult {
                    verified: false,
                    claim_id: 0,
                    operation: None,
                    agent_id: None,
                }
            }
        }
    }

    /// Tier-3 P3-c Phase 2: claim a cooperative lease by its bearer
    /// token hash.
    ///
    /// The caller (proxy hot path) has already extracted the
    /// `X-GVM-Context-Token` header, hashed it with the same
    /// SHA-256 the issuance side used, and passes the resulting 32
    /// bytes here. We look up the matching active lease, mark it
    /// `Claimed` (Phase 1 lifecycle still applies — confirm /
    /// release work the same way for cooperative leases as for
    /// legacy intents), and return the lease's decision-relevant
    /// snapshot so the hot path can:
    ///
    ///   1. Verify `method` / `host` / `path` match what the agent
    ///      declared (mismatch → `cooperative.mismatch` Deny).
    ///   2. Cross-check the observed body hash against
    ///      `payload_hash` if both are present.
    ///   3. Compare the lease's `policy_epoch` against the current
    ///      integrity ref (mismatch → `cooperative.expired` Deny
    ///      unless `allow_pinned_lease` is set).
    ///
    /// Outcome variants:
    ///   - `Some(LeaseClaim { .. })` — lease found and marked Claimed.
    ///   - `None` — lease not found, expired, or not in Active
    ///     state. The hot path treats this as
    ///     `CooperativeUnbound` and denies the request.
    ///
    /// Concurrency: two simultaneous claims on the same token
    /// resolve to exactly one `Some(_)` and one `None` — the second
    /// arrival sees the state already `Claimed` and falls into the
    /// `None` branch.
    pub fn claim_by_token_hash(&self, token_hash: &[u8; 32]) -> Option<LeaseClaim> {
        let mut store = self.inner.lock().ok()?;

        self.cleanup_inner(&mut store);

        // Find the lease whose token_hash matches AND is still
        // Active. A Claimed lease yields None (the concurrent
        // path lost the race).
        let intent_id = store
            .intents
            .values()
            .find(|i| {
                matches!(i.state, IntentState::Active)
                    && !i.is_expired()
                    && i.context_token_hash.as_ref() == Some(token_hash)
            })
            .map(|i| i.intent_id)?;

        let claim_id = self.next_claim_id.fetch_add(1, Ordering::Relaxed);
        let intent = store.intents.get_mut(&intent_id)?;

        let claim = intent.to_lease_claim(claim_id);
        intent.state = IntentState::Claimed {
            claim_id,
            at: Instant::now(),
        };

        tracing::debug!(
            intent_id,
            claim_id,
            "Cooperative lease claimed by token (pending WAL)"
        );

        Some(claim)
    }

    /// Tier-3 P3-c Phase 3c: claim a cooperative lease by network
    /// identity rather than by bearer token. Used when the proxy
    /// resolves the peer IP to a sandbox-allocated identity (via
    /// `resolve_sandbox_anchor`) and no `X-GVM-Context-Token`
    /// header is present — typically because the agent's client is
    /// cert-pinned or otherwise unable to set custom headers.
    ///
    /// **Trust model.** The veth IP carrying the request is
    /// allocated by GVM itself; spoofing it would require breaking
    /// the same network-namespace isolation that protects credential
    /// separation between sandboxes. So binding the lease via
    /// `agent_id` resolved from the source IP is no weaker than the
    /// rest of the sandbox model. The audit chain still records
    /// `cooperative.declared_only` (or `cooperative.cross_checked`
    /// when body inspection is enabled), exactly the same evidence
    /// tier as a token-bound claim — the binding channel changes,
    /// the trust tier does not.
    ///
    /// Match rule: the lease must be **cooperative** (its
    /// `context_token_hash` is `Some`), still `Active`, not
    /// expired, with `agent_id` and declared `method` / `host`
    /// matching exactly (the latter case-insensitively for hosts
    /// per DNS semantics), and `path` must start with the lease's
    /// `path_prefix`. Legacy URL-only intents (Shadow-Mode-only)
    /// are deliberately NOT eligible — those have their own
    /// claim path via [`claim`](IntentStore::claim).
    ///
    /// When multiple leases match, the most recently registered
    /// wins. This guards against a stale lease consuming the
    /// binding before a fresher one the agent actually intended
    /// (rare, but possible if an earlier lease's TTL has not
    /// elapsed). Ties on `created_at` resolve by highest
    /// `intent_id` (also recency-ordered).
    pub fn claim_by_sandbox_binding(
        &self,
        agent_id: &str,
        method: &str,
        host: &str,
        path: &str,
    ) -> Option<LeaseClaim> {
        let mut store = self.inner.lock().ok()?;

        self.cleanup_inner(&mut store);

        let intent_id = store
            .intents
            .values()
            .filter(|i| {
                matches!(i.state, IntentState::Active)
                    && !i.is_expired()
                    && i.context_token_hash.is_some() // cooperative only
                    && i.agent_id == agent_id
                    && i.method.eq_ignore_ascii_case(method)
                    && i.host.eq_ignore_ascii_case(host)
                    && path.starts_with(&i.path_prefix)
            })
            // Pick most recently registered to avoid stale stealing
            // the binding from a fresher lease the agent just minted.
            .max_by_key(|i| (i.created_at, i.intent_id))
            .map(|i| i.intent_id)?;

        let claim_id = self.next_claim_id.fetch_add(1, Ordering::Relaxed);
        let intent = store.intents.get_mut(&intent_id)?;

        let claim = intent.to_lease_claim(claim_id);
        intent.state = IntentState::Claimed {
            claim_id,
            at: Instant::now(),
        };

        tracing::debug!(
            intent_id,
            claim_id,
            agent_id,
            host,
            path,
            "Cooperative lease claimed by sandbox binding (pending WAL)"
        );

        Some(claim)
    }

    /// Phase 3c CONNECT-side variant of
    /// [`claim_by_sandbox_binding`]: bind by `(agent_id, host)`
    /// only, skipping method and path checks.
    ///
    /// CONNECT has no inner method or path visible to the proxy
    /// (those are encrypted inside the TLS tunnel that follows the
    /// 200), so the lease's declared method / path cannot be
    /// validated at CONNECT time. The token-based CONNECT path
    /// (`super::proxy::connect::claim_connect_lease`) has the same
    /// limitation. Like the HTTP variant this matches only
    /// cooperative leases (`context_token_hash.is_some()`); legacy
    /// URL-only intents are deliberately ineligible.
    pub fn claim_by_sandbox_binding_host(&self, agent_id: &str, host: &str) -> Option<LeaseClaim> {
        let mut store = self.inner.lock().ok()?;

        self.cleanup_inner(&mut store);

        let intent_id = store
            .intents
            .values()
            .filter(|i| {
                matches!(i.state, IntentState::Active)
                    && !i.is_expired()
                    && i.context_token_hash.is_some()
                    && i.agent_id == agent_id
                    && i.host.eq_ignore_ascii_case(host)
            })
            .max_by_key(|i| (i.created_at, i.intent_id))
            .map(|i| i.intent_id)?;

        let claim_id = self.next_claim_id.fetch_add(1, Ordering::Relaxed);
        let intent = store.intents.get_mut(&intent_id)?;

        let claim = intent.to_lease_claim(claim_id);
        intent.state = IntentState::Claimed {
            claim_id,
            at: Instant::now(),
        };

        tracing::debug!(
            intent_id,
            claim_id,
            agent_id,
            host,
            "Cooperative lease claimed by sandbox CONNECT binding (pending WAL)"
        );

        Some(claim)
    }

    /// Hard-remove an intent by its `intent_id`, regardless of
    /// `Active` / `Claimed` state. Used by issuance-rollback paths
    /// (e.g. `POST /gvm/intent` when the `gvm.intent.lease_issued`
    /// WAL append fails after `register_lease` already wrote the
    /// intent into the store).
    ///
    /// Why a separate method from [`confirm`]: `confirm(claim_id)`
    /// removes ONLY entries whose state is `Claimed { claim_id }`.
    /// A freshly-registered lease is in `Active` and has no claim_id
    /// yet, so `confirm(intent_id)` would silently do nothing,
    /// leaving the lease in the store. Sandbox-IP binding (Phase 3c)
    /// can then claim that ghost lease without the token ever
    /// reaching the agent — a `lease_issued` audit event was never
    /// durably recorded, but the lease is consumable. This method
    /// closes that hole.
    ///
    /// Returns `true` when an intent was actually removed, `false`
    /// when no intent with that `intent_id` was present (already
    /// confirmed / never inserted / lock poisoned).
    pub fn cancel_intent(&self, intent_id: u64) -> bool {
        let mut store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let Some(intent) = store.intents.remove(&intent_id) else {
            return false;
        };
        let key = make_key(&intent.method, &intent.host, &intent.path_prefix);
        if let Some(ids) = store.index.get_mut(&key) {
            ids.retain(|&i| i != intent_id);
            if ids.is_empty() {
                store.index.remove(&key);
            }
        }
        tracing::warn!(
            intent_id,
            "Intent cancelled (issuance rollback — no durable lease_issued audit record)"
        );
        true
    }

    /// Phase 2a: WAL write succeeded → delete the intent.
    /// This is the ONLY path that deletes an intent.
    pub fn confirm(&self, claim_id: u64) {
        let mut store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        let intent_id = store.intents.iter()
            .find(|(_, i)| matches!(i.state, IntentState::Claimed { claim_id: cid, .. } if cid == claim_id))
            .map(|(id, _)| *id);

        if let Some(id) = intent_id {
            let Some(intent) = store.intents.remove(&id) else {
                tracing::warn!(
                    claim_id,
                    "Intent already removed during confirm — idempotent"
                );
                return;
            };
            // Clean up index
            let key = make_key(&intent.method, &intent.host, &intent.path_prefix);
            if let Some(ids) = store.index.get_mut(&key) {
                ids.retain(|&i| i != id);
                if ids.is_empty() {
                    store.index.remove(&key);
                }
            }
            tracing::debug!(
                intent_id = id,
                claim_id,
                "Intent confirmed (WAL durable, deleted)"
            );
        }
    }

    /// Phase 2b: WAL write failed → restore intent to Active.
    /// Intent is NOT deleted — it can be claimed again on retry.
    pub fn release(&self, claim_id: u64) {
        let mut store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        for intent in store.intents.values_mut() {
            if let IntentState::Claimed { claim_id: cid, .. } = intent.state {
                if cid == claim_id {
                    intent.state = IntentState::Active;
                    tracing::warn!(
                        intent_id = intent.intent_id,
                        claim_id,
                        "Intent released (WAL failed, restored to Active)"
                    );
                    return;
                }
            }
        }
    }

    /// Legacy verify() — claims and immediately confirms (for non-transactional paths).
    pub fn verify(
        &self,
        method: &str,
        host: &str,
        path: &str,
        request_agent_id: Option<&str>,
    ) -> VerifyResult {
        let claim = self.claim(method, host, path, request_agent_id);
        if claim.verified {
            self.confirm(claim.claim_id);
        }
        VerifyResult {
            verified: claim.verified,
            operation: claim.operation,
            agent_id: claim.agent_id,
        }
    }

    /// Internal cleanup: remove expired Active intents, release timed-out Claims.
    fn cleanup_inner(&self, store: &mut StoreInner) {
        // Amortization gate: on a warm store, most claims come well
        // within CLEANUP_MIN_INTERVAL of each other, so the sweep is
        // pure overhead — nothing to reap. Skip unless (a) enough
        // time has passed OR (b) the store is > 50% of MAX_INTENTS,
        // which forces us to reap so `register` can't be starved.
        // Correctness is preserved because per-claim predicates
        // still call `is_expired()` and check `state` explicitly;
        // the sweep only reclaims memory for the store cap.
        if store.last_cleanup.elapsed() < CLEANUP_MIN_INTERVAL
            && store.intents.len() < MAX_INTENTS / 2
        {
            return;
        }

        let mut to_remove = Vec::new();

        for (id, intent) in store.intents.iter_mut() {
            match &intent.state {
                IntentState::Active if intent.is_expired() => {
                    to_remove.push(*id);
                }
                IntentState::Claimed { at, .. } if at.elapsed() > CLAIM_TIMEOUT => {
                    // Invariant: claimed intents timeout → release (not delete)
                    tracing::warn!(
                        intent_id = intent.intent_id,
                        "Claimed intent timed out — releasing to Active"
                    );
                    intent.state = IntentState::Active;
                    // Note: the intent's own TTL may have also expired,
                    // in which case it will be caught as expired Active on next cleanup.
                }
                _ => {}
            }
        }

        for id in &to_remove {
            if let Some(intent) = store.intents.remove(id) {
                let key = make_key(&intent.method, &intent.host, &intent.path_prefix);
                if let Some(ids) = store.index.get_mut(&key) {
                    ids.retain(|i| i != id);
                    if ids.is_empty() {
                        store.index.remove(&key);
                    }
                }
            }
        }

        store.last_cleanup = Instant::now();
    }

    /// Get current store stats.
    pub fn stats(&self) -> (usize, usize) {
        let store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return (0, 0),
        };
        let total = store.intents.len();
        let active = store.intents.values().filter(|i| i.is_active()).count();
        (total, active)
    }

    /// Count of intents currently held by the store, regardless of
    /// `Active` / `Claimed` state. Used by the lease-lifecycle
    /// regression test to assert that `confirm()` actually removed
    /// the intent — `stats()`'s "active" count excludes Claimed,
    /// which would mask a confirm-not-called regression where the
    /// lease lingers in Claimed and would auto-release after
    /// `CLAIM_TIMEOUT`. `active_count` returns the raw store size:
    /// after a confirmed claim the lease is gone (count drops),
    /// after release it's still there (count unchanged).
    pub fn active_count(&self) -> usize {
        let store = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        store.intents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, host: &str, path: &str, op: &str, agent: &str) -> IntentRequest {
        IntentRequest {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            operation: op.into(),
            agent_id: agent.into(),
            ttl_secs: None,
            payload_context: None,
            payload_hash: None,
            content_type: None,
            allow_pinned_lease: false,
            requires_observed_body: false,
        }
    }

    #[test]
    fn register_and_claim_confirm() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();

        let claim = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(claim.verified);
        assert_eq!(claim.operation.as_deref(), Some("stripe.read"));

        // Intent is Claimed — second claim should fail
        let claim2 = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(
            !claim2.verified,
            "claimed intent should not be claimable again"
        );

        // Confirm deletes the intent
        store.confirm(claim.claim_id);
        assert_eq!(store.stats().0, 0, "intent should be deleted after confirm");
    }

    #[test]
    fn claim_release_restores_intent() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();

        // Claim
        let claim = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(claim.verified);

        // Release (WAL failed)
        store.release(claim.claim_id);

        // Intent restored — can be claimed again
        let claim2 = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(claim2.verified, "released intent should be claimable again");

        // Different claim_id (ABA prevention)
        assert_ne!(claim.claim_id, claim2.claim_id);

        store.confirm(claim2.claim_id);
    }

    #[test]
    fn legacy_verify_still_works() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();

        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r.verified);

        // Consumed — second verify fails
        let r2 = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r2.verified);
    }

    #[test]
    fn agent_id_spoofing_blocked() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "agent-a",
            ))
            .unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("agent-b"));
        assert!(!r.verified, "should reject intent from different agent");

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("agent-a"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn expired_intent_not_claimable() {
        let store = IntentStore::new(0); // 0s TTL
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r.verified);
    }

    #[test]
    fn case_insensitive_matching() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "get",
                "API.Stripe.COM",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn claim_id_differs_from_intent_id() {
        let store = IntentStore::new(30);
        let intent_id = store
            .register(&req("GET", "a.com", "/x", "op", "t"))
            .unwrap();

        let claim = store.claim("GET", "a.com", "/x", Some("t"));
        assert!(claim.verified);
        assert_ne!(
            claim.claim_id, intent_id,
            "claim_id and intent_id must be distinct"
        );
        store.confirm(claim.claim_id);
    }

    #[test]
    fn unknown_agent_can_claim() {
        let store = IntentStore::new(30);
        store
            .register(&req(
                "GET",
                "api.stripe.com",
                "/v1/charges",
                "stripe.read",
                "test",
            ))
            .unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("unknown"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn mutex_poison_fail_closed() {
        // Drive the inner Mutex into Poison state by panicking inside a
        // thread that holds the lock, then assert every public surface
        // returns a fail-closed result instead of panicking the caller.
        use std::sync::Arc;

        let store = Arc::new(IntentStore::new(30));

        // Pre-register a real intent so claim() has something to find.
        let req = IntentRequest {
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/x".to_string(),
            operation: "test.poison".to_string(),
            agent_id: "agent-1".to_string(),
            ttl_secs: Some(30),
            payload_context: None,
            payload_hash: None,
            content_type: None,
            allow_pinned_lease: false,
            requires_observed_body: false,
        };
        let _ = store
            .register(&req)
            .expect("pre-poison register must succeed");

        // Poison the inner mutex.
        let store_clone = Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = store_clone.inner.lock().expect("first lock must succeed");
            panic!("intentional panic to poison IntentStore mutex");
        })
        .join();

        // Confirm the lock IS poisoned (sanity check on test harness).
        assert!(
            store.inner.lock().is_err(),
            "test harness failure: thread panic did not poison the mutex"
        );

        // claim() on a poisoned store must fail closed, not panic.
        let r = store.claim("GET", "example.com", "/x", Some("agent-1"));
        assert!(
            !r.verified,
            "poisoned IntentStore::claim must return verified=false (fail-closed)"
        );

        // confirm/release must not panic on a poisoned mutex (they are
        // documented as safe to call regardless).
        store.confirm(0);
        store.release(0);

        // register() should also surface an error rather than panic.
        let req2 = IntentRequest {
            method: "POST".to_string(),
            host: "y.com".to_string(),
            path: "/".to_string(),
            operation: "test.after_poison".to_string(),
            agent_id: "agent-2".to_string(),
            ttl_secs: Some(30),
            payload_context: None,
            payload_hash: None,
            content_type: None,
            allow_pinned_lease: false,
            requires_observed_body: false,
        };
        match store.register(&req2) {
            Ok(_) => {
                // Register may succeed if it bypasses inner — that's
                // also an acceptable contract, but record the observation.
                eprintln!("note: register() succeeded post-poison (may bypass inner)");
            }
            Err(e) => {
                assert!(
                    !e.is_empty(),
                    "post-poison register error must carry a non-empty message"
                );
            }
        }
    }
}
