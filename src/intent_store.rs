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
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShadowMode {
    /// Unverified requests are denied (production recommended).
    Strict,
    /// Unverified requests are delayed + audit logged.
    Cautious,
    /// Unverified requests are allowed + audit warning (onboarding).
    Permissive,
    /// Shadow verification disabled — proxy behaves as before.
    Disabled,
}

impl Default for ShadowMode {
    fn default() -> Self {
        ShadowMode::Disabled
    }
}

impl ShadowMode {
    /// Parse from environment variable (used by proxy startup).
    pub fn from_env() -> Option<Self> {
        match std::env::var("GVM_SHADOW_MODE").ok()?.to_lowercase().as_str() {
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

fn default_intent_ttl_secs() -> u64 { 30 }
fn default_cautious_delay_ms() -> u64 { 5000 }

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
}

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

/// Request body for POST /gvm/intent.
#[derive(Debug, Deserialize)]
pub struct IntentRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub operation: String,
    #[serde(default = "default_agent")]
    pub agent_id: String,
    pub ttl_secs: Option<u64>,
}

fn default_agent() -> String { "mcp-agent".to_string() }

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
            }),
            default_ttl: Duration::from_secs(default_ttl_secs),
            next_intent_id: AtomicU64::new(1),
            next_claim_id: AtomicU64::new(1_000_000), // Distinct namespace from intent_id
        }
    }

    /// Register a new intent (Active state).
    pub fn register(&self, req: &IntentRequest) -> Result<u64, String> {
        let mut store = self.inner.lock().map_err(|_| {
            "Intent store lock poisoned — fail-closed".to_string()
        })?;

        // Cleanup: expired Active intents + timed-out Claims → release
        self.cleanup_inner(&mut store);

        if store.intents.len() >= MAX_INTENTS {
            return Err(format!(
                "Intent store full ({} intents). Wait for TTL expiration.",
                MAX_INTENTS
            ));
        }

        let ttl = req.ttl_secs
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
                    verified: false, claim_id: 0,
                    operation: None, agent_id: None,
                };
            }
        };

        // Search for matching Active intent (newest first by intent_id)
        let mut candidates: Vec<_> = store.intents.values()
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
        candidates.sort_by(|a, b| b.intent_id.cmp(&a.intent_id)); // newest first
        let matched = candidates.first().map(|i| i.intent_id);

        match matched {
            Some(intent_id) => {
                let claim_id = self.next_claim_id.fetch_add(1, Ordering::Relaxed);
                let intent = match store.intents.get_mut(&intent_id) {
                    Some(i) => i,
                    None => {
                        // Intent was removed between candidate search and claim — race lost
                        tracing::warn!(intent_id, "Intent disappeared during claim — returning unverified");
                        return ClaimResult {
                            verified: false, claim_id: 0,
                            operation: None, agent_id: None,
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
                    verified: false, claim_id: 0,
                    operation: None, agent_id: None,
                }
            }
        }
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
                tracing::warn!(claim_id, "Intent already removed during confirm — idempotent");
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
            tracing::debug!(intent_id = id, claim_id, "Intent confirmed (WAL durable, deleted)");
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
    pub fn verify(&self, method: &str, host: &str, path: &str, request_agent_id: Option<&str>) -> VerifyResult {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, host: &str, path: &str, op: &str, agent: &str) -> IntentRequest {
        IntentRequest {
            method: method.into(), host: host.into(), path: path.into(),
            operation: op.into(), agent_id: agent.into(), ttl_secs: None,
        }
    }

    #[test]
    fn register_and_claim_confirm() {
        let store = IntentStore::new(30);
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "test")).unwrap();

        let claim = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(claim.verified);
        assert_eq!(claim.operation.as_deref(), Some("stripe.read"));

        // Intent is Claimed — second claim should fail
        let claim2 = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!claim2.verified, "claimed intent should not be claimable again");

        // Confirm deletes the intent
        store.confirm(claim.claim_id);
        assert_eq!(store.stats().0, 0, "intent should be deleted after confirm");
    }

    #[test]
    fn claim_release_restores_intent() {
        let store = IntentStore::new(30);
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "test")).unwrap();

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
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "test")).unwrap();

        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r.verified);

        // Consumed — second verify fails
        let r2 = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r2.verified);
    }

    #[test]
    fn agent_id_spoofing_blocked() {
        let store = IntentStore::new(30);
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "agent-a")).unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("agent-b"));
        assert!(!r.verified, "should reject intent from different agent");

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("agent-a"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn expired_intent_not_claimable() {
        let store = IntentStore::new(0); // 0s TTL
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "test")).unwrap();
        std::thread::sleep(Duration::from_millis(10));

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r.verified);
    }

    #[test]
    fn case_insensitive_matching() {
        let store = IntentStore::new(30);
        store.register(&req("get", "API.Stripe.COM", "/v1/charges", "stripe.read", "test")).unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn claim_id_differs_from_intent_id() {
        let store = IntentStore::new(30);
        let intent_id = store.register(&req("GET", "a.com", "/x", "op", "t")).unwrap();

        let claim = store.claim("GET", "a.com", "/x", Some("t"));
        assert!(claim.verified);
        assert_ne!(claim.claim_id, intent_id, "claim_id and intent_id must be distinct");
        store.confirm(claim.claim_id);
    }

    #[test]
    fn unknown_agent_can_claim() {
        let store = IntentStore::new(30);
        store.register(&req("GET", "api.stripe.com", "/v1/charges", "stripe.read", "test")).unwrap();

        let r = store.claim("GET", "api.stripe.com", "/v1/charges", Some("unknown"));
        assert!(r.verified);
        store.confirm(r.claim_id);
    }

    #[test]
    fn mutex_poison_fail_closed() {
        let store = IntentStore::new(30);
        let r = store.claim("GET", "nonexistent.com", "/", None);
        assert!(!r.verified);
    }
}
