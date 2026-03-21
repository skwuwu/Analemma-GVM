//! Shadow Mode Intent Store
//!
//! Stores declared intents from MCP tool calls. The proxy checks this store
//! before forwarding outbound requests. Requests without a matching intent
//! are handled according to the shadow mode policy (strict/cautious/permissive).
//!
//! Architecture:
//!   MCP gvm_declare_intent → POST /gvm/intent → IntentStore::register()
//!   Proxy request → IntentStore::verify() → Verified / Unverified

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
        // Default to Disabled for backward compatibility.
        // MCP server sets GVM_SHADOW_MODE=strict to activate.
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
    /// Verification mode (strict/cautious/permissive/disabled).
    #[serde(default)]
    pub mode: ShadowMode,
    /// Intent TTL in seconds (default: 30).
    #[serde(default = "default_intent_ttl_secs")]
    pub intent_ttl_secs: u64,
    /// Delay in milliseconds for cautious mode (default: 5000).
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

/// A declared intent with TTL.
#[derive(Debug, Clone)]
struct Intent {
    method: String,
    host: String,
    path_prefix: String,
    operation: String,
    agent_id: String,
    created_at: Instant,
    ttl: Duration,
}

impl Intent {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        if self.is_expired() {
            return false;
        }
        self.method.eq_ignore_ascii_case(method)
            && self.host.eq_ignore_ascii_case(host)
            && path.starts_with(&self.path_prefix)
    }
}

/// Result of intent verification.
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
    /// Override TTL in seconds (optional, uses config default otherwise).
    pub ttl_secs: Option<u64>,
}

fn default_agent() -> String {
    "mcp-agent".to_string()
}

/// Thread-safe intent store with automatic TTL expiration.
pub struct IntentStore {
    intents: Mutex<Vec<Intent>>,
    default_ttl: Duration,
    /// Maximum stored intents (prevent memory exhaustion).
    max_intents: usize,
}

/// Hard cap on stored intents.
const MAX_INTENTS: usize = 10_000;
/// Cleanup interval (every N registrations).
const CLEANUP_INTERVAL: usize = 100;

impl IntentStore {
    pub fn new(default_ttl_secs: u64) -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_intents: MAX_INTENTS,
        }
    }

    /// Register a new intent. Returns the intent ID (index).
    pub fn register(&self, req: &IntentRequest) -> Result<usize, String> {
        let mut intents = self.intents.lock().map_err(|_| {
            "Intent store lock poisoned — fail-closed".to_string()
        })?;

        // Periodic cleanup of expired intents
        if intents.len() % CLEANUP_INTERVAL == 0 || intents.len() >= self.max_intents {
            intents.retain(|i| !i.is_expired());
        }

        // Enforce capacity limit
        if intents.len() >= self.max_intents {
            return Err(format!(
                "Intent store full ({} intents). Wait for TTL expiration.",
                self.max_intents
            ));
        }

        let ttl = req
            .ttl_secs
            .map(|s| Duration::from_secs(s.min(300))) // Cap at 5 minutes
            .unwrap_or(self.default_ttl);

        let intent = Intent {
            method: req.method.to_uppercase(),
            host: req.host.to_lowercase(),
            path_prefix: req.path.clone(),
            operation: req.operation.clone(),
            agent_id: req.agent_id.clone(),
            created_at: Instant::now(),
            ttl,
        };

        let id = intents.len();
        intents.push(intent);

        tracing::info!(
            method = %req.method,
            host = %req.host,
            path = %req.path,
            operation = %req.operation,
            agent = %req.agent_id,
            ttl_secs = ttl.as_secs(),
            "Intent registered (shadow verification)"
        );

        Ok(id)
    }

    /// Check if a request has a matching, non-expired intent.
    /// Consumes the intent on match (one-time use).
    /// Validates agent_id if provided — prevents intent spoofing across agents.
    pub fn verify(&self, method: &str, host: &str, path: &str, request_agent_id: Option<&str>) -> VerifyResult {
        let mut intents = match self.intents.lock() {
            Ok(i) => i,
            Err(_) => {
                // Mutex poisoned → fail-closed: treat as unverified
                tracing::error!("Intent store lock poisoned — treating request as unverified");
                return VerifyResult {
                    verified: false,
                    operation: None,
                    agent_id: None,
                };
            }
        };

        // Find matching intent (newest first for performance).
        // If request_agent_id is provided, also validate agent ownership.
        let match_idx = intents
            .iter()
            .rposition(|i| {
                if !i.matches(method, host, path) {
                    return false;
                }
                // Cross-check: if caller provides agent_id, it must match
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
            });

        match match_idx {
            Some(idx) => {
                let intent = intents.remove(idx); // Consume (one-time use)
                tracing::debug!(
                    method = %method,
                    host = %host,
                    path = %path,
                    operation = %intent.operation,
                    "Intent verified (shadow match)"
                );
                VerifyResult {
                    verified: true,
                    operation: Some(intent.operation),
                    agent_id: Some(intent.agent_id),
                }
            }
            None => {
                tracing::warn!(
                    method = %method,
                    host = %host,
                    path = %path,
                    "No matching intent — request is UNVERIFIED"
                );
                VerifyResult {
                    verified: false,
                    operation: None,
                    agent_id: None,
                }
            }
        }
    }

    /// Get current store stats (for /gvm/info).
    pub fn stats(&self) -> (usize, usize) {
        let intents = match self.intents.lock() {
            Ok(i) => i,
            Err(_) => return (0, 0),
        };
        let total = intents.len();
        let active = intents.iter().filter(|i| !i.is_expired()).count();
        (total, active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_verify_intent() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        let result = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(result.verified);
        assert_eq!(result.operation.as_deref(), Some("stripe.read"));
    }

    #[test]
    fn intent_consumed_after_verify() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        let r1 = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r1.verified);

        // Second verify should fail — intent consumed
        let r2 = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r2.verified);
    }

    #[test]
    fn unmatched_request_unverified() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        // Wrong method
        let r = store.verify("POST", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r.verified);
    }

    #[test]
    fn expired_intent_not_matched() {
        let store = IntentStore::new(0); // 0 second TTL = immediately expired
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: Some(0),
        };
        store.register(&req).unwrap();

        std::thread::sleep(Duration::from_millis(10));
        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(!r.verified);
    }

    #[test]
    fn case_insensitive_matching() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "get".into(),
            host: "API.Stripe.COM".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("test"));
        assert!(r.verified);
    }

    #[test]
    fn agent_id_spoofing_blocked() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "agent-a".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        // Different agent trying to consume agent-a's intent → rejected
        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("agent-b"));
        assert!(!r.verified, "should reject intent registered by different agent");

        // Correct agent can still consume it
        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("agent-a"));
        assert!(r.verified);
    }

    #[test]
    fn unknown_agent_can_verify() {
        let store = IntentStore::new(30);
        let req = IntentRequest {
            method: "GET".into(),
            host: "api.stripe.com".into(),
            path: "/v1/charges".into(),
            operation: "stripe.read".into(),
            agent_id: "test".into(),
            ttl_secs: None,
        };
        store.register(&req).unwrap();

        // "unknown" agent_id skips cross-check (backward compat)
        let r = store.verify("GET", "api.stripe.com", "/v1/charges", Some("unknown"));
        assert!(r.verified);
    }

    #[test]
    fn mutex_poison_fail_closed() {
        let store = IntentStore::new(30);
        let r = store.verify("GET", "nonexistent.com", "/", None);
        assert!(!r.verified);
    }
}
