use crate::types::EnforcementDecision;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// ─── Network SRR (PART 4) ───

/// Network-level SRR rule from TOML config
#[derive(Deserialize, Clone, Debug)]
struct NetworkRuleConfig {
    method: String,
    pattern: String,
    decision: NetworkDecisionConfig,
    /// Optional payload field for GraphQL/gRPC defense
    payload_field: Option<String>,
    /// Payload values to match against
    payload_match: Option<Vec<String>>,
    /// Max body bytes to inspect (default 64KB)
    max_body_bytes: Option<usize>,
    description: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct NetworkDecisionConfig {
    #[serde(rename = "type")]
    decision_type: String,
    milliseconds: Option<u64>,
    reason: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct NetworkSrrFile {
    rules: Vec<NetworkRuleConfig>,
}

/// Compiled network rule ready for matching
#[derive(Clone, Debug)]
pub struct NetworkRule {
    pub method: String,
    pub host_pattern: HostPattern,
    pub path_pattern: String,
    pub decision: EnforcementDecision,
    pub description: String,
    pub payload_field: Option<String>,
    pub payload_match: Option<Vec<String>>,
    pub max_body_bytes: usize,
}

/// Host matching pattern
#[derive(Clone, Debug)]
pub enum HostPattern {
    /// Exact host match: "api.bank.com"
    Exact(String),
    /// Suffix match: "{host}.database.com" → *.database.com
    Suffix(String),
    /// Any host: "{any}" or "*"
    Any,
}

/// Network SRR engine — ordered rule list with pattern matching.
/// Rules are evaluated in TOML definition order (first match wins per method).
pub struct NetworkSRR {
    rules: Vec<NetworkRule>,
    default_decision: EnforcementDecision,
}

impl NetworkSRR {
    /// Load network SRR rules from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SRR file: {}", path.display()))?;
        let file: NetworkSrrFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse SRR file: {}", path.display()))?;

        let mut rules = Vec::new();

        for rule_cfg in &file.rules {
            let decision = parse_decision(&rule_cfg.decision)?;
            let (host_pattern, path_pattern) = parse_pattern(&rule_cfg.pattern);

            let methods = if rule_cfg.method == "*" {
                vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            } else {
                vec![rule_cfg.method.as_str()]
            };

            for method in methods {
                rules.push(NetworkRule {
                    method: method.to_uppercase(),
                    host_pattern: host_pattern.clone(),
                    path_pattern: path_pattern.clone(),
                    decision: decision.clone(),
                    description: rule_cfg.description.clone().unwrap_or_default(),
                    payload_field: rule_cfg.payload_field.clone(),
                    payload_match: rule_cfg.payload_match.clone(),
                    max_body_bytes: rule_cfg.max_body_bytes.unwrap_or(65536),
                });
            }
        }

        tracing::info!(rules = rules.len(), "Network SRR rules compiled");

        Ok(Self {
            rules,
            default_decision: EnforcementDecision::Delay { milliseconds: 300 },
        })
    }

    /// Check a request against network SRR rules.
    /// Rules are evaluated in order — first match wins.
    pub fn check(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> EnforcementDecision {
        for rule in &self.rules {
            // Method match
            if rule.method != method {
                continue;
            }

            // Host match
            if !match_host(&rule.host_pattern, host) {
                continue;
            }

            // Path match
            if !match_path(&rule.path_pattern, path) {
                continue;
            }

            // Payload inspection (if required)
            if let (Some(field), Some(matches)) = (&rule.payload_field, &rule.payload_match) {
                if let Some(body_bytes) = body {
                    if body_bytes.len() > rule.max_body_bytes {
                        tracing::warn!(
                            "Body exceeds max_body_bytes ({}), skipping payload inspection",
                            rule.max_body_bytes
                        );
                        return self.default_decision.clone();
                    }

                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
                        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
                            if matches.iter().any(|m| m == value) {
                                return rule.decision.clone();
                            }
                        }
                    }
                    // Payload didn't match this rule — continue to next
                    continue;
                } else {
                    // No body for inspection — continue
                    continue;
                }
            }

            // URL-only rule matched
            return rule.decision.clone();
        }

        // No match — Default-to-Caution
        self.default_decision.clone()
    }
}

/// Parse an SRR pattern into (host_pattern, path_pattern).
/// Pattern format: "api.bank.com/transfer/{any}" → Exact("api.bank.com"), "/transfer/*"
fn parse_pattern(pattern: &str) -> (HostPattern, String) {
    // Split on first '/'
    let (host_part, path_part) = match pattern.find('/') {
        Some(idx) => (&pattern[..idx], &pattern[idx..]),
        None => (pattern, "/*"),
    };

    let host_pattern = if host_part == "{any}" || host_part == "*" {
        HostPattern::Any
    } else if host_part.starts_with("{") && host_part.contains('.') {
        // e.g. "{host}.database.com" → suffix match on ".database.com"
        let dot_idx = host_part.find('.').unwrap();
        HostPattern::Suffix(host_part[dot_idx..].to_string())
    } else {
        HostPattern::Exact(host_part.to_string())
    };

    let path_pattern = path_part.replace("{any}", "*").to_string();

    (host_pattern, path_pattern)
}

/// Match a host against a HostPattern.
fn match_host(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::Exact(expected) => host == expected,
        HostPattern::Suffix(suffix) => host.ends_with(suffix.as_str()),
        HostPattern::Any => true,
    }
}

/// Match a path against a path pattern. Supports trailing '*' as wildcard.
fn match_path(pattern: &str, path: &str) -> bool {
    if pattern == "/*" || pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix("*") {
        // Prefix match: "/transfer/*" matches "/transfer/123"
        path.starts_with(prefix)
    } else {
        // Exact match
        path == pattern
    }
}

/// Parse a decision config into an EnforcementDecision
fn parse_decision(cfg: &NetworkDecisionConfig) -> Result<EnforcementDecision> {
    match cfg.decision_type.as_str() {
        "Allow" => Ok(EnforcementDecision::Allow),
        "Deny" => Ok(EnforcementDecision::Deny {
            reason: cfg
                .reason
                .clone()
                .unwrap_or_else(|| "Denied by SRR".to_string()),
        }),
        "Delay" => Ok(EnforcementDecision::Delay {
            milliseconds: cfg.milliseconds.unwrap_or(300),
        }),
        "RequireApproval" => Ok(EnforcementDecision::RequireApproval {
            urgency: crate::types::ApprovalUrgency::Standard,
        }),
        other => anyhow::bail!("Unknown decision type in SRR: {}", other),
    }
}

// ─── Hostile Environment Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a NetworkSRR from inline TOML
    fn srr_from_toml(toml_str: &str) -> NetworkSRR {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_srr.toml");
        std::fs::write(&path, toml_str).unwrap();
        NetworkSRR::load(&path).unwrap()
    }

    // ── Test 1: Payload > max_body_bytes → Default-to-Caution (no crash) ──

    #[test]
    fn payload_exceeding_max_body_bytes_falls_back_to_default_caution() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 100
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#);

        // Body is 200 bytes — exceeds max_body_bytes (100)
        let big_body = vec![b'x'; 200];

        let decision = srr.check("POST", "api.bank.com", "/graphql", Some(&big_body));

        // Must NOT crash. Must return Default-to-Caution (Delay 300ms), not Deny.
        match decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300, "Default-to-Caution must be 300ms");
            }
            other => panic!(
                "Expected Default-to-Caution (Delay 300ms), got {:?}",
                other
            ),
        }
    }

    // ── Test 2: Payload exactly at limit → still inspected ──

    #[test]
    fn payload_at_exact_limit_is_inspected() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 1024
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#);

        let body = br#"{"operationName": "TransferFunds"}"#;
        assert!(body.len() <= 1024);

        let decision = srr.check("POST", "api.bank.com", "/graphql", Some(body));
        match decision {
            EnforcementDecision::Deny { reason } => {
                assert!(reason.contains("Dangerous GraphQL"));
            }
            other => panic!("Expected Deny, got {:?}", other),
        }
    }

    // ── Test 3: 64KB+ body — OOM defense ──

    #[test]
    fn large_64kb_body_does_not_crash_or_oom() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "Dangerous GraphQL" }

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
        "#);

        // 128KB body — well over 64KB limit
        let huge_body = vec![b'A'; 131072];
        let decision = srr.check("POST", "api.bank.com", "/graphql", Some(&huge_body));

        // Must return Default-to-Caution, not crash
        match decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300);
            }
            other => panic!("Expected Delay (Default-to-Caution), got {:?}", other),
        }
    }

    // ── Test 4: Malformed JSON body → skip rule, continue matching ──

    #[test]
    fn malformed_json_body_skips_payload_rule() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "Dangerous GraphQL" }

            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            decision = { type = "Delay", milliseconds = 300 }
        "#);

        // Invalid JSON — should not crash, should skip to next rule
        let bad_json = b"this is not json {{{";
        let decision = srr.check("POST", "api.bank.com", "/graphql", Some(bad_json));

        match decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300, "Malformed JSON should fall through to next rule");
            }
            other => panic!("Expected Delay (fallthrough), got {:?}", other),
        }
    }

    // ── Test 5: No body when payload inspection required → skip rule ──

    #[test]
    fn no_body_for_payload_rule_skips_to_next() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            decision = { type = "Deny", reason = "Dangerous GraphQL" }

            [[rules]]
            method = "POST"
            pattern = "api.bank.com/{any}"
            decision = { type = "Delay", milliseconds = 500 }
        "#);

        // No body provided — payload rule should be skipped
        let decision = srr.check("POST", "api.bank.com", "/graphql", None);

        match decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 500);
            }
            other => panic!("Expected Delay 500ms (fallthrough), got {:?}", other),
        }
    }

    // ── Test 6: Header forgery — SDK claims storage.read but hits bank transfer URL ──
    // Layer 2 SRR catches this because URL-based rules are evaluated independently
    // of the semantic operation header. The proxy takes max_strict(policy, srr).

    #[test]
    fn srr_catches_url_regardless_of_operation_header() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // Agent lies: claims storage.read but URL is bank transfer
        // SRR doesn't care about headers — it inspects the actual URL
        let decision = srr.check("POST", "api.bank.com", "/transfer/123", None);

        match decision {
            EnforcementDecision::Deny { reason } => {
                assert!(reason.contains("Wire transfer"));
            }
            other => panic!(
                "SRR must deny based on URL even if header claims safe operation. Got: {:?}",
                other
            ),
        }
    }

    // ── Test 7: Default-to-Caution — unknown URL gets delay ──

    #[test]
    fn unknown_url_gets_default_to_caution() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // Completely unknown URL — should hit default_decision (Delay 300ms)
        let decision = srr.check("GET", "totally-unknown.com", "/some/path", None);

        match decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300, "Unknown URLs must get Default-to-Caution");
            }
            other => panic!("Expected Default-to-Caution, got {:?}", other),
        }
    }

    // ── Test 8: Suffix host pattern matching ──

    #[test]
    fn suffix_host_pattern_blocks_all_subdomains() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "DELETE"
            pattern = "{host}.database.com/{any}"
            decision = { type = "Deny", reason = "Database deletion blocked" }
        "#);

        // Any subdomain of database.com should be blocked
        let d1 = srr.check("DELETE", "prod.database.com", "/users/123", None);
        let d2 = srr.check("DELETE", "staging.database.com", "/orders", None);
        let d3 = srr.check("DELETE", "dev.database.com", "/anything", None);

        for (i, decision) in [d1, d2, d3].iter().enumerate() {
            match decision {
                EnforcementDecision::Deny { .. } => {}
                other => panic!("Subdomain {} should be denied, got {:?}", i + 1, other),
            }
        }
    }

    // ── Test 9: Method mismatch — GET to a POST-only rule ──

    #[test]
    fn method_mismatch_does_not_trigger_rule() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // GET to a POST-only rule — should NOT be denied
        let decision = srr.check("GET", "api.bank.com", "/transfer/123", None);

        match decision {
            EnforcementDecision::Deny { .. } => {
                panic!("GET should not match a POST-only deny rule");
            }
            _ => {} // Any non-Deny is correct
        }
    }

    // ── Test 10: Wildcard method expansion ──

    #[test]
    fn wildcard_method_matches_all_http_methods() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "*"
            pattern = "evil.com/{any}"
            decision = { type = "Deny", reason = "Blocked domain" }
        "#);

        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let decision = srr.check(method, "evil.com", "/anything", None);
            match decision {
                EnforcementDecision::Deny { .. } => {}
                other => panic!("{} should be denied for evil.com, got {:?}", method, other),
            }
        }
    }
}
