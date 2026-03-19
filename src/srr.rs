use crate::types::EnforcementDecision;
use gvm_types::strip_port;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

// ─── Network SRR (PART 4) ───

/// Network-level SRR rule from TOML config
#[derive(Deserialize, Clone, Debug)]
struct NetworkRuleConfig {
    method: String,
    pattern: String,
    decision: NetworkDecisionConfig,
    /// Optional regex pattern for path matching (overrides path portion of `pattern`).
    /// Compiled at load time using Rust's `regex` crate (automata-based, O(n) guaranteed).
    /// Example: `"^/api/v[1-3]/users/.*"` matches /api/v1/users/, /api/v2/users/foo, etc.
    path_regex: Option<String>,
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
    /// Pre-compiled regex for path matching (if `path_regex` was specified in config).
    /// Uses Rust's `regex` crate which guarantees O(n) linear-time matching (no backtracking).
    pub compiled_path_regex: Option<Regex>,
    pub decision: EnforcementDecision,
    pub description: String,
    pub payload_field: Option<String>,
    pub payload_match: Option<Vec<String>>,
    pub max_body_bytes: usize,
    /// True if this rule is a catch-all (method="*" + pattern="{any}").
    /// Catch-all matches are flagged as default-to-caution for the CLI.
    pub is_catch_all: bool,
}

/// Result of an SRR check, including metadata about which rule matched.
///
/// Used by the proxy to populate `matched_rule_id` and `default_caution` on events,
/// and by the CLI to detect unregistered URLs that may need explicit rules.
#[derive(Clone, Debug)]
pub struct SrrCheckResult {
    /// The enforcement decision for this request.
    pub decision: EnforcementDecision,
    /// Description of the matched rule (None if default-to-caution fired).
    pub matched_description: Option<String>,
    /// True if this request hit the catch-all rule or the built-in default
    /// (no specific, intentional rule exists for this URL).
    pub is_catch_all: bool,
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
///
/// Performance: linear scan O(N) per request. Benchmarked at ~300µs for 10,000 rules.
/// Sufficient for most deployments. If rule count exceeds ~1,000, consider indexing
/// by (method, host) for sub-linear lookup.
pub struct NetworkSRR {
    rules: Vec<NetworkRule>,
    default_decision: EnforcementDecision,
}

/// Summary of loaded SRR rules for startup banner display.
pub struct SrrSummary {
    pub total_rules: usize,
    pub deny_rules: usize,
    pub delay_rules: usize,
    pub allow_rules: usize,
    pub default_decision: String,
    /// Up to 3 representative deny rules for display
    pub sample_denies: Vec<String>,
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

            // Pre-compile path regex at load time (fail-fast on invalid patterns)
            let compiled_path_regex = match &rule_cfg.path_regex {
                Some(pattern) => {
                    let re = Regex::new(pattern)
                        .with_context(|| format!("Invalid path_regex '{}' in SRR rule", pattern))?;
                    Some(re)
                }
                None => None,
            };

            let methods = if rule_cfg.method == "*" {
                vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            } else {
                vec![rule_cfg.method.as_str()]
            };

            // Detect catch-all rules: method="*" and pattern="{any}" (or just "{any}")
            let is_catch_all = rule_cfg.method == "*"
                && matches!(host_pattern, HostPattern::Any)
                && (path_pattern == "/*" || path_pattern == "*")
                && compiled_path_regex.is_none();

            for method in methods {
                rules.push(NetworkRule {
                    method: method.to_uppercase(),
                    host_pattern: host_pattern.clone(),
                    path_pattern: path_pattern.clone(),
                    compiled_path_regex: compiled_path_regex.clone(),
                    decision: decision.clone(),
                    description: rule_cfg.description.clone().unwrap_or_default(),
                    payload_field: rule_cfg.payload_field.clone(),
                    payload_match: rule_cfg.payload_match.clone(),
                    max_body_bytes: rule_cfg.max_body_bytes.unwrap_or(65536),
                    is_catch_all,
                });
            }
        }

        tracing::info!(rules = rules.len(), "Network SRR rules compiled");

        Ok(Self {
            rules,
            default_decision: EnforcementDecision::Delay { milliseconds: 300 },
        })
    }

    /// Produce a summary of loaded rules for the startup banner.
    pub fn summary(&self) -> SrrSummary {
        let mut deny = 0;
        let mut delay = 0;
        let mut allow = 0;
        let mut sample_denies = Vec::new();

        for rule in &self.rules {
            match &rule.decision {
                EnforcementDecision::Deny { .. } => {
                    deny += 1;
                    if sample_denies.len() < 3 && !rule.is_catch_all {
                        let host = match &rule.host_pattern {
                            HostPattern::Exact(h) => h.clone(),
                            HostPattern::Suffix(s) => format!("*{}", s),
                            HostPattern::Any => "*".to_string(),
                        };
                        sample_denies.push(format!(
                            "{} {}{}",
                            rule.method, host, rule.path_pattern
                        ));
                    }
                }
                EnforcementDecision::Delay { .. }
                | EnforcementDecision::Throttle { .. } => delay += 1,
                EnforcementDecision::Allow => allow += 1,
                _ => {}
            }
        }

        let default_desc = match &self.default_decision {
            EnforcementDecision::Delay { milliseconds } => format!("Delay({}ms)", milliseconds),
            EnforcementDecision::Deny { reason } => format!("Deny({})", reason),
            EnforcementDecision::Allow => "Allow".to_string(),
            other => format!("{:?}", other),
        };

        SrrSummary {
            total_rules: self.rules.len(),
            deny_rules: deny,
            delay_rules: delay,
            allow_rules: allow,
            default_decision: default_desc,
            sample_denies,
        }
    }

    /// Check a request against network SRR rules.
    /// Rules are evaluated in order — first match wins.
    /// IPv6 addresses are normalized before matching to prevent SSRF bypass
    /// via zero-compression, IPv4-mapped, or bracket variations.
    /// Paths are canonicalized (percent-decoded, dot-segment resolved, double
    /// slashes collapsed) to prevent bypass via path manipulation.
    ///
    /// Returns `SrrCheckResult` with the decision, matched rule description,
    /// and whether this was a catch-all/default-to-caution match.
    pub fn check(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> SrrCheckResult {
        // Normalize method: uppercase once here to match rule storage format.
        // Rules are stored as uppercase (line 135). HTTP methods from hyper are
        // already uppercase, but direct API callers may pass lowercase.
        // Defense-in-depth: normalize here to prevent case-smuggling bypass.
        let effective_method = method.to_uppercase();

        // Normalize host: resolve IPv6 variants to canonical form so SRR rules
        // written for "localhost" or "127.0.0.1" also catch IPv6 equivalents.
        let normalized = normalize_host(host);
        let raw_host = normalized.as_deref().unwrap_or(host);
        // Case-insensitive: lowercase once here (O(1) per request) instead of
        // per-rule in match_host (avoids O(N) allocations for N rules).
        let effective_host = raw_host.to_lowercase();

        // Normalize path: prevent bypass via percent-encoding, dot segments,
        // double slashes, or null bytes.
        let canonical = normalize_path(path);
        let effective_path = canonical.as_deref().unwrap_or(path);

        for rule in &self.rules {
            // Method match (both sides uppercase — case-insensitive comparison)
            if rule.method != effective_method {
                continue;
            }

            // Host match
            if !match_host(&rule.host_pattern, &effective_host) {
                continue;
            }

            // Path match: if path_regex is set, use regex; otherwise use prefix/exact match.
            // Check BOTH normalized and original paths — normalization must
            // expand what gets caught (e.g., dot-segment traversal attempts
            // should not escape a deny rule that matched the original prefix).
            if let Some(ref re) = rule.compiled_path_regex {
                if !re.is_match(effective_path) && !re.is_match(path) {
                    continue;
                }
            } else if !match_path(&rule.path_pattern, effective_path)
                && !match_path(&rule.path_pattern, path)
            {
                continue;
            }

            // Payload inspection (if required)
            if let (Some(field), Some(matches)) = (&rule.payload_field, &rule.payload_match) {
                if let Some(body_bytes) = body {
                    if body_bytes.len() > rule.max_body_bytes {
                        // Body too large for this rule's payload inspection.
                        // Continue to next rule so URL-only rules for the same
                        // endpoint can still match. Returning here would skip
                        // all subsequent rules for this URL.
                        tracing::warn!(
                            "Body exceeds max_body_bytes ({}), skipping payload inspection for this rule",
                            rule.max_body_bytes
                        );
                        continue;
                    }

                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
                        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
                            if matches.iter().any(|m| m == value) {
                                return SrrCheckResult {
                                    decision: rule.decision.clone(),
                                    matched_description: Some(rule.description.clone()),
                                    is_catch_all: rule.is_catch_all,
                                };
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
            return SrrCheckResult {
                decision: rule.decision.clone(),
                matched_description: Some(rule.description.clone()),
                is_catch_all: rule.is_catch_all,
            };
        }

        // No match — Default-to-Caution (built-in fallback)
        SrrCheckResult {
            decision: self.default_decision.clone(),
            matched_description: None,
            is_catch_all: true,
        }
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

    // Order matters: check "{any}" (Any) BEFORE "{prefix}.domain" (Suffix).
    // "{any}" matches `starts_with("{")` too, so it must be tested first
    // to avoid being incorrectly parsed as a Suffix pattern.
    let host_pattern = if host_part == "{any}" || host_part == "*" {
        HostPattern::Any
    } else if host_part.starts_with("{") && host_part.contains('.') {
        // e.g. "{host}.database.com" → suffix match on ".database.com"
        // Safe: contains('.') guard above ensures find('.') always returns Some.
        // unwrap_or(0) is unreachable but avoids panic for defense-in-depth.
        let dot_idx = host_part.find('.').unwrap_or(0);
        HostPattern::Suffix(host_part[dot_idx..].to_lowercase())
    } else {
        HostPattern::Exact(host_part.to_lowercase())
    };

    let path_pattern = path_part.replace("{any}", "*").to_string();

    (host_pattern, path_pattern)
}

/// Match a host against a HostPattern.
/// Strips port number before matching (e.g., "api.bank.com:443" → "api.bank.com").
///
/// Caller must pass a pre-lowercased host (done once in `check()` for O(1) cost).
/// Patterns are lowercased at compile time in `parse_pattern()`.
fn match_host(pattern: &HostPattern, host: &str) -> bool {
    let host_without_port = strip_port(host);

    match pattern {
        HostPattern::Exact(expected) => host_without_port == expected.as_str(),
        HostPattern::Suffix(suffix) => {
            // Dot-boundary enforcement: suffix always starts with '.' from parse_pattern
            // (e.g., ".database.com"), so "attacker-database.com" cannot match —
            // it would need to end with ".database.com" which requires a dot boundary.
            host_without_port.ends_with(suffix.as_str())
        }
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

/// Canonicalize a request path to prevent SRR bypass via path manipulation.
///
/// Defenses:
/// - Percent-decoding: `%2F` → `/`, `%2e` → `.` (prevents encoded bypass)
/// - Null byte stripping: `/transfer%00` → `/transfer` (prevents null injection)
/// - Double-slash collapse: `//transfer` → `/transfer`
/// - Dot-segment resolution: `/a/../transfer` → `/transfer` (RFC 3986 §5.2.4)
/// - Trailing normalization: preserves trailing slash semantics
///
/// Returns None if the path is already in canonical form (avoids allocation).
fn normalize_path(path: &str) -> Option<String> {
    // Step 1: Percent-decode the path (only decode unreserved + path-safe chars)
    let decoded = percent_decode_path(path);
    let working = decoded.as_deref().unwrap_or(path);

    // Step 2: Strip null bytes
    let has_null = working.contains('\0');

    // Step 3: Check if any normalization is actually needed
    let has_double_slash = working.contains("//");
    let has_dot_segment = working.contains("/./") || working.contains("/../")
        || working.ends_with("/..") || working.ends_with("/.");

    if decoded.is_none() && !has_null && !has_double_slash && !has_dot_segment {
        return None; // Already canonical
    }

    // Step 4: Build canonical path
    let clean: String = if has_null {
        working.replace('\0', "")
    } else {
        working.to_string()
    };

    // Step 5: Collapse double slashes
    let mut result = String::with_capacity(clean.len());
    let mut prev_slash = false;
    for ch in clean.chars() {
        if ch == '/' {
            if !prev_slash {
                result.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            result.push(ch);
        }
    }

    // Step 6: Resolve dot segments (RFC 3986 §5.2.4)
    let resolved = resolve_dot_segments(&result);

    Some(resolved)
}

/// Percent-decode path-relevant characters.
/// Decodes %XX sequences to their byte values, focusing on characters that
/// could be used to bypass path matching (/, ., alphanumerics).
/// Returns None if no percent-encoded sequences are found.
fn percent_decode_path(path: &str) -> Option<String> {
    if !path.contains('%') {
        return None;
    }

    let bytes = path.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(result).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Resolve dot segments per RFC 3986 §5.2.4.
/// "/a/b/../c" → "/a/c", "/a/./b" → "/a/b"
fn resolve_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {} // Skip current-directory references
            ".." => {
                // Go up one level, but never above root
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    let resolved = segments.join("/");
    if resolved.starts_with('/') || resolved.is_empty() {
        resolved
    } else {
        format!("/{}", resolved)
    }
}

/// Normalize IPv6 host addresses to their canonical IPv4 equivalents.
///
/// This prevents SSRF bypass via IPv6 variants:
/// - `[::1]` → `localhost` (IPv6 loopback)
/// - `[::ffff:127.0.0.1]` → `127.0.0.1` (IPv4-mapped IPv6)
/// - `[0:0:0:0:0:ffff:127.0.0.1]` → `127.0.0.1` (full-form IPv4-mapped)
/// - `[::ffff:7f00:1]` → `127.0.0.1` (hex IPv4-mapped)
/// - `[fd00:ec2::254]` → `metadata.aws.ipv6` (AWS IPv6 metadata)
/// - `[::ffff:169.254.169.254]` → `169.254.169.254` (cloud metadata IPv4-mapped)
///
/// Returns None if no normalization needed (host is already in canonical form).
fn normalize_host(host: &str) -> Option<String> {
    // Strip brackets if present: [::1] → ::1
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .or_else(|| {
            // Also handle [::1]:port → ::1
            host.strip_prefix('[')
                .and_then(|h| h.split(']').next())
        });

    let ipv6 = match inner {
        Some(addr) => addr,
        None => return None, // Not an IPv6 address
    };

    // Normalize: remove leading zeros, lowercase
    let normalized = ipv6.to_lowercase();

    // Check for loopback variants
    if is_ipv6_loopback(&normalized) {
        return Some("localhost".to_string());
    }

    // Check for IPv4-mapped addresses: ::ffff:a.b.c.d or 0:0:0:0:0:ffff:a.b.c.d
    if let Some(v4) = extract_ipv4_mapped(&normalized) {
        return Some(v4);
    }

    // Check for known cloud metadata IPv6 addresses
    if is_cloud_metadata_ipv6(&normalized) {
        return Some("169.254.169.254".to_string());
    }

    None
}

/// Check if an IPv6 address (without brackets) is a loopback.
/// Covers: ::1, 0::1, 0:0:0:0:0:0:0:1 and all zero-compression variants.
fn is_ipv6_loopback(addr: &str) -> bool {
    // Parse by expanding :: and checking if result is 0:0:0:0:0:0:0:1
    let expanded = expand_ipv6(addr);
    expanded == [0, 0, 0, 0, 0, 0, 0, 1]
}

/// Extract IPv4 address from an IPv4-mapped IPv6 address.
/// ::ffff:127.0.0.1 → Some("127.0.0.1")
/// ::ffff:7f00:1 → Some("127.0.0.1")
/// 0:0:0:0:0:ffff:a9fe:a9fe → Some("169.254.169.254")
fn extract_ipv4_mapped(addr: &str) -> Option<String> {
    let segments = expand_ipv6(addr);

    // IPv4-mapped: first 5 segments zero, 6th = 0xffff
    if segments[0..5] != [0, 0, 0, 0, 0] || segments[5] != 0xffff {
        return None;
    }

    // Check if the original has dotted-decimal notation (::ffff:1.2.3.4)
    if let Some(dot_pos) = addr.rfind('.') {
        // Find the IPv4 part after the last colon before the dotted section
        let colon_before_v4 = addr[..dot_pos].rfind(':').unwrap_or(0);
        let v4_str = &addr[colon_before_v4 + 1..];
        if v4_str.contains('.') {
            return Some(v4_str.to_string());
        }
    }

    // Hex form: segments 6 and 7 encode the IPv4 address
    let a = (segments[6] >> 8) as u8;
    let b = (segments[6] & 0xff) as u8;
    let c = (segments[7] >> 8) as u8;
    let d = (segments[7] & 0xff) as u8;
    Some(format!("{}.{}.{}.{}", a, b, c, d))
}

/// Check if an IPv6 address is a known cloud metadata endpoint.
fn is_cloud_metadata_ipv6(addr: &str) -> bool {
    let segments = expand_ipv6(addr);
    // AWS IPv6 metadata: fd00:ec2::254
    // Expanded: fd00:ec2:0:0:0:0:0:254 → [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
    if segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
        return true;
    }
    false
}

/// Expand an IPv6 address string into 8 u16 segments.
/// Handles :: zero-compression and IPv4-mapped dotted notation.
fn expand_ipv6(addr: &str) -> [u16; 8] {
    let mut result = [0u16; 8];

    // Handle IPv4-mapped with dotted notation (e.g., ::ffff:127.0.0.1)
    let (ipv6_part, ipv4_tail) = if let Some(last_colon) = addr.rfind(':') {
        let after = &addr[last_colon + 1..];
        if after.contains('.') {
            // Parse IPv4 part
            let parts: Vec<&str> = after.split('.').collect();
            if parts.len() == 4 {
                if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                    parts[0].parse::<u8>(),
                    parts[1].parse::<u8>(),
                    parts[2].parse::<u8>(),
                    parts[3].parse::<u8>(),
                ) {
                    let seg6 = ((a as u16) << 8) | (b as u16);
                    let seg7 = ((c as u16) << 8) | (d as u16);
                    (&addr[..last_colon], Some((seg6, seg7)))
                } else {
                    (addr, None)
                }
            } else {
                (addr, None)
            }
        } else {
            (addr, None)
        }
    } else {
        (addr, None)
    };

    // Split on :: for zero-compression
    let parts: Vec<&str> = ipv6_part.split("::").collect();
    let max_segments = if ipv4_tail.is_some() { 6 } else { 8 };

    match parts.len() {
        1 => {
            // No :: — parse all segments
            for (i, seg) in parts[0].split(':').enumerate() {
                if i < max_segments && !seg.is_empty() {
                    result[i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }
        }
        2 => {
            // Has :: — left segments + gap + right segments
            let left: Vec<&str> = if parts[0].is_empty() {
                vec![]
            } else {
                parts[0].split(':').collect()
            };
            let right: Vec<&str> = if parts[1].is_empty() {
                vec![]
            } else {
                parts[1].split(':').collect()
            };

            for (i, seg) in left.iter().enumerate() {
                if !seg.is_empty() {
                    result[i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }

            let right_start = max_segments - right.len();
            for (i, seg) in right.iter().enumerate() {
                if !seg.is_empty() {
                    result[right_start + i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }
        }
        _ => {} // Invalid — return all zeros
    }

    if let Some((seg6, seg7)) = ipv4_tail {
        result[6] = seg6;
        result[7] = seg7;
    }

    result
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
        let dir = tempfile::tempdir().expect("temp directory creation must succeed");
        let path = dir.path().join("test_srr.toml");
        std::fs::write(&path, toml_str).expect("writing SRR TOML to temp file must succeed");
        NetworkSRR::load(&path).expect("valid SRR TOML must load")
    }

    // ── Test 1: Payload > max_body_bytes → skips to next rule (continue, not return) ──

    #[test]
    fn payload_exceeding_max_body_bytes_skips_to_next_rule() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 100
            decision = { type = "Deny", reason = "Dangerous GraphQL" }

            [[rules]]
            method = "POST"
            pattern = "api.bank.com/{any}"
            decision = { type = "Delay", milliseconds = 500 }
        "#);

        // Body is 200 bytes — exceeds max_body_bytes (100)
        let big_body = vec![b'x'; 200];

        let result = srr.check("POST", "api.bank.com", "/graphql", Some(&big_body));

        // Must NOT crash. Must skip the payload rule and match the URL-only rule.
        match result.decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 500, "Should fall through to URL-only rule");
            }
            other => panic!(
                "Expected Delay 500ms (fallthrough to URL-only rule), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn payload_exceeding_max_body_bytes_no_fallback_gets_default_caution() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 100
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#);

        // Body exceeds limit, no fallback rule → Default-to-Caution
        let big_body = vec![b'x'; 200];
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(&big_body));

        match result.decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300, "No fallback rule → Default-to-Caution");
            }
            other => panic!("Expected Default-to-Caution, got {:?}", other),
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

        let result = srr.check("POST", "api.bank.com", "/graphql", Some(body));
        match result.decision {
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
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(&huge_body));

        // Must return Default-to-Caution, not crash
        match result.decision {
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
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(bad_json));

        match result.decision {
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
        let result = srr.check("POST", "api.bank.com", "/graphql", None);

        match result.decision {
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
        let result = srr.check("POST", "api.bank.com", "/transfer/123", None);

        match result.decision {
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
        let result = srr.check("GET", "totally-unknown.com", "/some/path", None);

        match result.decision {
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

        for (i, r) in [d1, d2, d3].iter().enumerate() {
            match &r.decision {
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
        let result = srr.check("GET", "api.bank.com", "/transfer/123", None);

        match result.decision {
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
            let result = srr.check(method, "evil.com", "/anything", None);
            match result.decision {
                EnforcementDecision::Deny { .. } => {}
                other => panic!("{} should be denied for evil.com, got {:?}", method, other),
            }
        }
    }

    // ── Test 11: Port number stripped before host matching ──

    #[test]
    fn host_with_port_matches_exact_pattern() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // Host with port — must match "api.bank.com" pattern
        let result = srr.check("POST", "api.bank.com:443", "/transfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { reason } => {
                assert!(reason.contains("Wire transfer"));
            }
            other => panic!("Host with port should match exact pattern, got {:?}", other),
        }
    }

    #[test]
    fn host_with_port_matches_suffix_pattern() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "DELETE"
            pattern = "{host}.database.com/{any}"
            decision = { type = "Deny", reason = "Database deletion blocked" }
        "#);

        let result = srr.check("DELETE", "prod.database.com:5432", "/users/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!("Host with port should match suffix pattern, got {:?}", other),
        }
    }

    // ── Path normalization tests ──

    #[test]
    fn percent_encoded_path_is_decoded_before_matching() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // %2F = /, %74 = t, etc. — encoded path that resolves to /transfer/123
        let result = srr.check("POST", "api.bank.com", "/%74ransfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!("Percent-encoded path must be decoded before matching, got: {:?}", other),
        }
    }

    #[test]
    fn double_slash_collapsed_before_matching() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        let result = srr.check("POST", "api.bank.com", "//transfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!("Double slash must be collapsed, got: {:?}", other),
        }
    }

    #[test]
    fn dot_segment_traversal_does_not_bypass_deny() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);

        // /safe/../transfer/123 resolves to /transfer/123
        let result = srr.check("POST", "api.bank.com", "/safe/../transfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!("Dot-segment traversal must not bypass deny, got: {:?}", other),
        }
    }

    #[test]
    fn already_canonical_path_no_allocation() {
        // Verify normalize_path returns None for clean paths (no allocation)
        assert!(normalize_path("/transfer/123").is_none());
        assert!(normalize_path("/").is_none());
        assert!(normalize_path("/a/b/c").is_none());
    }

    #[test]
    fn normalize_path_handles_edge_cases() {
        // Percent-encoded slash
        assert_eq!(normalize_path("/a%2Fb").expect("percent-encoded path must normalize"), "/a/b");

        // Double dot at end
        assert_eq!(normalize_path("/a/b/..").expect("dot-segment path must normalize"), "/a");

        // Multiple consecutive slashes
        assert_eq!(normalize_path("///a///b///").expect("multi-slash path must normalize"), "/a/b/");

        // Single dot
        assert_eq!(normalize_path("/a/./b").expect("dot path must normalize"), "/a/b");

        // Null byte removal
        assert_eq!(normalize_path("/a\0b").expect("null-byte path must normalize"), "/ab");
    }

    // ── Test: SrrCheckResult metadata ──

    // ── Path regex tests ──

    #[test]
    fn path_regex_matches_versioned_api() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "GET"
            pattern = "api.example.com"
            path_regex = "^/api/v[1-3]/users/.*"
            decision = { type = "Delay", milliseconds = 500 }
            description = "Versioned API rate limit"
        "#);

        // v1, v2, v3 should match
        for v in &["v1", "v2", "v3"] {
            let path = format!("/api/{}/users/123", v);
            let r = srr.check("GET", "api.example.com", &path, None);
            match r.decision {
                EnforcementDecision::Delay { milliseconds } => {
                    assert_eq!(milliseconds, 500, "Path {} should match regex", path);
                }
                other => panic!("Path {} should match regex, got {:?}", path, other),
            }
        }

        // v4 should NOT match → default-to-caution (300ms)
        let r = srr.check("GET", "api.example.com", "/api/v4/users/123", None);
        match r.decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(milliseconds, 300, "v4 should not match [1-3] regex");
            }
            other => panic!("v4 should get default-to-caution, got {:?}", other),
        }
    }

    #[test]
    fn path_regex_deny_sensitive_endpoints() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "*"
            pattern = "{any}"
            path_regex = "(?i)/(admin|internal|debug)(/|$)"
            decision = { type = "Deny", reason = "Sensitive endpoint blocked" }
            description = "Block admin/internal/debug paths"

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
        "#);

        // Should be denied
        for path in &["/admin", "/admin/settings", "/internal/", "/debug/pprof"] {
            let r = srr.check("GET", "any.com", path, None);
            assert!(
                matches!(r.decision, EnforcementDecision::Deny { .. }),
                "Path {} should be denied by regex", path
            );
        }

        // Should NOT be denied (no match)
        for path in &["/api/users", "/administrator", "/public/debug-info"] {
            let r = srr.check("GET", "any.com", path, None);
            assert!(
                !matches!(r.decision, EnforcementDecision::Deny { .. }),
                "Path {} should not be denied", path
            );
        }
    }

    #[test]
    fn path_regex_combined_with_host_pattern() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "{host}.database.com"
            path_regex = "^/(drop|truncate|delete)/"
            decision = { type = "Deny", reason = "Destructive DB operation" }
        "#);

        // Matching host + regex path → Deny
        let r = srr.check("POST", "prod.database.com", "/drop/users", None);
        assert!(matches!(r.decision, EnforcementDecision::Deny { .. }));

        // Matching host + non-matching path → Default-to-Caution
        let r = srr.check("POST", "prod.database.com", "/select/users", None);
        assert!(matches!(r.decision, EnforcementDecision::Delay { .. }));

        // Non-matching host → Default-to-Caution
        let r = srr.check("POST", "other.com", "/drop/users", None);
        assert!(matches!(r.decision, EnforcementDecision::Delay { .. }));
    }

    #[test]
    fn path_regex_invalid_pattern_rejected_at_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bad_regex.toml");
        std::fs::write(&path, r#"
            [[rules]]
            method = "GET"
            pattern = "example.com"
            path_regex = "[invalid(regex"
            decision = { type = "Deny", reason = "Should not load" }
        "#).unwrap();

        let result = NetworkSRR::load(&path);
        assert!(result.is_err(), "Invalid regex must be rejected at load time");
    }

    #[test]
    fn path_regex_with_catch_all_is_not_catch_all() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "*"
            pattern = "{any}"
            path_regex = "^/api/"
            decision = { type = "Delay", milliseconds = 500 }
            description = "API rate limit"
        "#);

        let r = srr.check("GET", "any.com", "/api/users", None);
        assert!(!r.is_catch_all, "Regex rule with wildcard host should not be catch-all");
    }

    #[test]
    fn explicit_rule_match_is_not_catch_all() {
        let srr = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
            description = "Block wire transfers"

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
            description = "Default-to-Caution"
        "#);

        // Explicit rule match
        let r1 = srr.check("POST", "api.bank.com", "/transfer/123", None);
        assert!(!r1.is_catch_all, "Explicit rule must not be flagged as catch-all");
        assert_eq!(r1.matched_description.as_deref(), Some("Block wire transfers"));

        // Catch-all match
        let r2 = srr.check("GET", "unknown.com", "/any", None);
        assert!(r2.is_catch_all, "Catch-all rule must be flagged");

        // Built-in default (no rules match at all)
        let srr_no_catchall = srr_from_toml(r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#);
        let r3 = srr_no_catchall.check("GET", "unknown.com", "/any", None);
        assert!(r3.is_catch_all, "Built-in default must be flagged as catch-all");
        assert!(r3.matched_description.is_none(), "Built-in default has no description");
    }
}
