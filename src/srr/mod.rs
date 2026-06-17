use crate::types::EnforcementDecision;
use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Timelike, Utc};
use gvm_types::split_host_port;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

mod normalize;
#[cfg(test)]
use normalize::expand_ipv6;
use normalize::{normalize_host, normalize_path};

// ─── Network SRR (PART 4) ───

/// Network-level SRR rule from TOML config
#[derive(Deserialize, Clone, Debug)]
pub struct NetworkRuleConfig {
    pub method: String,
    pub pattern: String,
    pub decision: NetworkDecisionConfig,
    /// Optional regex pattern for path matching (overrides path portion of `pattern`).
    /// Compiled at load time using Rust's `regex` crate (automata-based, O(n) guaranteed).
    /// Example: `"^/api/v[1-3]/users/.*"` matches /api/v1/users/, /api/v2/users/foo, etc.
    pub path_regex: Option<String>,
    /// Optional payload field for GraphQL/gRPC defense
    pub payload_field: Option<String>,
    /// Payload values to match against
    pub payload_match: Option<Vec<String>>,
    /// GraphQL alias-bypass defense (`docs/srr.md §3.6`,
    /// `docs/internal/COVERAGE_HARDENING_PLAN.md △-10`).
    ///
    /// When set, SRR scans the request body's top-level `query`
    /// JSON field for any GraphQL mutation/query invocation
    /// whose **field name** matches an entry in this list,
    /// regardless of `operationName` or alias prefix. Catches:
    /// `mutation { x: transferFunds(...) }` (aliased),
    /// `mutation { transferFunds(...) }` (direct),
    /// `mutation Op { transferFunds(...) }` (named operation,
    /// even if `operationName` is omitted from the JSON envelope).
    ///
    /// The matcher is a narrow lexer
    /// ([`scan_graphql_query_for_invocation`]): comments + string
    /// literals are stripped, then identifier tokens are compared
    /// against the supplied names with whole-word matching. Pair
    /// with a URL-level Deny on the same endpoint for
    /// defense-in-depth — a malformed query that the lexer cannot
    /// parse falls through to the URL rule rather than producing
    /// a false negative.
    pub payload_query_alias_match: Option<Vec<String>>,
    /// Max body bytes to inspect (default 64KB)
    pub max_body_bytes: Option<usize>,
    /// Fail-close action for rules whose body-inspection branch
    /// cannot be evaluated. Fires when the body is present but the
    /// engine can't determine whether the rule applies — either the
    /// body exceeds `max_body_bytes` (inspection skipped) or neither
    /// the plain-JSON nor the base64-JSON parse succeeded
    /// (inspection performed and failed).
    ///
    /// `None` (default) preserves the legacy permissive behaviour:
    /// when inspection cannot run, the engine `continue`s to the
    /// next rule. `Some(action)` applies `action` immediately —
    /// typical use is `{ type = "Deny", reason = "..." }` or
    /// `{ type = "RequireApproval" }` for high-risk endpoints.
    ///
    /// Does NOT fire when the body is absent — a missing body is
    /// not an inspection failure; the rule's payload predicate
    /// trivially does not apply, so the engine falls through to
    /// URL-only rules for the same endpoint.
    pub unsafe_body_action: Option<NetworkDecisionConfig>,
    pub description: Option<String>,
    /// Human-readable label (used in warnings and logs)
    pub label: Option<String>,
    /// Optional gating condition. When set, the rule only fires if the
    /// condition matches against the request's evaluation timestamp.
    /// Today only `time_window` is defined; future variants land here.
    pub condition: Option<RuleConditionConfig>,
    /// Optional principal restriction. When set, the rule only fires
    /// for requests whose verified `agent_id` exactly equals this
    /// string (case-sensitive). When unset (default), the rule matches
    /// every principal — the legacy behaviour where `agent_id` was an
    /// audit label only.
    ///
    /// TOML:
    /// ```toml
    /// principal_filter = "agent:claims-reviewer-1842"
    /// ```
    ///
    /// Match contract: a rule with `principal_filter = Some(p)` matches
    /// only when the caller supplies `agent_id == Some(p)`. A rule
    /// keyed on a principal is skipped for unauthenticated traffic
    /// (`agent_id == None`) and for any other principal. This is the
    /// fail-close direction — a rule "for one agent" never accidentally
    /// fires for an unrelated agent or for traffic that hasn't
    /// established an identity yet.
    ///
    /// First cut is exact-match only. Glob / wildcard
    /// (`agent:claims-reviewer-*`) is scoped for a follow-up; exact
    /// match gives the strongest semantics and avoids smuggling via
    /// similar-named principals on day one.
    ///
    /// This promotes `agent_id` from an audit label to an SRR matching
    /// input — the missing piece for the lease primitive ([CHANGELOG.md]
    /// v0.7 roadmap). Combined with `expires_at`, a lease is "this
    /// principal may do these things until this instant."
    pub principal_filter: Option<String>,
    /// Optional absolute expiration. When set, the rule is skipped on
    /// any request whose evaluation timestamp is at or after `expires_at`.
    ///
    /// TOML accepts RFC 3339: `expires_at = "2026-07-01T15:00:00Z"`. The
    /// comparison uses the same `now` `check_at` already takes — so an
    /// auditor replaying the WAL against the same ruleset with the
    /// event's recorded timestamp reproduces the producer's decision
    /// exactly. No system-clock dependence at evaluation time.
    ///
    /// Semantics: half-open `[start_of_time, expires_at)` — at the moment
    /// `now == expires_at` the rule is considered expired (mirrors the
    /// time_window exclusive-end convention).
    ///
    /// Use case: orchestrator issues a 5-minute Allow rule after a human
    /// approves an IC-3 request, then forgets about cleanup — the rule
    /// silently disappears from matching once the clock crosses
    /// `expires_at`, no separate teardown call needed. This is the first
    /// building block of the lease primitive ([CHANGELOG.md] v0.7 roadmap).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// TOML-side condition config. Tagged enum; future variants (e.g.,
/// `request_count`, `header_value`) extend by adding new `kind` values.
#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleConditionConfig {
    /// Time-of-day window in a given timezone.
    /// `window` is `"HH:MM-HH:MM"`. Cross-midnight ranges (e.g., `"22:00-06:00"`)
    /// are allowed. `tz` is an IANA name (default `"UTC"`).
    /// `outside = true` inverts the match (fires when *outside* the window).
    TimeWindow {
        window: String,
        #[serde(default)]
        tz: Option<String>,
        #[serde(default)]
        outside: bool,
    },
}

#[derive(Deserialize, Clone, Debug)]
pub struct NetworkDecisionConfig {
    #[serde(rename = "type")]
    pub decision_type: String,
    pub milliseconds: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct NetworkSrrFile {
    /// `#[serde(default)]` lets an entirely empty file (or one that
    /// only contains comments) deserialize as `rules: vec![]` instead
    /// of failing with "missing field `rules`". Operators legitimately
    /// keep an empty rule file as a "no extra rules, defaults only"
    /// state — and `gvm suggest` may overwrite the file with content
    /// that has a leading TOML comment but no `rules =` line yet.
    /// Without the default, every such file fails proxy startup.
    #[serde(default)]
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
    /// Compiled list of mutation/query field names to match in the
    /// request body's GraphQL `query` field. See
    /// [`NetworkRuleConfig::payload_query_alias_match`].
    pub payload_query_alias_match: Option<Vec<String>>,
    pub max_body_bytes: usize,
    /// Fail-close action when body inspection cannot be evaluated.
    /// See [`NetworkRuleConfig::unsafe_body_action`].
    pub unsafe_body_action: Option<EnforcementDecision>,
    /// True if this rule is a catch-all (method="*" + pattern="{any}").
    /// Catch-all matches are flagged as default-to-caution for the CLI.
    pub is_catch_all: bool,
    /// Optional compiled gating condition. None = unconditional (legacy
    /// behaviour). Some(_) = rule fires only when the condition matches
    /// against the evaluation timestamp.
    pub condition: Option<Condition>,
    /// Optional absolute expiration. See [`NetworkRuleConfig::expires_at`].
    /// At or after this instant the rule does not match.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional principal restriction. See
    /// [`NetworkRuleConfig::principal_filter`].
    pub principal_filter: Option<String>,
}

/// Compiled gating condition. Pure function of (rule, evaluation timestamp).
///
/// **Determinism contract**: evaluation must be reproducible from the WAL.
/// `event.timestamp` is committed to the Merkle leaf in `compute_event_hash`,
/// so an auditor running `gvm replay --wal` against the same rule set with
/// `check_at(event.timestamp)` reproduces the producer's decision exactly,
/// no system-clock dependence. This is the same audit guarantee that
/// unconditional rules carry; the timestamp dependency adds no new trust
/// assumption because the timestamp is already anchor-signed.
#[derive(Clone, Debug)]
pub enum Condition {
    /// Time-of-day window match. Stored as minutes-from-midnight in the
    /// rule's timezone. Cross-midnight is encoded by `start_min > end_min`.
    TimeWindow {
        /// Inclusive start, in minutes from midnight (0..1440).
        start_min: u16,
        /// Exclusive end, in minutes from midnight (0..1440).
        end_min: u16,
        /// Timezone the operator wrote the window in.
        tz: chrono_tz::Tz,
        /// If true, condition matches when the time is *outside* the window.
        outside: bool,
    },
}

impl Condition {
    /// Evaluate the condition against an explicit timestamp. The caller
    /// passes the evaluation time — `Utc::now()` for live traffic, or
    /// `event.timestamp` for replay. No internal `now()` call.
    pub fn matches(&self, now: DateTime<Utc>) -> bool {
        match self {
            Condition::TimeWindow {
                start_min,
                end_min,
                tz,
                outside,
            } => {
                let local = now.with_timezone(tz);
                let mins = local.hour() * 60 + local.minute();
                let mins = mins as u16;
                let inside = if start_min <= end_min {
                    // Same-day window: [start, end)
                    mins >= *start_min && mins < *end_min
                } else {
                    // Cross-midnight window: [start, 24:00) ∪ [0:00, end)
                    mins >= *start_min || mins < *end_min
                };
                inside != *outside
            }
        }
    }
}

/// Parse a `"HH:MM-HH:MM"` window into `(start_min, end_min)` in
/// minutes-from-midnight. Rejects malformed input — operator config
/// errors fail fast at load.
fn parse_time_window(window: &str) -> Result<(u16, u16)> {
    let (start, end) = window
        .split_once('-')
        .with_context(|| format!("time window must be HH:MM-HH:MM, got '{}'", window))?;
    let start_min = parse_hhmm(start.trim())
        .with_context(|| format!("invalid window start '{}' in '{}'", start, window))?;
    let end_min = parse_hhmm(end.trim())
        .with_context(|| format!("invalid window end '{}' in '{}'", end, window))?;
    if start_min == end_min {
        anyhow::bail!(
            "time window '{}' has zero duration (start equals end); \
             use a non-empty range or omit the condition",
            window
        );
    }
    Ok((start_min, end_min))
}

fn parse_hhmm(s: &str) -> Result<u16> {
    let (h, m) = s
        .split_once(':')
        .with_context(|| format!("expected HH:MM, got '{}'", s))?;
    let h: u16 = h
        .parse()
        .with_context(|| format!("invalid hour '{}' in '{}'", h, s))?;
    let m: u16 = m
        .parse()
        .with_context(|| format!("invalid minute '{}' in '{}'", m, s))?;
    if h >= 24 {
        anyhow::bail!("hour must be 0..23, got {}", h);
    }
    if m >= 60 {
        anyhow::bail!("minute must be 0..59, got {}", m);
    }
    Ok(h * 60 + m)
}

/// Compile a TOML-side condition into the runtime form. Errors here
/// fail config load — fail-fast over silent rule omission.
fn compile_condition(cfg: &RuleConditionConfig) -> Result<Condition> {
    match cfg {
        RuleConditionConfig::TimeWindow {
            window,
            tz,
            outside,
        } => {
            let (start_min, end_min) = parse_time_window(window)?;
            let tz_name = tz.as_deref().unwrap_or("UTC");
            let tz: chrono_tz::Tz = tz_name.parse().map_err(|_| {
                anyhow::anyhow!(
                    "unknown timezone '{}'. Use IANA names like 'Asia/Seoul', 'America/New_York', 'UTC'",
                    tz_name
                )
            })?;
            Ok(Condition::TimeWindow {
                start_min,
                end_min,
                tz,
                outside: *outside,
            })
        }
    }
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

/// Host matching pattern with optional port constraint.
///
/// `port` follows Max-Strict semantics. `None` means "any port" — the
/// pattern matches whatever port the request used. `Some(p)` means
/// "port `p` only" — the request must use that exact port. Standard
/// ports (80 for HTTP, 443 for HTTPS) are normalised to `None` at
/// pattern compile time so that a pattern of "api.example.com:443"
/// matches both "api.example.com" and "api.example.com:443" — the
/// explicit port is redundant for the default-port case.
#[derive(Clone, Debug)]
pub enum HostPattern {
    /// Exact host match: "api.bank.com"
    Exact { host: String, port: Option<u16> },
    /// Suffix match: "{host}.database.com" → *.database.com
    Suffix { suffix: String, port: Option<u16> },
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

        // Defense in depth: reject SRR files containing ASCII control bytes
        // other than whitespace. The trigger is `gvm suggest > srr.toml` in
        // a shell that merges stderr into stdout (e.g. `2>&1`, some CI
        // capture wrappers), which used to embed an ANSI-coloured summary
        // line into the rule file. The TOML crate handled the resulting
        // ESC (0x1b) bytes inconsistently — some versions returned an
        // empty rule set silently, which left the proxy running with zero
        // governance rules and no error surface. That violates fail-close
        // ([CLAUDE.md](docs/internal/GVM_CODE_STANDARDS.md)). Fail loudly
        // here so the operator sees the file is corrupted before any
        // request is mis-classified.
        for (lineno, line) in content.lines().enumerate() {
            for (col, byte) in line.bytes().enumerate() {
                let is_control = byte < 0x20 && byte != b'\t';
                let is_del = byte == 0x7f;
                if is_control || is_del {
                    anyhow::bail!(
                        "SRR file {} contains a control byte (0x{:02x}) at line {}, column {}. \
                         This usually means terminal escape codes leaked into the file — \
                         likely `gvm suggest` was invoked with stderr merged into stdout \
                         (`2>&1`). Re-generate the file without merging stderr.",
                        path.display(),
                        byte,
                        lineno + 1,
                        col + 1,
                    );
                }
            }
        }

        let file: NetworkSrrFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse SRR file: {}", path.display()))?;

        // Final fail-close check: if the file textually contains at least
        // one `[[rules]]` array-of-tables header but the parser handed
        // back zero rules, those rules were silently dropped — refuse
        // rather than serve traffic with an empty governance set.
        //
        // We deliberately do NOT bail just because the file is "big and
        // empty" — operators legitimately keep `rules = []` placeholders
        // (Test 82's baseline writes exactly that), and rule-free files
        // with only comments and an empty array are 100+ bytes. Counting
        // `[[rules]]` headers in the raw text is the precise signal: if
        // none are present, the file is legitimately rule-free; if any
        // are present but `file.rules` is empty, something corrupted the
        // entries between disk and the deserialised struct.
        let textual_rule_blocks = content.matches("[[rules]]").count();
        if file.rules.is_empty() && textual_rule_blocks > 0 {
            anyhow::bail!(
                "SRR file {} contains {} [[rules]] block(s) in the source text \
                 but parsed to zero rules. The TOML loader likely dropped \
                 malformed entries silently. Inspect the file for stray \
                 non-ASCII bytes or unexpected sections.",
                path.display(),
                textual_rule_blocks,
            );
        }

        let mut rules = Vec::new();

        for rule_cfg in &file.rules {
            let decision = parse_decision(&rule_cfg.decision)?;
            let (host_pattern, path_pattern) = parse_pattern(&rule_cfg.pattern);

            // Compile the optional fail-close action at load time so any
            // typo in `type = "..."` surfaces at proxy startup, not at the
            // first request that hits the rule.
            let unsafe_body_action = match &rule_cfg.unsafe_body_action {
                Some(cfg) => Some(parse_decision(cfg)?),
                None => None,
            };

            // Pre-compile gating condition at load time (fail-fast on bad windows / tz)
            let condition = match &rule_cfg.condition {
                Some(c) => Some(compile_condition(c)?),
                None => None,
            };

            // Pre-compile path regex at load time (fail-fast on invalid patterns)
            let compiled_path_regex = match &rule_cfg.path_regex {
                Some(pattern) => {
                    const MAX_REGEX_LEN: usize = 10_000;
                    if pattern.len() > MAX_REGEX_LEN {
                        anyhow::bail!(
                            "path_regex too long in SRR rule: {} > {} bytes",
                            pattern.len(),
                            MAX_REGEX_LEN
                        );
                    }
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
                    payload_query_alias_match: rule_cfg.payload_query_alias_match.clone(),
                    max_body_bytes: rule_cfg.max_body_bytes.unwrap_or(65536),
                    unsafe_body_action: unsafe_body_action.clone(),
                    is_catch_all,
                    condition: condition.clone(),
                    expires_at: rule_cfg.expires_at,
                    principal_filter: rule_cfg.principal_filter.clone(),
                });
            }
        }

        // Detect unreachable rules: any rule after a catch-all is unreachable
        // for the methods that the catch-all covers. Static analysis at load time.
        {
            // Track which methods have a catch-all (host=Any, path=/*) preceding them
            let mut catchall_methods: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            for (idx, rule_cfg) in file.rules.iter().enumerate() {
                let (host_pat, path_pat) = parse_pattern(&rule_cfg.pattern);
                let is_catchall = matches!(host_pat, HostPattern::Any)
                    && (path_pat == "/*" || path_pat == "*")
                    && rule_cfg.path_regex.is_none();
                let label = rule_cfg
                    .label
                    .as_deref()
                    .or(rule_cfg.description.as_deref())
                    .unwrap_or("(unnamed)");

                if is_catchall {
                    // Record this catch-all for its methods
                    if rule_cfg.method == "*" {
                        for m in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
                            catchall_methods
                                .entry(m.to_string())
                                .or_insert_with(|| label.to_string());
                        }
                    } else {
                        catchall_methods
                            .entry(rule_cfg.method.to_uppercase())
                            .or_insert_with(|| label.to_string());
                    }
                } else if !catchall_methods.is_empty() {
                    // Check if this rule's methods are all covered by a preceding catch-all
                    let methods: Vec<String> = if rule_cfg.method == "*" {
                        vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                            .into_iter()
                            .map(String::from)
                            .collect()
                    } else {
                        vec![rule_cfg.method.to_uppercase()]
                    };

                    for method in &methods {
                        if let Some(catchall_label) = catchall_methods.get(method) {
                            tracing::warn!(
                                rule = label,
                                rule_index = idx + 1,
                                catchall = %catchall_label,
                                method = %method,
                                "Unreachable rule — catch-all \"{catchall_label}\" matches all {method} \
                                 requests before this rule. Move specific rules before catch-all \
                                 (SRR is first-match)."
                            );
                            break; // One warning per rule is enough
                        }
                    }
                }
            }
        }

        tracing::info!(rules = rules.len(), "Network SRR rules compiled");

        Ok(Self {
            rules,
            default_decision: EnforcementDecision::Delay { milliseconds: 300 },
        })
    }

    /// Build a NetworkSRR engine from pre-parsed rule configs (e.g. from gvm.toml).
    /// Same compilation logic as `load()` but takes configs instead of reading a file.
    pub fn from_rule_configs(rule_configs: Vec<NetworkRuleConfig>) -> Result<Self> {
        let mut rules = Vec::new();

        for rule_cfg in &rule_configs {
            let decision = parse_decision(&rule_cfg.decision)?;
            let (host_pattern, path_pattern) = parse_pattern(&rule_cfg.pattern);

            let unsafe_body_action = match &rule_cfg.unsafe_body_action {
                Some(cfg) => Some(parse_decision(cfg)?),
                None => None,
            };

            let condition = match &rule_cfg.condition {
                Some(c) => Some(compile_condition(c)?),
                None => None,
            };

            let compiled_path_regex = match &rule_cfg.path_regex {
                Some(pattern) => {
                    const MAX_REGEX_LEN: usize = 10_000;
                    if pattern.len() > MAX_REGEX_LEN {
                        anyhow::bail!(
                            "path_regex too long in SRR rule: {} > {} bytes",
                            pattern.len(),
                            MAX_REGEX_LEN
                        );
                    }
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
                    payload_query_alias_match: rule_cfg.payload_query_alias_match.clone(),
                    max_body_bytes: rule_cfg.max_body_bytes.unwrap_or(65536),
                    unsafe_body_action: unsafe_body_action.clone(),
                    is_catch_all,
                    condition: condition.clone(),
                    expires_at: rule_cfg.expires_at,
                    principal_filter: rule_cfg.principal_filter.clone(),
                });
            }
        }

        tracing::info!(
            rules = rules.len(),
            "Network SRR rules compiled from gvm.toml"
        );

        Ok(Self {
            rules,
            default_decision: EnforcementDecision::Delay { milliseconds: 300 },
        })
    }

    /// Override the default decision for unmatched URLs (Default-to-Caution).
    /// Called after loading to apply the config's `default_unknown` setting.
    pub fn set_default_decision(&mut self, decision: EnforcementDecision) {
        self.default_decision = decision;
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
                            HostPattern::Exact { host: h, port } => match port {
                                Some(p) => format!("{}:{}", h, p),
                                None => h.clone(),
                            },
                            HostPattern::Suffix { suffix: s, port } => match port {
                                Some(p) => format!("*{}:{}", s, p),
                                None => format!("*{}", s),
                            },
                            HostPattern::Any => "*".to_string(),
                        };
                        sample_denies
                            .push(format!("{} {}{}", rule.method, host, rule.path_pattern));
                    }
                }
                EnforcementDecision::Delay { .. } => delay += 1,
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
    /// Number of loaded rules (for info/reload reporting).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Extract all exact-match host domains from loaded rules.
    /// Used by MITM cert pre-warm to generate leaf certs at startup.
    /// Port qualifiers are dropped — cert SAN matches by hostname only.
    pub fn known_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .rules
            .iter()
            .filter_map(|r| match &r.host_pattern {
                HostPattern::Exact { host, .. } => Some(host.clone()),
                _ => None,
            })
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Domain-level check for CONNECT tunnels.
    /// If any non-catch-all rule exists for this host, Allow the tunnel.
    /// If only Deny rules exist, Deny. Otherwise Default-to-Caution.
    pub fn check_domain(&self, host: &str) -> (EnforcementDecision, Option<String>, bool) {
        let effective_host = host.to_lowercase();
        let mut has_allow = false;
        let mut has_any = false;
        let mut deny_reason = None;
        let mut matched: Option<String> = None;

        for rule in &self.rules {
            // Skip catch-all rules AND rules with wildcard host patterns.
            // CONNECT only has domain info (no method/path), so we only consider
            // rules that target THIS specific domain. A "DELETE {any}" rule should
            // NOT block CONNECT to api.anthropic.com — CONNECT might be for GET.
            let is_wildcard_host = matches!(rule.host_pattern, HostPattern::Any);
            if rule.is_catch_all
                || is_wildcard_host
                || !match_host(&rule.host_pattern, &effective_host)
            {
                continue;
            }
            has_any = true;
            match &rule.decision {
                EnforcementDecision::Deny { reason } => {
                    deny_reason = Some(reason.clone());
                    matched = Some(rule.description.clone());
                }
                EnforcementDecision::Allow => {
                    has_allow = true;
                    matched = Some(rule.description.clone());
                }
                _ => {
                    has_allow = true;
                    if matched.is_none() {
                        matched = Some(rule.description.clone());
                    }
                }
            }
        }

        if !has_any {
            return (self.default_decision.clone(), None, true);
        }
        if has_allow {
            (EnforcementDecision::Allow, matched, false)
        } else if let Some(r) = deny_reason {
            (EnforcementDecision::Deny { reason: r }, matched, false)
        } else {
            (self.default_decision.clone(), matched, true)
        }
    }

    /// Check a request, using `Utc::now()` as the evaluation timestamp.
    ///
    /// For replay (`gvm replay --wal`), use [`check_at`] with `event.timestamp`
    /// instead — that produces a deterministic decision recoverable from the
    /// audit chain alone, with no system-clock dependence.
    pub fn check(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> SrrCheckResult {
        self.check_at_with_principal(method, host, path, body, None, Utc::now())
    }

    /// Check a request with an explicit verified principal (`agent_id`).
    ///
    /// Use this from request handlers that resolve the caller's identity
    /// from JWT or the sandbox veth peer-IP → agent_id table before
    /// running enforcement. Rules carrying `principal_filter` only match
    /// when this argument is `Some(matching_id)`.
    ///
    /// Passing `None` is the same as calling [`check`] — rules with
    /// `principal_filter` are skipped (fail-closed for principal-bound
    /// rules under anonymous traffic).
    pub fn check_with_principal(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
        agent_id: Option<&str>,
    ) -> SrrCheckResult {
        self.check_at_with_principal(method, host, path, body, agent_id, Utc::now())
    }

    /// Check a request at an explicit evaluation timestamp.
    ///
    /// `now` is the time used to evaluate any [`Condition`] gates on rules.
    /// Producers pass `Utc::now()`; replay tools pass `event.timestamp`.
    /// Time-conditioned rules whose condition does not match are skipped
    /// (treated as if they did not match — fall through to the next rule).
    pub fn check_at(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
        now: DateTime<Utc>,
    ) -> SrrCheckResult {
        self.check_at_with_principal(method, host, path, body, None, now)
    }

    /// Full check entry point — explicit principal + explicit timestamp.
    /// All other entry points (`check`, `check_with_principal`, `check_at`)
    /// funnel through this method.
    pub fn check_at_with_principal(
        &self,
        method: &str,
        host: &str,
        path: &str,
        body: Option<&[u8]>,
        agent_id: Option<&str>,
        now: DateTime<Utc>,
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

            // Principal filter: if the rule is keyed on a specific agent
            // identity, only that agent's traffic should fire it. A rule
            // with `principal_filter = Some(p)` is skipped for any caller
            // whose `agent_id` is `None` (no verified identity) or any
            // other principal. Rules without `principal_filter` match
            // every caller (legacy behaviour preserved). One string
            // comparison; no allocation.
            if let Some(required) = &rule.principal_filter {
                match agent_id {
                    Some(supplied) if supplied == required.as_str() => { /* match */ }
                    _ => continue,
                }
            }

            // Expiration: a rule whose `expires_at` is at or before the
            // evaluation timestamp is dead. Cheaper than the gating
            // condition below — a single DateTime comparison — so it
            // goes here, right after the method/host filter. Half-open
            // semantics: rule is valid for `now < expires_at`.
            if let Some(deadline) = rule.expires_at {
                if now >= deadline {
                    continue;
                }
            }

            // Gating condition: a time-window rule that doesn't match the
            // evaluation timestamp falls through. Evaluated AFTER method/host
            // (cheap) but BEFORE path/regex/payload (expensive) — minute-cost
            // path is for rules that already passed the cheap filters and
            // are about to do work.
            if let Some(cond) = &rule.condition {
                if !cond.matches(now) {
                    continue;
                }
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
            //
            // The rule needs payload inspection if it has either the
            // legacy `payload_field` + `payload_match` pair OR the
            // newer `payload_query_alias_match` (GraphQL alias-bypass
            // defense, △-10). Both are evaluated when configured;
            // either one matching short-circuits to a Deny.
            let needs_payload = (rule.payload_field.is_some() && rule.payload_match.is_some())
                || rule.payload_query_alias_match.is_some();
            if needs_payload {
                let Some(body_bytes) = body else {
                    // No body for inspection — continue
                    continue;
                };
                if body_bytes.len() > rule.max_body_bytes {
                    // Body too large for this rule's payload inspection.
                    // Two paths:
                    //   - `unsafe_body_action` set on the rule: this is the
                    //     fail-close hook. The operator has declared "I'd
                    //     rather block / approval-gate this endpoint than
                    //     let an oversized body slip past inspection."
                    //   - Otherwise: legacy permissive behaviour — continue
                    //     to next rule so URL-only rules for the same
                    //     endpoint can still match.
                    tracing::warn!(
                        body_len = body_bytes.len(),
                        max_body_bytes = rule.max_body_bytes,
                        rule = %rule.description,
                        "Body exceeds max_body_bytes; payload inspection skipped"
                    );
                    if let Some(action) = &rule.unsafe_body_action {
                        return SrrCheckResult {
                            decision: action.clone(),
                            matched_description: Some(format!(
                                "{} (unsafe_body_action — body exceeds max_body_bytes)",
                                rule.description
                            )),
                            is_catch_all: rule.is_catch_all,
                        };
                    }
                    continue;
                }

                // Try JSON parsing first (normal case)
                let json_result = serde_json::from_slice::<serde_json::Value>(body_bytes);

                // If JSON parse fails, try Base64-decoding the body first
                let decoded_json = if json_result.is_err() {
                    base64::engine::general_purpose::STANDARD
                        .decode(
                            body_bytes
                                .iter()
                                .copied()
                                .filter(|b| !b.is_ascii_whitespace())
                                .collect::<Vec<u8>>(),
                        )
                        .ok()
                        .and_then(|decoded| {
                            serde_json::from_slice::<serde_json::Value>(&decoded).ok()
                        })
                } else {
                    None
                };

                let json_val = json_result.ok().or(decoded_json);

                if let Some(json) = json_val {
                    // ── Layer 1: legacy field-value match (operationName etc.) ──
                    if let (Some(field), Some(matches)) = (&rule.payload_field, &rule.payload_match)
                    {
                        // Check the target field value
                        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
                            if matches.iter().any(|m| m == value) {
                                return SrrCheckResult {
                                    decision: rule.decision.clone(),
                                    matched_description: Some(rule.description.clone()),
                                    is_catch_all: rule.is_catch_all,
                                };
                            }
                        }

                        // Also check if any string field value is Base64-encoded
                        // and contains a match when decoded
                        if let Some(value) = json.get(field).and_then(|v| v.as_str()) {
                            if let Ok(decoded) =
                                base64::engine::general_purpose::STANDARD.decode(value)
                            {
                                if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                                    if matches.iter().any(|m| decoded_str.contains(m.as_str())) {
                                        return SrrCheckResult {
                                            decision: rule.decision.clone(),
                                            matched_description: Some(rule.description.clone()),
                                            is_catch_all: rule.is_catch_all,
                                        };
                                    }
                                }
                            }
                        }
                    }

                    // ── Layer 2: GraphQL alias-bypass defense (△-10) ──
                    //
                    // Scan the body's `query` field for any invocation
                    // whose field name matches the configured list,
                    // regardless of `operationName` or alias prefix.
                    // Strips comments and string literals first so an
                    // attacker can't smuggle the name in a `# comment`
                    // or `"description"`.
                    if let Some(names) = &rule.payload_query_alias_match {
                        if let Some(query_str) = json.get("query").and_then(|v| v.as_str()) {
                            if scan_graphql_query_for_invocation(query_str, names) {
                                return SrrCheckResult {
                                    decision: rule.decision.clone(),
                                    matched_description: Some(rule.description.clone()),
                                    is_catch_all: rule.is_catch_all,
                                };
                            }
                        }
                    }
                } else if let Some(action) = &rule.unsafe_body_action {
                    // Body present but neither plain-JSON nor base64-JSON
                    // parse succeeded. Inspection performed and failed —
                    // apply fail-close action.
                    return SrrCheckResult {
                        decision: action.clone(),
                        matched_description: Some(format!(
                            "{} (unsafe_body_action — body unparseable as JSON)",
                            rule.description
                        )),
                        is_catch_all: rule.is_catch_all,
                    };
                }
                // Payload didn't match this rule — continue to next
                continue;
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
///
/// Pattern format: `[host[:port]]/path`. Examples:
///   "api.bank.com/transfer/{any}"      -> Exact("api.bank.com", None), "/transfer/*"
///   "api.bank.com:8080/api"            -> Exact("api.bank.com", Some(8080)), "/api"
///   "api.bank.com:443/api"             -> Exact("api.bank.com", None), "/api"
///                                          (default https port collapses to None)
///   "{host}.bank.com:9999/api"         -> Suffix(".bank.com", Some(9999)), "/api"
///   "{any}/anything"                   -> Any, "/anything"
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
    } else {
        // Split host:port BEFORE wildcard detection so authors can write
        // "{host}.bank.com:9999" without breaking on the colon.
        let (host_only, port) = split_host_port(host_part);
        // Standard ports collapse to None — "api.example.com:443" matches
        // requests for "api.example.com" too. Explicit ports stay set.
        let normalised_port = match port {
            Some(80) | Some(443) => None,
            other => other,
        };
        if host_only.starts_with("{") && host_only.contains('.') {
            // e.g. "{host}.database.com" → suffix match on ".database.com"
            let dot_idx = host_only.find('.').unwrap_or(0);
            HostPattern::Suffix {
                suffix: host_only[dot_idx..].to_lowercase(),
                port: normalised_port,
            }
        } else {
            HostPattern::Exact {
                host: host_only.to_lowercase(),
                port: normalised_port,
            }
        }
    };

    let path_pattern = path_part.replace("{any}", "*").to_string();

    (host_pattern, path_pattern)
}

/// Match a host:port authority against a HostPattern.
///
/// Port matching follows Max-Strict semantics. A pattern port of `None`
/// matches any request port; a pattern port of `Some(p)` matches only that
/// exact request port. Default ports (80 for HTTP, 443 for HTTPS) are
/// collapsed to `None` at compile time, so a pattern that omits the port
/// and a request that omits the port are equivalent for default-port traffic.
///
/// Caller must pass a pre-lowercased host (done once in `check()` for O(1) cost).
/// Patterns are lowercased at compile time in `parse_pattern()`.
fn match_host(pattern: &HostPattern, host: &str) -> bool {
    let (host_only, port) = split_host_port(host);
    // Normalise default ports the same way the pattern compile does so
    // a request to "api.example.com:443" matches a pattern that didn't
    // bother spelling out the default port.
    let request_port = match port {
        Some(80) | Some(443) => None,
        other => other,
    };

    match pattern {
        HostPattern::Exact {
            host: expected,
            port: pattern_port,
        } => {
            host_only == expected.as_str()
                && (pattern_port.is_none() || pattern_port == &request_port)
        }
        HostPattern::Suffix {
            suffix,
            port: pattern_port,
        } => {
            // Dot-boundary enforcement: suffix always starts with '.' from parse_pattern
            // (e.g., ".database.com"), so "attacker-database.com" cannot match —
            // it would need to end with ".database.com" which requires a dot boundary.
            host_only.ends_with(suffix.as_str())
                && (pattern_port.is_none() || pattern_port == &request_port)
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

/// Scan a GraphQL `query` body for any invocation whose field name
/// matches one of the configured names. Returns `true` on match.
///
/// Implements the GraphQL alias-bypass defense documented in
/// [`docs/srr.md §3.6`](../../../docs/srr.md) and tracked as `△-10`
/// in the coverage hardening plan. The scan:
///
/// 1. **Strips comments**: GraphQL line comments run from `#` to end
///    of line. Anything inside is ignored — an attacker cannot smuggle
///    `# transferFunds` as a no-op annotation that the lexer counts
///    as an invocation. Note that `#` inside a string literal is NOT
///    a comment; we handle this by stripping strings first.
/// 2. **Strips string literals**: Both single-line `"..."` and block
///    `"""..."""` strings have their contents removed. This prevents
///    an attacker from putting the dangerous mutation name inside a
///    `description` field of an introspection query and having it
///    flagged as an invocation. Escape-sequence handling is
///    deliberately conservative — a dangling backslash terminates
///    the string for our purposes.
/// 3. **Whole-word identifier match**: Once the comment-and-string
///    scrubbed input is in hand, scan for word-boundary matches of
///    each configured name. GraphQL identifiers are
///    `[_A-Za-z][_A-Za-z0-9]*`; we use that same alphabet for the
///    word boundary so `transferFundsExtra` does NOT match
///    `transferFunds` (no false positive on naming overlap), but
///    `: transferFunds(args)` and `t: transferFunds(args)` both do.
///
/// **Conservative bias**: when in doubt the scan favours **flagging**
/// over **passing**. A query the lexer cannot fully scrub (e.g. a
/// pathologically long string literal mid-truncation) falls through
/// to a no-match — but the URL-level Deny that operators are
/// instructed to pair this rule with still catches that path. Any
/// false positive blocks a benign query, which is the right
/// direction for security.
///
/// **Phase 1 → Phase 2 evolution**: the original Phase 1 scan
/// flagged any identifier matching the protected list anywhere in
/// the (scrubbed) query. That was conservative-correct — no false
/// negatives — but produced false positives when the protected
/// name appeared as an argument name (`mutation { x(transferFunds: 1) }`)
/// or a directive argument. Phase 2 (this implementation, △-10
/// follow-up) tracks structural state during the walk so identifiers
/// inside argument lists `(...)` and directive blocks `@name(...)`
/// are skipped — they cannot be selection field names by the
/// GraphQL grammar. False-negative resistance is preserved (every
/// genuine selection field name is still scanned); false-positive
/// rate drops materially on real-world queries that share argument
/// names with mutation names.
///
/// **Phase 2 limitations** (acceptable for the documented threat
/// model, tracked in `COVERAGE_HARDENING_PLAN.md △-10`):
///
/// - **Fragment definitions are scanned identically to operation
///   bodies**. A protected name inside `fragment Foo on T { ... }`
///   is detected — which means a fragment that defines an aliased
///   protected invocation, then is spread into the operation, is
///   caught. Distinguishing fragment-body selections from operation
///   selections (refining false-positive rate further) requires a
///   real GraphQL parser; tracked as a v0.7 line item.
/// - **Identifier matching is case-sensitive** (matches GraphQL
///   spec).
pub fn scan_graphql_query_for_invocation(query: &str, names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    let scrubbed = strip_graphql_comments_and_strings(query);
    // Build a HashSet for O(1) lookup; for typical name lists (1-10
    // entries) this is overkill but the cost is one allocation per
    // request and the SRR engine documents <1µs hot path budget.
    use std::collections::HashSet;
    let target: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
    let bytes = scrubbed.as_bytes();
    let mut i = 0;
    // Argument-list nesting depth. `>0` means we're inside `(...)`.
    // Identifiers inside argument lists are GraphQL argument names
    // or scalar values, never selection field names — skip them
    // for matching purposes, so e.g.
    //   mutation { wrapper(transferFunds: 1) { id } }
    // does NOT trip the scan on `transferFunds` here (it's an
    // argument name on `wrapper`, not an invocation).
    let mut paren_depth: u32 = 0;
    // Directive-context flag. After an `@`, we treat the following
    // identifier as a directive name (skipped) and any subsequent
    // `(...)` argument list as directive arguments (also skipped).
    // The flag clears once we leave the directive's argument list
    // or hit a non-`@` separator that isn't part of the directive.
    let mut in_directive_name = false;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' => {
                paren_depth = paren_depth.saturating_add(1);
                in_directive_name = false;
                i += 1;
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                in_directive_name = false;
                i += 1;
            }
            b'@' => {
                in_directive_name = true;
                i += 1;
            }
            b if b == b'_' || b.is_ascii_alphabetic() => {
                // Identifier. Read its full span, then decide whether
                // to treat it as a candidate selection field name.
                let start = i;
                while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                let ident = &scrubbed[start..i];
                let in_args = paren_depth > 0;
                let was_directive = in_directive_name;
                in_directive_name = false; // identifier consumes the directive flag
                                           // Skip identifiers that are:
                                           //   - Inside an argument list (arg names / scalar values)
                                           //   - The name immediately following `@` (directive name)
                if in_args || was_directive {
                    continue;
                }
                if target.contains(ident) {
                    return true;
                }
            }
            _ => {
                // Any other separator. Most don't need to clear
                // `in_directive_name` (e.g. whitespace right after
                // `@` is fine). The directive flag is cleared by
                // the next identifier or `(`.
                i += 1;
            }
        }
    }
    false
}

/// Strip GraphQL comments (`# ... \n`) and string literals
/// (single-line `"..."` and block `"""..."""`) from the input,
/// replacing them with single spaces so identifier boundaries
/// before/after a stripped span are preserved.
///
/// Internal helper for [`scan_graphql_query_for_invocation`]; pub
/// for the test module.
pub(crate) fn strip_graphql_comments_and_strings(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Comment: # to end of line (or EOF). Block strings come
        // first because """ contains a `#` would otherwise win
        // against a comment that starts mid-string.
        if b == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        // Block string: """ ... """ — three quotes terminate it.
        // No escape processing inside; spec says backslash escapes
        // are not meaningful in block strings.
        if i + 2 < bytes.len() && &bytes[i..i + 3] == b"\"\"\"" {
            i += 3;
            while i + 2 < bytes.len() && &bytes[i..i + 3] != b"\"\"\"" {
                i += 1;
            }
            // Skip closing """ (or EOF).
            if i + 2 < bytes.len() {
                i += 3;
            } else {
                i = bytes.len();
            }
            out.push(' ');
            continue;
        }
        // Single-line string: " ... " — backslash escapes one
        // character. A newline inside a non-block string is a
        // syntax error in GraphQL but we handle it gracefully by
        // letting the scan continue; precision-vs-safety, we
        // prefer the safe answer.
        if b == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' && bytes[i] != b'\n' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            // Skip closing quote (if present).
            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
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

    // ── Regression: expand_ipv6 must not panic on malformed addresses ──
    //
    // libFuzzer (fuzz_srr / fuzz_path_normalize) hit `index out of bounds`
    // panics in expand_ipv6 when an attacker-controlled IPv6 string had
    // more than 8 segments on the left side of `::`. The length guard
    // ran AFTER the left loop, so `result[i]` panicked first. Fixed by
    // moving the guard above both loops; this test pins the contract.
    #[test]
    fn expand_ipv6_oversized_left_does_not_panic() {
        // 9 left segments + empty right (`::` at end) — previously OOB
        let addr = "1:2:3:4:5:6:7:8:9::";
        let r = expand_ipv6(addr);
        assert_eq!(r, [0u16; 8], "malformed input must fail closed to zeros");
    }

    #[test]
    fn expand_ipv6_oversized_right_does_not_panic() {
        let addr = "::1:2:3:4:5:6:7:8:9";
        let r = expand_ipv6(addr);
        assert_eq!(r, [0u16; 8]);
    }

    #[test]
    fn expand_ipv6_oversized_combined_does_not_panic() {
        // 5 + 5 = 10 segments around `::`
        let addr = "1:2:3:4:5::6:7:8:9:a";
        let r = expand_ipv6(addr);
        assert_eq!(r, [0u16; 8]);
    }

    #[test]
    fn expand_ipv6_well_formed_still_works() {
        let r = expand_ipv6("2001:db8::1");
        assert_eq!(r[0], 0x2001);
        assert_eq!(r[1], 0x0db8);
        assert_eq!(r[7], 0x0001);
        assert_eq!(r[2], 0);
    }

    // ── Test 1: Payload > max_body_bytes → skips to next rule (continue, not return) ──

    #[test]
    fn payload_exceeding_max_body_bytes_skips_to_next_rule() {
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 100
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 1024
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

        // Invalid JSON — should not crash, should skip to next rule
        let bad_json = b"this is not json {{{";
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(bad_json));

        match result.decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(
                    milliseconds, 300,
                    "Malformed JSON should fall through to next rule"
                );
            }
            other => panic!("Expected Delay (fallthrough), got {:?}", other),
        }
    }

    // ── Test 4b: Base64-encoded body — entire body is Base64 ──

    #[test]
    fn base64_encoded_body_detected() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "Dangerous GraphQL via Base64" }
        "#,
        );

        // Base64 of: {"operationName":"TransferFunds","amount":5000}
        let b64_body = b"eyJvcGVyYXRpb25OYW1lIjoiVHJhbnNmZXJGdW5kcyIsImFtb3VudCI6NTAwMH0=";
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(b64_body));

        match result.decision {
            EnforcementDecision::Deny { .. } => {} // expected
            other => panic!("Base64 body should be decoded and matched, got {:?}", other),
        }
    }

    // ── Test 4c: Base64-encoded field value — field value is Base64 ──

    #[test]
    fn base64_encoded_field_value_detected() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.external.com/webhook"
            payload_field = "data"
            payload_match = ["ghp_"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "API key exfiltration blocked" }
        "#,
        );

        // JSON body where "data" field contains Base64-encoded API key
        // Base64 of: ghp_abc123secrettoken
        let body = br#"{"data":"Z2hwX2FiYzEyM3NlY3JldHRva2Vu","target":"attacker.com"}"#;
        let result = srr.check("POST", "api.external.com", "/webhook", Some(body));

        match result.decision {
            EnforcementDecision::Deny { .. } => {} // expected: decoded "ghp_abc123secrettoken" contains "ghp_"
            other => panic!(
                "Base64 field value should be decoded and pattern-matched, got {:?}",
                other
            ),
        }
    }

    // ── Test 4d: Non-Base64 body still works normally ──

    #[test]
    fn non_base64_body_works_normally() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "Dangerous GraphQL" }
        "#,
        );

        // Normal JSON (not Base64)
        let body = br#"{"operationName":"TransferFunds","amount":5000}"#;
        let result = srr.check("POST", "api.bank.com", "/graphql", Some(body));

        match result.decision {
            EnforcementDecision::Deny { .. } => {} // expected
            other => panic!("Normal JSON should still match, got {:?}", other),
        }
    }

    // ── Test 5: No body when payload inspection required → skip rule ──

    #[test]
    fn no_body_for_payload_rule_skips_to_next() {
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

        // Completely unknown URL — should hit default_decision (Delay 300ms)
        let result = srr.check("GET", "totally-unknown.com", "/some/path", None);

        match result.decision {
            EnforcementDecision::Delay { milliseconds } => {
                assert_eq!(
                    milliseconds, 300,
                    "Unknown URLs must get Default-to-Caution"
                );
            }
            other => panic!("Expected Default-to-Caution, got {:?}", other),
        }
    }

    // ── Test 8: Suffix host pattern matching ──

    #[test]
    fn suffix_host_pattern_blocks_all_subdomains() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "DELETE"
            pattern = "{host}.database.com/{any}"
            decision = { type = "Deny", reason = "Database deletion blocked" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

        // GET to a POST-only rule — should NOT be denied
        let result = srr.check("GET", "api.bank.com", "/transfer/123", None);

        if let EnforcementDecision::Deny { .. } = result.decision {
            panic!("GET should not match a POST-only deny rule");
        }
    }

    // ── Test 10: Wildcard method expansion ──

    #[test]
    fn wildcard_method_matches_all_http_methods() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "*"
            pattern = "evil.com/{any}"
            decision = { type = "Deny", reason = "Blocked domain" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "DELETE"
            pattern = "{host}.database.com/{any}"
            decision = { type = "Deny", reason = "Database deletion blocked" }
        "#,
        );

        let result = srr.check("DELETE", "prod.database.com:5432", "/users/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!(
                "Host with port should match suffix pattern, got {:?}",
                other
            ),
        }
    }

    // ── Path normalization tests ──

    #[test]
    fn percent_encoded_path_is_decoded_before_matching() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

        // %2F = /, %74 = t, etc. — encoded path that resolves to /transfer/123
        let result = srr.check("POST", "api.bank.com", "/%74ransfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!(
                "Percent-encoded path must be decoded before matching, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn double_slash_collapsed_before_matching() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

        let result = srr.check("POST", "api.bank.com", "//transfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!("Double slash must be collapsed, got: {:?}", other),
        }
    }

    #[test]
    fn dot_segment_traversal_does_not_bypass_deny() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );

        // /safe/../transfer/123 resolves to /transfer/123
        let result = srr.check("POST", "api.bank.com", "/safe/../transfer/123", None);
        match result.decision {
            EnforcementDecision::Deny { .. } => {}
            other => panic!(
                "Dot-segment traversal must not bypass deny, got: {:?}",
                other
            ),
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
        assert_eq!(
            normalize_path("/a%2Fb").expect("percent-encoded path must normalize"),
            "/a/b"
        );

        // Double dot at end
        assert_eq!(
            normalize_path("/a/b/..").expect("dot-segment path must normalize"),
            "/a"
        );

        // Multiple consecutive slashes
        assert_eq!(
            normalize_path("///a///b///").expect("multi-slash path must normalize"),
            "/a/b/"
        );

        // Single dot
        assert_eq!(
            normalize_path("/a/./b").expect("dot path must normalize"),
            "/a/b"
        );

        // Null byte removal
        assert_eq!(
            normalize_path("/a\0b").expect("null-byte path must normalize"),
            "/ab"
        );
    }

    #[test]
    fn normalize_path_decodes_percent_encoded_dot_segments() {
        // §4.1 traversal-bypass guard: %2E%2E (".." encoded) MUST be
        // decoded BEFORE dot-segment collapsing, otherwise an attacker
        // can sneak `/api/%2E%2E/admin` past a rule that matches
        // `/admin`. The normalizer must produce the same output as
        // `/api/../admin` → `/admin`.
        assert_eq!(
            normalize_path("/api/%2E%2E/admin").expect("encoded traversal must normalize"),
            "/admin",
            "regression: %2E%2E was not decoded → traversal bypass"
        );
        assert_eq!(
            normalize_path("/api/%2e%2e/admin")
                .expect("lowercase-encoded traversal must normalize"),
            "/admin",
            "regression: lowercase %2e%2e was not decoded"
        );
    }

    #[test]
    fn normalize_path_handles_invalid_percent_encoding() {
        // Lone `%` and `%X` (1 hex digit) must not panic. Either
        // pass through or reject — but no crash, no infinite loop.
        // We just call them and ensure the call returns within reason.
        let _ = normalize_path("/a%/b");
        let _ = normalize_path("/a%2/b");
        let _ = normalize_path("/a%ZZ/b");
    }

    #[test]
    fn normalize_path_oversized_does_not_explode() {
        // 4 KiB path. Some clients send long query-like paths; the
        // normalizer must not be O(N²) or panic.
        let long = format!("/{}", "a".repeat(4096));
        let t0 = std::time::Instant::now();
        let _ = normalize_path(&long);
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(200),
            "normalize_path on 4KiB input took {:?} — likely O(N²)",
            t0.elapsed()
        );
    }

    // ── Test: SrrCheckResult metadata ──

    // ── Path regex tests ──

    #[test]
    fn path_regex_matches_versioned_api() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.example.com"
            path_regex = "^/api/v[1-3]/users/.*"
            decision = { type = "Delay", milliseconds = 500 }
            description = "Versioned API rate limit"
        "#,
        );

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
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

        // Should be denied
        for path in &["/admin", "/admin/settings", "/internal/", "/debug/pprof"] {
            let r = srr.check("GET", "any.com", path, None);
            assert!(
                matches!(r.decision, EnforcementDecision::Deny { .. }),
                "Path {} should be denied by regex",
                path
            );
        }

        // Should NOT be denied (no match)
        for path in &["/api/users", "/administrator", "/public/debug-info"] {
            let r = srr.check("GET", "any.com", path, None);
            assert!(
                !matches!(r.decision, EnforcementDecision::Deny { .. }),
                "Path {} should not be denied",
                path
            );
        }
    }

    #[test]
    fn path_regex_combined_with_host_pattern() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "{host}.database.com"
            path_regex = "^/(drop|truncate|delete)/"
            decision = { type = "Deny", reason = "Destructive DB operation" }
        "#,
        );

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
        std::fs::write(
            &path,
            r#"
            [[rules]]
            method = "GET"
            pattern = "example.com"
            path_regex = "[invalid(regex"
            decision = { type = "Deny", reason = "Should not load" }
        "#,
        )
        .unwrap();

        let result = NetworkSRR::load(&path);
        assert!(
            result.is_err(),
            "Invalid regex must be rejected at load time"
        );
    }

    #[test]
    fn path_regex_with_catch_all_is_not_catch_all() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "*"
            pattern = "{any}"
            path_regex = "^/api/"
            decision = { type = "Delay", milliseconds = 500 }
            description = "API rate limit"
        "#,
        );

        let r = srr.check("GET", "any.com", "/api/users", None);
        assert!(
            !r.is_catch_all,
            "Regex rule with wildcard host should not be catch-all"
        );
    }

    #[test]
    fn explicit_rule_match_is_not_catch_all() {
        let srr = srr_from_toml(
            r#"
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
        "#,
        );

        // Explicit rule match
        let r1 = srr.check("POST", "api.bank.com", "/transfer/123", None);
        assert!(
            !r1.is_catch_all,
            "Explicit rule must not be flagged as catch-all"
        );
        assert_eq!(
            r1.matched_description.as_deref(),
            Some("Block wire transfers")
        );

        // Catch-all match
        let r2 = srr.check("GET", "unknown.com", "/any", None);
        assert!(r2.is_catch_all, "Catch-all rule must be flagged");

        // Built-in default (no rules match at all)
        let srr_no_catchall = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }
        "#,
        );
        let r3 = srr_no_catchall.check("GET", "unknown.com", "/any", None);
        assert!(
            r3.is_catch_all,
            "Built-in default must be flagged as catch-all"
        );
        assert!(
            r3.matched_description.is_none(),
            "Built-in default has no description"
        );
    }

    // ── Port-aware host matching ──────────────────────────────────────
    //
    // Pattern matrix the matcher must satisfy:
    //
    //   pattern               request                expect
    //   --------------------  ---------------------  ------
    //   api.demo/repos/foo    api.demo/repos/foo     Allow  (no port both sides)
    //   api.demo/repos/foo    api.demo:9999/...      Allow  (pattern omits port → any port)
    //   api.demo:443/...      api.demo/...           Allow  (default port collapses)
    //   api.demo:443/...      api.demo:443/...       Allow  (default port collapses)
    //   api.demo:9999/foo     api.demo:9999/foo      Allow  (exact non-default port)
    //   api.demo:9999/foo     api.demo:8888/foo      Default-to-Caution  (port mismatch)
    //   api.demo:9999/foo     api.demo/foo           Default-to-Caution  (request omits port)
    //   {host}.demo:9999/x    a.demo:9999/x          Allow  (suffix + port)
    //
    // The first three cases are the "default port collapses" guarantee
    // operators rely on so they don't have to spell out :443 in every
    // HTTPS rule. The fourth and fifth case enforce Max-Strict for
    // non-default ports — a pattern that explicitly names a port must
    // not silently allow other ports.

    fn allow(host: &str, path: &str, srr: &NetworkSRR) -> bool {
        matches!(
            srr.check("GET", host, path, None).decision,
            EnforcementDecision::Allow
        )
    }

    #[test]
    fn host_match_no_port_either_side() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.demo/repos/foo"
            decision = { type = "Allow" }
        "#,
        );
        assert!(allow("api.demo", "/repos/foo", &srr));
    }

    #[test]
    fn host_match_pattern_omits_port_request_supplies_port() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.demo/repos/foo"
            decision = { type = "Allow" }
        "#,
        );
        assert!(
            allow("api.demo:9999", "/repos/foo", &srr),
            "Pattern without port must allow any request port"
        );
    }

    #[test]
    fn host_match_default_https_port_collapses() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.bank.com:443/wire"
            decision = { type = "Allow" }
        "#,
        );
        assert!(allow("api.bank.com", "/wire", &srr));
        assert!(allow("api.bank.com:443", "/wire", &srr));
    }

    #[test]
    fn host_match_default_http_port_collapses() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.bank.com:80/wire"
            decision = { type = "Allow" }
        "#,
        );
        assert!(allow("api.bank.com", "/wire", &srr));
        assert!(allow("api.bank.com:80", "/wire", &srr));
    }

    #[test]
    fn host_match_explicit_nonstandard_port_exact() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.demo:9999/foo"
            decision = { type = "Allow" }
        "#,
        );
        assert!(allow("api.demo:9999", "/foo", &srr));
    }

    #[test]
    fn host_match_explicit_port_rejects_other_port() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.demo:9999/foo"
            decision = { type = "Allow" }
        "#,
        );
        assert!(
            !allow("api.demo:8888", "/foo", &srr),
            "Pattern :9999 must NOT match request :8888"
        );
    }

    #[test]
    fn host_match_explicit_port_rejects_unported_request() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "api.demo:9999/foo"
            decision = { type = "Allow" }
        "#,
        );
        // Bare "api.demo" implies the protocol's default port. The pattern
        // demands :9999 explicitly so this must NOT match.
        assert!(!allow("api.demo", "/foo", &srr));
    }

    #[test]
    fn host_match_suffix_pattern_with_explicit_port() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "{host}.demo:9999/x"
            decision = { type = "Allow" }
        "#,
        );
        assert!(allow("a.demo:9999", "/x", &srr));
        assert!(
            !allow("a.demo:8888", "/x", &srr),
            "Suffix pattern with port must enforce port"
        );
    }

    // ── Condition: time_window ─────────────────────────────────────────
    //
    // Contract:
    //  - Rules with `condition` only fire when the condition matches the
    //    evaluation timestamp.
    //  - `check_at(t)` is deterministic: same (rules, t) → same decision.
    //    This is the audit-replay contract — `event.timestamp` is in the
    //    Merkle leaf, so `verify_proof` can recompute the same decision.
    //  - Cross-midnight windows ("22:00-06:00") work.
    //  - `outside = true` inverts the match.
    //  - Timezone is honoured (operator writes in local time).

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("test timestamp parses")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn condition_time_window_inside_fires() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked outside biz hours" }
            condition = { kind = "time_window", window = "09:00-18:00", tz = "UTC", outside = true }
        "#,
        );

        // 03:00 UTC — outside business hours → condition matches (outside=true) → rule fires
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/123",
            None,
            at("2026-05-05T03:00:00Z"),
        );
        assert!(
            matches!(r.decision, EnforcementDecision::Deny { .. }),
            "outside biz hours → deny, got {:?}",
            r.decision
        );

        // 12:00 UTC — inside business hours → condition does NOT match → rule skipped
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/123",
            None,
            at("2026-05-05T12:00:00Z"),
        );
        // Falls through to default-to-caution (300ms delay)
        assert!(
            matches!(r.decision, EnforcementDecision::Delay { milliseconds: 300 }),
            "inside biz hours → fall-through to default, got {:?}",
            r.decision
        );
    }

    #[test]
    fn condition_time_window_inverted_fires_only_outside() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-18:00" }
        "#,
        );

        // 12:00 UTC — inside window → fires → Allow
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/123",
            None,
            at("2026-05-05T12:00:00Z"),
        );
        assert!(matches!(r.decision, EnforcementDecision::Allow));

        // 23:00 UTC — outside window → skipped → default-to-caution
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/123",
            None,
            at("2026-05-05T23:00:00Z"),
        );
        assert!(matches!(
            r.decision,
            EnforcementDecision::Delay { milliseconds: 300 }
        ));
    }

    #[test]
    fn condition_cross_midnight_window() {
        // "22:00-06:00" — overnight window, e.g. "deny during off-hours"
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "After-hours transfer" }
            condition = { kind = "time_window", window = "22:00-06:00" }
        "#,
        );

        // 23:00 — inside window → deny
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/x",
            None,
            at("2026-05-05T23:00:00Z"),
        );
        assert!(matches!(r.decision, EnforcementDecision::Deny { .. }));

        // 02:00 — inside window (post-midnight half) → deny
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/x",
            None,
            at("2026-05-05T02:00:00Z"),
        );
        assert!(matches!(r.decision, EnforcementDecision::Deny { .. }));

        // 14:00 — outside window → fall through
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/x",
            None,
            at("2026-05-05T14:00:00Z"),
        );
        assert!(matches!(
            r.decision,
            EnforcementDecision::Delay { milliseconds: 300 }
        ));
    }

    #[test]
    fn condition_timezone_is_honoured() {
        // Operator writes "09:00-18:00 Asia/Seoul" (KST = UTC+9).
        // 09:00 KST = 00:00 UTC, 18:00 KST = 09:00 UTC.
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-18:00", tz = "Asia/Seoul" }
        "#,
        );

        // 03:00 UTC = 12:00 KST — INSIDE Seoul biz hours → Allow
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/x",
            None,
            at("2026-05-05T03:00:00Z"),
        );
        assert!(matches!(r.decision, EnforcementDecision::Allow));

        // 15:00 UTC = 00:00 KST (next day) — OUTSIDE biz hours → fall through
        let r = srr.check_at(
            "POST",
            "api.bank.com",
            "/transfer/x",
            None,
            at("2026-05-05T15:00:00Z"),
        );
        assert!(matches!(
            r.decision,
            EnforcementDecision::Delay { milliseconds: 300 }
        ));
    }

    #[test]
    fn condition_replay_determinism() {
        // The same (rules, timestamp) MUST yield the same decision —
        // this is the audit-replay contract. We assert by calling
        // check_at twice with identical inputs separated by check()s
        // that use Utc::now() in between (which would diverge).
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Off-hours" }
            condition = { kind = "time_window", window = "22:00-06:00" }
        "#,
        );

        let t = at("2026-05-05T23:30:00Z");
        let r1 = srr.check_at("POST", "api.bank.com", "/transfer/abc", None, t);
        // sandwich a Utc::now()-based call
        let _ = srr.check("POST", "api.bank.com", "/transfer/abc", None);
        let r2 = srr.check_at("POST", "api.bank.com", "/transfer/abc", None, t);

        // r1 and r2 must agree (deterministic on t)
        assert_eq!(
            format!("{:?}", r1.decision),
            format!("{:?}", r2.decision),
            "check_at must be deterministic on timestamp"
        );
        assert!(matches!(r1.decision, EnforcementDecision::Deny { .. }));
    }

    #[test]
    fn condition_invalid_window_rejected_at_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bad_window.toml");
        std::fs::write(
            &path,
            r#"
            [[rules]]
            method = "GET"
            pattern = "example.com"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "25:00-30:00" }
        "#,
        )
        .unwrap();

        let result = NetworkSRR::load(&path);
        assert!(
            result.is_err(),
            "out-of-range hour must be rejected at load"
        );
    }

    #[test]
    fn condition_invalid_tz_rejected_at_load() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bad_tz.toml");
        std::fs::write(
            &path,
            r#"
            [[rules]]
            method = "GET"
            pattern = "example.com"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-18:00", tz = "Mars/Olympus" }
        "#,
        )
        .unwrap();

        let result = NetworkSRR::load(&path);
        assert!(
            result.is_err(),
            "unknown IANA timezone must be rejected at load"
        );
    }

    #[test]
    fn condition_zero_duration_window_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("zero_window.toml");
        std::fs::write(
            &path,
            r#"
            [[rules]]
            method = "GET"
            pattern = "example.com"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-09:00" }
        "#,
        )
        .unwrap();

        let result = NetworkSRR::load(&path);
        assert!(
            result.is_err(),
            "zero-duration window must be rejected (operator likely meant 24h)"
        );
    }

    #[test]
    fn condition_unconditional_rule_unaffected() {
        // Rule WITHOUT condition must keep firing regardless of timestamp.
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Always denied" }
        "#,
        );

        for t in &[
            "2026-05-05T03:00:00Z",
            "2026-05-05T12:00:00Z",
            "2026-05-05T23:59:59Z",
        ] {
            let r = srr.check_at("POST", "api.bank.com", "/transfer/x", None, at(t));
            assert!(
                matches!(r.decision, EnforcementDecision::Deny { .. }),
                "unconditional rule must fire at {}",
                t
            );
        }
    }

    #[test]
    fn host_match_case_insensitive_with_port() {
        let srr = srr_from_toml(
            r#"
            [[rules]]
            method = "GET"
            pattern = "API.demo:9999/Foo"
            decision = { type = "Allow" }
        "#,
        );
        // Host part lowercased at compile and request time. Path is
        // case-sensitive (RFC 7230) so we keep the original casing.
        assert!(allow("api.demo:9999", "/Foo", &srr));
        assert!(allow("API.DEMO:9999", "/Foo", &srr));
    }
}
