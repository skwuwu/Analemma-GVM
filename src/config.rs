use anyhow::{Context, Result};
use gvm_types::BlockResponseMode;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ─── Unified gvm.toml Configuration ───

/// Unified user-facing configuration (gvm.toml).
///
/// All governance settings in one file: network rules, API credentials,
/// budget limits, filesystem patterns, and seccomp profile.
/// When gvm.toml exists, it takes priority over separate config files.
/// When absent, the proxy falls back to legacy separate-file loading.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct GvmConfig {
    /// Network rules (SRR) — replaces config/srr_network.toml.
    #[serde(default)]
    pub rules: Vec<crate::srr::NetworkRuleConfig>,

    /// API credentials keyed by host — replaces config/secrets.toml.
    #[serde(default)]
    pub credentials: HashMap<String, crate::api_keys::Credential>,

    /// Token budget limits.
    #[serde(default)]
    pub budget: BudgetConfig,

    /// Filesystem governance patterns (Trust-on-Pattern).
    #[serde(default)]
    pub filesystem: Option<gvm_sandbox::FilesystemPolicy>,

    /// Seccomp profile selection.
    #[serde(default)]
    pub seccomp: SeccompConfig,
}

/// Seccomp profile configuration within gvm.toml.
#[derive(Deserialize, Clone, Debug)]
pub struct SeccompConfig {
    /// Profile name: "default", "strict", or "custom".
    #[serde(default = "default_seccomp_profile")]
    pub profile: String,
    /// Path to custom seccomp JSON profile (only when profile = "custom").
    pub custom_path: Option<String>,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            custom_path: None,
        }
    }
}

fn default_seccomp_profile() -> String {
    "default".to_string()
}

/// Search for gvm.toml in standard locations and load it.
///
/// Search order:
///   1. GVM_TOML env var (explicit path)
///   2. gvm.toml in current working directory
///   3. config/gvm.toml
///   4. ~/.config/gvm/gvm.toml
///
/// Returns None if no gvm.toml is found — triggers legacy fallback.
pub fn load_gvm_toml() -> Option<GvmConfig> {
    let candidates = [
        std::env::var("GVM_TOML").ok(),
        Some("gvm.toml".to_string()),
        Some("config/gvm.toml".to_string()),
        dirs_home().map(|h| format!("{}/.config/gvm/gvm.toml", h)),
    ];

    for candidate in candidates.iter().flatten() {
        let path = Path::new(candidate);
        if path.exists() {
            // Security: gvm.toml may contain API keys. Apply permission check.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(path) {
                    let mode = meta.permissions().mode();
                    if mode & 0o077 != 0 {
                        tracing::warn!(
                            path = %path.display(),
                            mode = format!("{:04o}", mode & 0o777),
                            "gvm.toml has insecure permissions — group/other can read API keys"
                        );
                        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        {
                            Ok(()) => tracing::info!(
                                path = %path.display(),
                                "Fixed gvm.toml permissions to 0600"
                            ),
                            Err(e) => tracing::warn!(
                                error = %e,
                                "Cannot fix gvm.toml permissions — ensure only the proxy user can read this file"
                            ),
                        }
                    }
                }
            }

            match std::fs::read_to_string(path) {
                Ok(content) => match toml::from_str::<GvmConfig>(&content) {
                    Ok(config) => {
                        tracing::info!(
                            path = %path.display(),
                            rules = config.rules.len(),
                            credentials = config.credentials.len(),
                            "Unified configuration loaded from gvm.toml"
                        );
                        return Some(config);
                    }
                    Err(e) => {
                        tracing::error!(
                            path = %path.display(),
                            error = %e,
                            "Failed to parse gvm.toml"
                        );
                        // Fail-close: do not silently fall back to legacy config
                        // if gvm.toml exists but is malformed.
                        eprintln!();
                        eprintln!("  ERROR: gvm.toml exists but failed to parse.");
                        eprintln!("  Path: {}", path.display());
                        eprintln!("  Error: {}", e);
                        eprintln!();
                        eprintln!("  Fix the file or remove it to use legacy config files.");
                        eprintln!();
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    tracing::error!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read gvm.toml"
                    );
                }
            }
        }
    }

    None
}

/// Top-level proxy configuration (proxy.toml)
#[derive(Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub enforcement: EnforcementConfig,
    pub nats: NatsConfig,
    pub redis: RedisConfig,
    pub srr: SrrConfig,
    /// Legacy ABAC policy config. Ignored (ABAC removed). Kept as optional
    /// so existing proxy.toml files with [policies] section still parse.
    pub policies: Option<PoliciesConfig>,
    /// Legacy operation registry config. Ignored (registry removed in gvm.toml unification).
    /// Kept as optional so existing proxy.toml files with [operations] section still parse.
    pub operations: Option<OperationsConfig>,
    pub secrets: SecretsConfig,
    pub dev: Option<DevConfig>,
    /// JWT authentication configuration (optional).
    /// When configured, agents authenticate via Bearer tokens.
    pub jwt: Option<JwtAuthConfig>,
    /// WAL (Write-Ahead Log) tuning options.
    #[serde(default)]
    pub wal: WalConfig,
    /// Shadow verification mode — requires MCP intent declaration before outbound requests.
    #[serde(default)]
    pub shadow: crate::intent_store::ShadowConfig,
    /// Filesystem governance (Trust-on-Pattern) for --sandbox mode.
    /// When present, overlayfs captures all file changes; patterns determine
    /// which are auto-merged, need manual commit, or discarded.
    pub filesystem: Option<gvm_sandbox::FilesystemPolicy>,
    /// DNS governance configuration (Delay-Alert, no Deny).
    /// Default: enabled with standard tier thresholds.
    /// Disable with `--no-dns-governance` CLI flag or `dns.enabled = false`.
    #[serde(default)]
    pub dns: DnsGovernanceConfig,
    /// Token budget configuration for LLM cost governance.
    /// Limits total tokens and/or cost per hour across all agents.
    #[serde(default)]
    pub budget: BudgetConfig,
}

/// Token budget configuration for LLM cost governance.
///
/// ```toml
/// [budget]
/// max_tokens_per_hour = 100000        # 0 = unlimited (org-wide)
/// max_cost_per_hour = 1.00            # 0.0 = unlimited (org-wide)
/// reserve_per_request = 500           # estimated tokens reserved per in-flight request
/// per_agent_max_tokens_per_hour = 0   # 0 = disabled (no per-agent quota)
/// per_agent_max_cost_per_hour = 0.0   # 0.0 = disabled
/// ```
///
/// **Per-agent quota** (multi-agent isolation, single org):
/// - `per_agent_max_*` fields, when nonzero, give each `agent_id` an
///   independent budget instance. One agent exhausting its share does
///   NOT consume from another agent's pool. The org-wide
///   `max_*_per_hour` still applies as a ceiling above all agents.
/// - Both must pass: an LLM request is admitted only when the agent's
///   per-agent quota AND the org-wide ceiling have headroom.
/// - Disabled by default (zeros). Operators turn it on when they want
///   noisy-neighbor isolation across agents in the same organization.
#[derive(Deserialize, Clone, Debug)]
pub struct BudgetConfig {
    /// Maximum tokens per hour across all agents (org-wide ceiling, 0 = unlimited).
    #[serde(default)]
    pub max_tokens_per_hour: u64,
    /// Maximum cost in USD per hour across all agents (0.0 = unlimited).
    #[serde(default)]
    pub max_cost_per_hour: f64,
    /// Tokens reserved per in-flight LLM request (default: 500).
    #[serde(default = "default_reserve")]
    pub reserve_per_request: u64,
    /// Per-agent token quota (0 = no per-agent limit; org-wide ceiling
    /// alone applies).
    #[serde(default)]
    pub per_agent_max_tokens_per_hour: u64,
    /// Per-agent cost quota in USD per hour (0.0 = no per-agent limit).
    #[serde(default)]
    pub per_agent_max_cost_per_hour: f64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_tokens_per_hour: 0,
            max_cost_per_hour: 0.0,
            reserve_per_request: 500,
            per_agent_max_tokens_per_hour: 0,
            per_agent_max_cost_per_hour: 0.0,
        }
    }
}

fn default_reserve() -> u64 {
    500
}

/// DNS soft governance configuration.
///
/// ```toml
/// [dns]
/// enabled = true          # false to disable entirely
/// listen_port = 5353      # local UDP port for the DNS proxy
/// ```
#[derive(Deserialize, Clone, Debug)]
pub struct DnsGovernanceConfig {
    /// Enable DNS query governance (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Local UDP port for the DNS governance proxy (default: 5353).
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,
    /// Sliding-window duration in seconds for Tier 3/4 burst detection
    /// (default: 60). Operators can shorten this for E2E tests to
    /// avoid 60-second waits, but values below 5 seconds are clamped
    /// to 5 — anything shorter would make Tier 3 (≥5 unique
    /// subdomains in the window) impossible to trigger. Reading from
    /// config (not env var) ensures the override is auditable in the
    /// WAL config-load record. See §6.5 of GVM_CODE_STANDARDS.md.
    #[serde(default = "default_dns_window_secs")]
    pub window_secs: u64,
    /// Tier 3 trigger: number of unique subdomains on the same base
    /// domain within the window before the tier escalates from 2 to
    /// 3. Default: 5. Floor: 1 (operator may NOT set this to 0,
    /// which would disable subdomain-burst detection entirely).
    /// Raise for CDN-heavy workloads where 5 unique subdomains is
    /// normal traffic; lower for high-security postures that want
    /// earlier alerting. The `MIN_TIER3_THRESHOLD` floor in
    /// `dns_governance.rs` clamps any value below 1 back to 1, so
    /// a misconfigured TOML can't silently weaken detection.
    #[serde(default = "default_tier3_unique_threshold")]
    pub tier3_unique_threshold: usize,
    /// Tier 4 trigger: total unique subdomain queries across all
    /// base domains within the window before "flood" tier fires.
    /// Default: 20. Floor: 1. Same rationale as
    /// `tier3_unique_threshold`.
    #[serde(default = "default_tier4_global_threshold")]
    pub tier4_global_threshold: usize,
    /// Delay applied to Tier 2 (unknown) queries in milliseconds
    /// (default: 200). No security floor — this is a cost knob, not
    /// a detection knob. Sane cap: 60_000 (1 minute) to prevent
    /// foot-guns from a typo turning every unknown query into a
    /// minute-long stall.
    #[serde(default = "default_tier2_delay_ms")]
    pub tier2_delay_ms: u64,
    /// Delay applied to Tier 3 (anomalous subdomain burst) in
    /// milliseconds (default: 3000).
    #[serde(default = "default_tier3_delay_ms")]
    pub tier3_delay_ms: u64,
    /// Delay applied to Tier 4 (flood) in milliseconds (default:
    /// 10000).
    #[serde(default = "default_tier4_delay_ms")]
    pub tier4_delay_ms: u64,
}

fn default_dns_window_secs() -> u64 {
    60
}
fn default_tier3_unique_threshold() -> usize {
    5
}
fn default_tier4_global_threshold() -> usize {
    20
}
fn default_tier2_delay_ms() -> u64 {
    200
}
fn default_tier3_delay_ms() -> u64 {
    3_000
}
fn default_tier4_delay_ms() -> u64 {
    10_000
}

impl Default for DnsGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 5353,
            window_secs: 60,
            tier3_unique_threshold: 5,
            tier4_global_threshold: 20,
            tier2_delay_ms: 200,
            tier3_delay_ms: 3_000,
            tier4_delay_ms: 10_000,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_dns_port() -> u16 {
    5353
}

/// JWT authentication configuration.
///
/// ```toml
/// [jwt]
/// secret_env = "GVM_JWT_SECRET"
/// token_ttl_secs = 3600
/// ```
#[derive(Deserialize, Clone, Debug)]
pub struct JwtAuthConfig {
    /// Environment variable name holding the hex-encoded HMAC secret (min 32 bytes).
    #[serde(default = "default_jwt_secret_env")]
    pub secret_env: String,
    /// Token time-to-live in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_jwt_ttl")]
    pub token_ttl_secs: u64,
}

fn default_jwt_secret_env() -> String {
    "GVM_JWT_SECRET".to_string()
}

fn default_jwt_ttl() -> u64 {
    3600
}

/// Dev-only configuration. Ignored when GVM_ENV=production.
#[derive(Deserialize, Clone, Debug)]
pub struct DevConfig {
    /// Map external hostnames to local addresses for development.
    /// Example: { "gmail.googleapis.com" = "localhost:9090" }
    #[serde(default)]
    pub host_overrides: HashMap<String, String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
    pub listen: String,
    /// Admin API listen address (default: "127.0.0.1:9090").
    /// Privileged endpoints (approve, reload, info) are served here, separated
    /// from the agent-facing proxy port. The agent never learns this address.
    /// This prevents a sandboxed agent from self-approving IC-3 requests.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    /// Graceful shutdown drain timeout in seconds (default: 5).
    /// After receiving SIGTERM/SIGINT, the proxy stops accepting new connections
    /// and waits up to this many seconds for in-flight requests to complete.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_drain_timeout_secs() -> u64 {
    5
}

#[derive(Deserialize, Clone, Debug)]
pub struct EnforcementConfig {
    pub default_decision: DefaultDecisionConfig,
    pub ic1_async_ledger: bool,
    pub ic1_loss_threshold: f64,
    /// Per-decision block response modes.
    /// Controls how agents should react to blocked operations.
    #[serde(default)]
    pub on_block: OnBlockConfig,
    /// IC-3 approval timeout in seconds (default: 300).
    /// When IC-3 is triggered, the proxy holds the HTTP response for up to this
    /// duration, waiting for an approval via POST /gvm/approve. On timeout, the
    /// request is auto-denied (fail-close).
    #[serde(default = "default_ic3_approval_timeout_secs")]
    pub ic3_approval_timeout_secs: u64,
    /// Policy for URLs that match no SRR rule (Default-to-Caution).
    ///
    /// - `"delay"` (default): Allow after delay_ms, record in WAL. Best for dev/test.
    /// - `"require_approval"`: Hold until human approves via `gvm approve` CLI. Best for production finance/healthcare.
    /// - `"deny"`: Block immediately. Best for high-security lockdown environments.
    ///
    /// ```toml
    /// [enforcement]
    /// default_unknown = "delay"
    /// default_delay_ms = 300
    /// ```
    #[serde(default = "default_unknown_policy")]
    pub default_unknown: String,
    /// Delay in milliseconds for Default-to-Caution when default_unknown = "delay" (default: 300).
    #[serde(default = "default_delay_ms")]
    pub default_delay_ms: u64,

    /// Optional URL template stamped on `X-GVM-Policy-Link` for blocked
    /// requests. The literal string `{rule_id}` is substituted with the
    /// matched rule id. Empty / unset → no header. Example:
    ///
    /// ```toml
    /// [enforcement]
    /// policy_link_template = "https://gvm-console.example.com/rules/{rule_id}"
    /// ```
    ///
    /// Why a template instead of a fixed URL: an operator running a
    /// hosted GVM console wants the rule id baked in. An operator with
    /// a wiki / runbook system wants `https://wiki/runbooks/srr#{rule_id}`.
    /// Template keeps both shapes one config field.
    #[serde(default)]
    pub policy_link_template: Option<String>,
}

fn default_ic3_approval_timeout_secs() -> u64 {
    300
}

fn default_unknown_policy() -> String {
    "delay".to_string()
}

fn default_delay_ms() -> u64 {
    300
}

/// Per-decision block response mode configuration.
///
/// ```toml
/// [enforcement.on_block]
/// deny = "halt"
/// require_approval = "soft_pivot"
/// ```
#[derive(Deserialize, Clone, Debug)]
pub struct OnBlockConfig {
    /// Mode for Deny decisions (default: halt)
    #[serde(default = "default_halt")]
    pub deny: BlockResponseMode,
    /// Mode for RequireApproval decisions (default: soft_pivot)
    #[serde(default = "default_soft_pivot")]
    pub require_approval: BlockResponseMode,
    /// Mode for WAL/infrastructure failures (default: halt)
    #[serde(default = "default_halt")]
    pub infrastructure_failure: BlockResponseMode,
}

impl Default for OnBlockConfig {
    fn default() -> Self {
        Self {
            deny: BlockResponseMode::Halt,
            require_approval: BlockResponseMode::SoftPivot,
            infrastructure_failure: BlockResponseMode::Halt,
        }
    }
}

fn default_halt() -> BlockResponseMode {
    BlockResponseMode::Halt
}

fn default_soft_pivot() -> BlockResponseMode {
    BlockResponseMode::SoftPivot
}

#[derive(Deserialize, Clone, Debug)]
pub struct DefaultDecisionConfig {
    #[serde(rename = "type")]
    pub decision_type: String,
    pub milliseconds: Option<u64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct NatsConfig {
    pub url: String,
    pub stream: String,
    pub max_age_days: u64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SrrConfig {
    pub network_file: String,
    pub semantic_file: String,
    pub hot_reload: bool,
    /// Enable request body buffering for SRR payload_field/payload_match rules.
    /// When false (default), SRR evaluates host/method/path only — body is not inspected.
    /// When true, the proxy buffers up to `max_body_bytes` of the request body and
    /// passes it to SRR for JSON field matching. Parse failure → fallback to host/method/path.
    #[serde(default)]
    pub payload_inspection: bool,
    /// Maximum request body bytes to buffer for payload inspection (default: 65536 = 64KB).
    /// Requests with Content-Length exceeding this limit skip payload inspection.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

fn default_max_body_bytes() -> usize {
    65536 // 64KB
}

#[derive(Deserialize, Clone, Debug)]
pub struct PoliciesConfig {
    pub directory: String,
    pub hot_reload: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct OperationsConfig {
    pub registry_file: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SecretsConfig {
    pub file: String,
    pub key_env: String,
}

/// WAL (Write-Ahead Log) tuning configuration.
///
/// ```toml
/// [wal]
/// batch_window_ms = 2
/// max_batch_size = 128
/// ```
#[derive(Deserialize, Clone, Debug)]
pub struct WalConfig {
    /// WAL file path (default: "data/wal.log").
    /// Override via GVM_WAL_PATH env var or [wal] path in proxy.toml.
    /// Useful for placing WAL on a dedicated disk in production.
    #[serde(default = "default_wal_path")]
    pub path: String,
    /// Group commit batch window in milliseconds (default: 2ms).
    /// Events arriving within this window are batched into a single fsync.
    /// Set to 0 for minimum latency (no batching wait), at the cost of
    /// one fsync per request under low concurrency.
    #[serde(default = "default_batch_window_ms")]
    pub batch_window_ms: u64,
    /// Maximum events per batch before forcing a flush (default: 128).
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,
    /// Maximum WAL file size in bytes before rotation (default: 100MB).
    /// When exceeded, the current file is renamed to `wal.log.<N>` and a new
    /// file is created. The inter-batch `prev_batch_root` field links segments.
    #[serde(default = "default_max_wal_bytes")]
    pub max_wal_bytes: u64,
    /// Maximum number of rotated WAL segments to keep (default: 10).
    /// Oldest segments are deleted when this count is exceeded.
    #[serde(default = "default_max_wal_segments")]
    pub max_wal_segments: usize,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            path: "data/wal.log".to_string(),
            batch_window_ms: 2,
            max_batch_size: 128,
            max_wal_bytes: 100 * 1024 * 1024, // 100MB
            max_wal_segments: 10,
        }
    }
}

fn default_wal_path() -> String {
    "data/wal.log".to_string()
}

fn default_max_wal_bytes() -> u64 {
    100 * 1024 * 1024 // 100MB
}

fn default_max_wal_segments() -> usize {
    10
}

fn default_batch_window_ms() -> u64 {
    2
}

fn default_max_batch_size() -> usize {
    128
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: "0.0.0.0:8080".to_string(),
                admin_listen: default_admin_listen(),
                drain_timeout_secs: 5,
            },
            enforcement: EnforcementConfig {
                default_decision: DefaultDecisionConfig {
                    decision_type: "Delay".to_string(),
                    milliseconds: Some(300),
                },
                ic1_async_ledger: true,
                ic1_loss_threshold: 0.001,
                on_block: OnBlockConfig::default(),
                ic3_approval_timeout_secs: default_ic3_approval_timeout_secs(),
                default_unknown: "delay".to_string(),
                default_delay_ms: 300,
                policy_link_template: None,
            },
            nats: NatsConfig {
                url: "nats://127.0.0.1:4222".to_string(),
                stream: "gvm-audit".to_string(),
                max_age_days: 2555,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".to_string(),
            },
            srr: SrrConfig {
                network_file: "config/srr_network.toml".to_string(),
                semantic_file: "config/srr_semantic.toml".to_string(),
                hot_reload: true,
                payload_inspection: false,
                max_body_bytes: default_max_body_bytes(),
            },
            policies: None,
            operations: None,
            secrets: SecretsConfig {
                file: "config/secrets.toml".to_string(),
                key_env: "GVM_SECRETS_KEY".to_string(),
            },
            dev: None,
            jwt: None,
            wal: WalConfig::default(),
            shadow: crate::intent_store::ShadowConfig::default(),
            filesystem: None,
            dns: DnsGovernanceConfig::default(),
            budget: BudgetConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// Load proxy configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: ProxyConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Try loading config from multiple locations, falling back to defaults.
    pub fn load_or_default() -> Self {
        let candidates = [
            std::env::var("GVM_CONFIG").ok(),
            Some("config/proxy.toml".to_string()),
            dirs_home().map(|h| format!("{}/.config/gvm/proxy.toml", h)),
        ];

        for candidate in candidates.iter().flatten() {
            let path = Path::new(candidate);
            if path.exists() {
                match Self::load(path) {
                    Ok(config) => {
                        tracing::info!(path = %path.display(), "Configuration loaded");
                        return config;
                    }
                    Err(e) => {
                        tracing::error!(path = %path.display(), error = %e, "Failed to load config");
                    }
                }
            }
        }

        tracing::warn!("No config file found — using built-in defaults (listen 0.0.0.0:8080)");
        Self::default()
    }
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── GvmConfig TOML deserialization ──

    #[test]
    fn gvm_config_empty_toml_uses_defaults() {
        let config: GvmConfig = toml::from_str("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.credentials.is_empty());
        assert_eq!(config.budget.max_tokens_per_hour, 0);
        assert_eq!(config.budget.reserve_per_request, 500);
        assert!(config.filesystem.is_none());
        assert_eq!(config.seccomp.profile, "default");
        assert!(config.seccomp.custom_path.is_none());
    }

    #[test]
    fn gvm_config_parses_rules() {
        let toml_str = r#"
[[rules]]
method = "POST"
pattern = "api.stripe.com/v1/charges"
description = "Payment charges"
[rules.decision]
type = "Deny"
reason = "Blocked"
"#;
        let config: GvmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].method, "POST");
        assert_eq!(config.rules[0].pattern, "api.stripe.com/v1/charges");
        assert_eq!(config.rules[0].decision.decision_type, "Deny");
    }

    #[test]
    fn gvm_config_parses_budget() {
        let toml_str = r#"
[budget]
max_tokens_per_hour = 100000
max_cost_per_hour = 5.50
reserve_per_request = 1000
"#;
        let config: GvmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.budget.max_tokens_per_hour, 100000);
        assert!((config.budget.max_cost_per_hour - 5.50).abs() < f64::EPSILON);
        assert_eq!(config.budget.reserve_per_request, 1000);
    }

    #[test]
    fn gvm_config_partial_budget_fills_defaults() {
        let toml_str = r#"
[budget]
max_tokens_per_hour = 50000
"#;
        let config: GvmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.budget.max_tokens_per_hour, 50000);
        assert!((config.budget.max_cost_per_hour - 0.0).abs() < f64::EPSILON);
        assert_eq!(config.budget.reserve_per_request, 500);
    }

    #[test]
    fn gvm_config_parses_credentials() {
        let toml_str = r#"
[credentials."api.openai.com"]
type = "Bearer"
token = "sk-test-123"
"#;
        let config: GvmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.credentials.len(), 1);
        assert!(config.credentials.contains_key("api.openai.com"));
    }

    #[test]
    fn gvm_config_malformed_toml_fails() {
        let bad = "[[rules]\nmethod = broken";
        let result = toml::from_str::<GvmConfig>(bad);
        assert!(result.is_err());
    }

    #[test]
    fn gvm_config_unknown_fields_ignored() {
        // serde(deny_unknown_fields) is NOT set, so extra keys should parse fine
        let toml_str = r#"
unknown_future_key = "value"
[budget]
max_tokens_per_hour = 1000
"#;
        let config: GvmConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.budget.max_tokens_per_hour, 1000);
    }

    // ── ProxyConfig defaults ──

    #[test]
    fn proxy_config_default_has_expected_values() {
        let config = ProxyConfig::default();
        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert_eq!(config.server.admin_listen, "127.0.0.1:9090");
        assert_eq!(config.server.drain_timeout_secs, 5);
        assert_eq!(config.enforcement.default_decision.decision_type, "Delay");
        assert_eq!(config.enforcement.default_decision.milliseconds, Some(300));
        assert!(config.enforcement.ic1_async_ledger);
        assert_eq!(config.enforcement.ic3_approval_timeout_secs, 300);
        assert_eq!(config.enforcement.default_unknown, "delay");
        assert_eq!(config.enforcement.default_delay_ms, 300);
        assert_eq!(config.nats.url, "nats://127.0.0.1:4222");
        assert_eq!(config.nats.stream, "gvm-audit");
        assert_eq!(config.redis.url, "redis://127.0.0.1:6379");
        assert!(config.srr.hot_reload);
        assert!(!config.srr.payload_inspection);
        assert_eq!(config.srr.max_body_bytes, 65536);
        assert!(config.policies.is_none());
        assert!(config.operations.is_none());
        assert!(config.dev.is_none());
        assert!(config.jwt.is_none());
        assert!(config.filesystem.is_none());
    }

    #[test]
    fn proxy_config_load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.toml");
        std::fs::write(
            &path,
            r#"
[server]
listen = "127.0.0.1:9999"

[enforcement]
ic1_async_ledger = false
ic1_loss_threshold = 0.01
[enforcement.default_decision]
type = "Allow"

[nats]
url = "nats://10.0.0.1:4222"
stream = "test-stream"
max_age_days = 30

[redis]
url = "redis://10.0.0.1:6379"

[srr]
network_file = "srr.toml"
semantic_file = "sem.toml"
hot_reload = false

[secrets]
file = "secrets.toml"
key_env = "MY_KEY"
"#,
        )
        .unwrap();

        let config = ProxyConfig::load(&path).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:9999");
        assert_eq!(config.server.admin_listen, "127.0.0.1:9090"); // default
        assert!(!config.enforcement.ic1_async_ledger);
        assert_eq!(config.nats.url, "nats://10.0.0.1:4222");
        assert!(!config.srr.hot_reload);
    }

    #[test]
    fn proxy_config_load_missing_file_returns_error() {
        let result = ProxyConfig::load(Path::new("/nonexistent/proxy.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn proxy_config_load_malformed_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml {{{").unwrap();
        let result = ProxyConfig::load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_config_load_missing_required_field_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.toml");
        // Missing [server], [enforcement], etc.
        std::fs::write(&path, "[redis]\nurl = \"redis://localhost\"").unwrap();
        let result = ProxyConfig::load(&path);
        assert!(result.is_err());
    }

    // ── WalConfig defaults ──

    #[test]
    fn wal_config_defaults() {
        let config = WalConfig::default();
        assert_eq!(config.path, "data/wal.log");
        assert_eq!(config.batch_window_ms, 2);
        assert_eq!(config.max_batch_size, 128);
        assert_eq!(config.max_wal_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_wal_segments, 10);
    }

    #[test]
    fn wal_config_partial_override() {
        let toml_str = r#"
path = "/var/log/gvm/wal.log"
max_batch_size = 256
"#;
        let config: WalConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.path, "/var/log/gvm/wal.log");
        assert_eq!(config.max_batch_size, 256);
        assert_eq!(config.batch_window_ms, 2); // default
        assert_eq!(config.max_wal_bytes, 100 * 1024 * 1024); // default
    }

    // ── OnBlockConfig defaults ──

    #[test]
    fn on_block_config_defaults() {
        let config = OnBlockConfig::default();
        assert!(matches!(config.deny, BlockResponseMode::Halt));
        assert!(matches!(
            config.require_approval,
            BlockResponseMode::SoftPivot
        ));
        assert!(matches!(
            config.infrastructure_failure,
            BlockResponseMode::Halt
        ));
    }

    // ── DnsGovernanceConfig defaults ──

    #[test]
    fn dns_governance_config_defaults() {
        let config = DnsGovernanceConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listen_port, 5353);
    }

    #[test]
    fn dns_governance_config_disabled() {
        let toml_str = r#"
enabled = false
listen_port = 5454
"#;
        let config: DnsGovernanceConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.listen_port, 5454);
    }

    // ── BudgetConfig defaults ──

    #[test]
    fn budget_config_defaults() {
        let config = BudgetConfig::default();
        assert_eq!(config.max_tokens_per_hour, 0);
        assert!((config.max_cost_per_hour - 0.0).abs() < f64::EPSILON);
        assert_eq!(config.reserve_per_request, 500);
    }

    // ── SeccompConfig defaults ──

    #[test]
    fn seccomp_config_defaults() {
        let config = SeccompConfig::default();
        assert_eq!(config.profile, "default");
        assert!(config.custom_path.is_none());
    }

    #[test]
    fn seccomp_config_custom_profile() {
        let toml_str = r#"
profile = "strict"
custom_path = "/etc/gvm/seccomp.json"
"#;
        let config: SeccompConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.profile, "strict");
        assert_eq!(config.custom_path.as_deref(), Some("/etc/gvm/seccomp.json"));
    }

    // ── JwtAuthConfig ──

    #[test]
    fn jwt_config_defaults() {
        let toml_str = ""; // empty — serde defaults apply
        let config: JwtAuthConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.secret_env, "GVM_JWT_SECRET");
        assert_eq!(config.token_ttl_secs, 3600);
    }

    // ── ProxyConfig TOML with legacy [policies] section still parses ──

    #[test]
    fn proxy_config_with_legacy_policies_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.toml");
        std::fs::write(
            &path,
            r#"
[server]
listen = "0.0.0.0:8080"

[enforcement]
ic1_async_ledger = true
ic1_loss_threshold = 0.001
[enforcement.default_decision]
type = "Delay"
milliseconds = 300

[nats]
url = "nats://localhost:4222"
stream = "gvm"
max_age_days = 30

[redis]
url = "redis://localhost"

[srr]
network_file = "srr.toml"
semantic_file = "sem.toml"
hot_reload = true

[secrets]
file = "secrets.toml"
key_env = "KEY"

[policies]
directory = "config/policies"
hot_reload = true

[operations]
registry_file = "config/operations.toml"
"#,
        )
        .unwrap();

        let config = ProxyConfig::load(&path).unwrap();
        assert!(config.policies.is_some());
        assert!(config.operations.is_some());
    }
}
