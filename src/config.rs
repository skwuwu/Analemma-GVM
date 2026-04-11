use anyhow::{Context, Result};
use gvm_types::BlockResponseMode;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Top-level proxy configuration (proxy.toml)
#[derive(Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub enforcement: EnforcementConfig,
    pub nats: NatsConfig,
    pub redis: RedisConfig,
    pub srr: SrrConfig,
    pub policies: PoliciesConfig,
    pub operations: OperationsConfig,
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
}

impl Default for DnsGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_port: 5353,
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
/// throttle = "rollback"
/// ```
#[derive(Deserialize, Clone, Debug)]
pub struct OnBlockConfig {
    /// Mode for Deny decisions (default: halt)
    #[serde(default = "default_halt")]
    pub deny: BlockResponseMode,
    /// Mode for RequireApproval decisions (default: soft_pivot)
    #[serde(default = "default_soft_pivot")]
    pub require_approval: BlockResponseMode,
    /// Mode for Throttle rate-limit blocks (default: rollback)
    #[serde(default = "default_rollback")]
    pub throttle: BlockResponseMode,
    /// Mode for WAL/infrastructure failures (default: halt)
    #[serde(default = "default_halt")]
    pub infrastructure_failure: BlockResponseMode,
}

impl Default for OnBlockConfig {
    fn default() -> Self {
        Self {
            deny: BlockResponseMode::Halt,
            require_approval: BlockResponseMode::SoftPivot,
            throttle: BlockResponseMode::Rollback,
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

fn default_rollback() -> BlockResponseMode {
    BlockResponseMode::Rollback
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
            policies: PoliciesConfig {
                directory: "config/policies/".to_string(),
                hot_reload: true,
            },
            operations: OperationsConfig {
                registry_file: "config/operation_registry.toml".to_string(),
            },
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
