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

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: "0.0.0.0:8080".to_string(),
            },
            enforcement: EnforcementConfig {
                default_decision: DefaultDecisionConfig {
                    decision_type: "Delay".to_string(),
                    milliseconds: Some(300),
                },
                ic1_async_ledger: true,
                ic1_loss_threshold: 0.001,
                on_block: OnBlockConfig::default(),
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
