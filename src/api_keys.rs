use anyhow::{anyhow, Result};
use axum::http::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Credential types for external API authentication (PART 5.5)
#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Credential {
    Bearer {
        token: String,
    },
    OAuth2 {
        access_token: String,
        refresh_token: String,
        expires_at: String,
    },
    ApiKey {
        header: String,
        value: String,
    },
}

/// API Key Store — holds credentials keyed by host.
/// The proxy injects the appropriate credential into forwarded requests (Layer 3).
#[derive(Clone, Debug)]
pub struct APIKeyStore {
    credentials: HashMap<String, Credential>,
}

#[derive(Deserialize, Debug)]
struct SecretsFile {
    #[serde(default)]
    credentials: HashMap<String, Credential>,
}

impl APIKeyStore {
    /// Load credentials from a TOML secrets file.
    /// In production, this file should be encrypted (secrets.toml.enc).
    /// For MVP, we support plaintext TOML.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::warn!(
                "Secrets file not found: {}. Starting with empty credential store.",
                path.display()
            );
            return Ok(Self {
                credentials: HashMap::new(),
            });
        }

        let content = std::fs::read_to_string(path)?;
        let file: SecretsFile = toml::from_str(&content)?;

        tracing::info!(
            "Loaded {} API credentials from {}",
            file.credentials.len(),
            path.display()
        );

        Ok(Self {
            credentials: file.credentials,
        })
    }

    /// Returns true if no credentials are configured.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Inject the appropriate credential into the request for the given host.
    /// This is Layer 3 (Capability Token) — the agent never has direct access to API keys.
    pub fn inject(
        &self,
        headers: &mut axum::http::HeaderMap,
        host: &str,
    ) -> Result<()> {
        let cred = match self.credentials.get(host) {
            Some(c) => c,
            None => {
                tracing::debug!("No credential configured for host: {}", host);
                return Ok(());
            }
        };

        match cred {
            Credential::Bearer { token } => {
                headers.insert(
                    axum::http::header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {}", token))?,
                );
            }
            Credential::OAuth2 { access_token, .. } => {
                headers.insert(
                    axum::http::header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {}", access_token))?,
                );
            }
            Credential::ApiKey { header, value } => {
                headers.insert(
                    HeaderName::from_bytes(header.as_bytes())
                        .map_err(|e| anyhow!("Invalid header name '{}': {}", header, e))?,
                    HeaderValue::from_str(value)?,
                );
            }
        }

        Ok(())
    }
}
