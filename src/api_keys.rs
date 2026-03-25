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

/// Policy for handling requests to hosts without configured credentials.
#[derive(Clone, Debug, Default)]
pub enum MissingCredentialPolicy {
    /// Forward request as-is (development mode). Agent-supplied auth headers
    /// pass through unmodified. This is the default for MVP convenience.
    #[default]
    Passthrough,
    /// Reject request if no credential configured (production mode).
    /// Prevents agents from using their own credentials to bypass Layer 3.
    Deny,
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

    /// Get the credential for a host, if configured. Used by MITM path for injection.
    pub fn get_credential(&self, host: &str) -> Option<&Credential> {
        self.credentials.get(host)
    }

    /// Inject the appropriate credential into the request for the given host.
    /// This is Layer 3 (Capability Token) — the agent never has direct access to API keys.
    ///
    /// Security: strips any agent-supplied Authorization header before injecting
    /// the proxy's credential, preventing agents from smuggling their own credentials.
    pub fn inject(
        &self,
        headers: &mut axum::http::HeaderMap,
        host: &str,
        policy: &MissingCredentialPolicy,
    ) -> Result<()> {
        let cred = match self.credentials.get(host) {
            Some(c) => c,
            None => {
                return match policy {
                    MissingCredentialPolicy::Passthrough => {
                        tracing::debug!("No credential for {}, passing through", host);
                        Ok(())
                    }
                    MissingCredentialPolicy::Deny => {
                        tracing::warn!("No credential for {} — request denied", host);
                        Err(anyhow!("No API credential configured for {}", host))
                    }
                };
            }
        };

        // Strip all agent-supplied auth headers before injecting proxy credentials.
        // This prevents agents from bypassing Layer 3 by smuggling their own credentials.
        // Covers standard and common non-standard auth headers.
        headers.remove(axum::http::header::AUTHORIZATION);
        headers.remove(axum::http::header::COOKIE);
        headers.remove(axum::http::header::PROXY_AUTHORIZATION);
        for name in &[
            "x-api-key",
            "apikey",
            "x-auth-token",
            "x-api-token",
            "x-signature",
            "x-hmac",
            "x-credentials",
        ] {
            if let Ok(k) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(k);
            }
        }

        match cred {
            Credential::Bearer { token } => {
                headers.insert(
                    axum::http::header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {}", token))?,
                );
            }
            Credential::OAuth2 { access_token, .. } => {
                // TODO: Check expires_at and refresh if expired (P3)
                // Currently injects access_token regardless of expiry
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
