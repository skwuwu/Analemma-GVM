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
    /// Create a store from a pre-built credential map. Used in tests.
    #[cfg(test)]
    pub fn from_map(credentials: HashMap<String, Credential>) -> Self {
        Self { credentials }
    }

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

        // Security check: secrets file should not be readable by group/other.
        // API keys in plaintext with 0644 permissions is a security risk.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:04o}", mode & 0o777),
                        "secrets.toml has insecure permissions — group/other can read API keys"
                    );
                    // Auto-fix to 0600
                    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                        Ok(()) => tracing::info!(
                            path = %path.display(),
                            "Fixed secrets.toml permissions to 0600"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "Cannot fix secrets.toml permissions — ensure only the proxy user can read this file"
                        ),
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_store() -> APIKeyStore {
        let mut credentials = HashMap::new();
        credentials.insert(
            "api.stripe.com".to_string(),
            Credential::Bearer {
                token: "sk_proxy_stripe_key".to_string(),
            },
        );
        credentials.insert(
            "api.sendgrid.com".to_string(),
            Credential::ApiKey {
                header: "x-api-key".to_string(),
                value: "SG.proxy_sendgrid_key".to_string(),
            },
        );
        APIKeyStore { credentials }
    }

    /// Agent has no key, proxy has key → proxy injects
    #[test]
    fn agent_no_key_proxy_injects() {
        let store = test_store();
        let mut headers = axum::http::HeaderMap::new();

        store
            .inject(
                &mut headers,
                "api.stripe.com",
                &MissingCredentialPolicy::Passthrough,
            )
            .unwrap();

        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk_proxy_stripe_key"
        );
    }

    /// Agent has its own key, proxy has key → proxy replaces agent's key
    #[test]
    fn agent_key_replaced_by_proxy() {
        let store = test_store();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer agent-own-stripe-key"),
        );

        store
            .inject(
                &mut headers,
                "api.stripe.com",
                &MissingCredentialPolicy::Passthrough,
            )
            .unwrap();

        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk_proxy_stripe_key",
            "Proxy key must replace agent's key"
        );
    }

    /// Agent has key, proxy has NO key for this host → agent key preserved (passthrough)
    #[test]
    fn agent_key_preserved_when_no_proxy_credential() {
        let store = test_store();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer agent-custom-api-key"),
        );
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("agent-extra-key"),
        );

        // Host NOT in store → passthrough
        store
            .inject(
                &mut headers,
                "custom-api.example.com",
                &MissingCredentialPolicy::Passthrough,
            )
            .unwrap();

        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer agent-custom-api-key",
            "Agent's key must pass through when proxy has no credential"
        );
        assert_eq!(
            headers.get("x-api-key").unwrap().to_str().unwrap(),
            "agent-extra-key",
            "Agent's extra headers must pass through"
        );
    }

    /// Agent has key + extra auth headers, proxy has key → ALL agent auth headers stripped
    #[test]
    fn all_agent_auth_headers_stripped_on_injection() {
        let store = test_store();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer agent-key"),
        );
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("agent-api-key"),
        );
        headers.insert(
            HeaderName::from_static("x-auth-token"),
            HeaderValue::from_static("agent-auth-token"),
        );
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("session=agent-session"),
        );

        store
            .inject(
                &mut headers,
                "api.stripe.com",
                &MissingCredentialPolicy::Passthrough,
            )
            .unwrap();

        // Proxy key injected
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            "Bearer sk_proxy_stripe_key"
        );
        // All agent auth headers stripped
        assert!(
            headers.get("x-api-key").is_none(),
            "x-api-key must be stripped"
        );
        assert!(
            headers.get("x-auth-token").is_none(),
            "x-auth-token must be stripped"
        );
        assert!(headers.get("cookie").is_none(), "cookie must be stripped");
    }

    /// No key anywhere (agent has nothing, proxy has nothing) → empty headers, no error
    #[test]
    fn no_key_anywhere_passthrough() {
        let store = test_store();
        let mut headers = axum::http::HeaderMap::new();

        store
            .inject(
                &mut headers,
                "unknown.example.com",
                &MissingCredentialPolicy::Passthrough,
            )
            .unwrap();

        assert!(
            headers.is_empty(),
            "No headers should be added for unknown host"
        );
    }
}
