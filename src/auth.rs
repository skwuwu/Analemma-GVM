//! JWT-based agent identity verification.
//!
//! Replaces self-declared `X-GVM-Agent-Id` headers with cryptographically
//! verified identity tokens. HMAC-SHA256 signing/verification.
//!
//! When `GVM_JWT_SECRET` is configured:
//! - POST /gvm/auth/token issues JWTs with agent_id, tenant_id claims
//! - proxy_handler verifies Bearer tokens and overrides header identity
//! - Unverified requests emit warnings but still proceed (backward-compat)
//!
//! When not configured: JWT is disabled, header-based identity continues.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Maximum token size to prevent DoS via oversized tokens.
const MAX_TOKEN_BYTES: usize = 4096;

/// Maximum agent_id length.
const MAX_AGENT_ID_LEN: usize = 128;

/// Clock skew leeway (seconds) for expiration check.
const EXPIRY_LEEWAY_SECS: u64 = 5;

// ─── Secret Management ───

/// HMAC signing key with secure zeroing on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JwtSecret {
    key: Vec<u8>,
}

impl JwtSecret {
    /// Create a JwtSecret from raw bytes. Used by tests and fuzz targets.
    pub fn from_bytes(key: Vec<u8>) -> Self {
        Self { key }
    }
}

/// JWT configuration: secret + token parameters.
pub struct JwtConfig {
    pub secret: JwtSecret,
    pub token_ttl_secs: u64,
}

impl JwtConfig {
    /// Load JWT secret from the named environment variable (hex-encoded).
    /// Returns None if the env var is unset (JWT disabled).
    /// Errors if the value is invalid hex or too short (< 32 bytes).
    pub fn from_env(env_var: &str, token_ttl_secs: u64) -> Result<Option<Self>> {
        let hex_secret = match std::env::var(env_var) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let key = hex::decode(&hex_secret).map_err(|_| anyhow!("JWT secret must be valid hex"))?;

        if key.len() < 32 {
            return Err(anyhow!(
                "JWT secret too short ({} bytes, minimum 32)",
                key.len()
            ));
        }

        Ok(Some(Self {
            secret: JwtSecret { key },
            token_ttl_secs,
        }))
    }
}

// ─── JWT Claims ───

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Claims {
    /// Subject: agent_id
    pub sub: String,
    /// Tenant ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<String>,
    /// Scope (e.g., "proxy")
    pub scope: String,
    /// Issued-at (Unix timestamp)
    pub iat: u64,
    /// Expiration (Unix timestamp)
    pub exp: u64,
    /// Unique token ID for audit trail
    pub jti: String,
    /// Issuer
    pub iss: String,
}

// ─── Verified Identity (output of verification) ───

/// Cryptographically verified agent identity extracted from a valid JWT.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub agent_id: String,
    pub tenant_id: Option<String>,
    pub token_id: String,
}

// ─── Token Issuance ───

/// Issue a JWT for the given agent.
pub fn issue_token(
    config: &JwtConfig,
    agent_id: &str,
    tenant_id: Option<&str>,
    scope: &str,
) -> Result<String> {
    // Input validation
    if agent_id.is_empty() {
        return Err(anyhow!("agent_id must not be empty"));
    }
    if agent_id.len() > MAX_AGENT_ID_LEN {
        return Err(anyhow!(
            "agent_id exceeds maximum length ({})",
            MAX_AGENT_ID_LEN
        ));
    }
    if agent_id.contains(':') {
        return Err(anyhow!("agent_id must not contain ':'"));
    }

    let now = now_unix();
    let claims = Claims {
        sub: agent_id.to_string(),
        tid: tenant_id.map(String::from),
        scope: scope.to_string(),
        iat: now,
        exp: now + config.token_ttl_secs,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: "gvm-proxy".to_string(),
    };

    encode_jwt(&config.secret, &claims)
}

/// Issue a token response struct (for the API endpoint).
pub fn issue_token_response(
    config: &JwtConfig,
    agent_id: &str,
    tenant_id: Option<&str>,
    scope: &str,
) -> Result<TokenResponse> {
    let token = issue_token(config, agent_id, tenant_id, scope)?;
    Ok(TokenResponse {
        token,
        expires_in: config.token_ttl_secs,
        token_type: "Bearer".to_string(),
    })
}

#[derive(serde::Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: u64,
    pub token_type: String,
}

// ─── Token Verification ───

/// Verify a JWT and return the verified identity.
pub fn verify_token(config: &JwtConfig, token: &str) -> Result<VerifiedIdentity> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(anyhow!("Token exceeds maximum size"));
    }

    let claims = decode_jwt(&config.secret, token)?;

    // Check expiration with leeway
    let now = now_unix();
    if claims.exp + EXPIRY_LEEWAY_SECS < now {
        return Err(anyhow!("Token expired"));
    }

    // Reject tokens issued in the future (clock skew defense).
    // Allows EXPIRY_LEEWAY_SECS tolerance for minor clock drift.
    if claims.iat > now + EXPIRY_LEEWAY_SECS {
        return Err(anyhow!("Token issued in the future"));
    }

    // Check issuer
    if claims.iss != "gvm-proxy" {
        return Err(anyhow!("Invalid token issuer"));
    }

    Ok(VerifiedIdentity {
        agent_id: claims.sub,
        tenant_id: claims.tid,
        token_id: claims.jti,
    })
}

/// Extract Bearer token from Authorization header.
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}

// ─── JWT Encoding/Decoding (HS256, manual) ───

fn encode_jwt(secret: &JwtSecret, claims: &Claims) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

    let payload_json =
        serde_json::to_string(claims).map_err(|e| anyhow!("Failed to serialize claims: {}", e))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let mut mac =
        HmacSha256::new_from_slice(&secret.key).map_err(|e| anyhow!("HMAC key error: {}", e))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

fn decode_jwt(secret: &JwtSecret, token: &str) -> Result<Claims> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Malformed token"));
    }

    // Validate header algorithm before signature verification.
    // Defense against alg:none attack (CVE-2015-9235): reject any token
    // that does not declare HS256. Even though we always verify with HMAC,
    // explicit validation prevents future regressions if decode logic changes.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid token encoding"))?;
    let header_str =
        std::str::from_utf8(&header_bytes).map_err(|_| anyhow!("Invalid token header encoding"))?;
    let header_json: serde_json::Value =
        serde_json::from_str(header_str).map_err(|_| anyhow!("Invalid token header"))?;
    match header_json.get("alg").and_then(|v| v.as_str()) {
        Some("HS256") => {}
        Some(alg) => {
            tracing::warn!(algorithm = alg, "JWT with unexpected algorithm rejected");
            return Err(anyhow!("Unsupported token algorithm"));
        }
        None => return Err(anyhow!("Missing token algorithm")),
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    // Verify signature
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid token encoding"))?;

    let mut mac =
        HmacSha256::new_from_slice(&secret.key).map_err(|e| anyhow!("HMAC key error: {}", e))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| anyhow!("Invalid token signature"))?;

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| anyhow!("Invalid token encoding"))?;

    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|_| anyhow!("Invalid token payload"))?;

    Ok(claims)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(ttl: u64) -> JwtConfig {
        JwtConfig {
            secret: JwtSecret {
                key: vec![0xAB; 32],
            },
            token_ttl_secs: ttl,
        }
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let config = test_config(3600);
        let token = issue_token(&config, "agent-001", Some("tenant-a"), "proxy")
            .expect("issue must succeed");

        let identity = verify_token(&config, &token).expect("verify must succeed");
        assert_eq!(identity.agent_id, "agent-001");
        assert_eq!(identity.tenant_id.as_deref(), Some("tenant-a"));
        assert!(!identity.token_id.is_empty());
    }

    #[test]
    fn issue_without_tenant() {
        let config = test_config(3600);
        let token = issue_token(&config, "agent-002", None, "proxy").expect("issue must succeed");

        let identity = verify_token(&config, &token).expect("verify must succeed");
        assert_eq!(identity.agent_id, "agent-002");
        assert!(identity.tenant_id.is_none());
    }

    #[test]
    fn expired_token_rejected() {
        let config = test_config(0); // TTL = 0 seconds
        let token = issue_token(&config, "agent-001", None, "proxy").expect("issue must succeed");

        // Sleep beyond leeway
        std::thread::sleep(std::time::Duration::from_secs(EXPIRY_LEEWAY_SECS + 1));

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "Expired token must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("expired"),
            "Error must mention expiration"
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let config = test_config(3600);
        let mut token =
            issue_token(&config, "agent-001", None, "proxy").expect("issue must succeed");

        // Flip last character of signature
        let last = token.pop().expect("token must have characters");
        let replacement = if last == 'A' { 'B' } else { 'A' };
        token.push(replacement);

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "Tampered signature must be rejected");
    }

    #[test]
    fn tampered_payload_rejected() {
        let config = test_config(3600);
        let token = issue_token(&config, "agent-001", None, "proxy").expect("issue must succeed");

        // Modify payload section (second part)
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{}{}.{}", parts[0], parts[1], "X", parts[2]);

        let result = verify_token(&config, &tampered);
        assert!(result.is_err(), "Tampered payload must be rejected");
    }

    #[test]
    fn wrong_secret_rejected() {
        let config_a = test_config(3600);
        let config_b = JwtConfig {
            secret: JwtSecret {
                key: vec![0xCD; 32],
            },
            token_ttl_secs: 3600,
        };

        let token = issue_token(&config_a, "agent-001", None, "proxy").expect("issue must succeed");

        let result = verify_token(&config_b, &token);
        assert!(result.is_err(), "Wrong secret must reject token");
    }

    #[test]
    fn malformed_tokens_rejected() {
        let config = test_config(3600);

        let oversized = "x".repeat(5000);
        let malformed = vec![
            "",
            "not-a-jwt",
            "a.b",
            "a.b.c.d",
            "....",
            "header.payload",
            &oversized, // oversized
        ];

        for token in malformed {
            let result = verify_token(&config, token);
            assert!(
                result.is_err(),
                "Malformed token '{}' must be rejected",
                &token[..token.len().min(20)]
            );
        }
    }

    #[test]
    fn extract_bearer_token_valid() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("Authorization", "Bearer my-jwt-token".parse().unwrap());

        assert_eq!(extract_bearer_token(&headers), Some("my-jwt-token"));
    }

    #[test]
    fn extract_bearer_token_missing() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_wrong_scheme() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("Authorization", "Basic abc123".parse().unwrap());

        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_empty_token() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("Authorization", "Bearer ".parse().unwrap());

        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn input_validation_empty_agent_id() {
        let config = test_config(3600);
        let result = issue_token(&config, "", None, "proxy");
        assert!(result.is_err(), "Empty agent_id must be rejected");
    }

    #[test]
    fn input_validation_colon_in_agent_id() {
        let config = test_config(3600);
        let result = issue_token(&config, "admin:spoofed", None, "proxy");
        assert!(result.is_err(), "Colon in agent_id must be rejected");
    }

    #[test]
    fn input_validation_oversized_agent_id() {
        let config = test_config(3600);
        let long_id = "a".repeat(MAX_AGENT_ID_LEN + 1);
        let result = issue_token(&config, &long_id, None, "proxy");
        assert!(result.is_err(), "Oversized agent_id must be rejected");
    }

    #[test]
    fn token_response_format() {
        let config = test_config(3600);
        let resp =
            issue_token_response(&config, "agent-001", None, "proxy").expect("issue must succeed");

        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.token.is_empty());
    }

    #[test]
    fn secret_zeroized_on_drop() {
        // Verify zeroize contract: JwtSecret derives ZeroizeOnDrop, which
        // calls Vec::zeroize() before the heap buffer is deallocated.
        // We capture the buffer pointer pre-drop and read the same bytes
        // post-drop with read_volatile — if the sentinel pattern still
        // appears, Drop did not zero.
        //
        // SAFETY caveat: the allocator may reuse the slot before we read.
        // We use a 32-byte distinctive sentinel (0xA5) so an allocator-
        // recycled slot is unlikely to match. The test fails if and only
        // if the original sentinel survives — which proves "no zeroing".

        let sentinel: u8 = 0xA5;
        let secret = JwtSecret {
            key: vec![sentinel; 32],
        };
        assert_eq!(secret.key.len(), 32);

        // Capture the pointer to the Vec's heap buffer.
        let buf_ptr: *const u8 = secret.key.as_ptr();

        drop(secret);

        // Read 32 bytes through the captured pointer post-drop.
        // SAFETY: pointer is dangling after drop; we use read_volatile to
        // defeat the optimizer. If the allocator has reused the slot for
        // something else, we'll read non-sentinel bytes — still passing
        // the contract. Only "still all 0xA5" indicates zeroize ran NOT.
        let observed: [u8; 32] = unsafe {
            let mut buf = [0u8; 32];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = std::ptr::read_volatile(buf_ptr.add(i));
            }
            buf
        };

        assert_ne!(
            observed, [sentinel; 32],
            "JwtSecret heap buffer still holds the original sentinel after \
             drop — ZeroizeOnDrop did not zero. observed={:02x?}",
            observed,
        );
    }

    #[test]
    fn from_env_missing_returns_none() {
        // Use a unique env var name that is guaranteed not to be set
        let result = JwtConfig::from_env("GVM_TEST_JWT_SECRET_NONEXISTENT_12345", 3600)
            .expect("missing env var must return Ok(None)");
        assert!(result.is_none());
    }

    // ── CVE-2015-9235: JWT alg:none Attack ──

    #[test]
    fn alg_none_attack_rejected() {
        // CVE-2015-9235: attacker crafts token with {"alg":"none"} header
        // to bypass signature verification. Must be rejected explicitly.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let config = test_config(3600);

        // Craft a token with alg:none header
        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

        let payload = serde_json::json!({
            "sub": "attacker",
            "scope": "proxy",
            "iat": now_unix(),
            "exp": now_unix() + 3600,
            "jti": "fake-id",
            "iss": "gvm-proxy"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        // Empty signature (alg:none means no signature)
        let token = format!("{}.{}.", header_b64, payload_b64);

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "alg:none token must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("algorithm"),
            "Error must mention algorithm"
        );
    }

    #[test]
    fn alg_rs256_confusion_rejected() {
        // Algorithm confusion attack: HS256 key used as RS256 public key.
        // Must reject any algorithm that is not HS256.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let config = test_config(3600);

        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("{}.{}.fake-sig", header_b64, payload_b64);

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "RS256 token must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("algorithm"),
            "Error must mention algorithm"
        );
    }

    // ── JWT Wrong Issuer ──

    #[test]
    fn wrong_issuer_rejected() {
        let config = test_config(3600);

        // Issue a valid token, then forge one with wrong issuer
        let now = now_unix();
        let claims = Claims {
            sub: "agent-001".to_string(),
            tid: None,
            scope: "proxy".to_string(),
            iat: now,
            exp: now + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "evil-proxy".to_string(), // Wrong issuer
        };

        let token = encode_jwt(&config.secret, &claims).expect("encoding must succeed");

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "Wrong issuer must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("issuer"),
            "Error must mention issuer"
        );
    }

    // ── JWT Future Timestamp ──

    #[test]
    fn future_iat_rejected() {
        let config = test_config(3600);

        // Forge a token with iat far in the future (clock manipulation attack)
        let future_time = now_unix() + 3600; // 1 hour in the future
        let claims = Claims {
            sub: "agent-001".to_string(),
            tid: None,
            scope: "proxy".to_string(),
            iat: future_time,
            exp: future_time + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "gvm-proxy".to_string(),
        };

        let token = encode_jwt(&config.secret, &claims).expect("encoding must succeed");

        let result = verify_token(&config, &token);
        assert!(result.is_err(), "Future iat must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("future"),
            "Error must mention future"
        );
    }

    #[test]
    fn slight_clock_skew_iat_accepted() {
        // iat slightly in the future (within EXPIRY_LEEWAY_SECS) should be accepted
        let config = test_config(3600);

        let now = now_unix();
        let claims = Claims {
            sub: "agent-001".to_string(),
            tid: None,
            scope: "proxy".to_string(),
            iat: now + EXPIRY_LEEWAY_SECS - 1, // Within leeway
            exp: now + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "gvm-proxy".to_string(),
        };

        let token = encode_jwt(&config.secret, &claims).expect("encoding must succeed");

        let result = verify_token(&config, &token);
        assert!(
            result.is_ok(),
            "Slight clock skew within leeway must be accepted"
        );
    }
}
