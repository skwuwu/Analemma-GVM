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
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
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

// ─── Algorithm dispatch ───

/// JWT signing algorithm. Operator picks ONE per deployment; the proxy
/// rejects tokens whose header `alg` does not match (alg-confusion
/// defense, CVE-2015-9235).
///
/// - `Hs256` — HMAC-SHA256, symmetric. Same secret signs and verifies;
///   simplest config; cannot be verified by parties who do not hold the
///   secret. The original v1 default.
/// - `Ed25519` — EdDSA over Curve25519 per RFC 8037. Asymmetric: the
///   proxy holds the private signing key, external auditors verify with
///   only the public key. Useful when token authenticity must be
///   verifiable downstream (compliance evidence, third-party auditor)
///   without sharing the signing key. ~50 µs sign, ~150 µs verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtAlgorithm {
    Hs256,
    Ed25519,
}

impl JwtAlgorithm {
    /// The JWS header `alg` string for this algorithm.
    pub fn jws_alg(&self) -> &'static str {
        match self {
            JwtAlgorithm::Hs256 => "HS256",
            JwtAlgorithm::Ed25519 => "EdDSA",
        }
    }

    /// Parse from the value an operator wrote in `[jwt] algorithm = "..."`.
    pub fn from_config_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "hs256" | "hmac" | "" => Ok(JwtAlgorithm::Hs256),
            "ed25519" | "eddsa" => Ok(JwtAlgorithm::Ed25519),
            other => Err(anyhow!(
                "Unsupported JWT algorithm: '{}'. Supported: hs256, ed25519",
                other
            )),
        }
    }
}

// ─── Secret Management ───

/// HMAC signing key with secure zeroing on drop. Retained as a
/// distinct type so the HS256 path keeps its existing zeroization
/// guarantee; the Ed25519 path uses `SigningKey` whose key material
/// is already zeroized by `ed25519-dalek` on drop.
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

/// Key material — variant tied to `JwtAlgorithm` choice. Operator
/// supplies one or the other depending on the configured algorithm.
pub enum JwtKeyMaterial {
    Hmac(JwtSecret),
    Ed25519 {
        signing: SigningKey,
        verifying: VerifyingKey,
    },
}

/// A single key slot in the multi-key rotation set. One slot is
/// `active = true` (used for signing); all slots are eligible for
/// verification as long as `expires_at` is in the future (or `None`).
///
/// Rotation pattern (active + previous, advance on a schedule):
/// 1. Add a new slot with `active = false`, `expires_at = None`.
/// 2. Promote it: set `active = true`; demote the previous active
///    by setting `active = false`, `expires_at = now + grace`.
/// 3. After grace expires, no token signed by the old key remains
///    valid. Operator removes the slot at next reload.
///
/// All steps are hot-reloadable via `POST /gvm/reload` — no proxy
/// restart, no in-flight verify torn down (atomic snapshot under
/// the `Arc<RwLock<...>>` reader path).
pub struct JwtKeySlot {
    /// Operator-assigned label. Baked into the JWS header `kid` so
    /// the verifier can locate the right slot for a given token.
    /// Empty string is allowed (matches header without `kid`), but
    /// only one such slot may exist or look-up is ambiguous.
    pub kid: String,
    /// Key material — algorithm must match `JwtConfig.algorithm`.
    pub material: JwtKeyMaterial,
    /// Exactly one slot in a `JwtConfig.keys` vector carries
    /// `active = true`. Signing always uses that slot; verification
    /// uses any matching `kid` regardless of active status.
    pub active: bool,
    /// Optional automatic expiry. After this wall-clock time, the
    /// slot is excluded from verification even if it is still in
    /// the keys vector — operator can leave deprecated slots in
    /// place and rely on the timer to retire them safely.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Maximum number of slots in a single `JwtConfig.keys` vector.
/// Picked low (4) so the verify-time linear scan stays cheap and a
/// runaway config can't blow up memory. Active + immediately
/// preceding + one in pre-promotion + one safety margin is the
/// realistic upper bound for any rotation cadence.
pub const MAX_KEY_SLOTS: usize = 4;

/// JWT configuration: algorithm + key material + token parameters.
pub struct JwtConfig {
    pub algorithm: JwtAlgorithm,
    /// One or more key slots. Exactly one carries `active = true`.
    /// Capped at `MAX_KEY_SLOTS`.
    pub keys: Vec<JwtKeySlot>,
    pub token_ttl_secs: u64,
    /// Strict mode — reject requests without a valid Bearer token.
    /// See `JwtAuthConfig.strict` in src/config.rs for rationale.
    pub strict: bool,
    /// Path to a revocation list file (one jti per line). `None`
    /// disables revocation enforcement.
    pub revocation_file: Option<std::path::PathBuf>,
}

impl JwtConfig {
    /// Load JWT secret from the named environment variable (hex-encoded).
    /// Returns None if the env var is unset (JWT disabled).
    /// Errors if the value is invalid hex or too short (< 32 bytes).
    ///
    /// Produces an HS256 config; the Ed25519 variant is loaded via
    /// `from_env_ed25519`.
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
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![JwtKeySlot {
                kid: String::new(),
                material: JwtKeyMaterial::Hmac(JwtSecret { key }),
                active: true,
                expires_at: None,
            }],
            token_ttl_secs,
            strict: false,
            revocation_file: None,
        }))
    }

    /// Load an Ed25519 signing key from a 32-byte seed (hex-encoded)
    /// in the named environment variable, plus a `key_id` operators
    /// embed in the JWS header `kid` claim so auditors can pick the
    /// matching verifying key from a registry.
    ///
    /// Returns `Ok(None)` when the env var is unset (JWT disabled);
    /// errors if the seed is not valid hex or not exactly 32 bytes.
    pub fn from_env_ed25519(
        seed_env: &str,
        key_id: impl Into<String>,
        token_ttl_secs: u64,
    ) -> Result<Option<Self>> {
        let hex_seed = match std::env::var(seed_env) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let bytes = hex::decode(&hex_seed).map_err(|_| {
            anyhow!("JWT Ed25519 seed must be valid hex (64 hex chars = 32 bytes)")
        })?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "JWT Ed25519 seed must be exactly 32 bytes (got {})",
                bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Ok(Some(Self {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![JwtKeySlot {
                kid: key_id.into(),
                material: JwtKeyMaterial::Ed25519 {
                    signing,
                    verifying,
                },
                active: true,
                expires_at: None,
            }],
            token_ttl_secs,
            strict: false,
            revocation_file: None,
        }))
    }

    /// Validate the slot invariants: at least one slot, exactly one
    /// active, no duplicate `kid`, length ≤ MAX_KEY_SLOTS. Called by
    /// the constructors and the hot-reload path.
    pub fn validate_slots(&self) -> Result<()> {
        if self.keys.is_empty() {
            return Err(anyhow!("JwtConfig must have at least one key slot"));
        }
        if self.keys.len() > MAX_KEY_SLOTS {
            return Err(anyhow!(
                "JwtConfig has {} slots; max is {}",
                self.keys.len(),
                MAX_KEY_SLOTS
            ));
        }
        let active_count = self.keys.iter().filter(|s| s.active).count();
        if active_count != 1 {
            return Err(anyhow!(
                "JwtConfig must have exactly one active slot (got {})",
                active_count
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for slot in &self.keys {
            if !seen.insert(slot.kid.as_str()) {
                return Err(anyhow!(
                    "JwtConfig has duplicate kid '{}'",
                    slot.kid
                ));
            }
        }
        Ok(())
    }

    /// Reference to the currently active slot. Panics if the slot
    /// invariants are violated — callers must `validate_slots` after
    /// constructing or reloading the config.
    pub fn active_slot(&self) -> &JwtKeySlot {
        self.keys
            .iter()
            .find(|s| s.active)
            .expect("validate_slots was not called or did not enforce active=1")
    }

    /// Locate a slot by `kid`. Used by `decode_jwt` to dispatch the
    /// verifying key. Slot is rejected (returned as `None`) if its
    /// `expires_at` is in the past, so the verifier transparently
    /// skips retired rotation slots without operator intervention.
    pub fn slot_by_kid(&self, kid: &str) -> Option<&JwtKeySlot> {
        let now = chrono::Utc::now();
        self.keys.iter().find(|s| {
            s.kid == kid && s.expires_at.map(|t| t > now).unwrap_or(true)
        })
    }

    /// Hex-encoded public key of the active slot, when the algorithm
    /// is Ed25519. Lets the proxy expose the verifying key to auditors
    /// via a static admin endpoint (out of scope here — operators can
    /// also just `xxd` the configured seed since they already trust
    /// the host that minted the key).
    pub fn public_key_hex(&self) -> Option<String> {
        match &self.active_slot().material {
            JwtKeyMaterial::Ed25519 { verifying, .. } => Some(hex::encode(verifying.as_bytes())),
            JwtKeyMaterial::Hmac(_) => None,
        }
    }

    /// Set strict-mode flag (chainable).
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Set revocation-list path (chainable).
    pub fn with_revocation_file(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.revocation_file = path;
        self
    }
}

/// Check whether `jti` appears in the revocation file. Re-reads the
/// file on every call so operators can append entries and have them
/// honoured on the next verify (no restart required). Returns false
/// (treat as not revoked) if the file is missing or unreadable — this
/// is fail-OPEN for the revocation list specifically; the rationale is
/// that an admin error (typo'd path, file moved) should not lock all
/// agents out. Operators paranoid about file availability should
/// monitor the proxy's startup log line which prints the resolved
/// revocation_file path.
pub fn is_jti_revoked(revocation_file: &std::path::Path, jti: &str) -> bool {
    let content = match std::fs::read_to_string(revocation_file) {
        Ok(s) => s,
        Err(_) => return false,
    };
    content
        .lines()
        .map(|line| line.trim())
        .any(|line| !line.is_empty() && !line.starts_with('#') && line == jti)
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
    /// Role marker for privilege-separated tokens. `None` (default)
    /// for normal agent tokens; `Some("admin")` for tokens minted to
    /// drive the admin port. Validated by the admin-port middleware
    /// when admin_listen is non-loopback. Kept narrow on purpose —
    /// SRR rule matching does NOT consult this field (that would
    /// resurrect the cross-agent privilege boundary that v0.7 was
    /// reframed to avoid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gvm_role: Option<String>,
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
    /// `gvm_role` claim from the token. `None` for normal agent
    /// tokens; `Some("admin")` for tokens minted via
    /// `issue_admin_token` and meant for the admin port.
    pub gvm_role: Option<String>,
}

impl VerifiedIdentity {
    /// Whether this identity has the `admin` role claim. Used by
    /// the admin-port middleware to gate access.
    pub fn is_admin(&self) -> bool {
        self.gvm_role.as_deref() == Some("admin")
    }
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
        gvm_role: None,
        iat: now,
        exp: now + config.token_ttl_secs,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: "gvm-proxy".to_string(),
    };

    encode_jwt(config, &claims)
}

/// Issue a JWT carrying the `admin` role claim. Used at proxy
/// bootstrap to produce a one-shot operator token when the admin
/// port is bound to a non-loopback address; also reachable via the
/// admin endpoint `POST /gvm/auth/token` when called by an already-
/// authenticated admin caller.
///
/// The `sub` claim is set to a synthetic marker (`admin:<label>`) so
/// audit events tied to this token are distinguishable from agent
/// traffic in the WAL.
pub fn issue_admin_token(
    config: &JwtConfig,
    label: &str,
    ttl_secs_override: Option<u64>,
) -> Result<String> {
    if label.is_empty() {
        return Err(anyhow!("admin token label must not be empty"));
    }
    if label.len() > 64 {
        return Err(anyhow!("admin token label too long (max 64)"));
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(anyhow!(
            "admin token label may only contain [A-Za-z0-9-_.]"
        ));
    }
    let now = now_unix();
    let ttl = ttl_secs_override.unwrap_or(config.token_ttl_secs);
    let claims = Claims {
        sub: format!("admin:{}", label),
        tid: None,
        scope: "admin".to_string(),
        gvm_role: Some("admin".to_string()),
        iat: now,
        exp: now + ttl,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: "gvm-proxy".to_string(),
    };
    encode_jwt(config, &claims)
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

    let claims = decode_jwt(config, token)?;

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

    // Revocation check (no-op when revocation_file is None).
    if let Some(ref rev_path) = config.revocation_file {
        if is_jti_revoked(rev_path, &claims.jti) {
            return Err(anyhow!("Token revoked"));
        }
    }

    Ok(VerifiedIdentity {
        agent_id: claims.sub,
        tenant_id: claims.tid,
        token_id: claims.jti,
        gvm_role: claims.gvm_role,
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

fn encode_jwt(config: &JwtConfig, claims: &Claims) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Signing always uses the ACTIVE slot. Verification is
    // multi-slot (any non-expired matching kid), but minting is
    // unambiguous — exactly one private key produces tokens.
    let slot = config.active_slot();
    let alg = config.algorithm.jws_alg();

    // Header — include `kid` so verifiers (and rotated past slots)
    // can dispatch. Sanitize kid against JSON-escape injection.
    let safe_kid: String = slot
        .kid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    let header_json = if safe_kid.is_empty() {
        format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg)
    } else {
        format!(r#"{{"alg":"{}","typ":"JWT","kid":"{}"}}"#, alg, safe_kid)
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let payload_json =
        serde_json::to_string(claims).map_err(|e| anyhow!("Failed to serialize claims: {}", e))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature_bytes: Vec<u8> = match &slot.material {
        JwtKeyMaterial::Hmac(secret) => {
            let mut mac = HmacSha256::new_from_slice(&secret.key)
                .map_err(|e| anyhow!("HMAC key error: {}", e))?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        JwtKeyMaterial::Ed25519 { signing, .. } => {
            let sig = signing.sign(signing_input.as_bytes());
            sig.to_bytes().to_vec()
        }
    };
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

fn decode_jwt(config: &JwtConfig, token: &str) -> Result<Claims> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Malformed token"));
    }

    // Validate header algorithm against the OPERATOR-CONFIGURED choice
    // before signature verification. Defense against:
    //  1. alg:none (CVE-2015-9235).
    //  2. alg-confusion attacks (CVE-2018-1000531-class): an attacker
    //     swaps the header to HS256 and signs with the public key as
    //     HMAC secret; if the verifier blindly trusts the header, it
    //     accepts. We instead refuse any token whose header `alg` does
    //     not equal what the operator told us to use.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow!("Invalid token encoding"))?;
    let header_str =
        std::str::from_utf8(&header_bytes).map_err(|_| anyhow!("Invalid token header encoding"))?;
    let header_json: serde_json::Value =
        serde_json::from_str(header_str).map_err(|_| anyhow!("Invalid token header"))?;
    let token_alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing token algorithm"))?;
    let expected_alg = config.algorithm.jws_alg();
    if token_alg != expected_alg {
        tracing::warn!(
            token_alg = token_alg,
            expected = expected_alg,
            "JWT with mismatched algorithm rejected (alg-confusion defense)"
        );
        return Err(anyhow!("Unsupported token algorithm"));
    }

    // Dispatch the verifying key by header `kid`. Token without
    // `kid` falls back to the active slot — preserves backward compat
    // for legacy tokens minted before multi-slot landed (kid="").
    let token_kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let slot = match config.slot_by_kid(token_kid) {
        Some(s) => s,
        None => {
            tracing::warn!(
                token_kid = token_kid,
                "JWT kid does not match any active key slot (rotation in progress, or token signed by retired key)"
            );
            return Err(anyhow!("No verifying key for token kid"));
        }
    };

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    // Verify signature with the slot's key.
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| anyhow!("Invalid token encoding"))?;

    match &slot.material {
        JwtKeyMaterial::Hmac(secret) => {
            let mut mac = HmacSha256::new_from_slice(&secret.key)
                .map_err(|e| anyhow!("HMAC key error: {}", e))?;
            mac.update(signing_input.as_bytes());
            mac.verify_slice(&signature)
                .map_err(|_| anyhow!("Invalid token signature"))?;
        }
        JwtKeyMaterial::Ed25519 { verifying, .. } => {
            let sig_bytes: &[u8; 64] = signature.as_slice().try_into().map_err(|_| {
                anyhow!("EdDSA signature must be exactly 64 bytes")
            })?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            verifying
                .verify(signing_input.as_bytes(), &sig)
                .map_err(|_| anyhow!("Invalid token signature"))?;
        }
    }

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

// ─── Admin port middleware ───

/// Axum middleware that enforces an admin-role JWT on every request.
/// Wired by main.rs onto the admin router when the admin listener is
/// bound to a non-loopback address (defense-in-depth — even if the
/// `allow_non_loopback_admin` policy gate is misconfigured or bypassed
/// by an L4/L7 forwarder, the runtime refuses unauthenticated callers).
///
/// For loopback admin (default), this middleware is NOT installed —
/// the trust path is "anyone with shell access on the host is already
/// the operator," matching the assumption baked into ServerConfig.
///
/// Returns 401 Unauthorized on:
///   - No `Authorization: Bearer <token>` header
///   - JWT verification failure (bad signature, expired, revoked, ...)
///   - Valid JWT but `gvm_role != "admin"`
pub async fn require_admin_jwt(
    axum::extract::State(jwt_config): axum::extract::State<std::sync::Arc<JwtConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> std::result::Result<axum::response::Response, axum::http::StatusCode> {
    let token = match extract_bearer_token(req.headers()) {
        Some(t) => t,
        None => {
            tracing::warn!(
                path = %req.uri().path(),
                "Admin port: rejecting request without Bearer token (non-loopback bind enforces JWT)"
            );
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    };
    let identity = match verify_token(&jwt_config, token) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                path = %req.uri().path(),
                error = %e,
                "Admin port: rejecting token (verification failed)"
            );
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    };
    if !identity.is_admin() {
        tracing::warn!(
            path = %req.uri().path(),
            sub = %identity.agent_id,
            "Admin port: rejecting token (gvm_role != admin)"
        );
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    fn single_slot_hmac(secret: Vec<u8>) -> JwtKeySlot {
        JwtKeySlot {
            kid: String::new(),
            material: JwtKeyMaterial::Hmac(JwtSecret { key: secret }),
            active: true,
            expires_at: None,
        }
    }

    fn single_slot_ed25519(seed: [u8; 32], kid: &str) -> JwtKeySlot {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        JwtKeySlot {
            kid: kid.to_string(),
            material: JwtKeyMaterial::Ed25519 { signing, verifying },
            active: true,
            expires_at: None,
        }
    }

    fn test_config(ttl: u64) -> JwtConfig {
        JwtConfig {
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![single_slot_hmac(vec![0xAB; 32])],
            token_ttl_secs: ttl,
            strict: false,
            revocation_file: None,
        }
    }

    fn test_config_ed25519(ttl: u64, key_id: &str) -> JwtConfig {
        JwtConfig {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![single_slot_ed25519([0xCD; 32], key_id)],
            token_ttl_secs: ttl,
            strict: false,
            revocation_file: None,
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
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![single_slot_hmac(vec![0xCD; 32])],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
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
            gvm_role: None,
            iat: now,
            exp: now + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "evil-proxy".to_string(), // Wrong issuer
        };

        let token = encode_jwt(&config, &claims).expect("encoding must succeed");

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
            gvm_role: None,
            iat: future_time,
            exp: future_time + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "gvm-proxy".to_string(),
        };

        let token = encode_jwt(&config, &claims).expect("encoding must succeed");

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
            gvm_role: None,
            iat: now + EXPIRY_LEEWAY_SECS - 1, // Within leeway
            exp: now + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "gvm-proxy".to_string(),
        };

        let token = encode_jwt(&config, &claims).expect("encoding must succeed");

        let result = verify_token(&config, &token);
        assert!(
            result.is_ok(),
            "Slight clock skew within leeway must be accepted"
        );
    }

    // ── Revocation list ──────────────────────────────────────────

    #[test]
    fn revoked_jti_rejected() {
        let tmpdir = tempfile::TempDir::new().expect("tempdir");
        let rev_path = tmpdir.path().join("revoked.txt");
        // Issue a token under a plain config so we can read its jti.
        let cfg = test_config(3600);
        let token = issue_token(&cfg, "agent-rev", None, "proxy").expect("issue");
        let claims = decode_jwt(&cfg, &token).expect("decode");

        // Build a config with revocation enabled pointing at the file.
        let cfg_rev = JwtConfig {
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![single_slot_hmac(vec![0xAB; 32])],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: Some(rev_path.clone()),
        };

        // Before revocation: valid.
        assert!(verify_token(&cfg_rev, &token).is_ok(), "unrevoked must pass");

        // Append jti and re-verify: must fail.
        std::fs::write(&rev_path, format!("{}\n", claims.jti)).expect("write rev");
        let err = verify_token(&cfg_rev, &token).expect_err("must reject");
        assert!(
            err.to_string().contains("revoked"),
            "error must mention revocation, got: {err}"
        );
    }

    #[test]
    fn revocation_file_missing_does_not_block() {
        // Operator typo: revocation_file path doesn't exist. Verification
        // must NOT lock everyone out — it should fail-OPEN on the
        // revocation check (consistent with is_jti_revoked's contract).
        let cfg = JwtConfig {
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![single_slot_hmac(vec![0xAB; 32])],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: Some(std::path::PathBuf::from(
                "/nonexistent/path/that/should/not/exist",
            )),
        };
        let token = issue_token(&cfg, "agent-x", None, "proxy").expect("issue");
        assert!(
            verify_token(&cfg, &token).is_ok(),
            "missing revocation file must not block"
        );
    }

    #[test]
    fn revocation_file_comments_and_blanks_ignored() {
        let tmpdir = tempfile::TempDir::new().expect("tempdir");
        let rev_path = tmpdir.path().join("revoked.txt");
        std::fs::write(
            &rev_path,
            "# header comment\n\n  \n# another comment\nactual-jti-here\n",
        )
        .expect("write");
        assert!(is_jti_revoked(&rev_path, "actual-jti-here"));
        assert!(!is_jti_revoked(&rev_path, "# header comment"));
        assert!(!is_jti_revoked(&rev_path, ""));
        assert!(!is_jti_revoked(&rev_path, "unrelated"));
    }

    // ── Asymmetric (Ed25519) algorithm ──────────────────────────

    #[test]
    fn ed25519_round_trip() {
        let cfg = test_config_ed25519(3600, "audit-key-2026");
        let token = issue_token(&cfg, "agent-001", Some("tenant-a"), "proxy")
            .expect("Ed25519 issue must succeed");
        let identity = verify_token(&cfg, &token).expect("Ed25519 verify must succeed");
        assert_eq!(identity.agent_id, "agent-001");
        assert_eq!(identity.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn ed25519_header_contains_kid_and_eddsa_alg() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let cfg = test_config_ed25519(3600, "audit-key-2026");
        let token = issue_token(&cfg, "agent-001", None, "proxy").expect("issue");
        let header_b64 = token.split('.').next().unwrap();
        let header = String::from_utf8(URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert!(header.contains(r#""alg":"EdDSA""#), "header must declare EdDSA: {header}");
        assert!(header.contains(r#""kid":"audit-key-2026""#), "header must carry kid: {header}");
    }

    #[test]
    fn ed25519_kid_sanitized_against_json_escape_injection() {
        // Operator-supplied kid contains a quote — must NOT break out
        // of the JSON header.
        let signing = SigningKey::from_bytes(&[0xEE; 32]);
        let verifying = signing.verifying_key();
        let cfg = JwtConfig {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![JwtKeySlot {
                kid: r#"evil","alg":"none","x":""#.to_string(),
                material: JwtKeyMaterial::Ed25519 { signing, verifying },
                active: true,
                expires_at: None,
            }],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
        };
        let token = issue_token(&cfg, "agent-x", None, "proxy").expect("issue");
        // Decode + parse header; must still be valid JSON, alg must
        // remain EdDSA (not the attacker's "none").
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("base64 decode");
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("JSON parse");
        assert_eq!(header["alg"], "EdDSA", "alg must remain EdDSA after sanitization");
        assert!(!header["kid"].as_str().unwrap().contains('"'));
    }

    // ── Algorithm-confusion attack defense (CVE-2018-1000531 class) ─

    #[test]
    fn ed25519_config_rejects_hs256_signed_token() {
        // Attacker takes the EdDSA public key, treats it as HMAC
        // secret, and signs an HS256 token. Verifier configured for
        // EdDSA MUST reject — `alg` mismatch detected before
        // signature verification ever runs.
        let cfg_ed = test_config_ed25519(3600, "k");
        let public_bytes = match &cfg_ed.active_slot().material {
            JwtKeyMaterial::Ed25519 { verifying, .. } => verifying.as_bytes().to_vec(),
            _ => unreachable!(),
        };
        // Forge an HS256 token using the public key as the HMAC secret.
        let cfg_attacker = JwtConfig {
            algorithm: JwtAlgorithm::Hs256,
            keys: vec![single_slot_hmac(public_bytes)],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
        };
        let token = issue_token(&cfg_attacker, "agent-evil", None, "proxy")
            .expect("attacker forges HS256 token");
        // Real verifier (EdDSA-configured) must reject.
        let result = verify_token(&cfg_ed, &token);
        assert!(result.is_err(), "Ed25519 verifier must refuse HS256 token");
        assert!(
            result.unwrap_err().to_string().contains("algorithm"),
            "error must indicate algorithm mismatch"
        );
    }

    #[test]
    fn hs256_config_rejects_eddsa_signed_token() {
        // Symmetric case: an HS256-configured verifier must refuse a
        // legitimately signed EdDSA token (even though the EdDSA
        // signature would verify against the public key, the verifier
        // is locked to HMAC by config and treats the token as wrong-alg).
        let cfg_ed = test_config_ed25519(3600, "k");
        let token = issue_token(&cfg_ed, "agent-001", None, "proxy").expect("EdDSA issue");
        let cfg_hs = test_config(3600);
        let result = verify_token(&cfg_hs, &token);
        assert!(result.is_err(), "HS256 verifier must refuse EdDSA token");
    }

    #[test]
    fn ed25519_tampered_signature_rejected() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let cfg = test_config_ed25519(3600, "k");
        let token = issue_token(&cfg, "agent-001", None, "proxy").expect("issue");
        let parts: Vec<&str> = token.split('.').collect();
        // Flip a single bit in the signature.
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("base64");
        sig_bytes[0] ^= 0x01;
        let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);
        assert!(verify_token(&cfg, &tampered).is_err());
    }

    #[test]
    fn ed25519_wrong_seed_rejected() {
        let cfg_a = test_config_ed25519(3600, "ka");
        let token = issue_token(&cfg_a, "agent-001", None, "proxy").expect("issue");
        // Different seed => different keypair.
        let other_signing = SigningKey::from_bytes(&[0x77; 32]);
        let other_verifying = other_signing.verifying_key();
        let cfg_b = JwtConfig {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![JwtKeySlot {
                kid: "ka".to_string(),  // SAME kid as cfg_a so kid-dispatch hits this slot
                material: JwtKeyMaterial::Ed25519 {
                    signing: other_signing,
                    verifying: other_verifying,
                },
                active: true,
                expires_at: None,
            }],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
        };
        assert!(verify_token(&cfg_b, &token).is_err());
    }

    #[test]
    fn algorithm_none_attack_rejected_for_eddsa() {
        // CVE-2015-9235: header forged to {"alg":"none"} + empty sig.
        // Must be rejected even when verifier is EdDSA-configured.
        let cfg = test_config_ed25519(3600, "k");
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let evil_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims = Claims {
            sub: "agent-evil".to_string(),
            tid: None,
            scope: "proxy".to_string(),
            gvm_role: None,
            iat: now_unix(),
            exp: now_unix() + 3600,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "gvm-proxy".to_string(),
        };
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let token = format!("{}.{}.", evil_header, payload);
        assert!(verify_token(&cfg, &token).is_err());
    }

    #[test]
    fn algorithm_from_config_str_parses_known_aliases() {
        assert_eq!(
            JwtAlgorithm::from_config_str("hs256").unwrap(),
            JwtAlgorithm::Hs256
        );
        assert_eq!(
            JwtAlgorithm::from_config_str("HMAC").unwrap(),
            JwtAlgorithm::Hs256
        );
        assert_eq!(
            JwtAlgorithm::from_config_str("ed25519").unwrap(),
            JwtAlgorithm::Ed25519
        );
        assert_eq!(
            JwtAlgorithm::from_config_str("EdDSA").unwrap(),
            JwtAlgorithm::Ed25519
        );
        assert_eq!(
            JwtAlgorithm::from_config_str("").unwrap(),
            JwtAlgorithm::Hs256,
            "empty string must default to HS256 for backward-compat"
        );
        assert!(JwtAlgorithm::from_config_str("rs256").is_err());
        assert!(JwtAlgorithm::from_config_str("none").is_err());
    }

    #[test]
    fn ed25519_from_env_seed_loads_keypair() {
        // Operator path: seed comes from env var as 64 hex chars.
        std::env::set_var(
            "GVM_TEST_JWT_ED25519_SEED",
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let cfg = JwtConfig::from_env_ed25519("GVM_TEST_JWT_ED25519_SEED", "k1", 3600)
            .expect("load")
            .expect("seed must produce a config");
        assert_eq!(cfg.algorithm, JwtAlgorithm::Ed25519);
        assert!(cfg.public_key_hex().is_some());
        std::env::remove_var("GVM_TEST_JWT_ED25519_SEED");
    }

    #[test]
    fn admin_token_carries_admin_role() {
        let cfg = test_config(3600);
        let token = issue_admin_token(&cfg, "bootstrap", None).expect("admin issue");
        let identity = verify_token(&cfg, &token).expect("verify");
        assert!(identity.is_admin(), "admin token must report is_admin");
        assert_eq!(identity.gvm_role.as_deref(), Some("admin"));
        assert_eq!(identity.agent_id, "admin:bootstrap");
    }

    #[test]
    fn admin_token_label_validated() {
        let cfg = test_config(3600);
        assert!(issue_admin_token(&cfg, "", None).is_err());
        assert!(issue_admin_token(&cfg, &"x".repeat(65), None).is_err());
        assert!(issue_admin_token(&cfg, "bad label", None).is_err()); // space
        assert!(issue_admin_token(&cfg, "evil\"escape", None).is_err());
        assert!(issue_admin_token(&cfg, "gvm-cli-laptop_2026.q2", None).is_ok());
    }

    #[test]
    fn agent_token_does_not_have_admin_role() {
        let cfg = test_config(3600);
        let token = issue_token(&cfg, "agent-001", None, "proxy").expect("issue");
        let identity = verify_token(&cfg, &token).expect("verify");
        assert!(!identity.is_admin(), "agent token must NOT report is_admin");
        assert_eq!(identity.gvm_role, None);
    }

    #[test]
    fn ed25519_admin_token_works() {
        let cfg = test_config_ed25519(3600, "k1");
        let token = issue_admin_token(&cfg, "ci-runner", None).expect("issue");
        let identity = verify_token(&cfg, &token).expect("verify");
        assert!(identity.is_admin());
    }

    #[test]
    fn ed25519_from_env_rejects_wrong_seed_length() {
        std::env::set_var("GVM_TEST_JWT_ED25519_SHORT", "deadbeef");
        let result = JwtConfig::from_env_ed25519("GVM_TEST_JWT_ED25519_SHORT", "k", 3600);
        assert!(result.is_err());
        std::env::remove_var("GVM_TEST_JWT_ED25519_SHORT");
    }

    // ── Multi-key slot rotation (Phase B) ──────────────────────

    fn multi_slot_config(active_seed: [u8; 32], prev_seed: [u8; 32]) -> JwtConfig {
        JwtConfig {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![
                JwtKeySlot {
                    kid: "active".to_string(),
                    material: {
                        let s = SigningKey::from_bytes(&active_seed);
                        let v = s.verifying_key();
                        JwtKeyMaterial::Ed25519 { signing: s, verifying: v }
                    },
                    active: true,
                    expires_at: None,
                },
                JwtKeySlot {
                    kid: "previous".to_string(),
                    material: {
                        let s = SigningKey::from_bytes(&prev_seed);
                        let v = s.verifying_key();
                        JwtKeyMaterial::Ed25519 { signing: s, verifying: v }
                    },
                    active: false,
                    expires_at: None,
                },
            ],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
        }
    }

    #[test]
    fn validate_slots_enforces_invariants() {
        // Empty slot vec → error
        let mut cfg = test_config(3600);
        cfg.keys.clear();
        assert!(cfg.validate_slots().is_err());

        // Two active slots → error
        let mut cfg = test_config(3600);
        cfg.keys.push(single_slot_hmac(vec![0x11; 32]));
        // both have active = true now
        assert!(cfg.validate_slots().is_err());

        // No active slot → error
        let mut cfg = test_config(3600);
        cfg.keys[0].active = false;
        assert!(cfg.validate_slots().is_err());

        // Duplicate kid → error
        let mut cfg = test_config(3600);
        let dup_kid = cfg.keys[0].kid.clone();
        cfg.keys.push(JwtKeySlot {
            kid: dup_kid,
            material: JwtKeyMaterial::Hmac(JwtSecret { key: vec![0x22; 32] }),
            active: false,
            expires_at: None,
        });
        assert!(cfg.validate_slots().is_err());

        // Too many slots (cap MAX_KEY_SLOTS=4) → error
        let mut cfg = test_config(3600);
        for i in 0..MAX_KEY_SLOTS {
            cfg.keys.push(JwtKeySlot {
                kid: format!("k{i}"),
                material: JwtKeyMaterial::Hmac(JwtSecret { key: vec![0x33; 32] }),
                active: false,
                expires_at: None,
            });
        }
        assert!(cfg.validate_slots().is_err());
    }

    #[test]
    fn sign_always_uses_active_slot() {
        // Issue a token, then inspect its header — kid must equal
        // the active slot's kid, not the previous slot's.
        let cfg = multi_slot_config([0x11; 32], [0x22; 32]);
        let token = issue_token(&cfg, "agent-1", None, "proxy").expect("issue");
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["kid"], "active");
    }

    #[test]
    fn rotation_previous_slot_token_still_verifies() {
        // Simulate a graceful rotation: a token was issued under
        // `previous` (when it was active), then operator rotated so
        // `active` slot took over. The previous-slot token must
        // STILL verify until its `expires_at` elapses.
        let mut cfg = multi_slot_config([0x11; 32], [0x22; 32]);
        // Issue under previous-active (swap roles temporarily).
        cfg.keys[0].active = false;
        cfg.keys[1].active = true;
        let token = issue_token(&cfg, "agent-1", None, "proxy").expect("issue under previous");
        // Now rotate back.
        cfg.keys[0].active = true;
        cfg.keys[1].active = false;
        assert!(
            verify_token(&cfg, &token).is_ok(),
            "rotated-out slot must continue to verify pre-rotation tokens"
        );
    }

    #[test]
    fn expired_slot_excluded_from_verification() {
        let mut cfg = multi_slot_config([0x11; 32], [0x22; 32]);
        // Issue under previous slot.
        cfg.keys[0].active = false;
        cfg.keys[1].active = true;
        let token = issue_token(&cfg, "agent-1", None, "proxy").expect("issue");
        // Mark previous expired in the past, restore active.
        cfg.keys[0].active = true;
        cfg.keys[1].active = false;
        cfg.keys[1].expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        assert!(
            verify_token(&cfg, &token).is_err(),
            "token signed by an expired slot must be rejected"
        );
    }

    #[test]
    fn unknown_kid_rejected() {
        let cfg = multi_slot_config([0x11; 32], [0x22; 32]);
        // Forge a token with an unknown kid (using attacker's own key).
        let attacker_signing = SigningKey::from_bytes(&[0x99; 32]);
        let attacker_verifying = attacker_signing.verifying_key();
        let attacker_cfg = JwtConfig {
            algorithm: JwtAlgorithm::Ed25519,
            keys: vec![JwtKeySlot {
                kid: "attacker-kid".to_string(),
                material: JwtKeyMaterial::Ed25519 {
                    signing: attacker_signing,
                    verifying: attacker_verifying,
                },
                active: true,
                expires_at: None,
            }],
            token_ttl_secs: 3600,
            strict: false,
            revocation_file: None,
        };
        let token = issue_token(&attacker_cfg, "evil", None, "proxy").expect("attacker issues");
        // Real verifier (cfg) does not have "attacker-kid" → rejection.
        let err = verify_token(&cfg, &token).expect_err("unknown kid must be rejected");
        assert!(err.to_string().contains("kid") || err.to_string().contains("verifying key"));
    }

    #[test]
    fn legacy_token_without_kid_falls_back_to_active_slot() {
        // A token whose header has no `kid` (legacy v1 issuance) must
        // verify against the slot with empty kid (default). This
        // preserves backward compat — operators rotating from
        // single-key configs to multi-key keep their old tokens working
        // as long as the original key is the active slot with kid="".
        let cfg = test_config(3600);
        let token = issue_token(&cfg, "agent-001", None, "proxy").expect("issue");
        assert!(verify_token(&cfg, &token).is_ok());
    }
}
