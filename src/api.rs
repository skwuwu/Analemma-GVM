use crate::auth;
use crate::merkle;
use crate::proxy::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ─── Checkpoint Merkle Tree Registry ───

/// Per-agent checkpoint state: ordered leaf hashes and current Merkle root.
///
/// Uses the same Merkle tree implementation as the WAL audit ledger (`merkle.rs`).
/// Each checkpoint's content hash is a leaf. All leaves form a Merkle tree
/// whose root changes on every new checkpoint. On restore, verification
/// uses O(log N) Merkle proof — same as WAL event verification.
///
/// ```text
/// Checkpoint 0 hash ─┐
///                     ├─ H(0,1) ─┐
/// Checkpoint 1 hash ─┘           │
///                                ├─ merkle_root
/// Checkpoint 2 hash ─┐           │
///                     ├─ H(2,3) ─┘
/// Checkpoint 3 hash ─┘
/// ```
#[derive(Clone, Debug)]
struct AgentCheckpointTree {
    /// Ordered leaf hashes (index = step number).
    leaves: Vec<String>,
    /// Current Merkle root over all leaves.
    merkle_root: String,
}

/// Registration result returned to the checkpoint_write handler.
#[derive(Clone, Debug)]
pub struct CheckpointRegistration {
    /// SHA-256 of the plaintext state.
    pub content_hash: String,
    /// Current Merkle root after including this checkpoint.
    pub merkle_root: String,
}

/// Verification result returned to the checkpoint_read handler.
#[derive(Clone, Debug)]
pub struct CheckpointVerification {
    /// Whether the content hash matches the stored leaf.
    pub content_verified: bool,
    /// Whether the Merkle proof verifies against the root.
    pub proof_verified: bool,
    /// Current Merkle root.
    pub merkle_root: Option<String>,
}

/// Per-agent checkpoint Merkle tree for integrity verification.
///
/// On write: computes plaintext content hash, appends as leaf, recomputes Merkle root.
/// On read: recomputes content hash, generates Merkle proof, verifies against root.
/// Reuses `merkle::compute_merkle_root()`, `merkle::generate_merkle_proof()`,
/// and `merkle::verify_merkle_proof()` — same primitives as WAL batch verification.
///
/// Bounded: max 10,000 agents and 10,000 steps per agent to prevent OOM.
#[derive(Clone, Default)]
pub struct CheckpointRegistry {
    /// agent_id → AgentCheckpointTree
    trees: Arc<RwLock<HashMap<String, AgentCheckpointTree>>>,
}

/// Maximum number of distinct agents tracked in checkpoint registry.
const MAX_CHECKPOINT_AGENTS: usize = 10_000;
/// Maximum number of checkpoint steps per agent.
const MAX_CHECKPOINT_STEPS: usize = 10_000;

impl CheckpointRegistry {
    pub fn new() -> Self {
        Self {
            trees: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a checkpoint's plaintext hash as a new leaf in the agent's Merkle tree.
    /// Returns the content hash and updated Merkle root, or an error if bounds are exceeded.
    pub async fn register(
        &self,
        agent_id: &str,
        step: u64,
        plaintext: &[u8],
    ) -> anyhow::Result<CheckpointRegistration> {
        // Validate step bound before any allocation
        if step as usize >= MAX_CHECKPOINT_STEPS {
            anyhow::bail!(
                "checkpoint step {} exceeds maximum ({})",
                step,
                MAX_CHECKPOINT_STEPS
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let content_hash = hex::encode(hasher.finalize());

        let mut trees = self.trees.write().await;

        // Validate agent count bound before inserting new agent
        if !trees.contains_key(agent_id) && trees.len() >= MAX_CHECKPOINT_AGENTS {
            anyhow::bail!("checkpoint agent limit reached ({})", MAX_CHECKPOINT_AGENTS);
        }

        let tree = trees
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentCheckpointTree {
                leaves: Vec::new(),
                merkle_root: String::new(),
            });

        let step_idx = step as usize;

        // Enforce sequential writes: step must be either the next index or an existing overwrite.
        // Non-sequential gaps are rejected to prevent Merkle root instability where
        // gap-filled placeholder hashes would be silently overwritten by later writes,
        // breaking any external system that verified the intermediate root.
        if step_idx > tree.leaves.len() {
            anyhow::bail!(
                "checkpoint step {} is non-sequential (current len {}): steps must be written in order",
                step, tree.leaves.len()
            );
        }

        if step_idx == tree.leaves.len() {
            // Append new leaf
            tree.leaves.push(content_hash.clone());
        } else {
            // Overwrite existing leaf (re-checkpoint at same step)
            tree.leaves[step_idx] = content_hash.clone();
        }

        // Recompute Merkle root over all leaves
        tree.merkle_root = merkle::compute_merkle_root(&tree.leaves)?;

        tracing::debug!(
            agent = agent_id,
            step = step,
            content_hash = %content_hash,
            merkle_root = %tree.merkle_root,
            total_leaves = tree.leaves.len(),
            "Checkpoint leaf registered in Merkle tree"
        );

        Ok(CheckpointRegistration {
            content_hash,
            merkle_root: tree.merkle_root.clone(),
        })
    }

    /// Verify a decrypted checkpoint against the Merkle tree.
    /// Recomputes the content hash, generates a Merkle proof for the leaf,
    /// and verifies it against the stored root.
    pub async fn verify(
        &self,
        agent_id: &str,
        step: u64,
        decrypted: &[u8],
    ) -> CheckpointVerification {
        let mut hasher = Sha256::new();
        hasher.update(decrypted);
        let computed_hash = hex::encode(hasher.finalize());

        let trees = self.trees.read().await;
        let tree = match trees.get(agent_id) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    agent = agent_id,
                    step = step,
                    "No checkpoint tree found for agent — cannot verify"
                );
                return CheckpointVerification {
                    content_verified: false,
                    proof_verified: false,
                    merkle_root: None,
                };
            }
        };

        let idx = step as usize;
        if idx >= tree.leaves.len() {
            tracing::warn!(
                agent = agent_id,
                step = step,
                total_leaves = tree.leaves.len(),
                "Checkpoint step exceeds tree size — cannot verify"
            );
            return CheckpointVerification {
                content_verified: false,
                proof_verified: false,
                merkle_root: Some(tree.merkle_root.clone()),
            };
        }

        // 1. Content hash verification: does decrypted data match the stored leaf?
        let content_verified = computed_hash == tree.leaves[idx];

        // 2. Merkle proof verification: O(log N) proof against the root
        let proof = match merkle::generate_merkle_proof(&tree.leaves, idx) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(agent = agent_id, step = step, error = %e, "Failed to generate merkle proof");
                return CheckpointVerification {
                    content_verified,
                    proof_verified: false,
                    merkle_root: Some(tree.merkle_root.clone()),
                };
            }
        };
        let proof_verified = merkle::verify_merkle_proof(&computed_hash, &proof, &tree.merkle_root);

        if !content_verified || !proof_verified {
            tracing::warn!(
                agent = agent_id,
                step = step,
                content_ok = content_verified,
                proof_ok = proof_verified,
                computed = %computed_hash,
                stored = %tree.leaves[idx],
                "Checkpoint Merkle verification FAILED"
            );
        }

        CheckpointVerification {
            content_verified,
            proof_verified,
            merkle_root: Some(tree.merkle_root.clone()),
        }
    }
}

// ─── Vault Identity Resolution ───

/// Resolve the effective agent_id for vault operations.
///
/// When JWT is configured:
/// - If a valid Bearer token is present, use the JWT-verified agent_id (ignoring self-declared).
/// - If a Bearer token is present but invalid, reject with 401.
/// - If no Bearer token is present, fall back to the declared agent_id with a warning.
///
/// When JWT is not configured: use the declared agent_id as-is.
fn resolve_vault_agent_id(
    jwt_config: &Option<Arc<auth::JwtConfig>>,
    headers: &HeaderMap,
    declared_agent_id: &str,
) -> Result<String, Response<Body>> {
    #![allow(clippy::result_large_err)]
    if let Some(ref jwt) = jwt_config {
        match auth::extract_bearer_token(headers) {
            Some(token) => match auth::verify_token(jwt, token) {
                Ok(identity) => {
                    if identity.agent_id != declared_agent_id {
                        tracing::warn!(
                            declared = declared_agent_id,
                            verified = %identity.agent_id,
                            "Vault request: JWT agent_id differs from declared — using verified identity"
                        );
                    }
                    Ok(identity.agent_id)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Vault request: JWT verification failed");
                    Err(json_response(
                        StatusCode::UNAUTHORIZED,
                        &serde_json::json!({"error": "Invalid or expired authentication token"}),
                    ))
                }
            },
            None => {
                tracing::warn!(
                    agent = declared_agent_id,
                    "Vault request: No JWT token — using unverified agent_id"
                );
                Ok(declared_agent_id.to_string())
            }
        }
    } else {
        Ok(declared_agent_id.to_string())
    }
}

// ─── Vault REST API ───

#[derive(Deserialize)]
pub struct VaultWriteRequest {
    pub value: String,
    pub agent_id: String,
}

#[derive(Serialize)]
pub struct VaultReadResponse {
    pub key: String,
    pub value: Option<String>,
}

/// Validate that an identifier does not contain the namespace separator `:`,
/// preventing namespace traversal attacks (e.g., agent_id="admin:foo" + key="bar" → "admin:foo:bar").
#[allow(clippy::result_large_err)]
fn validate_vault_identifier(id: &str, field_name: &str) -> Result<(), Response<Body>> {
    if id.is_empty() {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": format!("{} must not be empty", field_name)}),
        ));
    }
    if id.len() > 128 {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": format!("{} exceeds maximum length (128)", field_name)}),
        ));
    }
    if id.contains(':') {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": format!("invalid {}: must not contain ':'", field_name)}),
        ));
    }
    Ok(())
}

/// PUT /gvm/vault/:key — Write encrypted value to vault
///
/// Security: keys are scoped by agent_id prefix to enforce namespace isolation.
/// Agent "agent-001" can only write to keys prefixed with "agent-001:".
/// When JWT is configured, the agent_id is cryptographically verified from the Bearer token.
pub async fn vault_write(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<VaultWriteRequest>,
) -> Response<Body> {
    // Validate identifiers to prevent namespace traversal via separator injection
    if let Err(resp) = validate_vault_identifier(&body.agent_id, "agent_id") {
        return resp;
    }
    if let Err(resp) = validate_vault_identifier(&key, "key") {
        return resp;
    }

    // Resolve effective agent_id: JWT-verified takes precedence over self-declared
    let agent_id = match resolve_vault_agent_id(&state.jwt_config, &headers, &body.agent_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Namespace isolation: scope key by agent_id to prevent cross-agent access
    let scoped_key = format!("{}:{}", agent_id, key);

    match state
        .vault
        .write(&scoped_key, body.value.as_bytes(), &agent_id)
        .await
    {
        Ok(()) => json_response(
            StatusCode::OK,
            &serde_json::json!({"status": "ok", "key": key}),
        ),
        Err(e) => {
            tracing::error!(key = %key, agent = %agent_id, error = %e, "Vault write failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Internal vault error"}),
            )
        }
    }
}

/// GET /gvm/vault/:key?agent_id=xxx — Read and decrypt value from vault
///
/// Security: reads are scoped by agent_id prefix (namespace isolation).
/// When JWT is configured, the agent_id is cryptographically verified from the Bearer token.
pub async fn vault_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let declared_agent_id = params
        .get("agent_id")
        .map(|s| s.as_str())
        .unwrap_or("unknown");
    if let Err(resp) = validate_vault_identifier(declared_agent_id, "agent_id") {
        return resp;
    }
    if let Err(resp) = validate_vault_identifier(&key, "key") {
        return resp;
    }

    // Resolve effective agent_id: JWT-verified takes precedence over query param
    let agent_id = match resolve_vault_agent_id(&state.jwt_config, &headers, declared_agent_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let scoped_key = format!("{}:{}", agent_id, key);

    match state.vault.read(&scoped_key, &agent_id).await {
        Ok(Some(bytes)) => {
            let value = String::from_utf8_lossy(&bytes).to_string();
            json_response(
                StatusCode::OK,
                &serde_json::json!(VaultReadResponse {
                    key,
                    value: Some(value),
                }),
            )
        }
        Ok(None) => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "Key not found", "key": key}),
        ),
        Err(e) => {
            tracing::error!(key = %key, agent = %agent_id, error = %e, "Vault read failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Internal vault error"}),
            )
        }
    }
}

/// DELETE /gvm/vault/:key?agent_id=xxx — Delete key from vault
///
/// Security: deletes are scoped by agent_id prefix (namespace isolation).
/// When JWT is configured, the agent_id is cryptographically verified from the Bearer token.
pub async fn vault_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let declared_agent_id = params
        .get("agent_id")
        .map(|s| s.as_str())
        .unwrap_or("unknown");
    if let Err(resp) = validate_vault_identifier(declared_agent_id, "agent_id") {
        return resp;
    }
    if let Err(resp) = validate_vault_identifier(&key, "key") {
        return resp;
    }

    // Resolve effective agent_id: JWT-verified takes precedence over query param
    let agent_id = match resolve_vault_agent_id(&state.jwt_config, &headers, declared_agent_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let scoped_key = format!("{}:{}", agent_id, key);

    match state.vault.delete(&scoped_key, &agent_id).await {
        Ok(()) => json_response(
            StatusCode::OK,
            &serde_json::json!({"status": "deleted", "key": key}),
        ),
        Err(e) => {
            tracing::error!(key = %key, agent = %agent_id, error = %e, "Vault delete failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Internal vault error"}),
            )
        }
    }
}

// ─── Checkpoint API ───

/// PUT /gvm/vault/checkpoint/:agent_id/:step — Save agent state checkpoint
///
/// Stores a serialized agent state snapshot keyed by agent_id + step number.
/// Computes plaintext content hash, adds it as a leaf in the agent's
/// Merkle tree, and recomputes the root for integrity verification on restore.
pub async fn checkpoint_write(
    State(state): State<AppState>,
    Path((agent_id, step)): Path<(String, u64)>,
    body: axum::body::Bytes,
) -> Response<Body> {
    // Register plaintext hash as Merkle leaf BEFORE encryption
    let reg = match state
        .checkpoint_registry
        .register(&agent_id, step, &body)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(agent = %agent_id, step = step, error = %e, "Checkpoint registration failed");
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({"error": "Checkpoint limit exceeded"}),
            );
        }
    };

    let key = format!("checkpoint:{}:{}", agent_id, step);
    match state.vault.write(&key, &body, &agent_id).await {
        Ok(()) => {
            tracing::debug!(
                agent = %agent_id, step = step,
                content_hash = %reg.content_hash,
                merkle_root = %reg.merkle_root,
                "Checkpoint saved as Merkle leaf"
            );
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "status": "ok",
                    "checkpoint_step": step,
                    "agent_id": agent_id,
                    "content_hash": reg.content_hash,
                    "merkle_root": reg.merkle_root,
                }),
            )
        }
        Err(e) => {
            tracing::error!(agent = %agent_id, step = step, error = %e, "Checkpoint write failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Checkpoint write failed"}),
            )
        }
    }
}

/// GET /gvm/vault/checkpoint/:agent_id/:step — Restore agent state checkpoint
///
/// Retrieves and decrypts a previously saved checkpoint, then verifies
/// the decrypted content via Merkle proof against the tree root.
/// Returns real `X-GVM-Merkle-Verified` status based on O(log N) proof verification.
pub async fn checkpoint_read(
    State(state): State<AppState>,
    Path((agent_id, step)): Path<(String, u64)>,
) -> Response<Body> {
    let key = format!("checkpoint:{}:{}", agent_id, step);
    match state.vault.read(&key, &agent_id).await {
        Ok(Some(data)) => {
            // Verify decrypted content via Merkle proof
            let v = state
                .checkpoint_registry
                .verify(&agent_id, step, &data)
                .await;

            let merkle_verified = v.content_verified && v.proof_verified;

            if !merkle_verified {
                tracing::warn!(
                    agent = %agent_id, step = step,
                    content_ok = v.content_verified,
                    proof_ok = v.proof_verified,
                    "Checkpoint Merkle verification FAILED — possible tampering"
                );
            } else {
                tracing::debug!(
                    agent = %agent_id, step = step,
                    "Checkpoint restored (Merkle verified)"
                );
            }

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("X-GVM-Checkpoint-Step", step.to_string())
                .header(
                    "X-GVM-Merkle-Verified",
                    if merkle_verified { "true" } else { "false" },
                );

            if let Some(ref root) = v.merkle_root {
                builder = builder.header("X-GVM-Merkle-Root", root.as_str());
            }

            builder.body(Body::from(data)).unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .expect("fallback 500 response with empty body cannot fail")
            })
        }
        Ok(None) => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "Checkpoint not found", "step": step}),
        ),
        Err(e) => {
            tracing::error!(agent = %agent_id, step = step, error = %e, "Checkpoint read failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Checkpoint retrieval failed"}),
            )
        }
    }
}

/// DELETE /gvm/vault/checkpoint/:agent_id/:step — Delete a checkpoint (TTL cleanup)
///
/// Used by SDK to delete old checkpoints and prevent Vault bloat.
pub async fn checkpoint_delete(
    State(state): State<AppState>,
    Path((agent_id, step)): Path<(String, u64)>,
) -> Response<Body> {
    let key = format!("checkpoint:{}:{}", agent_id, step);
    match state.vault.delete(&key, &agent_id).await {
        Ok(()) => {
            tracing::debug!(agent = %agent_id, step = step, "Checkpoint deleted");
            json_response(
                StatusCode::OK,
                &serde_json::json!({"status": "deleted", "checkpoint_step": step}),
            )
        }
        Err(e) => {
            tracing::error!(agent = %agent_id, step = step, error = %e, "Checkpoint delete failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Checkpoint delete failed"}),
            )
        }
    }
}

// ─── Dry-Run Policy Check ───

#[derive(Deserialize)]
pub struct CheckRequest {
    pub operation: String,
    #[serde(default = "default_service")]
    pub resource_service: Option<String>,
    #[serde(default)]
    pub resource: Option<serde_json::Value>,
    #[serde(default = "default_host")]
    pub target_host: String,
    #[serde(default = "default_path")]
    pub target_path: String,
    #[serde(default = "default_method")]
    pub method: String,
    /// Agent ID for governance evaluation. Defaults to "dry-run".
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
}
fn default_agent_id() -> String {
    "dry-run".to_string()
}

fn default_service() -> Option<String> {
    Some("unknown".to_string())
}
fn default_host() -> String {
    "example.com".to_string()
}
fn default_path() -> String {
    "/".to_string()
}
fn default_method() -> String {
    "POST".to_string()
}

/// POST /gvm/check — Dry-run policy evaluation. No forwarding, no WAL write, no API keys.
///
/// Uses the same `enforcement::classify()` function as proxy_handler and MITM,
/// ensuring the check endpoint and real enforcement always produce identical decisions.
pub async fn check(
    State(state): State<AppState>,
    Json(body): Json<CheckRequest>,
) -> Response<Body> {
    let t0 = std::time::Instant::now();

    // Build GVM headers for governance evaluation (if operation is meaningful)
    let gvm_headers = if body.operation != "unknown" && body.operation != "test" {
        Some(crate::types::GVMHeaders {
            agent_id: body.agent_id.clone(),
            trace_id: "dry-run".to_string(),
            parent_event_id: None,
            event_id: "dry-run".to_string(),
            operation: body.operation.clone(),
            resource: body
                .resource
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            context: Default::default(),
            session_id: Some("dry-run".to_string()),
            tenant_id: None,
            rate_limit: None,
        })
    } else {
        None
    };

    // Unified classification via enforcement::classify() — same code path as
    // proxy_handler and handle_mitm_stream. Guarantees check results match
    // real enforcement decisions.
    let input = crate::enforcement::ClassifyInput {
        method: &body.method,
        host: &body.target_host,
        path: &body.target_path,
        body: None, // dry-run has no body
        gvm_headers: gvm_headers.as_ref(),
    };

    let output = match crate::enforcement::classify(&state, &input) {
        Ok(o) => o,
        Err(err) => {
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": err}),
            );
        }
    };

    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
    let decision = &output.classification.decision;
    let source = &output.classification.source;

    let srr_decision_str = state
        .srr
        .read()
        .ok()
        .map(|s| {
            format!(
                "{:?}",
                s.check(&body.method, &body.target_host, &body.target_path, None)
                    .decision
            )
        })
        .unwrap_or_else(|| "error".to_string());

    let (decision_str, next_action) = match decision {
        crate::types::EnforcementDecision::Allow => ("Allow".to_string(), None),
        crate::types::EnforcementDecision::Delay { milliseconds } => (
            format!("Delay {}ms", milliseconds),
            Some(format!(
                "Request will be delayed {}ms before forwarding",
                milliseconds
            )),
        ),
        crate::types::EnforcementDecision::RequireApproval { .. } => (
            "RequireApproval".to_string(),
            Some("Administrator approval required before execution".to_string()),
        ),
        crate::types::EnforcementDecision::Deny { reason } => {
            ("Deny".to_string(), Some(format!("Blocked: {}", reason)))
        }
        _ => (format!("{:?}", decision), None),
    };

    let decision_path = format!("SRR({}) → Final({})", srr_decision_str, decision_str);

    let mut resp = serde_json::json!({
        "decision": decision_str,
        "decision_source": format!("{:?}", source),
        "decision_path": decision_path,
        "srr_decision": srr_decision_str,
        "engine_us": (elapsed * 1000.0).round(), // microseconds for precision
        "engine_ms": (elapsed * 10.0).round() / 10.0,
        "operation": body.operation,
        "agent_id": body.agent_id,
        "method": body.method,
        "target_host": body.target_host,
        "target_path": body.target_path,
        "matched_rule": output.classification.matched_rule_id,
        "default_caution": output.is_default_caution,
        "dry_run": true,
    });

    if let Some(action) = &next_action {
        resp["next_action"] = serde_json::Value::String(action.clone());
    }

    json_response(StatusCode::OK, &resp)
}

// ─── JWT Token Issuance ───

#[derive(Deserialize)]
pub struct TokenRequest {
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "proxy".to_string()
}

/// POST /gvm/auth/token — Issue a JWT for agent authentication.
///
/// Returns a signed Bearer token that the proxy verifies on subsequent requests.
/// When JWT is not configured (no GVM_JWT_SECRET), returns 503.
pub async fn auth_token(
    State(state): State<AppState>,
    Json(body): Json<TokenRequest>,
) -> Response<Body> {
    let jwt_config = match &state.jwt_config {
        Some(c) => c,
        None => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &serde_json::json!({
                    "error": "JWT authentication not configured",
                    "hint": "Set GVM_JWT_SECRET environment variable (hex-encoded, min 32 bytes)"
                }),
            );
        }
    };

    // Validate agent_id
    if let Err(resp) = validate_vault_identifier(&body.agent_id, "agent_id") {
        return resp;
    }
    if body.agent_id.len() > 128 {
        return json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": "agent_id exceeds maximum length (128)"}),
        );
    }

    // Validate scope
    if body.scope != "proxy" {
        return json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": "Invalid scope. Supported: proxy"}),
        );
    }

    match crate::auth::issue_token_response(
        jwt_config,
        &body.agent_id,
        body.tenant_id.as_deref(),
        &body.scope,
    ) {
        Ok(resp) => json_response(StatusCode::OK, &serde_json::json!(resp)),
        Err(e) => {
            tracing::error!(error = %e, "Token issuance failed");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "Token issuance failed"}),
            )
        }
    }
}

// ─── Shadow Mode: Intent Registration ───

/// POST /gvm/intent — Register an intent for shadow verification.
///
/// MCP tools call this before the agent makes an outbound HTTP request.
/// The proxy checks the intent store during request processing.
pub async fn register_intent(
    State(state): State<AppState>,
    Json(body): Json<crate::intent_store::IntentRequest>,
) -> Response<Body> {
    match state.intent_store.register(&body) {
        Ok(id) => json_response(
            StatusCode::CREATED,
            &serde_json::json!({
                "registered": true,
                "intent_id": id,
                "method": body.method,
                "host": body.host,
                "path": body.path,
                "operation": body.operation,
                "ttl_secs": body.ttl_secs.unwrap_or(
                    state.shadow_config.intent_ttl_secs
                ),
                "shadow_mode": format!("{:?}", state.shadow_config.mode),
            }),
        ),
        Err(e) => json_response(
            StatusCode::TOO_MANY_REQUESTS,
            &serde_json::json!({
                "error": e,
            }),
        ),
    }
}

// ─── SRR Hot-Reload ───

/// POST /gvm/reload — Reload SRR rules from config file without restarting.
///
/// Atomically reloads all governance components: SRR rules and operation registry.
/// If any component fails to parse, ALL existing configurations are preserved
/// (atomic: all-or-nothing).
pub async fn reload_srr(State(state): State<AppState>) -> Response<Body> {
    use crate::srr::NetworkSRR;
    use std::path::Path;

    // Phase 1: Parse all configs BEFORE acquiring any locks.
    // If gvm.toml exists, reload from it. Otherwise fallback to separate files.
    let new_srr = if let Some(ref gvm_path) = state.gvm_toml_path {
        // Reload from gvm.toml
        match crate::config::load_gvm_toml() {
            Some(gvm) if !gvm.rules.is_empty() => {
                match NetworkSRR::from_rule_configs(gvm.rules) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "SRR reload from gvm.toml failed — config preserved");
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({
                                "reloaded": false,
                                "error": format!("gvm.toml SRR parse failed: {}. Config preserved.", e),
                            }),
                        );
                    }
                }
            }
            Some(_) => {
                // gvm.toml exists but no rules — try legacy file
                match NetworkSRR::load(Path::new(&state.srr_config_path)) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "SRR reload fallback failed — config preserved");
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({
                                "reloaded": false,
                                "error": format!("SRR parse failed: {}. Config preserved.", e),
                            }),
                        );
                    }
                }
            }
            None => {
                tracing::warn!(path = %gvm_path, "gvm.toml disappeared during reload — trying legacy file");
                match NetworkSRR::load(Path::new(&state.srr_config_path)) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(error = %e, "SRR reload failed — config preserved");
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({
                                "reloaded": false,
                                "error": format!("SRR parse failed: {}. Config preserved.", e),
                            }),
                        );
                    }
                }
            }
        }
    } else {
        match NetworkSRR::load(Path::new(&state.srr_config_path)) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "SRR reload parse failed — config preserved");
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({
                        "reloaded": false,
                        "error": format!("SRR parse failed: {}. Config preserved.", e),
                    }),
                );
            }
        }
    };

    // Phase 2: Acquire write lock and swap atomically.
    let srr_count = new_srr.rule_count();

    let mut srr_guard = match state.srr.write() {
        Ok(g) => g,
        Err(_) => {
            tracing::error!("SRR write lock poisoned during reload");
            return json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "SRR lock poisoned"}),
            );
        }
    };

    *srr_guard = new_srr;
    drop(srr_guard);

    tracing::info!(
        srr_rules = srr_count,
        "Governance hot-reloaded (SRR)"
    );
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "reloaded": true,
            "srr_rules": srr_count,
            "components": ["srr"],
        }),
    )
}

// ─── Health / Admin Endpoints ───

/// GET /gvm/health — Liveness + readiness check
///
/// Returns 200 for both healthy and degraded states (watchdog should NOT
/// restart on degraded — WAL primary failure during restart could worsen state).
/// Watchdog triggers restart only on unreachable (ECONNREFUSED/timeout).
///
/// Degraded threshold: >5 consecutive primary WAL failures (matches circuit
/// breaker in proxy.rs — 5 consecutive failures indicates persistent disk issue,
/// not a transient hiccup).
pub async fn health(State(state): State<AppState>) -> Response<Body> {
    let wal_failures = state.ledger.primary_failure_count();
    let emergency_writes = state.ledger.emergency_write_count();
    let srr_rules = state.srr.read().map(|s| s.rule_count()).unwrap_or(0);
    let pending = state.pending_approvals.len();
    let tls_ready = state.tls_ready.load(std::sync::atomic::Ordering::Relaxed);
    let uptime_secs = state.start_time.elapsed().as_secs();
    let total_requests = state
        .request_counter
        .load(std::sync::atomic::Ordering::Relaxed);

    let (status, wal_status) = if wal_failures > 5 {
        ("degraded", "primary_failed")
    } else {
        ("healthy", "ok")
    };

    let dns_governance = state.dns_governance.is_some();

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": status,
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "srr_rules": srr_rules,
            "tls_ready": tls_ready,
            "wal": wal_status,
            "wal_failures": wal_failures,
            "emergency_writes": emergency_writes,
            "pending_approvals": pending,
            "uptime_secs": uptime_secs,
            "total_requests": total_requests,
            "ca_expires_days": state.ca_expires_days,
            "dns_governance": dns_governance,
        }),
    )
}

// ─── IC-3 Approval Endpoints ───

/// GET /gvm/pending — List pending IC-3 approval requests.
///
/// Returns all requests currently waiting for human approval. Each entry
/// includes event_id, operation, host, path, method, agent_id, and timestamp.
/// Used by `gvm run` CLI (auto-polling) and `gvm approve` (standalone).
pub async fn pending_approvals(State(state): State<AppState>) -> Response<Body> {
    let pending: Vec<serde_json::Value> = state
        .pending_approvals
        .iter()
        .map(|entry| {
            let pa = entry.value();
            serde_json::json!({
                "event_id": pa.event_id,
                "operation": pa.operation,
                "host": pa.host,
                "path": pa.path,
                "method": pa.method,
                "agent_id": pa.agent_id,
                "timestamp": pa.timestamp.to_rfc3339(),
            })
        })
        .collect();

    json_response(StatusCode::OK, &serde_json::json!({ "pending": pending }))
}

/// POST /gvm/approve — Approve or deny a pending IC-3 request.
///
/// Request body: `{ "event_id": "...", "approved": true/false }`
///
/// If the event_id is found in pending_approvals, delivers the decision via the
/// oneshot channel. The proxy handler unblocks and either forwards (approved) or
/// returns 403 (denied). If the event_id is not found (already expired/decided),
/// returns 404.
pub async fn approve_request(
    State(state): State<AppState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response<Body> {
    let event_id = match body.get("event_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": "Missing 'event_id' field" }),
            );
        }
    };

    let approved = body
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Remove from pending map and deliver decision
    match state.pending_approvals.remove(&event_id) {
        Some((_, pending)) => {
            let decision_str = if approved { "approved" } else { "denied" };

            // Deliver decision via oneshot channel. If `send` returns an
            // error, the receiver has been dropped — almost always
            // because the agent disconnected (HTTP client timed out,
            // TCP closed) and hyper cancelled the proxy handler future
            // before the operator clicked approve. The proxy's
            // `ApprovalGuard` should have caught this, but the entry
            // can still be present briefly in a race window between
            // hyper drop and the guard running. Either way, the
            // operator's decision can no longer be honored — surface a
            // distinct 410 Gone with a clear reason instead of OK so
            // `gvm approve` can tell the operator the truth.
            if pending.sender.send(approved).is_err() {
                tracing::warn!(
                    event_id = %event_id,
                    "IC-3: approval arrived after agent disconnected — \
                     decision not deliverable"
                );
                return json_response(
                    StatusCode::GONE,
                    &serde_json::json!({
                        "error": "agent_disconnected",
                        "event_id": event_id,
                        "reason": "Agent's HTTP client closed the connection \
                                   before the approval was delivered. The \
                                   request is gone; no upstream call was made.",
                    }),
                );
            }

            tracing::info!(event_id = %event_id, decision = %decision_str, "IC-3: Approval decision delivered");
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "event_id": event_id,
                    "decision": decision_str,
                }),
            )
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            &serde_json::json!({
                "error": "No pending approval for this event_id",
                "event_id": event_id,
            }),
        ),
    }
}

/// GET /gvm/info — Proxy info and loaded configuration summary.
///
/// Security: returns summary counts only, not internal rule details.
pub async fn info(State(state): State<AppState>) -> Response<Body> {
    let srr_rules = state.srr.read().map(|s| s.rule_count()).unwrap_or(0);

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "components": {
                "srr": "loaded",
                "srr_engine": "loaded",
                "vault": "active",
                "ledger": "active",
            },
            "config_source": if state.gvm_toml_path.is_some() { "gvm.toml" } else { "legacy" },
            "srr_rules": srr_rules,
            "shadow": {
                "mode": format!("{:?}", state.shadow_config.mode),
                "active_intents": state.intent_store.stats().1,
            },
        }),
    )
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .expect("fallback 500 response with empty body cannot fail")
        })
}

// ─── Dashboard ───

/// True if the event is a proxy-internal system record (e.g., startup
/// config_load) rather than an agent governance decision. These events
/// live in the WAL for Merkle audit integrity but do not belong on the
/// user-facing dashboard timeline or in the "Allowed" metric.
fn is_internal_system_event(event: &serde_json::Value) -> bool {
    let enforcement_point = event
        .get("enforcement_point")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if enforcement_point == "startup" {
        return true;
    }
    let operation = event.get("operation").and_then(|v| v.as_str()).unwrap_or("");
    if operation.starts_with("gvm.system.") || operation.starts_with("gvm.vault.") {
        return true;
    }
    false
}

/// Serve the dashboard HTML page.
pub async fn dashboard() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(include_str!("dashboard.html")))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("dashboard unavailable"))
                .expect("fallback response")
        })
}

#[derive(Deserialize)]
pub struct DashboardEventsQuery {
    since_offset: Option<u64>,
    limit: Option<usize>,
}

/// Return WAL events as JSON, incrementally from a byte offset.
pub async fn dashboard_events(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<DashboardEventsQuery>,
) -> Json<serde_json::Value> {
    let offset = query.since_offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(500);

    let wal_path = &state.wal_path;
    let file = match std::fs::File::open(wal_path) {
        Ok(f) => f,
        Err(_) => {
            return Json(serde_json::json!({
                "events": [],
                "next_offset": 0,
                "total_in_wal": 0
            }));
        }
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len <= offset {
        return Json(serde_json::json!({
            "events": [],
            "next_offset": offset,
            "total_in_wal": file_len
        }));
    }

    use std::io::{BufRead, Seek, SeekFrom};
    let mut reader = std::io::BufReader::new(file);
    if offset > 0 {
        let _ = reader.seek(SeekFrom::Start(offset));
    }

    let mut events = Vec::new();
    let mut current_offset = offset;
    let mut current_batch_id: Option<u64> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        current_offset += line.len() as u64 + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            // Track batch IDs from MerkleBatchRecord lines
            if parsed.get("batch_id").is_some() && parsed.get("merkle_root").is_some() {
                current_batch_id = parsed.get("batch_id").and_then(|v| v.as_u64());
                continue;
            }

            // Skip non-event lines
            if parsed.get("event_id").is_none() {
                continue;
            }

            // Skip proxy-internal system events. They belong in the WAL
            // (config_load hashes are part of the Merkle audit chain) but
            // aren't agent governance decisions — showing them in the
            // dashboard timeline confuses the "Allowed" metric (a bootstrap
            // record is not an Allow on a request).
            if is_internal_system_event(&parsed) {
                continue;
            }

            // Attach batch_id from the preceding batch record
            let mut event = parsed;
            if let Some(bid) = current_batch_id {
                event
                    .as_object_mut()
                    .map(|o| o.insert("batch_id".to_string(), serde_json::json!(bid)));
            }

            events.push(event);
            if events.len() >= limit {
                break;
            }
        }
    }

    Json(serde_json::json!({
        "events": events,
        "next_offset": current_offset,
        "total_in_wal": file_len
    }))
}

/// Return aggregated WAL statistics as JSON.
pub async fn dashboard_stats(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let wal_path = &state.wal_path;
    let file = match std::fs::File::open(wal_path) {
        Ok(f) => f,
        Err(_) => {
            return Json(serde_json::json!({
                "total_requests": 0,
                "hosts": {},
                "decisions": {},
                "status_codes": {},
                "llm": { "total_tokens": 0, "estimated_cost_usd": 0.0, "models": [], "calls": 0 },
                "denied_rules": {},
                "uptime_secs": state.start_time.elapsed().as_secs_f64(),
                "wal_offset": 0
            }));
        }
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    use std::io::BufRead;
    let reader = std::io::BufReader::new(file);

    // Two-phase: collect latest state per event_id (upsert), then aggregate.
    // WAL may contain multiple entries per event_id (Pending → Confirmed + llm_trace).
    // We want the latest (most complete) version of each event.
    let mut latest: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if parsed.get("batch_id").is_some() && parsed.get("merkle_root").is_some() {
            continue;
        }
        let event_id = parsed
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if event_id.is_empty() {
            continue;
        }
        // Upsert: later WAL entries for same event_id overwrite earlier ones
        latest.insert(event_id.to_string(), parsed);
    }

    // Phase 2: aggregate from deduplicated events
    let mut total: u64 = 0;
    let mut hosts: HashMap<String, u64> = HashMap::new();
    let mut decisions: HashMap<String, u64> = HashMap::new();
    let mut status_codes: HashMap<String, u64> = HashMap::new();
    let mut denied_rules: HashMap<String, u64> = HashMap::new();
    let mut llm_tokens: u64 = 0;
    let mut llm_calls: u64 = 0;
    let mut llm_cost: f64 = 0.0;
    let mut models: std::collections::HashSet<String> = std::collections::HashSet::new();

    for parsed in latest.values() {
        // Exclude proxy-internal system events (config_load etc.) from
        // dashboard metrics — they are in the WAL for audit integrity
        // but do not represent agent traffic and would inflate the
        // "Allowed" counter.
        if is_internal_system_event(parsed) {
            continue;
        }

        total += 1;

        if let Some(host) = parsed.pointer("/transport/host").and_then(|v| v.as_str()) {
            *hosts.entry(host.to_string()).or_default() += 1;
        }

        if let Some(decision) = parsed.get("decision").and_then(|v| v.as_str()) {
            let bucket = if decision.contains("Allow") {
                "Allow"
            } else if decision.contains("Delay") {
                "Delay"
            } else if decision.contains("Deny") {
                "Deny"
            } else {
                "Other"
            };
            *decisions.entry(bucket.to_string()).or_default() += 1;

            if decision.contains("Deny") {
                let rule = parsed
                    .get("matched_rule_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unknown)");
                *denied_rules.entry(rule.to_string()).or_default() += 1;
            }
        }

        if let Some(code) = parsed.pointer("/transport/status_code").and_then(|v| v.as_u64()) {
            *status_codes.entry(code.to_string()).or_default() += 1;
        }

        if let Some(trace) = parsed.get("llm_trace") {
            if !trace.is_null() {
                llm_calls += 1;
                if let Some(model) = trace.get("model").and_then(|v| v.as_str()) {
                    models.insert(model.to_string());
                }
                if let Some(usage) = trace.get("usage") {
                    let prompt = usage
                        .get("prompt_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let completion = usage
                        .get("completion_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    llm_tokens += prompt + completion;

                    let provider =
                        trace.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let model_name = trace.get("model").and_then(|v| v.as_str());
                    llm_cost += estimate_llm_cost(provider, model_name, prompt, completion);
                }
            }
        }
    }

    let budget_json = budget_status_json(&state);

    Json(serde_json::json!({
        "total_requests": total,
        "hosts": hosts,
        "decisions": decisions,
        "status_codes": status_codes,
        "llm": {
            "total_tokens": llm_tokens,
            "estimated_cost_usd": llm_cost,
            "models": models.into_iter().collect::<Vec<_>>(),
            "calls": llm_calls
        },
        "denied_rules": denied_rules,
        "uptime_secs": state.start_time.elapsed().as_secs_f64(),
        "wal_offset": file_len,
        "proxy_total": state.request_counter.load(std::sync::atomic::Ordering::Relaxed),
        "budget": budget_json
    }))
}

fn budget_status_json(state: &crate::proxy::AppState) -> serde_json::Value {
    let bs = state.token_budget.status();
    serde_json::json!({
        "enabled": state.token_budget.is_enabled(),
        "tokens_used": bs.tokens_used,
        "tokens_limit": bs.tokens_limit,
        "cost_used_usd": bs.cost_used_usd(),
        "cost_limit_usd": bs.cost_limit_usd(),
        "pending_reservations": bs.pending_reservations,
        "tokens_pct": bs.tokens_pct(),
        "cost_pct": bs.cost_pct()
    })
}

/// Approximate LLM cost estimation (same logic as gvm-cli watch).
fn estimate_llm_cost(provider: &str, model: Option<&str>, prompt: u64, completion: u64) -> f64 {
    let (input_rate, output_rate) = match provider {
        "openai" => match model {
            Some(m) if m.contains("gpt-4o") && !m.contains("mini") => (2.50, 10.00),
            Some(m) if m.contains("gpt-4o-mini") => (0.15, 0.60),
            Some(m) if m.contains("o1") => (15.00, 60.00),
            Some(m) if m.contains("o3") => (10.00, 40.00),
            _ => (0.50, 1.50),
        },
        "anthropic" => match model {
            Some(m) if m.contains("opus") => (15.00, 75.00),
            Some(m) if m.contains("sonnet") => (3.00, 15.00),
            Some(m) if m.contains("haiku") => (0.25, 1.25),
            _ => (3.00, 15.00),
        },
        "gemini" => match model {
            Some(m) if m.contains("pro") => (1.25, 5.00),
            Some(m) if m.contains("flash") => (0.075, 0.30),
            _ => (1.25, 5.00),
        },
        _ => (1.00, 3.00),
    };
    (prompt as f64 * input_rate + completion as f64 * output_rate) / 1_000_000.0
}
