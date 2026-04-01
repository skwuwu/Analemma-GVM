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
    /// Agent ID for ABAC evaluation. Defaults to "dry-run".
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

    // Build GVM headers for ABAC evaluation (if operation is meaningful)
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

    // Reconstruct per-layer decisions for decision path visualization
    // (read locks are cheap — already released by classify())
    let policy_decision_str = if gvm_headers.is_some() {
        let gvm_h = gvm_headers.as_ref().unwrap();
        let op = crate::types::OperationMetadata {
            operation: gvm_h.operation.clone(),
            resource: gvm_h.resource.clone().unwrap_or_default(),
            subject: crate::types::SubjectDescriptor {
                agent_id: gvm_h.agent_id.clone(),
                tenant_id: None,
                session_id: "dry-run".to_string(),
            },
            context: crate::types::OperationContext { attributes: Default::default() },
            payload: crate::types::PayloadDescriptor::default(),
        };
        state.policy.read().ok()
            .map(|p| format!("{:?}", p.evaluate(&op).0))
            .unwrap_or_else(|| "error".to_string())
    } else {
        "N/A (no operation)".to_string()
    };
    let srr_decision_str = state.srr.read().ok()
        .map(|s| format!("{:?}", s.check(&body.method, &body.target_host, &body.target_path, None).decision))
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
        crate::types::EnforcementDecision::Deny { reason } => (
            "Deny".to_string(),
            Some(format!("Blocked: {}", reason)),
        ),
        _ => (format!("{:?}", decision), None),
    };

    // Decision path: shows how max_strict() combined the per-layer decisions.
    let decision_path = format!(
        "Policy({}) + SRR({}) → Final({})",
        policy_decision_str, srr_decision_str, decision_str
    );

    let mut resp = serde_json::json!({
        "decision": decision_str,
        "decision_source": format!("{:?}", source),
        "decision_path": decision_path,
        "policy_decision": policy_decision_str,
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
/// Atomically reloads all governance components: SRR rules, ABAC policies,
/// and operation registry. If any component fails to parse, ALL existing
/// configurations are preserved (atomic: all-or-nothing).
pub async fn reload_srr(State(state): State<AppState>) -> Response<Body> {
    use crate::policy::PolicyEngine;
    use crate::registry::OperationRegistry;
    use crate::srr::NetworkSRR;
    use std::path::Path;

    // Phase 1: Parse all configs BEFORE acquiring any locks.
    // If any parse fails, we abort without touching state.
    let new_srr = match NetworkSRR::load(Path::new(&state.srr_config_path)) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "SRR reload parse failed — all configs preserved");
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({
                    "reloaded": false,
                    "error": format!("SRR parse failed: {}. All configs preserved.", e),
                }),
            );
        }
    };

    let new_policy = match PolicyEngine::load(Path::new(&state.policy_dir)) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "Policy reload parse failed — all configs preserved");
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({
                    "reloaded": false,
                    "error": format!("Policy parse failed: {}. All configs preserved.", e),
                }),
            );
        }
    };

    let new_registry = match OperationRegistry::load(Path::new(&state.registry_path)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Registry reload parse failed — all configs preserved");
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({
                    "reloaded": false,
                    "error": format!("Registry parse failed: {}. All configs preserved.", e),
                }),
            );
        }
    };

    // Phase 2: All parsed successfully. Acquire write locks and swap atomically.
    let srr_count = new_srr.rule_count();

    let lock_err = |name: &str| {
        tracing::error!("{name} write lock poisoned during reload");
        json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({"error": format!("{name} lock poisoned")}),
        )
    };

    let mut srr_guard = match state.srr.write() {
        Ok(g) => g,
        Err(_) => return lock_err("SRR"),
    };
    let mut policy_guard = match state.policy.write() {
        Ok(g) => g,
        Err(_) => return lock_err("Policy"),
    };
    let mut registry_guard = match state.registry.write() {
        Ok(g) => g,
        Err(_) => return lock_err("Registry"),
    };

    *srr_guard = new_srr;
    *policy_guard = new_policy;
    *registry_guard = new_registry;

    drop(srr_guard);
    drop(policy_guard);
    drop(registry_guard);

    tracing::info!(srr_rules = srr_count, "Governance hot-reloaded (SRR + ABAC + Registry)");
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "reloaded": true,
            "srr_rules": srr_count,
            "components": ["srr", "policy", "registry"],
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

    let (status, wal_status) = if wal_failures > 5 {
        ("degraded", "primary_failed")
    } else {
        ("healthy", "ok")
    };

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": status,
            "version": "0.1.0",
            "wal": wal_status,
            "wal_failures": wal_failures,
            "emergency_writes": emergency_writes,
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
            tracing::info!(event_id = %event_id, decision = %decision_str, "IC-3: Approval decision delivered");

            // Deliver decision via oneshot channel. If receiver was dropped
            // (proxy handler timed out), the send will fail — that's OK.
            let _ = pending.sender.send(approved);

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
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "version": "0.1.0",
            "components": {
                "srr": "loaded",
                "policy_engine": "loaded",
                "registry": "loaded",
                "vault": "active",
                "ledger": "active",
            },
            "registry": {
                "core_operations": state.registry.read().map(|r| r.core_count()).unwrap_or(0),
                "custom_operations": state.registry.read().map(|r| r.custom_count()).unwrap_or(0),
            },
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
