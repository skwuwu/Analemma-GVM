use crate::merkle;
use crate::proxy::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Response, StatusCode};
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
                step, MAX_CHECKPOINT_STEPS
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let content_hash = hex::encode(hasher.finalize());

        let mut trees = self.trees.write().await;

        // Validate agent count bound before inserting new agent
        if !trees.contains_key(agent_id) && trees.len() >= MAX_CHECKPOINT_AGENTS {
            anyhow::bail!(
                "checkpoint agent limit reached ({})",
                MAX_CHECKPOINT_AGENTS
            );
        }

        let tree = trees.entry(agent_id.to_string()).or_insert_with(|| {
            AgentCheckpointTree {
                leaves: Vec::new(),
                merkle_root: String::new(),
            }
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
        let proof_verified =
            merkle::verify_merkle_proof(&computed_hash, &proof, &tree.merkle_root);

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
fn validate_vault_identifier(id: &str, field_name: &str) -> Result<(), Response<Body>> {
    if id.contains(':') {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": format!("invalid {}: must not contain ':'", field_name)}),
        ));
    }
    if id.is_empty() {
        return Err(json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error": format!("{} must not be empty", field_name)}),
        ));
    }
    Ok(())
}

/// PUT /gvm/vault/:key — Write encrypted value to vault
///
/// Security: keys are scoped by agent_id prefix to enforce namespace isolation.
/// Agent "agent-001" can only write to keys prefixed with "agent-001:".
pub async fn vault_write(
    State(state): State<AppState>,
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

    // Namespace isolation: scope key by agent_id to prevent cross-agent access
    let scoped_key = format!("{}:{}", body.agent_id, key);

    match state
        .vault
        .write(&scoped_key, body.value.as_bytes(), &body.agent_id)
        .await
    {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"status": "ok", "key": key})),
        Err(e) => {
            tracing::error!(key = %key, agent = %body.agent_id, error = %e, "Vault write failed");
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
pub async fn vault_read(
    State(state): State<AppState>,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let agent_id = params.get("agent_id").map(|s| s.as_str()).unwrap_or("unknown");
    if let Err(resp) = validate_vault_identifier(agent_id, "agent_id") {
        return resp;
    }
    if let Err(resp) = validate_vault_identifier(&key, "key") {
        return resp;
    }
    let scoped_key = format!("{}:{}", agent_id, key);

    match state.vault.read(&scoped_key, agent_id).await {
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
        Ok(None) => json_response(StatusCode::NOT_FOUND, &serde_json::json!({"error": "Key not found", "key": key})),
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
pub async fn vault_delete(
    State(state): State<AppState>,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let agent_id = params.get("agent_id").map(|s| s.as_str()).unwrap_or("unknown");
    if let Err(resp) = validate_vault_identifier(agent_id, "agent_id") {
        return resp;
    }
    if let Err(resp) = validate_vault_identifier(&key, "key") {
        return resp;
    }
    let scoped_key = format!("{}:{}", agent_id, key);

    match state.vault.delete(&scoped_key, agent_id).await {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"status": "deleted", "key": key})),
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
    let reg = match state.checkpoint_registry.register(&agent_id, step, &body).await {
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
pub async fn check(
    State(state): State<AppState>,
    Json(body): Json<CheckRequest>,
) -> Response<Body> {
    let t0 = std::time::Instant::now();

    // Parse resource descriptor from JSON if provided
    let resource: crate::types::ResourceDescriptor = body
        .resource
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Layer 1: ABAC policy evaluation
    let operation = crate::types::OperationMetadata {
        operation: body.operation.clone(),
        resource: resource.clone(),
        subject: crate::types::SubjectDescriptor {
            agent_id: "dry-run".to_string(),
            tenant_id: None,
            session_id: "dry-run".to_string(),
        },
        context: crate::types::OperationContext {
            attributes: Default::default(),
        },
        payload: crate::types::PayloadDescriptor::default(),
    };
    let (policy_decision, matched_rule) = state.policy.evaluate(&operation);

    // Layer 2: Network SRR evaluation (use actual target_path for accurate matching)
    let srr_result = state.srr.check(&body.method, &body.target_host, &body.target_path, None);

    // Combined decision
    let decision = crate::types::max_strict(srr_result.decision, policy_decision);
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let (decision_str, next_action) = match &decision {
        crate::types::EnforcementDecision::Allow => ("Allow".to_string(), None),
        crate::types::EnforcementDecision::Delay { milliseconds } => (
            format!("Delay {}ms", milliseconds),
            Some(format!("Request will be delayed {}ms before forwarding", milliseconds)),
        ),
        crate::types::EnforcementDecision::RequireApproval { .. } => (
            "RequireApproval".to_string(),
            Some("Administrator approval required before execution".to_string()),
        ),
        crate::types::EnforcementDecision::Deny { .. } => (
            "Deny".to_string(),
            Some("This operation is blocked by policy. Contact your administrator.".to_string()),
        ),
        _ => (format!("{:?}", decision), None),
    };

    let mut resp = serde_json::json!({
        "decision": decision_str,
        "engine_ms": (elapsed * 10.0).round() / 10.0,
        "operation": body.operation,
        "method": body.method,
        "target_host": body.target_host,
        "matched_rule": matched_rule,
        "dry_run": true,
    });

    if let Some(action) = &next_action {
        resp["next_action"] = serde_json::Value::String(action.clone());
    }

    json_response(StatusCode::OK, &resp)
}

// ─── Health / Admin Endpoints ───

/// GET /gvm/health — Liveness check
pub async fn health() -> Response<Body> {
    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "status": "healthy",
            "version": "0.1.0",
        }),
    )
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
                "core_operations": state.registry.core_count(),
                "custom_operations": state.registry.custom_count(),
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
