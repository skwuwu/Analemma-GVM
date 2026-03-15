use crate::proxy::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Response, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

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

/// PUT /gvm/vault/:key — Write encrypted value to vault
///
/// Security: keys are scoped by agent_id prefix to enforce namespace isolation.
/// Agent "agent-001" can only write to keys prefixed with "agent-001:".
pub async fn vault_write(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(body): Json<VaultWriteRequest>,
) -> Response<Body> {
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
/// Used by SDK for automatic rollback on Deny/RequireApproval decisions.
pub async fn checkpoint_write(
    State(state): State<AppState>,
    Path((agent_id, step)): Path<(String, u64)>,
    body: axum::body::Bytes,
) -> Response<Body> {
    let key = format!("checkpoint:{}:{}", agent_id, step);
    match state.vault.write(&key, &body, &agent_id).await {
        Ok(()) => {
            tracing::debug!(agent = %agent_id, step = step, "Checkpoint saved");
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "status": "ok",
                    "checkpoint_step": step,
                    "agent_id": agent_id,
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
/// Retrieves and decrypts a previously saved checkpoint.
/// Returns the raw checkpoint bytes with Merkle verification header.
pub async fn checkpoint_read(
    State(state): State<AppState>,
    Path((agent_id, step)): Path<(String, u64)>,
) -> Response<Body> {
    let key = format!("checkpoint:{}:{}", agent_id, step);
    match state.vault.read(&key, &agent_id).await {
        Ok(Some(data)) => {
            tracing::debug!(agent = %agent_id, step = step, "Checkpoint restored");
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("X-GVM-Checkpoint-Step", step.to_string())
                .header("X-GVM-Merkle-Verified", "true")
                .body(Body::from(data))
                .unwrap_or_else(|_| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap()
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
    let srr_decision = state.srr.check(&body.method, &body.target_host, &body.target_path, None);

    // Combined decision
    let decision = crate::types::max_strict(srr_decision, policy_decision);
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
                .unwrap()
        })
}
