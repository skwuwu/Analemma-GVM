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
pub async fn vault_write(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(body): Json<VaultWriteRequest>,
) -> Response<Body> {
    match state
        .vault
        .write(&key, body.value.as_bytes(), &body.agent_id)
        .await
    {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"status": "ok", "key": key})),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({"error": e.to_string()}),
        ),
    }
}

/// GET /gvm/vault/:key?agent_id=xxx — Read and decrypt value from vault
pub async fn vault_read(
    State(state): State<AppState>,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let agent_id = params.get("agent_id").map(|s| s.as_str()).unwrap_or("unknown");

    match state.vault.read(&key, agent_id).await {
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
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({"error": e.to_string()}),
        ),
    }
}

/// DELETE /gvm/vault/:key?agent_id=xxx — Delete key from vault
pub async fn vault_delete(
    State(state): State<AppState>,
    Path(key): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let agent_id = params.get("agent_id").map(|s| s.as_str()).unwrap_or("unknown");

    match state.vault.delete(&key, agent_id).await {
        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"status": "deleted", "key": key})),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &serde_json::json!({"error": e.to_string()}),
        ),
    }
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

/// GET /gvm/info — Proxy info and loaded configuration summary
pub async fn info(State(state): State<AppState>) -> Response<Body> {
    let registry_info = format!("{:?}", *state.registry);
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
            "registry_summary": registry_info,
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
