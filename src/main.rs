mod api;
mod api_keys;
mod config;
mod ledger;
mod policy;
mod proxy;
mod rate_limiter;
mod registry;
mod srr;
mod types;
mod vault;

use crate::api_keys::APIKeyStore;
use crate::config::ProxyConfig;
use crate::ledger::Ledger;
use crate::policy::PolicyEngine;
use crate::proxy::{proxy_handler, AppState};
use crate::rate_limiter::RateLimiter;
use crate::registry::OperationRegistry;
use crate::srr::NetworkSRR;
use crate::vault::Vault;
use axum::Router;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;

#[tokio::main]
async fn main() {
    // Initialize tracing (structured logging)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Analemma GVM Proxy v0.1.0 starting...");

    // 1. Load configuration (tries GVM_CONFIG env, CWD, home dir, then defaults)
    let config = ProxyConfig::load_or_default();

    // 2. Load Operation Registry (Fail-Close: invalid registry → panic)
    let registry = OperationRegistry::load(Path::new(&config.operations.registry_file))
        .expect("Failed to load operation registry — startup aborted");
    tracing::info!("Operation registry loaded and validated");

    // 3. Load Network SRR rules
    let srr = NetworkSRR::load(Path::new(&config.srr.network_file))
        .expect("Failed to load network SRR rules");
    tracing::info!("Network SRR rules loaded");

    // 4. Load ABAC policy engine
    let policy = PolicyEngine::load(Path::new(&config.policies.directory))
        .expect("Failed to load policy engine");
    tracing::info!("ABAC policy engine loaded");

    // 5. Load API key store
    let api_keys = APIKeyStore::load(Path::new(&config.secrets.file))
        .expect("Failed to load API key store");
    tracing::info!("API key store loaded");

    // 6. Initialize Ledger (WAL + NATS stub)
    let ledger = Ledger::new(
        Path::new("data/wal.log"),
        &config.nats.url,
        &config.nats.stream,
    )
    .await
    .expect("Failed to initialize ledger");
    let ledger = Arc::new(ledger);

    // 7. Run WAL crash recovery
    match ledger.recover_from_wal().await {
        Ok(report) => {
            if report.expired_marked > 0 {
                tracing::warn!(
                    expired = report.expired_marked,
                    "WAL recovery: expired events found — operator review required"
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "WAL recovery skipped (no prior WAL or first boot)");
        }
    }

    // 8. Initialize Vault (encrypted state store)
    let vault = Vault::new(ledger.clone()).expect("Failed to initialize vault");
    tracing::info!("Vault initialized");

    // 9. Build HTTP client for upstream forwarding
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    // 9.5. Load dev host overrides (ignored in production)
    let mut host_overrides = config
        .dev
        .as_ref()
        .map(|d| d.host_overrides.clone())
        .unwrap_or_default();

    if !host_overrides.is_empty() {
        if std::env::var("GVM_ENV").unwrap_or_default() == "production" {
            tracing::warn!("[dev] host_overrides ignored in production mode");
            host_overrides.clear();
        } else {
            tracing::warn!(
                overrides = ?host_overrides,
                "DEV MODE: host overrides active — do NOT use in production"
            );
        }
    }

    // 10. Compose shared state
    let state = AppState {
        srr: Arc::new(srr),
        policy: Arc::new(policy),
        registry: Arc::new(registry),
        api_keys: Arc::new(api_keys),
        ledger,
        vault: Arc::new(vault),
        rate_limiter: Arc::new(RateLimiter::new()),
        http_client,
        host_overrides,
    };

    // 11. Build axum router with security layers
    //     - /gvm/* routes: admin, health, vault API
    //     - fallback: proxy handler (all other requests)
    //     - Backpressure: request body limit (1MB) prevents OOM from oversized payloads
    //     - Concurrency: connection limit prevents FD exhaustion under DoS
    let app = Router::new()
        .route("/gvm/health", axum::routing::get(api::health))
        .route("/gvm/info", axum::routing::get(api::info))
        .route("/gvm/check", axum::routing::post(api::check))
        .route(
            "/gvm/vault/:key",
            axum::routing::put(api::vault_write)
                .get(api::vault_read)
                .delete(api::vault_delete),
        )
        .fallback(proxy_handler)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                // Panic Guard: catch any panic in handler, return 500 instead of killing process.
                // A security kernel must NEVER crash — panics from malformed input or
                // edge cases in dependencies are caught here.
                .layer(CatchPanicLayer::new())
                // Backpressure: reject request bodies > 1MB (prevents OOM/resource exhaustion)
                .layer(RequestBodyLimitLayer::new(1024 * 1024))
                // Concurrency: limit concurrent in-flight requests to 1024
                // Beyond this, new connections get 503 Service Unavailable
                .layer(tower::limit::ConcurrencyLimitLayer::new(1024)),
        );

    // 12. Start server
    let listener = tokio::net::TcpListener::bind(&config.server.listen)
        .await
        .expect("Failed to bind to listen address");

    tracing::info!(address = %config.server.listen, "GVM Proxy listening");

    axum::serve(listener, app).await.expect("Server error");
}
