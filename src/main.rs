use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use gvm_proxy::api;
use gvm_proxy::api_keys::APIKeyStore;
use gvm_proxy::auth;
use gvm_proxy::config::ProxyConfig;
use gvm_proxy::ledger::Ledger;
use gvm_proxy::policy::PolicyEngine;
use gvm_proxy::proxy::{proxy_handler, AppState};
use gvm_proxy::rate_limiter::RateLimiter;
use gvm_proxy::registry::OperationRegistry;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::vault::Vault;
use gvm_proxy::wasm_engine::WasmEngine;
use std::path::Path;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower::ServiceExt;
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
    let mut config = ProxyConfig::load_or_default();

    // 2. First-run detection: if config files are missing, offer interactive setup.
    //    After setup, reload config so template proxy.toml settings take effect.
    let registry_path_str = config.operations.registry_file.clone();
    let srr_path_str = config.srr.network_file.clone();
    if !Path::new(&registry_path_str).exists()
        && !Path::new(&srr_path_str).exists()
        && offer_first_run_setup()
    {
        // Template applied — reload config to pick up template's proxy.toml
        config = ProxyConfig::load_or_default();
    }
    let registry_path = Path::new(&config.operations.registry_file);
    let srr_path = Path::new(&config.srr.network_file);

    // 3. Load Operation Registry (Fail-Close: invalid registry → abort with guidance)
    let registry = match OperationRegistry::load(registry_path) {
        Ok(r) => {
            tracing::info!("Operation registry loaded and validated");
            r
        }
        Err(e) => {
            tracing::error!(
                path = %registry_path.display(),
                error = %e,
                "Failed to load operation registry"
            );
            eprintln!();
            eprintln!("  ERROR: Cannot start — operation registry not found or invalid.");
            eprintln!("  Expected: {}", registry_path.display());
            eprintln!();
            eprintln!("  Quick fix:");
            eprintln!("    git clone https://github.com/skwuwu/Analemma-GVM && cd Analemma-GVM");
            eprintln!("    cargo run   # config/ directory is included in the repo");
            eprintln!();
            eprintln!("  Or run: gvm init --industry saas");
            eprintln!();
            std::process::exit(1);
        }
    };

    // 4. Load Network SRR rules (Fail-Close: invalid SRR → abort with guidance)
    let mut srr = match NetworkSRR::load(srr_path) {
        Ok(s) => {
            tracing::info!("Network SRR rules loaded");
            s
        }
        Err(e) => {
            tracing::error!(
                path = %srr_path.display(),
                error = %e,
                "Failed to load network SRR rules"
            );
            eprintln!();
            eprintln!("  ERROR: Cannot start — network SRR rules not found or invalid.");
            eprintln!("  Expected: {}", srr_path.display());
            eprintln!();
            eprintln!("  Quick fix:");
            eprintln!("    Ensure config/srr_network.toml exists in the working directory.");
            eprintln!("    Or run: gvm init --industry saas");
            eprintln!();
            std::process::exit(1);
        }
    };

    // 3.5. Apply configurable Default-to-Caution policy for unmatched URLs
    // GVM_DEFAULT_UNKNOWN env var overrides proxy.toml (set by `gvm run --default-policy`)
    let default_unknown_setting = std::env::var("GVM_DEFAULT_UNKNOWN")
        .unwrap_or_else(|_| config.enforcement.default_unknown.clone());
    let default_unknown_decision = match default_unknown_setting.as_str() {
        "require_approval" => {
            tracing::info!("Default-to-Caution: RequireApproval (unmatched URLs held for human approval)");
            gvm_types::EnforcementDecision::RequireApproval {
                urgency: gvm_types::ApprovalUrgency::Standard,
            }
        }
        "deny" => {
            tracing::info!("Default-to-Caution: Deny (unmatched URLs blocked immediately)");
            gvm_types::EnforcementDecision::Deny {
                reason: "URL not in SRR allowlist (default_unknown = deny)".to_string(),
            }
        }
        _ => {
            let ms = config.enforcement.default_delay_ms;
            tracing::info!(delay_ms = ms, "Default-to-Caution: Delay (unmatched URLs delayed then forwarded)");
            gvm_types::EnforcementDecision::Delay { milliseconds: ms }
        }
    };
    srr.set_default_decision(default_unknown_decision);

    // 4. Load ABAC policy engine (graceful: empty dir → empty policy set)
    let policy = PolicyEngine::load(Path::new(&config.policies.directory))
        .expect("Failed to load policy engine");
    tracing::info!("ABAC policy engine loaded");

    // 5. Load API key store (graceful: missing file → empty store with warning)
    let api_keys =
        APIKeyStore::load(Path::new(&config.secrets.file)).expect("Failed to load API key store");
    if api_keys.is_empty() {
        tracing::warn!(
            "No API keys configured. Running in passthrough mode. \
             Layer 3 (API key isolation) is INACTIVE. \
             Agents can bypass proxy by calling APIs directly. \
             Run `gvm init` to configure API key isolation."
        );
    } else {
        tracing::info!("API key store loaded");
    }

    // 6. Initialize Ledger (WAL + NATS stub)
    let wal_config = gvm_proxy::ledger::GroupCommitConfig {
        batch_window: std::time::Duration::from_millis(config.wal.batch_window_ms),
        max_batch_size: config.wal.max_batch_size,
        max_wal_bytes: config.wal.max_wal_bytes,
        max_wal_segments: config.wal.max_wal_segments,
        ..Default::default()
    };
    let ledger = Ledger::with_config(
        Path::new("data/wal.log"),
        &config.nats.url,
        &config.nats.stream,
        wal_config,
    )
    .await
    .expect("Failed to initialize ledger");
    let ledger = Arc::new(ledger);
    let ledger_for_shutdown = ledger.clone();

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

    // 7.5. Record config file hashes in Merkle chain (tamper detection)
    {
        let policy_dir = Path::new(&config.policies.directory);

        let mut all_config_files: Vec<(String, std::path::PathBuf)> = vec![
            ("srr_network".to_string(), srr_path.to_path_buf()),
            (
                "operation_registry".to_string(),
                registry_path.to_path_buf(),
            ),
        ];

        if policy_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(policy_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "toml") {
                        let label = format!(
                            "policy/{}",
                            path.file_name().unwrap_or_default().to_string_lossy()
                        );
                        all_config_files.push((label, path));
                    }
                }
            }
        }

        let config_refs: Vec<(&str, &Path)> = all_config_files
            .iter()
            .map(|(label, path)| (label.as_str(), path.as_path()))
            .collect();

        if let Err(e) = ledger.record_config_load(&config_refs).await {
            tracing::warn!(error = %e, "Failed to record config hashes in WAL — continuing without config integrity record");
        }
    }

    // 8. Initialize Vault (encrypted state store)
    let vault = Vault::new(ledger.clone()).expect("Failed to initialize vault");
    tracing::info!("Vault initialized");

    // 8.5. Initialize Wasm Governance Engine (Layer 1: Immutable Logic)
    let wasm_engine = WasmEngine::load(Path::new("data/gvm_engine.wasm"))
        .expect("Failed to initialize Wasm engine");
    if wasm_engine.is_wasm() {
        tracing::info!(
            hash = %wasm_engine.module_hash.as_deref().unwrap_or("unknown"),
            "Layer 1: Wasm governance engine ACTIVE (immutable sandbox)"
        );
    } else {
        tracing::info!("Layer 1: Using native policy engine (Wasm module not loaded)");
    }

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

    // 9.7. Initialize JWT authentication (optional)
    let jwt_secret_env = config
        .jwt
        .as_ref()
        .map(|j| j.secret_env.as_str())
        .unwrap_or("GVM_JWT_SECRET");
    let jwt_ttl = config
        .jwt
        .as_ref()
        .map(|j| j.token_ttl_secs)
        .unwrap_or(3600);

    let jwt_config = match auth::JwtConfig::from_env(jwt_secret_env, jwt_ttl) {
        Ok(Some(c)) => {
            tracing::info!(
                ttl_secs = c.token_ttl_secs,
                "JWT authentication ACTIVE — agent identity will be cryptographically verified"
            );
            Some(Arc::new(c))
        }
        Ok(None) => {
            tracing::info!(
                "JWT authentication DISABLED (no {} env var). \
                 Agent identity uses self-declared X-GVM-Agent-Id headers.",
                jwt_secret_env
            );
            None
        }
        Err(e) => {
            tracing::error!(error = %e, "Invalid JWT secret — cannot start");
            eprintln!();
            eprintln!("  ERROR: JWT secret is configured but invalid.");
            eprintln!("  {}", e);
            eprintln!();
            eprintln!("  Fix: export {}=<64+ hex chars>", jwt_secret_env);
            eprintln!("  Or remove [jwt] section from proxy.toml to disable JWT.");
            eprintln!();
            std::process::exit(1);
        }
    };

    // 9.9. Generate ephemeral CA for MITM TLS inspection.
    // Single CA shared between:
    //   - TLS MITM listener (port 8443) — uses it to terminate agent TLS
    //   - GET /gvm/ca.pem endpoint — sandbox downloads it for trust store injection
    // This ensures the CA injected into the sandbox matches the one used by the listener.
    let mitm_ca = gvm_sandbox::ca::EphemeralCA::generate()
        .expect("Failed to generate ephemeral MITM CA");
    let mitm_ca_cert_pem = Arc::new(mitm_ca.ca_cert_pem().to_vec());
    let mitm_ca_key_pem = Arc::new(mitm_ca.ca_key_pem());
    tracing::info!("Ephemeral MITM CA generated (shared between TLS listener and sandbox)");

    // 10. Print startup policy summary
    print_startup_summary(&srr, &policy, &registry, &api_keys);

    // 11. Compose shared state
    let state = AppState {
        srr: Arc::new(std::sync::RwLock::new(srr)),
        policy: Arc::new(policy),
        registry: Arc::new(registry),
        api_keys: Arc::new(api_keys),
        ledger,
        vault: Arc::new(vault),
        rate_limiter: Arc::new(RateLimiter::new()),
        wasm_engine: Arc::new(wasm_engine),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: config.enforcement.on_block.clone(),
        http_client,
        host_overrides,
        jwt_config,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(
            config.shadow.intent_ttl_secs,
        )),
        srr_config_path: config.srr.network_file.clone(),
        mitm_ca_pem: Some(mitm_ca_cert_pem.clone()),
        payload_inspection: config.srr.payload_inspection,
        max_body_bytes: config.srr.max_body_bytes,
        pending_approvals: Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: config.enforcement.ic3_approval_timeout_secs,
        shadow_config: {
            // GVM_SHADOW_MODE env var overrides config (MCP server sets this)
            let mut sc = config.shadow.clone();
            if let Some(mode) = gvm_proxy::intent_store::ShadowMode::from_env() {
                if mode != sc.mode {
                    tracing::info!(mode = ?mode, "Shadow mode overridden by GVM_SHADOW_MODE env var");
                    sc.mode = mode;
                }
            }
            sc
        },
    };

    // Clone state for CONNECT handler before moving into axum router
    let connect_state = state.clone();

    // 11. Build axum router with security layers
    //     - /gvm/* routes: admin, health, vault API
    //     - fallback: proxy handler (all other requests)
    //     - Backpressure: request body limit (1MB) prevents OOM from oversized payloads
    //     - Concurrency: connection limit prevents FD exhaustion under DoS
    let app = Router::new()
        .route("/gvm/health", axum::routing::get(api::health))
        .route("/gvm/info", axum::routing::get(api::info))
        .route("/gvm/check", axum::routing::post(api::check))
        .route("/gvm/intent", axum::routing::post(api::register_intent))
        .route("/gvm/reload", axum::routing::post(api::reload_srr))
        .route("/gvm/pending", axum::routing::get(api::pending_approvals))
        .route("/gvm/approve", axum::routing::post(api::approve_request))
        .route("/gvm/ca.pem", axum::routing::get(serve_mitm_ca))
        .route("/gvm/auth/token", axum::routing::post(api::auth_token))
        .route(
            "/gvm/vault/:key",
            axum::routing::put(api::vault_write)
                .get(api::vault_read)
                .delete(api::vault_delete),
        )
        .route(
            "/gvm/vault/checkpoint/:agent_id/:step",
            axum::routing::put(api::checkpoint_write)
                .get(api::checkpoint_read)
                .delete(api::checkpoint_delete),
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

    // 12. Start server with CONNECT tunnel support
    let listener = tokio::net::TcpListener::bind(&config.server.listen)
        .await
        .expect("Failed to bind to listen address");

    tracing::info!(address = %config.server.listen, "GVM Proxy listening (HTTP)");

    // 13. Start TLS MITM listener (port 8443) for sandbox HTTPS inspection
    let tls_port = {
        let parts: Vec<&str> = config.server.listen.rsplitn(2, ':').collect();
        let base_port: u16 = parts[0].parse().unwrap_or(8080);
        let tls_port = base_port + 363; // 8080→8443
        let host = if parts.len() > 1 { parts[1] } else { "0.0.0.0" };
        format!("{}:{}", host, tls_port)
    };

    let tls_state = connect_state.clone();
    let tls_ca_cert = mitm_ca_cert_pem.clone();
    let tls_ca_key = mitm_ca_key_pem.clone();
    tokio::spawn(async move {
        if let Err(e) = start_tls_listener(&tls_port, tls_state, &tls_ca_cert, &tls_ca_key).await {
            tracing::warn!(error = %e, "TLS MITM listener failed to start (sandbox HTTPS inspection unavailable)");
        }
    });

    // Use hyper directly to handle CONNECT method (axum doesn't route CONNECT).
    // Named functions avoid deeply nested closures that trigger rustc ICE on 1.94.0.
    let app_for_connect = app.clone();
    let state_for_connect = connect_state;

    // ── Graceful shutdown: two-phase ──
    // Phase 1: Accept connections until shutdown signal (SIGTERM/SIGINT).
    // Phase 2: Stop accepting new connections, drain in-flight requests
    //          (up to drain_timeout_secs), flush WAL, exit.
    let drain_timeout = std::time::Duration::from_secs(config.server.drain_timeout_secs);

    // Track spawned connection handles so we can abort them after drain timeout.
    // This guarantees Arc<Ledger> references are released for WAL shutdown flush.
    let mut connection_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    loop {
        tokio::select! {
            conn = listener.accept() => {
                match conn {
                    Ok((stream, _addr)) => {
                        let app = app_for_connect.clone();
                        let cs = state_for_connect.clone();
                        let handle = tokio::spawn(async move {
                            serve_connection(stream, app, cs).await;
                        });
                        connection_handles.push(handle);
                        // Periodically clean up finished handles to avoid unbounded growth
                        if connection_handles.len() > 2048 {
                            connection_handles.retain(|h| !h.is_finished());
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Accept failed");
                    }
                }
            }
            _ = shutdown_signal() => {
                tracing::info!("Shutdown signal received — entering graceful shutdown");
                break;
            }
        }
    }

    // Phase 2: Drain in-flight connections
    // Remove already-finished handles first
    connection_handles.retain(|h| !h.is_finished());
    let active = connection_handles.len();

    if active > 0 {
        tracing::info!(
            active_connections = active,
            drain_timeout_secs = drain_timeout.as_secs(),
            "Draining in-flight connections (new connections refused)..."
        );

        // Wait for all handles with timeout
        let drain_result = tokio::time::timeout(
            drain_timeout,
            futures_util::future::join_all(
                connection_handles.iter_mut().map(|h| async { h.await.ok(); }),
            ),
        )
        .await;

        match drain_result {
            Ok(_) => {
                tracing::info!("All connections drained cleanly");
            }
            Err(_) => {
                // Drain timeout exceeded — abort remaining connections.
                // This drops their Arc<AppState> (which holds Arc<Ledger>),
                // allowing try_unwrap to succeed for WAL shutdown flush.
                let remaining = connection_handles.iter().filter(|h| !h.is_finished()).count();
                tracing::warn!(
                    remaining,
                    "Drain timeout reached — aborting {} remaining connections to release WAL",
                    remaining
                );
                for h in &connection_handles {
                    if !h.is_finished() {
                        h.abort();
                    }
                }
                // Brief yield to let abort propagate and drop Arc refs
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    drop(connection_handles); // Ensure all handles are dropped

    // Phase 3: Flush WAL
    // Drop all other Arc<AppState> references so only ledger_for_shutdown remains.
    drop(app_for_connect);
    drop(state_for_connect);

    match Arc::try_unwrap(ledger_for_shutdown) {
        Ok(mut ledger) => {
            ledger.shutdown().await;
        }
        Err(arc) => {
            // This should not happen after aborting all connections, but handle gracefully.
            let strong = Arc::strong_count(&arc);
            tracing::warn!(
                strong_refs = strong,
                "WAL shutdown: {} references still held — batch task will flush on final drop",
                strong
            );
            // Drop our reference. The batch task will flush when the last ref drops.
            drop(arc);
        }
    }

    tracing::info!("GVM Proxy shut down cleanly");
}

/// Wait for a shutdown signal (Ctrl+C or SIGTERM on Unix).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    app: axum::Router,
    state: gvm_proxy::proxy::AppState,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req| {
        let a = app.clone();
        let s = state.clone();
        route_request(req, a, s)
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(io, svc)
        .with_upgrades();
    if let Err(e) = conn.await {
        if !e.is_incomplete_message() {
            tracing::debug!(error = %e, "Connection error");
        }
    }
}

/// Serve the MITM CA certificate PEM for sandbox trust store injection.
/// Sandbox can download this via `curl http://proxy:8080/gvm/ca.pem` and inject into /etc/ssl/certs/.
async fn serve_mitm_ca(
    axum::extract::State(state): axum::extract::State<gvm_proxy::proxy::AppState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match &state.mitm_ca_pem {
        Some(pem) => (
            [(axum::http::header::CONTENT_TYPE, "application/x-pem-file")],
            pem.as_ref().clone(),
        )
            .into_response(),
        None => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn route_request(
    req: Request<hyper::body::Incoming>,
    app: axum::Router,
    state: gvm_proxy::proxy::AppState,
) -> Result<Response<Body>, std::convert::Infallible> {
    if req.method() == hyper::Method::CONNECT {
        return gvm_proxy::proxy::handle_connect(state, req).await;
    }
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, Body::new(body));
    let resp = app.oneshot(req).await.unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()
    });
    Ok(resp)
}

/// Maximum concurrent TLS MITM connections.
/// Matches the HTTP listener's ConcurrencyLimitLayer(1024).
/// Prevents FD exhaustion on port 8443 — excess connections wait on the semaphore.
const MAX_TLS_CONNECTIONS: usize = 1024;

/// TLS handshake timeout. Defends against Slowloris on the TLS layer:
/// attacker opens TCP, sends partial ClientHello, never completes.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Upstream connect + relay timeout. Prevents zombie connections when upstream hangs.
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// TLS MITM listener for sandbox HTTPS inspection.
///
/// Accepts TLS connections on port 8443, terminates TLS using the ephemeral CA,
/// inspects the plaintext HTTP request, applies SRR policy, and forwards to upstream.
async fn start_tls_listener(
    listen_addr: &str,
    state: gvm_proxy::proxy::AppState,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
) -> anyhow::Result<()> {
    use gvm_proxy::tls_proxy::{build_client_config, build_server_config, GvmCertResolver};

    // Install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Use the shared ephemeral CA (generated once in main, same CA injected into sandbox trust store)
    let resolver = std::sync::Arc::new(GvmCertResolver::new(ca_cert_pem, ca_key_pem)?);
    let server_config = std::sync::Arc::new(build_server_config(resolver.clone())?);
    let client_config = std::sync::Arc::new(build_client_config()?);

    // Semaphore: bound concurrent TLS connections to prevent FD exhaustion.
    let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_TLS_CONNECTIONS));

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(address = %listen_addr, "GVM TLS MITM proxy listening");

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "TLS accept failed");
                continue;
            }
        };

        let permit = match conn_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(addr = %addr, "TLS connection rejected: at capacity ({} max)", MAX_TLS_CONNECTIONS);
                drop(stream);
                continue;
            }
        };

        let sc = server_config.clone();
        let cc = client_config.clone();
        let st = state.clone();
        let res = resolver.clone();

        tokio::spawn(async move {
            let _permit = permit; // held until task completes → auto-released on drop
            if let Err(e) = handle_tls_connection(stream, sc, cc, st, res).await {
                tracing::debug!(error = %e, addr = %addr, "TLS connection error");
            }
        });
    }
}

/// Handle a single MITM TLS connection:
/// 1. Peek SNI + pre-warm cert cache on blocking thread (avoids tokio starvation)
/// 2. TLS handshake with agent (cert already cached → 0ns resolve)
/// 3. Read plaintext HTTP request (with timeout + smuggling defense)
/// 4. Apply SRR policy check
/// 5. If allowed: connect to upstream, forward request, relay response
/// 6. If denied: return 403 to agent
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    server_config: std::sync::Arc<rustls::ServerConfig>,
    client_config: std::sync::Arc<rustls::ClientConfig>,
    state: gvm_proxy::proxy::AppState,
    resolver: std::sync::Arc<gvm_proxy::tls_proxy::GvmCertResolver>,
) -> anyhow::Result<()> {
    use gvm_proxy::tls_proxy::{peek_sni, read_http_request};
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // 1. Pre-warm cert cache: peek SNI from raw TCP, generate cert on blocking
    //    thread pool. This prevents CPU-bound keygen from starving tokio workers.
    //    50 concurrent new-domain handshakes would otherwise block all async I/O.
    if let Some(sni) = peek_sni(&stream).await {
        resolver.ensure_cached(sni).await;
    }

    // 2. TLS handshake with timeout (SNI → cache hit from step 1)
    let acceptor = TlsAcceptor::from(server_config);
    let mut tls_stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;

    // 3. Read plaintext HTTP from decrypted stream (has its own 30s timeout)
    let req = read_http_request(&mut tls_stream).await?;

    let host = if req.host.is_empty() {
        "unknown".to_string()
    } else {
        req.host.clone()
    };

    tracing::info!(
        method = %req.method,
        host = %host,
        path = %req.path,
        "MITM: inspecting HTTPS request"
    );

    // 4. SRR policy check
    let srr_result = {
        let srr = state.srr.read().unwrap_or_else(|e| e.into_inner());
        let body_ref = if req.body.is_empty() {
            None
        } else {
            Some(req.body.as_slice())
        };
        srr.check(&req.method, &host, &req.path, body_ref)
    };

    let decision = &srr_result.decision;
    tracing::info!(decision = ?decision, host = %host, path = %req.path, "MITM: SRR decision");

    // 5. Enforce decision
    match decision {
        gvm_types::EnforcementDecision::Deny { reason } => {
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n\
                 {{\"blocked\":true,\"decision\":\"Deny\",\"reason\":\"{}\"}}\r\n",
                reason
            );
            tls_stream.write_all(response.as_bytes()).await?;
            tls_stream.shutdown().await?;
            tracing::warn!(host = %host, path = %req.path, reason = %reason, "MITM: request DENIED");
            return Ok(());
        }
        gvm_types::EnforcementDecision::Delay { milliseconds } => {
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
        }
        _ => {} // Allow, AuditOnly, etc. — proceed
    }

    // 6. API key injection (Layer 3) — strip agent auth headers, inject proxy credentials.
    //    This is the MITM equivalent of the HTTP path's api_keys.inject().
    //    The agent never holds API keys; the proxy injects them post-enforcement.
    let mut req = req;
    if req.inject_credentials(&state.api_keys) {
        tracing::info!(host = %host, "MITM: API key injected for upstream");
    }

    // 7. Connect to upstream with TLS (with timeout)
    let upstream_result = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        let connector = TlsConnector::from(client_config);
        let upstream_host = host.split(':').next().unwrap_or(&host);
        let upstream_addr = format!("{}:443", upstream_host);

        let upstream_tcp = tokio::net::TcpStream::connect(&upstream_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(upstream_host.to_string())?;
        let mut upstream_tls = connector.connect(server_name, upstream_tcp).await?;

        // 8. Forward the request (with injected credentials)
        upstream_tls.write_all(&req.raw_head).await?;
        if !req.body.is_empty() {
            upstream_tls.write_all(&req.body).await?;
        }

        // 8. Relay upstream response back to agent
        let mut buf = vec![0u8; 8192];
        loop {
            use tokio::io::AsyncReadExt;
            let n = upstream_tls.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tls_stream.write_all(&buf[..n]).await?;
        }

        tls_stream.shutdown().await.ok();
        Ok::<(), anyhow::Error>(())
    })
    .await;

    match upstream_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("Upstream relay timed out ({}s)", UPSTREAM_TIMEOUT.as_secs()),
    }
}

/// Print a human-readable startup summary of loaded governance rules.
/// Helps operators verify that the correct policies are active before
/// traffic starts flowing through the proxy.
fn print_startup_summary(
    srr: &gvm_proxy::srr::NetworkSRR,
    policy: &gvm_proxy::policy::PolicyEngine,
    registry: &gvm_proxy::registry::OperationRegistry,
    api_keys: &gvm_proxy::api_keys::APIKeyStore,
) {
    let srr_info = srr.summary();
    let (global_rules, tenant_count, agent_count) = policy.summary();

    eprintln!();
    eprintln!("  \x1b[1m\x1b[36m╔══════════════════════════════════════════╗\x1b[0m");
    eprintln!(
        "  \x1b[1m\x1b[36m║\x1b[0m   Analemma GVM — Governance Summary     \x1b[1m\x1b[36m║\x1b[0m"
    );
    eprintln!("  \x1b[1m\x1b[36m╚══════════════════════════════════════════╝\x1b[0m");
    eprintln!();

    // Layer 2: SRR (Network rules)
    eprintln!("  \x1b[1mLayer 2 — Network SRR\x1b[0m");
    eprintln!("    Rules loaded:     {}", srr_info.total_rules);
    eprintln!(
        "    \x1b[31mDeny:  {}\x1b[0m   \x1b[33mDelay: {}\x1b[0m   \x1b[32mAllow: {}\x1b[0m",
        srr_info.deny_rules, srr_info.delay_rules, srr_info.allow_rules
    );
    eprintln!(
        "    Default (no match): \x1b[33m{}\x1b[0m",
        srr_info.default_decision
    );

    if !srr_info.sample_denies.is_empty() {
        eprintln!("    Blocked endpoints:");
        for deny in &srr_info.sample_denies {
            eprintln!("      \x1b[31m✗\x1b[0m {}", deny);
        }
    }
    eprintln!();

    // Layer 1: ABAC (Policy engine)
    eprintln!("  \x1b[1mLayer 1 — ABAC Policy\x1b[0m  \x1b[2m(requires SDK)\x1b[0m");
    eprintln!(
        "    Global rules: {}   Tenants: {}   Agent policies: {}",
        global_rules, tenant_count, agent_count
    );
    if global_rules == 0 && tenant_count == 0 && agent_count == 0 {
        eprintln!("    \x1b[2mNo ABAC policies loaded — SRR-only mode\x1b[0m");
    }
    eprintln!();

    // Operations registry
    eprintln!("  \x1b[1mOperation Registry\x1b[0m");
    eprintln!(
        "    Core: {}   Custom: {}",
        registry.core_count(),
        registry.custom_count()
    );
    eprintln!();

    // Layer 3: API key isolation
    eprintln!("  \x1b[1mLayer 3 — API Key Isolation\x1b[0m");
    if api_keys.is_empty() {
        eprintln!("    \x1b[33m⚠ No API keys configured — passthrough mode\x1b[0m");
        eprintln!("    \x1b[2mAgents can call APIs directly without credential isolation.\x1b[0m");
        eprintln!("    \x1b[2mRun: gvm init --industry saas\x1b[0m");
    } else {
        eprintln!("    \x1b[32m✓ Active\x1b[0m — credentials injected post-enforcement");
    }
    eprintln!();

    // How decisions work
    eprintln!("  \x1b[2m┌─────────────────────────────────────────────┐\x1b[0m");
    eprintln!("  \x1b[2m│  Request flow:                              │\x1b[0m");
    eprintln!("  \x1b[2m│  Agent → [SRR check] → [ABAC check*] →     │\x1b[0m");
    eprintln!("  \x1b[2m│         [API key inject] → Upstream         │\x1b[0m");
    eprintln!("  \x1b[2m│  * ABAC only with SDK (X-GVM-Agent-Id)      │\x1b[0m");
    eprintln!("  \x1b[2m│  Unknown URLs → Delay(300ms) + audit trail  │\x1b[0m");
    eprintln!("  \x1b[2m└─────────────────────────────────────────────┘\x1b[0m");
    eprintln!();
}

/// Detect first-run (no config files present) and offer interactive setup.
/// Reads from stdin — only prompts when running in a terminal (not piped/CI).
/// Returns true if template files were successfully applied.
fn offer_first_run_setup() -> bool {
    use std::io::{self, BufRead, Write};

    // Skip prompt in non-interactive environments (CI, piped input, tests)
    if !atty_is_terminal() {
        return false;
    }

    eprintln!();
    eprintln!("  \x1b[1m\x1b[33m⚡ First Run Detected\x1b[0m");
    eprintln!();
    eprintln!("  No governance rules found. GVM needs a ruleset to enforce policies.");
    eprintln!("  Choose an industry template to get started:");
    eprintln!();
    eprintln!("    \x1b[1m1\x1b[0m  \x1b[36mfinance\x1b[0m  — Wire transfers blocked, payments need IC-3 approval");
    eprintln!("    \x1b[1m2\x1b[0m  \x1b[36msaas\x1b[0m     — Default-to-Caution, balanced security for SaaS agents");
    eprintln!("    \x1b[1m3\x1b[0m  Skip     — Exit and configure manually");
    eprintln!();
    eprint!("  Select [1/2/3]: ");
    io::stderr().flush().ok();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }

    let industry = match line.trim() {
        "1" | "finance" => "finance",
        "2" | "saas" => "saas",
        _ => {
            eprintln!();
            eprintln!("  Skipped. To set up later:");
            eprintln!("    \x1b[36mgvm init --industry saas\x1b[0m");
            eprintln!();
            return false;
        }
    };

    // Find template directory relative to the executable or CWD
    let template_candidates = [
        format!("config/templates/{}", industry),
        // If running from target/release or target/debug, look up
        format!("../../config/templates/{}", industry),
    ];

    let template_dir = template_candidates
        .iter()
        .find(|p| Path::new(p).exists())
        .cloned();

    let Some(template_dir) = template_dir else {
        eprintln!();
        eprintln!("  \x1b[31mTemplate directory not found.\x1b[0m");
        eprintln!(
            "  Run from repo root, or use: \x1b[36mgvm init --industry {}\x1b[0m",
            industry
        );
        eprintln!();
        return false;
    };

    let config_dir = Path::new("config");
    let template_path = Path::new(&template_dir);

    // Create config directory
    if let Err(e) = std::fs::create_dir_all(config_dir.join("policies")) {
        eprintln!("  \x1b[31mFailed to create config directory: {}\x1b[0m", e);
        return false;
    }

    // Copy template files
    let files_to_copy = [
        "proxy.toml",
        "srr_network.toml",
        "operation_registry.toml",
        "policies/global.toml",
    ];

    let mut copied = 0;
    for file in &files_to_copy {
        let src = template_path.join(file);
        let dst = config_dir.join(file);
        if src.exists() {
            // Never overwrite existing config — prevents accidental policy downgrade
            if dst.exists() {
                eprintln!("  \x1b[33m⊘\x1b[0m {} (exists, skipped)", file);
                continue;
            }
            if let Err(e) = std::fs::copy(&src, &dst) {
                eprintln!("  \x1b[31mFailed to copy {}: {}\x1b[0m", file, e);
                continue;
            }
            eprintln!("  \x1b[32m✓\x1b[0m {}", file);
            copied += 1;
        }
    }

    // Create empty secrets.toml if missing
    let secrets_path = config_dir.join("secrets.toml");
    if !secrets_path.exists() {
        let _ = std::fs::write(
            &secrets_path,
            "# API credentials — add your keys here\n# See secrets.toml.example for format\n",
        );
        eprintln!("  \x1b[32m✓\x1b[0m secrets.toml \x1b[2m(empty — add API keys later)\x1b[0m");
        copied += 1;
    }

    eprintln!();
    if copied > 0 {
        eprintln!(
            "  \x1b[1m\x1b[32m{} template applied ({} files)\x1b[0m",
            industry, copied
        );
        eprintln!("  Starting proxy with {} configuration...", industry);
        eprintln!();
        true
    } else {
        eprintln!("  \x1b[33mNo files copied. Check template directory.\x1b[0m");
        std::process::exit(1);
    }
}

/// Check if stderr is a terminal (for interactive prompt detection).
/// Returns false in CI, piped environments, or when running as a service.
fn atty_is_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stderr())
}
