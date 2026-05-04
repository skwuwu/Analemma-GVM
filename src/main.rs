use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use gvm_proxy::api;
use gvm_proxy::api_keys::APIKeyStore;
use gvm_proxy::auth;
use gvm_proxy::config::{self, ProxyConfig};
use gvm_proxy::dns_governance;
use gvm_proxy::ledger::Ledger;
use gvm_proxy::proxy::{proxy_handler, AppState};
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::token_budget::TokenBudget;
use gvm_proxy::vault::Vault;
#[cfg(feature = "wasm")]
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

    tracing::info!(
        "Analemma GVM Proxy v{} starting...",
        env!("CARGO_PKG_VERSION")
    );

    // 1. Load configuration (tries GVM_CONFIG env, CWD, home dir, then defaults)
    let mut config = ProxyConfig::load_or_default();

    // 1.5. Try loading unified gvm.toml (takes priority over separate config files)
    let gvm_config = config::load_gvm_toml();
    let gvm_toml_path: Option<String> = if gvm_config.is_some() {
        // Determine which path was loaded (re-check candidates)
        let candidates = [
            std::env::var("GVM_TOML").ok(),
            Some("gvm.toml".to_string()),
            Some("config/gvm.toml".to_string()),
        ];
        candidates
            .into_iter()
            .flatten()
            .find(|c| Path::new(c).exists())
    } else {
        None
    };

    // 2. First-run detection: if config files are missing, offer interactive setup.
    //    After setup, reload config so template proxy.toml settings take effect.
    let srr_path_str = config.srr.network_file.clone();
    if gvm_config.is_none() && !Path::new(&srr_path_str).exists() && offer_first_run_setup() {
        // Template applied — reload config to pick up template's proxy.toml
        config = ProxyConfig::load_or_default();
    }
    let srr_path = Path::new(&config.srr.network_file);

    // 3. Load Network SRR rules — from gvm.toml if available, else from separate file.
    let mut srr = if let Some(ref gvm) = gvm_config {
        if !gvm.rules.is_empty() {
            match NetworkSRR::from_rule_configs(gvm.rules.clone()) {
                Ok(s) => {
                    tracing::info!(
                        rules = gvm.rules.len(),
                        "Network SRR rules loaded from gvm.toml"
                    );
                    s
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to compile SRR rules from gvm.toml");
                    eprintln!();
                    eprintln!("  ERROR: gvm.toml contains invalid SRR rules.");
                    eprintln!("  Error: {}", e);
                    eprintln!();
                    std::process::exit(1);
                }
            }
        } else {
            // gvm.toml exists but has no rules — try legacy file
            match NetworkSRR::load(srr_path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "No rules in gvm.toml and legacy SRR file failed — starting with empty rules");
                    NetworkSRR::from_rule_configs(vec![]).unwrap_or_else(|_| {
                        eprintln!("  FATAL: Cannot create empty SRR engine");
                        std::process::exit(1);
                    })
                }
            }
        }
    } else {
        match NetworkSRR::load(srr_path) {
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
                eprintln!("    Create a gvm.toml in the working directory.");
                eprintln!("    Or run: gvm init --industry saas");
                eprintln!();
                std::process::exit(1);
            }
        }
    };

    // 3.5. Apply configurable Default-to-Caution policy for unmatched URLs
    // GVM_DEFAULT_UNKNOWN env var overrides proxy.toml (set by `gvm run --default-policy`)
    let default_unknown_setting = std::env::var("GVM_DEFAULT_UNKNOWN")
        .unwrap_or_else(|_| config.enforcement.default_unknown.clone());
    let default_unknown_decision = match default_unknown_setting.as_str() {
        "require_approval" => {
            tracing::info!(
                "Default-to-Caution: RequireApproval (unmatched URLs held for human approval)"
            );
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
            tracing::info!(
                delay_ms = ms,
                "Default-to-Caution: Delay (unmatched URLs delayed then forwarded)"
            );
            gvm_types::EnforcementDecision::Delay { milliseconds: ms }
        }
    };
    srr.set_default_decision(default_unknown_decision);

    // 4. Load API key store — from gvm.toml if available, else from secrets.toml.
    let api_keys = if let Some(ref gvm) = gvm_config {
        if !gvm.credentials.is_empty() {
            tracing::info!(
                count = gvm.credentials.len(),
                "API credentials loaded from gvm.toml"
            );
            APIKeyStore::from_map(gvm.credentials.clone())
        } else {
            // gvm.toml exists but no credentials — try legacy file
            match APIKeyStore::load(Path::new(&config.secrets.file)) {
                Ok(keys) => keys,
                Err(e) => {
                    tracing::warn!(error = %e, "No credentials in gvm.toml and legacy secrets file failed");
                    APIKeyStore::default()
                }
            }
        }
    } else {
        match APIKeyStore::load(Path::new(&config.secrets.file)) {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %config.secrets.file,
                    "Failed to load API key store — starting with empty store. \
                     Layer 3 (API key isolation) is INACTIVE."
                );
                APIKeyStore::default()
            }
        }
    };

    // 4.5. Override budget from gvm.toml if present
    if let Some(ref gvm) = gvm_config {
        // Only override if the gvm.toml budget has non-default values
        if gvm.budget.max_tokens_per_hour > 0 || gvm.budget.max_cost_per_hour > 0.0 {
            config.budget = gvm.budget.clone();
            tracing::info!("Budget configuration loaded from gvm.toml");
        }
    }

    // 4.6. Override filesystem policy from gvm.toml if present
    if let Some(ref gvm) = gvm_config {
        if gvm.filesystem.is_some() {
            config.filesystem = gvm.filesystem.clone();
            tracing::info!("Filesystem policy loaded from gvm.toml");
        }
    }
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
        Path::new(&std::env::var("GVM_WAL_PATH").unwrap_or_else(|_| config.wal.path.clone())),
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

    let active_integrity_ref: Arc<std::sync::RwLock<Option<String>>> =
        Arc::new(std::sync::RwLock::new(None));

    // 7.5a. Verify integrity chain from previous sessions
    {
        let wal_path_str =
            std::env::var("GVM_WAL_PATH").unwrap_or_else(|_| config.wal.path.clone());
        let wal_file = std::path::Path::new(&wal_path_str);
        let (valid, first_break) = Ledger::check_chain_integrity(wal_file);
        if let Some(ref broken_at) = first_break {
            tracing::warn!(
                valid_links = valid,
                broken_at = %broken_at,
                "Integrity chain break detected — config history may have been tampered with"
            );
        } else if valid > 0 {
            tracing::info!(valid_links = valid, "Integrity chain verified");
        }
    }

    // 7.5b. Record config file hashes in Merkle chain (tamper detection)
    {
        let mut all_config_files: Vec<(String, std::path::PathBuf)> = Vec::new();

        if let Some(ref gvm_path) = gvm_toml_path {
            all_config_files.push(("gvm_toml".to_string(), std::path::PathBuf::from(gvm_path)));
        } else {
            all_config_files.push(("srr_network".to_string(), srr_path.to_path_buf()));
        }

        let config_refs: Vec<(&str, &Path)> = all_config_files
            .iter()
            .map(|(label, path)| (label.as_str(), path.as_path()))
            .collect();

        match ledger.record_config_load(&config_refs, None).await {
            Ok(hash) => {
                tracing::info!(context_hash = %hash, "Integrity context recorded");
                if let Ok(mut guard) = active_integrity_ref.write() {
                    *guard = Some(hash);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to record integrity context in WAL");
            }
        }
    }

    // 8. Initialize Vault (encrypted state store)
    let vault = Vault::new(ledger.clone()).expect("Failed to initialize vault");
    tracing::info!("Vault initialized");

    // 8.5. Initialize Wasm Governance Engine (Layer 1: Immutable Logic)
    // Wasm engine is behind --features wasm (disabled by default).
    // Native Rust policy evaluation is used in default builds.
    #[cfg(feature = "wasm")]
    let wasm_engine = {
        let engine = WasmEngine::load(Path::new("data/gvm_engine.wasm"))
            .expect("Failed to initialize Wasm engine");
        if engine.is_wasm() {
            tracing::info!(
                hash = %engine.module_hash.as_deref().unwrap_or("unknown"),
                "Layer 1: Wasm governance engine ACTIVE (immutable sandbox)"
            );
        } else {
            tracing::info!("Layer 1: Using native policy engine (Wasm module not loaded)");
        }
        engine
    };
    #[cfg(not(feature = "wasm"))]
    tracing::info!("Layer 1: Native policy engine (Wasm disabled — enable with --features wasm)");

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

    // 9.9. Generate the legacy fallback MITM CA in RAM (CA-5).
    //
    // Used for any MITM CONNECT whose peer was NOT provisioned via
    // `POST /gvm/sandbox/launch` (CA-3) — i.e. older launch paths,
    // cooperative-loopback, etc. Per-sandbox flows get their own
    // `SandboxCA` from `CARegistry` and never touch this one.
    //
    // The keypair lives in proxy memory only; CA-5 dropped the
    // `data/mitm-ca-key.pem` persistence because keeping a
    // long-lived shared CA's key on disk is a larger blast radius
    // than a restart-induced trust break. Sandboxes that need to
    // survive proxy restart must use the per-sandbox flow.
    let mitm_ca = gvm_sandbox::ca::EphemeralCA::generate().expect("Failed to generate MITM CA");
    let mitm_ca_cert_pem = Arc::new(mitm_ca.ca_cert_pem().to_vec());
    let mitm_ca_key_pem = Arc::new(mitm_ca.ca_key_pem());
    // Snapshot CA validity for `/gvm/health` (consumed by `gvm status`).
    // Captured here because mitm_ca is dropped at end-of-scope after key extraction.
    let mitm_ca_expires_days: Option<i64> = Some(mitm_ca.expires_in_days());

    // 9.10. Pre-build MITM TLS state (shared between port-8443 listener and CONNECT handler).
    // Single GvmCertResolver instance → single cert cache → no duplicate keygen.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mitm_resolver = Arc::new(
        gvm_proxy::tls_proxy::GvmCertResolver::new(&mitm_ca_cert_pem, &mitm_ca_key_pem)
            .expect("Failed to create MITM cert resolver"),
    );
    let mitm_server_config = Arc::new(
        gvm_proxy::tls_proxy::build_server_config(mitm_resolver.clone())
            .expect("Failed to build MITM server config"),
    );
    let mitm_client_config = Arc::new(
        gvm_proxy::tls_proxy::build_client_config().expect("Failed to build MITM client config"),
    );

    // 10. Print startup policy summary
    print_startup_summary(&srr, &api_keys);

    // 11. Compose shared state
    let mut state = AppState {
        srr: Arc::new(std::sync::RwLock::new(srr)),
        api_keys: Arc::new(api_keys),
        ledger,
        vault: Arc::new(vault),
        token_budget: Arc::new(TokenBudget::new(
            config.budget.max_tokens_per_hour,
            config.budget.max_cost_per_hour,
            config.budget.reserve_per_request,
        )),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(
            config.budget.per_agent_max_tokens_per_hour,
            config.budget.per_agent_max_cost_per_hour,
            config.budget.reserve_per_request,
        )),
        #[cfg(feature = "wasm")]
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
        gvm_toml_path: gvm_toml_path.clone(),
        mitm_ca_pem: Some(mitm_ca_cert_pem.clone()),
        ca_registry: Arc::new(gvm_sandbox::ca::CARegistry::new()),
        per_sandbox_tls: Arc::new(dashmap::DashMap::new()),
        per_sandbox_metadata: Arc::new(dashmap::DashMap::new()),
        payload_inspection: config.srr.payload_inspection,
        max_body_bytes: config.srr.max_body_bytes,
        pending_approvals: Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: config.enforcement.ic3_approval_timeout_secs,
        mitm_resolver: Some(mitm_resolver.clone()),
        mitm_server_config: Some(mitm_server_config.clone()),
        mitm_client_config: Some(mitm_client_config.clone()),
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
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: mitm_ca_expires_days,
        dns_governance: None, // populated below if enabled
        wal_path: std::env::var("GVM_WAL_PATH").unwrap_or_else(|_| config.wal.path.clone()),
        active_integrity_ref: active_integrity_ref.clone(),
    };

    // 11a. DNS governance proxy (Delay-Alert, no Deny)
    let dns_governance_enabled = config.dns.enabled
        && std::env::var("GVM_NO_DNS_GOVERNANCE")
            .map(|v| v != "1")
            .unwrap_or(true);

    if dns_governance_enabled {
        // Build known_hosts set from SRR for free-pass tier
        let known_set: std::collections::HashSet<String> = state
            .srr
            .read()
            .map(|srr| srr.known_hosts().into_iter().collect())
            .unwrap_or_default();
        let known_hosts = Arc::new(std::sync::RwLock::new(known_set));
        // Read sliding-window from config (clamped at 5s minimum inside
        // DnsGovernance::with_window_secs to keep Tier 3 detection
        // meaningful — see DnsGovernanceConfig::window_secs doc).
        let dns_gov = Arc::new(dns_governance::DnsGovernance::with_window_secs(
            known_hosts,
            config.dns.window_secs,
        ));
        state.dns_governance = Some(dns_gov.clone());

        // Bind to 0.0.0.0 (all interfaces) instead of 127.0.0.1.
        // The sandbox's iptables PREROUTING DNAT rewrites packets arriving
        // on the host-side veth to the DNS proxy. If the proxy binds to
        // 127.0.0.1, those DNAT'd packets are dropped because
        // route_localnet=0 (kernel default, and we don't change it —
        // enabling route_localnet opens a class of SSRF attacks). Binding
        // to 0.0.0.0 lets the proxy receive packets on any interface,
        // including the host-side veth.
        let dns_listen: std::net::SocketAddr = format!("0.0.0.0:{}", config.dns.listen_port)
            .parse()
            .unwrap();
        let dns_upstream = gvm_proxy::dns_governance::resolve_upstream_dns();
        let dns_ledger = state.ledger.clone();

        tokio::spawn(async move {
            if let Err(e) =
                dns_governance::run_dns_proxy(dns_listen, dns_upstream, dns_gov, dns_ledger).await
            {
                tracing::error!(error = %e, "DNS governance proxy exited with error");
            }
        });

        // Tell the sandbox DNAT setup where to redirect DNS queries.
        // network.rs reads GVM_DNS_LISTEN to decide the DNAT target.
        std::env::set_var("GVM_DNS_LISTEN", dns_listen.to_string());

        tracing::info!(
            listen = %dns_listen,
            upstream = %dns_upstream,
            "DNS governance proxy enabled (Delay-Alert, no Deny)"
        );
    } else {
        // Clear so sandbox falls back to upstream resolver
        std::env::remove_var("GVM_DNS_LISTEN");
        tracing::info!("DNS governance disabled (--no-dns-governance or dns.enabled=false)");
    }

    // Clone state for CONNECT handler before moving into axum router
    let connect_state = state.clone();

    // 11. Build two separate routers:
    //     - Agent-facing (proxy port): proxy handler + agent-safe endpoints only
    //     - Admin (admin port): privileged endpoints (approve, reload, info)
    //
    // This separation prevents a sandboxed agent from calling /gvm/approve to
    // self-approve IC-3 requests. The agent only knows the proxy port.

    // Agent-facing router: proxy + safe endpoints (health, check, info, vault, ca.pem)
    // /gvm/info is read-only (GET) so safe on agent port. MCP server needs it.
    // /gvm/reload is also on agent port but restricted to loopback (127.0.0.1) only.
    // Sandbox agents come from 10.200.x.x and cannot reach it.
    // /gvm/approve remains admin-only (IC-3 self-approval prevention).
    let app = Router::new()
        .route("/gvm/health", axum::routing::get(api::health))
        .route("/gvm/info", axum::routing::get(api::info))
        .route(
            "/gvm/reload",
            axum::routing::post(reload_srr_localhost_only),
        )
        .route("/gvm/check", axum::routing::post(api::check))
        .route("/gvm/intent", axum::routing::post(api::register_intent))
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
        .with_state(state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::new())
                .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
                .layer(tower::limit::ConcurrencyLimitLayer::new(1024)),
        );

    // Admin router: privileged endpoints only (not reachable from agent network)
    let admin_app = Router::new()
        .route("/gvm/health", axum::routing::get(api::health))
        .route("/gvm/info", axum::routing::get(api::info))
        .route("/gvm/pending", axum::routing::get(api::pending_approvals))
        .route("/gvm/approve", axum::routing::post(api::approve_request))
        .route("/gvm/reload", axum::routing::post(api::reload_srr))
        .route("/gvm/dashboard", axum::routing::get(api::dashboard))
        .route(
            "/gvm/dashboard/events",
            axum::routing::get(api::dashboard_events),
        )
        .route(
            "/gvm/dashboard/stats",
            axum::routing::get(api::dashboard_stats),
        )
        // Per-sandbox MITM CA (CA-3). Admin-only — sandbox launch is
        // operator-initiated. The CLI calls these to provision a CA
        // before a sandbox spawns and to revoke it on exit.
        .route(
            "/gvm/sandbox/launch",
            axum::routing::post(api::sandbox_launch),
        )
        // CA-7 list endpoint registered BEFORE the :sandbox_id routes
        // so axum's matchit doesn't accidentally route GET /gvm/sandbox
        // through the parameterized path.
        .route("/gvm/sandbox", axum::routing::get(api::sandbox_list))
        .route(
            "/gvm/sandbox/:sandbox_id/ca.pem",
            axum::routing::get(api::sandbox_ca_pem),
        )
        .route(
            "/gvm/sandbox/:sandbox_id",
            axum::routing::delete(api::sandbox_revoke),
        )
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::new())
                .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024)),
        );

    // 12. Start server with CONNECT tunnel support
    // Use TcpSocket with SO_REUSEADDR so the proxy can restart immediately
    // after a crash without waiting for TIME_WAIT to expire.
    //
    // GVM Code Standard §2.3: required configuration must cause startup
    // failure. Silently falling back to a hard-coded address would open a
    // different port than the operator configured, which is a fail-open
    // behavior. Refuse to start instead.
    let listen_addr: std::net::SocketAddr = config.server.listen.parse().unwrap_or_else(|e| {
        eprintln!(
            "Fatal: invalid server.listen `{}`: {} — fix proxy config and restart",
            config.server.listen, e
        );
        std::process::exit(1);
    });
    let socket = tokio::net::TcpSocket::new_v4().expect("Failed to create TCP socket");
    socket
        .set_reuseaddr(true)
        .expect("Failed to set SO_REUSEADDR");
    socket.bind(listen_addr).unwrap_or_else(|e| {
        eprintln!("Fatal: cannot bind to {listen_addr}: {e}");
        std::process::exit(1);
    });
    let listener = socket.listen(1024).unwrap_or_else(|e| {
        eprintln!("Fatal: listen on {listen_addr} failed: {e}");
        std::process::exit(1);
    });

    tracing::info!(address = %config.server.listen, "GVM Proxy listening (HTTP)");

    // 12.5. Start admin API listener on a separate port (not reachable by agent)
    let admin_addr = config.server.admin_listen.clone();
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(&admin_addr).await {
            Ok(admin_listener) => {
                tracing::info!(address = %admin_addr, "GVM Admin API listening (privileged)");
                loop {
                    if let Ok((stream, _)) = admin_listener.accept().await {
                        let app = admin_app.clone();
                        tokio::spawn(async move {
                            let service = hyper::service::service_fn(move |req| {
                                let app = app.clone();
                                async move {
                                    Ok::<_, std::convert::Infallible>(
                                        tower::ServiceExt::oneshot(app, req).await.unwrap_or_else(
                                            |_| {
                                                axum::http::Response::builder()
                                                    .status(500)
                                                    .body(axum::body::Body::from("Internal error"))
                                                    .unwrap_or_default()
                                            },
                                        ),
                                    )
                                }
                            });
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await
                            {
                                tracing::debug!(error = %e, "Admin connection error");
                            }
                        });
                    }
                }
            }
            Err(e) => {
                tracing::error!(address = %admin_addr, error = %e, "Failed to bind admin API listener");
            }
        }
    });

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
    let tls_ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let tls_ready_tx = tls_ready.clone();
    tokio::spawn(async move {
        if let Err(e) = start_tls_listener(
            &tls_port,
            tls_state,
            &tls_ca_cert,
            &tls_ca_key,
            tls_ready_tx,
        )
        .await
        {
            tracing::warn!(error = %e, "TLS MITM listener failed to start (sandbox HTTPS inspection unavailable)");
        }
    });
    // Wait for TLS listener to bind (up to 5s) before accepting HTTP connections.
    // Sandbox DNAT redirects port 443→8443, so the listener must be ready.
    tokio::select! {
        _ = tls_ready.notified() => {
            tracing::debug!("TLS MITM listener ready");
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            tracing::warn!("TLS MITM listener not ready after 5s — continuing without HTTPS inspection");
        }
    }

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

    // Raise FD limit to support high connection counts.
    // Default ulimit (1024) is too low for proxy + MITM (each request uses 2-4 FDs).
    #[cfg(unix)]
    {
        let target_nofile = 65536;
        let rlim = libc::rlimit {
            rlim_cur: target_nofile,
            rlim_max: target_nofile,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) == 0 {
                tracing::info!(nofile = target_nofile, "FD limit raised");
            } else {
                // Try soft limit only (may not have permission for hard limit)
                let mut current = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::getrlimit(libc::RLIMIT_NOFILE, &mut current);
                let soft = libc::rlimit {
                    rlim_cur: current.rlim_max,
                    rlim_max: current.rlim_max,
                };
                libc::setrlimit(libc::RLIMIT_NOFILE, &soft);
                tracing::info!(nofile = current.rlim_max, "FD limit raised to hard limit");
            }
        }
    }

    loop {
        // Aggressively clean up finished handles to prevent FD leak
        if connection_handles.len() > 256 {
            connection_handles.retain(|h| !h.is_finished());
        }

        tokio::select! {
            conn = listener.accept() => {
                match conn {
                    Ok((stream, addr)) => {
                        let app = app_for_connect.clone();
                        let cs = state_for_connect.clone();
                        let peer_ip = addr.ip();
                        let handle = tokio::spawn(async move {
                            serve_connection(stream, app, cs, peer_ip).await;
                        });
                        connection_handles.push(handle);
                    }
                    Err(e) => {
                        // EMFILE (too many open files): clean up handles and pause briefly
                        let err_str = format!("{}", e);
                        if err_str.contains("Too many open files") || err_str.contains("os error 24") {
                            connection_handles.retain(|h| !h.is_finished());
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                        tracing::error!(error = %e, active = connection_handles.len(), "Accept failed");
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
            futures_util::future::join_all(connection_handles.iter_mut().map(|h| async {
                h.await.ok();
            })),
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
                let remaining = connection_handles
                    .iter()
                    .filter(|h| !h.is_finished())
                    .count();
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

    // Phase 3: Zeroize CA key material + Flush WAL
    // Zeroize the CA private key PEM before dropping — defense-in-depth against
    // memory forensics. The Arc may have multiple references, so we zeroize our copy.
    {
        use zeroize::Zeroize;
        if let Some(mut key_bytes) = Arc::into_inner(mitm_ca_key_pem) {
            key_bytes.zeroize();
            tracing::debug!("MITM CA key PEM zeroized on shutdown");
        }
        // mitm_ca_key_pem is consumed; other Arc clones (TLS listener) will be
        // zeroized when their tasks are aborted above.
    }

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
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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

/// Reload SRR rules — allowed on agent port only from loopback (127.0.0.1).
/// Sandbox agents (10.200.x.x) cannot trigger reloads. MCP server (localhost) can.
/// This prevents agents from modifying their own governance rules while allowing
/// the MCP server (which runs on the same host) to hot-reload rulesets.
async fn reload_srr_localhost_only(
    axum::extract::State(state): axum::extract::State<gvm_proxy::proxy::AppState>,
    request: Request<Body>,
) -> Response<Body> {
    let peer_ip = request.extensions().get::<std::net::IpAddr>().copied();
    let is_loopback = peer_ip.is_some_and(|ip| ip.is_loopback());

    if !is_loopback {
        tracing::warn!(
            peer = ?peer_ip,
            "Reload attempt from non-loopback address blocked (use admin port 9090)"
        );
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":"Reload only allowed from localhost. Use admin port for remote access."}"#,
            ))
            .unwrap_or_else(|_| {
                // SAFETY (logical): builder above uses static literals only,
                // so this fallback is unreachable in practice. Standard §1.2
                // forbids unwrap()/expect() on runtime paths regardless, so
                // we return an empty 403 rather than panic.
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::empty())
                    .unwrap_or_else(|_| Response::new(Body::empty()))
            });
    }

    api::reload_srr(axum::extract::State(state)).await
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    app: axum::Router,
    state: gvm_proxy::proxy::AppState,
    peer_ip: std::net::IpAddr,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        // Pass peer IP to handlers via request extensions
        req.extensions_mut().insert(peer_ip);
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
            .unwrap_or_default()
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
const _UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// TLS MITM listener for sandbox HTTPS inspection.
///
/// Accepts TLS connections on port 8443, terminates TLS using the ephemeral CA,
/// inspects the plaintext HTTP request, applies SRR policy, and forwards to upstream.
async fn start_tls_listener(
    listen_addr: &str,
    state: gvm_proxy::proxy::AppState,
    _ca_cert_pem: &[u8],
    _ca_key_pem: &[u8],
    ready: std::sync::Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    // Reuse the shared MITM resolver/configs from AppState (initialized in main).
    // Single cert cache instance shared with CONNECT handler.
    let resolver = state
        .mitm_resolver
        .clone()
        .ok_or_else(|| anyhow::anyhow!("MITM resolver not initialized"))?;
    let server_config = state
        .mitm_server_config
        .clone()
        .ok_or_else(|| anyhow::anyhow!("MITM server config not initialized"))?;
    let client_config = state
        .mitm_client_config
        .clone()
        .ok_or_else(|| anyhow::anyhow!("MITM client config not initialized"))?;

    // Semaphore: bound concurrent TLS connections to prevent FD exhaustion.
    let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_TLS_CONNECTIONS));

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(address = %listen_addr, "GVM TLS MITM proxy listening");

    // Pre-warm MITM cert cache for known domains (SRR hosts + secrets hosts).
    // Without this, the first TLS connection to a new domain blocks on keygen
    // (~1-5ms per cert) and fast-retrying clients (OpenClaw, Node.js) may
    // timeout before the cert is ready — causing "connection error" on startup.
    {
        let srr_hosts = state
            .srr
            .read()
            .map(|s| s.known_hosts())
            .unwrap_or_default();
        let secret_hosts: Vec<String> = state
            .api_keys
            .known_hosts()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let mut all_hosts: Vec<String> = srr_hosts;
        all_hosts.extend(secret_hosts);
        all_hosts.sort();
        all_hosts.dedup();
        if !all_hosts.is_empty() {
            tracing::info!(
                count = all_hosts.len(),
                "Pre-warming MITM cert cache for known domains"
            );
            for host in &all_hosts {
                resolver.ensure_cached(host.clone()).await;
            }
            tracing::info!("MITM cert cache pre-warmed");
        }
        state
            .tls_ready
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    ready.notify_one();

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
                // Debug level: intermittent handshake failures are normal
                // (client connection resets, retries). Not actionable as warnings.
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
    use gvm_proxy::tls_proxy::peek_sni;
    use tokio_rustls::TlsAcceptor;

    // Capture the peer's IP BEFORE moving the stream into the
    // acceptor — needed by Phase B (CA-6 part 2) to resolve which
    // sandbox launch event should be the parent of every L7 event
    // emitted on this connection. Falls back to None on the rare
    // peer-address read failure (no anchor wired, agent_id stays
    // unverified — same as the legacy path).
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let sandbox_anchor = state.resolve_sandbox_anchor(peer_ip);

    // 1. Pre-warm cert cache: peek SNI from raw TCP, generate cert on blocking
    //    thread pool. This prevents CPU-bound keygen from starving tokio workers.
    //    We also keep the SNI string itself to pass to the MITM handler — it's
    //    the only authoritative source for the upstream host on this code path.
    //    Without it the handler falls back to the client's Host header, which
    //    inside a sandbox is the proxy's own veth IP, causing the upstream
    //    relay to connect back to itself and hang.
    let sni = peek_sni(&stream).await;
    if let Some(ref s) = sni {
        resolver.ensure_cached(s.clone()).await;
    }

    // 2. TLS handshake with timeout (SNI → cache hit from step 1)
    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;

    // 3-8. Shared MITM handler (read request, SRR check, enforce, forward, relay)
    let host_hint = sni.as_deref().unwrap_or("");
    gvm_proxy::tls_proxy::handle_mitm_stream(
        tls_stream,
        host_hint,
        client_config,
        &state,
        sandbox_anchor,
    )
    .await
}

/// Print a human-readable startup summary of loaded governance rules.
/// Helps operators verify that the correct policies are active before
/// traffic starts flowing through the proxy.
fn print_startup_summary(
    srr: &gvm_proxy::srr::NetworkSRR,
    api_keys: &gvm_proxy::api_keys::APIKeyStore,
) {
    let srr_info = srr.summary();

    eprintln!();
    eprintln!("  \x1b[1m\x1b[36m╔══════════════════════════════════════════╗\x1b[0m");
    eprintln!(
        "  \x1b[1m\x1b[36m║\x1b[0m   Analemma GVM — Governance Summary     \x1b[1m\x1b[36m║\x1b[0m"
    );
    eprintln!("  \x1b[1m\x1b[36m╚══════════════════════════════════════════╝\x1b[0m");
    eprintln!();

    // Network SRR rules
    eprintln!("  \x1b[1mNetwork SRR\x1b[0m");
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

    // API key isolation
    eprintln!("  \x1b[1mAPI Key Isolation\x1b[0m");
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
    eprintln!("  \x1b[2m│  Agent → [SRR check] → [API key inject]    │\x1b[0m");
    eprintln!("  \x1b[2m│         → Upstream                          │\x1b[0m");
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
    let files_to_copy = ["proxy.toml", "srr_network.toml", "policies/global.toml"];

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
