//! Shared helpers for integration tests.
//!
//! Integration tests that need an `AppState` historically duplicated ~30
//! lines of field initialization at every call site (11+ occurrences in
//! `tests/integration.rs` alone). Adding a new field to `AppState`
//! requires touching every one of them, and the fix-up is silent
//! (type-checker accepts `..Default::default()` only if `Default` is
//! derived, which isn't the case here because most fields are service
//! handles that cannot have a meaningful default).
//!
//! [`test_state`] centralises this. Tests that only need one or two
//! specific fields still write:
//!
//! ```ignore
//! let state = common::test_state_with_srr(my_srr).await;
//! ```
//!
//! Tests that need to tweak fields do so via struct-update syntax on
//! the returned value (all fields are `pub`, so this works).

#![allow(dead_code)]

use std::sync::Arc;

use gvm_proxy::api_keys::APIKeyStore;
use gvm_proxy::ledger::Ledger;
use gvm_proxy::proxy::AppState;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::token_budget::TokenBudget;
use gvm_proxy::vault::Vault;

/// Build an `AppState` suitable for integration tests. All fields are
/// initialised to inert defaults:
/// - Empty in-memory SRR (no rules)
/// - Empty credential store
/// - Fresh WAL in a temp file (path returned via the second tuple slot)
/// - No MITM, no DNS governance, no JWT, no host overrides
/// - `tls_ready = true` so handlers gated on TLS readiness don't stall
///
/// Override specific fields with struct-update syntax. Example:
/// ```ignore
/// let (mut state, _wal) = common::test_state().await;
/// state.srr = my_custom_srr;
/// ```
///
/// Returns (state, wal_path). Caller keeps the `PathBuf` alive for the
/// lifetime of the test so the tempfile isn't garbage-collected; once
/// the test ends the temp dir is cleaned up automatically.
pub async fn test_state() -> (AppState, std::path::PathBuf) {
    let wal_path =
        std::env::temp_dir().join(format!("gvm-test-{}.wal", uuid::Uuid::new_v4()));

    // Write an empty TOML file and parse it — this matches what all
    // existing integration tests did inline, and keeps NetworkSRR's
    // only constructor (`load`) as the single entry point.
    let empty_srr_path = std::env::temp_dir()
        .join(format!("gvm-test-srr-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(&empty_srr_path, "").expect("write empty srr file");
    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&empty_srr_path).expect("empty SRR must parse"),
    ));
    let _ = std::fs::remove_file(&empty_srr_path);
    let api_keys = Arc::new(APIKeyStore::from_map(std::collections::HashMap::new()));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("test ledger must initialize"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("test vault"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,
        api_keys,
        ledger,
        vault,
        token_budget,
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),
        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: wal_path.to_string_lossy().into_owned(),
        active_integrity_ref: Arc::new(std::sync::RwLock::new(None)),
    };

    (state, wal_path)
}

/// Shorthand: `test_state()` but with a caller-provided SRR already
/// installed. For the most common test shape where the point of the
/// test is "SRR with these rules — does enforcement do X."
pub async fn test_state_with_srr(srr: NetworkSRR) -> (AppState, std::path::PathBuf) {
    let (mut state, wal) = test_state().await;
    state.srr = Arc::new(std::sync::RwLock::new(srr));
    (state, wal)
}
