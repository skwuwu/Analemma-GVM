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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use gvm_proxy::api_keys::APIKeyStore;
use gvm_proxy::ledger::Ledger;
use gvm_proxy::proxy::AppState;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::token_budget::TokenBudget;
use gvm_proxy::vault::Vault;

/// RAII guard for a temporary WAL file used by integration tests.
///
/// The previous design returned a bare `PathBuf` and assumed callers
/// would keep it alive, but `PathBuf` is just a string — it has no
/// `Drop` that removes the file. Result: every `cargo test` run leaked
/// `gvm-test-{uuid}.wal` files into `std::env::temp_dir()`. After
/// enough runs that's thousands of orphans (we observed 1185 on the
/// EC2 test instance). This struct fixes the leak by holding a
/// `tempfile::TempDir` whose `Drop` recursively deletes everything.
///
/// Callers that need the WAL path can pass `&TestWal` anywhere a
/// `&Path` is expected (`Deref<Target=Path>` + `AsRef<Path>` are
/// implemented), or read `wal.path` directly for a `PathBuf`.
pub struct TestWal {
    pub path: PathBuf,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for TestWal {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TestWal {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

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
/// Returns (state, wal). The `TestWal` guard auto-deletes its temp
/// directory (and the WAL inside) when dropped at the end of the test.
/// Callers that don't read the WAL can bind it to `_wal` — the guard
/// still runs.
pub async fn test_state() -> (AppState, TestWal) {
    // Install rustls CryptoProvider once per test process. The proxy's
    // `tls_proxy::build_server_config` panics without it; production
    // installs in main.rs. Idempotent: `install_default` returns Err
    // on re-install which we deliberately ignore.
    static RUSTLS_INIT: std::sync::Once = std::sync::Once::new();
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    // Single temp dir owns both the WAL file and the throwaway SRR
    // bootstrap file. When the returned TestWal drops, the dir's
    // recursive removal takes everything with it.
    let dir = tempfile::Builder::new()
        .prefix("gvm-test-")
        .tempdir()
        .expect("test tempdir must create");
    let wal_path = dir.path().join("wal.log");
    let empty_srr_path = dir.path().join("empty-srr.toml");

    // Write an empty TOML file and parse it — this matches what all
    // existing integration tests did inline, and keeps NetworkSRR's
    // only constructor (`load`) as the single entry point.
    std::fs::write(&empty_srr_path, "").expect("write empty srr file");
    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&empty_srr_path).expect("empty SRR must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::from_map(std::collections::HashMap::new()));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("test ledger must initialize"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("test vault"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let per_agent_budgets = Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,
        api_keys,
        ledger,
        vault,
        token_budget,
        per_agent_budgets,
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
        ca_registry: Arc::new(gvm_sandbox::ca::CARegistry::new()),
        per_sandbox_tls: Arc::new(dashmap::DashMap::new()),
        per_sandbox_metadata: Arc::new(dashmap::DashMap::new()),
        policy_link_template: None,
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

    (
        state,
        TestWal {
            path: wal_path,
            _dir: dir,
        },
    )
}

/// Shorthand: `test_state()` but with a caller-provided SRR already
/// installed. For the most common test shape where the point of the
/// test is "SRR with these rules — does enforcement do X."
pub async fn test_state_with_srr(srr: NetworkSRR) -> (AppState, TestWal) {
    let (mut state, wal) = test_state().await;
    state.srr = Arc::new(std::sync::RwLock::new(srr));
    (state, wal)
}
