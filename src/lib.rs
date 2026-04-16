// Library entry point — exposes modules for integration tests.
// The binary entry point remains in main.rs.

pub mod api;
pub mod api_keys;
pub mod auth;
pub mod config;
pub mod dns_governance;
pub mod enforcement;
pub mod intent_store;
pub mod ledger;
pub mod llm_trace;
pub mod merkle;
pub mod proxy;
pub mod srr;
pub mod tls_proxy;
pub mod tls_proxy_hyper;
pub mod token_budget;
pub mod types;
pub mod vault;
/// Wasm policy engine — UNSUPPORTED EXPERIMENTAL FEATURE.
/// Disabled by default. The native Rust policy engine handles all enforcement.
/// Enabling adds ~10MB to binary + 5 wasmtime CVEs. For future third-party
/// policy plugin scenarios only. Do not enable in production.
#[cfg(feature = "wasm")]
pub mod wasm_engine;
