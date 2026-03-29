// Library entry point — exposes modules for integration tests.
// The binary entry point remains in main.rs.

pub mod api;
pub mod api_keys;
pub mod auth;
pub mod config;
pub mod intent_store;
pub mod ledger;
pub mod llm_trace;
pub mod merkle;
pub mod policy;
pub mod proxy;
pub mod rate_limiter;
pub mod registry;
pub mod srr;
pub mod tls_proxy;
pub mod types;
pub mod vault;
#[cfg(feature = "wasm")]
pub mod wasm_engine;
