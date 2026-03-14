// Library entry point — exposes modules for integration tests.
// The binary entry point remains in main.rs.

pub mod api;
pub mod api_keys;
pub mod config;
pub mod ledger;
pub mod policy;
pub mod proxy;
pub mod rate_limiter;
pub mod registry;
pub mod srr;
pub mod types;
pub mod vault;
pub mod wasm_engine;
