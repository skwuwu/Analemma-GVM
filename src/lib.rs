// Library entry point — exposes modules for integration tests.
// The binary entry point remains in main.rs.

pub mod api;
pub mod api_keys;
pub mod auth;
pub mod checkpoint;
pub mod config;
pub mod dns_governance;
pub mod enforcement;
pub mod intent_store;
pub mod ledger;
pub mod llm_trace;
pub mod merkle;
pub mod operation;
pub mod proof;
pub mod proxy;
pub mod sign;
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

/// Public helpers that exist solely so integration tests can drive
/// proxy-internal behavior. Production code does not consume this
/// module — every entry point delegates to the same `pub(super)`
/// helper used by the live request path, so the tests are exercising
/// the same code, not a parallel implementation.
pub mod test_helpers {
    /// Test re-export of `proxy::responses::build_policy_link`.
    /// Pure function; no I/O, no AppState dependency.
    pub fn build_policy_link_for_test(
        template: Option<&str>,
        matched_rule_id: Option<&str>,
    ) -> Option<String> {
        crate::proxy::responses_for_test::build_policy_link(template, matched_rule_id)
    }
}
