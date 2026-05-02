//! Phase 4 — `GvmProof` / `GvmBatchProof` builder.
//!
//! The builder + verifier live in `gvm-types::proof` so the CLI can
//! call them without depending on the proxy crate. This module is a
//! thin re-export so existing callers in gvm-proxy and its tests can
//! continue to use `gvm_proxy::proof::build_proof(...)`.

pub use gvm_types::proof::{
    build_batch_proof, build_proof, generate_merkle_proof_path, ProofBuildError,
    DEFAULT_CONFIG_CHAIN_DEPTH,
};
