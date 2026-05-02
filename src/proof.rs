//! Phase 4 — `GvmProof` / `GvmBatchProof` builder.
//!
//! The builder + verifier live in `gvm-types::proof` so the CLI can
//! call them without depending on the proxy crate. This module is a
//! thin re-export plus a Phase-3 helper that bolts a per-step
//! `CheckpointInclusion` onto a built proof using a live
//! `CheckpointAggregator`.

pub use gvm_types::proof::{
    build_batch_proof, build_proof, generate_merkle_proof_path, ProofBuildError,
    DEFAULT_CONFIG_CHAIN_DEPTH,
};

use crate::checkpoint::CheckpointAggregator;
use anyhow::Result;
use gvm_types::{GvmProof, RedactionLevel};

/// Build a single-event proof and attach a `CheckpointInclusion` for
/// `(agent_id, step)` if the aggregator has it. The agent_id defaults
/// to the proof's event.agent_id so a typical caller can pass only
/// the step.
///
/// If the aggregator does not have the (agent, step) registered at
/// the time of the call, the proof is returned with
/// `checkpoint_inclusion: None` (degrades gracefully — verifier still
/// validates every other layer).
pub async fn build_proof_with_checkpoint(
    wal_path: &std::path::Path,
    event_id: &str,
    level: RedactionLevel,
    aggregator: &CheckpointAggregator,
    step: u32,
) -> Result<GvmProof> {
    let mut proof = build_proof(wal_path, event_id, level).map_err(|e| anyhow::anyhow!("{}", e))?;

    let agent_id = match &proof.event {
        gvm_types::GVMEventOrRedacted::Full(e) => e.agent_id.clone(),
        gvm_types::GVMEventOrRedacted::Redacted(r) => r.agent_id.clone(),
    };
    proof.checkpoint_inclusion = aggregator.proof(&agent_id, step).await;
    Ok(proof)
}
