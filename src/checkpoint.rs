//! Phase 3 (full) — per-agent per-step checkpoint aggregator.
//!
//! Each agent owns an `AgentCheckpointTree` keyed by `step: u32`. The
//! global aggregator's root is computed over `(agent_id, agent_root)`
//! pairs and published into the ledger's `TripleState::checkpoint_root`
//! so the next batch's seal/anchor binds the live aggregator state.
//!
//! Compared to the v0.5.0 simpler aggregator (one leaf per agent),
//! this design lets the proof export emit a per-step inclusion path:
//!   - Per-agent path: step → agent_root.
//!   - Global path: agent_root → checkpoint_root.
//! Verifier composes them to reconstruct the seal's `checkpoint_root`.
//!
//! Last-write-wins per (agent, step). Memory is `O(distinct (agent,
//! step) pairs)` plus a small per-tree cached_root. The Merkle tree
//! is recomputed from the BTreeMap on every register — well under
//! 1ms for 1k agents × 100 steps on a modern CPU.
//!
//! Concurrency: writers serialize through a `tokio::sync::Mutex`. The
//! ledger update inside the locked section happens BEFORE the lock
//! is released so two concurrent updates cannot publish out of
//! insertion order.

use crate::ledger::Ledger;
use anyhow::Result;
use gvm_types::CheckpointInclusion;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-agent checkpoint tree keyed by step.
///
/// `cached_root` is a stale-on-write cache: it is recomputed on every
/// `set` so callers get the correct root from a single field read. For
/// pure proof callers, `proof()` recomputes from `leaves` on demand.
#[derive(Clone, Debug, Default)]
pub struct AgentCheckpointTree {
    pub leaves: BTreeMap<u32, [u8; 32]>,
    pub cached_root: Option<[u8; 32]>,
}

impl AgentCheckpointTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / overwrite the checkpoint hash at `step`. Recomputes
    /// `cached_root`. Returns the new root.
    pub fn set(&mut self, step: u32, hash: [u8; 32]) -> [u8; 32] {
        self.leaves.insert(step, hash);
        let root =
            gvm_types::compute_agent_checkpoint_root(&self.leaves).expect("non-empty after insert");
        self.cached_root = Some(root);
        root
    }

    /// Read the cached root, recomputing if it's stale.
    pub fn root(&self) -> Option<[u8; 32]> {
        if let Some(r) = self.cached_root {
            return Some(r);
        }
        gvm_types::compute_agent_checkpoint_root(&self.leaves)
    }

    /// Hex form of the root.
    pub fn root_hex(&self) -> Option<String> {
        self.root().map(hex::encode)
    }

    /// Generate an inclusion proof for `step`. Returns
    /// `(leaf_hex, path)` per `gvm_types::agent_checkpoint_proof`.
    pub fn proof(&self, step: u32) -> Option<(String, Vec<(String, bool)>)> {
        gvm_types::agent_checkpoint_proof(&self.leaves, step)
    }

    pub fn step_count(&self) -> usize {
        self.leaves.len()
    }
}

/// Live checkpoint aggregator. Cheap to clone (one `Arc`).
#[derive(Clone)]
pub struct CheckpointAggregator {
    inner: Arc<Mutex<Inner>>,
    ledger: Arc<Ledger>,
}

struct Inner {
    /// Per-agent trees. `BTreeMap` so iteration order matches the
    /// canonical sort that the global aggregator performs.
    agents: BTreeMap<String, AgentCheckpointTree>,
    /// Most recent published global root (hex). Cached so observers
    /// can read the last-known root without recomputing.
    last_root_hex: Option<String>,
}

impl CheckpointAggregator {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                agents: BTreeMap::new(),
                last_root_hex: None,
            })),
            ledger,
        }
    }

    /// Register a checkpoint hash for `(agent_id, step)`. Replaces any
    /// prior hash at the same (agent, step). Recomputes the per-agent
    /// root and the global aggregator root, then publishes the global
    /// root into the ledger's triple state.
    ///
    /// Returns the hex-encoded global aggregator root after the update.
    pub async fn register(
        &self,
        agent_id: &str,
        step: u32,
        checkpoint: [u8; 32],
    ) -> Result<String> {
        let mut inner = self.inner.lock().await;

        let entry = inner
            .agents
            .entry(agent_id.to_string())
            .or_default();
        entry.set(step, checkpoint);

        // Build the (agent_id, agent_root) leaf set for the global
        // aggregator — one entry per registered agent.
        let global_leaves: Vec<(String, [u8; 32])> = inner
            .agents
            .iter()
            .filter_map(|(id, tree)| tree.root().map(|r| (id.clone(), r)))
            .collect();

        let root_hex = gvm_types::compute_checkpoint_root_hex(&global_leaves)
            .expect("non-empty after register");

        inner.last_root_hex = Some(root_hex.clone());
        self.ledger.update_checkpoint_root(Some(root_hex.clone()));

        Ok(root_hex)
    }

    /// Compatibility helper that mirrors the v0.5.0 single-leaf API.
    /// Stores the checkpoint at step 0 — useful for callers who don't
    /// track a step yet.
    pub async fn register_agent_root(
        &self,
        agent_id: &str,
        checkpoint: [u8; 32],
    ) -> Result<String> {
        self.register(agent_id, 0, checkpoint).await
    }

    /// Build a `CheckpointInclusion` for `(agent_id, step)` — composes
    /// the per-agent path (step → agent_root) with the global path
    /// (agent_root → checkpoint_root). Returns `None` if the
    /// (agent, step) pair is not registered.
    pub async fn proof(&self, agent_id: &str, step: u32) -> Option<CheckpointInclusion> {
        let inner = self.inner.lock().await;
        let agent_tree = inner.agents.get(agent_id)?;
        let leaf_hash = agent_tree.leaves.get(&step)?;
        let agent_root_bytes = agent_tree.root()?;
        let agent_root_hex = hex::encode(agent_root_bytes);

        let (_agent_leaf_hex, agent_path) = agent_tree.proof(step)?;

        // Build the global aggregator's leaves and its path.
        let global_leaves: Vec<(String, [u8; 32])> = inner
            .agents
            .iter()
            .filter_map(|(id, tree)| tree.root().map(|r| (id.clone(), r)))
            .collect();
        let (_global_leaf_hex, global_path) =
            gvm_types::aggregator_inclusion_proof(&global_leaves, agent_id)?;

        Some(CheckpointInclusion {
            agent_id: agent_id.to_string(),
            step,
            checkpoint_hash: hex::encode(leaf_hash),
            agent_root: agent_root_hex,
            agent_path,
            global_path,
        })
    }

    /// Read the last-published global aggregator root.
    pub async fn current_root_hex(&self) -> Option<String> {
        self.inner.lock().await.last_root_hex.clone()
    }

    /// Number of distinct agents with at least one registered step.
    pub async fn entry_count(&self) -> usize {
        self.inner.lock().await.agents.len()
    }

    /// Number of distinct (agent, step) pairs.
    pub async fn total_step_count(&self) -> usize {
        self.inner
            .lock()
            .await
            .agents
            .values()
            .map(|t| t.step_count())
            .sum()
    }
}
