//! Phase 3 — Per-agent checkpoint aggregator.
//!
//! Maintains a `(agent_id -> checkpoint_hash)` map and exposes the
//! aggregator root via `gvm_types::compute_checkpoint_root_hex`. On every
//! `register`, the new root is published to the ledger's `TripleState`
//! so the next batch's seal/anchor captures it as `checkpoint_root`.
//!
//! Last-write-wins per agent: a fresh checkpoint hash for the same
//! `agent_id` replaces the previous one.
//!
//! Concurrency: writers serialize through a `tokio::sync::Mutex` so a
//! `register` ordering is well-defined; the ledger update inside the
//! locked section happens BEFORE the lock is released so two concurrent
//! updates cannot publish out of insertion order.
//!
//! Memory: leaves-only — no SMT. The Merkle root is recomputed inside
//! `register` from the current map. For 10k agents this is well under
//! a millisecond and runs off the request hot path (checkpoint
//! registration is a per-step event, not a per-request event).

use crate::ledger::Ledger;
use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Live checkpoint aggregator. Cheap to clone (one `Arc`).
#[derive(Clone)]
pub struct CheckpointAggregator {
    inner: Arc<Mutex<Inner>>,
    ledger: Arc<Ledger>,
}

struct Inner {
    /// Per-agent checkpoint hash. `BTreeMap` so iteration order matches
    /// the canonical sort that `compute_checkpoint_root` performs (the
    /// root is order-independent regardless, but BTreeMap makes the
    /// in-memory state easier to reason about during tests).
    leaves: BTreeMap<String, [u8; 32]>,
    /// Most recent published root. Cached so observers can read the
    /// last-known root without recomputing.
    last_root_hex: Option<String>,
}

impl CheckpointAggregator {
    /// Create a fresh aggregator bound to a ledger. The ledger receives
    /// `update_checkpoint_root` calls on every `register`.
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                leaves: BTreeMap::new(),
                last_root_hex: None,
            })),
            ledger,
        }
    }

    /// Register a new checkpoint hash for `agent_id`. Replaces any prior
    /// hash for the same agent. After the map updates, the new
    /// aggregator root is published into the ledger's triple state and
    /// returned.
    ///
    /// Returns the hex-encoded aggregator root after the update.
    pub async fn register(&self, agent_id: &str, checkpoint: [u8; 32]) -> Result<String> {
        let mut inner = self.inner.lock().await;
        inner.leaves.insert(agent_id.to_string(), checkpoint);

        let snapshot: Vec<(String, [u8; 32])> =
            inner.leaves.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let root_hex = gvm_types::compute_checkpoint_root_hex(&snapshot)
            .expect("non-empty leaves must yield Some(root)");

        inner.last_root_hex = Some(root_hex.clone());
        self.ledger.update_checkpoint_root(Some(root_hex.clone()));

        Ok(root_hex)
    }

    /// Read the last-published aggregator root. `None` until the first
    /// `register` call.
    pub async fn current_root_hex(&self) -> Option<String> {
        self.inner.lock().await.last_root_hex.clone()
    }

    /// Number of distinct agents with a registered checkpoint.
    pub async fn entry_count(&self) -> usize {
        self.inner.lock().await.leaves.len()
    }
}
