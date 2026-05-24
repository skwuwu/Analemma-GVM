//! Phase 3 (full) — per-agent per-step checkpoint aggregator.
//!
//! Each agent owns an `AgentCheckpointTree` keyed by `step: u32`. The
//! global aggregator's root is computed over `(agent_id, agent_root)`
//! pairs and published into the ledger's `TripleState::checkpoint_root`
//! so the next batch's seal/anchor binds the live aggregator state.
//!
//! Compared to the v0.5.0 simpler aggregator (one leaf per agent),
//! this design lets the proof export emit a per-step inclusion path:
//!
//!   - Per-agent path: step → agent_root.
//!   - Global path: agent_root → checkpoint_root.
//!
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
//!
//! Phase 4 leaves-only persistence: the aggregator can be created
//! with a snapshot path via `with_snapshot`; at startup it attempts
//! to reload the prior `BTreeMap` from disk so `checkpoint_root`
//! survives a proxy restart. Snapshots are written atomically (tmp,
//! fsync, rename) on demand (`save_snapshot`) or periodically
//! (`spawn_periodic_save`). The next anchor sealed after reload
//! captures the reconstructed root via the existing
//! `BatchSealRecord::checkpoint_root` field so the snapshot
//! transitively hashes into the anchor chain without any schema
//! change. Self-consistency (`expected_checkpoint_root` matches the
//! recomputed root) catches transit corruption at load time;
//! adversarial tampering is detectable post-hoc through the chain.

use crate::ledger::Ledger;
use anyhow::{anyhow, Result};
use gvm_types::CheckpointInclusion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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

/// Current snapshot file format version. Bump when the on-disk
/// schema changes incompatibly; the loader rejects unknown versions.
pub const SNAPSHOT_SPEC_VERSION: u8 = 1;

/// On-disk snapshot of the aggregator state.
///
/// Stored as JSON for human inspection. Keys are agent_id → step →
/// 32-byte checkpoint hash (hex). `expected_checkpoint_root` is the
/// global aggregator root recomputed at write time — the loader
/// recomputes the same root from `agents` and rejects the snapshot
/// on mismatch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSnapshot {
    pub spec_version: u8,
    /// Global aggregator root over the per-agent roots at write time.
    /// Used as a transit-corruption check on load.
    pub expected_checkpoint_root: String,
    /// Wall-clock at write time. Informational only — not part of
    /// the consistency check.
    pub written_at: chrono::DateTime<chrono::Utc>,
    /// agent_id → (step → checkpoint_hash_hex).
    pub agents: BTreeMap<String, BTreeMap<u32, String>>,
}

impl CheckpointSnapshot {
    /// Build a snapshot from the live aggregator state. Returns `None`
    /// if no agents have been registered (nothing to persist).
    fn from_inner(inner: &Inner) -> Option<Self> {
        if inner.agents.is_empty() {
            return None;
        }

        let mut agents: BTreeMap<String, BTreeMap<u32, String>> = BTreeMap::new();
        for (agent_id, tree) in inner.agents.iter() {
            let steps: BTreeMap<u32, String> = tree
                .leaves
                .iter()
                .map(|(step, hash)| (*step, hex::encode(hash)))
                .collect();
            agents.insert(agent_id.clone(), steps);
        }

        let global_leaves: Vec<(String, [u8; 32])> = inner
            .agents
            .iter()
            .filter_map(|(id, tree)| tree.root().map(|r| (id.clone(), r)))
            .collect();
        let expected_checkpoint_root = gvm_types::compute_checkpoint_root_hex(&global_leaves)?;

        Some(Self {
            spec_version: SNAPSHOT_SPEC_VERSION,
            expected_checkpoint_root,
            written_at: chrono::Utc::now(),
            agents,
        })
    }

    /// Parse a snapshot from disk bytes, validate self-consistency,
    /// and return the reconstructed `BTreeMap` of agent trees plus
    /// the global aggregator root.
    fn into_aggregator_state(self) -> Result<(BTreeMap<String, AgentCheckpointTree>, String)> {
        if self.spec_version != SNAPSHOT_SPEC_VERSION {
            return Err(anyhow!(
                "snapshot spec_version {} not supported (loader expects {})",
                self.spec_version,
                SNAPSHOT_SPEC_VERSION
            ));
        }
        if self.agents.is_empty() {
            return Err(anyhow!("snapshot contains no agents"));
        }

        let mut agents: BTreeMap<String, AgentCheckpointTree> = BTreeMap::new();
        for (agent_id, steps) in self.agents.into_iter() {
            if steps.is_empty() {
                return Err(anyhow!("agent {} has no steps in snapshot", agent_id));
            }
            let mut tree = AgentCheckpointTree::new();
            for (step, hex_hash) in steps.into_iter() {
                let bytes = hex::decode(&hex_hash).map_err(|e| {
                    anyhow!(
                        "agent {} step {} hash is not valid hex: {}",
                        agent_id,
                        step,
                        e
                    )
                })?;
                if bytes.len() != 32 {
                    return Err(anyhow!(
                        "agent {} step {} hash is {} bytes, expected 32",
                        agent_id,
                        step,
                        bytes.len()
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                tree.set(step, arr);
            }
            agents.insert(agent_id, tree);
        }

        let global_leaves: Vec<(String, [u8; 32])> = agents
            .iter()
            .filter_map(|(id, tree)| tree.root().map(|r| (id.clone(), r)))
            .collect();
        let recomputed = gvm_types::compute_checkpoint_root_hex(&global_leaves)
            .ok_or_else(|| anyhow!("recomputation produced no root (empty after parse)"))?;

        if recomputed != self.expected_checkpoint_root {
            return Err(anyhow!(
                "snapshot self-hash mismatch: file says {}, recomputed {}",
                self.expected_checkpoint_root,
                recomputed
            ));
        }

        Ok((agents, recomputed))
    }
}

/// Outcome of attempting to load a snapshot at startup.
#[derive(Debug, Clone)]
pub struct SnapshotLoadReport {
    pub status: SnapshotLoadStatus,
    pub agents_loaded: usize,
    pub steps_loaded: usize,
}

#[derive(Debug, Clone)]
pub enum SnapshotLoadStatus {
    /// No file at the snapshot path. Aggregator starts empty. Normal
    /// on first startup.
    NoFile,
    /// File parsed and validated. Aggregator state restored.
    Loaded { reconstructed_root: String },
    /// File present but rejected (corruption, version mismatch,
    /// self-hash mismatch). Aggregator starts empty so the system can
    /// keep running; operator must reconcile the snapshot file.
    Rejected { reason: String },
}

impl SnapshotLoadReport {
    fn no_file() -> Self {
        Self {
            status: SnapshotLoadStatus::NoFile,
            agents_loaded: 0,
            steps_loaded: 0,
        }
    }

    fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: SnapshotLoadStatus::Rejected {
                reason: reason.into(),
            },
            agents_loaded: 0,
            steps_loaded: 0,
        }
    }

    /// Returns true iff the snapshot was either absent or restored
    /// cleanly. False iff a file existed but was rejected — caller
    /// may want to surface this as a warning.
    pub fn is_ok(&self) -> bool {
        !matches!(self.status, SnapshotLoadStatus::Rejected { .. })
    }
}

/// Live checkpoint aggregator. Cheap to clone (one `Arc`).
#[derive(Clone)]
pub struct CheckpointAggregator {
    inner: Arc<Mutex<Inner>>,
    ledger: Arc<Ledger>,
    snapshot_path: Option<PathBuf>,
}

struct Inner {
    /// Per-agent trees. `BTreeMap` so iteration order matches the
    /// canonical sort that the global aggregator performs.
    agents: BTreeMap<String, AgentCheckpointTree>,
    /// Most recent published global root (hex). Cached so observers
    /// can read the last-known root without recomputing.
    last_root_hex: Option<String>,
    /// Monotonic counter incremented on every `register`. Compared
    /// against `saved_at_counter` to decide whether `save_snapshot`
    /// has anything to do — avoids no-op fsync work in the periodic
    /// saver.
    write_counter: u64,
    /// `write_counter` value at the moment of the most recent
    /// successful snapshot write. Initialised to 0; equals
    /// `write_counter` after a clean save.
    saved_at_counter: u64,
}

impl Inner {
    fn is_dirty(&self) -> bool {
        self.write_counter != self.saved_at_counter
    }
}

impl CheckpointAggregator {
    /// In-memory only. Existing callers that don't need persistence
    /// (tests, deployments without checkpoint snapshotting) keep this
    /// signature unchanged.
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                agents: BTreeMap::new(),
                last_root_hex: None,
                write_counter: 0,
                saved_at_counter: 0,
            })),
            ledger,
            snapshot_path: None,
        }
    }

    /// Create the aggregator, attempt to restore state from
    /// `snapshot_path`, and publish the reconstructed root into the
    /// ledger so the next sealed batch's anchor binds it.
    ///
    /// Never fails: on any I/O or validation error the aggregator
    /// starts empty and the returned `SnapshotLoadReport` describes
    /// what happened. The caller is expected to log the report.
    pub async fn with_snapshot(
        ledger: Arc<Ledger>,
        snapshot_path: PathBuf,
    ) -> (Self, SnapshotLoadReport) {
        let (inner, report) = match tokio::fs::read(&snapshot_path).await {
            Ok(bytes) => Self::parse_and_validate(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                Inner {
                    agents: BTreeMap::new(),
                    last_root_hex: None,
                    write_counter: 0,
                    saved_at_counter: 0,
                },
                SnapshotLoadReport::no_file(),
            ),
            Err(e) => (
                Inner {
                    agents: BTreeMap::new(),
                    last_root_hex: None,
                    write_counter: 0,
                    saved_at_counter: 0,
                },
                SnapshotLoadReport::rejected(format!("read error: {}", e)),
            ),
        };

        if let SnapshotLoadStatus::Loaded {
            reconstructed_root, ..
        } = &report.status
        {
            ledger.update_checkpoint_root(Some(reconstructed_root.clone()));
        }

        (
            Self {
                inner: Arc::new(Mutex::new(inner)),
                ledger,
                snapshot_path: Some(snapshot_path),
            },
            report,
        )
    }

    fn parse_and_validate(bytes: &[u8]) -> (Inner, SnapshotLoadReport) {
        let snapshot: CheckpointSnapshot = match serde_json::from_slice(bytes) {
            Ok(s) => s,
            Err(e) => {
                return (
                    Inner {
                        agents: BTreeMap::new(),
                        last_root_hex: None,
                        write_counter: 0,
                        saved_at_counter: 0,
                    },
                    SnapshotLoadReport::rejected(format!("parse error: {}", e)),
                );
            }
        };

        match snapshot.into_aggregator_state() {
            Ok((agents, root_hex)) => {
                let steps_loaded: usize = agents.values().map(|t| t.leaves.len()).sum();
                let agents_loaded = agents.len();
                let inner = Inner {
                    agents,
                    last_root_hex: Some(root_hex.clone()),
                    write_counter: 0,
                    saved_at_counter: 0,
                };
                (
                    inner,
                    SnapshotLoadReport {
                        status: SnapshotLoadStatus::Loaded {
                            reconstructed_root: root_hex,
                        },
                        agents_loaded,
                        steps_loaded,
                    },
                )
            }
            Err(e) => (
                Inner {
                    agents: BTreeMap::new(),
                    last_root_hex: None,
                    write_counter: 0,
                    saved_at_counter: 0,
                },
                SnapshotLoadReport::rejected(e.to_string()),
            ),
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

        let entry = inner.agents.entry(agent_id.to_string()).or_default();
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
        inner.write_counter = inner.write_counter.wrapping_add(1);
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

    /// Path the aggregator persists to. `None` for in-memory-only mode.
    pub fn snapshot_path(&self) -> Option<&Path> {
        self.snapshot_path.as_deref()
    }

    /// Persist the current state to `snapshot_path` if (a) a path is
    /// configured and (b) the aggregator has been mutated since the
    /// last successful save. Writes are atomic: tmp → fsync → rename.
    ///
    /// Returns `Ok(true)` on a real write, `Ok(false)` when there was
    /// nothing to do (no path, no dirty state, or empty aggregator).
    pub async fn save_snapshot(&self) -> Result<bool> {
        let Some(path) = self.snapshot_path.clone() else {
            return Ok(false);
        };

        let (snapshot, taken_at_counter) = {
            let inner = self.inner.lock().await;
            if !inner.is_dirty() {
                return Ok(false);
            }
            (CheckpointSnapshot::from_inner(&inner), inner.write_counter)
        };

        let Some(snapshot) = snapshot else {
            // Dirty but agents map is empty — somebody cleared state
            // we never observed. Mark clean and skip the write.
            let mut inner = self.inner.lock().await;
            inner.saved_at_counter = taken_at_counter;
            return Ok(false);
        };

        let bytes = serde_json::to_vec_pretty(&snapshot)?;

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let tmp = path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        let file = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, &path).await?;

        // Only advance the saved counter if no newer save raced ahead.
        // (Concurrent save_snapshot from periodic + shutdown handler.)
        let mut inner = self.inner.lock().await;
        if inner.saved_at_counter < taken_at_counter {
            inner.saved_at_counter = taken_at_counter;
        }

        Ok(true)
    }

    /// Spawn a background task that calls `save_snapshot` every
    /// `interval`. Returns a `JoinHandle` so the caller can abort
    /// it at shutdown — the caller is also expected to call
    /// `save_snapshot()` one last time after aborting, to flush
    /// any state written between the last tick and shutdown.
    ///
    /// No-op (returns an aborted handle) when no snapshot path is
    /// configured.
    pub fn spawn_periodic_save(self: &Arc<Self>, interval: Duration) -> JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            if me.snapshot_path.is_none() {
                return;
            }
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick that `tokio::time::interval`
            // emits at construction — we want the first save at
            // `interval` from now, not at startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = me.save_snapshot().await {
                    tracing::warn!(
                        target: "gvm.audit.checkpoint",
                        error = %e,
                        "periodic checkpoint snapshot save failed"
                    );
                }
            }
        })
    }
}
