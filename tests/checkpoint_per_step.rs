//! Phase 3 (full) — per-agent per-step `AgentCheckpointTree` + proof.
//!
//! Pinned invariants:
//!   - `compute_agent_checkpoint_root` is deterministic and order-stable
//!     under BTreeMap iteration. A single-bit change in any leaf changes
//!     the root.
//!   - `agent_checkpoint_proof(step)` produces a path that
//!     `verify_agent_checkpoint_proof` accepts against the agent root.
//!     Tampering ANY pair in the path invalidates the verify.
//!   - Domain prefixes for the per-agent tree are distinct from the
//!     global aggregator's (`gvm-ckpt-agent-*` vs `gvm-ckpt-*`).
//!   - Live `CheckpointAggregator::register(agent, step, hash)`:
//!     last-write-wins per `(agent, step)` and changing one agent's
//!     leaves does NOT invalidate another agent's per-step proof.
//!   - End-to-end: after `register`, `proof(agent, step)` yields a
//!     `CheckpointInclusion` whose `agent_path` verifies to
//!     `agent_root` AND whose `global_path` verifies to the seal's
//!     `checkpoint_root` (a real on-disk anchor).

use gvm_proxy::checkpoint::{AgentCheckpointTree, CheckpointAggregator};
use gvm_proxy::ledger::{GroupCommitConfig, Ledger};
use gvm_types::{
    agent_checkpoint_proof, compose_aggregator_leaf, compute_agent_checkpoint_leaf,
    compute_agent_checkpoint_root, compute_agent_checkpoint_root_hex,
    verify_agent_checkpoint_proof, verify_aggregator_inclusion, GvmStateAnchor,
    PREFIX_CKPT_AGENT_LEAF_V1, PREFIX_CKPT_AGENT_NODE_V1, PREFIX_CKPT_AGENT_ROOT_V1,
};
use std::collections::BTreeMap;
use std::sync::Arc;

// ────────────────────────────────────────────────────────────────────
// 1. Pure agent-tree functions
// ────────────────────────────────────────────────────────────────────

#[test]
fn empty_agent_tree_yields_no_root() {
    let leaves: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    assert!(compute_agent_checkpoint_root(&leaves).is_none());
    assert!(compute_agent_checkpoint_root_hex(&leaves).is_none());
}

#[test]
fn single_step_yields_some_root_and_distinct_from_genesis() {
    let mut leaves = BTreeMap::new();
    leaves.insert(0, [9u8; 32]);
    let root = compute_agent_checkpoint_root_hex(&leaves).expect("Some root");
    assert_eq!(root.len(), 64);
    assert_ne!(root, gvm_types::GENESIS_HASH_HEX);
}

#[test]
fn agent_root_is_deterministic_for_same_inputs() {
    let mut a = BTreeMap::new();
    let mut b = BTreeMap::new();
    for i in 0..5 {
        a.insert(i, [i as u8; 32]);
        b.insert(i, [i as u8; 32]);
    }
    assert_eq!(
        compute_agent_checkpoint_root(&a),
        compute_agent_checkpoint_root(&b)
    );
}

#[test]
fn changing_one_leaf_changes_root() {
    let mut base = BTreeMap::new();
    for i in 0..4 {
        base.insert(i, [i as u8; 32]);
    }
    let baseline = compute_agent_checkpoint_root(&base).unwrap();
    let mut tampered = base.clone();
    tampered.entry(2).and_modify(|v| v[0] ^= 0x01);
    let after = compute_agent_checkpoint_root(&tampered).unwrap();
    assert_ne!(baseline, after, "single-bit leaf change must change root");
}

#[test]
fn step_is_part_of_leaf_input() {
    // Same hash at different steps must produce different leaf hashes
    // (so the proof distinguishes between them).
    let h = [42u8; 32];
    let l0 = compute_agent_checkpoint_leaf(0, &h);
    let l1 = compute_agent_checkpoint_leaf(1, &h);
    assert_ne!(
        l0, l1,
        "step is part of the leaf — same hash at different steps must differ"
    );
}

#[test]
fn agent_tree_prefixes_are_distinct() {
    assert_ne!(PREFIX_CKPT_AGENT_LEAF_V1, PREFIX_CKPT_AGENT_NODE_V1);
    assert_ne!(PREFIX_CKPT_AGENT_LEAF_V1, PREFIX_CKPT_AGENT_ROOT_V1);
    assert_ne!(PREFIX_CKPT_AGENT_NODE_V1, PREFIX_CKPT_AGENT_ROOT_V1);
}

// ────────────────────────────────────────────────────────────────────
// 2. Inclusion proof round-trip
// ────────────────────────────────────────────────────────────────────

#[test]
fn agent_proof_round_trips_for_every_step() {
    let mut leaves = BTreeMap::new();
    for i in 0..7 {
        leaves.insert(i, [i as u8; 32]);
    }
    let root_hex = compute_agent_checkpoint_root_hex(&leaves).unwrap();

    for step in leaves.keys().copied().collect::<Vec<_>>() {
        let (leaf_hex, path) = agent_checkpoint_proof(&leaves, step)
            .unwrap_or_else(|| panic!("proof must exist for step {}", step));
        assert!(
            verify_agent_checkpoint_proof(&leaf_hex, &path, &root_hex),
            "proof for step {} must verify",
            step
        );
    }
}

#[test]
fn agent_proof_rejects_tampered_path() {
    let mut leaves = BTreeMap::new();
    for i in 0..6 {
        leaves.insert(i, [i as u8; 32]);
    }
    let root_hex = compute_agent_checkpoint_root_hex(&leaves).unwrap();

    let (leaf_hex, mut path) = agent_checkpoint_proof(&leaves, 3).unwrap();
    if !path.is_empty() {
        // Flip the first sibling.
        path[0].0 = "ff".repeat(32);
    }
    assert!(
        !verify_agent_checkpoint_proof(&leaf_hex, &path, &root_hex),
        "tampered path must fail verify"
    );
}

#[test]
fn agent_proof_for_missing_step_is_none() {
    let mut leaves = BTreeMap::new();
    leaves.insert(0, [1u8; 32]);
    leaves.insert(2, [2u8; 32]);
    assert!(agent_checkpoint_proof(&leaves, 1).is_none());
}

// ────────────────────────────────────────────────────────────────────
// 3. Live aggregator: per-step semantics
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn live_aggregator_last_write_wins_per_step() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = Arc::new(
        Ledger::new(&dir.path().join("wal.log"), "", "")
            .await
            .unwrap(),
    );
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));

    agg.register("agent-1", 5, [1u8; 32]).await.unwrap();
    let r1 = agg.current_root_hex().await.unwrap();
    assert_eq!(agg.entry_count().await, 1, "one agent registered");
    assert_eq!(agg.total_step_count().await, 1, "one (agent, step) pair");

    // Same agent + same step: overwrite. Step count stays at 1.
    agg.register("agent-1", 5, [99u8; 32]).await.unwrap();
    let r2 = agg.current_root_hex().await.unwrap();
    assert_eq!(agg.total_step_count().await, 1);
    assert_ne!(r1, r2, "overwriting (agent, step) must change global root");

    // Same agent + different step: new pair. Step count grows.
    agg.register("agent-1", 6, [42u8; 32]).await.unwrap();
    assert_eq!(
        agg.total_step_count().await,
        2,
        "different step is a new leaf"
    );

    drop(agg);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;
}

#[tokio::test]
async fn live_aggregator_independent_agents_dont_invalidate_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = Arc::new(
        Ledger::new(&dir.path().join("wal.log"), "", "")
            .await
            .unwrap(),
    );
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));

    // Register agent-A's step 0.
    agg.register("agent-A", 0, [1u8; 32]).await.unwrap();
    let proof_a_before = agg.proof("agent-A", 0).await.expect("proof");
    let agent_root_a_before = proof_a_before.agent_root.clone();

    // Register agent-B's step 0 — agent-A's per-agent root must NOT
    // change (only the global aggregator's root changes).
    agg.register("agent-B", 0, [2u8; 32]).await.unwrap();
    let proof_a_after = agg.proof("agent-A", 0).await.expect("proof");
    assert_eq!(
        proof_a_before.agent_root, proof_a_after.agent_root,
        "agent-A's per-agent root must be independent of other agents"
    );
    assert_eq!(agent_root_a_before, proof_a_after.agent_root);

    // The global path for agent-A changes (sibling now exists).
    // verify the path against the new global root.
    let agent_root_bytes: [u8; 32] = hex::decode(&proof_a_after.agent_root)
        .unwrap()
        .try_into()
        .unwrap();
    let agg_leaf = compose_aggregator_leaf("agent-A", &agent_root_bytes);
    let global_root_hex = agg.current_root_hex().await.unwrap();
    assert!(
        verify_aggregator_inclusion(
            &hex::encode(agg_leaf),
            &proof_a_after.global_path,
            &global_root_hex,
        ),
        "post-B-register: agent-A's global path must verify against the new global root"
    );

    drop(agg);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;
}

// ────────────────────────────────────────────────────────────────────
// 4. End-to-end: CheckpointInclusion path verifies to anchor's
//    checkpoint_root
// ────────────────────────────────────────────────────────────────────

fn make_event(event_id: &str) -> gvm_types::GVMEvent {
    use gvm_types::{EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor};
    use std::collections::HashMap;
    GVMEvent {
        event_id: event_id.to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        agent_id: "agent-A".to_string(),
        tenant_id: None,
        session_id: "ckpt-per-step-test".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "test.event".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

#[tokio::test]
async fn checkpoint_inclusion_path_verifies_against_anchor_checkpoint_root() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("wal.log");
    let mut ledger = Arc::new(
        Ledger::with_config(
            &wal_path,
            "",
            "",
            GroupCommitConfig {
                batch_window: std::time::Duration::ZERO,
                max_batch_size: 1,
                channel_capacity: 16,
                max_wal_bytes: 0,
                max_wal_segments: 0,
            },
        )
        .await
        .unwrap(),
    );
    let agg = CheckpointAggregator::new(Arc::clone(&ledger));

    // Register checkpoints for two agents with multiple steps.
    agg.register("agent-A", 0, [1u8; 32]).await.unwrap();
    agg.register("agent-A", 1, [2u8; 32]).await.unwrap();
    agg.register("agent-A", 2, [3u8; 32]).await.unwrap();
    agg.register("agent-B", 0, [4u8; 32]).await.unwrap();
    let final_root = agg.register("agent-B", 1, [5u8; 32]).await.unwrap();

    // Write an event so a batch closes; the seal captures the live
    // aggregator root.
    ledger
        .append_durable(&make_event("evt-after-ckpt"))
        .await
        .unwrap();

    // Build the inclusion proof for (agent-A, step 1).
    let inclusion = agg
        .proof("agent-A", 1)
        .await
        .expect("proof must exist for registered (agent, step)");

    drop(agg);
    let ledger_mut = Arc::get_mut(&mut ledger).expect("only ref");
    ledger_mut.shutdown().await;

    // Verify the per-agent path: leaf → agent_root.
    let leaf_bytes = compute_agent_checkpoint_leaf(
        inclusion.step,
        &hex::decode(&inclusion.checkpoint_hash)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert!(
        verify_agent_checkpoint_proof(
            &hex::encode(leaf_bytes),
            &inclusion.agent_path,
            &inclusion.agent_root,
        ),
        "per-agent inclusion path must verify to agent_root"
    );

    // Verify the global path: agent_root (composed as aggregator leaf)
    // → checkpoint_root (read from the on-disk anchor).
    let agent_root_bytes: [u8; 32] = hex::decode(&inclusion.agent_root)
        .unwrap()
        .try_into()
        .unwrap();
    let agg_leaf = compose_aggregator_leaf(&inclusion.agent_id, &agent_root_bytes);
    assert!(
        verify_aggregator_inclusion(&hex::encode(agg_leaf), &inclusion.global_path, &final_root,),
        "global aggregator path must verify against the published global root"
    );

    // Cross-check: the on-disk anchor's checkpoint_root must equal
    // the global root we used.
    let content = std::fs::read_to_string(&wal_path).unwrap();
    let last_anchor: GvmStateAnchor = content
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<GvmStateAnchor>(l).ok())
        .next()
        .expect("anchor present");
    assert_eq!(
        last_anchor.checkpoint_root.as_deref(),
        Some(final_root.as_str()),
        "anchor.checkpoint_root MUST equal the aggregator's published root"
    );
}

// ────────────────────────────────────────────────────────────────────
// 5. AgentCheckpointTree direct API
// ────────────────────────────────────────────────────────────────────

#[test]
fn agent_tree_set_returns_root_and_caches() {
    let mut tree = AgentCheckpointTree::new();
    let r0 = tree.set(0, [1u8; 32]);
    let r1 = tree.set(1, [2u8; 32]);
    assert_ne!(r0, r1, "second insert changes root");
    assert_eq!(tree.root(), Some(r1), "cached_root reflects last insert");
    assert_eq!(tree.step_count(), 2);
}

#[test]
fn agent_tree_proof_via_struct_api() {
    let mut tree = AgentCheckpointTree::new();
    for i in 0..5 {
        tree.set(i, [i as u8; 32]);
    }
    let root_hex = tree.root_hex().unwrap();
    let (leaf_hex, path) = tree.proof(2).expect("proof for step 2");
    assert!(verify_agent_checkpoint_proof(&leaf_hex, &path, &root_hex));
}

// ────────────────────────────────────────────────────────────────────
// 6. Scale: 1k agents × 100 steps under a soft time budget
// ────────────────────────────────────────────────────────────────────

#[test]
fn one_k_agents_hundred_steps_recompute_within_budget() {
    // This is a smoke test, not a benchmark — we just confirm the
    // happy-path data structure handles realistic load without
    // hanging. Strict time SLO is left to a separate bench.
    use std::time::Instant;
    let mut trees: Vec<AgentCheckpointTree> = (0..1000)
        .map(|i| {
            let mut t = AgentCheckpointTree::new();
            for s in 0..100u32 {
                let mut h = [0u8; 32];
                h[0] = (i % 256) as u8;
                h[1] = (s % 256) as u8;
                t.set(s, h);
            }
            t
        })
        .collect();

    let start = Instant::now();
    // Recompute every tree's root (touches the cache and the leaves).
    for t in &mut trees {
        t.cached_root = None;
        let _ = t.root();
    }
    let elapsed = start.elapsed();

    // Generous budget — only catches catastrophic regressions (e.g.
    // accidental O(N²) in compute_agent_checkpoint_root).
    assert!(
        elapsed.as_secs() < 30,
        "1k×100 recompute took {:?} — investigate possible perf regression",
        elapsed
    );
}
