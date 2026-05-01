#![allow(clippy::manual_div_ceil, clippy::manual_is_multiple_of)]
//! Merkle tree computation and WAL integrity verification.
//!
//! # Architecture
//!
//! Events within a batch form a Merkle tree (intra-batch integrity).
//! Batches are chained via `prev_batch_root` (inter-batch integrity).
//!
//! ```text
//! Batch N:
//!   event_1.hash ─┐
//!                  ├─ H(1,2) ─┐
//!   event_2.hash ─┘           │
//!                             ├─ merkle_root_N
//!   event_3.hash ─┐           │
//!                  ├─ H(3,4) ─┘
//!   event_4.hash ─┘
//!
//! Batch N+1:
//!   prev_batch_root = merkle_root_N  ← inter-batch chain
//! ```
//!
//! Single-event verification: O(log N) proof path within the batch.
//! Batch chain verification: O(B) where B = number of batches.

use crate::types::{GVMEvent, MerkleBatchRecord};
use sha2::{Digest, Sha256};

// ─── Event Hash Computation ───

/// Compute the SHA-256 hash of an event's audit-critical fields.
///
/// Dispatcher (Phase 1):
/// - `event.operation_descriptor.is_some()` → v2 hash
///   (uses `category` and `detail_digest` instead of raw operation)
/// - `event.operation_descriptor.is_none()` → v1 hash (legacy)
///   (uses `operation: String` directly)
///
/// Both versions share the same set of audit-critical fields:
/// event_id, trace_id, agent_id, operation*, decision, decision_source,
/// status, enforcement_point, timestamp, payload.content_hash.
/// The only difference is whether the "operation" axis is taken
/// monolithically (v1) or split into category + salted detail digest
/// (v2 — privacy-preserving for redacted proofs).
///
/// `status` field prevents undetected Pending→Confirmed tampering;
/// `decision_source` / `enforcement_point` prevent attribution falsification.
pub fn compute_event_hash(event: &GVMEvent) -> String {
    match &event.operation_descriptor {
        Some(desc) => compute_event_hash_v2(event, desc),
        None => compute_event_hash_v1(event),
    }
}

/// Legacy v1 event hash. Uses `event.operation: String` directly.
/// Kept for backward compatibility with WAL entries written before
/// the v2 dispatcher landed.
fn compute_event_hash_v1(event: &GVMEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(gvm_types::PREFIX_EVENT_V1);
    for field in &[
        event.event_id.as_str(),
        event.trace_id.as_str(),
        event.agent_id.as_str(),
        event.operation.as_str(),
        event.decision.as_str(),
        event.decision_source.as_str(),
        &format!("{:?}", event.status),
        event.enforcement_point.as_str(),
        &event.timestamp.to_rfc3339(),
        event.payload.content_hash.as_str(),
    ] {
        hasher.update((field.len() as u32).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Phase 1 v2 event hash. Uses `category` and `detail_digest` from
/// the OperationDescriptor instead of `event.operation: String`.
///
/// Privacy property: when the verifier holds a redacted proof
/// (no `detail`, no `detail_salt`, but `detail_digest` preserved),
/// `compute_event_hash_v2` recomputes the same hash as the producer
/// — so audit verification works without leaking the operation detail.
pub fn compute_event_hash_v2(event: &GVMEvent, desc: &gvm_types::OperationDescriptor) -> String {
    let mut hasher = Sha256::new();
    hasher.update(gvm_types::PREFIX_EVENT_V2);
    for field in &[
        event.event_id.as_str(),
        event.trace_id.as_str(),
        event.agent_id.as_str(),
        desc.category.as_str(),
        desc.detail_digest.as_str(),
        event.decision.as_str(),
        event.decision_source.as_str(),
        &format!("{:?}", event.status),
        event.enforcement_point.as_str(),
        &event.timestamp.to_rfc3339(),
        event.payload.content_hash.as_str(),
    ] {
        hasher.update((field.len() as u32).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

// ─── Merkle Tree Computation ───

/// Compute the Merkle root from a list of hex-encoded leaf hashes.
/// For a single leaf, the root is the leaf itself.
/// For an odd number of leaves, the last leaf is duplicated.
///
/// Returns an error if the leaf list is empty or contains invalid hex data.
pub fn compute_merkle_root(leaf_hashes: &[String]) -> anyhow::Result<String> {
    if leaf_hashes.is_empty() {
        anyhow::bail!("cannot compute merkle root of empty set");
    }

    let mut current_level: Vec<[u8; 32]> = leaf_hashes
        .iter()
        .map(|h| {
            let bytes =
                hex::decode(h).map_err(|e| anyhow::anyhow!("invalid hex in leaf hash: {}", e))?;
            if bytes.len() != 32 {
                anyhow::bail!("leaf hash must be 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            // Domain separation for internal nodes vs leaf hashes
            hasher.update(b"gvm-node-v1:");
            hasher.update(chunk[0]);
            if chunk.len() == 2 {
                hasher.update(chunk[1]);
            } else {
                // Odd leaf: duplicate
                hasher.update(chunk[0]);
            }
            let hash: [u8; 32] = hasher.finalize().into();
            next_level.push(hash);
        }

        current_level = next_level;
    }

    Ok(hex::encode(current_level[0]))
}

/// Generate a Merkle proof (sibling hashes + directions) for a leaf at `index`.
/// Returns a list of (sibling_hash, is_right) pairs, from leaf to root.
///
/// Returns an error if the index is out of bounds or leaf hashes contain invalid hex.
pub fn generate_merkle_proof(
    leaf_hashes: &[String],
    index: usize,
) -> anyhow::Result<Vec<(String, bool)>> {
    if index >= leaf_hashes.len() {
        anyhow::bail!(
            "merkle proof index {} out of bounds (len {})",
            index,
            leaf_hashes.len()
        );
    }

    let mut current_level: Vec<[u8; 32]> = leaf_hashes
        .iter()
        .map(|h| {
            let bytes =
                hex::decode(h).map_err(|e| anyhow::anyhow!("invalid hex in leaf hash: {}", e))?;
            if bytes.len() != 32 {
                anyhow::bail!("leaf hash must be 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut proof = Vec::new();
    let mut idx = index;

    while current_level.len() > 1 {
        // Pad with duplicate if odd number of nodes at this level.
        // This means for the last leaf at an odd level, its sibling in the
        // proof will be itself (a duplicate). This is the standard Bitcoin
        // Merkle tree behavior and is intentional — it preserves the
        // property that every node has a sibling for proof construction.
        if current_level.len() % 2 == 1 {
            // Safe: while condition guarantees len >= 2, so last() always succeeds.
            // After odd-padding, len becomes even.
            let last = current_level[current_level.len() - 1];
            current_level.push(last);
        }

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let is_right = idx % 2 == 0; // sibling is on the right
        proof.push((hex::encode(current_level[sibling_idx]), is_right));

        // Build next level
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(b"gvm-node-v1:");
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            let hash: [u8; 32] = hasher.finalize().into();
            next_level.push(hash);
        }

        current_level = next_level;
        idx /= 2;
    }

    Ok(proof)
}

/// Verify a Merkle proof for a given leaf hash against an expected root.
pub fn verify_merkle_proof(leaf_hash: &str, proof: &[(String, bool)], expected_root: &str) -> bool {
    let mut current = match hex::decode(leaf_hash) {
        Ok(bytes) => {
            let mut arr = [0u8; 32];
            if bytes.len() != 32 {
                return false;
            }
            arr.copy_from_slice(&bytes);
            arr
        }
        Err(_) => return false,
    };

    for (sibling_hex, is_right) in proof {
        let sibling = match hex::decode(sibling_hex) {
            Ok(bytes) => {
                let mut arr = [0u8; 32];
                if bytes.len() != 32 {
                    return false;
                }
                arr.copy_from_slice(&bytes);
                arr
            }
            Err(_) => return false,
        };

        let mut hasher = Sha256::new();
        hasher.update(b"gvm-node-v1:");
        if *is_right {
            // sibling is on the right: H(current || sibling)
            hasher.update(current);
            hasher.update(sibling);
        } else {
            // sibling is on the left: H(sibling || current)
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
    }

    hex::encode(current) == expected_root
}

// ─── WAL Verification ───

/// Result of WAL integrity verification.
#[derive(Debug)]
pub struct VerificationReport {
    pub total_events: usize,
    pub total_batches: usize,
    pub valid_batches: usize,
    pub invalid_batches: Vec<u64>,
    /// Event IDs whose content hash does not match the stored hash.
    /// These events were tampered with after being written to WAL.
    /// Note: the stored hash is still used for Merkle root verification
    /// so we can distinguish "event content tampered but batch root intact"
    /// from "batch root itself tampered".
    pub tampered_events: Vec<String>,
    /// Event IDs that had no event_hash (legacy or IC-1 async records).
    /// These events cannot be individually verified but are included in
    /// batch Merkle root computation via on-the-fly hash calculation.
    pub unhashed_events: Vec<String>,
    pub chain_intact: bool,
}

/// Verify WAL integrity by re-computing Merkle roots and checking batch chain.
///
/// WAL format: each line is either a GVMEvent JSON or a MerkleBatchRecord JSON.
/// Batch records are identified by the presence of a `merkle_root` field.
pub fn verify_wal(wal_content: &str) -> VerificationReport {
    let mut events_in_current_batch: Vec<String> = Vec::new();
    let mut total_events = 0usize;
    let mut total_batches = 0usize;
    let mut valid_batches = 0usize;
    let mut invalid_batches: Vec<u64> = Vec::new();
    let mut tampered_events: Vec<String> = Vec::new();
    let mut unhashed_events: Vec<String> = Vec::new();
    let mut chain_intact = true;
    let mut prev_root: Option<String> = None;

    for line in wal_content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Try to parse as a batch record first (has merkle_root field)
        if let Ok(batch_record) = serde_json::from_str::<MerkleBatchRecord>(trimmed) {
            total_batches += 1;

            // Verify Merkle root
            if events_in_current_batch.is_empty() {
                // No events before this batch record — invalid
                invalid_batches.push(batch_record.batch_id);
            } else {
                match compute_merkle_root(&events_in_current_batch) {
                    Ok(computed_root) => {
                        if computed_root == batch_record.merkle_root {
                            valid_batches += 1;
                        } else {
                            invalid_batches.push(batch_record.batch_id);
                        }
                    }
                    Err(e) => {
                        tracing::error!(batch_id = batch_record.batch_id, error = %e, "Failed to compute merkle root during WAL verification");
                        invalid_batches.push(batch_record.batch_id);
                    }
                }
            }

            // Verify inter-batch chain
            if batch_record.prev_batch_root != prev_root {
                chain_intact = false;
            }

            prev_root = Some(batch_record.merkle_root.clone());
            events_in_current_batch.clear();
            continue;
        }

        // Parse as event
        if let Ok(event) = serde_json::from_str::<GVMEvent>(trimmed) {
            total_events += 1;

            match event.event_hash {
                Some(ref hash) => {
                    // Verify the event hash matches recomputed value
                    let computed = compute_event_hash(&event);
                    if computed != *hash {
                        // Event content was tampered — hash doesn't match.
                        // Track the tampered event for the report.
                        tampered_events.push(event.event_id.clone());
                    }
                    // Always use the stored hash for batch root verification.
                    // This lets us distinguish "event content tampered but batch
                    // root intact" from "batch root itself tampered".
                    events_in_current_batch.push(hash.clone());
                }
                None => {
                    // No stored hash (legacy event or IC-1 async record).
                    // Compute hash on-the-fly so batch Merkle root stays correct.
                    unhashed_events.push(event.event_id.clone());
                    let computed = compute_event_hash(&event);
                    events_in_current_batch.push(computed);
                }
            }
        }
    }

    VerificationReport {
        total_events,
        total_batches,
        valid_batches,
        invalid_batches,
        tampered_events,
        unhashed_events,
        chain_intact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventStatus, PayloadDescriptor, ResourceDescriptor};
    use std::collections::HashMap;

    fn hash_str(s: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[test]
    fn merkle_single_leaf() {
        let leaf = hash_str("event_1");
        // Verify hash format: must be exactly 64 hex characters (SHA-256)
        assert_eq!(leaf.len(), 64, "SHA-256 hash must be 64 hex characters");
        assert!(
            leaf.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash must be valid hex"
        );
        let root = compute_merkle_root(std::slice::from_ref(&leaf)).unwrap();
        assert_eq!(root, leaf, "single leaf should be its own root");
    }

    /// Helper: compute internal node hash with domain separation (matches production code)
    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"gvm-node-v1:");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn decode_hash(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("test hash must be valid hex");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    #[test]
    fn merkle_two_leaves() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let root = compute_merkle_root(&[a.clone(), b.clone()]).unwrap();

        let expected = hex::encode(node_hash(&decode_hash(&a), &decode_hash(&b)));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_odd_leaves_duplicates_last() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let c = hash_str("event_3");
        let root = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]).unwrap();

        let hab = node_hash(&decode_hash(&a), &decode_hash(&b));
        let hcc = node_hash(&decode_hash(&c), &decode_hash(&c));
        let expected = hex::encode(node_hash(&hab, &hcc));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_four_leaves_balanced() {
        let leaves: Vec<String> = (0..4).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root = compute_merkle_root(&leaves).unwrap();

        let n01 = node_hash(&decode_hash(&leaves[0]), &decode_hash(&leaves[1]));
        let n23 = node_hash(&decode_hash(&leaves[2]), &decode_hash(&leaves[3]));
        let expected = hex::encode(node_hash(&n01, &n23));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_verifies_each_leaf() {
        let leaves: Vec<String> = (0..5).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root = compute_merkle_root(&leaves).unwrap();

        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i).unwrap();
            assert!(
                verify_merkle_proof(&leaves[i], &proof, &root),
                "proof failed for leaf index {}",
                i
            );
        }
    }

    #[test]
    fn merkle_proof_rejects_wrong_leaf() {
        let leaves: Vec<String> = (0..4).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root = compute_merkle_root(&leaves).unwrap();
        let proof = generate_merkle_proof(&leaves, 0).unwrap();

        let wrong_leaf = hash_str("tampered_event");
        assert!(
            !verify_merkle_proof(&wrong_leaf, &proof, &root),
            "proof should reject tampered leaf"
        );
    }

    #[test]
    fn merkle_proof_rejects_wrong_root() {
        let leaves: Vec<String> = (0..4).map(|i| hash_str(&format!("event_{}", i))).collect();
        let proof = generate_merkle_proof(&leaves, 0).unwrap();

        let wrong_root = hash_str("wrong_root");
        assert!(
            !verify_merkle_proof(&leaves[0], &proof, &wrong_root),
            "proof should reject wrong root"
        );
    }

    #[test]
    fn merkle_deterministic() {
        let leaves: Vec<String> = (0..10).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root1 = compute_merkle_root(&leaves).unwrap();
        let root2 = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root1, root2, "same input must produce same root");
    }

    #[test]
    fn merkle_node_hash_uses_domain_separation_prefix() {
        // §1.6: domain-separation prefix `gvm-node-v1:` MUST be present
        // in every internal-node hash. Removing the prefix would silently
        // break hash universality across contexts but produce mathemati-
        // cally valid output. This test pins the contract by hashing
        // two leaves with AND without the prefix and asserting the
        // production result matches the prefixed variant only.
        let a = hash_str("event_a");
        let b = hash_str("event_b");
        let root =
            compute_merkle_root(&[a.clone(), b.clone()]).expect("two-leaf root must compute");

        // Same hash, NO domain prefix.
        let no_prefix = {
            let mut h = Sha256::new();
            h.update(decode_hash(&a));
            h.update(decode_hash(&b));
            hex::encode(h.finalize())
        };

        // Same hash, WRONG (different) domain prefix.
        let wrong_prefix = {
            let mut h = Sha256::new();
            h.update(b"gvm-node-v2:");
            h.update(decode_hash(&a));
            h.update(decode_hash(&b));
            hex::encode(h.finalize())
        };

        // Same hash, CORRECT prefix.
        let with_prefix = {
            let mut h = Sha256::new();
            h.update(b"gvm-node-v1:");
            h.update(decode_hash(&a));
            h.update(decode_hash(&b));
            hex::encode(h.finalize())
        };

        assert_eq!(
            root, with_prefix,
            "production node hash MUST include the `gvm-node-v1:` prefix"
        );
        assert_ne!(
            root, no_prefix,
            "regression: production node hash matches the no-prefix variant — \
             prefix is no longer load-bearing"
        );
        assert_ne!(
            root, wrong_prefix,
            "regression: production node hash matches a different prefix — \
             version pinning is broken"
        );
    }

    #[test]
    fn merkle_event_hash_uses_domain_separation_prefix() {
        // §1.6 sibling test for compute_event_hash.
        let event = GVMEvent {
            event_id: "deadbeef".to_string(),
            trace_id: "cafebabe".to_string(),
            parent_event_id: None,
            agent_id: "agent-x".to_string(),
            tenant_id: None,
            session_id: "sess".to_string(),
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            operation: "gvm.test.op".to_string(),
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
        };
        let prod_hash = compute_event_hash(&event);

        // Build same hash WITHOUT the domain prefix.
        let no_prefix = {
            let mut h = Sha256::new();
            for field in &[
                event.event_id.as_str(),
                event.trace_id.as_str(),
                event.agent_id.as_str(),
                event.operation.as_str(),
                event.decision.as_str(),
                event.decision_source.as_str(),
                &format!("{:?}", event.status),
                event.enforcement_point.as_str(),
                &event.timestamp.to_rfc3339(),
                event.payload.content_hash.as_str(),
            ] {
                h.update((field.len() as u32).to_le_bytes());
                h.update(field.as_bytes());
            }
            hex::encode(h.finalize())
        };
        assert_ne!(
            prod_hash, no_prefix,
            "regression: compute_event_hash output equals the no-prefix variant — \
             `gvm-event-v1:` prefix is no longer applied"
        );
    }

    #[test]
    fn merkle_different_order_different_root() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let root_ab = compute_merkle_root(&[a.clone(), b.clone()]).unwrap();
        let root_ba = compute_merkle_root(&[b, a]).unwrap();
        assert_ne!(root_ab, root_ba, "order must matter");
    }

    // ─── Phase 1 — event_hash dispatcher (v1/v2) ────────────────

    fn make_test_event(operation: &str) -> GVMEvent {
        GVMEvent {
            event_id: "evt-001".to_string(),
            trace_id: "trace-001".to_string(),
            parent_event_id: None,
            agent_id: "agent-1".to_string(),
            tenant_id: None,
            session_id: "sess".to_string(),
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-05-02T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            operation: operation.to_string(),
            resource: ResourceDescriptor::default(),
            context: HashMap::new(),
            transport: None,
            decision: "Allow".to_string(),
            decision_source: "SRR".to_string(),
            matched_rule_id: None,
            enforcement_point: "proxy".to_string(),
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

    #[test]
    fn dispatcher_uses_v1_when_descriptor_is_none() {
        // Legacy event (no descriptor) MUST hash through v1 path.
        // Pin that the dispatcher returns the same value as the old
        // monolithic compute_event_hash would have, so existing WAL
        // entries continue to verify after this commit lands.
        let event = make_test_event("POST /api/v1/x");
        assert!(event.operation_descriptor.is_none());
        let dispatched = compute_event_hash(&event);
        let v1_direct = super::compute_event_hash_v1(&event);
        assert_eq!(dispatched, v1_direct, "None descriptor must dispatch to v1");
    }

    #[test]
    fn dispatcher_uses_v2_when_descriptor_present() {
        let mut event = make_test_event("POST /api/v1/x");
        let desc = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/x".to_string()),
            vec![1u8; 16],
        );
        event.operation_descriptor = Some(desc.clone());

        let dispatched = compute_event_hash(&event);
        let v2_direct = compute_event_hash_v2(&event, &desc);
        assert_eq!(dispatched, v2_direct, "Some descriptor must dispatch to v2");
    }

    #[test]
    fn v1_and_v2_produce_distinct_hashes_for_same_event() {
        // Domain-separation prefix differs, so even with the same
        // logical event content the two algorithms produce different
        // hashes. This is intentional — verifiers MUST know which
        // version they're using and not silently accept either.
        let mut event = make_test_event("POST /api/v1/x");
        let desc = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/x".to_string()),
            vec![1u8; 16],
        );
        let v1 = compute_event_hash_v1(&event);
        event.operation_descriptor = Some(desc.clone());
        let v2 = compute_event_hash_v2(&event, &desc);
        assert_ne!(v1, v2, "v1 and v2 hashes must be distinct");
    }

    #[test]
    fn v2_hash_redaction_preserving_property() {
        // The privacy goal: redacting (detail, salt) from the
        // descriptor MUST NOT change the v2 hash output, because
        // the hash uses detail_digest (which survives redaction).
        let event = make_test_event("POST /api/v1/secret");
        let salt = vec![42u8; 16];
        let full = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/secret".to_string()),
            salt,
        );
        let redacted = gvm_types::OperationDescriptor {
            category: full.category.clone(),
            detail: None,
            detail_salt: Vec::new(),
            detail_digest: full.detail_digest.clone(),
        };

        let h_full = compute_event_hash_v2(&event, &full);
        let h_redacted = compute_event_hash_v2(&event, &redacted);
        assert_eq!(
            h_full, h_redacted,
            "v2 hash must be invariant under detail/salt redaction \
             when detail_digest is preserved"
        );
    }

    #[test]
    fn v2_hash_changes_with_different_detail_digest() {
        let event = make_test_event("POST /api/v1/x");
        let d1 = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/x".to_string()),
            vec![1u8; 16],
        );
        let d2 = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/x".to_string()),
            vec![2u8; 16], // different salt → different digest
        );
        assert_ne!(d1.detail_digest, d2.detail_digest);

        let h1 = compute_event_hash_v2(&event, &d1);
        let h2 = compute_event_hash_v2(&event, &d2);
        assert_ne!(h1, h2, "different detail_digest must affect v2 hash");
    }

    #[test]
    fn v2_hash_uses_category_not_legacy_operation() {
        // Two events: same category, different legacy operation.
        // v2 hash must NOT depend on the legacy operation field.
        let mut e1 = make_test_event("POST /api/v1/x");
        let mut e2 = make_test_event("DIFFERENT_LEGACY_STRING");
        let desc = gvm_types::OperationDescriptor::new(
            "http.POST",
            Some("/api/v1/x".to_string()),
            vec![5u8; 16],
        );
        e1.operation_descriptor = Some(desc.clone());
        e2.operation_descriptor = Some(desc.clone());
        let h1 = compute_event_hash(&e1);
        let h2 = compute_event_hash(&e2);
        assert_eq!(
            h1, h2,
            "v2 hash must be independent of legacy operation field — \
             event.operation should NOT be in canonical input"
        );
    }
}
