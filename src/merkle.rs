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

use sha2::{Digest, Sha256};
use crate::types::{GVMEvent, MerkleBatchRecord};

// ─── Event Hash Computation ───

/// Compute the SHA-256 hash of an event's audit-critical fields.
///
/// Fields included: event_id, trace_id, agent_id, operation, decision,
/// decision_source, status, enforcement_point, timestamp, payload.content_hash.
///
/// These fields cover all audit-significant properties. In particular,
/// `status` prevents undetected Pending→Confirmed tampering, and
/// `decision_source` / `enforcement_point` prevent attribution falsification.
pub fn compute_event_hash(event: &GVMEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(b"|");
    hasher.update(event.trace_id.as_bytes());
    hasher.update(b"|");
    hasher.update(event.agent_id.as_bytes());
    hasher.update(b"|");
    hasher.update(event.operation.as_bytes());
    hasher.update(b"|");
    hasher.update(event.decision.as_bytes());
    hasher.update(b"|");
    hasher.update(event.decision_source.as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{:?}", event.status).as_bytes());
    hasher.update(b"|");
    hasher.update(event.enforcement_point.as_bytes());
    hasher.update(b"|");
    hasher.update(event.timestamp.to_rfc3339().as_bytes());
    hasher.update(b"|");
    hasher.update(event.payload.content_hash.as_bytes());
    hex::encode(hasher.finalize())
}

// ─── Merkle Tree Computation ───

/// Compute the Merkle root from a list of hex-encoded leaf hashes.
/// For a single leaf, the root is the leaf itself.
/// For an odd number of leaves, the last leaf is duplicated.
pub fn compute_merkle_root(leaf_hashes: &[String]) -> String {
    assert!(!leaf_hashes.is_empty(), "cannot compute merkle root of empty set");

    let mut current_level: Vec<[u8; 32]> = leaf_hashes
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("leaf hash must be valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
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

    hex::encode(current_level[0])
}

/// Generate a Merkle proof (sibling hashes + directions) for a leaf at `index`.
/// Returns a list of (sibling_hash, is_right) pairs, from leaf to root.
pub fn generate_merkle_proof(leaf_hashes: &[String], index: usize) -> Vec<(String, bool)> {
    assert!(index < leaf_hashes.len(), "index out of bounds");

    let mut current_level: Vec<[u8; 32]> = leaf_hashes
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("leaf hash must be valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    let mut proof = Vec::new();
    let mut idx = index;

    while current_level.len() > 1 {
        // Pad with duplicate if odd number of nodes at this level.
        // This means for the last leaf at an odd level, its sibling in the
        // proof will be itself (a duplicate). This is the standard Bitcoin
        // Merkle tree behavior and is intentional — it preserves the
        // property that every node has a sibling for proof construction.
        if current_level.len() % 2 == 1 {
            let last = *current_level.last().expect("merkle proof: level is non-empty (checked by while condition)");
            current_level.push(last);
        }

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let is_right = idx % 2 == 0; // sibling is on the right
        proof.push((hex::encode(current_level[sibling_idx]), is_right));

        // Build next level
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            let hash: [u8; 32] = hasher.finalize().into();
            next_level.push(hash);
        }

        current_level = next_level;
        idx /= 2;
    }

    proof
}

/// Verify a Merkle proof for a given leaf hash against an expected root.
pub fn verify_merkle_proof(leaf_hash: &str, proof: &[(String, bool)], expected_root: &str) -> bool {
    let mut current = match hex::decode(leaf_hash) {
        Ok(bytes) => {
            let mut arr = [0u8; 32];
            if bytes.len() != 32 { return false; }
            arr.copy_from_slice(&bytes);
            arr
        }
        Err(_) => return false,
    };

    for (sibling_hex, is_right) in proof {
        let sibling = match hex::decode(sibling_hex) {
            Ok(bytes) => {
                let mut arr = [0u8; 32];
                if bytes.len() != 32 { return false; }
                arr.copy_from_slice(&bytes);
                arr
            }
            Err(_) => return false,
        };

        let mut hasher = Sha256::new();
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
                let computed_root = compute_merkle_root(&events_in_current_batch);
                if computed_root == batch_record.merkle_root {
                    valid_batches += 1;
                } else {
                    invalid_batches.push(batch_record.batch_id);
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

    fn hash_str(s: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        hex::encode(hasher.finalize())
    }

    #[test]
    fn merkle_single_leaf() {
        let leaf = hash_str("event_1");
        let root = compute_merkle_root(&[leaf.clone()]);
        assert_eq!(root, leaf, "single leaf should be its own root");
    }

    #[test]
    fn merkle_two_leaves() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let root = compute_merkle_root(&[a.clone(), b.clone()]);

        // Manual: H(a || b)
        let mut hasher = Sha256::new();
        hasher.update(hex::decode(&a).expect("test hash 'a' must be valid hex"));
        hasher.update(hex::decode(&b).expect("test hash 'b' must be valid hex"));
        let expected = hex::encode(hasher.finalize());

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_odd_leaves_duplicates_last() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let c = hash_str("event_3");
        let root = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]);

        // Manual: H(H(a,b), H(c,c))
        let mut h_ab = Sha256::new();
        h_ab.update(hex::decode(&a).expect("test hash 'a' must be valid hex"));
        h_ab.update(hex::decode(&b).expect("test hash 'b' must be valid hex"));
        let hab: [u8; 32] = h_ab.finalize().into();

        let mut h_cc = Sha256::new();
        h_cc.update(hex::decode(&c).expect("test hash 'c' must be valid hex"));
        h_cc.update(hex::decode(&c).expect("test hash 'c' must be valid hex"));
        let hcc: [u8; 32] = h_cc.finalize().into();

        let mut h_root = Sha256::new();
        h_root.update(hab);
        h_root.update(hcc);
        let expected = hex::encode(h_root.finalize());

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_four_leaves_balanced() {
        let leaves: Vec<String> = (0..4).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root = compute_merkle_root(&leaves);

        // Manually compute balanced tree
        let mut h01 = Sha256::new();
        h01.update(hex::decode(&leaves[0]).expect("test leaf hash must be valid hex"));
        h01.update(hex::decode(&leaves[1]).expect("test leaf hash must be valid hex"));
        let n01: [u8; 32] = h01.finalize().into();

        let mut h23 = Sha256::new();
        h23.update(hex::decode(&leaves[2]).expect("test leaf hash must be valid hex"));
        h23.update(hex::decode(&leaves[3]).expect("test leaf hash must be valid hex"));
        let n23: [u8; 32] = h23.finalize().into();

        let mut h_root = Sha256::new();
        h_root.update(n01);
        h_root.update(n23);
        let expected = hex::encode(h_root.finalize());

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_proof_verifies_each_leaf() {
        let leaves: Vec<String> = (0..5).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root = compute_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = generate_merkle_proof(&leaves, i);
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
        let root = compute_merkle_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);

        let wrong_leaf = hash_str("tampered_event");
        assert!(
            !verify_merkle_proof(&wrong_leaf, &proof, &root),
            "proof should reject tampered leaf"
        );
    }

    #[test]
    fn merkle_proof_rejects_wrong_root() {
        let leaves: Vec<String> = (0..4).map(|i| hash_str(&format!("event_{}", i))).collect();
        let proof = generate_merkle_proof(&leaves, 0);

        let wrong_root = hash_str("wrong_root");
        assert!(
            !verify_merkle_proof(&leaves[0], &proof, &wrong_root),
            "proof should reject wrong root"
        );
    }

    #[test]
    fn merkle_deterministic() {
        let leaves: Vec<String> = (0..10).map(|i| hash_str(&format!("event_{}", i))).collect();
        let root1 = compute_merkle_root(&leaves);
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root1, root2, "same input must produce same root");
    }

    #[test]
    fn merkle_different_order_different_root() {
        let a = hash_str("event_1");
        let b = hash_str("event_2");
        let root_ab = compute_merkle_root(&[a.clone(), b.clone()]);
        let root_ba = compute_merkle_root(&[b, a]);
        assert_ne!(root_ab, root_ba, "order must matter");
    }
}
