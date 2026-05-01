//! Tests for Phase 2 anchor foundation:
//!   - BatchSealRecord seal_hash determinism + domain separation
//!   - GvmStateAnchor compute_hash + verify_self_hash
//!   - MerkleBatchRecord leaves_blob invariants + zero-copy iteration
//!   - GENESIS_HASH_HEX bootstrap convention
//!
//! These types are not yet wired into the group commit task — that is
//! the next session's work. This file pins the type-level contracts so
//! the wiring step has a stable target to integrate against.

use chrono::TimeZone;
use gvm_types::{
    BatchSealRecord, GvmStateAnchor, LeavesFormat, MerkleBatchRecord, GENESIS_HASH_HEX,
    PREFIX_ANCHOR_V1, PREFIX_SEAL_V1,
};

// ────────────────────────────────────────────────────────────────────
// Genesis sentinel
// ────────────────────────────────────────────────────────────────────

#[test]
fn genesis_hash_hex_is_64_zero_chars() {
    assert_eq!(GENESIS_HASH_HEX.len(), 64);
    assert!(GENESIS_HASH_HEX.chars().all(|c| c == '0'));
}

#[test]
fn domain_prefixes_are_versioned_and_distinct() {
    // §1.6 — every hash function uses a distinct, versioned prefix.
    // Catching prefix collision early prevents cross-context hash reuse.
    assert_ne!(PREFIX_SEAL_V1, PREFIX_ANCHOR_V1);
    assert!(PREFIX_SEAL_V1.starts_with(b"gvm-"));
    assert!(PREFIX_ANCHOR_V1.starts_with(b"gvm-"));
    assert!(PREFIX_SEAL_V1.ends_with(b":"));
    assert!(PREFIX_ANCHOR_V1.ends_with(b":"));
}

// ────────────────────────────────────────────────────────────────────
// BatchSealRecord
// ────────────────────────────────────────────────────────────────────

fn fixed_seal(seal_id: u64) -> BatchSealRecord {
    BatchSealRecord {
        seal_id,
        sealed_at: chrono::Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap(),
        context_hash: "a".repeat(64),
        checkpoint_root: Some("b".repeat(64)),
        prev_anchor: Some("c".repeat(64)),
    }
}

#[test]
fn seal_hash_is_deterministic_across_calls() {
    let seal = fixed_seal(7);
    let h1 = seal.seal_hash();
    let h2 = seal.seal_hash();
    assert_eq!(
        h1, h2,
        "seal_hash must be a pure function of the seal fields"
    );
}

#[test]
fn seal_hash_changes_when_any_field_changes() {
    let base = fixed_seal(1);
    let h_base = base.seal_hash();

    // Mutate each canonical field in turn — every change MUST produce
    // a different hash. This pins the "every field is in canonical
    // input" contract.
    let mut s = base.clone();
    s.seal_id = 2;
    assert_ne!(s.seal_hash(), h_base, "seal_id must affect seal_hash");

    let mut s = base.clone();
    s.sealed_at = base.sealed_at + chrono::Duration::seconds(1);
    assert_ne!(s.seal_hash(), h_base, "sealed_at must affect seal_hash");

    let mut s = base.clone();
    s.context_hash = "z".repeat(64);
    assert_ne!(s.seal_hash(), h_base, "context_hash must affect seal_hash");

    let mut s = base.clone();
    s.checkpoint_root = Some("z".repeat(64));
    assert_ne!(
        s.seal_hash(),
        h_base,
        "checkpoint_root must affect seal_hash"
    );

    let mut s = base.clone();
    s.prev_anchor = Some("z".repeat(64));
    assert_ne!(s.seal_hash(), h_base, "prev_anchor must affect seal_hash");
}

#[test]
fn seal_hash_treats_none_as_genesis_sentinel() {
    // checkpoint_root = None and Some(GENESIS_HASH_HEX) MUST produce
    // the same seal_hash (genesis substitution rule).
    let mut none_seal = fixed_seal(0);
    none_seal.checkpoint_root = None;
    none_seal.prev_anchor = None;

    let mut sentinel_seal = fixed_seal(0);
    sentinel_seal.checkpoint_root = Some(GENESIS_HASH_HEX.to_string());
    sentinel_seal.prev_anchor = Some(GENESIS_HASH_HEX.to_string());

    assert_eq!(
        none_seal.seal_hash(),
        sentinel_seal.seal_hash(),
        "None must canonicalize to GENESIS_HASH_HEX in seal_hash input — \
         both must produce identical hash"
    );
}

#[test]
fn seal_hash_includes_domain_prefix() {
    // Without the gvm-seal-v1: prefix, two seals from different
    // contexts could collide. We pin that the prefix is load-bearing
    // by computing the same fields with a no-prefix raw hasher and
    // asserting they DIFFER.
    use sha2::{Digest, Sha256};
    let seal = fixed_seal(42);
    let prefixed = seal.seal_hash();

    let no_prefix: [u8; 32] = {
        let mut h = Sha256::new();
        for f in [
            &seal.seal_id.to_le_bytes()[..],
            &seal.sealed_at.timestamp().to_le_bytes(),
            seal.context_hash.as_bytes(),
            seal.checkpoint_root
                .as_deref()
                .unwrap_or(GENESIS_HASH_HEX)
                .as_bytes(),
            seal.prev_anchor
                .as_deref()
                .unwrap_or(GENESIS_HASH_HEX)
                .as_bytes(),
        ] {
            h.update((f.len() as u32).to_le_bytes());
            h.update(f);
        }
        h.finalize().into()
    };

    assert_ne!(
        prefixed, no_prefix,
        "gvm-seal-v1: prefix must be load-bearing"
    );
}

#[test]
fn seal_hash_hex_is_64_chars_lowercase() {
    let seal = fixed_seal(3);
    let hex = seal.seal_hash_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

// ────────────────────────────────────────────────────────────────────
// GvmStateAnchor
// ────────────────────────────────────────────────────────────────────

#[test]
fn anchor_seal_produces_self_consistent_hash() {
    let seal = fixed_seal(11);
    let anchor = GvmStateAnchor::seal(1, &seal, "d".repeat(64));
    assert!(
        anchor.verify_self_hash(),
        "freshly-sealed anchor must have a self-consistent anchor_hash"
    );
    assert_eq!(anchor.batch_id, seal.seal_id);
    assert_eq!(anchor.timestamp, seal.sealed_at);
    assert_eq!(anchor.context_hash, seal.context_hash);
    assert!(
        anchor.signature.is_none(),
        "Phase 2 anchors are unsigned by default"
    );
}

#[test]
fn anchor_verify_self_hash_detects_field_tamper() {
    let seal = fixed_seal(11);
    let mut anchor = GvmStateAnchor::seal(1, &seal, "d".repeat(64));

    anchor.context_hash = "tampered".repeat(8); // 64 chars
    assert!(
        !anchor.verify_self_hash(),
        "verify_self_hash must reject in-place context_hash tamper"
    );
}

#[test]
fn anchor_genesis_substitution_for_none_fields() {
    // First-anchor case: prev_anchor = None and checkpoint_root = None.
    // GENESIS_HASH_HEX substitution must keep hash deterministic.
    let mut seal = fixed_seal(0);
    seal.prev_anchor = None;
    seal.checkpoint_root = None;
    let a1 = GvmStateAnchor::seal(1, &seal, "r".repeat(64));

    let mut seal2 = fixed_seal(0);
    seal2.prev_anchor = Some(GENESIS_HASH_HEX.to_string());
    seal2.checkpoint_root = Some(GENESIS_HASH_HEX.to_string());
    let a2 = GvmStateAnchor::seal(1, &seal2, "r".repeat(64));

    assert_eq!(
        a1.anchor_hash, a2.anchor_hash,
        "None and Some(GENESIS_HASH_HEX) must produce identical anchor_hash"
    );
}

#[test]
fn anchor_chain_link_changes_hash() {
    // Two anchors with otherwise identical content but different
    // prev_anchor must produce different anchor_hash.
    let seal_a = BatchSealRecord {
        prev_anchor: Some("a".repeat(64)),
        ..fixed_seal(5)
    };
    let seal_b = BatchSealRecord {
        prev_anchor: Some("b".repeat(64)),
        ..fixed_seal(5)
    };

    let a = GvmStateAnchor::seal(1, &seal_a, "r".repeat(64));
    let b = GvmStateAnchor::seal(1, &seal_b, "r".repeat(64));
    assert_ne!(
        a.anchor_hash, b.anchor_hash,
        "different prev_anchor must yield different anchor_hash"
    );
}

#[test]
fn anchor_serde_roundtrip_preserves_self_hash() {
    let seal = fixed_seal(99);
    let original = GvmStateAnchor::seal(1, &seal, "f".repeat(64));
    let json = serde_json::to_string(&original).unwrap();
    let parsed: GvmStateAnchor = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.anchor_hash, original.anchor_hash);
    assert!(
        parsed.verify_self_hash(),
        "round-tripped anchor must still verify"
    );
}

// ────────────────────────────────────────────────────────────────────
// MerkleBatchRecord — leaves_blob invariants + zero-copy iter
// ────────────────────────────────────────────────────────────────────

fn make_batch_record(events: usize, with_seal: bool) -> MerkleBatchRecord {
    let leaf_count = if with_seal { events + 1 } else { events };
    let blob: Vec<u8> = (0..(leaf_count * 32)).map(|i| (i % 256) as u8).collect();
    MerkleBatchRecord {
        batch_id: 1,
        merkle_root: "r".repeat(64),
        prev_batch_root: None,
        event_count: events,
        timestamp: chrono::Utc::now(),
        leaves_blob: blob,
        seal_position: if with_seal { Some(events) } else { None },
        leaves_format: if with_seal {
            Some(LeavesFormat::Sha256Concat)
        } else {
            None
        },
    }
}

#[test]
fn legacy_batch_passes_invariant_with_empty_blob() {
    let mut rec = make_batch_record(5, false);
    rec.leaves_blob = Vec::new();
    rec.seal_position = None;
    rec.leaves_format = None;
    rec.validate_leaves_invariant()
        .expect("legacy form must pass");
}

#[test]
fn legacy_batch_with_orphan_seal_position_fails() {
    let mut rec = make_batch_record(0, false);
    rec.leaves_blob = Vec::new();
    rec.seal_position = Some(0); // orphan
    let err = rec.validate_leaves_invariant().unwrap_err();
    assert!(err.contains("seal_position"));
}

#[test]
fn phase2_batch_with_correct_invariant_passes() {
    let rec = make_batch_record(10, true);
    rec.validate_leaves_invariant()
        .expect("phase 2 batch must pass");
    assert_eq!(rec.leaves_blob.len(), 11 * 32);
    assert_eq!(rec.seal_position, Some(10));
}

#[test]
fn phase2_batch_with_wrong_seal_position_fails() {
    let mut rec = make_batch_record(10, true);
    rec.seal_position = Some(5); // not at end
    let err = rec.validate_leaves_invariant().unwrap_err();
    assert!(err.contains("seal_position"));
}

#[test]
fn phase2_batch_with_non_multiple_of_32_blob_fails() {
    let mut rec = make_batch_record(10, true);
    rec.leaves_blob.push(0xAA); // 11*32 + 1 bytes
    let err = rec.validate_leaves_invariant().unwrap_err();
    assert!(err.contains("multiple of 32"));
}

#[test]
fn phase2_batch_with_wrong_blob_length_fails() {
    let mut rec = make_batch_record(10, true);
    rec.event_count = 5; // claim 5 events but blob has 11 leaves
    let err = rec.validate_leaves_invariant().unwrap_err();
    assert!(err.contains("expected"));
}

#[test]
fn leaves_iter_is_zero_copy_chunks_exact() {
    // §② — chunks_exact(32) means we never allocate during iteration.
    // Verify by asserting that iterating produces 32-byte slices
    // pointing into the original blob (compare addresses).
    let rec = make_batch_record(3, true);
    let blob_ptr = rec.leaves_blob.as_ptr() as usize;
    let mut count = 0;
    for (i, leaf) in rec.leaves_iter().enumerate() {
        assert_eq!(leaf.len(), 32);
        let leaf_ptr = leaf.as_ptr() as usize;
        let offset = leaf_ptr - blob_ptr;
        assert_eq!(
            offset,
            i * 32,
            "leaf {} must point to blob offset {} (zero-copy)",
            i,
            i * 32
        );
        count += 1;
    }
    assert_eq!(count, 4, "3 events + 1 seal = 4 leaves");
}

#[test]
fn leaf_index_access_returns_correct_slice() {
    let rec = make_batch_record(3, true);
    // Leaf 0 starts at byte 0, leaf 1 at byte 32, leaf 2 at byte 64,
    // seal leaf at byte 96.
    let l0 = rec.leaf(0).expect("leaf 0");
    assert_eq!(l0[0], 0); // (0 % 256)
    assert_eq!(l0[31], 31);

    let l_seal = rec.leaf(3).expect("seal leaf");
    assert_eq!(l_seal[0], 96u8); // byte at offset 96 == 96 % 256 == 96

    assert!(rec.leaf(4).is_none(), "out of range");
}

#[test]
fn seal_leaf_returns_last_leaf_when_present() {
    let rec = make_batch_record(2, true);
    let seal_leaf = rec.seal_leaf().expect("seal_leaf must be present");
    let direct = rec.leaf(2).unwrap();
    assert_eq!(
        seal_leaf, direct,
        "seal_leaf must match leaf at seal_position"
    );
}

#[test]
fn seal_leaf_is_none_for_legacy_batches() {
    let rec = make_batch_record(0, false);
    let mut legacy = rec.clone();
    legacy.leaves_blob = Vec::new();
    legacy.seal_position = None;
    assert!(legacy.seal_leaf().is_none());
}

#[test]
fn merkle_batch_record_serde_roundtrip_omits_legacy_fields() {
    // Backward compat: a legacy MerkleBatchRecord (no leaves_blob /
    // seal_position / leaves_format) must serialize WITHOUT those
    // fields, so old WAL readers don't see unknown keys.
    let mut rec = make_batch_record(5, false);
    rec.leaves_blob = Vec::new();
    rec.seal_position = None;
    rec.leaves_format = None;
    let json = serde_json::to_string(&rec).unwrap();
    assert!(
        !json.contains("leaves_blob"),
        "legacy form must omit leaves_blob"
    );
    assert!(!json.contains("seal_position"));
    assert!(!json.contains("leaves_format"));

    let reparsed: MerkleBatchRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(reparsed.leaves_blob.len(), 0);
    assert!(reparsed.seal_position.is_none());
    assert!(reparsed.leaves_format.is_none());
}
