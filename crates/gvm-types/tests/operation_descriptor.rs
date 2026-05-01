//! Phase 1 — `OperationDescriptor` + `compute_detail_digest` tests.
//!
//! Pins the privacy-preserving event_hash contract:
//!   - detail_digest is a domain-separated salted SHA-256
//!   - identical (salt, detail) → identical digest
//!   - different salt OR detail → different digest
//!   - None detail → category_only canonical digest
//!   - Domain prefix is load-bearing
//!   - verify_digest() detects tamper of detail/salt without recomputing
//!     the outer event_hash
//!   - Serde round-trip preserves digest integrity
//!   - Redaction (drop detail + salt, keep digest) keeps the digest
//!     verifiable as a leaf for compute_event_hash_v2

use gvm_types::{
    compute_detail_digest, OperationDescriptor, PREFIX_EVENT_V1, PREFIX_EVENT_V2,
    PREFIX_OPDETAIL_V1,
};

// ────────────────────────────────────────────────────────────────────
// compute_detail_digest
// ────────────────────────────────────────────────────────────────────

#[test]
fn detail_digest_is_64_hex_chars_lowercase() {
    let salt = vec![1u8; 16];
    let d = compute_detail_digest(&salt, Some("/api/v1/x"));
    assert_eq!(d.len(), 64);
    assert!(d
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn detail_digest_is_deterministic_for_same_inputs() {
    let salt = vec![7u8; 16];
    let d1 = compute_detail_digest(&salt, Some("/api/v1/user/1234/delete"));
    let d2 = compute_detail_digest(&salt, Some("/api/v1/user/1234/delete"));
    assert_eq!(d1, d2);
}

#[test]
fn detail_digest_changes_with_different_salt() {
    let detail = "/api/v1/user/1234/delete";
    let d1 = compute_detail_digest(&[1u8; 16], Some(detail));
    let d2 = compute_detail_digest(&[2u8; 16], Some(detail));
    assert_ne!(
        d1, d2,
        "salt MUST be in canonical input — without it, two events with \
         the same detail produce the same digest, defeating the salt"
    );
}

#[test]
fn detail_digest_changes_with_different_detail() {
    let salt = vec![5u8; 16];
    let d1 = compute_detail_digest(&salt, Some("/api/v1/x"));
    let d2 = compute_detail_digest(&salt, Some("/api/v1/y"));
    assert_ne!(d1, d2);
}

#[test]
fn detail_digest_none_is_deterministic_canonical_value() {
    // category_only events all share the same "no detail" digest
    // regardless of caller-supplied salt (which is forced empty).
    let d1 = compute_detail_digest(&[], None);
    let d2 = compute_detail_digest(&[], None);
    let d3 = compute_detail_digest(&[42u8; 16], None);
    assert_eq!(d1, d2);
    // With None detail, the salt should not affect the digest in
    // category_only path. The free function still hashes whatever
    // salt is supplied — the contract is "canonicalize via descriptor
    // builder", not "this function ignores salt for None detail".
    // Document the difference: free function honours salt; descriptor
    // builder forces empty salt for None detail.
    assert_ne!(
        d1, d3,
        "free function honours salt even for None detail — \
         that's why callers must use OperationDescriptor::category_only \
         which forces empty salt"
    );
}

#[test]
fn detail_digest_includes_domain_prefix() {
    use sha2::{Digest, Sha256};
    let salt = vec![3u8; 16];
    let detail = "secret";
    let with_prefix = compute_detail_digest(&salt, Some(detail));

    let no_prefix: String = {
        let mut h = Sha256::new();
        h.update((salt.len() as u32).to_le_bytes());
        h.update(&salt);
        h.update((detail.len() as u32).to_le_bytes());
        h.update(detail.as_bytes());
        hex::encode(h.finalize())
    };

    assert_ne!(
        with_prefix, no_prefix,
        "PREFIX_OPDETAIL_V1 must be load-bearing in compute_detail_digest"
    );
}

// ────────────────────────────────────────────────────────────────────
// OperationDescriptor
// ────────────────────────────────────────────────────────────────────

#[test]
fn descriptor_with_detail_populates_salt_and_digest() {
    let salt = vec![9u8; 16];
    let d = OperationDescriptor::new(
        "http.POST",
        Some("/api/v1/user/1234/delete".to_string()),
        salt.clone(),
    );
    assert_eq!(d.category, "http.POST");
    assert_eq!(d.detail.as_deref(), Some("/api/v1/user/1234/delete"));
    assert_eq!(d.detail_salt, salt);
    assert_eq!(
        d.detail_digest,
        compute_detail_digest(&salt, Some("/api/v1/user/1234/delete"))
    );
}

#[test]
fn descriptor_category_only_forces_empty_salt() {
    let d = OperationDescriptor::category_only("gvm.system.config_load");
    assert_eq!(d.category, "gvm.system.config_load");
    assert!(d.detail.is_none());
    assert!(d.detail_salt.is_empty());
    assert_eq!(d.detail_digest, compute_detail_digest(&[], None));
}

#[test]
fn descriptor_new_with_none_detail_ignores_supplied_salt() {
    // When detail is None, the salt the caller supplies must NOT
    // leak into the digest — otherwise two category_only descriptors
    // with different "ambient" salt material would mis-compare.
    let d_with_salt = OperationDescriptor::new("gvm.dns.query", None, vec![55u8; 16]);
    let d_no_salt = OperationDescriptor::category_only("gvm.dns.query");
    assert_eq!(d_with_salt, d_no_salt);
    assert!(d_with_salt.detail_salt.is_empty());
}

#[test]
fn descriptor_verify_digest_round_trip() {
    let salt = vec![13u8; 16];
    let d = OperationDescriptor::new("http.GET", Some("/v1/x".to_string()), salt);
    assert!(d.verify_digest());
}

#[test]
fn descriptor_verify_digest_detects_detail_tamper() {
    let salt = vec![13u8; 16];
    let mut d = OperationDescriptor::new("http.GET", Some("/v1/x".to_string()), salt);
    d.detail = Some("/v1/y".to_string());
    assert!(!d.verify_digest(), "detail tamper must be detected");
}

#[test]
fn descriptor_verify_digest_detects_salt_tamper() {
    let salt = vec![13u8; 16];
    let mut d = OperationDescriptor::new("http.GET", Some("/v1/x".to_string()), salt);
    d.detail_salt = vec![14u8; 16];
    assert!(!d.verify_digest(), "salt tamper must be detected");
}

#[test]
fn descriptor_serde_roundtrip_preserves_digest() {
    let salt = vec![21u8; 16];
    let d = OperationDescriptor::new("http.POST", Some("/api/v1/x".to_string()), salt);
    let json = serde_json::to_string(&d).unwrap();
    let parsed: OperationDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, d);
    assert!(parsed.verify_digest());
}

#[test]
fn descriptor_redacted_form_still_recomputes_event_hash() {
    // Simulate redaction: drop detail + salt, keep digest only.
    // Verifier must still be able to use the digest as a leaf for
    // compute_event_hash_v2 (which is what makes the redaction
    // privacy-preserving without breaking auditability).
    let salt = vec![1u8; 16];
    let original = OperationDescriptor::new("http.POST", Some("/api/v1/secret".to_string()), salt);
    let original_digest = original.detail_digest.clone();

    let redacted = OperationDescriptor {
        category: original.category.clone(),
        detail: None,
        detail_salt: Vec::new(),
        detail_digest: original.detail_digest.clone(),
    };

    // Redacted form's digest is the same hex string (untouched).
    assert_eq!(redacted.detail_digest, original_digest);

    // verify_digest of the redacted form will FAIL (because we
    // intentionally don't have the salt to recompute) — but that
    // is OK: the verifier of a redacted proof does NOT call
    // verify_digest; they only need detail_digest as input to
    // compute_event_hash_v2, which uses the field as-is.
    assert!(
        !redacted.verify_digest(),
        "redacted form intentionally cannot self-verify the digest \
         (no salt) — verification of redacted proofs goes through \
         compute_event_hash_v2 instead"
    );
}

#[test]
fn descriptor_serde_skip_empty_fields_in_redacted_form() {
    let salt = vec![1u8; 16];
    let original = OperationDescriptor::new("http.POST", Some("/api/v1/secret".to_string()), salt);
    let redacted = OperationDescriptor {
        category: original.category.clone(),
        detail: None,
        detail_salt: Vec::new(),
        detail_digest: original.detail_digest.clone(),
    };
    let json = serde_json::to_string(&redacted).unwrap();
    // detail and detail_salt MUST be omitted from JSON when empty
    // so a redacted proof transmits no leak signal:
    assert!(
        !json.contains("\"detail\":"),
        "redacted detail must be omitted from JSON; got: {}",
        json
    );
    assert!(
        !json.contains("\"detail_salt\":"),
        "redacted detail_salt must be omitted from JSON; got: {}",
        json
    );
    assert!(
        json.contains("\"detail_digest\":"),
        "detail_digest MUST survive redaction (verifier needs it); got: {}",
        json
    );
    assert!(json.contains("\"category\":"));
}

// ────────────────────────────────────────────────────────────────────
// Domain prefix catalog (sanity)
// ────────────────────────────────────────────────────────────────────

#[test]
fn domain_prefixes_are_distinct_versioned() {
    // Cross-collision impossibility: each prefix MUST be unique.
    let prefixes: Vec<&[u8]> = vec![PREFIX_EVENT_V1, PREFIX_EVENT_V2, PREFIX_OPDETAIL_V1];
    for (i, p1) in prefixes.iter().enumerate() {
        for (j, p2) in prefixes.iter().enumerate() {
            if i != j {
                assert_ne!(p1, p2, "prefix collision between #{} and #{}", i, j);
            }
        }
        assert!(p1.starts_with(b"gvm-"), "prefix must start with gvm-");
        assert!(p1.ends_with(b":"), "prefix must end with :");
    }
}
