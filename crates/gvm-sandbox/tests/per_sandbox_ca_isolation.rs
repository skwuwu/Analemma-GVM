//! Adversarial isolation tests for per-sandbox MITM CA (`bf0af7e`).
//!
//! security-model.md §21 makes three load-bearing claims about the
//! per-sandbox CA model. Each claim turns into one test below:
//!
//! 1. **Distinct keypair per sandbox** — provisioning two sandboxes
//!    yields two CAs whose pubkey hashes differ. If this fails, the
//!    "compromised sandbox cannot impersonate peer" property collapses
//!    because both CAs would chain to a shared root.
//! 2. **Lookup is sandbox_id-bound** — `lookup(B)` after
//!    `provision(A)` returns `None`, not `A`'s CA. This is the
//!    dispatch primitive the TLS resolver leans on (the resolver
//!    routes by veth source-IP → sandbox_id → CA, and the registry
//!    is the second hop). Routing leakage at the registry would
//!    mean A could be served B's leaf, defeating cross-sandbox MITM
//!    isolation.
//! 3. **Revoke is sandbox_id-scoped** — revoking A leaves B's CA
//!    intact, observable via `lookup(B)`. A revocation that bled
//!    across sandboxes would cause cooperative DoS (operator
//!    cleaning up A as it exits also takes B offline).
//!
//! These are adversarial tests in the sense that they fail-loud the
//! moment a refactor breaks the trust-boundary guarantee — even one
//! shared `Arc` clone or a misnamed key in the DashMap would surface
//! here, not in production.
//!
//! Pure logic tests; no Linux namespace / iptables setup required.
//! Cross-platform.

use gvm_sandbox::ca::CARegistry;

#[test]
fn each_sandbox_gets_a_distinct_keypair() {
    let registry = CARegistry::new();

    let ca_a = registry.provision("sandbox-A").expect("provision A");
    let ca_b = registry.provision("sandbox-B").expect("provision B");

    // Pubkey hashes are SHA-256 of the SubjectPublicKeyInfo DER. If
    // both sandboxes accidentally got the same keypair (e.g. a
    // refactor moved the keygen behind a process-wide cache), the
    // hashes would match and one sandbox could impersonate the other
    // by replaying its own leaf cert. They MUST differ.
    assert_ne!(
        ca_a.pubkey_hash(),
        ca_b.pubkey_hash(),
        "two provisioned sandboxes must hold distinct CA keypairs — \
         shared keypair collapses cross-sandbox isolation"
    );

    // Same property, surfaced via the operator-facing hex form so a
    // failure here also exercises the hex serializer (used by
    // `gvm sandbox list` and the WAL `ca_pubkey_hash` field).
    assert_ne!(ca_a.pubkey_hash_hex(), ca_b.pubkey_hash_hex());

    // The PEM-encoded private keys must also differ. We compare the
    // serialized form rather than just the pubkey to catch a
    // hypothetical regression where the public key was randomized
    // but the private material was deterministic (would still pass
    // the pubkey check).
    assert_ne!(
        ca_a.ca_key_pem(),
        ca_b.ca_key_pem(),
        "private-key material must differ across sandboxes"
    );
}

#[test]
fn lookup_does_not_leak_across_sandbox_ids() {
    let registry = CARegistry::new();
    registry.provision("sandbox-A").expect("provision A");

    // The registry is the dispatch lookup the TLS resolver leans on.
    // Asking for a sandbox that has not been provisioned must return
    // None — never a fallback to "any active CA" or to the most
    // recently inserted one. A lookup that silently returns A's CA
    // when asked for B would let sandbox B negotiate TLS using A's
    // chain, and A's leaf cert would validate.
    let probe = registry.lookup("sandbox-B");
    assert!(
        probe.is_none(),
        "lookup for an unprovisioned sandbox must return None — \
         silent fallback to a peer's CA breaks isolation"
    );

    // Provision B, then verify A's lookup still returns A (not B).
    registry.provision("sandbox-B").expect("provision B");
    let a = registry.lookup("sandbox-A").expect("A still present");
    let b = registry.lookup("sandbox-B").expect("B present");
    assert_eq!(a.sandbox_id(), "sandbox-A");
    assert_eq!(b.sandbox_id(), "sandbox-B");
    assert_ne!(a.pubkey_hash(), b.pubkey_hash());
}

#[test]
fn revoke_is_sandbox_scoped_does_not_take_peers_offline() {
    let registry = CARegistry::new();
    let ca_a = registry.provision("sandbox-A").expect("provision A");
    let ca_b = registry.provision("sandbox-B").expect("provision B");
    let pubkey_a = ca_a.pubkey_hash();
    let pubkey_b = ca_b.pubkey_hash();

    // Sanity — both present before revoke.
    assert_eq!(registry.active_count(), 2);

    // Revoke A. B must still answer lookup, with the same key
    // material we provisioned a moment ago. A revoke that swept B
    // out alongside A — or one that mutated B's keypair — would
    // appear here.
    registry.revoke("sandbox-A");
    assert!(registry.lookup("sandbox-A").is_none(), "A revoked");
    let b_after = registry.lookup("sandbox-B").expect("B still alive");
    assert_eq!(
        b_after.pubkey_hash(),
        pubkey_b,
        "revoking A must not perturb B's CA material"
    );
    assert_ne!(
        b_after.pubkey_hash(),
        pubkey_a,
        "B never inherits A's pubkey on revoke (sanity)"
    );
    assert_eq!(registry.active_count(), 1);
}

#[test]
fn provisioning_n_sandboxes_yields_n_unique_pubkeys() {
    // Spot-check the keygen entropy: 32 distinct sandbox IDs must
    // produce 32 distinct pubkey hashes. A regression that seeded
    // the RNG once at registry construction would surface as
    // duplicates here.
    let registry = CARegistry::new();
    let mut pubkeys = std::collections::HashSet::new();
    for i in 0..32 {
        let id = format!("sandbox-{i:02}");
        let ca = registry.provision(&id).expect("provision");
        let inserted = pubkeys.insert(ca.pubkey_hash());
        assert!(
            inserted,
            "duplicate pubkey on provision #{i} — keygen is not per-sandbox-fresh"
        );
    }
    assert_eq!(pubkeys.len(), 32);
    assert_eq!(registry.active_count(), 32);
}

#[test]
fn rotate_via_reprovision_keeps_id_stable_changes_keypair() {
    // The CARegistry doc says re-`provision`-ing the same id replaces
    // the prior CA — pin that contract: same id, NEW keypair. A
    // refactor that turned re-provision into a no-op (returning the
    // existing Arc) would silently keep a compromised key in
    // service. Failing this test means key rotation broke.
    let registry = CARegistry::new();
    let original = registry.provision("sandbox-X").expect("provision");
    let original_pubkey = original.pubkey_hash();

    let rotated = registry.provision("sandbox-X").expect("rotate");
    assert_eq!(rotated.sandbox_id(), "sandbox-X");
    assert_ne!(
        rotated.pubkey_hash(),
        original_pubkey,
        "re-provisioning the same sandbox_id must mint a fresh keypair"
    );

    // Look up — registry must hand back the rotated one, not the
    // original. The original Arc may still live (in-flight handshake
    // protection), but new lookups go to the new CA.
    let lookup = registry.lookup("sandbox-X").expect("post-rotate lookup");
    assert_eq!(lookup.pubkey_hash(), rotated.pubkey_hash());
    assert_ne!(lookup.pubkey_hash(), original_pubkey);
}
