//! Cooperative intent lease — Tier-3 P3-c Phase 3c regression suite.
//!
//! Phase 3c is **sandbox-IP binding** — implicit lease claim for
//! requests originating from a GVM-allocated sandbox veth IP. The
//! agent registers a cooperative lease through GVM's controlled API
//! (`POST /gvm/intent`), then subsequent requests bind to that lease
//! by network identity rather than by `X-GVM-Context-Token` header.
//! This is the delivery channel for cert-pinned clients that cannot
//! plumb custom headers through TLS.
//!
//! Trust model: the veth IP is allocated by GVM itself; spoofing it
//! would require breaking the same network-namespace isolation that
//! already protects credential separation between sandboxes. Audit
//! tier matches the token-binding path —
//! `cooperative.declared_only` or `cooperative.cross_checked`
//! depending on whether body inspection is enabled.
//!
//! These tests exercise `IntentStore::claim_by_sandbox_binding{,_host}`
//! directly because the proxy hot-path integration requires Linux
//! state files (`/run/gvm/*.state`) which are not available on the
//! Windows CI runner. The store-layer test pins the matching and
//! atomic-state-transition logic, which is where Phase 3c's
//! correctness lives. The proxy hot-path call sites are covered by
//! the existing Phase 2/3a/3b regression files (NoToken arm /
//! sandbox fallback).
//!
//! End-to-end Linux coverage of the proxy hot-path integration
//! belongs in the sandbox-observability stress test, where real
//! veth + state files exist.

use gvm_proxy::intent_store::{IntentRequest, IntentStore};

fn coop(agent: &str, method: &str, host: &str, path: &str) -> IntentRequest {
    IntentRequest {
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        operation: format!("test.{}.{}", agent, method),
        agent_id: agent.to_string(),
        ttl_secs: Some(30),
        payload_context: Some(serde_json::json!({"k": "v"})),
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
    }
}

fn register_coop(store: &IntentStore, req: &IntentRequest) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(req.payload_context.as_ref().unwrap()).unwrap();
    let mut h = Sha256::new();
    h.update(&canonical);
    let hash: [u8; 32] = h.finalize().into();
    let (_intent_id, token, _hex) = store
        .register_lease(
            req,
            req.payload_context.clone().unwrap(),
            hash,
            None,
            String::new(),
        )
        .expect("register_lease must succeed");
    token
}

// ─── 1. Happy path — sandbox binding by (agent, method, host, path) ───────

#[test]
fn sandbox_binding_matches_cooperative_lease() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    let claim = store
        .claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer")
        .expect("sandbox binding must find the matching cooperative lease");
    assert_eq!(claim.agent_id, "agent-A");
    assert_eq!(claim.method, "POST");
    assert_eq!(claim.host, "api.bank.com");
    assert_eq!(claim.path_prefix, "/transfer");
}

#[test]
fn sandbox_binding_accepts_child_path_via_prefix() {
    // Lease was for /transfer; request is /transfer/123. Same
    // prefix semantics as the token path.
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    let claim = store
        .claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer/123/foo")
        .expect("child path must match by prefix");
    assert_eq!(claim.path_prefix, "/transfer");
}

#[test]
fn sandbox_binding_host_compare_is_case_insensitive() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(
        store
            .claim_by_sandbox_binding("agent-A", "POST", "API.BANK.COM", "/transfer")
            .is_some(),
        "host must compare case-insensitively per DNS semantics"
    );
}

// ─── 2. Reject paths — wrong identity / wrong shape ───────────────────────

#[test]
fn sandbox_binding_rejects_different_agent() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(
        store
            .claim_by_sandbox_binding("agent-B", "POST", "api.bank.com", "/transfer")
            .is_none(),
        "binding from a different sandbox's agent must NOT consume agent-A's lease"
    );
}

#[test]
fn sandbox_binding_rejects_different_host() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(store
        .claim_by_sandbox_binding("agent-A", "POST", "api.evil.com", "/transfer")
        .is_none());
}

#[test]
fn sandbox_binding_rejects_different_method() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    // Lease was POST; binding asks for GET — must NOT match
    // (otherwise a sandbox could execute a GET against a lease
    // that authorised a POST).
    assert!(store
        .claim_by_sandbox_binding("agent-A", "GET", "api.bank.com", "/transfer")
        .is_none());
}

#[test]
fn sandbox_binding_rejects_path_outside_prefix() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(store
        .claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/admin")
        .is_none());
}

#[test]
fn sandbox_binding_skips_legacy_url_only_intents() {
    // The legacy URL-only register path (no payload_context) is
    // claimed via Shadow Mode's claim(), NOT the cooperative
    // sandbox-binding path. A pure URL-only intent must NOT be
    // eligible — otherwise an agent that only ever registered a
    // Shadow-Mode preflight would accidentally get
    // cooperative.declared_only evidence tier on a normal request.
    let store = IntentStore::new(30);
    let legacy = IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "legacy".to_string(),
        agent_id: "agent-A".to_string(),
        ttl_secs: Some(30),
        payload_context: None, // <-- legacy: no payload, no token
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
    };
    store
        .register(&legacy)
        .expect("legacy register must succeed");

    assert!(
        store
            .claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer")
            .is_none(),
        "legacy URL-only intent must NOT be eligible for cooperative sandbox binding"
    );
}

// ─── 3. Single-use semantics ──────────────────────────────────────────────

#[test]
fn sandbox_binding_is_single_use() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    let first = store.claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer");
    assert!(first.is_some(), "first claim must succeed");

    let second = store.claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer");
    assert!(
        second.is_none(),
        "second sandbox-binding attempt must NOT find the lease (already Claimed)"
    );
}

#[test]
fn sandbox_binding_and_token_binding_share_the_state_machine() {
    // A lease can be claimed by either channel, but never both.
    // The first claim (regardless of channel) wins the race; the
    // second arrives finding state = Claimed.
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let token = register_coop(&store, &req);

    let sandbox_claim =
        store.claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer");
    assert!(sandbox_claim.is_some());

    // Token-based attempt on the same lease — must fail because
    // the sandbox binding already moved it out of Active.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let token_hash: [u8; 32] = h.finalize().into();
    let token_claim = store.claim_by_token_hash(&token_hash);
    assert!(
        token_claim.is_none(),
        "token claim must fail when the lease was already taken via sandbox binding"
    );
}

// ─── 4. Recency selection when multiple leases match ──────────────────────

#[test]
fn sandbox_binding_picks_most_recent_when_multiple_match() {
    // Two leases for the same (agent, method, host, path). The
    // agent re-registered (perhaps the operator updated the
    // payload_context). The binding must pick the FRESH one so
    // an old, half-staleness lease doesn't consume the binding
    // before the agent's actual current intent.
    let store = IntentStore::new(30);
    let mut old = coop("agent-A", "POST", "api.bank.com", "/transfer");
    old.payload_context = Some(serde_json::json!({"version": "old"}));
    let _ = register_coop(&store, &old);

    // Sleep ~10ms so the second register has a distinct
    // created_at. The Intent struct uses Instant::now() and
    // the max_by_key tiebreak falls back to intent_id, so this
    // is belt-and-suspenders anyway.
    std::thread::sleep(std::time::Duration::from_millis(10));

    let mut fresh = coop("agent-A", "POST", "api.bank.com", "/transfer");
    fresh.payload_context = Some(serde_json::json!({"version": "fresh"}));
    let _ = register_coop(&store, &fresh);

    let claim = store
        .claim_by_sandbox_binding("agent-A", "POST", "api.bank.com", "/transfer")
        .expect("must find a match");
    assert_eq!(
        claim.payload_context.unwrap()["version"],
        "fresh",
        "must claim the most recently registered lease"
    );
}

// ─── 5. CONNECT (host-only) variant ───────────────────────────────────────

#[test]
fn sandbox_binding_host_variant_matches_any_method_path_for_agent_host() {
    // CONNECT does not see inner method / path. The host-only
    // sandbox binding must match a cooperative lease for the
    // (agent, host) pair regardless of declared method / path.
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    let claim = store
        .claim_by_sandbox_binding_host("agent-A", "api.bank.com")
        .expect("CONNECT-shape sandbox binding must find by (agent, host)");
    assert_eq!(
        claim.method, "POST",
        "claim preserves the lease's declared method"
    );
    assert_eq!(claim.path_prefix, "/transfer");
}

#[test]
fn sandbox_binding_host_variant_rejects_different_host() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(store
        .claim_by_sandbox_binding_host("agent-A", "api.evil.com")
        .is_none());
}

#[test]
fn sandbox_binding_host_variant_rejects_different_agent() {
    let store = IntentStore::new(30);
    let req = coop("agent-A", "POST", "api.bank.com", "/transfer");
    let _ = register_coop(&store, &req);

    assert!(store
        .claim_by_sandbox_binding_host("agent-B", "api.bank.com")
        .is_none());
}

// ─── 6. WAL-rollback ghost-lease regression ───────────────────────────────
//
// /gvm/intent registers the lease BEFORE writing the
// `gvm.intent.lease_issued` WAL event. If the WAL append fails
// the API handler must hard-remove the lease via `cancel_intent`
// — NOT `confirm`, which only touches `Claimed` entries and
// silently leaves the freshly-registered `Active` lease alive.
// Without that fix, a "ghost lease" sits in the store with no
// durable audit record; the agent never gets the token, but
// Phase 3c sandbox-IP binding can still claim it implicitly via
// the agent_id + host match, producing an un-audited Allow.

#[test]
fn cancel_intent_removes_active_cooperative_lease() {
    // Direct store-level regression: the exact failure mode the
    // Blocker 2 critique pointed at. `register_lease` writes the
    // intent in Active state; `confirm(intent_id)` would no-op
    // because the state is Active, not Claimed; `cancel_intent`
    // is the correct rollback primitive.
    let store = IntentStore::new(30);
    let (_id, _token, _hex) = store
        .register_lease(
            &coop("agent-rollback", "POST", "api.bank.com", "/transfer"),
            serde_json::json!({"k": "v"}),
            [0u8; 32],
            None,
            String::new(),
        )
        .expect("register_lease must succeed");
    // Pull out the intent_id from the registered store by looking
    // for the agent_id+method+host+path combination.
    let claim_for_lookup = store
        .claim_by_sandbox_binding("agent-rollback", "POST", "api.bank.com", "/transfer")
        .expect("freshly registered lease must be claimable");
    let intent_id = claim_for_lookup.intent_id;
    // Restore it to Active so we can rollback from a real Active state.
    store.release(claim_for_lookup.claim_id);

    assert!(
        store.cancel_intent(intent_id),
        "cancel_intent must remove an Active lease"
    );
    // Now sandbox-binding must NOT find it — the ghost-lease hole
    // is closed.
    assert!(
        store
            .claim_by_sandbox_binding("agent-rollback", "POST", "api.bank.com", "/transfer")
            .is_none(),
        "after cancel_intent, the lease must be gone — sandbox-binding cannot resurrect it"
    );
}

#[test]
fn confirm_intent_does_not_remove_active_lease_proving_old_bug() {
    // Negative-control test: documents WHY we added `cancel_intent`
    // instead of just calling `confirm(intent_id)`. The legacy
    // call site at api.rs:1254 used `confirm(intent_id)` for
    // rollback — this test pins the broken behavior so a future
    // refactor that "simplifies" by replacing cancel_intent with
    // confirm gets caught.
    let store = IntentStore::new(30);
    let (intent_id, _token, _hex) = store
        .register_lease(
            &coop("agent-X", "POST", "api.bank.com", "/transfer"),
            serde_json::json!({"k": "v"}),
            [0u8; 32],
            None,
            String::new(),
        )
        .expect("register_lease must succeed");
    // confirm() expects a claim_id; passing an intent_id of an
    // Active lease must be a no-op because the lease's state is
    // not `Claimed { claim_id: intent_id }`.
    store.confirm(intent_id);
    // Lease must still be there — proving the old rollback path
    // was broken and `cancel_intent` was necessary.
    assert!(
        store
            .claim_by_sandbox_binding("agent-X", "POST", "api.bank.com", "/transfer")
            .is_some(),
        "confirm(intent_id) on an Active lease must be a no-op — \
         this is why api.rs rollback now uses cancel_intent"
    );
}

#[test]
fn cancel_intent_idempotent_returns_false_when_already_gone() {
    let store = IntentStore::new(30);
    let (intent_id, _token, _hex) = store
        .register_lease(
            &coop("agent-Y", "POST", "api.bank.com", "/transfer"),
            serde_json::json!({"k": "v"}),
            [0u8; 32],
            None,
            String::new(),
        )
        .expect("register_lease must succeed");

    assert!(store.cancel_intent(intent_id));
    assert!(
        !store.cancel_intent(intent_id),
        "second cancel must return false — idempotent, not panic"
    );
}

#[test]
fn sandbox_binding_host_variant_skips_legacy_intents() {
    // Same guard as the HTTP-shape variant — legacy URL-only
    // intents must not be eligible for the cooperative
    // sandbox-binding path.
    let store = IntentStore::new(30);
    let legacy = IntentRequest {
        method: "POST".to_string(),
        host: "api.bank.com".to_string(),
        path: "/transfer".to_string(),
        operation: "legacy".to_string(),
        agent_id: "agent-A".to_string(),
        ttl_secs: Some(30),
        payload_context: None,
        payload_hash: None,
        content_type: None,
        allow_pinned_lease: false,
    };
    store.register(&legacy).unwrap();

    assert!(store
        .claim_by_sandbox_binding_host("agent-A", "api.bank.com")
        .is_none());
}
