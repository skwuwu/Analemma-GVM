//! IntentStore concurrency tests for Shadow Mode pre-flight.
//!
//! IntentStore is the heart of Shadow Mode: agents register an intent
//! (method/host/path expectation) before each outbound request; the
//! proxy `claim()`s the matching intent on inbound traffic, then
//! `confirm()` (WAL write success) or `release()` (WAL failure)
//! transitions the lifecycle. The actual purpose of the
//! `claim → confirm/release` flow is to prove the agent declared
//! its intent before acting — and to do that under real production
//! contention without losing or duplicating intents.
//!
//! Existing src/intent_store.rs unit tests cover the basic state
//! machine in isolation. This file fills the contention contract:
//!
//!   1. Concurrent claims for distinct intents all succeed without
//!      losing or cross-binding.
//!   2. Concurrent claims for the SAME intent: exactly one wins;
//!      losers see verified=false. No double-claim.
//!   3. Confirm + release races for the same claim_id are safe
//!      (no panic, no state corruption).
//!   4. Memory bound: registering N then claiming all of them
//!      drains the store back to zero (no leak).

use gvm_proxy::intent_store::{IntentRequest, IntentStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

fn intent(method: &str, host: &str, path: &str, agent: &str) -> IntentRequest {
    IntentRequest {
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        operation: format!("test.{}.{}", method, host),
        agent_id: agent.to_string(),
        ttl_secs: Some(60),
    }
}

// ════════════════════════════════════════════════════════════════
// 1. Concurrent claims for distinct intents — none cross-bind.
// ════════════════════════════════════════════════════════════════

#[test]
fn distinct_intents_claim_concurrently_without_cross_binding() {
    let store = Arc::new(IntentStore::new(60));
    const N: usize = 64;

    // Register N intents, each unique by host suffix.
    let mut intent_ids = Vec::with_capacity(N);
    for i in 0..N {
        let id = store
            .register(&intent("POST", &format!("host-{}.example", i), "/", "agent"))
            .expect("register");
        intent_ids.push(id);
    }

    // Each thread claims its own distinct intent at a barriered start.
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let s = store.clone();
        let bar = barrier.clone();
        handles.push(thread::spawn(move || {
            bar.wait();
            let host = format!("host-{}.example", i);
            let result = s.claim("POST", &host, "/", Some("agent"));
            (i, result.verified, result.claim_id)
        }));
    }

    let mut verified_count = 0;
    let mut claim_ids = std::collections::HashSet::new();
    for h in handles {
        let (i, verified, claim_id) = h.join().unwrap();
        assert!(verified, "intent #{} must claim successfully", i);
        verified_count += 1;
        assert!(
            claim_ids.insert(claim_id),
            "claim_id {} repeated — concurrent claims produced overlapping ids",
            claim_id
        );
    }
    assert_eq!(verified_count, N, "every distinct intent must verify");
    let (registered, _) = store.stats();
    // All intents are still in the store (Active → Claimed but not yet
    // confirmed). Total count unchanged.
    assert_eq!(
        registered, N,
        "no intents should be deleted before confirm — got {} after claiming {}",
        registered, N
    );
}

// ════════════════════════════════════════════════════════════════
// 2. Concurrent claims for the SAME intent: exactly one winner.
// ════════════════════════════════════════════════════════════════

#[test]
fn same_intent_concurrent_claim_yields_exactly_one_winner() {
    let store = Arc::new(IntentStore::new(60));
    let _id = store
        .register(&intent("POST", "api.bank.com", "/transfer", "agent"))
        .expect("register");

    const RACERS: usize = 16;
    let barrier = Arc::new(Barrier::new(RACERS));
    let winner_count = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let s = store.clone();
        let bar = barrier.clone();
        let wc = winner_count.clone();
        handles.push(thread::spawn(move || {
            bar.wait();
            let r = s.claim("POST", "api.bank.com", "/transfer", Some("agent"));
            if r.verified {
                wc.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let winners = winner_count.load(Ordering::Relaxed);
    assert_eq!(
        winners, 1,
        "exactly one racer must win the claim; got {} winners. \
         More than one means two requests both believed they had the \
         intent — Shadow Mode integrity broken.",
        winners
    );
}

// ════════════════════════════════════════════════════════════════
// 3. Confirm + release race on the same claim_id is safe.
// ════════════════════════════════════════════════════════════════
//
// Production contract: the proxy calls EXACTLY ONE of confirm
// (WAL succeeded) or release (WAL failed) per claim_id. Defensive
// test: even if a buggy caller fires both concurrently, the store
// must not panic or leak state.

#[test]
fn confirm_and_release_race_on_same_claim_is_safe() {
    let store = Arc::new(IntentStore::new(60));
    let _id = store
        .register(&intent("POST", "api.test.com", "/x", "agent"))
        .expect("register");
    let claimed = store.claim("POST", "api.test.com", "/x", Some("agent"));
    assert!(claimed.verified);
    let claim_id = claimed.claim_id;

    let s1 = store.clone();
    let s2 = store.clone();
    let barrier = Arc::new(Barrier::new(2));
    let b1 = barrier.clone();
    let b2 = barrier.clone();

    let h1 = thread::spawn(move || {
        b1.wait();
        s1.confirm(claim_id);
    });
    let h2 = thread::spawn(move || {
        b2.wait();
        s2.release(claim_id);
    });

    h1.join().unwrap();
    h2.join().unwrap();

    // After both fire, the intent's state is whatever the last
    // operation observed. Whichever ran last should be the "final"
    // state. The test contract: store still has 0 or 1 entries
    // (no corruption), no panic.
    let (active, _) = store.stats();
    assert!(
        active <= 1,
        "store has {} entries after race — should be 0 (confirm won) or \
         1 (release won, resurrected to Active)",
        active
    );
}

// ════════════════════════════════════════════════════════════════
// 4. N register + N claim + N confirm cycles drain the store.
// ════════════════════════════════════════════════════════════════
//
// Memory-bound check: under sustained high-throughput register →
// claim → confirm cycles, the store's intent count must return to
// zero. A leak would manifest as ever-growing counts as cycles
// progress.

#[test]
fn register_claim_confirm_cycle_drains_store_to_zero() {
    let store = Arc::new(IntentStore::new(60));
    const PARALLEL: usize = 8;
    const ITERATIONS: usize = 200;

    let barrier = Arc::new(Barrier::new(PARALLEL));
    let mut handles = Vec::with_capacity(PARALLEL);
    for tid in 0..PARALLEL {
        let s = store.clone();
        let bar = barrier.clone();
        handles.push(thread::spawn(move || {
            bar.wait();
            for i in 0..ITERATIONS {
                let host = format!("h-{}-{}.test", tid, i);
                let _id = s
                    .register(&intent("POST", &host, "/", "agent"))
                    .expect("register");
                let r = s.claim("POST", &host, "/", Some("agent"));
                assert!(r.verified, "tid={} i={} claim must succeed", tid, i);
                s.confirm(r.claim_id);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let (active, _) = store.stats();
    assert_eq!(
        active, 0,
        "after balanced register/claim/confirm churn, store must be \
         empty; got {} leaked entries",
        active
    );
}
