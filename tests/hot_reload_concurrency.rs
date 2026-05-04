//! Hot-reload concurrency tests.
//!
//! `POST /gvm/reload` swaps the live `NetworkSRR` rule set under
//! the `srr: Arc<std::sync::RwLock<NetworkSRR>>` lock. Operators
//! run reload in production while traffic is flowing — the contract
//! is that no in-flight or concurrent request panics, returns Err,
//! or observes a partial rule state. Tests/api_handlers.rs already
//! covers the single-call happy paths (success, malformed file
//! returns 400, rules preserved on failure). It does NOT cover the
//! actual production concurrency:
//!
//!   1. Burst of classify calls happening DURING reload.
//!      Every classify must succeed and observe either the pre- or
//!      post-reload rule set — never a partial mix, never a
//!      poisoned-lock error, never a panic.
//!
//!   2. After reload completes, all subsequent classify calls see
//!      the new rules (no stale read).
//!
//!   3. Concurrent reloads: two reloads racing don't deadlock, and
//!      after both complete the post-state matches one of the
//!      reloads' inputs (last-write-wins via RwLock semantics).
//!
//! These tests run on real `NetworkSRR` + `enforcement::classify`
//! using the actual production code paths, just orchestrated from
//! a test harness.

mod common;

use axum::extract::State;
use axum::http::StatusCode;
use gvm_proxy::enforcement::{classify, ClassifyInput};
use gvm_proxy::types::EnforcementDecision;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn write_srr(rules: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("gvm-hot-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(&path, rules).unwrap();
    path
}

const RULES_R1: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/*"
[rules.decision]
type = "Deny"
reason = "R1 deny"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#;

const RULES_R2: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/*"
[rules.decision]
type = "Allow"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Delay"
milliseconds = 50
"#;

// ════════════════════════════════════════════════════════════════
// 1. Concurrent classify during reload — no errors, no panics
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classify_during_reload_never_errors_and_never_observes_partial_state() {
    let path = write_srr(RULES_R1);
    let initial = gvm_proxy::srr::NetworkSRR::load(&path).unwrap();
    let (mut state, _wal) = common::test_state_with_srr(initial).await;
    state.srr_config_path = path.to_string_lossy().into_owned();

    let state = Arc::new(state);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed_deny = Arc::new(AtomicU64::new(0));
    let observed_allow = Arc::new(AtomicU64::new(0));
    let observed_delay = Arc::new(AtomicU64::new(0));

    // Spawn 8 classify-burst tasks
    let mut workers = Vec::new();
    for _ in 0..8 {
        let s = state.clone();
        let stop = stop.clone();
        let cd = observed_deny.clone();
        let ca = observed_allow.clone();
        let cdy = observed_delay.clone();
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let input = ClassifyInput {
                    method: "POST",
                    host: "api.bank.com",
                    path: "/transfer/123",
                    body: None,
                    gvm_headers: None,
                };
                let out = classify(&s, &input).expect(
                    "classify must NEVER return Err during reload — \
                     would mean RwLock poisoned or rules half-loaded",
                );
                match out.classification.decision {
                    EnforcementDecision::Deny { .. } => {
                        cd.fetch_add(1, Ordering::Relaxed);
                    }
                    EnforcementDecision::Allow => {
                        ca.fetch_add(1, Ordering::Relaxed);
                    }
                    EnforcementDecision::Delay { .. } => {
                        cdy.fetch_add(1, Ordering::Relaxed);
                    }
                    other => panic!(
                        "unexpected decision during reload: {:?} — partial \
                         rule set was visible",
                        other
                    ),
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    // Run for 200ms while flipping rules R1↔R2 every 20ms. The file
    // writes happen on the main test task only, so there is no
    // file-handle race against the workers (workers only read
    // through the in-memory NetworkSRR via classify()).
    let start = std::time::Instant::now();
    let mut toggle = false;
    while start.elapsed() < Duration::from_millis(200) {
        let active = if toggle { RULES_R2 } else { RULES_R1 };
        std::fs::write(&path, active).unwrap();
        let _ = gvm_proxy::api::reload_srr(State((*state).clone())).await;
        toggle = !toggle;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.await;
    }

    // We must have classified at least one of each major decision type
    // (proves both R1 and R2 were active at some point). The exact
    // counts vary with scheduling but each must be > 0.
    let d = observed_deny.load(Ordering::Relaxed);
    let a = observed_allow.load(Ordering::Relaxed);
    let dy = observed_delay.load(Ordering::Relaxed);
    assert!(
        d > 0,
        "no Deny observed — R1 (deny rule active) was never seen; reload may not have flipped"
    );
    // After R2 active, POST /transfer goes through Allow rule from R2,
    // OR through default-{any} Delay. Either is correct for R2.
    assert!(
        a > 0 || dy > 0,
        "no Allow/Delay observed — R2 was never seen; reload didn't flip \
         (a={} dy={})",
        a,
        dy
    );

    let _ = std::fs::remove_file(path);
}

// ════════════════════════════════════════════════════════════════
// 2. Reload completion is observable: post-reload classify uses new rules
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_atomically_promotes_new_rules_to_subsequent_classify() {
    let path = write_srr(RULES_R1);
    let initial = gvm_proxy::srr::NetworkSRR::load(&path).unwrap();
    let (mut state, _wal) = common::test_state_with_srr(initial).await;
    state.srr_config_path = path.to_string_lossy().into_owned();

    // Verify pre-reload behaviour: POST /transfer is Deny.
    let input = ClassifyInput {
        method: "POST",
        host: "api.bank.com",
        path: "/transfer/123",
        body: None,
        gvm_headers: None,
    };
    let pre = classify(&state, &input).unwrap();
    assert!(matches!(
        pre.classification.decision,
        EnforcementDecision::Deny { .. }
    ));

    // Swap the file to R2 contents and reload.
    std::fs::write(&path, RULES_R2).unwrap();
    let resp = gvm_proxy::api::reload_srr(State(state.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Post-reload behaviour: POST /transfer is now Allow (per R2).
    let post = classify(&state, &input).unwrap();
    assert!(
        matches!(post.classification.decision, EnforcementDecision::Allow),
        "post-reload classify did not see R2 rules: {:?}",
        post.classification.decision
    );

    let _ = std::fs::remove_file(path);
}

// ════════════════════════════════════════════════════════════════
// 3. Concurrent reloads do not deadlock or panic
// ════════════════════════════════════════════════════════════════
//
// Production: two operators or scripts run `gvm reload` simultaneously
// (or a watchdog auto-reloads while a manual reload is mid-flight).
// RwLock guarantees the writers serialise; the test ensures both
// calls complete OK, the post-state is one of the two inputs (last
// write wins), and no classify call during the storm errors.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reloads_serialize_without_deadlock() {
    let path = write_srr(RULES_R1);
    let initial = gvm_proxy::srr::NetworkSRR::load(&path).unwrap();
    let (mut state, _wal) = common::test_state_with_srr(initial).await;
    state.srr_config_path = path.to_string_lossy().into_owned();

    // Issue 8 concurrent reloads, each with a slightly different
    // payload (just the comment line so we can spot which one was
    // last to win in the eventual state).
    let mut handles = Vec::new();
    for i in 0..8u32 {
        let s = state.clone();
        let p = path.clone();
        handles.push(tokio::spawn(async move {
            let body = format!(
                "# reload {}\n[[rules]]\nmethod = \"GET\"\npattern = \"api.r{}.test/*\"\n\
                 [rules.decision]\ntype = \"Allow\"\n",
                i, i
            );
            std::fs::write(&p, body).unwrap();
            let resp = gvm_proxy::api::reload_srr(State(s)).await;
            resp.status()
        }));
    }
    let mut results = Vec::new();
    for h in handles {
        results.push(
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("reload deadlocked")
                .expect("task panic"),
        );
    }
    for s in results {
        assert_eq!(
            s,
            StatusCode::OK,
            "every concurrent reload must succeed (final state = one of them, \
             but none should fail)"
        );
    }

    // Stronger assertion: the loaded rule must be ONE of the 8 we wrote.
    // If the lock had corrupted state into "empty" or "stale R1", every
    // classify against `api.r{i}.test/*` would fail, and no winner would
    // be identifiable. We probe each candidate; exactly one must Allow.
    let rule_count = state.srr.read().unwrap().rule_count();
    assert_eq!(
        rule_count, 1,
        "post-concurrent-reload rule count must be 1 (winner's rule) — \
         got {}; lock state may be corrupt",
        rule_count
    );

    let mut allow_winners = Vec::new();
    for i in 0..8u32 {
        let host = format!("api.r{}.test", i);
        let result = state
            .srr
            .read()
            .unwrap()
            .check("GET", &host, "/anything", None);
        if matches!(result.decision, gvm_types::EnforcementDecision::Allow) {
            allow_winners.push(i);
        }
    }
    assert_eq!(
        allow_winners.len(),
        1,
        "exactly one of the 8 concurrent reload payloads must be the winner; \
         got allow_winners={:?} (0=stale state, 2+=double-application)",
        allow_winners,
    );

    let _ = std::fs::remove_file(path);
}
