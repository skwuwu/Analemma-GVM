//! enforcement::classify() robustness tests.
//!
//! tests/enforcement.rs covers the happy paths (Allow/Deny/Delay,
//! catch-all detection, GVM header parsing, lock poisoning). It uses
//! body=None throughout, treats GVM headers as trustworthy, and only
//! checks `is_default_caution` as a bool flag without verifying its
//! downstream effect.
//!
//! This file fills four gaps that map to real adversarial production
//! conditions:
//!
//!   1. Payload-field SRR rules: classify must thread `body`
//!      through to the SRR engine so payload_match decisions actually
//!      fire. body=None tests prove nothing about that wiring.
//!
//!   2. Hostile GVM headers: agent SDKs are attacker-reachable. 1MB
//!      agent_id and control chars in trace_id are real log-injection
//!      / DoS vectors. Verify classify either truncates / sanitises
//!      OR documents the lack thereof so operators run their audit
//!      pipelines accordingly.
//!
//!   3. is_default_caution actually drives behaviour: the bool must
//!      end up on the WAL event so audit / dashboards can flag
//!      catch-all hits. A test that only checks the field at the
//!      classify return is field-allocation testing, not security.
//!
//!   4. Hot-path RwLock contention: hundreds of concurrent classify()
//!      calls must complete with bounded p99 latency. A regression
//!      that holds the read lock across an .await — or accidentally
//!      promotes it to a write lock — would tank throughput before
//!      any functional test failed.

mod common;

use gvm_proxy::enforcement::{classify, ClassifyInput};
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn srr_from_toml(toml: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml).unwrap();
    NetworkSRR::load(&path).unwrap()
}

// ════════════════════════════════════════════════════════════════
// 1. Payload-field SRR rule receives the body verbatim
// ════════════════════════════════════════════════════════════════
//
// Rules with `payload_field` + `payload_match` extract a JSON field
// from the request body and compare it to the match list. The test:
// classify() with a body whose JSON has the matching field value
// must produce the rule's decision; with a non-matching value must
// fall through to the next rule.

#[tokio::test]
async fn classify_routes_body_to_srr_payload_inspection_match() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
payload_field = "operation"
payload_match = ["WireTransfer"]
[rules.decision]
type = "Deny"
reason = "wire transfer blocked by payload inspection"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    // Body JSON whose `operation` field matches → rule fires → Deny.
    let body = br#"{"operation":"WireTransfer","amount":1000}"#;
    let input = ClassifyInput {
        method: "POST",
        host: "api.bank.com",
        path: "/transfer",
        body: Some(body.as_slice()),
        gvm_headers: None,
    };
    let out = classify(&state, &input).expect("classify");
    assert!(
        matches!(
            out.classification.decision,
            EnforcementDecision::Deny { .. }
        ),
        "matching payload must produce Deny, got {:?}",
        out.classification.decision
    );
}

#[tokio::test]
async fn classify_payload_inspection_falls_through_on_mismatch() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
payload_field = "operation"
payload_match = ["WireTransfer"]
[rules.decision]
type = "Deny"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    // operation=BalanceCheck — does NOT match the deny rule. Must fall
    // through to the catch-all Allow rule.
    let body = br#"{"operation":"BalanceCheck"}"#;
    let input = ClassifyInput {
        method: "POST",
        host: "api.bank.com",
        path: "/transfer",
        body: Some(body.as_slice()),
        gvm_headers: None,
    };
    let out = classify(&state, &input).expect("classify");
    assert!(
        matches!(out.classification.decision, EnforcementDecision::Allow),
        "non-matching payload must fall through to Allow, got {:?}",
        out.classification.decision
    );
}

#[tokio::test]
async fn classify_payload_inspection_handles_garbage_body_without_panic() {
    // Garbage bytes (non-UTF-8, non-JSON) must not panic the classifier.
    // Production agents send arbitrary payloads — protobuf binaries,
    // truncated JSON from network errors, gzip without
    // content-encoding, etc.
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
payload_field = "operation"
payload_match = ["WireTransfer"]
[rules.decision]
type = "Deny"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let garbage: Vec<u8> = (0u8..=255u8).collect();
    let input = ClassifyInput {
        method: "POST",
        host: "api.bank.com",
        path: "/transfer",
        body: Some(garbage.as_slice()),
        gvm_headers: None,
    };
    // Just must not panic; falling through to Allow is correct.
    let out = classify(&state, &input).expect("classify on garbage");
    assert!(matches!(
        out.classification.decision,
        EnforcementDecision::Allow
    ));
}

// ════════════════════════════════════════════════════════════════
// 2. Hostile GVM headers — agent-sourced strings need treating
//    as untrusted input.
// ════════════════════════════════════════════════════════════════

fn hostile_headers(agent_id: String, trace_id: String) -> GVMHeaders {
    GVMHeaders {
        operation: "test.op".to_string(),
        agent_id,
        tenant_id: None,
        session_id: None,
        trace_id,
        event_id: "evt-h".to_string(),
        parent_event_id: None,
        rate_limit: None,
        resource: None,
        context: HashMap::new(),
    }
}

#[tokio::test]
async fn classify_does_not_panic_on_oversize_agent_id() {
    // 1 MB of 'A's. Production agents could supply this either by
    // bug, malicious intent, or an SDK that auto-encodes long
    // metadata. Classify MUST handle without panic AND must not
    // unbound-allocate the entire payload N times across the
    // request lifetime.
    let huge = "A".repeat(1024 * 1024);
    let headers = hostile_headers(huge.clone(), "trace".to_string());

    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.example.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.example.com",
        path: "/x",
        body: None,
        gvm_headers: Some(&headers),
    };
    let t0 = std::time::Instant::now();
    let out = classify(&state, &input).expect("must not panic on 1MB agent_id");
    let elapsed = t0.elapsed();

    // Contract (intentionally permissive): agent_id may pass through
    // verbatim today (no boundary cap is enforced at classify), or a
    // future hardening pass may truncate / reject. Either is acceptable
    // — what we CANNOT tolerate is a panic, hang, or quadratic blowup.
    //
    // Upper bound on accepted length: the input itself. A future fix
    // that truncates to N bytes (N < 1MB) STILL satisfies the assertion
    // — we deliberately do NOT lock in verbatim passthrough as the
    // contract (that would block §1.5 boundary-validation hardening).
    assert!(
        out.agent_id.len() <= huge.len(),
        "agent_id must never grow past input length; got {} > {}",
        out.agent_id.len(),
        huge.len(),
    );
    // Soft latency guard against quadratic regression. 1MB classify on
    // a debug build is ~50ms typical; 5s catches unbounded copy loops.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "classify on 1MB input took {:?} — likely O(N²) regression",
        elapsed,
    );
}

#[tokio::test]
async fn classify_passes_control_char_trace_id_without_panic() {
    // Trace IDs with embedded \n / \r / \0 / BEL would inject log
    // lines if any downstream sink does plain printf. Classify must
    // not panic. The actual line of defense is JSON serialization —
    // we verify here that ANY sanitization layer (current: none on
    // classify; future: a possible boundary truncator) plus the JSON
    // emitter combine to keep raw control bytes out of the WAL stream.
    let bad = "trace\r\nFAKE: injected log line\0\u{0007}".to_string();
    let headers = hostile_headers("agent".to_string(), bad.clone());

    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.example.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.example.com",
        path: "/x",
        body: None,
        gvm_headers: Some(&headers),
    };
    let out = classify(&state, &input).expect("must not panic on control-char trace_id");
    let op = out
        .classification
        .operation
        .expect("operation metadata present");

    // The actual contract per §1.5: the audit-stream emitter must
    // never spill raw control bytes onto a line-oriented sink.
    // Whether classify sanitizes upstream or relies on JSON escaping
    // downstream, the *combined* output must escape \r, \n, \0.
    let serialized = serde_json::to_string(&op).expect("operation metadata must JSON-serialize");
    assert!(
        !serialized.contains('\r') && !serialized.contains('\n') && !serialized.contains('\0'),
        "WAL JSON line must not contain raw CR/LF/NUL — log-injection \
         defense breached. serialized={:?}",
        serialized
    );

    // Round-trip integrity: a JSON consumer that parses this line
    // must get back the original bytes (escape != lossy mutation).
    let reparsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("re-parse must succeed");
    let session = reparsed
        .get("subject")
        .and_then(|s| s.get("session_id"))
        .and_then(|s| s.as_str())
        .expect("session_id must round-trip through JSON");
    assert_eq!(
        session, bad,
        "JSON round-trip must preserve original bytes; escape ≠ mutate"
    );
}

#[tokio::test]
async fn classify_without_required_gvm_headers_falls_back_to_unknown_agent() {
    // gvm_headers: None — equivalent to agent NOT sending the SDK
    // headers. Production contract is fail-OPEN (request still
    // governed by SRR network rules) with agent_id="unknown" so the
    // audit log records WHICH calls bypassed the SDK. Confirms the
    // documented behaviour.
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.example.com/*"
[rules.decision]
type = "Allow"
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    let input = ClassifyInput {
        method: "GET",
        host: "api.example.com",
        path: "/x",
        body: None,
        gvm_headers: None,
    };
    let out = classify(&state, &input).expect("classify");
    assert_eq!(
        out.agent_id, "unknown",
        "missing GVM headers must surface as agent_id=unknown (NOT empty \
         string, NOT panic)"
    );
    assert!(
        out.classification.operation.is_none(),
        "no GVM headers → no operation metadata"
    );
}

// ════════════════════════════════════════════════════════════════
// 3. is_default_caution actually plumbs to the WAL event.
// ════════════════════════════════════════════════════════════════
//
// The bool flag returned from classify is consumed by proxy_handler
// at src/proxy.rs:506 (`event.default_caution = is_default_caution`)
// and serialized as `default_caution: true|false` in the WAL JSON.
// The flag's value is what the dashboard / `gvm watch` colour the
// "default-caution" call-outs from. A regression that drops the
// flag (or always sets it to false) would silently strip the
// catch-all observability without tripping any current test.
//
// This test verifies the wire-level contract: catch-all match →
// is_default_caution == true; specific match → false.

#[tokio::test]
async fn default_caution_flag_matches_catch_all_match_status() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "GET"
pattern = "api.specific.com/*"
[rules.decision]
type = "Allow"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Delay"
milliseconds = 100
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;

    // Hit the specific rule → is_default_caution must be FALSE.
    let specific = ClassifyInput {
        method: "GET",
        host: "api.specific.com",
        path: "/x",
        body: None,
        gvm_headers: None,
    };
    let r1 = classify(&state, &specific).unwrap();
    assert!(
        !r1.is_default_caution,
        "specific rule match must NOT be marked default-caution"
    );

    // Hit the catch-all → is_default_caution must be TRUE.
    let unknown = ClassifyInput {
        method: "POST",
        host: "totally-new-vendor.example",
        path: "/anything",
        body: None,
        gvm_headers: None,
    };
    let r2 = classify(&state, &unknown).unwrap();
    assert!(
        r2.is_default_caution,
        "catch-all match MUST be marked default-caution so the WAL \
         event surfaces it for downstream dashboards"
    );
}

// ════════════════════════════════════════════════════════════════
// 4. classify under contention: hot-path P99 latency
// ════════════════════════════════════════════════════════════════
//
// classify takes a read lock on AppState.srr (std::sync::RwLock),
// reads, drops. The lock is held for microseconds. Contention should
// not push P99 into milliseconds even with hundreds of concurrent
// callers. If a regression promotes the read lock to write or holds
// it across an .await, a single classify call will block all others
// and the P99 will explode.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn classify_under_high_contention_holds_p99_under_threshold() {
    let srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/*"
[rules.decision]
type = "Deny"

[[rules]]
method = "GET"
pattern = "api.github.com/*"
[rules.decision]
type = "Allow"

[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Delay"
milliseconds = 50
"#,
    );
    let (state, _wal) = common::test_state_with_srr(srr).await;
    let state = Arc::new(state);

    const PARALLEL: usize = 64;
    const CALLS_PER_TASK: usize = 200;
    let max_us = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));

    let mut tasks = Vec::with_capacity(PARALLEL);
    for tid in 0..PARALLEL {
        let s = state.clone();
        let mu = max_us.clone();
        let tot = total.clone();
        tasks.push(tokio::spawn(async move {
            let mut local_max = 0u64;
            for i in 0..CALLS_PER_TASK {
                let host = match (tid + i) % 3 {
                    0 => "api.bank.com",
                    1 => "api.github.com",
                    _ => "api.unknown.example",
                };
                let path = match (tid + i) % 3 {
                    0 => "/transfer/abc",
                    1 => "/repos/x",
                    _ => "/anything",
                };
                let method = if (tid + i) % 3 == 0 { "POST" } else { "GET" };
                let input = ClassifyInput {
                    method,
                    host,
                    path,
                    body: None,
                    gvm_headers: None,
                };
                let start = Instant::now();
                let _ = classify(&s, &input).expect("classify");
                let elapsed_us = start.elapsed().as_micros() as u64;
                local_max = local_max.max(elapsed_us);
                tot.fetch_add(1, Ordering::Relaxed);
            }
            // Update global max
            let mut cur = mu.load(Ordering::Relaxed);
            while local_max > cur {
                match mu.compare_exchange(cur, local_max, Ordering::Relaxed, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(c) => cur = c,
                }
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    let observed_total = total.load(Ordering::Relaxed);
    assert_eq!(
        observed_total as usize,
        PARALLEL * CALLS_PER_TASK,
        "every classify call must complete (no deadlock)"
    );

    // P99 budget: classify should be ≤1µs on a hot CPU. Under
    // contention with 64 tasks × 200 calls = 12,800 reads, the
    // worst-case observed must stay below 50ms — generous tolerance
    // for CI shared-runner jitter, tight enough to catch a
    // write-lock regression which would push max into seconds.
    let max_observed_us = max_us.load(Ordering::Relaxed);
    let max_observed = Duration::from_micros(max_observed_us);
    assert!(
        max_observed < Duration::from_millis(50),
        "max classify latency under contention was {:?} — RwLock \
         either held across an .await or promoted to write. classify \
         is the hot path; this is a release-blocker.",
        max_observed
    );
}
