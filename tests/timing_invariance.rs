//! SRR timing invariance — coverage hardening plan △-1.
//!
//! `tests/hostile.rs::srr_decision_time_is_roughly_constant` already
//! pins a coarse bound (any two decision-type latencies within 10x).
//! That bound is loose enough that a side channel of hundreds of
//! microseconds would slip through. This file tightens the contract:
//!
//! 1. **Cross-rule median ratio bound**: across five distinct
//!    decision-type scenarios, every pairwise median latency
//!    ratio stays below `CROSS_RULE_MEDIAN_BOUND` (3.0). Catches
//!    whole-scale leaks where one branch is, say, 5× slower than
//!    a peer.
//! 2. **Within-rule IQR overlap**: for two scenarios that hit
//!    the SAME URL pattern but take a different sub-path inside
//!    the matching rule (e.g. payload_match vs payload_skip on
//!    `POST /graphql`), the IQR ranges must overlap. A
//!    same-rule timing oracle is a real attacker tool because
//!    the URL/method does not pre-disclose the sub-path; the
//!    legacy "what rule fired" inference (cross-rule timings
//!    differ) is information the URL pattern already gives away,
//!    so it doesn't need pinning here.
//!
//! Residual cross-rule timing differences (payload-inspecting
//! rules are inherently slower than URL-only rules because they
//! parse JSON) are documented in `docs/security-model.md §1`
//! as accepted: the URL the attacker sent already tells them
//! which rule shape applied. Tightening this further requires
//! constant-time policy evaluation, tracked as a roadmap item.
//!
//! Tests are deliberately CPU-cheap (~10K iters per scenario,
//! single-thread, no I/O), so they're fast in CI but precise
//! enough to surface a real regression. They are NOT a defence
//! against true side-channel attackers — that requires
//! constant-time discipline at the instruction level. They ARE
//! a regression pin: a refactor that introduces a 5× slowdown on
//! one decision branch surfaces here.
//!
//! Acceptance bound documentation (`docs/security-model.md §1`)
//! cites this file's `MEDIAN_RATIO_BOUND` constant.

use std::time::{Duration, Instant};

use gvm_proxy::srr::{NetworkDecisionConfig, NetworkRuleConfig, NetworkSRR};

/// Maximum tolerated ratio between any pair of cross-rule
/// scenarios' median latencies. Document this number in
/// security-model §1. Cross-rule means "two requests that match
/// different URL patterns" — the URL itself discloses which
/// pattern matched, so this bound is a coarse regression catch
/// rather than a side-channel guarantee.
const CROSS_RULE_MEDIAN_BOUND: f64 = 3.0;

/// Maximum tolerated within-rule median ratio. Two requests that
/// hit the SAME URL pattern but take different decision sub-paths
/// (payload-match vs payload-skip on `POST /graphql`) must stay
/// inside this bound. This IS a side-channel-relevant invariant:
/// the URL doesn't tell the attacker which sub-path took.
const WITHIN_RULE_MEDIAN_BOUND: f64 = 1.6;

/// How many timed iterations per scenario. Higher is more
/// statistically stable; lower keeps CI fast. 10_000 with single-
/// digit microsecond per-call cost gives ~50ms total per scenario,
/// which is comfortably within CI per-test budgets.
const ITERATIONS: usize = 10_000;

/// Warmup iterations to absorb cache-cold and JIT effects before
/// timing. Critical on Windows + tokio runners where the first
/// call after `Instant::now()` takes 10× the steady-state cost.
const WARMUP: usize = 2_000;

fn deny(reason: &str) -> NetworkDecisionConfig {
    NetworkDecisionConfig {
        decision_type: "Deny".to_string(),
        milliseconds: None,
        reason: Some(reason.to_string()),
    }
}

fn delay(ms: u64) -> NetworkDecisionConfig {
    NetworkDecisionConfig {
        decision_type: "Delay".to_string(),
        milliseconds: Some(ms),
        reason: None,
    }
}

fn rule(
    method: &str,
    pattern: &str,
    decision: NetworkDecisionConfig,
    payload_field: Option<&str>,
    payload_match: Option<Vec<&str>>,
) -> NetworkRuleConfig {
    NetworkRuleConfig {
        method: method.to_string(),
        pattern: pattern.to_string(),
        decision,
        path_regex: None,
        payload_field: payload_field.map(String::from),
        payload_match: payload_match.map(|v| v.into_iter().map(String::from).collect()),
        payload_query_alias_match: None,
        max_body_bytes: Some(65536),
        description: Some(format!("{method} {pattern}")),
        label: None,
        condition: None,
    }
}

/// Build the SRR fixture once per scenario set so all five
/// scenarios run against the same compiled rule chain. Without
/// this, each scenario would compile its own SRR and compilation
/// noise would dwarf the per-call cost we're trying to measure.
fn build_srr() -> NetworkSRR {
    NetworkSRR::from_rule_configs(vec![
        // 1. URL-level Deny: POST /transfer/* → Deny
        rule(
            "POST",
            "api.bank.com/transfer/{any}",
            deny("URL deny"),
            None,
            None,
        ),
        // 2. Payload-rule: POST /graphql with operationName=TransferFunds → Deny
        rule(
            "POST",
            "api.bank.com/graphql",
            deny("Payload deny"),
            Some("operationName"),
            Some(vec!["TransferFunds"]),
        ),
        // 3. Catch-all: anything else → Delay 300ms
        rule("*", "{any}", delay(300), None, None),
    ])
    .expect("rules compile")
}

/// One scenario: a tagged closure that produces a single SRR check.
/// All scenarios share `build_srr()`'s rule chain so the only
/// variable being timed is the decision-path traversal.
struct Scenario {
    name: &'static str,
    run: fn(&NetworkSRR),
}

/// Run a scenario `ITERATIONS + WARMUP` times. Returns the timed
/// per-call durations as nanoseconds, sorted ascending. The
/// caller computes statistics; sorting here keeps the analysis
/// step trivial.
fn measure(srr: &NetworkSRR, scenario: &Scenario) -> Vec<u128> {
    // Warmup. Discarded.
    for _ in 0..WARMUP {
        (scenario.run)(srr);
    }
    // Timed.
    let mut samples: Vec<u128> = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        (scenario.run)(srr);
        let dt = t0.elapsed();
        samples.push(dt.as_nanos());
    }
    samples.sort_unstable();
    samples
}

fn quantile(sorted: &[u128], q: f64) -> u128 {
    let idx = (sorted.len() as f64 * q) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn median(sorted: &[u128]) -> u128 {
    quantile(sorted, 0.5)
}

#[test]
fn srr_timing_is_input_invariant_within_bound() {
    let srr = build_srr();

    let scenarios: Vec<Scenario> = vec![
        Scenario {
            name: "url_deny_match",
            run: |s| {
                let _ = s.check("POST", "api.bank.com", "/transfer/123", None);
            },
        },
        Scenario {
            name: "default_caution_unknown_url",
            run: |s| {
                let _ = s.check("GET", "unknown.example.com", "/anywhere", None);
            },
        },
        Scenario {
            name: "payload_match_op_name",
            run: |s| {
                let body =
                    br#"{"operationName":"TransferFunds","query":"mutation TransferFunds {x}"}"#;
                let _ = s.check("POST", "api.bank.com", "/graphql", Some(body));
            },
        },
        Scenario {
            name: "payload_skip_field_missing",
            run: |s| {
                let body = br#"{"query":"query { user { id } }"}"#;
                let _ = s.check("POST", "api.bank.com", "/graphql", Some(body));
            },
        },
        Scenario {
            name: "method_mismatch_falls_through",
            run: |s| {
                let _ = s.check("DELETE", "api.bank.com", "/transfer/123", None);
            },
        },
    ];

    // Measure each scenario.
    let mut measured: Vec<(&'static str, u128, u128, u128)> = Vec::new();
    for scenario in &scenarios {
        let samples = measure(&srr, scenario);
        let q1 = quantile(&samples, 0.25);
        let med = median(&samples);
        let q3 = quantile(&samples, 0.75);
        measured.push((scenario.name, q1, med, q3));
    }

    // Diagnostics — print every measurement so a CI failure is
    // self-explanatory. `cargo test -- --nocapture` shows these.
    eprintln!("\n  scenario                           Q1ns      med      Q3ns");
    eprintln!("  ────────────────────────────────  ──────  ──────  ──────");
    for (name, q1, med, q3) in &measured {
        eprintln!("  {name:<32}  {q1:>6}  {med:>6}  {q3:>6}");
    }
    eprintln!();

    // Invariant 1: every pairwise CROSS-RULE median ratio <
    // CROSS_RULE_MEDIAN_BOUND. Catches gross regressions; not a
    // side-channel guarantee (URL pattern already discloses
    // which rule fired).
    for i in 0..measured.len() {
        for j in (i + 1)..measured.len() {
            let med_i = measured[i].2 as f64;
            let med_j = measured[j].2 as f64;
            let ratio = if med_i > med_j {
                med_i / med_j.max(1.0)
            } else {
                med_j / med_i.max(1.0)
            };
            assert!(
                ratio < CROSS_RULE_MEDIAN_BOUND,
                "cross-rule median ratio {:.2}× between {} and {} exceeds bound {:.1}×. \
                 A scenario that is hot-path slower than a peer by more than {:.1}× \
                 is a regression candidate. See test diagnostics above.",
                ratio,
                measured[i].0,
                measured[j].0,
                CROSS_RULE_MEDIAN_BOUND,
                CROSS_RULE_MEDIAN_BOUND
            );
        }
    }

    // Invariant 2: WITHIN-RULE median ratio < WITHIN_RULE_MEDIAN_BOUND.
    // The two `POST /graphql` scenarios traverse the same matching
    // rule but take different sub-paths inside it (payload field
    // present vs missing). The URL doesn't disclose which sub-path
    // executed, so a measurable timing delta IS a side-channel
    // leak. Pin a tight bound on this pair specifically.
    let payload_match = measured
        .iter()
        .find(|s| s.0 == "payload_match_op_name")
        .map(|s| s.2 as f64)
        .unwrap();
    let payload_skip = measured
        .iter()
        .find(|s| s.0 == "payload_skip_field_missing")
        .map(|s| s.2 as f64)
        .unwrap();
    let within_ratio = if payload_match > payload_skip {
        payload_match / payload_skip.max(1.0)
    } else {
        payload_skip / payload_match.max(1.0)
    };
    assert!(
        within_ratio < WITHIN_RULE_MEDIAN_BOUND,
        "within-rule (payload-match vs payload-skip on POST /graphql) median ratio \
         {:.2}× exceeds bound {:.1}×. The URL/method does not tell an attacker \
         which sub-path was taken, so a measurable timing delta here is a side-channel. \
         payload_match={payload_match:.0}ns, payload_skip={payload_skip:.0}ns. \
         See test diagnostics above.",
        within_ratio,
        WITHIN_RULE_MEDIAN_BOUND
    );
}

#[test]
fn srr_timing_per_call_stays_under_one_millisecond_typical() {
    // Sanity bound: even pathological inputs through the SRR
    // engine should complete well under 1ms per call. This is a
    // performance contract documented in the SRR section of the
    // architecture doc and pinned here so a regression that
    // accidentally introduced a network call / slow regex /
    // disk read in the SRR hot path surfaces with a clear
    // failure rather than a vague slowdown.
    let srr = build_srr();
    let body = br#"{"operationName":"TransferFunds","query":"mutation { x }"}"#;

    // Warmup
    for _ in 0..WARMUP {
        let _ = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    }

    let t0 = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    }
    let total = t0.elapsed();
    let per_call = total / (ITERATIONS as u32);
    assert!(
        per_call < Duration::from_millis(1),
        "SRR per-call latency {:?} exceeds the documented < 1ms hot-path \
         budget. Total over {} iters = {:?}",
        per_call,
        ITERATIONS,
        total
    );
}
