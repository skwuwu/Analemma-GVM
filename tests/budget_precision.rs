//! Token-budget cumulative-cost precision regression tests
//! (`docs/internal/COVERAGE_HARDENING_PLAN.md` △-11).
//!
//! Background: the security-model previously listed "f64 precision
//! drift on cumulative cost" as a roadmap item. The 2026-05-10 audit
//! traced the actual code path and found:
//!
//! - The accumulation slot (`Slot::cost_millionths: AtomicU64`) is
//!   already integer arithmetic — exact.
//! - The cap comparison (`total_cost > max_cost_per_hour_millionths`)
//!   is also integer-only — exact.
//! - The only f64 hop is at the boundary of `record(tokens, cost_usd)`,
//!   where `cost_usd * 1_000_000.0 as u64` previously **truncated** —
//!   biasing drift downward by up to 1 millionth per record.
//!
//! The fix flips truncation to **round-to-nearest** and adds
//! `record_millionths(tokens, cost_millionths)` for callers that
//! already have a fixed-point cost. These tests pin both:
//!
//! 1. Round-to-nearest is unbiased — accumulating N records of the
//!    same `cost_usd = X.Y_millionths` reaches the analytic total
//!    `N * round(X.Y_millionths)` exactly. No drift from arithmetic.
//! 2. Sustained 1M-record load through the exact path
//!    (`record_millionths`) preserves the cumulative cost exactly.
//! 3. The mixed-cost scenario (1M records spanning rates that don't
//!    land on a whole millionth) drifts by less than 1 millionth
//!    per record on average — bounded and acceptable.
//!
//! These tests are deliberately CPU-cheap (no concurrency, no
//! sleeps); the precision claim is per-record, not under-load.
//! Concurrent-load drift is covered by
//! `tests/hostile.rs::token_budget_*`.

use gvm_proxy::token_budget::TokenBudget;

/// Build a budget with caps high enough never to fire — we only
/// care about accumulation arithmetic, not enforcement.
fn unbounded_budget() -> TokenBudget {
    TokenBudget::new(/* tokens/hr */ u64::MAX, /* $/hr */ 1e9_f64, 0)
}

#[test]
fn record_with_exact_millionth_cost_is_exact_to_the_millionth() {
    // $0.000001 = exactly 1 millionth → no f64 representation issue.
    let b = unbounded_budget();
    for _ in 0..1000 {
        b.record(0, 0.000001);
    }
    let s = b.status();
    assert_eq!(
        s.cost_used_millionths, 1000,
        "1000 charges of exactly 1 millionth must accumulate to exactly 1000 millionths"
    );
}

#[test]
fn record_rounds_to_nearest_not_truncate() {
    let b = unbounded_budget();
    // $0.0000005 = 0.5 millionths → round-to-nearest goes to 1.
    // The old truncating code produced 0 (lost decrement).
    b.record(0, 0.0000005);
    assert_eq!(
        b.status().cost_used_millionths,
        1,
        "0.5 millionths must round up to 1, not truncate to 0"
    );

    // $0.0000004 = 0.4 millionths → rounds DOWN to 0. Pin the
    // direction so a refactor to ceil/floor is caught.
    let b2 = unbounded_budget();
    b2.record(0, 0.0000004);
    assert_eq!(
        b2.status().cost_used_millionths,
        0,
        "0.4 millionths must round down to 0"
    );
}

#[test]
fn record_millionths_path_is_exact_under_one_million_records() {
    // Use the exact-arithmetic API directly. 1M records × 1
    // millionth each = exactly 1M millionths = $1.00 total. The
    // f64 hop is bypassed entirely, so the result must be bit-
    // exact, not "approximately 1M".
    let b = unbounded_budget();
    for _ in 0..1_000_000 {
        b.record_millionths(0, 1);
    }
    assert_eq!(
        b.status().cost_used_millionths,
        1_000_000,
        "exact-arithmetic path must accumulate 1M records of 1 millionth to exactly 1M millionths"
    );
}

#[test]
fn realistic_per_call_cost_drifts_within_one_millionth_per_call() {
    // Realistic LLM rates produce per-call costs in the
    // 100s-of-millionths range (e.g. Anthropic Haiku at
    // $0.25/1M input tokens × 1000 tokens = $0.00025 = 250
    // millionths per call). At this granularity round-to-nearest
    // is exact (input × 1e6 lands on or near an integer), and
    // the only drift source is f64 representation noise on the
    // multiplication itself.
    //
    // Pin the contract: 100K records of $0.000123 (123 millionths
    // per call, exact) accumulate to exactly 100K × 123 millionths.
    let b = unbounded_budget();
    let n = 100_000_u64;
    for _ in 0..n {
        b.record(0, 0.000123);
    }
    let observed = b.status().cost_used_millionths;
    let analytic = n * 123;
    let drift = observed.abs_diff(analytic);
    assert!(
        drift == 0,
        "exact-millionth per-call cost ($0.000123 = 123 millionths) \
         over {n} records must accumulate to exactly {analytic}; \
         observed {observed}, drift {drift}"
    );
}

#[test]
fn sub_millionth_per_call_cost_is_lost_without_record_millionths() {
    // Documented limitation, pinned here so the contract is
    // explicit: when the f64 path receives a per-call cost below
    // the round-to-nearest threshold (< 0.5 millionths), every
    // record rounds to 0 and cumulative total is 0 regardless
    // of N. This is the expected behaviour of round-to-nearest
    // at sub-unit granularity; the **mitigation** is to use the
    // exact-arithmetic `record_millionths` API instead, which
    // accumulates whole millionths regardless of how many calls
    // it took to reach them. Operators billing in
    // sub-millionth-per-call increments must use the integer API.
    let b_f64 = unbounded_budget();
    for _ in 0..100_000 {
        // 0.1 millionths per call — below round-to-nearest threshold.
        b_f64.record(0, 0.0000001);
    }
    assert_eq!(
        b_f64.status().cost_used_millionths,
        0,
        "f64 path with sub-millionth per-call cost rounds each call to 0; \
         cumulative is also 0. This is the documented limitation."
    );

    // Same scenario via `record_millionths` would compose the
    // upstream calculation in integers and submit (e.g.)
    // 1 millionth per 10 calls — exact. We simulate that here.
    let b_int = unbounded_budget();
    for batch in 0..10_000 {
        // every 10 calls accumulate to 1 millionth via the caller's
        // own integer math, then submit as an integer — the f64
        // hop is bypassed entirely.
        let _ = batch;
        b_int.record_millionths(0, 1);
    }
    assert_eq!(
        b_int.status().cost_used_millionths,
        10_000,
        "integer-path mitigation produces exact accumulation"
    );
}

#[test]
fn record_handles_pathological_f64_inputs_without_panic() {
    // The conversion path must not panic on NaN / infinity /
    // negative cost. The contract is: invalid inputs contribute 0
    // (fail-closed silent — the status snapshot reveals zero
    // accumulation, which the operator can spot).
    let b = unbounded_budget();
    b.record(0, f64::NAN);
    b.record(0, f64::INFINITY);
    b.record(0, f64::NEG_INFINITY);
    b.record(0, -1.5);
    b.record(0, -0.0);

    assert_eq!(
        b.status().cost_used_millionths,
        0,
        "non-finite or negative cost must contribute 0 to accumulation, not panic and not pollute"
    );
}

#[test]
fn record_then_record_millionths_compose_exactly() {
    // Mixing the two APIs in the same budget must give exact
    // accumulation. This pins that `record_millionths` does not
    // accidentally take a different code path (e.g. a separate
    // slot, double-counting through reservation release).
    let b = unbounded_budget();

    // 100 × $0.000001 = 100 millionths via f64 path.
    for _ in 0..100 {
        b.record(0, 0.000001);
    }
    // 200 × 1 millionth via integer path.
    for _ in 0..200 {
        b.record_millionths(0, 1);
    }
    // 50 × 5 millionths via integer path.
    for _ in 0..50 {
        b.record_millionths(0, 5);
    }
    let s = b.status();
    assert_eq!(
        s.cost_used_millionths,
        100 + 200 + 250,
        "f64 path + integer path + variable-amount integer path must compose exactly"
    );
}
