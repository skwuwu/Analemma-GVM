//! Time-window SRR condition tests (`docs/srr.md §3.8`).
//!
//! The `condition = { kind = "time_window", window, tz, outside }`
//! TOML schema gates a rule by request timestamp. The implementation
//! is in `src/srr/mod.rs::Condition` and the dispatch path in
//! `check_at(method, host, path, body, now)`. These tests pin the
//! contract so that:
//!
//! 1. Window boundaries are correct on both sides (inclusive start,
//!    exclusive end) — the place a refactor most often slips.
//! 2. Cross-midnight ranges (`22:00-06:00`) work — internally
//!    `start_min > end_min`, which is easy to break on a "if start
//!    > end then swap" cleanup.
//! 3. `outside = true` correctly inverts. The proxy lets the
//!    operator say "deny outside biz hours"; if the inversion bug
//!    flipped this, the rule would block during biz hours instead.
//! 4. Replay determinism: running the same WAL through `check_at`
//!    with the original `event.timestamp` yields the same decision
//!    regardless of the auditor's wall clock. This is the
//!    auditability claim the security model leans on.
//! 5. Non-UTC timezones (IANA names) compile, and the window is
//!    interpreted in the rule's timezone — not the system's.
//!
//! Pure logic; no I/O. Runs everywhere.

use chrono::{TimeZone, Utc};
use gvm_proxy::srr::{NetworkRuleConfig, NetworkSRR, RuleConditionConfig};
use gvm_types::EnforcementDecision;

fn allow_rule(host: &str, condition: Option<RuleConditionConfig>) -> NetworkRuleConfig {
    NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: format!("{host}/{{any}}"),
        decision: gvm_proxy::srr::NetworkDecisionConfig {
            decision_type: "Allow".to_string(),
            milliseconds: None,
            reason: None,
        },
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        description: Some("test rule".to_string()),
        label: None,
        condition,
    }
}

fn srr_with(rules: Vec<NetworkRuleConfig>) -> NetworkSRR {
    NetworkSRR::from_rule_configs(rules).expect("rules compile")
}

fn time_window(window: &str, tz: Option<&str>, outside: bool) -> RuleConditionConfig {
    RuleConditionConfig::TimeWindow {
        window: window.to_string(),
        tz: tz.map(String::from),
        outside,
    }
}

#[test]
fn window_inclusive_start_exclusive_end() {
    // 09:00-18:00 UTC. The implementation treats start as inclusive
    // and end as exclusive — pin both sides.
    let rule = allow_rule(
        "api.example.com",
        Some(time_window("09:00-18:00", None, false)),
    );
    let srr = srr_with(vec![rule]);

    let inside = Utc.with_ymd_and_hms(2026, 5, 10, 9, 0, 0).unwrap();
    let inside_late = Utc.with_ymd_and_hms(2026, 5, 10, 17, 59, 59).unwrap();
    let just_before = Utc.with_ymd_and_hms(2026, 5, 10, 8, 59, 59).unwrap();
    let exactly_end = Utc.with_ymd_and_hms(2026, 5, 10, 18, 0, 0).unwrap();
    let well_after = Utc.with_ymd_and_hms(2026, 5, 10, 22, 0, 0).unwrap();

    // Inside the window — rule fires (Allow).
    let r = srr.check_at("POST", "api.example.com", "/whatever", None, inside);
    assert!(matches!(r.decision, EnforcementDecision::Allow));
    let r = srr.check_at("POST", "api.example.com", "/whatever", None, inside_late);
    assert!(matches!(r.decision, EnforcementDecision::Allow));

    // Outside the window — rule doesn't fire, falls through to
    // default (Default-to-Caution = Delay 300ms).
    for ts in [just_before, exactly_end, well_after] {
        let r = srr.check_at("POST", "api.example.com", "/whatever", None, ts);
        assert!(
            !matches!(r.decision, EnforcementDecision::Allow),
            "request at {ts} should NOT be allowed — rule's window is closed"
        );
    }
}

#[test]
fn cross_midnight_window_22_to_06() {
    // 22:00-06:00 UTC — start > end, the "wrap around midnight"
    // case. A naive "start..end" range check fails this; pin it.
    let rule = allow_rule(
        "api.example.com",
        Some(time_window("22:00-06:00", None, false)),
    );
    let srr = srr_with(vec![rule]);

    let twenty_two_oclock = Utc.with_ymd_and_hms(2026, 5, 10, 22, 0, 0).unwrap();
    let one_am = Utc.with_ymd_and_hms(2026, 5, 11, 1, 0, 0).unwrap();
    let five_fifty_nine = Utc.with_ymd_and_hms(2026, 5, 11, 5, 59, 0).unwrap();
    let six_am = Utc.with_ymd_and_hms(2026, 5, 11, 6, 0, 0).unwrap();
    let noon = Utc.with_ymd_and_hms(2026, 5, 11, 12, 0, 0).unwrap();
    let nine_pm = Utc.with_ymd_and_hms(2026, 5, 10, 21, 0, 0).unwrap();

    // Inside the wrap-around window.
    for ts in [twenty_two_oclock, one_am, five_fifty_nine] {
        let r = srr.check_at("POST", "api.example.com", "/x", None, ts);
        assert!(
            matches!(r.decision, EnforcementDecision::Allow),
            "{ts} is inside the 22:00-06:00 window and must Allow, got {:?}",
            r.decision
        );
    }
    // Outside.
    for ts in [six_am, noon, nine_pm] {
        let r = srr.check_at("POST", "api.example.com", "/x", None, ts);
        assert!(
            !matches!(r.decision, EnforcementDecision::Allow),
            "{ts} is outside the 22:00-06:00 window — must not Allow"
        );
    }
}

#[test]
fn outside_inverts_match() {
    // Same window as test #1, but `outside = true` — rule should
    // fire ONLY when the request is OUTSIDE 09:00-18:00. This is
    // the "deny outside biz hours" pattern.
    let rule = allow_rule(
        "api.example.com",
        Some(time_window("09:00-18:00", None, true)),
    );
    let srr = srr_with(vec![rule]);

    let inside = Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap();
    let outside = Utc.with_ymd_and_hms(2026, 5, 10, 22, 0, 0).unwrap();

    let r_inside = srr.check_at("POST", "api.example.com", "/x", None, inside);
    assert!(
        !matches!(r_inside.decision, EnforcementDecision::Allow),
        "outside=true: inside the time-window the rule must NOT fire"
    );
    let r_outside = srr.check_at("POST", "api.example.com", "/x", None, outside);
    assert!(
        matches!(r_outside.decision, EnforcementDecision::Allow),
        "outside=true: outside the time-window the rule fires, got {:?}",
        r_outside.decision
    );
}

#[test]
fn replay_with_old_timestamp_reproduces_decision() {
    // The replay determinism contract: an auditor running the same
    // SRR ruleset against an old event's timestamp must reach the
    // same decision the producer reached. The auditor's wall clock
    // is irrelevant. We simulate the contract by calling check_at
    // with an "event time" that is months in the past, while the
    // operating wall clock is "now".
    let rule = allow_rule(
        "api.example.com",
        Some(time_window("09:00-18:00", None, false)),
    );
    let srr = srr_with(vec![rule]);

    // Producer originally evaluated at 14:30 on 2025-12-15 — inside
    // the window. The replay must reach the same Allow even if it
    // runs in 2026-05.
    let producer_time = Utc.with_ymd_and_hms(2025, 12, 15, 14, 30, 0).unwrap();
    let r = srr.check_at("POST", "api.example.com", "/foo", None, producer_time);
    assert!(matches!(r.decision, EnforcementDecision::Allow));

    // Producer at 23:00 — outside the window. Same auditor, different
    // request timestamp, opposite decision.
    let outside_time = Utc.with_ymd_and_hms(2025, 12, 15, 23, 0, 0).unwrap();
    let r = srr.check_at("POST", "api.example.com", "/foo", None, outside_time);
    assert!(!matches!(r.decision, EnforcementDecision::Allow));
}

#[test]
fn timezone_is_interpreted_in_rules_tz_not_system() {
    // 09:00-18:00 in Asia/Seoul is 00:00-09:00 UTC (Seoul is UTC+9
    // year-round, no DST). A request at 03:00 UTC must hit the
    // window (it's noon Seoul time). A request at 12:00 UTC must
    // miss it (it's 21:00 Seoul time).
    let rule = allow_rule(
        "api.example.com",
        Some(time_window("09:00-18:00", Some("Asia/Seoul"), false)),
    );
    let srr = srr_with(vec![rule]);

    let three_am_utc = Utc.with_ymd_and_hms(2026, 5, 10, 3, 0, 0).unwrap();
    let noon_utc = Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap();

    let r = srr.check_at("POST", "api.example.com", "/x", None, three_am_utc);
    assert!(
        matches!(r.decision, EnforcementDecision::Allow),
        "03:00 UTC = 12:00 Seoul, inside 09:00-18:00 Seoul, got {:?}",
        r.decision
    );
    let r = srr.check_at("POST", "api.example.com", "/x", None, noon_utc);
    assert!(
        !matches!(r.decision, EnforcementDecision::Allow),
        "12:00 UTC = 21:00 Seoul, outside 09:00-18:00 Seoul"
    );
}

#[test]
fn unconditioned_rule_runs_at_any_time() {
    // Sanity — a rule WITHOUT a condition fires unconditionally
    // regardless of timestamp. Confirms time-window machinery
    // doesn't bleed into rules that didn't ask for it.
    let rule = allow_rule("api.example.com", None);
    let srr = srr_with(vec![rule]);

    for hour in [0, 6, 12, 18, 23] {
        let ts = Utc.with_ymd_and_hms(2026, 5, 10, hour, 0, 0).unwrap();
        let r = srr.check_at("POST", "api.example.com", "/x", None, ts);
        assert!(
            matches!(r.decision, EnforcementDecision::Allow),
            "unconditioned rule must fire at hour {hour}, got {:?}",
            r.decision
        );
    }
}

#[test]
fn time_conditioned_rule_falls_through_when_condition_false() {
    // When the time-window condition fails, evaluation must fall
    // through to subsequent rules — not return "no rule matched"
    // immediately. Pin this with a two-rule policy: first rule is
    // a time-conditioned Allow, second rule is an unconditioned
    // Deny. Outside the window, the second rule must fire.
    let conditioned_allow = allow_rule(
        "api.example.com",
        Some(time_window("09:00-18:00", None, false)),
    );
    let mut unconditioned_deny = allow_rule("api.example.com", None);
    unconditioned_deny.decision = gvm_proxy::srr::NetworkDecisionConfig {
        decision_type: "Deny".to_string(),
        milliseconds: None,
        reason: Some("after hours".to_string()),
    };

    let srr = srr_with(vec![conditioned_allow, unconditioned_deny]);

    // Inside the window — first rule fires, Allow.
    let inside = Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap();
    let r = srr.check_at("POST", "api.example.com", "/x", None, inside);
    assert!(matches!(r.decision, EnforcementDecision::Allow));

    // Outside — first rule's condition is false, must fall through
    // to the Deny.
    let outside = Utc.with_ymd_and_hms(2026, 5, 10, 22, 0, 0).unwrap();
    let r = srr.check_at("POST", "api.example.com", "/x", None, outside);
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "outside the window the time-conditioned rule must fall \
         through, allowing the next rule (Deny) to match. Got {:?}",
        r.decision
    );
}
