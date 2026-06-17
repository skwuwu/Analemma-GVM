//! SRR `expires_at` regression — Tier-1 P1-b from the strategic audit
//! roadmap. First building block of the lease primitive.
//!
//! Contract: a rule whose `expires_at` is at or before the evaluation
//! timestamp does not match. Half-open semantics — the rule is valid
//! while `now < expires_at`, dead at `now == expires_at`. Determinism:
//! evaluation uses the timestamp `check_at` already takes, so an
//! auditor replaying the WAL with the event's recorded timestamp
//! reproduces the producer's decision exactly. No system-clock
//! dependence in matching.

mod common;

use chrono::{Duration, TimeZone, Utc};
use common::srr_from_toml;
use gvm_proxy::types::EnforcementDecision;

/// Rule set: a high-priority `Deny` on `/transfer` that expires at a
/// specific instant, followed by a catch-all `Allow`. After the rule
/// expires, the same request hits the catch-all instead and gets
/// `Allow` — that's how we distinguish "rule still firing" from
/// "rule expired".
const EXPIRING_DENY_TOML: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
expires_at = "2026-07-01T12:00:00Z"
decision = { type = "Deny", reason = "transfer freeze in effect" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#;

// ─── Validity window ───────────────────────────────────────────────────────

#[test]
fn rule_fires_strictly_before_expires_at() {
    let srr = srr_from_toml(EXPIRING_DENY_TOML);
    // One nanosecond before the deadline — rule must still fire.
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 11, 59, 59).unwrap();
    let result = srr.check_at("POST", "api.bank.com", "/transfer", None, now);
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "before expires_at: rule must still fire, got {:?}",
        result.decision
    );
}

#[test]
fn rule_dead_at_exact_expires_at_instant() {
    let srr = srr_from_toml(EXPIRING_DENY_TOML);
    // At the deadline exactly — half-open semantics: rule does NOT fire.
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let result = srr.check_at("POST", "api.bank.com", "/transfer", None, now);
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "at exact expires_at instant: rule must be dead, got {:?} \
         (half-open semantics: now == expires_at is OUT of validity)",
        result.decision
    );
}

#[test]
fn rule_dead_after_expires_at() {
    let srr = srr_from_toml(EXPIRING_DENY_TOML);
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 1).unwrap();
    let result = srr.check_at("POST", "api.bank.com", "/transfer", None, now);
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "after expires_at: rule must be dead, got {:?}",
        result.decision
    );
}

// ─── Backwards compatibility ───────────────────────────────────────────────

#[test]
fn rules_without_expires_at_never_expire() {
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Deny", reason = "always blocked" }
"#;
    let srr = srr_from_toml(toml);
    // Pick a wildly-far-future timestamp — rule must still match.
    let far_future = Utc.with_ymd_and_hms(2999, 12, 31, 23, 59, 59).unwrap();
    let result = srr.check_at("POST", "api.bank.com", "/transfer", None, far_future);
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "rule without expires_at must never expire, got {:?}",
        result.decision
    );
}

// ─── Parse-path validation ─────────────────────────────────────────────────

#[test]
fn malformed_expires_at_fails_at_load() {
    // RFC 3339 is strict — "2026-07-01" with no time portion is not
    // accepted by chrono's DateTime<Utc> deserializer. The compile
    // path must surface the failure at proxy startup (gvm reload),
    // not at the first matching request.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
expires_at = "not a timestamp"
decision = { type = "Deny" }
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml).expect("write");
    let load_result = gvm_proxy::srr::NetworkSRR::load(&path);
    assert!(
        load_result.is_err(),
        "malformed expires_at must fail at load time, not at request time. \
         load() returned Ok — string was silently coerced to a default."
    );
}

// ─── Determinism / replay safety ───────────────────────────────────────────

#[test]
fn replay_reproduces_decision_for_pre_and_post_expiry_timestamps() {
    let srr = srr_from_toml(EXPIRING_DENY_TOML);
    let pre = Utc.with_ymd_and_hms(2026, 7, 1, 11, 59, 0).unwrap();
    let post = pre + Duration::minutes(2);

    // Same request, two different timestamps — two different decisions
    // are correct. An auditor replaying the WAL with the recorded
    // timestamp gets the same decision the producer got.
    let pre_result = srr.check_at("POST", "api.bank.com", "/transfer", None, pre);
    let post_result = srr.check_at("POST", "api.bank.com", "/transfer", None, post);

    assert!(matches!(
        pre_result.decision,
        EnforcementDecision::Deny { .. }
    ));
    assert!(matches!(post_result.decision, EnforcementDecision::Allow));

    // Idempotency: replaying the SAME timestamp must yield the SAME
    // decision (no internal Utc::now() in the match path).
    let pre_replay = srr.check_at("POST", "api.bank.com", "/transfer", None, pre);
    let post_replay = srr.check_at("POST", "api.bank.com", "/transfer", None, post);
    assert!(matches!(
        pre_replay.decision,
        EnforcementDecision::Deny { .. }
    ));
    assert!(matches!(post_replay.decision, EnforcementDecision::Allow));
}
