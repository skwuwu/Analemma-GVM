//! SRR `unsafe_body_action` regression — Tier-1 P1-a from the strategic
//! audit roadmap. Pins the fail-close-on-unverifiable-body contract:
//!
//!   * when a rule needs body inspection but the body is too large to
//!     inspect, OR
//!   * when the body is present but neither plain JSON nor base64-JSON
//!     parses,
//!
//! the engine applies the rule's `unsafe_body_action` if configured.
//! Without the field, the legacy permissive behaviour (`continue` to
//! the next rule) is preserved — covered by the "absent" tests below.
//!
//! The field deliberately does NOT fire when the body is absent (e.g.
//! a GET request hits a rule that has `payload_field` set). Missing
//! body is not an inspection failure; it's "rule doesn't apply" — the
//! engine must fall through to URL-only rules for the same endpoint.

mod common;

use common::srr_from_toml;
use gvm_proxy::types::EnforcementDecision;

/// Rule that requires JSON body inspection on `api.bank.com/cmd`
/// and explicitly fails closed when inspection cannot run. Followed
/// by a catch-all Allow so the test can distinguish "fail-close fired"
/// from "fell through to next rule" by which decision came back.
const FAIL_CLOSE_TOML: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/cmd"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 64
unsafe_body_action = { type = "Deny", reason = "body inspection failed" }
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#;

/// Same rule shape but WITHOUT `unsafe_body_action` — pins the legacy
/// permissive behaviour (continue to next rule on inspection failure).
const PERMISSIVE_TOML: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/cmd"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 64
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#;

// ─── Fail-close path ───────────────────────────────────────────────────────

#[test]
fn body_too_large_triggers_unsafe_body_action_deny() {
    let srr = srr_from_toml(FAIL_CLOSE_TOML);
    // Body larger than max_body_bytes (64) — inspection skipped.
    let huge = vec![b'x'; 1024];
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(&huge));
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "oversized body must trigger unsafe_body_action Deny, got {:?}",
        result.decision
    );
    let desc = result.matched_description.unwrap_or_default();
    assert!(
        desc.contains("unsafe_body_action"),
        "matched_description should explain the fail-close path, got: {desc}"
    );
}

#[test]
fn unparseable_body_triggers_unsafe_body_action_deny() {
    let srr = srr_from_toml(FAIL_CLOSE_TOML);
    // Garbage bytes — not plain JSON, not base64-of-JSON.
    let garbage = b"\xff\xfe\xfd\xfc not json at all";
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(garbage));
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "unparseable body must trigger unsafe_body_action Deny, got {:?}",
        result.decision
    );
}

#[test]
fn matching_body_still_applies_rule_decision_not_unsafe_action() {
    let srr = srr_from_toml(FAIL_CLOSE_TOML);
    // Body parses as plain JSON, hits the payload_match — must apply
    // the rule's own decision (Allow), not the unsafe_body_action.
    // This pins that unsafe_body_action does not fire on successful
    // inspection that happens to match.
    let body = br#"{"op":"drop_table"}"#;
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(body));
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "matching body must apply rule decision (Allow), got {:?}",
        result.decision
    );
}

#[test]
fn non_matching_body_continues_to_next_rule_not_unsafe_action() {
    let srr = srr_from_toml(FAIL_CLOSE_TOML);
    // Body parses fine, but `op` is not in `payload_match`. This is
    // "rule does not apply", not "inspection failed". Engine must
    // continue to the catch-all Allow, NOT apply unsafe_body_action.
    let body = br#"{"op":"safe_op"}"#;
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(body));
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "non-matching body must fall through to next rule (Allow), got {:?}",
        result.decision
    );
}

#[test]
fn absent_body_does_not_trigger_unsafe_body_action() {
    let srr = srr_from_toml(FAIL_CLOSE_TOML);
    // No body. The rule's payload predicate trivially does not apply.
    // unsafe_body_action MUST NOT fire — that would block GET requests
    // and any POST without a body, both of which the operator did not
    // ask to fail-close on.
    let result = srr.check("POST", "api.bank.com", "/cmd", None);
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "absent body must fall through to next rule (Allow), got {:?}. \
         unsafe_body_action firing on absent body would break GETs and \
         body-less POSTs.",
        result.decision
    );
}

// ─── Legacy permissive path (no unsafe_body_action) ────────────────────────

#[test]
fn legacy_permissive_body_too_large_falls_through() {
    let srr = srr_from_toml(PERMISSIVE_TOML);
    let huge = vec![b'x'; 1024];
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(&huge));
    // No unsafe_body_action set — engine continues past the body-too-large
    // rule and hits the catch-all Allow. This is the documented legacy
    // behaviour; we pin it so a future change that defaults to fail-close
    // breaks this test explicitly.
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "without unsafe_body_action, oversized body must continue to next rule, got {:?}",
        result.decision
    );
}

#[test]
fn legacy_permissive_unparseable_body_falls_through() {
    let srr = srr_from_toml(PERMISSIVE_TOML);
    let garbage = b"\xff not json";
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(garbage));
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "without unsafe_body_action, unparseable body must continue to next rule, got {:?}",
        result.decision
    );
}

// ─── Alternate effect types ────────────────────────────────────────────────

#[test]
fn unsafe_body_action_accepts_require_approval() {
    // Operator might prefer "approval required" over "outright deny"
    // for borderline endpoints. Verify the parse path accepts the
    // full set of decision types.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/cmd"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 64
unsafe_body_action = { type = "RequireApproval" }
decision = { type = "Allow" }
"#;
    let srr = srr_from_toml(toml);
    let huge = vec![b'x'; 1024];
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(&huge));
    assert!(
        matches!(result.decision, EnforcementDecision::RequireApproval { .. }),
        "unsafe_body_action = RequireApproval must produce that decision, got {:?}",
        result.decision
    );
}

#[test]
fn unsafe_body_action_accepts_delay_with_milliseconds() {
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/cmd"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 64
unsafe_body_action = { type = "Delay", milliseconds = 5000 }
decision = { type = "Allow" }
"#;
    let srr = srr_from_toml(toml);
    let huge = vec![b'x'; 1024];
    let result = srr.check("POST", "api.bank.com", "/cmd", Some(&huge));
    match result.decision {
        EnforcementDecision::Delay { milliseconds } => {
            assert_eq!(milliseconds, 5000, "Delay must honour configured ms");
        }
        other => panic!("expected Delay(5000), got {other:?}"),
    }
}
