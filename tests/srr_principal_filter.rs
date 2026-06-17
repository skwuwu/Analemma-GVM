//! SRR `principal_filter` regression — Tier-1 P1-c from the strategic
//! audit roadmap. Final Tier-1 item.
//!
//! Promotes `agent_id` from an audit label to an SRR matching input:
//! a rule carrying `principal_filter` matches only when the caller
//! supplies the exact agent id. Combined with `expires_at` (P1-b)
//! this is the building block of the lease primitive — "this principal
//! may do these things until this instant."
//!
//! Match contract:
//!   * rule has no principal_filter → matches every principal (legacy)
//!   * rule has principal_filter = Some(p), caller supplies Some(p)
//!     where the strings match exactly → rule fires
//!   * rule has principal_filter = Some(p), caller supplies Some(q)
//!     where p != q → rule skipped
//!   * rule has principal_filter = Some(p), caller supplies None
//!     (unauthenticated traffic) → rule skipped (fail-closed)
//!
//! Three callers can deliver the principal: `check_with_principal`,
//! `check_at_with_principal`, and the proxy hot path (covered by the
//! integration suite, not directly here). The legacy `check` /
//! `check_at` entry points pass `None` and therefore can never fire
//! principal-filtered rules — this is the intended fail-close
//! semantics for code paths that haven't been audited to propagate
//! identity.

mod common;

use common::srr_from_toml;
use gvm_proxy::types::EnforcementDecision;

/// Two rules — one keyed on a specific principal, one catch-all Allow.
/// Used so the test can distinguish "principal_filter rule fired"
/// (Deny) from "rule skipped" (Allow via catch-all).
const PRINCIPAL_DENY_TOML: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
principal_filter = "agent:claims-reviewer-1842"
decision = { type = "Deny", reason = "outside lease scope" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#;

// ─── Match path ────────────────────────────────────────────────────────────

#[test]
fn matching_principal_fires_rule() {
    let srr = srr_from_toml(PRINCIPAL_DENY_TOML);
    let result = srr.check_with_principal(
        "POST",
        "api.bank.com",
        "/transfer",
        None,
        Some("agent:claims-reviewer-1842"),
    );
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "matching principal must fire the rule, got {:?}",
        result.decision
    );
}

#[test]
fn non_matching_principal_skips_rule() {
    let srr = srr_from_toml(PRINCIPAL_DENY_TOML);
    let result = srr.check_with_principal(
        "POST",
        "api.bank.com",
        "/transfer",
        None,
        Some("agent:some-other-agent"),
    );
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "non-matching principal must skip the rule and fall through to \
         catch-all Allow, got {:?}",
        result.decision
    );
}

#[test]
fn absent_principal_skips_principal_filtered_rule() {
    let srr = srr_from_toml(PRINCIPAL_DENY_TOML);
    let result = srr.check_with_principal(
        "POST",
        "api.bank.com",
        "/transfer",
        None,
        None, // unauthenticated traffic
    );
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "unauthenticated traffic must NOT fire a principal-filtered rule. \
         got {:?}. (Fail-close direction: a rule 'for one agent' never \
         accidentally fires for traffic that hasn't established an identity.)",
        result.decision
    );
}

// ─── Legacy entry points ──────────────────────────────────────────────────

#[test]
fn legacy_check_entry_never_fires_principal_filtered_rule() {
    // The legacy `check` entry point doesn't take an agent_id and
    // internally calls check_at_with_principal(..., None, ...). So it
    // can NEVER fire a principal-filtered rule. This is the intended
    // safety: code paths that haven't been audited to propagate identity
    // get the strictest possible default.
    let srr = srr_from_toml(PRINCIPAL_DENY_TOML);
    let result = srr.check("POST", "api.bank.com", "/transfer", None);
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "legacy check() entry point must skip principal-filtered rules \
         (calls check_at_with_principal with None internally), got {:?}",
        result.decision
    );
}

#[test]
fn rules_without_principal_filter_match_every_caller() {
    // Backwards compat: a rule without principal_filter matches every
    // caller — legacy behaviour. Confirms the field's "None means
    // every principal" semantics.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Deny", reason = "blanket block" }
"#;
    let srr = srr_from_toml(toml);

    // No principal supplied — must still match.
    let r1 = srr.check("POST", "api.bank.com", "/transfer", None);
    assert!(matches!(r1.decision, EnforcementDecision::Deny { .. }));

    // Some principal — must still match.
    let r2 = srr.check_with_principal("POST", "api.bank.com", "/transfer", None, Some("any-agent"));
    assert!(matches!(r2.decision, EnforcementDecision::Deny { .. }));
}

// ─── Composition with expires_at (lease primitive shape) ───────────────────

#[test]
fn principal_filter_composes_with_expires_at_lease_shape() {
    // This is what a 5-minute lease looks like in v0.5.3 TOML:
    // "this principal may do these things until this instant."
    // The two fields together give the lease primitive its semantics.
    use chrono::{TimeZone, Utc};
    let toml = r#"
[[rules]]
method = "POST"
pattern = "workflow.internal/claims/1842"
principal_filter = "agent:claims-reviewer-1842"
expires_at = "2026-07-01T12:05:00Z"
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#;
    let srr = srr_from_toml(toml);

    // Inside the lease window AND right principal → Allow
    let pre = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let r_inside = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:claims-reviewer-1842"),
        pre,
    );
    assert!(
        matches!(r_inside.decision, EnforcementDecision::Allow),
        "inside lease window + matching principal: must Allow, got {:?}",
        r_inside.decision
    );

    // Inside the window but WRONG principal → skip the Allow, hit Delay
    let r_wrong_principal = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:other-reviewer"),
        pre,
    );
    assert!(
        matches!(
            r_wrong_principal.decision,
            EnforcementDecision::Delay { .. }
        ),
        "wrong principal inside window: must fall through (Delay), got {:?}",
        r_wrong_principal.decision
    );

    // RIGHT principal but past the deadline → skip the Allow (expired), hit Delay
    let post = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 1).unwrap();
    let r_expired = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:claims-reviewer-1842"),
        post,
    );
    assert!(
        matches!(r_expired.decision, EnforcementDecision::Delay { .. }),
        "right principal past deadline: must fall through (Delay), got {:?}",
        r_expired.decision
    );
}

// ─── Case-sensitivity / exact match ───────────────────────────────────────

#[test]
fn principal_filter_is_case_sensitive_exact_match() {
    // The field documents exact-match. A capitalised variant must NOT
    // accidentally fire — that would let an attacker smuggle by case
    // manipulation of agent identifiers.
    let srr = srr_from_toml(PRINCIPAL_DENY_TOML);
    let result = srr.check_with_principal(
        "POST",
        "api.bank.com",
        "/transfer",
        None,
        Some("AGENT:CLAIMS-REVIEWER-1842"),
    );
    assert!(
        matches!(result.decision, EnforcementDecision::Allow),
        "case-variant principal must NOT match the exact-cased filter. \
         got {:?}. Case folding would be a smuggling surface.",
        result.decision
    );
}
