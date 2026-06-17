//! SRR `insert_rule` / `remove_rule` regression — Tier-3 P3-a, library
//! layer. Pins the contract that the admin HTTP endpoints
//! (`POST /gvm/srr/rule` + `DELETE /gvm/srr/rule/:id`, tested
//! separately) rely on.
//!
//! Three load-bearing properties:
//!
//!   1. **Injected rules iterate FIRST.** An orchestrator-issued lease
//!      shadows the file's defaults without rewriting the file. The
//!      classic case: pack ships `github.pr.merge = RequireApproval`
//!      by default; the orchestrator injects an `Allow` for one bot,
//!      one PR, one window; the bot's call goes through.
//!
//!   2. **`gvm reload` does not disturb the injected slot.** Reload
//!      rebuilds `rules` (file-loaded) but leaves `injected_rules`
//!      untouched. The orchestrator owns the lease lifecycle and
//!      shouldn't have to re-issue on every file edit.
//!
//!   3. **Duplicate-ID and cap errors fail loudly.** Insertion errors
//!      bubble through `Result` so the HTTP layer can map them to
//!      well-defined response codes (409 / 429 / 400).

mod common;

use common::srr_from_toml;
use gvm_proxy::srr::{NetworkRuleConfig, MAX_INJECTED_RULES};
use gvm_proxy::types::EnforcementDecision;

fn deny_cfg(description: &str) -> NetworkRuleConfig {
    NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/transfer".to_string(),
        decision: gvm_proxy::srr::NetworkDecisionConfig {
            decision_type: "Deny".to_string(),
            milliseconds: None,
            reason: Some(description.to_string()),
        },
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        unsafe_body_action: None,
        description: Some(description.to_string()),
        label: None,
        condition: None,
        expires_at: None,
        principal_filter: None,
    }
}

// ─── Iteration order — injected wins over file ─────────────────────────────

#[test]
fn injected_rule_shadows_file_rule_for_same_match() {
    // File ships an Allow for /transfer. Orchestrator injects a Deny
    // (e.g. a temporary freeze rule). Without the injected slot
    // iterating first, the file rule would win and the freeze would
    // be a no-op.
    let mut srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Allow" }
description = "transfer.file.default"
"#,
    );

    let id = srr
        .insert_rule(deny_cfg("transfer.freeze.lease.1842"))
        .expect("insert");
    assert_eq!(id, "transfer.freeze.lease.1842");

    let r = srr.check("POST", "api.bank.com", "/transfer", None);
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "injected rule must iterate FIRST and shadow the file rule, got {:?}",
        r.decision
    );
    assert_eq!(
        r.matched_description.as_deref(),
        Some("transfer.freeze.lease.1842"),
        "injected rule's description must surface"
    );
}

#[test]
fn removing_injected_rule_restores_file_rule() {
    let mut srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Allow" }
description = "transfer.file.default"
"#,
    );
    srr.insert_rule(deny_cfg("transfer.freeze")).unwrap();

    // While injected — Deny wins
    assert!(matches!(
        srr.check("POST", "api.bank.com", "/transfer", None)
            .decision,
        EnforcementDecision::Deny { .. }
    ));

    // Remove — file rule resumes
    assert!(srr.remove_rule("transfer.freeze"));
    let r = srr.check("POST", "api.bank.com", "/transfer", None);
    assert!(
        matches!(r.decision, EnforcementDecision::Allow),
        "after removing the injected rule the file rule must take over, got {:?}",
        r.decision
    );
    assert_eq!(
        r.matched_description.as_deref(),
        Some("transfer.file.default")
    );
}

// ─── Error paths ───────────────────────────────────────────────────────────

#[test]
fn insert_with_empty_description_errors() {
    let mut srr = srr_from_toml("");
    let mut cfg = deny_cfg("placeholder");
    cfg.description = None;
    let err = srr.insert_rule(cfg).unwrap_err();
    assert!(
        err.to_string().contains("description"),
        "missing-description error must explain the requirement, got: {err}"
    );
    assert_eq!(srr.injected_rule_count(), 0);
}

#[test]
fn insert_with_duplicate_description_errors() {
    let mut srr = srr_from_toml("");
    srr.insert_rule(deny_cfg("lease.foo")).unwrap();
    let err = srr.insert_rule(deny_cfg("lease.foo")).unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "duplicate-id error should say 'already exists', got: {err}"
    );
    // Counter unchanged — the second insert must NOT have left a
    // half-applied rule behind.
    assert_eq!(srr.injected_rule_count(), 1);
}

#[test]
fn remove_unknown_id_returns_false() {
    let mut srr = srr_from_toml("");
    assert!(!srr.remove_rule("nope"));
}

#[test]
fn insert_caps_at_max_injected_rules() {
    let mut srr = srr_from_toml("");
    // Fill exactly to the cap.
    for i in 0..MAX_INJECTED_RULES {
        srr.insert_rule(deny_cfg(&format!("lease.{i}")))
            .unwrap_or_else(|e| panic!("insert {i} must succeed: {e}"));
    }
    assert_eq!(srr.injected_rule_count(), MAX_INJECTED_RULES);

    // One more — the cap kicks in.
    let err = srr.insert_rule(deny_cfg("lease.overflow")).unwrap_err();
    assert!(
        err.to_string().contains("cap"),
        "cap-reached error should mention 'cap', got: {err}"
    );
    assert_eq!(srr.injected_rule_count(), MAX_INJECTED_RULES);
}

#[test]
fn insert_with_bad_regex_returns_compile_error() {
    let mut srr = srr_from_toml("");
    let mut cfg = deny_cfg("lease.bad-regex");
    cfg.path_regex = Some("[unclosed".to_string()); // not a valid regex
    let err = srr.insert_rule(cfg).unwrap_err();
    // The error chain includes the underlying regex error message —
    // we just need to confirm the insert failed and no rule was added.
    let s = format!("{err}");
    assert!(
        !s.is_empty(),
        "bad regex error must be non-empty so the HTTP layer can return it"
    );
    assert_eq!(srr.injected_rule_count(), 0);
}

// ─── Lease primitive composition (Tier-3 → Tier-1 round-trip) ──────────────

#[test]
fn lease_composition_principal_plus_expires_at_via_injection() {
    // The full lease shape that v0.5.3 supports: orchestrator
    // POSTs ONE rule with principal_filter + expires_at, the engine
    // enforces both dimensions, no caller-side cleanup.
    use chrono::{TimeZone, Utc};
    let mut srr = srr_from_toml(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
description = "default"
"#,
    );
    srr.insert_rule(NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "workflow.internal/{any}".to_string(),
        decision: gvm_proxy::srr::NetworkDecisionConfig {
            decision_type: "Allow".to_string(),
            milliseconds: None,
            reason: None,
        },
        path_regex: Some("^/claims/1842$".to_string()),
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        unsafe_body_action: None,
        description: Some("workflow.claims.lease.1842".to_string()),
        label: None,
        condition: None,
        expires_at: Some(Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 0).unwrap()),
        principal_filter: Some("agent:claims-reviewer-1842".to_string()),
    })
    .unwrap();

    let in_window = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let after = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 1).unwrap();

    // Right principal, in window → lease fires (Allow)
    let r1 = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:claims-reviewer-1842"),
        in_window,
    );
    assert!(matches!(r1.decision, EnforcementDecision::Allow));

    // Wrong principal → lease skipped, hits default Delay
    let r2 = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:other"),
        in_window,
    );
    assert!(matches!(r2.decision, EnforcementDecision::Delay { .. }));

    // Right principal, past deadline → lease expired, hits default Delay
    let r3 = srr.check_at_with_principal(
        "POST",
        "workflow.internal",
        "/claims/1842",
        None,
        Some("agent:claims-reviewer-1842"),
        after,
    );
    assert!(matches!(r3.decision, EnforcementDecision::Delay { .. }));
}

// ─── Inspection API ────────────────────────────────────────────────────────

#[test]
fn injected_rule_ids_returns_inserted_ids_only() {
    let mut srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Allow" }
description = "file.rule"
"#,
    );
    assert_eq!(srr.injected_rule_ids(), Vec::<String>::new());

    srr.insert_rule(deny_cfg("lease.alpha")).unwrap();
    srr.insert_rule(deny_cfg("lease.beta")).unwrap();
    let ids = srr.injected_rule_ids();
    assert_eq!(ids, vec!["lease.alpha", "lease.beta"]);
    // The file rule's description does NOT leak into the injected list.
    assert!(!ids.iter().any(|id| id == "file.rule"));

    srr.remove_rule("lease.alpha");
    assert_eq!(srr.injected_rule_ids(), vec!["lease.beta"]);
}

#[test]
fn rule_count_returns_only_file_loaded() {
    // `rule_count()` is the legacy startup-banner metric. It should
    // continue to count only file-loaded rules, so an injection burst
    // doesn't make the next startup banner look wildly different.
    let mut srr = srr_from_toml(
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer"
decision = { type = "Allow" }
description = "f1"

[[rules]]
method = "POST"
pattern = "api.bank.com/withdraw"
decision = { type = "Allow" }
description = "f2"
"#,
    );
    let file_count = srr.rule_count();
    srr.insert_rule(deny_cfg("lease.x")).unwrap();
    srr.insert_rule(deny_cfg("lease.y")).unwrap();
    assert_eq!(
        srr.rule_count(),
        file_count,
        "file-rule count must not change"
    );
    assert_eq!(srr.injected_rule_count(), 2);
}
