//! GraphQL alias direct-match — Phase 2 false-positive reduction.
//!
//! Phase 1 (`tests/graphql_alias_direct_match.rs`) was conservative-
//! correct: any identifier matching the protected list anywhere in
//! the (scrubbed) query body produced a Deny. That preserved the
//! key security property — no false negatives — at the cost of
//! flagging legitimate queries that happened to use the protected
//! name as an argument name or a directive argument.
//!
//! Phase 2 (`COVERAGE_HARDENING_PLAN.md △-10` follow-up) tracks
//! structural state during the walk so identifiers that are
//! grammatically prohibited from being selection field names — i.e.,
//! identifiers inside `(...)` argument lists or following `@` as
//! directive names — are skipped. False-negative resistance is
//! preserved (every position that COULD be a selection field name
//! is still scanned).
//!
//! This file pins the new false-positive properties:
//!
//! 1. **Argument name shadowing** — `mutation { wrapper(transferFunds: 1) { id } }`
//!    must NOT match `transferFunds` (it's an argument name on
//!    `wrapper`, not an invocation).
//! 2. **Directive name shadowing** — `query @transferFunds { user { id } }`
//!    is grammatically impossible (operations don't have directives
//!    of arbitrary name in practice, but the parser tolerates it),
//!    yet a directive named `transferFunds` is not a selection.
//!    Phase 2 must skip directive names.
//! 3. **Argument values that look like identifiers** — `(role: TRANSFER_FUNDS)`
//!    where `TRANSFER_FUNDS` is an enum value passed as an
//!    argument. Inside `(...)` it cannot be a field name.
//! 4. **Nested argument lists** must still skip correctly — Phase 2
//!    tracks paren depth, not just a binary flag.
//!
//! The complementary direction — that Phase 2 still catches every
//! genuine alias-bypass invocation — is covered by the existing
//! `tests/graphql_alias_direct_match.rs` (11 tests, all still
//! green after the Phase 2 lexer change).

use gvm_proxy::srr::{NetworkDecisionConfig, NetworkRuleConfig, NetworkSRR};
use gvm_types::EnforcementDecision;

fn deny() -> NetworkDecisionConfig {
    NetworkDecisionConfig {
        decision_type: "Deny".to_string(),
        milliseconds: None,
        reason: Some("Phase 2 test".to_string()),
    }
}

fn alias_match_rule(names: &[&str]) -> NetworkRuleConfig {
    NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/graphql".to_string(),
        decision: deny(),
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: Some(names.iter().map(|s| s.to_string()).collect()),
        max_body_bytes: Some(65536),
        unsafe_body_action: None,
        description: Some("phase 2 alias-match".to_string()),
        label: None,
        condition: None,
    }
}

fn srr_with(rule: NetworkRuleConfig) -> NetworkSRR {
    NetworkSRR::from_rule_configs(vec![rule]).expect("rule compiles")
}

fn check(srr: &NetworkSRR, body: &[u8]) -> bool {
    matches!(
        srr.check("POST", "api.bank.com", "/graphql", Some(body))
            .decision,
        EnforcementDecision::Deny { .. }
    )
}

#[test]
fn argument_name_with_protected_label_is_not_a_match() {
    // `mutation { wrapper(transferFunds: 1) { id } }`
    // Here `transferFunds` is the name of an argument passed to
    // the `wrapper` mutation, not an invocation. Phase 1 would
    // have flagged this as a false positive; Phase 2 skips it
    // because the identifier sits inside `(...)`.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { wrapper(transferFunds: 1) { id } }"}"#;
    assert!(
        !check(&srr, body),
        "identifier inside argument list must not produce a false positive"
    );
}

#[test]
fn enum_value_argument_is_not_a_match() {
    // `query { users(role: TRANSFER_FUNDS) { id } }`
    // `TRANSFER_FUNDS` is an enum value passed as an argument.
    // Different casing from a typical mutation name, but the
    // protected list is case-sensitive — so configure the same
    // shape to make the test meaningful.
    let srr = srr_with(alias_match_rule(&["TRANSFER_FUNDS"]));
    let body = br#"{"query":"query { users(role: TRANSFER_FUNDS) { id } }"}"#;
    assert!(
        !check(&srr, body),
        "enum value inside argument list must not produce a false positive"
    );
}

#[test]
fn directive_name_with_protected_label_is_not_a_match() {
    // `query @transferFunds { user { id } }`
    // Highly contrived (no real schema would have a directive
    // named after a mutation), but the lexer must skip identifiers
    // immediately after `@`. The risk this guards against is an
    // attacker including the protected name inside a custom
    // directive to exploit a Phase 1 lexer's ambiguity.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"query @transferFunds { user { id } }"}"#;
    assert!(!check(&srr, body), "directive name must not match");
}

#[test]
fn directive_argument_with_protected_value_is_not_a_match() {
    // `query @include(transferFunds: $skip) { user { id } }`
    // `transferFunds` here is an argument name to the directive —
    // covered by the paren-depth skip.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"query @include(transferFunds: true) { user { id } }"}"#;
    assert!(!check(&srr, body), "directive argument name must not match");
}

#[test]
fn nested_argument_lists_track_paren_depth_correctly() {
    // `mutation { do(filter: { transferFunds: 1 }) { id } }`
    // The protected name is nested inside both an outer arg list
    // and an inline object. Phase 2 tracks paren depth — must
    // remain inside-args throughout. Curly braces don't open a
    // new selection set when we're already inside `(...)`, so
    // the paren-depth check is what gates this correctly.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { do(filter: { transferFunds: 1 }) { id } }"}"#;
    assert!(
        !check(&srr, body),
        "deeply-nested identifier inside argument list must still be skipped"
    );
}

#[test]
fn nested_argument_lists_do_not_swallow_subsequent_invocations() {
    // After the argument list closes, a subsequent selection
    // invocation must STILL match. This pins that the paren_depth
    // counter correctly returns to 0 on `)` — a regression that
    // saturated the counter (or never decremented) would silently
    // disable matching for the rest of the query.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { wrapper(arg: 1) transferFunds(amount: 5) { id } }"}"#;
    assert!(
        check(&srr, body),
        "after argument list closes, the protected invocation must still be detected"
    );
}

#[test]
fn protected_name_used_both_as_argument_and_invocation_is_a_match() {
    // Defense-in-depth: if the same query has the protected name
    // as both an argument name AND as a top-level invocation,
    // the invocation MUST still trigger Deny. The argument-list
    // skip cannot mask a real invocation that follows.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { x(transferFunds: 1) transferFunds(amount: 99) { id } }"}"#;
    assert!(
        check(&srr, body),
        "argument-list skip must not mask a subsequent real invocation"
    );
}

#[test]
fn invocation_inside_fragment_definition_still_caught() {
    // Phase 2 documented limitation: fragment definitions are
    // scanned the same as operation bodies. Pin this so a future
    // refactor that "improves" the parser by ignoring fragment
    // bodies surfaces here — that change would be a regression
    // because it breaks the spread-via-fragment evasion path.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { ...Bad } fragment Bad on Mutation { transferFunds(amount: 1) { id } }"}"#;
    assert!(
        check(&srr, body),
        "fragment-body invocation must still be caught (anti-spread evasion)"
    );
}

#[test]
fn multi_argument_with_protected_name_only_in_first_arg() {
    // `mutation { do(transferFunds: 1, other: 2) { id } }`
    // First argument's name happens to be the protected
    // identifier. Both should be skipped (both are arg names).
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { do(transferFunds: 1, other: 2) { id } }"}"#;
    assert!(
        !check(&srr, body),
        "argument name in a multi-arg list must not match"
    );
}
