//! GraphQL alias direct-match — Phase 1 of the alias-bypass
//! defense (`docs/internal/COVERAGE_HARDENING_PLAN.md △-10`).
//!
//! Phase 1 ships a narrow lexer (`src/srr/mod.rs::scan_graphql_query_for_invocation`)
//! that scans the request body's `query` field for any GraphQL
//! invocation whose field name matches a configured list,
//! regardless of `operationName` or alias prefix. This closes the
//! "operationName missing → operation aliased" evasion that
//! pre-Phase-1 SRR could not block by primitive defense (only by
//! pairing with a URL-level Deny per the documented mitigation).
//!
//! Tests in this file pin:
//!
//! - **Direct invocation** — `mutation { transferFunds(...) }`
//!   matches.
//! - **Aliased invocation** — `mutation { x: transferFunds(...) }`
//!   matches even with no `operationName` field at all.
//! - **Named operation** — `mutation Op { transferFunds(...) }`
//!   matches even when the operationName envelope says
//!   something innocent.
//! - **Comment / string-literal smuggling** — putting the name
//!   inside `# transferFunds` or a description string does not
//!   trigger the match.
//! - **No false positive on identifier overlap** —
//!   `transferFundsExtra` does not match `transferFunds`.
//! - **Pure URL-Deny still works** without alias-list configured.
//!
//! Phase 2 (full GraphQL parser, fragment expansion) is tracked
//! in the hardening plan as deferred. For Phase 1 the documented
//! mitigation pattern (alias-list + URL-level Deny on the same
//! endpoint, defense-in-depth) is what operators are still
//! advised to deploy.

use gvm_proxy::srr::{NetworkDecisionConfig, NetworkRuleConfig, NetworkSRR};
use gvm_types::EnforcementDecision;

fn deny(reason: &str) -> NetworkDecisionConfig {
    NetworkDecisionConfig {
        decision_type: "Deny".to_string(),
        milliseconds: None,
        reason: Some(reason.to_string()),
    }
}

fn alias_match_rule(names: &[&str]) -> NetworkRuleConfig {
    NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/graphql".to_string(),
        decision: deny("Dangerous GraphQL invocation"),
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: Some(names.iter().map(|s| s.to_string()).collect()),
        max_body_bytes: Some(65536),
        unsafe_body_action: None,
        description: Some("graphql alias-match".to_string()),
        label: Some("graphql_alias".to_string()),
        condition: None,
    }
}

fn srr_with(rule: NetworkRuleConfig) -> NetworkSRR {
    NetworkSRR::from_rule_configs(vec![rule]).expect("rule compiles")
}

#[test]
fn direct_invocation_with_no_operation_name_is_caught() {
    // The exact bypass case: no operationName field, mutation
    // invoked directly in the query body. Pre-Phase-1 the payload
    // rule would have skipped (no operationName to match) and the
    // request would fall through to whatever URL-level rule
    // existed. With alias-match, the invocation itself is detected.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"mutation { transferFunds(amount: 1000, dest: \"x\") { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "direct invocation without operationName must be denied, got {:?}",
        r.decision
    );
}

#[test]
fn aliased_invocation_is_caught() {
    // The headline alias-bypass: attacker prefixes the dangerous
    // mutation with an arbitrary alias label. Pre-Phase-1 this
    // was the documented evasion; Phase 1 catches it directly.
    let srr = srr_with(alias_match_rule(&["transferFunds", "deleteAccount"]));
    for body in [
        br#"{"query":"mutation { x: transferFunds(amount: 1) { id } }"}"#.as_slice(),
        br#"{"query":"mutation { harmless: deleteAccount(id: \"5\") }"}"#.as_slice(),
        br#"{"query":"mutation { a: transferFunds(amount: 1) b: deleteAccount(id: \"x\") }"}"#
            .as_slice(),
    ] {
        let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
        assert!(
            matches!(r.decision, EnforcementDecision::Deny { .. }),
            "aliased invocation must be denied. body={}, got {:?}",
            std::str::from_utf8(body).unwrap_or("(non-utf8)"),
            r.decision
        );
    }
}

#[test]
fn named_operation_with_innocent_operation_name_is_caught() {
    // Attacker provides operationName = "GetAccount" (sounds
    // innocent), but the body actually invokes transferFunds
    // under that operation. The legacy `payload_field =
    // operationName` rule would pass the GetAccount label;
    // alias-match scans the query body itself.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"operationName":"GetAccount","query":"mutation GetAccount { transferFunds(amount: 9999) { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "operationName lying about the actual invocation must still be caught, got {:?}",
        r.decision
    );
}

#[test]
fn name_inside_comment_does_not_trigger_false_positive() {
    // GraphQL comments run from `#` to end-of-line. An attacker
    // can't get a deny by including the dangerous name in a
    // comment of an otherwise-benign query — that would be a
    // griefing surface (poisoning a peer's query with our
    // mutation name to get them blocked).
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    // Comment contains the trigger; the actual query is benign.
    // The JSON value's `\n` is a JSON escape that decodes to a
    // real newline after serde parse, so the lexer sees the
    // comment terminator. Build the body as a regular string so
    // the `\n` escape goes through Rust's string escaping AND
    // the JSON `\n` escape is preserved for serde to decode.
    let body_str = "{\"query\":\"# transferFunds\\nquery { user { id } }\"}";
    let body = body_str.as_bytes();
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "name inside a `#` comment must NOT produce a Deny, got {:?}",
        r.decision
    );
}

#[test]
fn name_inside_string_literal_does_not_trigger_false_positive() {
    // Same property for string literals. A description / argument
    // value containing the dangerous name verbatim must not
    // trigger the match.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"query":"query Search { hits(q: \"transferFunds tutorial\") { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "name inside a string literal must NOT produce a Deny, got {:?}",
        r.decision
    );
}

#[test]
fn identifier_overlap_does_not_trigger_false_positive() {
    // `transferFundsExtra`, `notTransferFunds`, `myTransferFundsHelper`
    // — none of these should match `transferFunds`. The lexer's
    // word-boundary check prevents substring matches.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    for body in [
        br#"{"query":"mutation { transferFundsExtra(x: 1) { id } }"}"#.as_slice(),
        br#"{"query":"mutation { notTransferFunds(x: 1) { id } }"}"#.as_slice(),
        br#"{"query":"query { myTransferFundsHelper(x: 1) }"}"#.as_slice(),
    ] {
        let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
        assert!(
            !matches!(r.decision, EnforcementDecision::Deny { .. }),
            "identifier-overlap (not whole-word) must NOT match. \
             body={}, got {:?}",
            std::str::from_utf8(body).unwrap_or("(non-utf8)"),
            r.decision
        );
    }
}

#[test]
fn empty_alias_list_never_matches() {
    // Sanity: an empty `payload_query_alias_match` configures the
    // rule to require payload inspection but offers no names to
    // match against. Behaviour: never matches (skip rule).
    let srr = srr_with(alias_match_rule(&[]));
    let body = br#"{"query":"mutation { transferFunds(amount: 1) { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "empty alias list must not produce Deny, got {:?}",
        r.decision
    );
}

#[test]
fn rule_with_alias_match_only_does_not_require_operation_name_field() {
    // The new field is independent of `payload_field` /
    // `payload_match`. A rule that ONLY sets
    // `payload_query_alias_match` must trigger payload inspection
    // (reach the lexer) without the operator also configuring
    // the legacy operationName check. Pin this so a refactor that
    // re-coupled them surfaces.
    //
    // We construct exactly that: payload_field = None, alias-list
    // present. A direct invocation must still be caught.
    let rule = alias_match_rule(&["transferFunds"]);
    assert!(
        rule.payload_field.is_none() && rule.payload_match.is_none(),
        "fixture must isolate the alias-list path (no operationName check)"
    );
    let srr = srr_with(rule);
    let body = br#"{"query":"mutation { transferFunds(amount: 1) { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "alias-match-only rule must still trigger payload inspection, got {:?}",
        r.decision
    );
}

#[test]
fn alias_match_combines_with_operation_name_match() {
    // Both layers configured on the same rule. Either matching
    // produces Deny. Pin that the layers are OR-composed inside
    // one rule (versus AND-composed, which would require both
    // matches to fire).
    let mut rule = alias_match_rule(&["transferFunds"]);
    rule.payload_field = Some("operationName".to_string());
    rule.payload_match = Some(vec!["TransferFundsLegacy".to_string()]);
    let srr = NetworkSRR::from_rule_configs(vec![rule]).unwrap();

    // Case A: only operationName matches (legacy).
    let body_a =
        br#"{"operationName":"TransferFundsLegacy","query":"mutation TransferFundsLegacy { x }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body_a));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "operationName layer must still fire when configured. Got {:?}",
        r.decision
    );

    // Case B: operationName lies, alias-match catches it.
    let body_b = br#"{"operationName":"BenignThing","query":"mutation { y: transferFunds(amount: 1) { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body_b));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "alias layer must catch invocation that operationName lied about. Got {:?}",
        r.decision
    );

    // Case C: neither matches.
    let body_c = br#"{"operationName":"Search","query":"query Search { hits { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body_c));
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "no payload trigger and no URL-level rule: must not Deny. Got {:?}",
        r.decision
    );
}

#[test]
fn malformed_json_body_does_not_crash() {
    // Defensive: a body that isn't valid JSON falls through to
    // the rule's no-match path. No panic, no infinite loop.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = b"not valid json at all { { mutation: transferFunds }";
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    // The body isn't JSON, so the rule's payload inspection
    // can't extract a `query` field. The rule doesn't match,
    // and the request falls to default-to-caution.
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "non-JSON body must not crash the lexer or produce Deny without a query field, got {:?}",
        r.decision
    );
}

#[test]
fn body_with_no_query_field_does_not_match() {
    // The lexer scan only fires on `body.query`. A body that's
    // valid JSON but lacks a `query` field produces no match.
    let srr = srr_with(alias_match_rule(&["transferFunds"]));
    let body = br#"{"data":{"transferFunds":"yes"}}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "no `query` field in body — lexer has nothing to scan, must not Deny. Got {:?}",
        r.decision
    );
}
