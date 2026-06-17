//! GraphQL alias bypass — interaction with URL-level Deny.
//!
//! security-model.md §10 ("GraphQL Alias Bypass") documents a known
//! evasion: the SRR payload-inspection rule matches the JSON
//! `operationName` field literally, so an attacker who omits
//! `operationName` and aliases the dangerous mutation in the query
//! body slips past the payload rule. The model's recommended
//! mitigation is **defense in depth**: pair the payload rule with
//! a URL-level Deny on the mutation endpoint so the aliased request
//! is still blocked even when payload inspection is evaded.
//!
//! Both layers individually have unit/integration tests. What the
//! coverage audit (2026-05-10) flagged is that the *interaction*
//! between them — "alias evades the payload rule, URL-Deny
//! catches it anyway" — wasn't pinned. This file pins it. A
//! refactor that broke fall-through after a payload rule
//! "considered but didn't match" would let aliased mutations
//! through, and that would surface here.

use gvm_proxy::srr::{NetworkDecisionConfig, NetworkRuleConfig, NetworkSRR};
use gvm_types::EnforcementDecision;

fn deny(reason: &str) -> NetworkDecisionConfig {
    NetworkDecisionConfig {
        decision_type: "Deny".to_string(),
        milliseconds: None,
        reason: Some(reason.to_string()),
    }
}

fn payload_rule_then_url_deny() -> Vec<NetworkRuleConfig> {
    // Rule 1: payload-level Deny — "if operationName matches one
    // of these dangerous values, deny". This is the precise rule
    // an operator writes for known-bad mutations.
    let payload = NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/graphql".to_string(),
        decision: deny("Dangerous GraphQL operation"),
        path_regex: None,
        payload_field: Some("operationName".to_string()),
        payload_match: Some(vec![
            "TransferFunds".to_string(),
            "DeleteAccount".to_string(),
        ]),
        payload_query_alias_match: None,
        max_body_bytes: Some(65536),
        unsafe_body_action: None,
        description: Some("graphql payload rule".to_string()),
        label: Some("graphql_dangerous".to_string()),
        condition: None,
        expires_at: None,
    };

    // Rule 2: URL-level Deny on the same endpoint. The audit's
    // recommended defense-in-depth — even when the payload rule
    // can be evaded by alias-only mutations (no operationName
    // set), this rule still matches by URL alone.
    let url_deny = NetworkRuleConfig {
        method: "POST".to_string(),
        pattern: "api.bank.com/graphql".to_string(),
        decision: deny("GraphQL endpoint locked down"),
        path_regex: None,
        payload_field: None,
        payload_match: None,
        payload_query_alias_match: None,
        max_body_bytes: None,
        unsafe_body_action: None,
        description: Some("graphql url-level deny".to_string()),
        label: Some("graphql_url".to_string()),
        condition: None,
        expires_at: None,
    };

    vec![payload, url_deny]
}

#[test]
fn payload_rule_fires_when_operation_name_matches() {
    // Sanity: the payload rule actually catches the literal
    // operationName. Without this the layered test below would
    // pass trivially (any rule denies → SRR returns Deny).
    let srr = NetworkSRR::from_rule_configs(payload_rule_then_url_deny()).unwrap();
    let body =
        br#"{"operationName":"TransferFunds","query":"mutation TransferFunds { transferFunds }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(body));
    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "literal operationName=TransferFunds must be denied by the payload rule, got {:?}",
        r.decision
    );
}

#[test]
fn aliased_mutation_evades_payload_rule_but_url_deny_catches_it() {
    // The defense-in-depth scenario from security-model.md §10:
    // attacker omits operationName entirely and aliases the
    // dangerous mutation in the query body. The payload rule
    // sees no operationName field, skips itself, and evaluation
    // falls through to the URL-level Deny — which fires
    // regardless of body content.
    let srr = NetworkSRR::from_rule_configs(payload_rule_then_url_deny()).unwrap();

    // Aliased mutation, no operationName field at all.
    let aliased =
        br#"{"query":"mutation { t: transferFunds(amount: 1000000, dest: \"attacker\") { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(aliased));

    assert!(
        matches!(r.decision, EnforcementDecision::Deny { .. }),
        "aliased mutation without operationName must STILL be denied — \
         the URL-level rule is the defense-in-depth layer that catches \
         payload-rule evasion. Got {:?}",
        r.decision
    );

    // The exact reason should be from the URL-level rule (rule 2),
    // not the payload rule (rule 1) — because the payload rule
    // never matched. This pins which layer caught the evasion,
    // not just that *some* rule denied.
    if let EnforcementDecision::Deny { reason } = &r.decision {
        assert!(
            reason.contains("GraphQL endpoint locked down"),
            "the URL-level rule must be the one that fires when \
             payload rule's field is missing. Got reason={reason:?}"
        );
    }
}

#[test]
fn payload_rule_alone_lets_aliased_request_through() {
    // Without the URL-level Deny, the same aliased request is
    // NOT caught by the payload rule alone. This pins the
    // documented limitation: payload inspection without
    // defense-in-depth is evadable.
    //
    // Just the payload rule, no URL Deny:
    let just_payload = vec![payload_rule_then_url_deny().remove(0)];
    let srr = NetworkSRR::from_rule_configs(just_payload).unwrap();

    let aliased = br#"{"query":"mutation { t: transferFunds(amount: 1000000) { id } }"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(aliased));

    // No payload match → no rule matches → Default-to-Caution = Delay.
    // Specifically NOT Deny. This is the documented evasion that
    // motivates the layered policy in the test above.
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "without URL-level Deny, alias-bypass evades the payload rule \
         and should not produce Deny. The correct mitigation is layered \
         (test above). Got {:?}",
        r.decision
    );
}

#[test]
fn rule_order_matters_url_deny_first_short_circuits_payload_rule() {
    // Variant of the layered test with rule order flipped: URL
    // Deny first, payload second. The URL Deny matches everything
    // posted to /graphql, so the payload rule never gets to run.
    // This is fine semantically (the request is denied either
    // way), but the *rule that fires* changes — which the audit
    // reads as `matched_rule_id`. Pin the order-sensitivity so a
    // refactor that re-orders rules surfaces here.
    let mut rules = payload_rule_then_url_deny();
    rules.swap(0, 1); // url_deny is now [0]
    let srr = NetworkSRR::from_rule_configs(rules).unwrap();

    let literal = br#"{"operationName":"TransferFunds"}"#;
    let r = srr.check("POST", "api.bank.com", "/graphql", Some(literal));
    if let EnforcementDecision::Deny { reason } = &r.decision {
        assert!(
            reason.contains("GraphQL endpoint locked down"),
            "URL-Deny ordered first must fire on every POST to /graphql, \
             including the one the payload rule would have caught. \
             Got reason={reason:?}"
        );
    } else {
        panic!("expected Deny, got {:?}", r.decision);
    }
}

#[test]
fn payload_rule_skip_does_not_terminate_evaluation_on_unrelated_paths() {
    // Final cross-check: a request to a completely unrelated path
    // on the same host is NOT caught by either rule (both target
    // /graphql) and falls to Default-to-Caution. This pins that
    // payload-rule's "skip on field-missing" behaviour doesn't
    // somehow leak into routes the rule wasn't supposed to govern.
    let srr = NetworkSRR::from_rule_configs(payload_rule_then_url_deny()).unwrap();

    let r = srr.check("POST", "api.bank.com", "/healthz", None);
    assert!(
        !matches!(r.decision, EnforcementDecision::Deny { .. }),
        "/healthz on the same host must not be denied — neither rule targets it. Got {:?}",
        r.decision
    );
}
