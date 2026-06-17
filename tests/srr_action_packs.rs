//! Provider action pack regression — Tier-2 P2-a.
//!
//! Each action pack file (`config/templates/_action_packs/<provider>.toml`)
//! is a curated SRR ruleset whose `description` fields carry the
//! canonical semantic action name. This test pins:
//!
//!   1. The pack TOML loads cleanly via the production `NetworkSRR::load`
//!      path — typo in `decision.type` or `path_regex` would surface here.
//!   2. A canonical request URL for each documented action triggers the
//!      expected `description` ("github.pr.merge", "slack.message.send", ...).
//!   3. The right decision-type comes back per the documented risk class
//!      (Allow for reads, Delay for writes, RequireApproval for high-risk,
//!      Deny for destructive).
//!
//! When a new action is added to a pack, the operator adds a row to the
//! per-provider test below. This keeps the pack and the audit-readable
//! vocabulary in lockstep — a renamed action without a matching test
//! shows up as a missing case here, not as a silent mismatch in
//! production logs.

use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::EnforcementDecision;
use std::path::PathBuf;

/// Load an action pack from the canonical location.
fn load_pack(name: &str) -> NetworkSRR {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "config",
        "templates",
        "_action_packs",
        name,
    ]
    .iter()
    .collect();
    NetworkSRR::load(&path).unwrap_or_else(|e| {
        panic!(
            "action pack {} at {} failed to load: {e}",
            name,
            path.display()
        )
    })
}

/// Tag the expected decision discriminant so the test errors point at
/// the right pack row when a regression happens.
fn assert_decision(
    pack: &NetworkSRR,
    method: &str,
    host: &str,
    path: &str,
    expected_description: &str,
    expected_kind: ExpectedKind,
) {
    let result = pack.check(method, host, path, None);
    let actual_desc = result.matched_description.as_deref().unwrap_or("<none>");
    assert_eq!(
        actual_desc, expected_description,
        "expected description '{}' for {method} {host}{path}, got '{actual_desc}'",
        expected_description
    );
    match (expected_kind, &result.decision) {
        (ExpectedKind::Allow, EnforcementDecision::Allow) => {}
        (ExpectedKind::Delay, EnforcementDecision::Delay { .. }) => {}
        (ExpectedKind::RequireApproval, EnforcementDecision::RequireApproval { .. }) => {}
        (ExpectedKind::Deny, EnforcementDecision::Deny { .. }) => {}
        (expected, actual) => panic!(
            "expected decision kind {:?} for {method} {host}{path} ({expected_description}), \
             got {:?}",
            expected, actual
        ),
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedKind {
    Allow,
    Delay,
    RequireApproval,
    Deny,
}

// ─── GitHub ────────────────────────────────────────────────────────────────

#[test]
fn github_action_pack_loads_and_matches_canonical_urls() {
    let pack = load_pack("github.toml");

    // (method, path, expected description, expected decision class)
    let cases: &[(&str, &str, &str, ExpectedKind)] = &[
        // Reads
        (
            "GET",
            "/repos/octocat/hello-world",
            "github.repo.read",
            ExpectedKind::Allow,
        ),
        (
            "GET",
            "/repos/octocat/hello-world/issues",
            "github.issue.read",
            ExpectedKind::Allow,
        ),
        (
            "GET",
            "/repos/octocat/hello-world/issues/42",
            "github.issue.read",
            ExpectedKind::Allow,
        ),
        (
            "GET",
            "/repos/octocat/hello-world/pulls",
            "github.pr.read",
            ExpectedKind::Allow,
        ),
        (
            "GET",
            "/repos/octocat/hello-world/pulls/1842",
            "github.pr.read",
            ExpectedKind::Allow,
        ),
        // Writes
        (
            "POST",
            "/repos/octocat/hello-world/issues/42/comments",
            "github.issue.comment.create",
            ExpectedKind::Delay,
        ),
        (
            "POST",
            "/repos/octocat/hello-world/pulls",
            "github.pr.create",
            ExpectedKind::Delay,
        ),
        // High-risk
        (
            "PUT",
            "/repos/octocat/hello-world/pulls/1842/merge",
            "github.pr.merge",
            ExpectedKind::RequireApproval,
        ),
        (
            "POST",
            "/repos/octocat/hello-world/actions/workflows/release.yml/dispatches",
            "github.workflow.dispatch",
            ExpectedKind::RequireApproval,
        ),
        // Destructive
        (
            "DELETE",
            "/repos/octocat/hello-world",
            "github.repo.delete",
            ExpectedKind::Deny,
        ),
    ];

    for (method, path, desc, kind) in cases {
        assert_decision(&pack, method, "api.github.com", path, desc, *kind);
    }
}

#[test]
fn github_catch_all_handles_unmapped_endpoints() {
    let pack = load_pack("github.toml");
    // Some endpoint we didn't enumerate — should hit the catch-all
    // "github.api.unspecified" rule with Delay (audit, not block).
    let result = pack.check("GET", "api.github.com", "/user/keys", None);
    assert_eq!(
        result.matched_description.as_deref(),
        Some("github.api.unspecified"),
        "unmapped GitHub endpoint should hit the catch-all"
    );
    assert!(matches!(result.decision, EnforcementDecision::Delay { .. }));
}

// ─── Slack ─────────────────────────────────────────────────────────────────

#[test]
fn slack_action_pack_loads_and_matches_canonical_urls() {
    let pack = load_pack("slack.toml");

    let cases: &[(&str, &str, &str, ExpectedKind)] = &[
        // Reads
        (
            "POST",
            "/api/users.lookupByEmail",
            "slack.user.lookup",
            ExpectedKind::Allow,
        ),
        (
            "POST",
            "/api/users.info",
            "slack.user.lookup",
            ExpectedKind::Allow,
        ),
        (
            "POST",
            "/api/conversations.list",
            "slack.conversations.list",
            ExpectedKind::Allow,
        ),
        // Writes
        (
            "POST",
            "/api/chat.postMessage",
            "slack.message.send",
            ExpectedKind::Delay,
        ),
        (
            "POST",
            "/api/chat.update",
            "slack.message.update",
            ExpectedKind::Delay,
        ),
        (
            "POST",
            "/api/files.upload",
            "slack.file.upload",
            ExpectedKind::Delay,
        ),
        (
            "POST",
            "/api/files.uploadV2",
            "slack.file.upload",
            ExpectedKind::Delay,
        ),
        // High-risk
        (
            "POST",
            "/api/conversations.create",
            "slack.channel.create",
            ExpectedKind::RequireApproval,
        ),
        (
            "POST",
            "/api/workflows.triggers.run",
            "slack.workflow.trigger",
            ExpectedKind::RequireApproval,
        ),
        // Destructive
        (
            "POST",
            "/api/chat.delete",
            "slack.message.delete",
            ExpectedKind::Deny,
        ),
    ];

    for (method, path, desc, kind) in cases {
        assert_decision(&pack, method, "slack.com", path, desc, *kind);
    }
}

#[test]
fn slack_catch_all_handles_unmapped_endpoints() {
    let pack = load_pack("slack.toml");
    let result = pack.check("POST", "slack.com", "/api/reactions.add", None);
    assert_eq!(
        result.matched_description.as_deref(),
        Some("slack.api.unspecified"),
        "unmapped Slack endpoint should hit the catch-all"
    );
    assert!(matches!(result.decision, EnforcementDecision::Delay { .. }));
}

// ─── Lease composition shape ───────────────────────────────────────────────

#[test]
fn action_pack_rule_can_be_overridden_by_per_agent_lease() {
    // The documented lease pattern: a lease rule appears BEFORE the
    // action pack's RequireApproval rule, so it fires first (SRR is
    // first-match-wins). This verifies the composition actually works
    // — the lease's Allow shadows the pack's RequireApproval for the
    // named principal in the named window.
    use chrono::{TimeZone, Utc};
    let mut toml = String::new();
    toml.push_str(
        r#"
[[rules]]
method = "PUT"
pattern = "api.github.com/{any}"
path_regex = "^/repos/my-org/my-repo/pulls/1842/merge$"
principal_filter = "agent:release-bot"
expires_at = "2026-07-01T15:00:00Z"
decision = { type = "Allow" }
description = "github.pr.merge"
label = "github_pr_merge_lease"
"#,
    );
    let pack_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "config",
        "templates",
        "_action_packs",
        "github.toml",
    ]
    .iter()
    .collect();
    toml.push_str(&std::fs::read_to_string(&pack_path).unwrap());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("composed.toml");
    std::fs::write(&path, &toml).unwrap();
    let srr = NetworkSRR::load(&path).unwrap();

    let in_window = Utc.with_ymd_and_hms(2026, 7, 1, 14, 0, 0).unwrap();
    let after_window = Utc.with_ymd_and_hms(2026, 7, 1, 15, 0, 1).unwrap();

    // Right agent, in window → Allow (lease wins)
    let r1 = srr.check_at_with_principal(
        "PUT",
        "api.github.com",
        "/repos/my-org/my-repo/pulls/1842/merge",
        None,
        Some("agent:release-bot"),
        in_window,
    );
    assert!(
        matches!(r1.decision, EnforcementDecision::Allow),
        "in-lease request must Allow, got {:?}",
        r1.decision
    );

    // Wrong agent, in window → lease skipped, pack's RequireApproval fires
    let r2 = srr.check_at_with_principal(
        "PUT",
        "api.github.com",
        "/repos/my-org/my-repo/pulls/1842/merge",
        None,
        Some("agent:other-bot"),
        in_window,
    );
    assert!(
        matches!(r2.decision, EnforcementDecision::RequireApproval { .. }),
        "wrong agent must fall to pack's RequireApproval, got {:?}",
        r2.decision
    );

    // Right agent, past deadline → lease skipped, pack's RequireApproval fires
    let r3 = srr.check_at_with_principal(
        "PUT",
        "api.github.com",
        "/repos/my-org/my-repo/pulls/1842/merge",
        None,
        Some("agent:release-bot"),
        after_window,
    );
    assert!(
        matches!(r3.decision, EnforcementDecision::RequireApproval { .. }),
        "expired lease must fall to pack's RequireApproval, got {:?}",
        r3.decision
    );
}
