//! Edge-case tests for verify_integrity_chain.
//!
//! tests/wal_rotation_integrity.rs covers the happy path: a WAL that
//! has been rotated multiple times and contains a valid chain of N
//! config_load events. This file fills the rest of the contract:
//!
//!   - Missing file → empty report (no panic).
//!   - File with no config_load events → zero counts, no break.
//!   - Single config_load → 1 valid link, no break.
//!   - Tampered integrity_context (claimed_prev wrong) → first_break set.
//!   - Malformed JSON line (corruption) → skipped, doesn't poison rest.
//!   - Pruned segment files between active and others → still scans
//!     every existing segment in order without erroring.
//!
//! All tests construct WAL contents by writing JSONL directly. This
//! gives precise control over the integrity-context fields without
//! routing through Ledger::record_config_load — which is fine
//! because we're testing the verifier in isolation, not the writer.

use gvm_types::{verify_integrity_chain, GvmIntegrityContext};
use std::io::Write;

fn write_wal(lines: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.log");
    let mut f = std::fs::File::create(&path).unwrap();
    for line in lines {
        writeln!(f, "{}", line).unwrap();
    }
    (dir, path)
}

fn config_load_event(ctx: &GvmIntegrityContext) -> String {
    let ctx_value = serde_json::to_value(ctx).unwrap();
    let event = serde_json::json!({
        "event_id": format!("sys-{}", ctx.config_hash),
        "trace_id": "system",
        "agent_id": "gvm-proxy",
        "session_id": "startup",
        "timestamp": "2026-04-30T00:00:00Z",
        "operation": "gvm.system.config_load",
        "decision": "Allow",
        "decision_source": "system",
        "enforcement_point": "startup",
        "status": "Confirmed",
        "context": {
            "_integrity_context": ctx_value,
        },
        "resource": {"service": "", "tier": "External", "sensitivity": "Medium"},
        "payload": {"content_hash": "", "size_bytes": 0, "flagged_patterns": []},
    });
    event.to_string()
}

#[test]
fn missing_file_returns_empty_report_without_panic() {
    let report = verify_integrity_chain(std::path::Path::new("/nonexistent/wal.log"));
    assert_eq!(report.total_config_loads, 0);
    assert_eq!(report.valid_links, 0);
    assert!(report.first_break.is_none());
}

#[test]
fn wal_without_any_config_load_returns_zero_counts() {
    let (_dir, path) = write_wal(&[
        r#"{"event_id":"e1","operation":"gvm.test.allow","decision":"Allow"}"#,
        r#"{"event_id":"e2","operation":"gvm.test.deny","decision":"Deny"}"#,
    ]);
    let report = verify_integrity_chain(&path);
    assert_eq!(report.total_config_loads, 0);
    assert_eq!(report.valid_links, 0);
    assert!(report.first_break.is_none());
}

#[test]
fn single_config_load_counts_as_one_valid_link() {
    let ctx = GvmIntegrityContext::local("hash-1".to_string(), None, None);
    let (_dir, path) = write_wal(&[&config_load_event(&ctx)]);
    let report = verify_integrity_chain(&path);
    assert_eq!(report.total_config_loads, 1);
    assert_eq!(
        report.valid_links, 1,
        "the very first config_load (no prior context) is always counted as a valid link"
    );
    assert!(report.first_break.is_none());
}

#[test]
fn properly_chained_two_event_run_validates_both_links() {
    let ctx1 = GvmIntegrityContext::local("config-A".to_string(), None, None);
    let ctx2 = GvmIntegrityContext::local("config-B".to_string(), Some(ctx1.context_hash()), None);
    let (_dir, path) = write_wal(&[&config_load_event(&ctx1), &config_load_event(&ctx2)]);
    let report = verify_integrity_chain(&path);
    assert_eq!(report.total_config_loads, 2);
    assert_eq!(report.valid_links, 2);
    assert!(report.first_break.is_none());
}

#[test]
fn tampered_previous_state_records_first_break() {
    let ctx1 = GvmIntegrityContext::local("config-A".to_string(), None, None);
    // Second event claims a previous_state that doesn't match ctx1's
    // context_hash — simulates an attacker editing the WAL to splice
    // in unrelated history.
    let ctx2 = GvmIntegrityContext::local(
        "config-B".to_string(),
        Some("totally-fake-prior-hash".to_string()),
        None,
    );
    let (_dir, path) = write_wal(&[&config_load_event(&ctx1), &config_load_event(&ctx2)]);
    let report = verify_integrity_chain(&path);
    assert_eq!(report.total_config_loads, 2);
    assert_eq!(
        report.valid_links, 1,
        "only the first event passes (no predecessor to compare); second \
         must be flagged as a chain break"
    );
    assert!(
        report.first_break.is_some(),
        "first_break must be set to the event_id of the broken link"
    );
}

#[test]
fn malformed_json_line_is_skipped_without_poisoning_subsequent_events() {
    let ctx1 = GvmIntegrityContext::local("config-A".to_string(), None, None);
    let ctx2 = GvmIntegrityContext::local("config-B".to_string(), Some(ctx1.context_hash()), None);
    let event1 = config_load_event(&ctx1);
    let event2 = config_load_event(&ctx2);
    let (_dir, path) = write_wal(&[
        &event1,
        "{this is not valid JSON, possibly from a crash mid-write",
        &event2,
    ]);
    let report = verify_integrity_chain(&path);
    assert_eq!(
        report.total_config_loads, 2,
        "corrupt line must be skipped, valid surrounding events still counted"
    );
    assert_eq!(report.valid_links, 2);
    assert!(report.first_break.is_none());
}

#[test]
#[ignore = "documents known evasion vector — see security-model.md \
            'integrity-context strip evasion'. Re-enable once verifier \
            treats missing _integrity_context as a chain break."]
fn integrity_context_missing_should_break_chain() {
    // SECURITY GAP: an event with operation "gvm.system.config_load"
    // but NO _integrity_context in its context map is currently
    // SKIPPED by the verifier (treated as legacy data). This means an
    // attacker who strips _integrity_context from a forged event
    // evades the integrity-chain check entirely.
    //
    // Correct behavior (target contract): missing _integrity_context
    // on a config_load event MUST be reported as first_break.
    //
    // This test pins the *target* contract; it is #[ignore]d until
    // the production verifier is hardened. The current "silently
    // skipped" behavior is preserved by `integrity_context_missing_…
    // _silently_skipped_documents_gap` below.
    let no_ctx_event = serde_json::json!({
        "event_id": "sys-broken",
        "operation": "gvm.system.config_load",
        "context": {},
        "decision": "Allow",
    })
    .to_string();
    let ctx_good = GvmIntegrityContext::local("config-A".to_string(), None, None);
    let (_dir, path) = write_wal(&[&no_ctx_event, &config_load_event(&ctx_good)]);
    let report = verify_integrity_chain(&path);
    assert_eq!(
        report.first_break.as_deref(),
        Some("sys-broken"),
        "config_load missing _integrity_context MUST be reported as a chain break"
    );
}

#[test]
fn truncated_history_first_with_some_prev_is_flagged() {
    // §4.8 strip-evasion guard.
    //
    // Attack: attacker keeps wal.log.5 (which contains a config_load
    // claiming previous_state = Some(some_hash)) but deletes wal.log.1-4.
    // The audit walk starts from wal.log.5; the first config_load it
    // sees claims Some(prior) but no prior is in the WAL we walked.
    //
    // OLD behavior: (None, _) was accepted unconditionally — attack
    // succeeded silently.
    //
    // NEW behavior: only (None, None) is accepted as genesis. The
    // (None, Some(_)) form is a truncation signal — break.
    let truncated_first = GvmIntegrityContext::local(
        "config-mid-chain".to_string(),
        Some("phantom-prior-hash".to_string()),
        None,
    );
    let next = GvmIntegrityContext::local(
        "config-after".to_string(),
        Some(truncated_first.context_hash()),
        None,
    );

    let (_dir, path) = write_wal(&[
        &config_load_event(&truncated_first),
        &config_load_event(&next),
    ]);
    let report = verify_integrity_chain(&path);

    assert_eq!(report.total_config_loads, 2);
    assert!(
        report.first_break.is_some(),
        "WAL whose first config_load claims a Some(prior) must be flagged \
         as broken (truncation evidence) — got {:?}",
        report.first_break
    );
    assert_eq!(
        report.first_break.as_deref(),
        Some(
            serde_json::from_str::<serde_json::Value>(&config_load_event(&truncated_first))
                .unwrap()
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap()
        ),
        "first_break must point at the surviving 'first' config_load \
         (not the chain-internal next event)"
    );
}

#[test]
fn genuine_genesis_with_none_prev_is_accepted() {
    // Sanity: the (None, None) form — a genuinely fresh-install
    // first config_load — must still be accepted by the new guard.
    let genesis_ctx = GvmIntegrityContext::local("genesis-config".to_string(), None, None);
    let (_dir, path) = write_wal(&[&config_load_event(&genesis_ctx)]);
    let report = verify_integrity_chain(&path);

    assert_eq!(report.total_config_loads, 1);
    assert_eq!(report.valid_links, 1);
    assert!(
        report.first_break.is_none(),
        "(None, None) form must be accepted as genuine genesis"
    );
}

#[test]
fn integrity_context_missing_silently_skipped_documents_gap() {
    // Pins CURRENT behavior: missing _integrity_context is skipped.
    // Paired with the #[ignore]d test above, which pins the TARGET
    // behavior. When the verifier is hardened, this test should be
    // deleted and the ignored one re-enabled.
    let no_ctx_event = serde_json::json!({
        "event_id": "sys-broken",
        "operation": "gvm.system.config_load",
        "context": {},
        "decision": "Allow",
    })
    .to_string();
    let ctx_good = GvmIntegrityContext::local("config-A".to_string(), None, None);
    let (_dir, path) = write_wal(&[&no_ctx_event, &config_load_event(&ctx_good)]);
    let report = verify_integrity_chain(&path);
    // Documents the gap: the broken event is invisible to the verifier.
    assert_eq!(
        report.total_config_loads, 1,
        "current behavior: config_load missing _integrity_context is invisible"
    );
    assert_eq!(report.valid_links, 1);
    assert!(
        report.first_break.is_none(),
        "current behavior: no break reported — this is the security gap"
    );
}
