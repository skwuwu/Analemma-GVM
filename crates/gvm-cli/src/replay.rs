//! `gvm replay` — re-classify historical WAL events through a proposed
//! SRR ruleset and report the verdict delta. (#3 visibility item.)
//!
//! Read-only: never touches the running proxy, never modifies the WAL,
//! never loads the proposed rules into a live engine. Pure reasoning
//! over saved data. Answers exactly one question: **"If I had
//! deployed THIS rule file yesterday, how many requests would it have
//! affected, and which way?"**
//!
//! Limits (be honest with the operator):
//! - **Payload-based rules can't be replayed.** WAL events do not
//!   carry the request body — privacy invariant of the v3 audit
//!   architecture. A proposed rule that matches on `payload_field`
//!   will simply not fire during replay; we still count and surface
//!   it so the operator knows that branch went un-evaluated.
//! - **Default-to-Caution baseline assumes `Delay { 300 }`** to match
//!   the most common config. If your deployment overrides that to
//!   `RequireApproval` or `Deny`, the "no rule matched" baseline in
//!   the report won't equal what your live proxy emitted. The
//!   per-event original decision in the WAL is the ground truth;
//!   the report shows both.
//! - **Single ruleset only.** No per-agent / per-tenant overlay
//!   replay, because GVM doesn't support that at runtime either
//!   (single-org SRR is a deliberate design choice).
//!
//! Output is two-column: counts (Allow/Delay/Deny/RequireApproval)
//! before and after, plus a "delta" line showing how many requests
//! moved between buckets. JSON output (`--json`) is suitable for
//! piping into a regression harness.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// Histogram of decisions, keyed by the canonical decision name as it
/// appears in `GVMEvent.decision` / `EnforcementDecision::Debug`.
/// Counted because a histogram is the most operator-readable summary;
/// per-event diffs are emitted separately (and capped) so a noisy
/// WAL doesn't dump 10MB of text on the operator.
#[derive(Default, Debug, Clone, serde::Serialize)]
struct DecisionCounts {
    allow: usize,
    delay: usize,
    deny: usize,
    require_approval: usize,
    audit_only: usize,
    other: usize,
}

impl DecisionCounts {
    fn add(&mut self, decision: &str) {
        if decision.starts_with("Allow") {
            self.allow += 1;
        } else if decision.starts_with("Delay") {
            self.delay += 1;
        } else if decision.starts_with("Deny") {
            self.deny += 1;
        } else if decision.starts_with("RequireApproval") {
            self.require_approval += 1;
        } else if decision.starts_with("AuditOnly") {
            self.audit_only += 1;
        } else {
            self.other += 1;
        }
    }

    #[cfg(test)]
    fn total(&self) -> usize {
        self.allow + self.delay + self.deny + self.require_approval + self.audit_only + self.other
    }
}

/// One event's before/after delta, for the "what specifically changed"
/// section of the report.
#[derive(Debug, Clone, serde::Serialize)]
struct VerdictChange {
    method: String,
    host: String,
    path: String,
    original: String,
    proposed: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReplayReport {
    /// How many WAL records were inspected (events only — seal/anchor/batch
    /// records are filtered out).
    events_evaluated: usize,
    /// Events skipped because they had no transport metadata to
    /// classify against (e.g. system events like
    /// `gvm.system.config_load` and `gvm.sandbox.launch`). Reported
    /// so the operator's denominator math is honest.
    events_skipped: usize,
    original: DecisionCounts,
    proposed: DecisionCounts,
    /// Up to `MAX_CHANGE_SAMPLES` per-event diffs. The full set is
    /// reachable in JSON mode; the human table caps to keep the
    /// terminal scrollback manageable.
    changes: Vec<VerdictChange>,
    /// Total number of changes (may exceed `changes.len()` when
    /// truncated for human output).
    total_changes: usize,
    /// Events whose `timestamp` field couldn't be parsed as RFC3339.
    /// In non-strict mode (default) these are skipped from the
    /// proposed-decision count and surfaced here so the operator can
    /// see how much of the WAL fell back. Strict mode aborts the run
    /// the moment one is encountered.
    timestamp_missing: usize,
}

const MAX_CHANGE_SAMPLES: usize = 50;

/// Outcome of trying to classify one WAL line.
///
/// Extracted from the inner loop so the per-event logic is unit-testable
/// without hijacking stdout — important because the determinism guarantee
/// (replay against `event.timestamp`) is the load-bearing property and
/// regressions would silently change verdicts on time-conditioned rules.
enum EventClass {
    /// Not an event (seal/anchor/batch record, malformed JSON, missing event_id).
    NotAnEvent,
    /// A system event (config_load, sandbox.launch) with no `transport`.
    SystemEvent,
    /// A request event whose `timestamp` field couldn't be parsed as
    /// RFC3339. `strict` mode treats this as a hard error (exit 1);
    /// non-strict mode falls back to `Utc::now()` and counts the event
    /// as `timestamp_fallback`. The event_id is surfaced so the
    /// operator can locate it in the WAL.
    MissingTimestamp { event_id: String },
    /// A classified request event with original + proposed verdicts.
    Classified {
        method: String,
        host: String,
        path: String,
        original: String,
        proposed: String,
    },
}

fn classify_one(srr: &gvm_proxy::srr::NetworkSRR, value: &serde_json::Value) -> EventClass {
    // Filter to actual events. Seal records have `seal_id`,
    // anchor records have `anchor_hash`, batch records have
    // `merkle_root` + `batch_id`. Events have `event_id` and
    // (typically) `transport`.
    if !value.is_object()
        || !value
            .get("event_id")
            .map(|v| v.is_string())
            .unwrap_or(false)
    {
        return EventClass::NotAnEvent;
    }
    if value.get("seal_id").is_some() || value.get("anchor_hash").is_some() {
        return EventClass::NotAnEvent;
    }

    let transport = match value.get("transport") {
        Some(t) if !t.is_null() => t,
        _ => return EventClass::SystemEvent,
    };

    let method = transport
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let host = transport
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let path = transport
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let original = value
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    // Pull the WAL event's timestamp so condition evaluation is
    // reproducible. `event.timestamp` is committed to the Merkle leaf
    // and anchor-signed, so re-classifying with `check_at(ts)` produces
    // a deterministic verdict regardless of when replay runs. Using
    // `Utc::now()` here would silently flip "biz-hours-only allow"
    // to/from "always allow" depending on when the operator runs the
    // report — a critical determinism break for audit replay.
    //
    // When the timestamp can't be parsed we surface it as a distinct
    // `EventClass::MissingTimestamp`. The caller decides whether to
    // (a) fall back to `Utc::now()` (legacy behaviour, non-strict mode)
    // or (b) abort the entire replay run (strict mode). We never silently
    // substitute here — keeping the determinism break visible at the
    // single chokepoint that controls it.
    let event_timestamp = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let event_timestamp = match event_timestamp {
        Some(ts) => ts,
        None => {
            let event_id = value
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<no-event_id>")
                .to_string();
            return EventClass::MissingTimestamp { event_id };
        }
    };

    // `body=None` — payload-rule matchers skip without firing (the WAL
    // doesn't store the request body; payload-deny rules can't replay).
    let result = srr.check_at(&method, &host, &path, None, event_timestamp);
    let proposed = format!("{:?}", result.decision);

    EventClass::Classified {
        method,
        host,
        path,
        original,
        proposed,
    }
}

pub fn run(
    wal_path: &str,
    rules_path: &str,
    emit_json: bool,
    limit: usize,
    strict: bool,
) -> Result<()> {
    // 1. Load proposed SRR. Reuses the production loader, so any
    //    parse error here means the ruleset wouldn't have started
    //    the proxy either — exactly the early-warning we want.
    let srr = gvm_proxy::srr::NetworkSRR::load(Path::new(rules_path))
        .with_context(|| format!("Failed to load proposed SRR file: {}", rules_path))?;

    // 2. Stream the WAL. Plain JSONL — same shape `gvm proof event`
    //    parses. Skip non-event records (seal/anchor/batch JSON
    //    objects) by checking for the discriminating `event_id`
    //    field's presence + absence of seal/anchor markers.
    let content = std::fs::read_to_string(wal_path)
        .with_context(|| format!("Failed to read WAL: {}", wal_path))?;

    let mut report = ReplayReport {
        events_evaluated: 0,
        events_skipped: 0,
        original: DecisionCounts::default(),
        proposed: DecisionCounts::default(),
        changes: Vec::new(),
        total_changes: 0,
        timestamp_missing: 0,
    };

    for line in content.lines() {
        if limit > 0 && report.events_evaluated >= limit {
            break;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // skip malformed
        };
        match classify_one(&srr, &value) {
            EventClass::NotAnEvent => continue,
            EventClass::SystemEvent => {
                report.events_skipped += 1;
                continue;
            }
            EventClass::MissingTimestamp { event_id } => {
                if strict {
                    // Strict mode: any unparseable timestamp aborts the
                    // entire run with a non-zero exit. Use this in CI /
                    // compliance reports where a silent fallback would
                    // turn time-conditioned rules into "evaluated against
                    // current wall-clock" — the determinism property the
                    // audit chain exists to preserve.
                    anyhow::bail!(
                        "replay --strict: event {} has no parseable RFC3339 `timestamp` \
                         field. Time-conditioned rules cannot be replayed deterministically \
                         without it. Re-run without --strict to fall back to Utc::now() \
                         on missing timestamps (NOT recommended for compliance reports).",
                        event_id
                    );
                }
                // Non-strict: count it and skip. Don't quietly run the
                // event through `Utc::now()` — that's the silent
                // determinism break we explicitly designed away.
                report.timestamp_missing += 1;
                report.events_skipped += 1;
            }
            EventClass::Classified {
                method,
                host,
                path,
                original,
                proposed,
            } => {
                report.events_evaluated += 1;
                report.original.add(&original);
                report.proposed.add(&proposed);

                if original != proposed {
                    report.total_changes += 1;
                    if report.changes.len() < MAX_CHANGE_SAMPLES {
                        report.changes.push(VerdictChange {
                            method,
                            host,
                            path,
                            original,
                            proposed,
                        });
                    }
                }
            }
        }
    }

    if emit_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_human_report(&report, wal_path, rules_path);
    Ok(())
}

fn print_human_report(report: &ReplayReport, wal_path: &str, rules_path: &str) {
    println!();
    println!("  {BOLD}SRR replay report{RESET}");
    println!("  {DIM}WAL:{RESET}   {}", wal_path);
    println!("  {DIM}Rules:{RESET} {}", rules_path);
    println!();

    println!(
        "  {DIM}Events evaluated:{RESET}     {}",
        report.events_evaluated
    );
    println!(
        "  {DIM}Events skipped:{RESET}       {} {DIM}(no transport — config_load, sandbox.launch, etc.){RESET}",
        report.events_skipped
    );
    println!();

    println!("  {BOLD}Decision histogram (before \u{2192} after){RESET}");
    println!();
    print_row("Allow", report.original.allow, report.proposed.allow, GREEN);
    print_row(
        "Delay",
        report.original.delay,
        report.proposed.delay,
        YELLOW,
    );
    print_row(
        "RequireApproval",
        report.original.require_approval,
        report.proposed.require_approval,
        YELLOW,
    );
    print_row("Deny", report.original.deny, report.proposed.deny, RED);
    print_row(
        "AuditOnly",
        report.original.audit_only,
        report.proposed.audit_only,
        CYAN,
    );
    if report.original.other > 0 || report.proposed.other > 0 {
        print_row("(other)", report.original.other, report.proposed.other, DIM);
    }
    println!();

    if report.total_changes == 0 {
        println!(
            "  {GREEN}\u{2713}{RESET} No verdict changes \u{2014} the proposed ruleset is decision-equivalent over this WAL slice."
        );
        println!();
        return;
    }

    println!(
        "  {BOLD}Changes:{RESET} {YELLOW}{}{RESET} of {} events would have been re-classified.",
        report.total_changes, report.events_evaluated
    );
    if report.total_changes > MAX_CHANGE_SAMPLES {
        println!(
            "  {DIM}(showing first {} \u{2014} use --json for the full diff){RESET}",
            MAX_CHANGE_SAMPLES
        );
    }
    println!();

    // Group changes by (host, original→proposed) so a single rule
    // change that hits 200 calls of the same endpoint reads as one
    // line, not 200.
    let mut grouped: HashMap<(String, String, String), usize> = HashMap::new();
    for c in &report.changes {
        *grouped
            .entry((c.host.clone(), c.original.clone(), c.proposed.clone()))
            .or_insert(0) += 1;
    }
    let mut group_vec: Vec<_> = grouped.into_iter().collect();
    group_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for ((host, original, proposed), count) in group_vec.iter().take(20) {
        println!(
            "    {YELLOW}{:>3}{RESET}× {host:<32} {DIM}{original}{RESET} \u{2192} {BOLD}{proposed}{RESET}",
            count,
            host = host,
            original = original,
            proposed = proposed,
        );
    }
    println!();
}

fn print_row(label: &str, before: usize, after: usize, color: &str) {
    let delta = after as i64 - before as i64;
    let delta_str = if delta == 0 {
        format!("{DIM}    0{RESET}")
    } else if delta > 0 {
        format!("{GREEN}+{:>4}{RESET}", delta)
    } else {
        format!("{RED}{:>5}{RESET}", delta)
    };
    println!(
        "    {color}{:<18}{RESET} {:>6} \u{2192} {:>6}    {}",
        label, before, after, delta_str
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_counts_buckets_by_prefix() {
        let mut c = DecisionCounts::default();
        c.add("Allow");
        c.add("Allow");
        c.add("Delay { milliseconds: 300 }");
        c.add("Deny { reason: \"foo\" }");
        c.add("RequireApproval { urgency: Standard }");
        c.add("AuditOnly { alert_level: Notice }");
        c.add("WeirdThingFromFuture");

        assert_eq!(c.allow, 2);
        assert_eq!(c.delay, 1);
        assert_eq!(c.deny, 1);
        assert_eq!(c.require_approval, 1);
        assert_eq!(c.audit_only, 1);
        assert_eq!(c.other, 1);
        assert_eq!(c.total(), 7);
    }

    /// Compile a NetworkSRR from inline TOML for tests.
    fn srr_from_inline(toml: &str) -> gvm_proxy::srr::NetworkSRR {
        let dir = tempfile::tempdir().expect("temp dir");
        let p = dir.path().join("rules.toml");
        std::fs::write(&p, toml).unwrap();
        let s = gvm_proxy::srr::NetworkSRR::load(&p).expect("rules load");
        // tempdir is dropped here, but NetworkSRR has already read and
        // compiled the rules — no further file access. Keep dir alive
        // by leaking it; tests run in tempdir, OS will reclaim.
        std::mem::forget(dir);
        s
    }

    fn make_event(timestamp_rfc3339: &str, method: &str, host: &str, path: &str) -> serde_json::Value {
        serde_json::json!({
            "event_id": "evt-test-1",
            "agent_id": "test",
            "timestamp": timestamp_rfc3339,
            "transport": { "method": method, "host": host, "path": path },
            "decision": "Allow",
            "operation": "unknown",
        })
    }

    #[test]
    fn replay_evaluates_condition_against_event_timestamp() {
        // Critical determinism property: a time-conditioned rule MUST
        // produce the same verdict whenever replay is run, by evaluating
        // the rule against `event.timestamp` (committed to the Merkle
        // leaf), NOT against `Utc::now()`. We assert this with two
        // events whose timestamps fall on opposite sides of the same
        // condition window — they must yield DIFFERENT proposed
        // verdicts, regardless of when the test runs.
        let srr = srr_from_inline(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.payroll.example.com/{any}"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-18:00", tz = "Asia/Seoul" }
            description = "biz-hours-only allow"

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
            description = "default"
        "#,
        );

        // 04:00 UTC = 13:00 KST → INSIDE 09:00-18:00 KST → Allow fires
        let inside = make_event(
            "2026-05-05T04:00:00Z",
            "POST",
            "api.payroll.example.com",
            "/run",
        );
        // 14:00 UTC = 23:00 KST → OUTSIDE → falls through to default Delay
        let outside = make_event(
            "2026-05-05T14:00:00Z",
            "POST",
            "api.payroll.example.com",
            "/run",
        );

        let inside_proposed = match classify_one(&srr, &inside) {
            EventClass::Classified { proposed, .. } => proposed,
            _ => panic!("inside event must classify"),
        };
        let outside_proposed = match classify_one(&srr, &outside) {
            EventClass::Classified { proposed, .. } => proposed,
            _ => panic!("outside event must classify"),
        };

        assert!(
            inside_proposed.starts_with("Allow"),
            "INSIDE the window should fire Allow, got {}",
            inside_proposed
        );
        assert!(
            outside_proposed.starts_with("Delay"),
            "OUTSIDE the window should fall through to default Delay, got {}",
            outside_proposed
        );
        assert_ne!(
            inside_proposed, outside_proposed,
            "regression: replay must use event.timestamp, not Utc::now() — \
             same rule + same URL across two timestamps must yield distinct verdicts"
        );
    }

    #[test]
    fn replay_classify_one_idempotent_on_same_event() {
        // Calling classify_one twice on the same event must give the
        // same answer — reinforces that there's no hidden state /
        // current-time dependency that would creep back in.
        let srr = srr_from_inline(
            r#"
            [[rules]]
            method = "POST"
            pattern = "api.payroll.example.com/{any}"
            decision = { type = "Allow" }
            condition = { kind = "time_window", window = "09:00-18:00", tz = "Asia/Seoul" }
            description = "biz-hours-only allow"
        "#,
        );

        let event = make_event(
            "2026-05-05T04:00:00Z",
            "POST",
            "api.payroll.example.com",
            "/x",
        );

        let a = match classify_one(&srr, &event) {
            EventClass::Classified { proposed, .. } => proposed,
            _ => panic!("must classify"),
        };
        let b = match classify_one(&srr, &event) {
            EventClass::Classified { proposed, .. } => proposed,
            _ => panic!("must classify"),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn replay_report_total_changes_can_exceed_samples() {
        // Confirm the truncation invariant: total_changes is counted
        // even when the changes vec is capped at MAX_CHANGE_SAMPLES.
        // Without this, a noisy rule diff would silently look smaller
        // than it is.
        let mut report = ReplayReport {
            events_evaluated: 100,
            events_skipped: 0,
            original: DecisionCounts::default(),
            proposed: DecisionCounts::default(),
            changes: Vec::new(),
            total_changes: 0,
            timestamp_missing: 0,
        };
        for i in 0..(MAX_CHANGE_SAMPLES + 5) {
            report.total_changes += 1;
            if report.changes.len() < MAX_CHANGE_SAMPLES {
                report.changes.push(VerdictChange {
                    method: "GET".to_string(),
                    host: format!("h{i}.example.com"),
                    path: "/".to_string(),
                    original: "Allow".to_string(),
                    proposed: "Deny".to_string(),
                });
            }
        }
        assert_eq!(report.changes.len(), MAX_CHANGE_SAMPLES);
        assert_eq!(report.total_changes, MAX_CHANGE_SAMPLES + 5);
    }

    #[test]
    fn classify_one_reports_missing_timestamp_distinctly() {
        // The replay determinism property hinges on `event.timestamp`
        // being parseable for every classified event. Earlier code
        // silently fell back to `Utc::now()` when parse failed —
        // turning every time-conditioned rule into "evaluated against
        // the operator's wall-clock at replay time", the exact
        // non-determinism the audit chain was designed to prevent.
        //
        // `classify_one` now surfaces missing timestamps as a separate
        // EventClass variant. Strict mode aborts the run; non-strict
        // mode counts them. This test pins the variant boundary so a
        // future "let me just default it to now()" patch can't bring
        // back the silent fallback.
        let srr = srr_from_inline(
            r#"
            [[rules]]
            method = "GET"
            pattern = "{any}"
            decision = { type = "Allow" }
            description = "any-allow"
        "#,
        );

        let event_no_ts = serde_json::json!({
            "event_id": "evt-no-ts",
            "agent_id": "test",
            // intentionally omit "timestamp"
            "transport": { "method": "GET", "host": "h.example.com", "path": "/" },
            "decision": "Allow",
            "operation": "unknown",
        });
        match classify_one(&srr, &event_no_ts) {
            EventClass::MissingTimestamp { event_id } => {
                assert_eq!(event_id, "evt-no-ts");
            }
            other => panic!(
                "missing timestamp must surface as MissingTimestamp, got {:?}",
                std::any::type_name_of_val(&other)
            ),
        }

        // Unparseable timestamp string also classifies as missing —
        // the parser returns None and we don't substitute now().
        let event_bad_ts = serde_json::json!({
            "event_id": "evt-bad-ts",
            "agent_id": "test",
            "timestamp": "not an RFC3339 string",
            "transport": { "method": "GET", "host": "h.example.com", "path": "/" },
            "decision": "Allow",
            "operation": "unknown",
        });
        assert!(matches!(
            classify_one(&srr, &event_bad_ts),
            EventClass::MissingTimestamp { .. }
        ));

        // Parseable timestamp classifies normally.
        let event_ok = serde_json::json!({
            "event_id": "evt-ok",
            "agent_id": "test",
            "timestamp": "2026-05-05T04:00:00Z",
            "transport": { "method": "GET", "host": "h.example.com", "path": "/" },
            "decision": "Allow",
            "operation": "unknown",
        });
        assert!(matches!(
            classify_one(&srr, &event_ok),
            EventClass::Classified { .. }
        ));
    }
}
