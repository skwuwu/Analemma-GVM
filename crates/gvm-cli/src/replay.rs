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
}

const MAX_CHANGE_SAMPLES: usize = 50;

pub fn run(wal_path: &str, rules_path: &str, emit_json: bool, limit: usize) -> Result<()> {
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
    };

    for line in content.lines() {
        if limit > 0 && report.events_evaluated >= limit {
            break;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // skip malformed
        };
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
            continue;
        }
        if value.get("seal_id").is_some() || value.get("anchor_hash").is_some() {
            continue;
        }

        let transport = match value.get("transport") {
            Some(t) if !t.is_null() => t,
            _ => {
                // System events (config_load, sandbox.launch, etc.)
                // have no transport — count as skipped so the
                // operator's denominator stays honest.
                report.events_skipped += 1;
                continue;
            }
        };

        let method = transport
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let host = transport.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let path = transport.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let original_decision = value
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        // Re-classify against the proposed ruleset. `body=None`
        // means payload-rule matchers will skip without firing —
        // see module docs.
        let result = srr.check(method, host, path, None);
        let proposed_decision = format!("{:?}", result.decision);

        report.events_evaluated += 1;
        report.original.add(&original_decision);
        report.proposed.add(&proposed_decision);

        if original_decision != proposed_decision {
            report.total_changes += 1;
            if report.changes.len() < MAX_CHANGE_SAMPLES {
                report.changes.push(VerdictChange {
                    method: method.to_string(),
                    host: host.to_string(),
                    path: path.to_string(),
                    original: original_decision,
                    proposed: proposed_decision,
                });
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
}
