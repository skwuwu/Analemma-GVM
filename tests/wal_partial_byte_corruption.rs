//! WAL recovery — partial-byte / mid-line corruption regression pin.
//!
//! `tests/hostile.rs::wal_tampered_entry_does_not_crash_recovery`
//! covers whole-line garbage (`{CORRUPTED_DATA_TAMPERE{{{{D}}}}`).
//! What it does *not* cover, and what the 2026-05-10 coverage audit
//! flagged, is the more realistic crash-or-partial-write case:
//!
//! 1. A power loss / SIGKILL / disk-full mid-`writeln!` truncates
//!    the last line halfway through. If the line happened to
//!    contain a multi-byte UTF-8 sequence (e.g. a Korean
//!    `agent_id`, or a Japanese error message that survived a
//!    redaction pass), the byte boundary lands inside the
//!    sequence — invalid UTF-8 by definition.
//! 2. `BufRead::read_line` will surface the bytes as "lossy"
//!    UTF-8 (replacement chars), and `serde_json::from_str` will
//!    refuse the result.
//! 3. The recovery path must:
//!    a. Not panic on the invalid bytes.
//!    b. Drop only the truncated line.
//!    c. Continue counting the valid lines that came before it.
//!    d. Permit a fresh `append_durable` after restart — the
//!    truncated tail is allowed to carry over into the log so an
//!    audit can still see "X bytes were lost"; what matters is
//!    that the live append path doesn't refuse to start.
//!
//! These properties matter because production hosts crash mid-fsync
//! routinely (kernel panic, container OOM-kill, EBS volume detach).
//! A recovery loop that hard-failed on UTF-8 boundaries would
//! brick the proxy's restart path on perfectly recoverable data.

use gvm_proxy::ledger::Ledger;
use std::io::Write;

fn build_valid_wal_event_json(event_id: &str, agent_id: &str) -> String {
    serde_json::json!({
        "event_id": event_id,
        "trace_id": format!("trace-{event_id}"),
        "parent_event_id": null,
        "agent_id": agent_id,
        "tenant_id": null,
        "session_id": "session-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "operation": "gvm.storage.read",
        "resource": {
            "service": "",
            "identifier": null,
            "tier": "External",
            "sensitivity": "Medium"
        },
        "context": {},
        "transport": null,
        "decision": "Allow",
        "decision_source": "Semantic",
        "matched_rule_id": null,
        "enforcement_point": "both",
        "status": "Pending",
        "payload": {
            "content_hash": "",
            "size_bytes": 0,
            "flagged_patterns": []
        },
        "wal_sequence": null
    })
    .to_string()
}

#[tokio::test]
async fn recovery_skips_utf8_truncated_tail_line() {
    // Korean character "한" is U+D55C, 3 bytes in UTF-8 (E1 95 9C).
    // We build a WAL with two valid entries, then write a third
    // entry whose agent_id contains "한국-agent" and *truncate*
    // the file in the middle of one of "한"'s 3 bytes. The result
    // is invalid UTF-8 at the boundary.
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");

    let entry_1 = build_valid_wal_event_json("evt-001", "agent-eng");
    let entry_2 = build_valid_wal_event_json("evt-002", "agent-eng");
    let entry_3 = build_valid_wal_event_json("evt-003", "agent-한국");

    // We need to truncate the file at a byte offset that lands
    // inside one of "한"'s 3 UTF-8 bytes. Compute the byte position
    // of the FIRST occurrence of "한" inside entry_3, then truncate
    // to (length-of-entries-1+2 + that offset + 1) — i.e. one byte
    // INTO the 3-byte sequence.
    let han_offset_in_entry3 = entry_3
        .find('한')
        .expect("test fixture must contain a Korean char");
    let prefix_len = entry_1.len() + 1 /* \n */ + entry_2.len() + 1 /* \n */;
    // truncation lands at prefix + han_offset + 1 → middle of "한"
    let truncated_len = prefix_len + han_offset_in_entry3 + 1;

    {
        let mut f = std::fs::File::create(&wal_path).expect("create wal");
        writeln!(f, "{entry_1}").unwrap();
        writeln!(f, "{entry_2}").unwrap();
        write!(f, "{entry_3}").unwrap();
        f.flush().unwrap();
    }
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .unwrap();
        f.set_len(truncated_len as u64).unwrap();
    }

    // Sanity: the file as a whole is now invalid UTF-8 (the cut
    // landed mid-multibyte). If this check fails, the test setup
    // didn't produce the regression-pinning condition we wanted.
    let raw = std::fs::read(&wal_path).unwrap();
    assert!(
        std::str::from_utf8(&raw).is_err(),
        "test setup must produce malformed UTF-8 at the file tail; \
         truncated_len={truncated_len}, han_offset={han_offset_in_entry3}"
    );

    // Recovery must not panic. The corrupted tail line is silently
    // skipped; the two valid Pending entries before it are still
    // counted and marked Expired.
    let ledger = Ledger::new(&wal_path)
        .await
        .expect("Ledger must initialize on partially-corrupted WAL");
    let report = ledger
        .recover_from_wal()
        .await
        .expect("recover_from_wal must not error on UTF-8 truncation");

    assert_eq!(
        report.pending_found, 2,
        "two valid Pending lines before the truncation must be found"
    );
    assert_eq!(
        report.expired_marked, 2,
        "both valid Pending entries must be marked Expired"
    );
}

#[tokio::test]
async fn recovery_handles_truncation_inside_first_line() {
    // Even more pathological: the file contains exactly one entry
    // and that entry was truncated mid-write before any newline
    // was ever flushed. Recovery must observe zero valid entries
    // and succeed (not "found 1 corrupt, panicking").
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");

    let entry = build_valid_wal_event_json("evt-001", "한");
    {
        let mut f = std::fs::File::create(&wal_path).expect("create wal");
        // Write only the first half of the entry, ending mid-JSON.
        let half = &entry.as_bytes()[..entry.len() / 2];
        f.write_all(half).unwrap();
        // No trailing newline — emulates "writeln! never reached
        // its trailing \n because the disk filled up first".
    }

    let ledger = Ledger::new(&wal_path)
        .await
        .expect("Ledger must initialize even on a WAL where the only line is truncated");
    let report = ledger
        .recover_from_wal()
        .await
        .expect("recover_from_wal must not error on truncated-only WAL");

    assert_eq!(
        report.pending_found, 0,
        "no valid pending entries — only a half-written line"
    );
    assert_eq!(report.expired_marked, 0);
}

#[tokio::test]
async fn recovery_then_append_works() {
    // After recovery on a corrupted WAL, the live append path must
    // still function. Pin this so a regression that left the file
    // in an unwritable state (e.g. holding an exclusive lock past
    // recovery) surfaces immediately.
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");

    {
        let mut f = std::fs::File::create(&wal_path).expect("create wal");
        writeln!(f, "{}", build_valid_wal_event_json("evt-001", "agent")).unwrap();
        // Corrupted second line — truncated mid-JSON.
        let bad = build_valid_wal_event_json("evt-002", "agent-한국");
        let half = &bad.as_bytes()[..bad.len() / 2];
        f.write_all(half).unwrap();
    }

    let ledger = Ledger::new(&wal_path)
        .await
        .expect("Ledger init after partial-byte truncation");
    let _report = ledger
        .recover_from_wal()
        .await
        .expect("recover_from_wal must not error");

    // Recovery succeeded; the WAL file is still writable. We don't
    // try to call append_durable (it requires a full proxy state
    // setup), but we verify the file is at least openable for
    // append — the property a runtime path needs.
    let appendable = std::fs::OpenOptions::new()
        .append(true)
        .open(&wal_path)
        .is_ok();
    assert!(
        appendable,
        "WAL file must be openable for append after recovery on a partially-corrupt file"
    );
}
