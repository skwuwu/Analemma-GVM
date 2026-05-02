use anyhow::{Context, Result};
use gvm_types::GVMEvent;
use std::io::BufRead;

/// Recompute the expected event_hash from event fields. Dispatches
/// between v1 (legacy `operation: String`) and v2 (Phase 1
/// `operation_descriptor` with salted detail digest) based on whether
/// the event carries a descriptor. Mirrors `gvm_proxy::merkle::compute_event_hash`
/// — kept thin here so the CLI binary doesn't pull in gvm-proxy's
/// axum/hyper/rustls dependency tree, but the hash MUST stay
/// bit-identical to the writer's hash or every legitimate v2 record
/// would be flagged as tampered.
fn recompute_event_hash(event: &GVMEvent) -> String {
    // Reuse the canonical implementation from gvm-types (same crate
    // both the writer and the verifier already depend on). This
    // automatically handles v1 vs v2 dispatch, so the CLI report stays
    // in sync with whatever schema the writer emitted.
    gvm_types::proof::recompute_event_hash(event)
}

/// Verify WAL integrity: check for parseable events, monotonic timestamps,
/// and hash chain continuity.
pub async fn verify_wal(wal_file: &str) -> Result<()> {
    let file = std::fs::File::open(wal_file)
        .with_context(|| format!("Failed to open WAL file: {}", wal_file))?;
    let reader = std::io::BufReader::new(file);

    let mut total_lines: u64 = 0;
    let mut valid_events: u64 = 0;
    let mut corrupt_lines: u64 = 0;
    let mut merkle_batch_records: u64 = 0;
    let mut prev_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut out_of_order: u64 = 0;
    let mut events_with_hash: u64 = 0;
    let mut events_without_hash: u64 = 0;
    let mut pending_events: u64 = 0;
    let mut hash_mismatches: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total_lines += 1;

        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                corrupt_lines += 1;
                continue;
            }
        };

        // Merkle batch records are valid WAL metadata, not GVMEvent rows.
        if value.get("merkle_root").is_some() && value.get("batch_id").is_some() {
            merkle_batch_records += 1;
            continue;
        }

        match serde_json::from_value::<GVMEvent>(value) {
            Ok(event) => {
                valid_events += 1;

                // Check timestamp ordering
                if let Some(prev) = prev_timestamp {
                    if event.timestamp < prev {
                        out_of_order += 1;
                    }
                }
                prev_timestamp = Some(event.timestamp);

                // Check event hash presence and integrity
                if let Some(stored_hash) = &event.event_hash {
                    events_with_hash += 1;
                    let computed = recompute_event_hash(&event);
                    if *stored_hash != computed {
                        hash_mismatches += 1;
                    }
                } else {
                    events_without_hash += 1;
                }

                // Check for stuck Pending events
                if matches!(event.status, gvm_types::EventStatus::Pending) {
                    pending_events += 1;
                }
            }
            Err(_) => {
                corrupt_lines += 1;
            }
        }
    }

    let chain = gvm_types::verify_integrity_chain(std::path::Path::new(wal_file));

    println!("WAL integrity report: {}", wal_file);
    println!("{}", "-".repeat(50));
    println!("  Total lines:             {}", total_lines);
    println!("  Valid events:            {}", valid_events);
    println!("  Merkle batch records:    {}", merkle_batch_records);
    println!("  Corrupt/unparseable:     {}", corrupt_lines);
    println!("  Timestamp out-of-order:  {}", out_of_order);
    println!("  Events with hash:        {}", events_with_hash);
    println!("  Events without hash:     {}", events_without_hash);
    println!("  Hash mismatches:         {}", hash_mismatches);
    println!("  Stuck Pending events:    {}", pending_events);
    println!(
        "  Integrity chain (GIC):   {}/{} valid links",
        chain.valid_links, chain.total_config_loads
    );
    println!();

    if corrupt_lines > 0 {
        println!(
            "  WARNING: {} corrupt entries found. These will be skipped during recovery.",
            corrupt_lines
        );
    }
    if out_of_order > 0 {
        println!(
            "  WARNING: {} out-of-order timestamps detected. May indicate concurrent write issues.",
            out_of_order
        );
    }
    if pending_events > 0 {
        println!(
            "  WARNING: {} events in Pending state (possible phantom records from crash).",
            pending_events
        );
    }
    if hash_mismatches > 0 {
        println!(
            "  TAMPER DETECTED: {} event(s) have invalid hashes. WAL integrity compromised.",
            hash_mismatches
        );
    }
    if let Some(ref broken_at) = chain.first_break {
        println!(
            "  TAMPER DETECTED: integrity chain broke at event_id={}. \
             A gvm.system.config_load event's previous_state does not match the \
             preceding config_hash. WAL may have been edited or truncated.",
            broken_at
        );
    }
    if corrupt_lines == 0
        && out_of_order == 0
        && pending_events == 0
        && hash_mismatches == 0
        && chain.first_break.is_none()
    {
        println!("  OK: WAL integrity verified. No issues found.");
    }

    Ok(())
}

/// Export events from WAL as JSON, optionally filtered by time window.
pub async fn export_events(since: &str, wal_file: &str, format: &str) -> Result<()> {
    let duration_secs = parse_duration(since)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(duration_secs);

    let file = std::fs::File::open(wal_file)
        .with_context(|| format!("Failed to open WAL file: {}", wal_file))?;
    let reader = std::io::BufReader::new(file);

    let mut events: Vec<GVMEvent> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<GVMEvent>(trimmed) {
            if event.timestamp >= cutoff {
                events.push(event);
            }
        }
    }

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        "jsonl" => {
            for event in &events {
                println!("{}", serde_json::to_string(event)?);
            }
        }
        _ => {
            anyhow::bail!("Unsupported export format '{}'. Use json or jsonl.", format);
        }
    }

    eprintln!("Exported {} event(s) since {}.", events.len(), since);

    Ok(())
}

/// Parse duration string.
fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str.parse().context("Invalid duration number")?;
    let seconds = match unit {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => anyhow::bail!("Unknown duration unit '{}'. Use s/m/h/d.", unit),
    };
    Ok(seconds)
}
