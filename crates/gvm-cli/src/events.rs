use anyhow::{Context, Result};
use gvm_types::GVMEvent;
use std::io::BufRead;

/// Parse a duration string like "1h", "30m", "7d" into seconds.
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

/// Read events from a WAL file (JSON lines format).
fn read_wal_events(path: &str) -> Result<Vec<GVMEvent>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open WAL file: {}", path))?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<GVMEvent>(trimmed) {
            Ok(event) => events.push(event),
            Err(_) => continue, // skip malformed lines
        }
    }

    Ok(events)
}

/// List events with optional filters.
pub async fn list_events(
    agent: Option<String>,
    last: &str,
    wal_file: Option<&str>,
    format: &str,
) -> Result<()> {
    let duration_secs = parse_duration(last)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(duration_secs);

    let events = if let Some(path) = wal_file {
        read_wal_events(path)?
    } else {
        // NATS not yet connected — fall back to default WAL path
        eprintln!("NATS not yet connected. Use --wal-file to read from WAL directly.");
        eprintln!("Example: gvm events list --wal-file data/wal.log");
        return Ok(());
    };

    let filtered: Vec<&GVMEvent> = events
        .iter()
        .filter(|e| e.timestamp >= cutoff)
        .filter(|e| {
            if let Some(ref a) = agent {
                &e.agent_id == a
            } else {
                true
            }
        })
        .collect();

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    // Table format
    if filtered.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    println!(
        "{:<24} {:<20} {:<24} {:<18} {:<12}",
        "Timestamp", "Agent", "Operation", "Decision", "Status"
    );
    println!("{}", "-".repeat(98));

    for event in &filtered {
        let ts = event.timestamp.format("%Y-%m-%d %H:%M:%S");
        let status = format!("{:?}", event.status);
        println!(
            "{:<24} {:<20} {:<24} {:<18} {:<12}",
            ts, event.agent_id, event.operation, event.decision, status,
        );
    }

    println!("\n{} event(s) found.", filtered.len());

    Ok(())
}

/// Show causal chain for a trace ID.
pub async fn trace_events(trace_id: &str, wal_file: Option<&str>) -> Result<()> {
    let events = if let Some(path) = wal_file {
        read_wal_events(path)?
    } else {
        eprintln!("NATS not yet connected. Use --wal-file to read from WAL directly.");
        eprintln!("Example: gvm events trace --trace-id xxx --wal-file data/wal.log");
        return Ok(());
    };

    let mut traced: Vec<&GVMEvent> = events
        .iter()
        .filter(|e| e.trace_id == trace_id)
        .collect();

    if traced.is_empty() {
        println!("No events found for trace_id: {}", trace_id);
        return Ok(());
    }

    traced.sort_by_key(|e| e.timestamp);

    println!("[trace {}]", trace_id);
    for (i, event) in traced.iter().enumerate() {
        let indent = "  ".repeat(i);
        let connector = if i == 0 { "" } else { "\u{2514}\u{2500} " };
        let status = format!("{:?}", event.status);
        println!(
            "{}{}{} ({}) \u{2192} {}",
            indent, connector, event.operation, event.decision, status,
        );
    }

    Ok(())
}
