use anyhow::Result;
use std::collections::HashMap;

use crate::events;

/// Per-agent token usage statistics.
struct AgentStats {
    total_tokens: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    llm_events: u64,
    total_events: u64,
    denied_events: u64,
    delayed_events: u64,
}

/// Show per-agent token usage and governance summary.
pub async fn show_token_stats(
    agent: Option<String>,
    last: &str,
    wal_file: Option<&str>,
) -> Result<()> {
    let all_events =
        match events::load_events(wal_file, "gvm stats --tokens --wal-file data/wal.log")? {
            Some(e) => e,
            None => return Ok(()),
        };

    let duration_secs = parse_duration(last)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(duration_secs);

    let mut agent_map: HashMap<String, AgentStats> = HashMap::new();

    for event in &all_events {
        if event.timestamp < cutoff {
            continue;
        }
        if let Some(ref a) = agent {
            if &event.agent_id != a {
                continue;
            }
        }

        let stats = agent_map
            .entry(event.agent_id.clone())
            .or_insert(AgentStats {
                total_tokens: 0,
                prompt_tokens: 0,
                completion_tokens: 0,
                llm_events: 0,
                total_events: 0,
                denied_events: 0,
                delayed_events: 0,
            });

        stats.total_events += 1;

        if event.decision.contains("Deny") {
            stats.denied_events += 1;
        }
        if event.decision.contains("Delay") {
            stats.delayed_events += 1;
        }

        if let Some(ref trace) = event.llm_trace {
            stats.llm_events += 1;
            if let Some(ref usage) = trace.usage {
                stats.prompt_tokens += usage.prompt_tokens.unwrap_or(0);
                stats.completion_tokens += usage.completion_tokens.unwrap_or(0);
                stats.total_tokens += usage.computed_total().unwrap_or(0);
            }
        }
    }

    if agent_map.is_empty() {
        println!("No events found in the specified time window.");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<12} {:<12} {:<12} {:<10} {:<10} {:<10}",
        "Agent", "Events", "LLM Calls", "Prompt Tk", "Compl Tk", "Total Tk", "Denied", "Delayed"
    );
    println!("{}", "-".repeat(96));

    let mut sorted_agents: Vec<_> = agent_map.iter().collect();
    sorted_agents.sort_by(|a, b| b.1.total_tokens.cmp(&a.1.total_tokens));

    let mut grand_total_tokens: u64 = 0;
    let mut grand_denied: u64 = 0;

    for (agent_id, stats) in &sorted_agents {
        println!(
            "{:<20} {:<10} {:<12} {:<12} {:<12} {:<10} {:<10} {:<10}",
            agent_id,
            stats.total_events,
            stats.llm_events,
            stats.prompt_tokens,
            stats.completion_tokens,
            stats.total_tokens,
            stats.denied_events,
            stats.delayed_events,
        );
        grand_total_tokens += stats.total_tokens;
        grand_denied += stats.denied_events;
    }

    println!("{}", "-".repeat(96));
    println!(
        "Total: {} agent(s), {} tokens consumed, {} actions blocked",
        sorted_agents.len(),
        grand_total_tokens,
        grand_denied,
    );

    Ok(())
}

/// Show rollback savings estimate.
/// Counts denied events that targeted LLM providers — these represent
/// tokens that would have been consumed without governance.
pub async fn show_rollback_savings(last: &str, wal_file: Option<&str>) -> Result<()> {
    let all_events = match events::load_events(
        wal_file,
        "gvm stats --rollback-savings --wal-file data/wal.log",
    )? {
        Some(e) => e,
        None => return Ok(()),
    };

    let duration_secs = parse_duration(last)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(duration_secs);

    let mut denied_llm_count: u64 = 0;
    let mut denied_total_count: u64 = 0;
    let mut delayed_count: u64 = 0;
    let mut total_events: u64 = 0;

    for event in &all_events {
        if event.timestamp < cutoff {
            continue;
        }
        total_events += 1;

        if event.decision.contains("Deny") {
            denied_total_count += 1;
            // Check if this targeted an LLM provider
            if let Some(ref transport) = event.transport {
                let host = transport.host.to_lowercase();
                if host.contains("openai.com")
                    || host.contains("anthropic.com")
                    || host.contains("googleapis.com")
                {
                    denied_llm_count += 1;
                }
            }
        }
        if event.decision.contains("Delay") {
            delayed_count += 1;
        }
    }

    println!("Governance savings (last {}):", last);
    println!("{}", "-".repeat(50));
    println!("  Total events processed:     {}", total_events);
    println!("  Actions blocked (Deny):     {}", denied_total_count);
    println!("  LLM calls prevented:        {}", denied_llm_count);
    println!("  Actions delayed (IC-2):     {}", delayed_count);
    println!();
    if denied_llm_count > 0 {
        println!(
            "  Estimated savings: {} LLM API calls avoided by governance.",
            denied_llm_count
        );
    } else {
        println!("  No LLM calls were blocked in this period.");
    }

    Ok(())
}

/// Parse duration string (reuse from events module logic).
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

use anyhow::Context;
