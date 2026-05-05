//! `gvm dns status` — operator inspection of DNS governance state.
//!
//! Calls `GET /gvm/dns/state` on the admin port and renders either a
//! human-readable table or pass-through JSON. Read-only; no side
//! effects on the running proxy. Closes the "opaque decay" gap
//! identified in the charter review — operators can now answer
//! "which domain is currently at which tier and why" without grepping
//! the WAL.

use anyhow::{Context, Result};

use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

pub(crate) async fn run_status(proxy: &str, emit_json: bool) -> Result<()> {
    let admin_url = crate::run::derive_admin_url(proxy);
    let url = format!("{}/gvm/dns/state", admin_url.trim_end_matches('/'));
    let resp = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {} failed (proxy not running?)", url))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "DNS state endpoint returned HTTP {} — {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .context("DNS state response is not valid JSON")?;

    if emit_json {
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    print_human(&json);
    Ok(())
}

fn print_human(json: &serde_json::Value) {
    println!();
    println!("  {BOLD}DNS governance state{RESET}");

    if json.get("enabled").and_then(|v| v.as_bool()) == Some(false) {
        println!("  {DIM}DNS governance disabled in proxy config (dns.enabled = false).{RESET}");
        println!();
        return;
    }

    let global = json
        .get("global_unique_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tier4_t = json
        .get("tier4_threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tier3_t = json
        .get("tier3_threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let window_secs = json
        .get("window_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let tracked = json
        .get("tracked_base_domains")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!();
    println!("  {DIM}Window:{RESET}     {window_secs}s sliding");
    println!(
        "  {DIM}Thresholds:{RESET} Tier 3 (subdomain burst) > {tier3_t}    Tier 4 (global flood) > {tier4_t}"
    );
    let global_color = if global > tier4_t {
        RED
    } else if global * 2 > tier4_t {
        YELLOW
    } else {
        GREEN
    };
    println!(
        "  {DIM}Global unique:{RESET} {global_color}{global}{RESET} / {tier4_t}    {DIM}({} tracked base domains){RESET}",
        tracked
    );

    let domains = json.get("domains").and_then(|v| v.as_array());
    let Some(domains) = domains else {
        println!();
        return;
    };
    if domains.is_empty() {
        println!();
        println!(
            "  {DIM}No tracked base domains — all queries hit Tier 1 (known) right now.{RESET}"
        );
        println!();
        return;
    }

    println!();
    println!(
        "  {DIM}{:<32} {:>10} {:>8} {:>14}{RESET}",
        "BASE_DOMAIN", "UNIQUE", "TIER", "AGE"
    );
    for d in domains.iter().take(50) {
        let base = d.get("base_domain").and_then(|v| v.as_str()).unwrap_or("?");
        let unique = d
            .get("unique_subdomain_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tier = d.get("tier").and_then(|v| v.as_str()).unwrap_or("unknown");
        let age = d
            .get("oldest_entry_age_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let tier_colored = match tier {
            "anomalous" => format!("{RED}{BOLD}{}{RESET}", tier),
            "flood" => format!("{RED}{BOLD}{}{RESET}", tier),
            "unknown" => format!("{YELLOW}{}{RESET}", tier),
            _ => format!("{DIM}{}{RESET}", tier),
        };

        let unique_colored = if unique > tier3_t {
            format!("{RED}{:>10}{RESET}", unique)
        } else if unique * 2 > tier3_t {
            format!("{YELLOW}{:>10}{RESET}", unique)
        } else {
            format!("{:>10}", unique)
        };

        println!(
            "  {CYAN}{:<32}{RESET} {} {:>8} {:>12}s",
            truncate(base, 32),
            unique_colored,
            tier_colored,
            age,
        );
    }
    if domains.len() > 50 {
        println!(
            "  {DIM}(showing 50 of {} — use --json for the full list){RESET}",
            domains.len()
        );
    }
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_handles_multibyte() {
        // Same correctness invariant as `sandbox_inspect::truncate`.
        let s = "한국어-도메인";
        assert!(truncate(s, 5).chars().count() <= 5);
        assert!(truncate(s, 100).chars().count() <= 7);
    }
}
