use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::time::Instant;

/// Dry-run policy check: sends a preflight request to the proxy's check endpoint.
/// No external API calls are made — only the policy engine evaluates the request.
#[allow(clippy::too_many_arguments)]
pub async fn run_check(
    operation: &str,
    agent_id: &str,
    service: &str,
    tier: &str,
    sensitivity: &str,
    host: &str,
    path: &str,
    method: &str,
    proxy_url: &str,
) -> Result<()> {
    let resource = serde_json::json!({
        "service": service,
        "tier": tier,
        "sensitivity": sensitivity,
    });

    let client = reqwest::Client::new();
    let check_url = format!("{}/gvm/check", proxy_url);

    let t0 = Instant::now();
    let resp = client
        .post(&check_url)
        .json(&serde_json::json!({
            "operation": operation,
            "agent_id": agent_id,
            "resource": resource,
            "target_host": host,
            "target_path": path,
            "method": method,
        }))
        .send()
        .await
        .context("Failed to reach proxy — is it running?")?;

    let _elapsed = t0.elapsed().as_secs_f64() * 1000.0;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    // Extract fields from response
    let decision =
        body["decision"]
            .as_str()
            .unwrap_or(if status.is_success() { "Allow" } else { "Deny" });
    let decision_path = body["decision_path"].as_str();
    let _policy_decision = body["policy_decision"].as_str();
    let _srr_decision = body["srr_decision"].as_str();
    let decision_source = body["decision_source"].as_str();
    let matched_rule = body["matched_rule"].as_str();
    let engine_us = body["engine_us"].as_f64();
    let next_action = body["next_action"].as_str();
    let is_default_caution = body["default_caution"].as_bool().unwrap_or(false);

    // ── Pretty print ──
    eprintln!();
    eprintln!("  {BOLD}GVM Policy Check (dry-run){RESET}");
    eprintln!();
    eprintln!("  {DIM}Operation:{RESET}    {CYAN}{operation}{RESET}");
    eprintln!("  {DIM}Agent:{RESET}        {agent_id}");
    eprintln!("  {DIM}Target:{RESET}       {method} {host}{path}");
    eprintln!("  {DIM}Resource:{RESET}     {service} / {tier} / {sensitivity}");
    eprintln!();

    // Decision with color
    let decision_color = match decision {
        "Allow" => GREEN,
        "Deny" => RED,
        _ => YELLOW,
    };
    eprintln!("  {BOLD}Decision:{RESET}     {decision_color}{decision}{RESET}");

    // Decision path
    if let Some(dp) = decision_path {
        eprintln!("  {DIM}Path:{RESET}         {dp}");
    }

    // Source
    if let Some(src) = decision_source {
        eprintln!("  {DIM}Source:{RESET}       {src}");
    }

    // Matched rule
    if let Some(rule) = matched_rule {
        eprintln!("  {DIM}Matched rule:{RESET} {rule}");
    }

    // Default caution warning
    if is_default_caution {
        eprintln!("  {YELLOW}⚠ Default-to-Caution{RESET} {DIM}(no explicit SRR rule — add one with `gvm suggest`){RESET}");
    }

    // Latency
    if let Some(us) = engine_us {
        if us < 1000.0 {
            eprintln!("  {DIM}Latency:{RESET}      {us:.0}μs");
        } else {
            eprintln!("  {DIM}Latency:{RESET}      {:.1}ms", us / 1000.0);
        }
    }

    // Next action
    if let Some(action) = next_action {
        eprintln!("  {DIM}Action:{RESET}       {action}");
    }

    eprintln!();

    Ok(())
}

/// Machine-readable JSON output for scripts and CI.
/// Outputs the proxy's check response directly to stdout.
#[allow(clippy::too_many_arguments)]
pub async fn run_check_json(
    operation: &str,
    agent_id: &str,
    service: &str,
    tier: &str,
    sensitivity: &str,
    host: &str,
    path: &str,
    method: &str,
    proxy_url: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let check_url = format!("{}/gvm/check", proxy_url);

    let resp = client
        .post(&check_url)
        .json(&serde_json::json!({
            "operation": operation,
            "agent_id": agent_id,
            "resource": {
                "service": service,
                "tier": tier,
                "sensitivity": sensitivity,
            },
            "target_host": host,
            "target_path": path,
            "method": method,
        }))
        .send()
        .await
        .context("Failed to reach proxy — is it running?")?;

    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    println!("{}", serde_json::to_string(&body).unwrap_or_default());
    Ok(())
}
