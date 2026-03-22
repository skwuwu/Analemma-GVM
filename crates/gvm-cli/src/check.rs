use crate::ui;
use anyhow::{Context, Result};
use std::time::Instant;

/// Dry-run policy check: sends a preflight request to the proxy's check endpoint.
/// No external API calls are made — only the policy engine evaluates the request.
pub async fn run_check(
    operation: &str,
    service: &str,
    tier: &str,
    sensitivity: &str,
    host: &str,
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
            "resource": resource,
            "target_host": host,
            "method": method,
        }))
        .send()
        .await
        .context("Failed to reach proxy — is it running?")?;

    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    let decision =
        body["decision"]
            .as_str()
            .unwrap_or(if status.is_success() { "Allow" } else { "Deny" });
    let event_id = body["event_id"].as_str();
    let next_action = body["next_action"].as_str();

    ui::print_check_result(
        operation,
        service,
        tier,
        sensitivity,
        host,
        method,
        decision,
        elapsed,
        event_id,
        next_action,
    );

    Ok(())
}
