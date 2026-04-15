use crate::ui::{BOLD, GREEN, RED, RESET};
use anyhow::{Context, Result};

/// Hot-reload SRR rules and registry from disk.
/// Sends POST /gvm/reload to the proxy (localhost only).
pub async fn run_reload(proxy_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/gvm/reload", proxy_url);

    let resp = client
        .post(&url)
        .send()
        .await
        .context("Failed to reach proxy — is it running?")?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    if status.is_success() {
        let srr_count = body["srr_rules"].as_u64().unwrap_or(0);
        eprintln!("  {GREEN}\u{2713}{RESET} {BOLD}Rules reloaded{RESET}");
        eprintln!("    SRR rules:    {srr_count}");
    } else {
        let error = body["error"].as_str().unwrap_or("unknown error");
        eprintln!("  {RED}\u{2717}{RESET} {BOLD}Reload failed{RESET}: {error}");
        anyhow::bail!("Reload failed: {}", error);
    }

    Ok(())
}
