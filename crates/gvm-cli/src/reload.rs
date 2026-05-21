use crate::ui::{BOLD, GREEN, RED, RESET};
use anyhow::{Context, Result};

/// Hot-reload SRR rules and registry from disk.
/// Sends POST /gvm/reload to the admin port (localhost-only by default;
/// authenticated via GVM_ADMIN_TOKEN when admin_listen is non-loopback).
pub async fn run_reload(proxy_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let admin_url = crate::run::derive_admin_url(proxy_url);
    let url = format!("{}/gvm/reload", admin_url.trim_end_matches('/'));

    let resp = crate::run::with_admin_bearer(client.post(&url))
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
