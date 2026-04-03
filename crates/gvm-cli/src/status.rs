use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::Result;

/// Show proxy status: health, SRR rules, WAL state, pending approvals.
pub async fn run_status(proxy_url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health_url = format!("{}/gvm/health", proxy_url);
    let resp = match client.get(&health_url).send().await {
        Ok(r) => r,
        Err(_) => {
            eprintln!("  {RED}\u{2717}{RESET} {BOLD}Proxy not reachable{RESET} at {proxy_url}");
            eprintln!("    Proxy is not running or not listening on this address.");
            eprintln!("    Start with: gvm run <agent>");
            std::process::exit(1);
        }
    };

    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    let status = body["status"].as_str().unwrap_or("unknown");
    let version = body["version"].as_str().unwrap_or("?");
    let srr_rules = body["srr_rules"].as_u64().unwrap_or(0);
    let wal_status = body["wal"].as_str().unwrap_or("unknown");
    let wal_failures = body["wal_failures"].as_u64().unwrap_or(0);
    let emergency = body["emergency_writes"].as_u64().unwrap_or(0);
    let pending = body["pending_approvals"].as_u64().unwrap_or(0);
    let tls_ready = body["tls_ready"].as_bool().unwrap_or(false);

    let status_color = match status {
        "healthy" => GREEN,
        "degraded" => YELLOW,
        _ => RED,
    };
    let status_icon = match status {
        "healthy" => "\u{2713}",
        _ => "\u{26a0}",
    };

    eprintln!();
    eprintln!("  {BOLD}GVM Proxy Status{RESET}");
    eprintln!();
    eprintln!("  {status_color}{status_icon}{RESET} {BOLD}{status}{RESET}  {DIM}v{version}{RESET}");
    eprintln!("  {DIM}Listen:{RESET}       {CYAN}{proxy_url}{RESET}");
    eprintln!("  {DIM}SRR rules:{RESET}    {srr_rules}");
    if tls_ready {
        eprintln!("  {DIM}TLS MITM:{RESET}     ready");
    } else {
        eprintln!("  {YELLOW}TLS MITM:{RESET}     warming up");
    }
    eprintln!("  {DIM}WAL:{RESET}          {wal_status}");
    if wal_failures > 0 {
        eprintln!("  {YELLOW}WAL failures:{RESET} {wal_failures}");
    }
    if emergency > 0 {
        eprintln!("  {YELLOW}Emergency writes:{RESET} {emergency}");
    }
    if pending > 0 {
        eprintln!("  {YELLOW}Pending approvals:{RESET} {pending} (run gvm approve)");
    }
    eprintln!();

    Ok(())
}
