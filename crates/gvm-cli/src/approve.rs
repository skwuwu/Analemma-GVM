use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::io::Write;

/// Pending approval entry from the proxy.
#[derive(serde::Deserialize, Debug)]
struct PendingEntry {
    event_id: String,
    operation: String,
    host: String,
    path: String,
    method: String,
    agent_id: String,
    timestamp: String,
}

/// Response from GET /gvm/pending.
#[derive(serde::Deserialize, Debug)]
struct PendingResponse {
    pending: Vec<PendingEntry>,
}

/// Run the standalone approval CLI.
/// Polls GET /gvm/pending and prompts for each pending request.
pub async fn run_approve(proxy: &str, poll_interval: u64, auto_deny: bool) -> Result<()> {
    eprintln!();
    eprintln!("{BOLD}Analemma GVM \u{2014} IC-3 Approval Monitor{RESET}");
    if auto_deny {
        eprintln!("{DIM}Auto-deny mode: all pending requests will be denied.{RESET}");
    } else {
        eprintln!("{DIM}Watching for pending approval requests. Press Ctrl+C to exit.{RESET}");
    }
    eprintln!("  {DIM}Proxy:{RESET}        {}", proxy);
    eprintln!("  {DIM}Poll interval:{RESET} {}s", poll_interval);
    eprintln!();

    let client = reqwest::Client::new();
    let pending_url = format!("{}/gvm/pending", proxy.trim_end_matches('/'));
    let approve_url = format!("{}/gvm/approve", proxy.trim_end_matches('/'));

    // Track which events we've already prompted for
    let mut prompted: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        // Poll for pending approvals
        let pending = match fetch_pending(&client, &pending_url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  {DIM}Poll failed: {}{RESET}", e);
                tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
                continue;
            }
        };

        for entry in &pending {
            if prompted.contains(&entry.event_id) {
                continue;
            }

            if auto_deny {
                // Auto-deny
                match send_decision(&client, &approve_url, &entry.event_id, false).await {
                    Ok(_) => {
                        eprintln!(
                            "  {RED}\u{2717}{RESET} Auto-denied: {DIM}{} {} {}{RESET}",
                            entry.method, entry.host, entry.path
                        );
                    }
                    Err(e) => {
                        eprintln!("  {RED}Failed to deny {}: {}{RESET}", entry.event_id, e);
                    }
                }
                prompted.insert(entry.event_id.clone());
            } else {
                // Interactive prompt
                print_approval_prompt(entry);
                let approved = prompt_user_decision()?;

                match send_decision(&client, &approve_url, &entry.event_id, approved).await {
                    Ok(_) => {
                        if approved {
                            eprintln!("  {GREEN}\u{2713} Approved{RESET}");
                        } else {
                            eprintln!("  {RED}\u{2717} Denied{RESET}");
                        }
                    }
                    Err(e) => {
                        eprintln!("  {RED}Failed to send decision: {}{RESET}", e);
                    }
                }
                prompted.insert(entry.event_id.clone());
                eprintln!();
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
    }
}

/// Fetch pending approvals from the proxy.
async fn fetch_pending(client: &reqwest::Client, url: &str) -> Result<Vec<PendingEntry>> {
    let resp = client
        .get(url)
        .send()
        .await
        .context("Failed to reach proxy")?;

    if !resp.status().is_success() {
        anyhow::bail!("Proxy returned {}", resp.status());
    }

    let body: PendingResponse = resp.json().await.context("Failed to parse pending response")?;
    Ok(body.pending)
}

/// Send an approval decision to the proxy.
async fn send_decision(
    client: &reqwest::Client,
    url: &str,
    event_id: &str,
    approved: bool,
) -> Result<()> {
    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "event_id": event_id,
            "approved": approved,
        }))
        .send()
        .await
        .context("Failed to send approval decision")?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Proxy returned error: {}", body);
    }
    Ok(())
}

/// Print the approval prompt for a pending request.
fn print_approval_prompt(entry: &PendingEntry) {
    eprintln!(
        "  {YELLOW}{BOLD}\u{1f6e1}\u{fe0f}  IC-3 Approval Required{RESET}"
    );
    eprintln!("  {DIM}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{RESET}");
    eprintln!("  {DIM}Event:{RESET}      {CYAN}{}{RESET}", entry.event_id);
    eprintln!("  {DIM}Agent:{RESET}      {}", entry.agent_id);
    eprintln!("  {DIM}Operation:{RESET}  {}", entry.operation);
    eprintln!(
        "  {DIM}Target:{RESET}     {BOLD}{} {} {}{RESET}",
        entry.method, entry.host, entry.path
    );
    eprintln!("  {DIM}Time:{RESET}       {}", entry.timestamp);
}

/// Prompt the user for y/n decision. Returns true for approve, false for deny.
fn prompt_user_decision() -> Result<bool> {
    eprint!("  {BOLD}Approve? [y/N]:{RESET} ");
    std::io::stderr().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();

    Ok(trimmed == "y" || trimmed == "yes")
}

/// Poll for pending approvals and display prompts inline during `gvm run`.
/// This is a background task spawned by `gvm run` when the proxy has IC-3 rules.
/// Returns when the cancellation token is set.
pub async fn poll_and_prompt_background(
    proxy: &str,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    let client = reqwest::Client::new();
    let pending_url = format!("{}/gvm/pending", proxy.trim_end_matches('/'));
    let approve_url = format!("{}/gvm/approve", proxy.trim_end_matches('/'));
    let mut prompted: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Ok(pending) = fetch_pending(&client, &pending_url).await {
                    for entry in &pending {
                        if prompted.contains(&entry.event_id) {
                            continue;
                        }

                        // Show prompt on stderr (interleaved with agent output)
                        print_approval_prompt(entry);

                        // In background mode, read from stdin
                        match prompt_user_decision() {
                            Ok(approved) => {
                                let _ = send_decision(&client, &approve_url, &entry.event_id, approved).await;
                                if approved {
                                    eprintln!("  {GREEN}\u{2713} Approved — request forwarded{RESET}");
                                } else {
                                    eprintln!("  {RED}\u{2717} Denied — 403 returned to agent{RESET}");
                                }
                            }
                            Err(_) => {
                                // stdin closed or error — auto-deny
                                let _ = send_decision(&client, &approve_url, &entry.event_id, false).await;
                                eprintln!("  {RED}\u{2717} Auto-denied (stdin unavailable){RESET}");
                            }
                        }
                        prompted.insert(entry.event_id.clone());
                        eprintln!();
                    }
                }
            }
            Ok(()) = cancel.changed() => {
                if *cancel.borrow() {
                    return;
                }
            }
        }
    }
}
