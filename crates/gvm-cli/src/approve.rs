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
                let outcome = send_decision(&client, &approve_url, &entry.event_id, false).await;
                render_outcome(entry, false, &outcome);
                prompted.insert(entry.event_id.clone());
            } else {
                // Interactive prompt
                print_approval_prompt(entry);
                let approved = prompt_user_decision()?;

                let outcome = send_decision(&client, &approve_url, &entry.event_id, approved).await;
                render_outcome(entry, approved, &outcome);
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

    let body: PendingResponse = resp
        .json()
        .await
        .context("Failed to parse pending response")?;
    Ok(body.pending)
}

/// Outcome of a single approve/deny POST.
enum DecisionOutcome {
    /// Proxy accepted the decision and delivered it to the waiting handler.
    Delivered,
    /// Proxy returned 410 Gone — the agent disconnected before the
    /// decision arrived. The operator's click had no effect on the
    /// upstream request because there is no upstream request anymore.
    AgentGone,
    /// Proxy returned 404 — the event_id is unknown (already drained,
    /// already timed out, or never existed).
    Unknown,
    /// Other / network failure.
    Error(String),
}

/// Send an approval decision to the proxy. Maps the proxy's status
/// code into an explicit outcome so the caller can render a truthful
/// message instead of an unconditional "Approved".
async fn send_decision(
    client: &reqwest::Client,
    url: &str,
    event_id: &str,
    approved: bool,
) -> DecisionOutcome {
    let resp = match client
        .post(url)
        .json(&serde_json::json!({
            "event_id": event_id,
            "approved": approved,
        }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return DecisionOutcome::Error(format!("send: {}", e)),
    };

    let status = resp.status();
    if status.is_success() {
        DecisionOutcome::Delivered
    } else if status == reqwest::StatusCode::GONE {
        DecisionOutcome::AgentGone
    } else if status == reqwest::StatusCode::NOT_FOUND {
        DecisionOutcome::Unknown
    } else {
        let body = resp.text().await.unwrap_or_default();
        DecisionOutcome::Error(format!("{}: {}", status, body))
    }
}

/// Print the approval prompt for a pending request.
fn print_approval_prompt(entry: &PendingEntry) {
    eprintln!("  {YELLOW}{BOLD}\u{1f6e1}\u{fe0f}  IC-3 Approval Required{RESET}");
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

/// Render the result of a single approve/deny POST. The truth-table
/// matters here: the operator needs to know when their click did
/// nothing (agent already disconnected) so they don't trust a stale
/// audit log entry.
fn render_outcome(entry: &PendingEntry, approved: bool, outcome: &DecisionOutcome) {
    match outcome {
        DecisionOutcome::Delivered => {
            if approved {
                eprintln!("  {GREEN}\u{2713} Approved — request forwarded to upstream{RESET}");
            } else {
                eprintln!("  {RED}\u{2717} Denied — 403 returned to agent{RESET}");
            }
        }
        DecisionOutcome::AgentGone => {
            // The proxy returned 410 Gone: hyper cancelled the handler
            // future before our decision arrived, almost always because
            // the agent's HTTP client timed out. Tell the operator
            // explicitly so they don't think they just approved a wire
            // transfer that actually never happened.
            eprintln!(
                "  {YELLOW}\u{26a0}  Agent already disconnected{RESET}  \
                 {DIM}({} {}){RESET}",
                entry.method, entry.host
            );
            eprintln!(
                "  {DIM}    The agent's HTTP client closed the connection \
                 before your decision arrived. No upstream call was made;{RESET}"
            );
            eprintln!(
                "  {DIM}    your '{}' had no effect on the request.{RESET}",
                if approved { "approve" } else { "deny" }
            );
        }
        DecisionOutcome::Unknown => {
            // 404: event_id is gone. Most likely the IC-3 timeout fired
            // first or another `gvm approve` instance already drained
            // it. Show as a soft warning, not an error.
            eprintln!(
                "  {DIM}\u{2014} {} already drained (timeout or another \
                 approver got there first){RESET}",
                entry.event_id
            );
        }
        DecisionOutcome::Error(msg) => {
            eprintln!("  {RED}Failed to send decision: {}{RESET}", msg);
        }
    }
}
