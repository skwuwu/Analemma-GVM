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

/// Run the interactive demo — sends requests through the proxy,
/// reads X-GVM-* response headers, and displays the dashboard.
pub async fn run_demo(proxy_url: &str, mock_port: u16) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM — Interactive Demo{RESET}");
    println!("{DIM}No API keys needed. Everything runs locally.{RESET}");
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

    // ── Define scenarios ──
    let scenarios = vec![
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
            body: Some(serde_json::json!({"to": "cfo@acme.com", "subject": "Report", "body": "Q4 summary"})),
        },
        Scenario {
            index: 3,
            operation: "gvm.payment.charge",
            method: "POST",
            url: "http://api.bank.com/transfer/123",
            target_host: "api.bank.com",
            resource_json: r#"{"service":"bank","tier":"External","sensitivity":"Critical"}"#,
            body: Some(serde_json::json!({"amount": 50000, "to": "offshore-9999"})),
        },
        Scenario {
            index: 4,
            operation: "gvm.storage.delete",
            method: "DELETE",
            url: "http://gmail.googleapis.com/gmail/v1/users/me/messages/msg-001",
            target_host: "gmail.googleapis.com",
            resource_json: r#"{"service":"gmail","tier":"External","sensitivity":"Critical"}"#,
            body: None,
        },
    ];

    println!("  {DIM}Running {}-step demo scenario...{RESET}", scenarios.len());
    println!();

    let mut steps: Vec<StepResult> = Vec::new();

    for scenario in &scenarios {
        let t0 = Instant::now();

        // Build request with GVM headers
        let mut req = match scenario.method {
            "GET" => client.get(scenario.url),
            "POST" => client.post(scenario.url),
            "DELETE" => client.delete(scenario.url),
            _ => client.get(scenario.url),
        };

        req = req
            .header("X-GVM-Agent-Id", "demo-agent")
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
                decision: format!("Error"),
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
    // Simulate LLM reasoning time (typical Claude call)
    let llm_ms = 1840.0;

    ui::print_dashboard(&session_id, &steps, llm_ms);

    Ok(())
}
