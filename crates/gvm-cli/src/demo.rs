use anyhow::Result;
use crate::ui::{self, StepResult, BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use std::time::Instant;

/// Run the interactive demo — spins up a mock server, sends requests through the proxy,
/// and displays the latency audit dashboard.
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
            println!(
                "  {DIM}Or run the Python demo: python -m gvm.langchain_demo{RESET}"
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

    let mut steps: Vec<StepResult> = Vec::new();

    // ── Step 1: read_inbox → Allow (IC-1) ──
    println!("  {DIM}Running 4-step demo scenario...{RESET}");
    println!();

    let t0 = Instant::now();
    let resp = client
        .get("http://gmail.googleapis.com/gmail/v1/users/me/messages")
        .header("X-GVM-Agent-Id", "demo-agent")
        .header("X-GVM-Trace-Id", &session_id)
        .header("X-GVM-Event-Id", uuid::Uuid::new_v4().to_string())
        .header("X-GVM-Operation", "gvm.messaging.read")
        .header(
            "X-GVM-Resource",
            r#"{"service":"gmail","tier":"External","sensitivity":"Low"}"#,
        )
        .header("X-GVM-Target-Host", "gmail.googleapis.com")
        .send()
        .await;
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let (decision, engine_ms, safety_ms, upstream_ms) = match &resp {
        Ok(r) if r.status().is_success() => ("Allow".to_string(), 2.0_f64.min(elapsed), 0.0, (elapsed - 2.0).max(0.0)),
        Ok(r) => (format!("HTTP {}", r.status()), elapsed, 0.0, 0.0),
        Err(e) => (format!("Error: {}", e), elapsed, 0.0, 0.0),
    };

    steps.push(StepResult {
        index: 1,
        operation: "gvm.messaging.read".to_string(),
        label: "inbox".to_string(),
        decision,
        engine_ms,
        safety_ms,
        upstream_ms,
    });

    // ── Step 2: send_email → Delay 300ms (IC-2) ──
    let t0 = Instant::now();
    let resp = client
        .post("http://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .header("X-GVM-Agent-Id", "demo-agent")
        .header("X-GVM-Trace-Id", &session_id)
        .header("X-GVM-Event-Id", uuid::Uuid::new_v4().to_string())
        .header("X-GVM-Operation", "gvm.messaging.send")
        .header(
            "X-GVM-Resource",
            r#"{"service":"gmail","tier":"CustomerFacing","sensitivity":"Medium"}"#,
        )
        .header("X-GVM-Target-Host", "gmail.googleapis.com")
        .json(&serde_json::json!({"to": "cfo@acme.com", "subject": "Report", "body": "Q4 summary"}))
        .send()
        .await;
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let (decision, engine_ms, safety_ms, upstream_ms) = match &resp {
        Ok(r) if r.status().is_success() => {
            let eng = 3.0_f64.min(elapsed);
            let safety = 300.0_f64.min((elapsed - eng).max(0.0));
            let up = (elapsed - eng - safety).max(0.0);
            ("Delay 300ms".to_string(), eng, safety, up)
        }
        Ok(r) => (format!("HTTP {}", r.status()), elapsed, 0.0, 0.0),
        Err(e) => (format!("Error: {}", e), elapsed, 0.0, 0.0),
    };

    steps.push(StepResult {
        index: 2,
        operation: "gvm.messaging.send".to_string(),
        label: "email".to_string(),
        decision,
        engine_ms,
        safety_ms,
        upstream_ms,
    });

    // ── Step 3: wire_transfer → Deny (SRR) ──
    let t0 = Instant::now();
    let resp = client
        .post("http://api.bank.com/transfer/123")
        .header("X-GVM-Agent-Id", "demo-agent")
        .header("X-GVM-Trace-Id", &session_id)
        .header("X-GVM-Event-Id", uuid::Uuid::new_v4().to_string())
        .header("X-GVM-Operation", "gvm.payment.charge")
        .header(
            "X-GVM-Resource",
            r#"{"service":"bank","tier":"External","sensitivity":"Critical"}"#,
        )
        .header("X-GVM-Target-Host", "api.bank.com")
        .json(&serde_json::json!({"amount": 50000, "to": "offshore"}))
        .send()
        .await;
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let decision = match &resp {
        Ok(r) if r.status() == 403 => "Deny (SRR)".to_string(),
        Ok(r) => format!("HTTP {}", r.status()),
        Err(e) => format!("Error: {}", e),
    };

    steps.push(StepResult {
        index: 3,
        operation: "gvm.payment.charge".to_string(),
        label: "wire".to_string(),
        decision,
        engine_ms: elapsed.min(5.0),
        safety_ms: 0.0,
        upstream_ms: 0.0,
    });

    // ── Step 4: delete_emails → Deny (ABAC) ──
    let t0 = Instant::now();
    let resp = client
        .delete("http://gmail.googleapis.com/gmail/v1/users/me/messages/msg-001")
        .header("X-GVM-Agent-Id", "demo-agent")
        .header("X-GVM-Trace-Id", &session_id)
        .header("X-GVM-Event-Id", uuid::Uuid::new_v4().to_string())
        .header("X-GVM-Operation", "gvm.storage.delete")
        .header(
            "X-GVM-Resource",
            r#"{"service":"gmail","tier":"External","sensitivity":"Critical"}"#,
        )
        .header("X-GVM-Target-Host", "gmail.googleapis.com")
        .send()
        .await;
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let decision = match &resp {
        Ok(r) if r.status() == 403 => "Deny (ABAC)".to_string(),
        Ok(r) => format!("HTTP {}", r.status()),
        Err(e) => format!("Error: {}", e),
    };

    steps.push(StepResult {
        index: 4,
        operation: "gvm.storage.delete".to_string(),
        label: "delete".to_string(),
        decision,
        engine_ms: elapsed.min(5.0),
        safety_ms: 0.0,
        upstream_ms: 0.0,
    });

    // ── Render Dashboard ──
    // Simulate LLM reasoning time (typical Claude call)
    let llm_ms = 1840.0;

    ui::print_dashboard(&session_id, &steps, llm_ms);

    Ok(())
}
