/// ANSI color codes for terminal output.
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const RED: &str = "\x1b[91m";
pub const CYAN: &str = "\x1b[96m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

const BAR_WIDTH: usize = 40;
const WIDTH: usize = 72;

/// A single step result for the latency dashboard.
pub struct StepResult {
    pub index: usize,
    pub operation: String,
    pub target_host: String,
    pub method: String,
    pub decision: String,
    pub layer: String,
    pub engine_ms: f64,
    pub safety_ms: f64,
    pub upstream_ms: f64,
    pub event_id: String,
    pub trace_id: String,
    pub matched_rule: String,
    pub reason: Option<String>,
}

impl StepResult {
    pub fn icon(&self) -> &str {
        match self.decision.as_str() {
            "Allow" => "\u{2713}",     // ✓
            d if d.starts_with("Delay") => "\u{23f1}", // ⏱
            _ => "\u{2717}",           // ✗
        }
    }

    pub fn color(&self) -> &str {
        match self.decision.as_str() {
            "Allow" => GREEN,
            d if d.starts_with("Delay") => YELLOW,
            _ => RED,
        }
    }

    pub fn total_ms(&self) -> f64 {
        self.engine_ms + self.safety_ms + self.upstream_ms
    }

    pub fn is_allowed(&self) -> bool {
        self.decision == "Allow" || self.decision.starts_with("Delay")
    }

    pub fn is_blocked(&self) -> bool {
        self.decision.starts_with("Deny") || self.decision.starts_with("RequireApproval")
    }

    /// Parse GVM headers from a reqwest response into this step result.
    pub fn from_response_headers(resp: &reqwest::Response) -> StepHeaders {
        let h = resp.headers();
        StepHeaders {
            decision: h.get("X-GVM-Decision")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
            layer: h.get("X-GVM-Decision-Source")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
            engine_ms: h.get("X-GVM-Engine-Ms")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0),
            safety_ms: h.get("X-GVM-Safety-Delay-Ms")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0),
            event_id: h.get("X-GVM-Event-Id")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
            trace_id: h.get("X-GVM-Trace-Id")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
            matched_rule: h.get("X-GVM-Matched-Rule")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        }
    }
}

/// Parsed X-GVM-* response headers.
pub struct StepHeaders {
    pub decision: String,
    pub layer: String,
    pub engine_ms: f64,
    pub safety_ms: f64,
    pub event_id: String,
    pub trace_id: String,
    pub matched_rule: String,
}

/// Render a horizontal bar proportional to `value` out of `max`.
fn bar(value: f64, max: f64, width: usize) -> String {
    let filled = if max > 0.0 {
        ((value / max) * width as f64).round() as usize
    } else {
        0
    };
    let filled = filled.min(width).max(if value > 0.0 { 1 } else { 0 });
    format!("{}{}", "\u{2588}".repeat(filled), " ".repeat(width - filled))
}

/// Render a progress bar with fraction: [████████████░░░░] n/m
fn progress_bar(done: usize, total: usize, width: usize) -> String {
    let filled = if total > 0 {
        ((done as f64 / total as f64) * width as f64).round() as usize
    } else {
        0
    };
    let filled = filled.min(width);
    format!(
        "[{}{}] {}/{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(width - filled),
        done,
        total,
    )
}

/// Print the full execution + latency audit dashboard.
pub fn print_dashboard(session_id: &str, steps: &[StepResult], llm_ms: f64) {
    // ── Header ──
    println!();
    println!(
        "{BOLD}Analemma-GVM v0.1.0{RESET} {DIM}| Session: {CYAN}{}{RESET}",
        &session_id[..13.min(session_id.len())]
    );
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();

    // ── Step Results (boxed) ──
    println!("  {BOLD}Execution Results{RESET}");
    println!("  \u{250c}{}\u{2510}", "\u{2500}".repeat(WIDTH - 4));

    for step in steps {
        let total_ms = step.total_ms();
        let pad_decision = format!("{}{}{}", step.color(), step.decision, RESET);

        // Main line: icon + operation + decision + timing
        println!(
            "  \u{2502}  {DIM}\u{25cf}{RESET} {:<20} \u{2192} {} {:<20} {DIM}{:>6.0}ms{RESET}  \u{2502}",
            step.operation,
            step.icon(),
            pad_decision,
            total_ms,
        );

        // Detail line: layer + target
        println!(
            "  \u{2502}    {DIM}Layer: {:<6}  Target: {} {}{RESET}  \u{2502}",
            step.layer, step.method, step.target_host,
        );

        // Reason for blocked steps
        if step.is_blocked() {
            if let Some(ref reason) = step.reason {
                let display = if reason.len() > 50 { &reason[..50] } else { reason.as_str() };
                println!(
                    "  \u{2502}    {RED}Reason: {}{RESET}  \u{2502}",
                    display,
                );
            }
        }
    }

    println!("  \u{2502}{}\u{2502}", " ".repeat(WIDTH - 4));

    // ── Summary line inside box ──
    let allowed = steps.iter().filter(|s| s.is_allowed()).count();
    let blocked = steps.iter().filter(|s| s.is_blocked()).count();
    let total_engine: f64 = steps.iter().map(|s| s.engine_ms).sum();
    let total_tool: f64 = steps.iter().map(|s| s.total_ms()).sum();
    let overhead_pct = if total_tool > 0.0 {
        (total_engine / total_tool) * 100.0
    } else {
        0.0
    };

    let prog = progress_bar(allowed, steps.len(), 20);
    println!(
        "  \u{2502}  {prog} {GREEN}allowed{RESET}  {DIM}|{RESET}  {RED}{blocked} blocked{RESET}  \u{2502}",
    );
    println!(
        "  \u{2502}  {DIM}Security overhead: {CYAN}{BOLD}{:.1}%{RESET}  {DIM}({:.1}ms engine / {:.0}ms total){RESET}  \u{2502}",
        overhead_pct, total_engine, total_tool,
    );

    println!("  \u{2514}{}\u{2518}", "\u{2500}".repeat(WIDTH - 4));
    println!();

    // ── Pipeline Latency Audit ──
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!("{BOLD}  Pipeline Latency Audit{RESET}");
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();

    let total_safety: f64 = steps.iter().map(|s| s.safety_ms).sum();
    let total_upstream: f64 = steps.iter().map(|s| s.upstream_ms).sum();
    let total_time = llm_ms + total_upstream + total_engine + total_safety;

    let rows: Vec<(&str, f64, &str)> = vec![
        ("LLM Reasoning (Claude)", llm_ms, DIM),
        ("Upstream API (Gmail/Stripe)", total_upstream, DIM),
        ("GVM Governance (Engine)", total_engine, CYAN),
        ("GVM Safety Margin (IC-2)", total_safety, YELLOW),
    ];

    for (label, ms, color) in &rows {
        println!(
            "  {:<30} {}{}{RESET} {BOLD}{:>8.1}ms{RESET}",
            label,
            color,
            bar(*ms, total_time, BAR_WIDTH),
            ms,
        );
    }

    println!();
    println!("  {}", "\u{2500}".repeat(WIDTH - 4));

    let pure_pct = if total_time > 0.0 {
        (total_engine / total_time) * 100.0
    } else {
        0.0
    };
    let safety_pct = if total_time > 0.0 {
        ((total_engine + total_safety) / total_time) * 100.0
    } else {
        0.0
    };

    println!(
        "  {:<30} {:>8.1}ms",
        "Total Turnaround Time:", total_time,
    );
    println!(
        "  {:<30} {CYAN}{BOLD}{:>8.3} %{RESET}  {DIM}<-- engine only{RESET}",
        "GVM Pure Overhead:", pure_pct,
    );
    println!(
        "  {:<30} {:>8.3} %",
        "Total Safety Impact:", safety_pct,
    );

    println!();
    println!("{}", "\u{2501}".repeat(WIDTH));

    if total_safety > 0.0 {
        println!(
            "  {DIM}IC-2 delays are intentional safety margins, not performance overhead.{RESET}"
        );
        println!(
            "  {DIM}The {CYAN}{:.1}ms{RESET}{DIM} engine time is the true cost of governance.{RESET}",
            total_engine
        );
    }

    for step in steps {
        if step.engine_ms > 10.0 {
            println!(
                "  {YELLOW}Note:{RESET} {DIM}{} took {:.1}ms — payload inspection may be active.{RESET}",
                step.operation, step.engine_ms
            );
        }
    }

    println!("{}", "\u{2501}".repeat(WIDTH));

    // ── Trace ID hint ──
    let trace_ids: Vec<&str> = steps.iter()
        .map(|s| s.trace_id.as_str())
        .filter(|t| !t.is_empty())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !trace_ids.is_empty() {
        println!();
        for tid in &trace_ids {
            println!("  {DIM}Trace the full causal chain:{RESET}");
            println!("  {CYAN}gvm events trace --trace-id {}{RESET}", tid);
        }
    }

    println!();
}

/// Print a single dry-run check result.
pub fn print_check_result(
    operation: &str,
    service: &str,
    tier: &str,
    sensitivity: &str,
    host: &str,
    method: &str,
    decision: &str,
    engine_ms: f64,
    event_id: Option<&str>,
    next_action: Option<&str>,
) {
    println!();
    println!(
        "{BOLD}Analemma-GVM — Dry-Run Policy Check{RESET}"
    );
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();
    println!("  {DIM}Operation:{RESET}    {BOLD}{}{RESET}", operation);
    println!("  {DIM}Resource:{RESET}     {} (tier={}, sensitivity={})", service, tier, sensitivity);
    println!("  {DIM}Target:{RESET}       {} {}", method, host);
    println!();

    let (icon, color) = match decision {
        d if d.contains("Allow") => ("\u{2713}", GREEN),
        d if d.contains("Delay") => ("\u{23f1}", YELLOW),
        d if d.contains("Approval") => ("\u{1f6e1}\u{fe0f}", RED),
        _ => ("\u{2717}", RED),
    };

    println!(
        "  {BOLD}Decision:{RESET}    {color}{icon} {}{RESET}",
        decision
    );
    println!("  {DIM}Engine time:{RESET}  {:.1}ms", engine_ms);

    if let Some(id) = event_id {
        println!("  {DIM}Event ID:{RESET}    {}", id);
    }
    if let Some(action) = next_action {
        println!("  {DIM}Next action:{RESET} {}", action);
    }

    println!();
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!(
        "  {DIM}This was a dry-run. No API calls were made. No events were recorded.{RESET}"
    );
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();
}
