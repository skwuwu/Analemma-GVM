/// ANSI color codes for terminal output.
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const RED: &str = "\x1b[91m";
pub const CYAN: &str = "\x1b[96m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

const BAR_WIDTH: usize = 40;

/// A single step result for the latency dashboard.
pub struct StepResult {
    pub index: usize,
    pub operation: String,
    pub label: String,
    pub decision: String,
    pub engine_ms: f64,
    pub safety_ms: f64,
    pub upstream_ms: f64,
}

impl StepResult {
    pub fn icon(&self) -> &str {
        match self.decision.as_str() {
            "Allow" => "\u{2713}",  // ✓
            d if d.starts_with("Delay") => "\u{23f1}", // ⏱
            _ => "\u{2717}",       // ✗
        }
    }

    pub fn color(&self) -> &str {
        match self.decision.as_str() {
            "Allow" => GREEN,
            d if d.starts_with("Delay") => YELLOW,
            _ => RED,
        }
    }

    pub fn total_gvm_ms(&self) -> f64 {
        self.engine_ms + self.safety_ms
    }
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

/// Print the full execution + latency audit dashboard.
pub fn print_dashboard(session_id: &str, steps: &[StepResult], llm_ms: f64) {
    let width = 72;

    // ── Header ──
    println!();
    println!(
        "{BOLD}Analemma-GVM v0.1.0{RESET} {DIM}| Session: {CYAN}{}{RESET}",
        &session_id[..13.min(session_id.len())]
    );
    println!("{}", "\u{2501}".repeat(width));
    println!();

    // ── Step Results ──
    for step in steps {
        let total_ms = step.engine_ms + step.safety_ms + step.upstream_ms;
        let decision_display = format!("{}{}{}", step.color(), step.decision, RESET);
        println!(
            "  {DIM}[{}]{RESET} {:<32} {} {:<20} {DIM}({:.1}ms){RESET}",
            step.index, step.operation, step.icon(), decision_display, total_ms,
        );
    }

    println!();
    println!("{}", "\u{2501}".repeat(width));
    println!(
        "{}  Pipeline Latency Audit{}",
        BOLD, RESET
    );
    println!("{}", "\u{2501}".repeat(width));
    println!();

    // ── Aggregate latencies ──
    let total_engine: f64 = steps.iter().map(|s| s.engine_ms).sum();
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
    println!("  {}", "\u{2500}".repeat(width - 4));

    // ── Summary stats ──
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
    println!("{}", "\u{2501}".repeat(width));

    // ── Contextual note ──
    if total_safety > 0.0 {
        println!(
            "  {DIM}IC-2 delays are intentional safety margins, not performance overhead.{RESET}"
        );
        println!(
            "  {DIM}The {CYAN}{:.1}ms{RESET}{DIM} engine time is the true cost of governance.{RESET}",
            total_engine
        );
    }

    // Explain any slow engine steps
    for step in steps {
        if step.engine_ms > 10.0 {
            println!(
                "  {YELLOW}Note:{RESET} {DIM}{} took {:.1}ms — payload inspection may be active.{RESET}",
                step.operation, step.engine_ms
            );
        }
    }

    println!("{}", "\u{2501}".repeat(width));
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
    let width = 72;

    println!();
    println!(
        "{BOLD}Analemma-GVM — Dry-Run Policy Check{RESET}"
    );
    println!("{}", "\u{2501}".repeat(width));
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
    println!("{}", "\u{2501}".repeat(width));
    println!(
        "  {DIM}This was a dry-run. No API calls were made. No events were recorded.{RESET}"
    );
    println!("{}", "\u{2501}".repeat(width));
    println!();
}
