use crate::run;
use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

// ─── Output format abstraction ───

/// Output mode for watch results — designed for future extensibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    Text,
    Json,
}

impl OutputMode {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => anyhow::bail!("Unknown output format '{}'. Use 'text' or 'json'.", s),
        }
    }
}

// ─── Cost estimation ───

/// Estimate cost in USD based on provider, model, and token usage.
/// Prices are approximate as of 2025 — users needing precision should
/// configure a pricing.toml (planned for a future release).
fn estimate_cost(
    provider: &str,
    model: Option<&str>,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> f64 {
    // Per-1M-token pricing (USD)
    let (input_rate, output_rate) = match provider {
        "openai" => match model {
            Some(m) if m.contains("gpt-4o") && !m.contains("mini") => (2.50, 10.00),
            Some(m) if m.contains("gpt-4o-mini") => (0.15, 0.60),
            Some(m) if m.contains("gpt-4") => (30.00, 60.00),
            Some(m) if m.contains("o1") => (15.00, 60.00),
            Some(m) if m.contains("o3") => (10.00, 40.00),
            _ => (0.50, 1.50),
        },
        "anthropic" => match model {
            Some(m) if m.contains("opus") => (15.00, 75.00),
            Some(m) if m.contains("sonnet") => (3.00, 15.00),
            Some(m) if m.contains("haiku") => (0.25, 1.25),
            _ => (3.00, 15.00),
        },
        "gemini" => match model {
            Some(m) if m.contains("pro") => (1.25, 5.00),
            Some(m) if m.contains("flash") => (0.075, 0.30),
            _ => (1.25, 5.00),
        },
        _ => (1.00, 3.00),
    };
    (prompt_tokens as f64 * input_rate + completion_tokens as f64 * output_rate) / 1_000_000.0
}

// ─── Anomaly detector ───

struct AnomalyDetector {
    /// Sliding window for burst detection
    request_times: VecDeque<Instant>,
    /// Track (method:host:path) -> recent timestamps for loop detection
    loop_detector: HashMap<String, VecDeque<Instant>>,
    /// Collected warnings
    warnings: Vec<String>,
}

impl AnomalyDetector {
    fn new() -> Self {
        Self {
            request_times: VecDeque::new(),
            loop_detector: HashMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Record a request and check for anomalies. Returns a warning if detected.
    fn record_request(
        &mut self,
        method: &str,
        host: &str,
        path: &str,
        default_caution: bool,
    ) -> Option<String> {
        let now = Instant::now();

        // --- Burst detection: >10 requests within 2 seconds ---
        self.request_times.push_back(now);
        while let Some(&front) = self.request_times.front() {
            if now.duration_since(front).as_secs_f64() > 2.0 {
                self.request_times.pop_front();
            } else {
                break;
            }
        }
        if self.request_times.len() > 10 {
            let msg = format!(
                "Burst detected: {} requests in 2s",
                self.request_times.len()
            );
            // Only warn once per burst (suppress if already warned recently)
            if !self.warnings.last().is_some_and(|w| w.starts_with("Burst")) {
                self.warnings.push(msg.clone());
                return Some(msg);
            }
        }

        // --- Loop detection: same (method, host, path) >5 times in 10 seconds ---
        let key = format!("{}:{}:{}", method, host, path);
        let times = self.loop_detector.entry(key.clone()).or_default();
        times.push_back(now);
        while let Some(&front) = times.front() {
            if now.duration_since(front).as_secs_f64() > 10.0 {
                times.pop_front();
            } else {
                break;
            }
        }
        if times.len() > 5 {
            let msg = format!(
                "Loop detected: {} {} {} called {} times in 10s",
                method,
                host,
                path,
                times.len()
            );
            if !self.warnings.iter().any(|w| w.contains(&key)) {
                self.warnings.push(msg.clone());
                return Some(msg);
            }
        }

        // --- Unknown host warning (default-to-caution) ---
        if default_caution {
            let msg = format!("Unknown host (no SRR rule): {} {}{}", method, host, path);
            // Only warn once per unique host
            let host_key = format!("unknown:{}", host);
            if !self.warnings.iter().any(|w| w.contains(&host_key)) {
                self.warnings.push(format!("unknown:{}", host));
                return Some(msg);
            }
        }

        None
    }
}

// ─── Session stats ───

struct SessionStats {
    total_requests: u64,
    hosts: HashMap<String, u64>,
    methods: HashMap<String, u64>,
    status_codes: HashMap<u16, u64>,
    decisions: HashMap<String, u64>,
    decision_sources: HashMap<String, u64>,
    total_prompt_tokens: u64,
    total_completion_tokens: u64,
    total_tokens: u64,
    llm_calls: u64,
    models_used: HashSet<String>,
    providers_used: HashSet<String>,
    default_caution_count: u64,
    thinking_count: u64,
    estimated_cost: f64,
    start_time: Instant,
}

impl SessionStats {
    fn new() -> Self {
        Self {
            total_requests: 0,
            hosts: HashMap::new(),
            methods: HashMap::new(),
            status_codes: HashMap::new(),
            decisions: HashMap::new(),
            decision_sources: HashMap::new(),
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            total_tokens: 0,
            llm_calls: 0,
            models_used: HashSet::new(),
            providers_used: HashSet::new(),
            default_caution_count: 0,
            thinking_count: 0,
            estimated_cost: 0.0,
            start_time: Instant::now(),
        }
    }

    fn record_event(&mut self, event: &serde_json::Value) {
        self.total_requests += 1;

        // Host
        if let Some(host) = event.pointer("/transport/host").and_then(|v| v.as_str()) {
            *self.hosts.entry(host.to_string()).or_default() += 1;
        }

        // Method
        if let Some(method) = event.pointer("/transport/method").and_then(|v| v.as_str()) {
            *self.methods.entry(method.to_string()).or_default() += 1;
        }

        // Status code
        if let Some(code) = event
            .pointer("/transport/status_code")
            .and_then(|v| v.as_u64())
        {
            *self.status_codes.entry(code as u16).or_default() += 1;
        }

        // Decision
        if let Some(decision) = event.get("decision").and_then(|v| v.as_str()) {
            let bucket = if decision.contains("Allow") {
                "Allow"
            } else if decision.contains("Delay") {
                "Delay"
            } else if decision.contains("Deny") {
                "Deny"
            } else {
                "Other"
            };
            *self.decisions.entry(bucket.to_string()).or_default() += 1;
        }

        // Decision source
        if let Some(src) = event.get("decision_source").and_then(|v| v.as_str()) {
            *self.decision_sources.entry(src.to_string()).or_default() += 1;
        }

        // Default-to-Caution
        if event
            .get("default_caution")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            self.default_caution_count += 1;
        }

        // LLM trace
        if let Some(trace) = event.get("llm_trace") {
            self.llm_calls += 1;
            let provider = trace
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let model = trace.get("model").and_then(|v| v.as_str());

            self.providers_used.insert(provider.to_string());
            if let Some(m) = model {
                self.models_used.insert(m.to_string());
            }

            // Thinking trace
            if trace.get("thinking").is_some() {
                self.thinking_count += 1;
            }

            // Token usage
            if let Some(usage) = trace.get("usage") {
                let prompt = usage
                    .get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let completion = usage
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let total = usage
                    .get("total_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(prompt + completion);

                self.total_prompt_tokens += prompt;
                self.total_completion_tokens += completion;
                self.total_tokens += total;

                self.estimated_cost += estimate_cost(provider, model, prompt, completion);
            }
        }
    }
}

// ─── Allow-all temp config ───

/// Generate a temporary SRR config that allows all requests through.
/// Returns the path to the temp directory (caller must clean up).
fn create_allow_all_config(base_config_dir: &Path) -> Result<PathBuf> {
    let temp_dir = std::env::temp_dir().join(format!("gvm-watch-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)
        .with_context(|| format!("Failed to create temp config dir: {}", temp_dir.display()))?;

    // Copy existing proxy.toml as base (if exists), or create minimal one
    let src_proxy = base_config_dir.join("proxy.toml");
    let dst_proxy = temp_dir.join("proxy.toml");

    if src_proxy.exists() {
        let mut content = std::fs::read_to_string(&src_proxy)
            .with_context(|| format!("Failed to read {}", src_proxy.display()))?;

        // Override srr_file path to our allow-all SRR
        // Look for srr_file and replace, or append
        if content.contains("srr_file") {
            // Replace the srr_file line to point to our temp SRR
            let srr_path = temp_dir.join("srr_network.toml");
            let srr_path_str = srr_path.to_string_lossy().replace('\\', "/");
            let mut new_lines = Vec::new();
            for line in content.lines() {
                if line.trim_start().starts_with("srr_file") {
                    new_lines.push(format!("srr_file = \"{}\"", srr_path_str));
                } else {
                    new_lines.push(line.to_string());
                }
            }
            content = new_lines.join("\n");
        }
        std::fs::write(&dst_proxy, content)?;
    } else {
        // Minimal proxy.toml
        let srr_path = temp_dir.join("srr_network.toml");
        let srr_path_str = srr_path.to_string_lossy().replace('\\', "/");
        std::fs::write(
            &dst_proxy,
            format!(
                r#"[proxy]
listen = "127.0.0.1:8080"
srr_file = "{}"
"#,
                srr_path_str
            ),
        )?;
    }

    // Write allow-all SRR: single rule that matches everything as Allow
    let srr_content = r#"# Auto-generated by gvm watch (allow-all observation mode)
# This file is temporary and will be deleted when watch exits.

[[rules]]
host = "{any}"
method = "ANY"
path = "/*"
decision = "Allow"
label = "watch-allow-all"
"#;
    std::fs::write(temp_dir.join("srr_network.toml"), srr_content)?;

    Ok(temp_dir)
}

/// Clean up temporary config directory.
fn cleanup_temp_config(temp_dir: &Path) {
    if temp_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(temp_dir) {
            eprintln!(
                "  {DIM}Warning: failed to clean up temp config at {}: {}{RESET}",
                temp_dir.display(),
                e
            );
        }
    }
}

// ─── WAL tailing ───

/// Tail the WAL file from a given offset, processing new events in real-time.
/// Returns when the cancellation token is set.
async fn tail_wal(
    wal_path: &str,
    start_offset: u64,
    stats: &mut SessionStats,
    anomaly: &mut AnomalyDetector,
    output_mode: OutputMode,
    cancel: tokio::sync::watch::Receiver<bool>,
) {
    let mut offset = start_offset;
    let mut cancel = cancel;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Try to read new data from WAL
                let new_events = match read_wal_from_offset(wal_path, offset) {
                    Ok((events, new_offset)) => {
                        offset = new_offset;
                        events
                    }
                    Err(_) => Vec::new(),
                };

                for (event, raw_line) in &new_events {
                    stats.record_event(event);

                    let method = event.pointer("/transport/method").and_then(|v| v.as_str()).unwrap_or("");
                    let host = event.pointer("/transport/host").and_then(|v| v.as_str()).unwrap_or("");
                    let path = event.pointer("/transport/path").and_then(|v| v.as_str()).unwrap_or("");
                    let default_caution = event.get("default_caution").and_then(|v| v.as_bool()).unwrap_or(false);

                    // Check for anomalies
                    let warning = anomaly.record_request(method, host, path, default_caution);

                    match output_mode {
                        OutputMode::Text => {
                            print_live_event_text(event, warning.as_deref());
                        }
                        OutputMode::Json => {
                            // In JSON mode, output each event as a JSON line
                            println!("{}", raw_line);
                        }
                    }
                }
            }
            Ok(()) = cancel.changed() => {
                if *cancel.borrow() {
                    break;
                }
            }
        }
    }
}

/// Read new WAL events from a given byte offset.
/// Returns (parsed events with raw lines, new offset).
fn read_wal_from_offset(
    wal_path: &str,
    offset: u64,
) -> Result<(Vec<(serde_json::Value, String)>, u64)> {
    let file = std::fs::File::open(wal_path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len();

    if file_len <= offset {
        return Ok((Vec::new(), offset));
    }

    let mut reader = std::io::BufReader::new(file);
    reader.seek(SeekFrom::Start(offset))?;

    let mut events = Vec::new();
    let mut current_offset = offset;

    for line in reader.lines() {
        let line = line?;
        current_offset += line.len() as u64 + 1; // +1 for newline
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip Merkle batch records
        if trimmed.contains("\"batch_id\"") && trimmed.contains("\"merkle_root\"") {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed) {
            events.push((event, trimmed.to_string()));
        }
    }

    Ok((events, current_offset))
}

/// Print a single event in human-readable format.
fn print_live_event_text(event: &serde_json::Value, warning: Option<&str>) {
    let timestamp = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Extract HH:MM:SS from ISO timestamp
    let time_short = if timestamp.len() >= 19 {
        &timestamp[11..19]
    } else {
        timestamp
    };

    let method = event
        .pointer("/transport/method")
        .and_then(|v| v.as_str())
        .unwrap_or("???");
    let host = event
        .pointer("/transport/host")
        .and_then(|v| v.as_str())
        .unwrap_or("???");
    let path = event
        .pointer("/transport/path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let status_code = event
        .pointer("/transport/status_code")
        .and_then(|v| v.as_u64());
    let decision = event.get("decision").and_then(|v| v.as_str()).unwrap_or("");

    // Token usage (conditional)
    let token_info = event
        .pointer("/llm_trace/usage")
        .and_then(|usage| {
            let total = usage
                .get("total_tokens")
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    let p = usage
                        .get("prompt_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let c = usage
                        .get("completion_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if p > 0 || c > 0 {
                        Some(p + c)
                    } else {
                        None
                    }
                });
            total.map(|t| format!("[{} tokens]", format_number(t)))
        })
        .unwrap_or_default();

    // Decision color
    let (icon, color) = if decision.contains("Allow") {
        ("\u{2713}", GREEN)
    } else if decision.contains("Delay") {
        ("\u{23f1}", YELLOW)
    } else if decision.contains("Deny") {
        ("\u{2717}", RED)
    } else {
        ("\u{2022}", DIM)
    };

    let status_str = status_code
        .map(|c| format!("{}", c))
        .unwrap_or_else(|| "---".to_string());

    // Truncate path for display
    let display_path = if path.len() > 40 {
        format!("{}...", &path[..37])
    } else {
        path.to_string()
    };

    eprintln!(
        "  {DIM}{}{RESET}  {color}{icon}{RESET} {:<6} {:<30} {:<40} {:>3}  {DIM}{}{RESET}",
        time_short, method, host, display_path, status_str, token_info
    );

    // Print anomaly warning inline
    if let Some(warn) = warning {
        eprintln!("  {YELLOW}  \u{26a0} {}{RESET}", warn);
    }
}

// ─── Session summary ───

fn print_session_summary_text(stats: &SessionStats, anomaly: &AnomalyDetector) {
    let duration = stats.start_time.elapsed();
    let duration_str = format_duration(duration);
    let rps = if duration.as_secs_f64() > 0.0 {
        stats.total_requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    let width = 60;
    eprintln!();
    eprintln!(
        "{BOLD}\u{2550}\u{2550}\u{2550} Session Summary {}{RESET}",
        "\u{2550}".repeat(width - 17)
    );
    eprintln!(
        "  Duration: {DIM}{}{RESET}  |  {BOLD}{}{RESET} requests  |  {DIM}{:.2} req/s{RESET}",
        duration_str, stats.total_requests, rps
    );
    eprintln!();

    // Top hosts
    if !stats.hosts.is_empty() {
        eprintln!("  {BOLD}Top Hosts:{RESET}");
        let mut sorted_hosts: Vec<_> = stats.hosts.iter().collect();
        sorted_hosts.sort_by(|a, b| b.1.cmp(a.1));
        for (host, count) in sorted_hosts.iter().take(5) {
            let pct = **count as f64 / stats.total_requests as f64 * 100.0;
            eprintln!(
                "    {:<35} {:>5} reqs  {DIM}({:.1}%){RESET}",
                host, count, pct
            );
        }
        if sorted_hosts.len() > 5 {
            eprintln!(
                "    {DIM}... and {} more hosts{RESET}",
                sorted_hosts.len() - 5
            );
        }
        eprintln!();
    }

    // LLM usage (conditional — only if there were LLM calls)
    if stats.llm_calls > 0 {
        eprintln!("  {BOLD}LLM Usage:{RESET}");
        if !stats.models_used.is_empty() {
            let models: Vec<_> = stats.models_used.iter().collect();
            eprintln!(
                "    Models: {CYAN}{}{RESET}",
                models
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        eprintln!(
            "    Tokens: {BOLD}{}{RESET} total ({} prompt + {} completion)",
            format_number(stats.total_tokens),
            format_number(stats.total_prompt_tokens),
            format_number(stats.total_completion_tokens),
        );
        eprintln!(
            "    Est. Cost: {BOLD}${:.4}{RESET} {DIM}(approximate){RESET}",
            stats.estimated_cost
        );
        if stats.thinking_count > 0 {
            eprintln!(
                "    {DIM}{} response(s) included reasoning traces{RESET}",
                stats.thinking_count
            );
        }
        eprintln!();
    }

    // Status codes
    if !stats.status_codes.is_empty() {
        let s2xx: u64 = stats
            .status_codes
            .iter()
            .filter(|(k, _)| **k >= 200 && **k < 300)
            .map(|(_, v)| v)
            .sum();
        let s4xx: u64 = stats
            .status_codes
            .iter()
            .filter(|(k, _)| **k >= 400 && **k < 500)
            .map(|(_, v)| v)
            .sum();
        let s5xx: u64 = stats
            .status_codes
            .iter()
            .filter(|(k, _)| **k >= 500)
            .map(|(_, v)| v)
            .sum();
        eprintln!(
            "  {BOLD}Status Codes:{RESET}  {GREEN}2xx: {}{RESET}  |  {YELLOW}4xx: {}{RESET}  |  {RED}5xx: {}{RESET}",
            s2xx, s4xx, s5xx
        );
        eprintln!();
    }

    // Decision breakdown
    if !stats.decisions.is_empty() {
        let allowed = stats.decisions.get("Allow").unwrap_or(&0);
        let delayed = stats.decisions.get("Delay").unwrap_or(&0);
        let denied = stats.decisions.get("Deny").unwrap_or(&0);
        eprintln!(
            "  {BOLD}Decisions:{RESET}  {GREEN}{} allowed{RESET}  {YELLOW}{} delayed{RESET}  {RED}{} denied{RESET}",
            allowed, delayed, denied
        );
        eprintln!();
    }

    // Decision source breakdown
    if stats.decision_sources.len() > 1 {
        let parts: Vec<String> = stats
            .decision_sources
            .iter()
            .map(|(src, count)| format!("{}: {}", src, count))
            .collect();
        eprintln!(
            "  {BOLD}Decision Sources:{RESET}  {DIM}{}{RESET}",
            parts.join("  |  ")
        );
        eprintln!();
    }

    // Default-to-Caution hits
    if stats.default_caution_count > 0 {
        eprintln!(
            "  {YELLOW}\u{26a0} {} request(s) hit unknown hosts (no SRR rule){RESET}",
            stats.default_caution_count
        );
        eprintln!();
    }

    // Anomaly warnings
    let real_warnings: Vec<_> = anomaly
        .warnings
        .iter()
        .filter(|w| !w.starts_with("unknown:"))
        .collect();
    if !real_warnings.is_empty() {
        eprintln!("  {YELLOW}{BOLD}\u{26a0} Anomalies:{RESET}");
        for w in &real_warnings {
            eprintln!("    {YELLOW}\u{2022} {}{RESET}", w);
        }
        eprintln!();
    }

    // Conversion funnel
    eprintln!("  {DIM}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{RESET}");
    eprintln!(
        "  {BOLD}\u{2192}{RESET} To enforce rules:          {CYAN}gvm run my_agent.py{RESET}"
    );
    eprintln!(
        "  {BOLD}\u{2192}{RESET} To discover rules:         {CYAN}gvm run --interactive my_agent.py{RESET}"
    );
    eprintln!(
        "  {BOLD}\u{2192}{RESET} To add kernel isolation:   {CYAN}gvm run --sandbox my_agent.py{RESET}"
    );
    eprintln!("{}", "\u{2550}".repeat(width));
}

fn print_session_summary_json(stats: &SessionStats, anomaly: &AnomalyDetector) {
    let duration = stats.start_time.elapsed();

    let mut hosts: Vec<_> = stats.hosts.iter().map(|(k, v)| (k.clone(), *v)).collect();
    hosts.sort_by(|a, b| b.1.cmp(&a.1));

    let real_warnings: Vec<_> = anomaly
        .warnings
        .iter()
        .filter(|w| !w.starts_with("unknown:"))
        .cloned()
        .collect();

    let summary = serde_json::json!({
        "type": "session_summary",
        "duration_secs": duration.as_secs_f64(),
        "total_requests": stats.total_requests,
        "requests_per_sec": if duration.as_secs_f64() > 0.0 {
            stats.total_requests as f64 / duration.as_secs_f64()
        } else { 0.0 },
        "hosts": hosts,
        "methods": stats.methods,
        "status_codes": stats.status_codes,
        "decisions": stats.decisions,
        "decision_sources": stats.decision_sources,
        "llm": {
            "calls": stats.llm_calls,
            "prompt_tokens": stats.total_prompt_tokens,
            "completion_tokens": stats.total_completion_tokens,
            "total_tokens": stats.total_tokens,
            "models": stats.models_used.iter().collect::<Vec<_>>(),
            "estimated_cost_usd": stats.estimated_cost,
            "thinking_responses": stats.thinking_count,
        },
        "default_caution_count": stats.default_caution_count,
        "anomalies": real_warnings,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&summary).unwrap_or_default()
    );
}

// ─── Formatting helpers ───

fn format_number(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

// ─── Main entry point ───

#[allow(clippy::too_many_arguments)]
pub async fn run_watch(
    command: &[String],
    agent_id: &str,
    proxy: &str,
    with_rules: bool,
    sandbox: bool,
    contained: bool,
    no_mitm: bool,
    image: &str,
    memory: &str,
    cpus: &str,
    output: &str,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "No command specified. Usage: gvm watch agent.py  OR  gvm watch -- node my_agent.js"
        );
    }
    if sandbox && contained {
        anyhow::bail!("Cannot use --sandbox and --contained together.");
    }

    let output_mode = OutputMode::parse(output)?;
    // run::run_agent determines binary vs script mode internally

    // --- Allow-all config (default behavior: no enforcement) ---
    let config_dir = PathBuf::from("config");
    let temp_config_dir = if !with_rules {
        let dir = create_allow_all_config(&config_dir)?;
        Some(dir)
    } else {
        None
    };

    // Ensure cleanup on exit
    let _cleanup_guard = temp_config_dir.as_ref().map(|d| TempConfigGuard(d.clone()));

    let workspace = run::workspace_root_for_proxy();
    crate::proxy_manager::ensure_available(proxy, &workspace, false).await?;

    // If allow-all mode, reload proxy with our temp config via admin API
    let admin_url = run::derive_admin_url(proxy);
    if let Some(ref temp_dir) = temp_config_dir {
        let srr_path = temp_dir.join("srr_network.toml");
        reload_proxy_srr(&admin_url, &srr_path).await?;
    }

    // --- Banner ---
    if output_mode == OutputMode::Text {
        eprintln!();
        eprintln!("{BOLD}Analemma GVM \u{2014} Watch Mode (observation only){RESET}");
        if with_rules {
            eprintln!("{DIM}Applying existing SRR rules while observing.{RESET}");
        } else {
            eprintln!("{DIM}All requests allowed through. No enforcement.{RESET}");
        }
        eprintln!();
        eprintln!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
        eprintln!("  {DIM}Command:{RESET}      {}", command.join(" "));
        eprintln!("  {DIM}Proxy:{RESET}        {}", proxy);
        if with_rules {
            eprintln!("  {DIM}Mode:{RESET}         observe + enforce");
        } else {
            eprintln!("  {DIM}Mode:{RESET}         observe only (allow-all)");
        }
        eprintln!();
        eprintln!(
            "  {DIM}{:<8}  {:<6} {:<30} {:<40} {:>3}  TOKENS{RESET}",
            "TIME", "METHOD", "HOST", "PATH", "ST"
        );
        eprintln!("  {DIM}{}{RESET}", "\u{2500}".repeat(95));
    }

    // --- Record WAL position ---
    let wal_path = "data/wal.log";
    let wal_start_len = std::fs::metadata(wal_path).map(|m| m.len()).unwrap_or(0);

    // --- Start WAL tailing and agent process concurrently ---
    let mut stats = SessionStats::new();
    let mut anomaly = AnomalyDetector::new();

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Build pipeline config and run pre-launch + launch via pipeline.
    // Watch uses pipeline directly (not run_agent) to avoid duplicate banners/audit.
    let mode = if sandbox {
        crate::pipeline::LaunchMode::Sandbox
    } else if contained {
        crate::pipeline::LaunchMode::Contained {
            image: image.to_string(),
            memory: memory.to_string(),
            cpus: cpus.to_string(),
            detach: false,
        }
    } else {
        crate::pipeline::LaunchMode::Cooperative
    };

    let agent_config = crate::pipeline::AgentConfig {
        command: command.to_vec(),
        agent_id: agent_id.to_string(),
        proxy: proxy.to_string(),
        mode,
        no_mitm,
        fs_governance: false, // Watch mode: legacy filesystem (observation only)
        sandbox_profile: gvm_sandbox::SandboxProfile::Standard,
        host_ports: vec![],
        memory_limit: None,
        cpu_limit: None,
        interactive: false,
    };

    // Pre-launch (ensure proxy, orphan cleanup, CA download)
    let pre = crate::pipeline::pre_launch(&agent_config).await?;

    // Spawn agent via pipeline::launch
    let config_clone = agent_config.clone();
    let mitm_ca = pre.mitm_ca.clone();
    let is_binary = pre.is_binary_mode;
    let agent_handle = tokio::spawn(async move {
        let pre_state = crate::pipeline::PreLaunchState {
            mitm_ca,
            wal_offset: 0, // watch manages its own WAL offset
            is_binary_mode: is_binary,
        };
        crate::pipeline::launch(&config_clone, &pre_state).await
    });

    let watchdog_proxy = proxy.to_string();
    let watchdog_workspace = run::workspace_root_for_proxy();
    let watchdog_handle = tokio::spawn(crate::proxy_manager::watchdog(
        watchdog_proxy,
        watchdog_workspace,
    ));

    // Give the agent a moment to start, then begin tailing
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Tail WAL until agent exits
    tokio::select! {
        agent_result = agent_handle => {
            // Agent finished — stop watchdog and do a final WAL read
            watchdog_handle.abort();
            let _ = cancel_tx.send(true);
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;

            // Final sweep
            if let Ok((events, _)) = read_wal_from_offset(wal_path, wal_start_len) {
                // Re-process all events for stats (tailing may have missed some)
                stats = SessionStats::new();
                anomaly = AnomalyDetector::new();
                for (event, raw_line) in &events {
                    stats.record_event(event);
                    let method = event.pointer("/transport/method").and_then(|v| v.as_str()).unwrap_or("");
                    let host = event.pointer("/transport/host").and_then(|v| v.as_str()).unwrap_or("");
                    let path = event.pointer("/transport/path").and_then(|v| v.as_str()).unwrap_or("");
                    let dc = event.get("default_caution").and_then(|v| v.as_bool()).unwrap_or(false);
                    anomaly.record_request(method, host, path, dc);

                    // Print any events we might have missed during tail
                    // (This is a simplified approach — in practice the tail loop
                    // handles most events. This final sweep catches stragglers.)
                    match output_mode {
                        OutputMode::Text => print_live_event_text(event, None),
                        OutputMode::Json => println!("{}", raw_line),
                    }
                }
            }

            if output_mode == OutputMode::Text {
                // Print agent exit status
                match agent_result {
                    Ok(Ok(code)) => {
                        eprintln!();
                        if code == 0 {
                            eprintln!("  {GREEN}Agent completed successfully{RESET}");
                        } else {
                            eprintln!("  {YELLOW}Agent exited with code: {}{RESET}", code);
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!();
                        eprintln!("  {RED}Agent failed: {}{RESET}", e);
                    }
                    Err(e) => {
                        eprintln!();
                        eprintln!("  {RED}Agent task panicked: {}{RESET}", e);
                    }
                }
            }
        }
        _ = async {
            // Tail loop runs concurrently
            tail_wal(wal_path, wal_start_len, &mut stats, &mut anomaly, output_mode, cancel_rx).await;
        } => {}
    }

    // --- Restore original SRR if we used allow-all ---
    if !with_rules {
        // Reload proxy with original config
        let original_srr = config_dir.join("srr_network.toml");
        if original_srr.exists() {
            let _ = reload_proxy_srr(&admin_url, &original_srr).await;
        }
    }

    // --- Session summary ---
    match output_mode {
        OutputMode::Text => print_session_summary_text(&stats, &anomaly),
        OutputMode::Json => print_session_summary_json(&stats, &anomaly),
    }

    // Interactive rule suggestions (text mode only)
    if output_mode == OutputMode::Text && stats.default_caution_count > 0 {
        eprintln!();
        eprintln!(
            "  {DIM}Tip: Run {CYAN}gvm run --interactive my_agent.py{RESET}{DIM} to create rules for unknown hosts.{RESET}"
        );
        eprintln!();
    }

    Ok(())
}

/// Reload proxy SRR rules via the /gvm/reload endpoint.
async fn reload_proxy_srr(proxy: &str, srr_path: &Path) -> Result<()> {
    let reload_url = format!("{}/gvm/reload", proxy.trim_end_matches('/'));
    let body = serde_json::json!({
        "srr_file": srr_path.to_string_lossy().replace('\\', "/")
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(&reload_url)
        .json(&body)
        .send()
        .await
        .context("Failed to reload proxy SRR rules")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Proxy reload failed ({}): {}", status, body);
    }
    Ok(())
}

/// RAII guard to clean up temp config directory on drop.
struct TempConfigGuard(PathBuf);

impl Drop for TempConfigGuard {
    fn drop(&mut self) {
        cleanup_temp_config(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(std::time::Duration::from_secs(45)), "45s");
        assert_eq!(
            format_duration(std::time::Duration::from_secs(90)),
            "1m 30s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3661)),
            "1h 1m 1s"
        );
    }

    #[test]
    fn test_estimate_cost_openai_gpt4o() {
        let cost = estimate_cost("openai", Some("gpt-4o-2024-08-06"), 1_000_000, 1_000_000);
        // input: $2.50, output: $10.00 → $12.50
        assert!((cost - 12.50).abs() < 0.01);
    }

    #[test]
    fn test_estimate_cost_anthropic_sonnet() {
        let cost = estimate_cost(
            "anthropic",
            Some("claude-sonnet-4-20250514"),
            1_000_000,
            1_000_000,
        );
        // input: $3.00, output: $15.00 → $18.00
        assert!((cost - 18.00).abs() < 0.01);
    }

    #[test]
    fn test_anomaly_detector_loop() {
        let mut ad = AnomalyDetector::new();
        // 5 calls should not trigger
        for _ in 0..5 {
            let w = ad.record_request("POST", "api.openai.com", "/v1/chat/completions", false);
            assert!(w.is_none());
        }
        // 6th should trigger loop
        let w = ad.record_request("POST", "api.openai.com", "/v1/chat/completions", false);
        assert!(w.is_some());
        assert!(w.unwrap().contains("Loop detected"));
    }

    #[test]
    fn test_anomaly_detector_default_caution() {
        let mut ad = AnomalyDetector::new();
        let w = ad.record_request("GET", "unknown.api.com", "/foo", true);
        assert!(w.is_some());
        assert!(w.unwrap().contains("Unknown host"));

        // Second call to same host should NOT re-warn
        let w2 = ad.record_request("GET", "unknown.api.com", "/bar", true);
        assert!(w2.is_none());
    }

    #[test]
    fn test_output_mode_parse() {
        assert_eq!(OutputMode::parse("text").unwrap(), OutputMode::Text);
        assert_eq!(OutputMode::parse("json").unwrap(), OutputMode::Json);
        assert!(OutputMode::parse("xml").is_err());
    }

    #[test]
    fn test_session_stats_record() {
        let mut stats = SessionStats::new();
        let event = serde_json::json!({
            "transport": { "host": "api.openai.com", "method": "POST", "path": "/v1/chat", "status_code": 200 },
            "decision": "Allow",
            "decision_source": "SRR",
            "default_caution": false,
            "llm_trace": {
                "provider": "openai",
                "model": "gpt-4o",
                "usage": { "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150 }
            }
        });
        stats.record_event(&event);

        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.llm_calls, 1);
        assert_eq!(stats.total_tokens, 150);
        assert!(stats.models_used.contains("gpt-4o"));
        assert_eq!(*stats.hosts.get("api.openai.com").unwrap(), 1);
    }
}
