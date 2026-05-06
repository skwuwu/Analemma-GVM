use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// A URL pattern that hit Default-to-Caution (no explicit SRR rule).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CautionTarget {
    method: String,
    host: String,
    /// Generalized path pattern (e.g. "/v1/messages" → "/v1/messages")
    path_pattern: String,
}

/// Strip the default port (`:80` for HTTP, `:443` for HTTPS) from a host
/// authority before serialising into a suggested SRR pattern.
///
/// The SRR matcher already collapses default ports on both sides, so the
/// behaviour is identical with or without the suffix — but operators read
/// these generated files and a noisy `:443` suffix on every HTTPS rule
/// just adds visual clutter and trains them to ignore the port column.
/// Non-default ports stay so the human can see "this rule was learned
/// from a non-standard endpoint" at a glance.
fn pretty_host(host: &str) -> String {
    if let Some((h, p)) = host.rsplit_once(':') {
        if p == "80" || p == "443" {
            return h.to_string();
        }
    }
    host.to_string()
}

/// Sanitise a host for use in a TOML label. Strips the optional port
/// before slugging so labels stay stable across HTTP/HTTPS variants.
fn host_label(host: &str) -> String {
    pretty_host(host).replace('.', "-")
}

/// Validate a `"HH:MM-HH:MM"` window without dragging in the proxy's
/// private parser. Same rules as `gvm_proxy::srr::parse_time_window`:
/// HH ∈ 0..23, MM ∈ 0..59, start ≠ end.
///
/// Returns Ok(()) on success. Validation lives here so the prompt
/// rejects bad input immediately instead of writing a TOML file the
/// proxy will refuse to load.
fn validate_window_str(window: &str) -> Result<(), String> {
    let (start, end) = window
        .split_once('-')
        .ok_or_else(|| format!("expected HH:MM-HH:MM, got '{}'", window))?;
    let parse_hhmm = |s: &str| -> Result<u16, String> {
        let (h, m) = s
            .trim()
            .split_once(':')
            .ok_or_else(|| format!("expected HH:MM, got '{}'", s))?;
        let h: u16 = h
            .parse()
            .map_err(|_| format!("invalid hour '{}' in '{}'", h, s))?;
        let m: u16 = m
            .parse()
            .map_err(|_| format!("invalid minute '{}' in '{}'", m, s))?;
        if h >= 24 {
            return Err(format!("hour must be 0..23, got {}", h));
        }
        if m >= 60 {
            return Err(format!("minute must be 0..59, got {}", m));
        }
        Ok(h * 60 + m)
    };
    let s = parse_hhmm(start)?;
    let e = parse_hhmm(end)?;
    if s == e {
        return Err(format!(
            "window '{}' has zero duration (start equals end)",
            window
        ));
    }
    Ok(())
}

/// Prompt the operator for a time_window condition. Returns:
///   Ok(Some(toml_fragment)) on success — fragment is the inline-table
///     value for the rule's `condition = ...` line.
///   Ok(None) if the operator cancels (empty input on first prompt).
///   Err(msg) on validation failure.
///
/// Validation runs here so an obviously broken value (`25:00-30:00`,
/// `Mars/Olympus`) is rejected before the file is touched.
fn prompt_time_condition<R: std::io::BufRead>(reader: &mut R) -> Result<Option<String>, String> {
    use crate::ui::{BOLD, DIM, RESET};

    let mut buf = String::new();

    println!();
    println!(
        "    {DIM}Time-conditional rule — fires only when request timestamp matches.{RESET}"
    );
    println!(
        "    {DIM}Replay (`gvm replay`) is deterministic via event.timestamp.{RESET}"
    );
    println!();

    // Window
    print!(
        "      {BOLD}window{RESET} {DIM}(HH:MM-HH:MM, default 09:00-18:00):{RESET} "
    );
    std::io::stdout().flush().ok();
    buf.clear();
    if reader.read_line(&mut buf).is_err() {
        return Ok(None);
    }
    let window = match buf.trim() {
        "" => "09:00-18:00".to_string(),
        s => s.to_string(),
    };
    validate_window_str(&window)?;

    // Timezone
    print!(
        "      {BOLD}timezone{RESET} {DIM}(IANA, default UTC):{RESET} "
    );
    std::io::stdout().flush().ok();
    buf.clear();
    if reader.read_line(&mut buf).is_err() {
        return Ok(None);
    }
    let tz = match buf.trim() {
        "" => "UTC".to_string(),
        s => s.to_string(),
    };
    if tz.parse::<chrono_tz::Tz>().is_err() {
        return Err(format!(
            "unknown IANA timezone '{}' (try 'Asia/Seoul', 'America/New_York', 'UTC')",
            tz
        ));
    }

    // Inside vs outside
    print!(
        "      {BOLD}fires{RESET} {DIM}([i]nside or [o]utside the window, default i):{RESET} "
    );
    std::io::stdout().flush().ok();
    buf.clear();
    if reader.read_line(&mut buf).is_err() {
        return Ok(None);
    }
    let outside = match buf.trim().to_lowercase().as_str() {
        "" | "i" | "in" | "inside" => false,
        "o" | "out" | "outside" => true,
        other => return Err(format!("expected i or o, got '{}'", other)),
    };

    Ok(Some(format!(
        r#"{{ kind = "time_window", window = "{}", tz = "{}", outside = {} }}"#,
        window, tz, outside
    )))
}

/// Scan WAL events for Default-to-Caution hits and interactively suggest rules.
///
/// Called after the agent run when `--interactive` is set. Reads new WAL entries,
/// identifies unique (method, host, path) combos that triggered default-to-caution,
/// and prompts the operator to add explicit SRR rules.
pub fn suggest_rules_interactive(wal_path: &str, start_offset: u64, srr_file: &str) {
    use std::io::BufRead;

    let file = match std::fs::File::open(wal_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Seek past already-processed events instead of loading entire file.
    // Previous implementation used read_to_string (OOM risk on large WALs).
    let reader = if start_offset > 0 {
        use std::io::{Seek, SeekFrom};
        let mut file = file;
        if file.seek(SeekFrom::Start(start_offset)).is_err() {
            return;
        }
        std::io::BufReader::new(file)
    } else {
        std::io::BufReader::new(file)
    };

    // Collect unique (method, host, path) combos that hit default-to-caution
    let mut caution_targets: BTreeMap<CautionTarget, usize> = BTreeMap::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break, // I/O error — stop reading
        };
        let event: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check if this event was flagged as default-to-caution
        let is_default = event
            .get("default_caution")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !is_default {
            continue;
        }

        let method = event
            .get("transport")
            .and_then(|t| t.get("method"))
            .and_then(|v| v.as_str())
            .unwrap_or("POST");
        let host = event
            .get("transport")
            .and_then(|t| t.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = event
            .get("transport")
            .and_then(|t| t.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if host.is_empty() {
            continue;
        }

        let target = CautionTarget {
            method: if method.is_empty() {
                "POST".to_string()
            } else {
                method.to_uppercase()
            },
            host: host.to_string(),
            path_pattern: generalize_path(path),
        };

        *caution_targets.entry(target).or_insert(0) += 1;
    }

    if caution_targets.is_empty() {
        return;
    }

    println!();
    println!("  {BOLD}SRR Rule Suggestions{RESET} {DIM}(Default-to-Caution detected){RESET}");
    println!(
        "  {DIM}The following URLs had no explicit SRR rule and fell back to 300ms delay.{RESET}"
    );
    println!("  {DIM}Add explicit rules to make governance intent clear.{RESET}");
    println!();

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut rules_added = 0usize;

    for (target, count) in &caution_targets {
        // The path_pattern may already carry one or more `{any}` from
        // the heuristic generalizer. The operator can additionally
        // wildcard segments via `[e <nums>]` — useful when a custom
        // slug or base64-encoded segment slipped past `looks_like_id`.
        // The loop continues until a decision (a/d/n/s) is picked or
        // input EOF.
        let mut current_path = target.path_pattern.clone();
        // Optional time-window gate. Stays None unless the operator
        // explicitly invokes [t] — interactive mode never auto-suggests
        // a condition (that would be policy design, which `gvm suggest`
        // is not). When Some(_), the next a/d/n decision attaches it.
        let mut pending_condition: Option<String> = None;

        let (decision_toml, description, final_pattern, condition_toml) = loop {
            let pattern = format!("{}{}", pretty_host(&target.host), current_path);
            println!(
                "  {YELLOW}\u{26a0}{RESET} {BOLD}{} {}{RESET} {DIM}({} hit{}){RESET}",
                target.method,
                pattern,
                count,
                if *count > 1 { "s" } else { "" },
            );
            println!();
            // Numbered segments — operator references them in `e`.
            let segs = path_segments(&current_path);
            if !segs.is_empty() {
                let mut line = String::from("    ");
                for (i, s) in segs.iter().enumerate() {
                    line.push_str(&format!("{DIM}[{}]{RESET} {} ", i + 1, s));
                }
                println!("{}", line);
                println!();
            }

            println!("    {CYAN}[a]{RESET} Allow     {DIM}(IC-1: instant, no delay){RESET}");
            println!(
                "    {CYAN}[d]{RESET} Delay     {DIM}(IC-2: 300ms safety delay + audit){RESET}"
            );
            println!("    {CYAN}[n]{RESET} Deny      {DIM}(IC-3: block completely){RESET}");
            println!("    {CYAN}[s]{RESET} Skip      {DIM}(leave as Default-to-Caution){RESET}");
            println!(
                "    {CYAN}[e <nums>]{RESET} Edit     {DIM}(wildcard segments — e.g. \"e 2 3\"){RESET}"
            );
            // Time-conditional is opt-in: shown as a peer choice but no
            // auto-suggestion. Reason: condition.time_window is policy
            // design (the operator decides "deny outside biz hours"),
            // and `gvm suggest` is a baseline-construction tool, not a
            // policy designer. The [t] key surfaces the feature without
            // making it the default path. When a condition is already
            // staged we show a preview of the resulting rule and offer
            // [c] to clear, [t] to replace.
            if let Some(cond) = &pending_condition {
                println!("    {CYAN}[t]{RESET} Time      {GREEN}(staged — replace){RESET}");
                println!(
                    "    {CYAN}[c]{RESET} Clear     {DIM}(drop the staged condition){RESET}"
                );
                // Preview block — show the operator the exact TOML
                // their next decision will produce. Surfacing the
                // staged condition this way avoids the "I forgot what
                // I picked" footgun: the operator types `t`, picks a
                // window, gets distracted, comes back, and now sees
                // the full rule in front of them before pressing a/d/n.
                let preview_decision = match pending_condition.as_deref() {
                    // We don't know yet which decision they'll pick,
                    // but Allow is the most common pairing with a
                    // time-window condition ("allow only during biz
                    // hours"). The preview makes it clear this is
                    // illustrative — operator's actual a/d/n choice
                    // overrides the decision line.
                    Some(_) => r#"{ type = "Allow" }  # ← your a/d/n choice overrides this"#,
                    None => r#"{ type = "Allow" }"#,
                };
                println!();
                println!("    {DIM}── preview ──{RESET}");
                println!("    {DIM}[[rules]]{RESET}");
                println!("    {DIM}method = \"{}\"{RESET}", target.method);
                println!("    {DIM}pattern = \"{}\"{RESET}", pretty_host(&target.host));
                println!("    {DIM}decision = {}{RESET}", preview_decision);
                println!("    {DIM}condition = {}{RESET}", cond);
                println!();
            } else {
                println!(
                    "    {CYAN}[t]{RESET} Time      {DIM}(gate by HH:MM-HH:MM in your timezone){RESET}"
                );
            }
            println!();
            print!("    {BOLD}Choice:{RESET} ");
            io::stdout().flush().unwrap_or(());

            let mut input = String::new();
            if reader.read_line(&mut input).is_err() {
                // EOF — abandon this target. The outer for loop's
                // `continue` won't reach because we're inside a
                // sub-loop; explicit break with a sentinel.
                break (
                    String::new(),
                    String::new(),
                    String::new(), // empty pattern marks "no rule produced"
                    None,
                );
            }

            let choice = input.trim().to_lowercase();

            // Edit branch — wildcard the requested segments and loop
            // back to display the new pattern. No rule produced yet.
            if let Some(indices) = parse_edit_indices(&choice) {
                if indices.is_empty() {
                    println!("    {DIM}Edit needs segment numbers, e.g. \"e 2 3\"{RESET}");
                    println!();
                    continue;
                }
                current_path = apply_segment_edits(&current_path, &indices);
                println!(
                    "    {DIM}Pattern updated:{RESET} {}{}",
                    pretty_host(&target.host),
                    current_path
                );
                println!();
                continue;
            }

            let pattern_for_decision = pattern.clone();
            match choice.as_str() {
                "t" | "time" => {
                    match prompt_time_condition(&mut reader) {
                        Ok(Some(cond)) => {
                            pending_condition = Some(cond);
                            println!(
                                "    {GREEN}condition staged{RESET} \
                                 {DIM}— now choose decision (a/d/n), or [c] to clear{RESET}"
                            );
                            println!();
                        }
                        Ok(None) => {
                            // operator cancelled the subprompt
                            println!("    {DIM}cancelled — no condition staged{RESET}");
                            println!();
                        }
                        Err(e) => {
                            println!("    {RED}invalid input: {}{RESET}", e);
                            println!();
                        }
                    }
                    continue;
                }
                "c" | "clear" if pending_condition.is_some() => {
                    // Drop the staged condition without making any other
                    // change. Useful when the operator stages [t], reads
                    // the preview, and decides this rule shouldn't be
                    // time-conditional after all — without this they'd
                    // either abandon the whole prompt with [s] (losing
                    // any segment edits they made) or re-stage with a
                    // fake "always" window.
                    pending_condition = None;
                    println!("    {DIM}staged condition cleared{RESET}");
                    println!();
                    continue;
                }
                "a" | "allow" => {
                    break (
                        r#"{ type = "Allow" }"#.to_string(),
                        format!(
                            "{} {} — explicitly allowed",
                            target.method, pattern_for_decision
                        ),
                        pattern_for_decision,
                        pending_condition.clone(),
                    )
                }
                "d" | "delay" => {
                    break (
                        r#"{ type = "Delay", milliseconds = 300 }"#.to_string(),
                        format!(
                            "{} {} — monitored with 300ms delay",
                            target.method, pattern_for_decision
                        ),
                        pattern_for_decision,
                        pending_condition.clone(),
                    )
                }
                "n" | "deny" => {
                    break (
                        format!(
                            r#"{{ type = "Deny", reason = "{} {} — blocked by operator" }}"#,
                            target.method, pattern_for_decision
                        ),
                        format!(
                            "{} {} — blocked by operator",
                            target.method, pattern_for_decision
                        ),
                        pattern_for_decision,
                        pending_condition.clone(),
                    )
                }
                "s" | "skip" | "" => {
                    println!("    {DIM}Skipped{RESET}");
                    println!();
                    break (String::new(), String::new(), String::new(), None);
                }
                _ => {
                    let extra = if pending_condition.is_some() {
                        ", c to clear staged condition"
                    } else {
                        ""
                    };
                    println!(
                        "    {DIM}Unknown choice, try a/d/n/s/t or \"e <nums>\"{}{RESET}",
                        extra
                    );
                    println!();
                    continue;
                }
            }
        };

        // Skip / EOF / unknown all surface as empty pattern → no rule.
        if final_pattern.is_empty() {
            continue;
        }

        // Build the TOML rule block. The optional `condition` line is
        // appended only if the operator explicitly staged one via [t].
        let condition_line = match &condition_toml {
            Some(c) => format!("condition = {}\n", c),
            None => String::new(),
        };
        let rule_toml = format!(
            r#"
[[rules]]
method = "{method}"
pattern = "{pattern}"
decision = {decision}
{condition_line}description = "{description}"
"#,
            method = target.method,
            pattern = final_pattern,
            decision = decision_toml,
            condition_line = condition_line,
            description = description,
        );

        // Append to SRR file
        match append_rule_to_file(srr_file, &rule_toml) {
            Ok(()) => {
                rules_added += 1;
                println!("    {GREEN}\u{2713} Rule added to {}{RESET}", srr_file);
                println!();
            }
            Err(e) => {
                println!("    {RED}\u{2717} Failed to write rule: {}{RESET}", e);
                println!();
            }
        }
    }

    if rules_added > 0 {
        println!(
            "  {GREEN}{BOLD}{} rule(s) added{RESET} to {CYAN}{}{RESET}",
            rules_added, srr_file
        );
        println!(
            "  {DIM}Rules take effect on next proxy restart (or immediately with hot-reload).{RESET}"
        );
        println!();
    }
}

/// Generate SRR rules from a watch session JSON log (batch, non-interactive).
///
/// Reads JSON lines from a watch `--output json` session, identifies all URLs
/// that hit Default-to-Caution, groups by (method, host, generalized_path),
/// and outputs TOML rules with the specified default decision.
pub fn suggest_rules_batch(log_path: &str, output_path: Option<&str>, default_decision: &str) {
    use std::io::BufRead;

    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{RED}Cannot open watch log: {e}{RESET}");
            return;
        }
    };

    let reader = std::io::BufReader::new(file);
    let mut caution_targets: BTreeMap<CautionTarget, usize> = BTreeMap::new();
    let mut total_events = 0usize;
    // Each request produces multiple WAL events as it transitions through the
    // EventStatus state machine (Pending -> Executed -> Confirmed/Failed). All
    // share the same `event_id`. Without dedup, suggest counts a single call
    // 2-3 times and inflates rule "hits". Dedup by event_id, keeping the first
    // occurrence (which has the request transport info we care about).
    let mut seen_event_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };
        let event: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(event_id) = event.get("event_id").and_then(|v| v.as_str()) {
            if !seen_event_ids.insert(event_id.to_string()) {
                continue; // duplicate state-machine transition for the same request
            }
        }

        total_events += 1;

        let is_default = event
            .get("default_caution")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !is_default {
            continue;
        }

        let method = event
            .get("transport")
            .and_then(|t| t.get("method"))
            .and_then(|v| v.as_str())
            .unwrap_or("POST");
        let host = event
            .get("transport")
            .and_then(|t| t.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = event
            .get("transport")
            .and_then(|t| t.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if host.is_empty() {
            continue;
        }

        let target = CautionTarget {
            method: if method.is_empty() {
                "POST".to_string()
            } else {
                method.to_uppercase()
            },
            host: host.to_string(),
            path_pattern: generalize_path(path),
        };

        *caution_targets.entry(target).or_insert(0) += 1;
    }

    if caution_targets.is_empty() {
        eprintln!("{DIM}No Default-to-Caution hits found in {total_events} events.{RESET}");
        return;
    }

    // Build decision TOML based on flag
    let decision_toml = match default_decision.to_lowercase().as_str() {
        "allow" | "a" => r#"{ type = "Allow" }"#.to_string(),
        "delay" | "d" => r#"{ type = "Delay", milliseconds = 300 }"#.to_string(),
        "deny" | "n" => r#"{ type = "Deny", reason = "Blocked by suggest" }"#.to_string(),
        other => {
            eprintln!("{RED}Unknown decision: {other}. Use: allow, delay, deny{RESET}");
            return;
        }
    };

    // Generate TOML rules
    let mut toml_output = String::from(
        "# SRR rules generated by `gvm suggest`\n\
         # Review and adjust before applying.\n\n",
    );

    for (target, count) in &caution_targets {
        let pattern = format!("{}{}", pretty_host(&target.host), target.path_pattern);
        let label = format!(
            "suggest-{}-{}",
            target.method.to_lowercase(),
            host_label(&target.host)
        );
        toml_output.push_str(&format!(
            "[[rules]]\nmethod = \"{}\"\npattern = \"{}\"\ndecision = {}\n\
             label = \"{}\"\n# {} hit{}\n\n",
            target.method,
            pattern,
            decision_toml,
            label,
            count,
            if *count > 1 { "s" } else { "" },
        ));
    }

    // Output
    match output_path {
        Some(path) => match std::fs::write(path, &toml_output) {
            Ok(()) => {
                eprintln!(
                    "{GREEN}{BOLD}{} rule(s){RESET} written to {CYAN}{path}{RESET} \
                         {DIM}(from {total_events} events, {} caution hits){RESET}",
                    caution_targets.len(),
                    caution_targets.values().sum::<usize>(),
                );
            }
            Err(e) => eprintln!("{RED}Failed to write {path}: {e}{RESET}"),
        },
        None => {
            // stdout — used by `gvm suggest --from x > srr.toml`. Whatever
            // we emit here MUST remain valid TOML, because the user almost
            // always pipes us straight into srr_network.toml. Previously
            // this branch printed a colored summary on stderr; if the
            // shell merged stderr into stdout (e.g. `2>&1`, CI capture,
            // some IDE consoles), the ANSI escape bytes landed inside the
            // rule file. The proxy's TOML loader then silently produced
            // zero rules and governance was disabled without any error
            // surface. Lesson: the only safe channel that survives every
            // shell redirection mode is the toml_output buffer itself,
            // and the only safe content is plain ASCII inside a `#`
            // comment line. So embed the summary as the final TOML
            // comment and drop the stderr write entirely.
            let summary = format!(
                "# {} rule(s) from {} events ({} caution hits)\n",
                caution_targets.len(),
                total_events,
                caution_targets.values().sum::<usize>(),
            );
            print!("{toml_output}{summary}");
        }
    }
}

/// Count how many WAL events hit default-to-caution (no explicit SRR rule).
/// Used by pipeline.rs post_exit_audit to suggest batch rule generation.
pub fn count_default_caution_hits(wal_path: &str, start_offset: u64) -> usize {
    use std::io::BufRead;

    let file = match std::fs::File::open(wal_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };

    let reader = if start_offset > 0 {
        use std::io::{Seek, SeekFrom};
        let mut file = file;
        if file.seek(SeekFrom::Start(start_offset)).is_err() {
            return 0;
        }
        std::io::BufReader::new(file)
    } else {
        std::io::BufReader::new(file)
    };

    let mut count = 0;
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
            if event
                .get("default_caution")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

/// Generalize a specific path to a wildcard pattern.
///
/// Heuristic: keep the first 2 path segments, wildcard the rest.
/// `/v1/chat/completions` → `/v1/chat/completions` (short enough)
/// `/users/12345/orders/456` → `/users/{any}` (dynamic segments detected)
///
/// For paths with numeric segments (likely IDs), wildcards are applied.
fn generalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return "/{any}".to_string();
    }

    // If any segment looks like a dynamic ID (numeric, UUID-like), wildcard from there
    let mut result = Vec::new();
    for seg in &segments {
        if looks_like_id(seg) {
            result.push("{any}");
            break;
        }
        result.push(seg);
    }

    // If nothing was wildcarded and path is specific, add trailing wildcard
    if result.len() == segments.len() && segments.len() <= 3 {
        // Short, static path — keep as-is (e.g. /v1/messages)
        format!("/{}", result.join("/"))
    } else if result.len() < segments.len() {
        // We wildcarded at an ID segment
        format!("/{}", result.join("/"))
    } else {
        // Long path — wildcard the rest
        format!("/{}/{{any}}", result[..2.min(result.len())].join("/"))
    }
}

/// Check if a path segment looks like a dynamic ID (numeric, UUID, hex hash).
fn looks_like_id(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // All digits (numeric ID)
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // UUID-like (contains hyphens and hex chars)
    if segment.len() >= 32 && segment.contains('-') {
        let hex_chars = segment
            .chars()
            .filter(|c| c.is_ascii_hexdigit() || *c == '-')
            .count();
        if hex_chars == segment.len() {
            return true;
        }
    }
    // Long hex string (hash)
    if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

/// Split `path` on `/` into non-empty segments. The leading `/` and
/// any duplicate separators are stripped — same convention used by
/// `generalize_path`. Pure helper, no allocation beyond the returned
/// `Vec<&str>`.
fn path_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Parse a `e <nums>` edit command. Returns `Some(indices)` (1-based,
/// in input order, deduped is the caller's job) when the line begins
/// with `e` followed by whitespace and one or more positive integers.
/// Returns `None` when the line doesn't start with `e ` (caller falls
/// through to the decision branch).
///
/// Tolerant by design:
/// - Tabs are accepted as separators (`e\t2\t3`).
/// - Non-numeric tokens are silently dropped — operator typos like
///   `e 2,3` partially work (drops the `2,3` token but accepts neither;
///   we surface "needs segment numbers" if the result is empty).
/// - Negative / zero / overflow → silently dropped. The caller
///   bounds-checks against the actual segment count later, so a stray
///   `999` is harmless.
fn parse_edit_indices(line: &str) -> Option<Vec<usize>> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("e ")
        .or_else(|| trimmed.strip_prefix("e\t"))?;
    let indices: Vec<usize> = rest
        .split_whitespace()
        .filter_map(|tok| tok.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .collect();
    Some(indices)
}

/// Apply 1-based segment-wildcard edits to a path pattern.
///
/// `indices` are 1-based positions of segments to replace with
/// `{any}`. Out-of-range indices are silently ignored — they don't
/// propagate as errors because the caller (interactive prompt) just
/// re-displays the pattern and lets the operator try again.
///
/// Pure: no I/O, no allocation beyond the returned `String`. Same
/// input → same output (deterministic), which keeps the operator's
/// rule-authoring decision reproducible across `gvm suggest` runs.
fn apply_segment_edits(path: &str, indices: &[usize]) -> String {
    let segs = path_segments(path);
    if segs.is_empty() {
        return path.to_string();
    }
    // Use a HashSet for O(1) membership; small enough that allocation
    // cost is dominated by the format!() below regardless.
    let to_wildcard: std::collections::HashSet<usize> = indices.iter().copied().collect();
    let new_segs: Vec<String> = segs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if to_wildcard.contains(&(i + 1)) {
                "{any}".to_string()
            } else {
                (*s).to_string()
            }
        })
        .collect();
    format!("/{}", new_segs.join("/"))
}

/// Append a TOML rule block to the SRR file.
fn append_rule_to_file(path: &str, rule_toml: &str) -> io::Result<()> {
    use std::fs::OpenOptions;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    file.write_all(rule_toml.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_window_str_accepts_canonical() {
        assert!(validate_window_str("09:00-18:00").is_ok());
        assert!(validate_window_str("22:00-06:00").is_ok()); // cross-midnight
        assert!(validate_window_str("00:00-23:59").is_ok());
        // Whitespace tolerance — operators retype these from prose
        assert!(validate_window_str("09:00 - 18:00").is_ok());
    }

    #[test]
    fn validate_window_str_rejects_garbage() {
        assert!(validate_window_str("25:00-30:00").is_err());
        assert!(validate_window_str("9-18").is_err()); // missing :MM
        assert!(validate_window_str("09:60-10:00").is_err()); // minute oob
        assert!(validate_window_str("09:00-09:00").is_err()); // zero duration
        assert!(validate_window_str("not a window").is_err());
        assert!(validate_window_str("").is_err());
    }

    #[test]
    fn generalize_short_static_path() {
        assert_eq!(generalize_path("/v1/messages"), "/v1/messages");
        assert_eq!(generalize_path("/api/health"), "/api/health");
    }

    #[test]
    fn generalize_path_with_numeric_id() {
        assert_eq!(generalize_path("/users/12345/orders"), "/users/{any}");
        assert_eq!(generalize_path("/transfer/99999"), "/transfer/{any}");
    }

    #[test]
    fn generalize_path_with_uuid() {
        assert_eq!(
            generalize_path("/events/550e8400-e29b-41d4-a716-446655440000/details"),
            "/events/{any}"
        );
    }

    #[test]
    fn generalize_empty_path() {
        assert_eq!(generalize_path("/"), "/{any}");
        assert_eq!(generalize_path(""), "/{any}");
    }

    #[test]
    fn looks_like_id_detects_numbers() {
        assert!(looks_like_id("12345"));
        assert!(looks_like_id("0"));
        assert!(!looks_like_id("users"));
        assert!(!looks_like_id("v1"));
    }

    #[test]
    fn looks_like_id_detects_uuids() {
        assert!(looks_like_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!looks_like_id("short-uuid"));
    }

    #[test]
    fn pretty_host_strips_default_https_port() {
        assert_eq!(pretty_host("api.bank.com:443"), "api.bank.com");
    }

    #[test]
    fn pretty_host_strips_default_http_port() {
        assert_eq!(pretty_host("api.bank.com:80"), "api.bank.com");
    }

    #[test]
    fn pretty_host_keeps_nonstandard_port() {
        // Non-default ports stay so an operator reading the generated TOML
        // can see "this rule was learned from a non-standard endpoint".
        assert_eq!(pretty_host("api.demo:9999"), "api.demo:9999");
        assert_eq!(pretty_host("internal.svc:8080"), "internal.svc:8080");
    }

    #[test]
    fn pretty_host_handles_no_port() {
        assert_eq!(pretty_host("api.bank.com"), "api.bank.com");
    }

    #[test]
    fn host_label_strips_port_before_slugging() {
        // Label sanitisation must produce the same slug whether the host
        // came in with a default port or without — otherwise HTTPS and
        // HTTP variants of the same host generate two different labels
        // and the operator sees duplicate-looking entries.
        assert_eq!(host_label("api.bank.com"), "api-bank-com");
        assert_eq!(host_label("api.bank.com:443"), "api-bank-com");
        assert_eq!(host_label("api.demo:9999"), "api-demo:9999");
    }

    // ── Segment editor (interactive `e <nums>` branch) ──

    #[test]
    fn parse_edit_indices_recognises_e_prefix() {
        assert_eq!(parse_edit_indices("e 2 3"), Some(vec![2, 3]));
        assert_eq!(parse_edit_indices("e 1"), Some(vec![1]));
        // Tab separator (real shells emit either; pasting from
        // tmux selection often produces tabs).
        assert_eq!(parse_edit_indices("e\t2\t3"), Some(vec![2, 3]));
    }

    #[test]
    fn parse_edit_indices_returns_none_for_non_edit() {
        // a/d/n/s and unknown go through the decision branch — the
        // helper must signal "not an edit" with None so the caller
        // doesn't accidentally treat "a" as an edit with no indices.
        assert!(parse_edit_indices("a").is_none());
        assert!(parse_edit_indices("d").is_none());
        assert!(parse_edit_indices("skip").is_none());
        // Bare `e` without space is also not an edit (no indices to
        // wildcard, no separator either) — falls to "unknown choice".
        assert!(parse_edit_indices("e").is_none());
    }

    #[test]
    fn parse_edit_indices_drops_invalid_tokens_silently() {
        // `2,3` is a single non-numeric token (because comma);
        // operator's typo. Drops it; returns the valid `5`.
        assert_eq!(parse_edit_indices("e 2,3 5"), Some(vec![5]));
        // Negative / zero are dropped (1-based positions only).
        assert_eq!(parse_edit_indices("e 0 -1 4"), Some(vec![4]));
        // All-invalid → empty vec; caller surfaces "needs segment numbers".
        assert_eq!(parse_edit_indices("e xyz abc"), Some(vec![]));
    }

    #[test]
    fn apply_segment_edits_wildcards_specified_positions() {
        // 1-based, in input order (not deduped; the caller's HashSet
        // membership check handles duplicates implicitly).
        assert_eq!(
            apply_segment_edits("/repos/torvalds/linux/issues/12345", &[2, 3]),
            "/repos/{any}/{any}/issues/12345"
        );
        assert_eq!(apply_segment_edits("/v1/messages", &[2]), "/v1/{any}");
    }

    #[test]
    fn apply_segment_edits_ignores_out_of_range() {
        // Indices past the end are silently ignored — this is the
        // "operator typed a wrong number" case; no panic, no
        // partial pattern.
        assert_eq!(
            apply_segment_edits("/v1/messages", &[5, 999]),
            "/v1/messages"
        );
        // 0 is invalid (1-based); ignored. Only segment 1 wildcards.
        assert_eq!(
            apply_segment_edits("/v1/messages", &[0, 1]),
            "/{any}/messages"
        );
    }

    #[test]
    fn apply_segment_edits_empty_indices_is_noop() {
        // No-op: same input → same output. Pinned because the
        // outer interactive loop relies on this to display the
        // updated pattern unchanged when the operator types a bare
        // `e` (caught earlier by the "needs segment numbers"
        // branch, but defence-in-depth).
        assert_eq!(apply_segment_edits("/repos/foo/bar", &[]), "/repos/foo/bar");
    }

    #[test]
    fn apply_segment_edits_handles_already_wildcarded() {
        // Path that came from `generalize_path` already has `{any}`
        // segments. Editor can wildcard further static segments
        // without breaking the existing markers.
        assert_eq!(
            apply_segment_edits("/repos/{any}/issues/abc", &[3]),
            "/repos/{any}/{any}/abc"
        );
    }

    #[test]
    fn apply_segment_edits_preserves_root() {
        // Pattern always starts with `/`. Empty path defensively
        // stays empty rather than producing `//`.
        assert_eq!(apply_segment_edits("", &[1]), "");
        assert_eq!(apply_segment_edits("/", &[1]), "/");
    }
}
