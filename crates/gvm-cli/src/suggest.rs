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
        let pattern = format!("{}{}", pretty_host(&target.host), target.path_pattern);
        println!(
            "  {YELLOW}\u{26a0}{RESET} {BOLD}{} {}{RESET} {DIM}({} hit{}){RESET}",
            target.method,
            pattern,
            count,
            if *count > 1 { "s" } else { "" },
        );
        println!();
        println!("    {CYAN}[a]{RESET} Allow     {DIM}(IC-1: instant, no delay){RESET}");
        println!("    {CYAN}[d]{RESET} Delay     {DIM}(IC-2: 300ms safety delay + audit){RESET}");
        println!("    {CYAN}[n]{RESET} Deny      {DIM}(IC-3: block completely){RESET}");
        println!("    {CYAN}[s]{RESET} Skip      {DIM}(leave as Default-to-Caution){RESET}");
        println!();
        print!("    {BOLD}Choice [a/d/n/s]:{RESET} ");
        io::stdout().flush().unwrap_or(());

        let mut input = String::new();
        if reader.read_line(&mut input).is_err() {
            break;
        }

        let choice = input.trim().to_lowercase();
        let (decision_toml, description) = match choice.as_str() {
            "a" | "allow" => (
                r#"{ type = "Allow" }"#.to_string(),
                format!("{} {} — explicitly allowed", target.method, pattern),
            ),
            "d" | "delay" => (
                r#"{ type = "Delay", milliseconds = 300 }"#.to_string(),
                format!("{} {} — monitored with 300ms delay", target.method, pattern),
            ),
            "n" | "deny" => (
                format!(
                    r#"{{ type = "Deny", reason = "{} {} — blocked by operator" }}"#,
                    target.method, pattern
                ),
                format!("{} {} — blocked by operator", target.method, pattern),
            ),
            "s" | "skip" | "" => {
                println!("    {DIM}Skipped{RESET}");
                println!();
                continue;
            }
            _ => {
                println!("    {DIM}Unknown choice, skipping{RESET}");
                println!();
                continue;
            }
        };

        // Build the TOML rule block
        let rule_toml = format!(
            r#"
[[rules]]
method = "{method}"
pattern = "{pattern}"
decision = {decision}
description = "{description}"
"#,
            method = target.method,
            pattern = pattern,
            decision = decision_toml,
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
}
