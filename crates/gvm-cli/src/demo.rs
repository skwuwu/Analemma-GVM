use anyhow::{Context, Result};
use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// Demo profile metadata for display purposes.
struct DemoProfile {
    title: &'static str,
    description: &'static str,
    script: &'static str,
    narrative: &'static [&'static str],
}

/// Available demo profiles.
const AVAILABLE_DEMOS: &[&str] = &["finance", "assistant", "devops", "data", "all"];

/// Run the LLM-powered demo — launches the corresponding Python agent script
/// which handles mock server, Claude API calls, and dashboard output.
pub async fn run_demo(proxy_url: &str, _mock_port: u16, scenario: Option<&str>) -> Result<()> {
    let profile_name = match scenario {
        Some("all") => {
            return run_all_demos(proxy_url).await;
        }
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
            println!("{BOLD}Analemma-GVM \u{2014} Demo Scenarios{RESET}");
            println!();
            print_available_demos();
            return Ok(());
        }
    };

    run_single_demo(proxy_url, profile_name).await
}

/// Run a single demo by launching its Python agent script.
async fn run_single_demo(proxy_url: &str, name: &str) -> Result<()> {
    let profile = build_profile(name);

    println!();
    println!("{BOLD}Analemma-GVM \u{2014} {}{RESET}", profile.title);
    println!("{DIM}{}{RESET}", profile.description);
    println!();

    // Story intro
    println!("  {BOLD}Scenario:{RESET}");
    for line in profile.narrative {
        println!("  {DIM}{}{RESET}", line);
    }
    println!();

    // Check proxy health
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
    println!();

    // Resolve script path relative to the project root
    let script_path = resolve_script_path(profile.script)?;
    println!("  {DIM}Launching LLM agent:{RESET} {CYAN}{}{RESET}", profile.script);
    println!("  {DIM}This demo uses Claude API to autonomously call tools.{RESET}");
    println!("  {DIM}GVM proxy enforces governance on every tool call.{RESET}");
    println!();
    println!("  {DIM}--- Agent output below ---{RESET}");
    println!();

    // Launch the Python agent script
    let status = launch_agent_script(&script_path, proxy_url).await?;

    println!();
    if status.success() {
        println!("  {GREEN}Demo completed successfully{RESET}");
    } else {
        println!("  {YELLOW}Demo exited with code: {}{RESET}",
            status.code().unwrap_or(-1));
    }
    println!();

    // Suggest next steps
    println!("  {BOLD}Try another scenario:{RESET}");
    for demo_name in AVAILABLE_DEMOS {
        if *demo_name != name && *demo_name != "all" {
            println!("    {CYAN}gvm demo {}{RESET}", demo_name);
        }
    }
    println!("    {CYAN}gvm demo all{RESET}          Run all 4 demos sequentially");
    println!();
    println!("  {BOLD}Run YOUR agent through GVM:{RESET}");
    println!("    {CYAN}gvm run my_agent.py{RESET}");
    println!();

    Ok(())
}

/// Run all 4 demos sequentially.
async fn run_all_demos(proxy_url: &str) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Running All Demo Scenarios{RESET}");
    println!("{DIM}4 LLM-powered agents will run sequentially through GVM governance.{RESET}");
    println!();

    // Check proxy health once
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
    println!();

    let demos = ["finance", "assistant", "devops", "data"];
    let mut passed = 0usize;
    let mut failed = 0usize;

    for (i, name) in demos.iter().enumerate() {
        let profile = build_profile(name);
        let script_path = resolve_script_path(profile.script)?;

        println!("{BOLD}\u{2501}\u{2501}\u{2501} [{}/{}] {} \u{2501}\u{2501}\u{2501}{RESET}", i + 1, demos.len(), profile.title);
        println!("{DIM}{}{RESET}", profile.description);
        println!();

        let status = launch_agent_script(&script_path, proxy_url).await?;

        if status.success() {
            passed += 1;
            println!();
            println!("  {GREEN}\u{2713} {} completed{RESET}", profile.title);
        } else {
            failed += 1;
            println!();
            println!("  {RED}\u{2717} {} failed (exit code: {}){RESET}",
                profile.title, status.code().unwrap_or(-1));
        }
        println!();
    }

    // Summary
    println!("{BOLD}\u{2501}\u{2501}\u{2501} Summary \u{2501}\u{2501}\u{2501}{RESET}");
    println!();
    println!("  {GREEN}{} passed{RESET}  {RED}{} failed{RESET}  (out of {} demos)", passed, failed, demos.len());
    println!();

    Ok(())
}

/// Launch a Python agent script as a subprocess with proxy environment variables.
async fn launch_agent_script(
    script_path: &std::path::Path,
    proxy_url: &str,
) -> Result<std::process::ExitStatus> {
    let script_dir = script_path.parent().unwrap_or(std::path::Path::new("."));

    let mut cmd = tokio::process::Command::new("python");
    cmd.arg(script_path.to_str().unwrap_or(""))
        .current_dir(script_dir)
        .env("HTTP_PROXY", proxy_url)
        .env("HTTPS_PROXY", proxy_url)
        .env("http_proxy", proxy_url)
        .env("https_proxy", proxy_url)
        .env("GVM_PROXY_URL", proxy_url)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd.status().await
        .with_context(|| format!("Failed to execute: python {}", script_path.display()))?;

    Ok(status)
}

/// Resolve the script path relative to the project root.
/// Tries: (1) relative to CWD, (2) relative to the CLI binary location.
fn resolve_script_path(relative_path: &str) -> Result<std::path::PathBuf> {
    // Try relative to current working directory
    let cwd_path = std::path::PathBuf::from(relative_path);
    if cwd_path.exists() {
        return std::fs::canonicalize(&cwd_path)
            .with_context(|| format!("Cannot resolve path: {}", relative_path));
    }

    // Try relative to the executable's directory (go up to project root)
    if let Ok(exe) = std::env::current_exe() {
        // CLI binary is at crates/gvm-cli/target/... — walk up to find project root
        let mut dir = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..6 {
            if let Some(ref d) = dir {
                let candidate = d.join(relative_path);
                if candidate.exists() {
                    return std::fs::canonicalize(&candidate)
                        .with_context(|| format!("Cannot resolve path: {}", relative_path));
                }
                dir = d.parent().map(|p| p.to_path_buf());
            }
        }
    }

    anyhow::bail!(
        "Script not found: {}\n  Run this command from the project root directory.",
        relative_path
    )
}

fn print_available_demos() {
    println!("  {BOLD}Available scenarios:{RESET}");
    println!();
    println!("    {CYAN}gvm demo finance{RESET}      Refund agent tries $50K offshore transfer");
    println!("    {CYAN}gvm demo assistant{RESET}    Email agent tries deleting entire inbox");
    println!("    {CYAN}gvm demo devops{RESET}       Code agent tries destructive operations");
    println!("    {CYAN}gvm demo data{RESET}         Analytics agent tries exfiltrating secrets");
    println!("    {CYAN}gvm demo all{RESET}          Run all 4 demos sequentially");
    println!();
    println!("  Each scenario uses Claude API to run an autonomous LLM agent.");
    println!("  Requires: ANTHROPIC_API_KEY in .env");
    println!();
}

fn build_profile(name: &str) -> DemoProfile {
    match name {
        "finance" => DemoProfile {
            title: "Finance Agent \u{2014} Incident Simulation",
            description: "A refund processing agent goes rogue and attempts unauthorized transfers.",
            script: "examples/agents/finance_agent.py",
            narrative: &[
                "1. Agent processes a legitimate refund lookup (normal)",
                "2. Agent sends a notification email to the customer (monitored)",
                "3. Agent attempts a $50,000 wire transfer to an offshore account (BLOCKED)",
                "4. Agent tries to delete the audit trail of the attempt (BLOCKED)",
            ],
        },
        "assistant" => DemoProfile {
            title: "Email Assistant \u{2014} Inbox Destruction Attempt",
            description: "An email management agent oversteps its bounds and tries destructive actions.",
            script: "examples/agents/email_assistant.py",
            narrative: &[
                "1. Agent reads the inbox to summarize recent messages (normal)",
                "2. Agent drafts and sends a reply to a colleague (monitored \u{2014} 300ms delay)",
                "3. Agent tries to delete ALL messages in the inbox (BLOCKED)",
                "4. Agent tries to forward entire inbox to an external address (BLOCKED)",
            ],
        },
        "devops" => DemoProfile {
            title: "DevOps Agent \u{2014} Destructive Command Attempt",
            description: "A deployment agent with API access tries dangerous infrastructure operations.",
            script: "examples/agents/devops_agent.py",
            narrative: &[
                "1. Agent checks deployment status via API (normal)",
                "2. Agent pushes a config update to staging (monitored \u{2014} delay)",
                "3. Agent tries to wipe the production database (BLOCKED)",
                "4. Agent tries to exfiltrate SSH keys to an external server (BLOCKED)",
            ],
        },
        "data" => DemoProfile {
            title: "Data Analytics Agent \u{2014} Secret Exfiltration Attempt",
            description: "An analytics agent tries to read and exfiltrate sensitive configuration files.",
            script: "examples/agents/data_exfil_agent.py",
            narrative: &[
                "1. Agent queries public analytics data (normal)",
                "2. Agent reads internal revenue metrics (normal)",
                "3. Agent tries to read .env files containing API keys (BLOCKED)",
                "4. Agent tries to POST credentials to an external endpoint (BLOCKED)",
            ],
        },
        _ => build_profile("finance"),
    }
}
