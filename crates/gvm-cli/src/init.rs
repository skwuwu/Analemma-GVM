use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Known industry templates (shipped with the repo)
const INDUSTRIES: &[&str] = &["finance", "saas"];

/// Template files to copy from template directory into config/
const TEMPLATE_FILES: &[&str] = &["proxy.toml", "srr_network.toml", "policies/global.toml"];

/// Run `gvm init` — apply an industry template over the existing config.
pub fn run_init(industry: &str, config_dir: &str) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM — Configuration Init{RESET}");
    println!();

    // Validate industry
    if !INDUSTRIES.contains(&industry) {
        println!("  {RED}Unknown industry: {}{RESET}", industry);
        println!();
        println!("  Available templates:");
        for ind in INDUSTRIES {
            println!("    {CYAN}gvm init --industry {}{RESET}", ind);
        }
        println!();
        return Ok(());
    }

    let config_path = Path::new(config_dir);
    let template_dir = find_template_dir(industry)?;

    println!("  {DIM}Industry:{RESET}     {CYAN}{}{RESET}", industry);
    println!("  {DIM}Template:{RESET}     {}", template_dir.display());
    println!("  {DIM}Target:{RESET}       {}", config_path.display());
    println!();

    // Ensure config directory exists
    std::fs::create_dir_all(config_path)
        .with_context(|| format!("Failed to create {}", config_path.display()))?;
    std::fs::create_dir_all(config_path.join("policies"))
        .with_context(|| "Failed to create config/policies/")?;

    // Copy template files
    let mut copied = 0;
    for file in TEMPLATE_FILES {
        let src = template_dir.join(file);
        let dst = config_path.join(file);

        if !src.exists() {
            println!("  {DIM}skip{RESET}  {} {DIM}(not in template){RESET}", file);
            continue;
        }

        // Check if destination exists
        if dst.exists() {
            let backup = dst.with_extension("toml.bak");
            std::fs::copy(&dst, &backup)?;
            println!(
                "  {YELLOW}\u{21bb}{RESET}  {:<30} {DIM}(backed up to .bak){RESET}",
                file,
            );
        } else {
            println!("  {GREEN}\u{2713}{RESET}  {}", file);
        }

        std::fs::copy(&src, &dst).with_context(|| format!("Failed to copy {}", file))?;
        copied += 1;
    }

    // Generate gvm.toml template (unified config) in project root
    let gvm_toml_dst = Path::new("gvm.toml");
    if !gvm_toml_dst.exists() {
        let gvm_template = generate_gvm_toml_template(industry);
        std::fs::write(gvm_toml_dst, gvm_template)?;
        println!("  {GREEN}\u{2713}{RESET}  gvm.toml {DIM}(unified config — add API keys here){RESET}");
        copied += 1;
    } else {
        println!("  {DIM}skip{RESET}  gvm.toml {DIM}(already exists — not overwriting){RESET}");
    }

    // Legacy: ensure secrets.toml exists for backward compatibility
    let secrets_dst = config_path.join("secrets.toml");
    if !secrets_dst.exists() {
        std::fs::write(
            &secrets_dst,
            "# Legacy credentials file. Prefer gvm.toml [credentials] section instead.\n",
        )?;
        println!(
            "  {GREEN}\u{2713}{RESET}  secrets.toml {DIM}(legacy — prefer gvm.toml){RESET}"
        );
        copied += 1;
    } else {
        println!("  {DIM}skip{RESET}  secrets.toml {DIM}(already exists — not overwriting credentials){RESET}");
    }

    println!();
    println!("  {GREEN}{BOLD}{} files applied.{RESET}", copied);
    println!();

    // Show what the template enables
    match industry {
        "finance" => {
            println!("  {BOLD}Finance template enables:{RESET}");
            println!("    \u{2022} Wire transfers blocked by SRR (api.bank.com, *.stripe.com)");
            println!("    \u{2022} All payments require IC-3 approval");
            println!("    \u{2022} Critical data deletion unconditionally denied");
            println!("    \u{2022} 500ms review window for customer-facing operations");
            println!("    \u{2022} Financial operation registry (gvm.payment.*, gvm.account.*)");
        }
        "saas" => {
            println!("  {BOLD}SaaS template enables:{RESET}");
            println!("    \u{2022} Default-to-Caution (300ms delay for unknown APIs)");
            println!("    \u{2022} Email/Slack operations monitored with audit trail");
            println!("    \u{2022} Critical storage deletions blocked");
            println!("    \u{2022} Balanced security-performance tradeoff");
        }
        _ => {}
    }

    println!();
    println!("  {BOLD}Next steps:{RESET}");
    println!("    1. Add API keys:    {CYAN}edit gvm.toml{RESET}");
    println!("    2. Start proxy:     {CYAN}cargo run{RESET}");
    println!("    3. Point agent:     {CYAN}HTTP_PROXY=http://localhost:8080{RESET}");
    println!();

    Ok(())
}

/// Generate a gvm.toml template for the given industry.
fn generate_gvm_toml_template(industry: &str) -> String {
    match industry {
        "finance" => r#"# Analemma GVM — Unified Configuration (Finance template)
# All governance rules, credentials, and settings in one file.

# ─── Network Rules (SRR) ───
# Rules are evaluated in order (first match wins).
# decision.type: Allow, Delay, Deny, RequireApproval

[[rules]]
method = "POST"
pattern = "api.bank.com/v1/transfers"
description = "Wire transfers require human approval"
[rules.decision]
type = "RequireApproval"
reason = "Financial transfer requires IC-3 approval"

[[rules]]
method = "DELETE"
pattern = "*.database.com/*"
description = "Critical data deletion blocked"
[rules.decision]
type = "Deny"
reason = "Data deletion prohibited by governance policy"

[[rules]]
method = "POST"
pattern = "*.stripe.com/v1/charges"
description = "Payment charges require approval"
[rules.decision]
type = "RequireApproval"
reason = "Payment operation requires IC-3 approval"

[[rules]]
method = "*"
pattern = "{any}"
description = "Default-to-Caution: delay unrecognized APIs"
[rules.decision]
type = "Delay"
milliseconds = 500

# ─── API Credentials ───
# Keys are injected by the proxy post-enforcement. Agent never sees real keys.

# [credentials."api.stripe.com"]
# type = "Bearer"
# token = "sk_live_your_stripe_key_here"

# [credentials."api.openai.com"]
# type = "Bearer"
# token = "sk-your-openai-key-here"

# ─── Budget ───
[budget]
max_tokens_per_hour = 50000
max_cost_per_hour = 5.00
reserve_per_request = 500

# ─── Filesystem Governance ───
# [filesystem]
# auto_merge = ["*.csv", "*.pdf", "*.txt"]
# manual_commit = ["*.sh", "*.py", "*.js", "*.json"]
# discard = ["/tmp/*", "*.log", "__pycache__/*"]
# default = "manual_commit"
# upper_size_mb = 256

# ─── Seccomp ───
[seccomp]
profile = "default"
"#
        .to_string(),

        "saas" | _ => r#"# Analemma GVM — Unified Configuration (SaaS template)
# All governance rules, credentials, and settings in one file.

# ─── Network Rules (SRR) ───
# Rules are evaluated in order (first match wins).
# decision.type: Allow, Delay, Deny, RequireApproval

[[rules]]
method = "POST"
pattern = "api.sendgrid.com/v3/mail/send"
description = "Email sending monitored"
[rules.decision]
type = "Delay"
milliseconds = 200

[[rules]]
method = "POST"
pattern = "api.slack.com/api/chat.postMessage"
description = "Slack messages monitored"
[rules.decision]
type = "Delay"
milliseconds = 100

[[rules]]
method = "DELETE"
pattern = "*.database.com/*"
description = "Database deletions blocked"
[rules.decision]
type = "Deny"
reason = "Storage deletion prohibited by governance policy"

[[rules]]
method = "GET"
pattern = "{any}"
description = "Read operations allowed"
[rules.decision]
type = "Allow"

[[rules]]
method = "*"
pattern = "{any}"
description = "Default-to-Caution: delay unrecognized APIs"
[rules.decision]
type = "Delay"
milliseconds = 300

# ─── API Credentials ───
# Keys are injected by the proxy post-enforcement. Agent never sees real keys.

# [credentials."api.openai.com"]
# type = "Bearer"
# token = "sk-your-openai-key-here"

# [credentials."api.anthropic.com"]
# type = "Bearer"
# token = "sk-ant-your-anthropic-key-here"

# ─── Budget ───
[budget]
max_tokens_per_hour = 100000
max_cost_per_hour = 10.00
reserve_per_request = 500

# ─── Filesystem Governance ───
# [filesystem]
# auto_merge = ["*.csv", "*.pdf", "*.txt"]
# manual_commit = ["*.sh", "*.py", "*.js", "*.json"]
# discard = ["/tmp/*", "*.log", "__pycache__/*"]
# default = "manual_commit"
# upper_size_mb = 256

# ─── Seccomp ───
[seccomp]
profile = "default"
"#
        .to_string(),
    }
}

/// Find the template directory — checks relative to CWD and common install paths.
fn find_template_dir(industry: &str) -> Result<PathBuf> {
    let candidates = [
        format!("config/templates/{}", industry),
        format!("../config/templates/{}", industry),
    ];

    for candidate in &candidates {
        let path = Path::new(candidate);
        if path.exists() && path.is_dir() {
            return Ok(path.to_path_buf());
        }
    }

    anyhow::bail!(
        "Template directory not found for industry '{}'. \
         Expected config/templates/{}/. \
         Make sure you're running from the Analemma-GVM repo root.",
        industry,
        industry
    )
}
