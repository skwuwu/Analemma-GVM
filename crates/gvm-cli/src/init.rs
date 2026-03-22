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

    // Copy operation_registry.toml from template if it exists, otherwise leave existing
    let registry_src = template_dir.join("operation_registry.toml");
    let registry_dst = config_path.join("operation_registry.toml");
    if registry_src.exists() {
        if registry_dst.exists() {
            let backup = registry_dst.with_extension("toml.bak");
            std::fs::copy(&registry_dst, &backup)?;
            println!(
                "  {YELLOW}\u{21bb}{RESET}  {:<30} {DIM}(backed up to .bak){RESET}",
                "operation_registry.toml",
            );
        } else {
            println!("  {GREEN}\u{2713}{RESET}  operation_registry.toml");
        }
        std::fs::copy(&registry_src, &registry_dst)?;
        copied += 1;
    } else if !registry_dst.exists() {
        println!(
            "  {DIM}skip{RESET}  operation_registry.toml {DIM}(using default from repo){RESET}"
        );
    }

    // Ensure secrets.toml exists (don't overwrite — user's credentials)
    let secrets_dst = config_path.join("secrets.toml");
    if !secrets_dst.exists() {
        let secrets_example = template_dir
            .parent()
            .and_then(|p| p.parent())
            .map(|root| root.join("secrets.toml.example"));

        if let Some(ref example) = secrets_example {
            if example.exists() {
                std::fs::copy(example, &secrets_dst)?;
                println!("  {GREEN}\u{2713}{RESET}  secrets.toml {DIM}(from template — add your API keys){RESET}");
                copied += 1;
            }
        }

        if !secrets_dst.exists() {
            // Create minimal empty secrets
            std::fs::write(
                &secrets_dst,
                "# API credentials — see secrets.toml.example for format\n",
            )?;
            println!(
                "  {GREEN}\u{2713}{RESET}  secrets.toml {DIM}(empty — add API keys later){RESET}"
            );
            copied += 1;
        }
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
    println!(
        "    1. Add API keys:    {CYAN}edit {}/secrets.toml{RESET}",
        config_dir
    );
    println!("    2. Start proxy:     {CYAN}cargo run{RESET}");
    println!("    3. Point agent:     {CYAN}HTTP_PROXY=http://localhost:8080{RESET}");
    println!();

    Ok(())
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
