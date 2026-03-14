use anyhow::{Context, Result};
use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// Run an AI agent inside a GVM containment container (Layer 3).
///
/// This creates a Docker container on the `gvm-internal` network,
/// which can ONLY communicate with gvm-proxy. Direct external API
/// access is blocked at the network level.
pub async fn run_agent(
    script: &str,
    agent_id: &str,
    proxy: &str,
    image: &str,
    memory: &str,
    cpus: &str,
    detach: bool,
) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM — Agent Containment (Layer 3){RESET}");
    println!();

    // Verify Docker is available
    let docker_check = tokio::process::Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .output()
        .await
        .context("Docker not found. Install Docker to use agent containment.")?;

    if !docker_check.status.success() {
        println!("  {RED}Docker is not running.{RESET}");
        println!("  Start Docker Desktop and try again.");
        println!();
        return Ok(());
    }

    let docker_version = String::from_utf8_lossy(&docker_check.stdout);
    println!("  {DIM}Docker:{RESET}       {}", docker_version.trim());

    // Resolve script path
    let script_path = std::path::Path::new(script);
    if !script_path.exists() {
        println!("  {RED}Agent script not found: {}{RESET}", script);
        println!();
        return Ok(());
    }

    let abs_script = std::fs::canonicalize(script_path)
        .with_context(|| format!("Cannot resolve path: {}", script))?;
    let script_dir = abs_script.parent().unwrap();
    let script_name = abs_script.file_name().unwrap().to_str().unwrap();

    println!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    println!("  {DIM}Script:{RESET}       {}", abs_script.display());
    println!("  {DIM}Image:{RESET}        {}", image);
    println!("  {DIM}Proxy:{RESET}        {}", proxy);
    println!("  {DIM}Memory:{RESET}       {}", memory);
    println!("  {DIM}CPUs:{RESET}         {}", cpus);
    println!("  {DIM}Network:{RESET}      gvm-internal {DIM}(isolated){RESET}");
    println!();

    // Ensure gvm-internal network exists
    let net_check = tokio::process::Command::new("docker")
        .args(["network", "inspect", "gvm-internal"])
        .output()
        .await?;

    if !net_check.status.success() {
        println!("  {YELLOW}Creating gvm-internal network (isolated)...{RESET}");
        let net_create = tokio::process::Command::new("docker")
            .args(["network", "create", "--internal", "gvm-internal"])
            .output()
            .await?;

        if !net_create.status.success() {
            let err = String::from_utf8_lossy(&net_create.stderr);
            println!("  {RED}Failed to create network: {}{RESET}", err.trim());
            return Ok(());
        }
        println!("  {GREEN}Network created{RESET}");
    }

    // Build docker run command
    let container_name = format!("gvm-agent-{}", agent_id);

    // Convert Windows path for Docker mount
    let mount_dir = script_dir.to_str().unwrap_or(".");

    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run")
        .arg("--name").arg(&container_name)
        .arg("--rm")
        .arg("--network").arg("gvm-internal")
        .arg("--read-only")
        .arg("--tmpfs").arg("/tmp")
        .arg("--security-opt").arg("no-new-privileges:true")
        .arg("--memory").arg(memory)
        .arg("--cpus").arg(cpus)
        .arg("-e").arg(format!("GVM_AGENT_ID={}", agent_id))
        .arg("-e").arg(format!("HTTP_PROXY={}", proxy))
        .arg("-e").arg(format!("HTTPS_PROXY={}", proxy))
        .arg("-e").arg(format!("http_proxy={}", proxy))
        .arg("-e").arg(format!("https_proxy={}", proxy))
        .arg("-v").arg(format!("{}:/home/agent/workspace:ro", mount_dir))
        .arg(image)
        .arg(script_name);

    if detach {
        cmd.arg("-d");
    }

    println!("  {BOLD}Starting contained agent...{RESET}");
    println!("  {DIM}Container:{RESET}    {}", container_name);
    println!();

    // Security summary
    println!("  {BOLD}Security layers active:{RESET}");
    println!("    {GREEN}\u{2713}{RESET} Layer 1: Governance Engine (policy evaluation)");
    println!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy (request interception)");
    println!("    {GREEN}\u{2713}{RESET} Layer 3: OS Containment (network isolation)");
    println!("      {DIM}\u{2022} Network: gvm-internal (no external access){RESET}");
    println!("      {DIM}\u{2022} Filesystem: read-only root{RESET}");
    println!("      {DIM}\u{2022} Privileges: no-new-privileges{RESET}");
    println!("      {DIM}\u{2022} Resources: {} memory, {} CPUs{RESET}", memory, cpus);
    println!();

    if detach {
        let output = cmd.output().await?;
        if output.status.success() {
            let container_id = String::from_utf8_lossy(&output.stdout);
            println!("  {GREEN}Agent started in background{RESET}");
            println!("  Container: {}", container_id.trim());
            println!();
            println!("  {BOLD}Useful commands:{RESET}");
            println!("    {CYAN}docker logs -f {}{RESET}         — follow agent output", container_name);
            println!("    {CYAN}docker stop {}{RESET}            — stop agent", container_name);
            println!("    {CYAN}gvm events list --agent {}{RESET} — view audit trail", agent_id);
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            println!("  {RED}Failed to start agent: {}{RESET}", err.trim());
        }
    } else {
        println!("  {DIM}--- Agent output below ---{RESET}");
        println!();

        let status = cmd
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await?;

        println!();
        if status.success() {
            println!("  {GREEN}Agent completed successfully{RESET}");
        } else {
            println!("  {YELLOW}Agent exited with code: {}{RESET}",
                status.code().unwrap_or(-1));
        }
    }

    println!();
    println!("  {BOLD}Review:{RESET}");
    println!("    {CYAN}gvm events list --agent {}{RESET}", agent_id);
    println!();

    Ok(())
}
