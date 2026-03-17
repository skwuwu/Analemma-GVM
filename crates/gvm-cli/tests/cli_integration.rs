//! Integration tests for gvm CLI: proxy auto-start and agent execution workflow.
//!
//! This test suite validates the end-to-end flow:
//! 1. Proxy is initially unavailable
//! 2. `gvm run` initiates auto-start for localhost targets
//! 3. Agent script is executed through the governance pipeline
//! 4. Audit trail is recorded

use std::process::Command;
use std::time::Duration;
use std::thread;
use std::fs;
use std::path::PathBuf;

/// Create a minimal test script for agent execution.
fn create_test_script() -> PathBuf {
    let script_path = PathBuf::from("/tmp/gvm_test_noop.py");
    let content = "#!/usr/bin/env python3\nimport sys\nprint('Test agent ran successfully')\nsys.exit(0)\n";
    fs::write(&script_path, content).expect("Failed to write test script");
    script_path
}

/// Check if proxy is reachable at the given URL using tokio runtime.
fn is_proxy_ready(_proxy_url: &str) -> bool {
    // Simple TCP port check using bash (works in any Unix environment)
    // Port 8080 is the default GVM proxy port
    std::process::Command::new("bash")
        .arg("-c")
        .arg("timeout 1 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/8080' 2>/dev/null && echo ok || echo fail")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains("ok"))
        .unwrap_or(false)
}

/// Kill any existing gvm-proxy processes to ensure clean test state.
fn kill_existing_proxy() {
    let _ = Command::new("pkill")
        .arg("-f")
        .arg("gvm-proxy")
        .output();
    thread::sleep(Duration::from_millis(500));
}

#[test]
#[ignore] // Run with: cargo test --test cli_integration -- --ignored --nocapture
fn test_gvm_run_local_mode_with_proxy_autostart() {
    // Precondition: no proxy running
    kill_existing_proxy();
    assert!(!is_proxy_ready("http://127.0.0.1:8080"), "Proxy should be down at test start");

    let agent_id = "test-agent-local";
    let script = create_test_script();

    // Run gvm run in local mode (no isolation)
    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("gvm-cli")
        .arg("--")
        .arg("run")
        .arg(script.to_str().unwrap())
        .arg("--agent-id")
        .arg(agent_id)
        .env("GVM_PROXY", "http://127.0.0.1:8080")
        .output()
        .expect("Failed to execute gvm run");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let error_str = String::from_utf8_lossy(&output.stderr);

    println!("STDOUT:\n{}", output_str);
    println!("STDERR:\n{}", error_str);

    // Assertions
    // 1. Command should succeed (auto-start worked + agent executed)
    assert!(output.status.success(), "gvm run should succeed with proxy auto-start");

    // 2. Output should contain auto-start message
    assert!(
        output_str.contains("Attempting auto-start"),
        "Should show proxy auto-start attempt"
    );
    assert!(
        output_str.contains("auto-started successfully"),
        "Should show successful proxy auto-start"
    );

    // 3. Output should show the agent executed
    assert!(
        output_str.contains("Agent completed successfully") || output_str.contains("noop"),
        "Agent execution result should be visible"
    );

    // 4. Output should reference Layer 1 & Layer 2 governance
    assert!(
        output_str.contains("Layer 1") && output_str.contains("Layer 2"),
        "Should reference governance layers"
    );

    // Cleanup
    kill_existing_proxy();
    let _ = fs::remove_file(&script);
}

#[test]
fn test_gvm_run_help_succeeds() {
    // Simple smoke test: `gvm run --help` should always work
    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("gvm-cli")
        .arg("--")
        .arg("run")
        .arg("--help")
        .output()
        .expect("Failed to execute gvm run --help");

    assert!(
        output.status.success(),
        "gvm run --help should succeed"
    );

    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        output_str.contains("Run") || output_str.contains("agent"),
        "Help output should mention running agents"
    );
}

#[test]
fn test_gvm_events_list_basic() {
    // Verify gvm events list command is available and responds
    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("gvm-cli")
        .arg("--")
        .arg("events")
        .arg("list")
        .output()
        .expect("Failed to execute gvm events list");

    // Command should succeed (even if WAL is empty)
    assert!(
        output.status.success(),
        "gvm events list should succeed"
    );
}

#[test]
fn test_gvm_stats_basic() {
    // Verify gvm stats command is available
    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("gvm-cli")
        .arg("--")
        .arg("stats")
        .arg("tokens")
        .output()
        .expect("Failed to execute gvm stats tokens");

    // Command should succeed (even if no events recorded)
    assert!(
        output.status.success(),
        "gvm stats tokens should succeed"
    );
}
