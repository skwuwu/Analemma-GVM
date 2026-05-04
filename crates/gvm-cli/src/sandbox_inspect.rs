//! `gvm sandbox list` and `gvm sandbox inspect` (CA-7).
//!
//! Operator-facing view of the proxy's `CARegistry`: which sandboxes
//! are currently active, which agent is in each one, what CA pubkey
//! hash is governing their TLS, and which `gvm.sandbox.launch` event
//! anchors them in the audit chain.
//!
//! Calls `GET /gvm/sandbox` on the admin port (proxy_port + 1010).
//! The endpoint is admin-only because listing active sandboxes leaks
//! identity + fingerprint information that an agent should not be
//! able to enumerate about its peers.

use anyhow::{Context, Result};

use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// Single sandbox entry as returned by `GET /gvm/sandbox`.
/// Mirrors the JSON shape constructed in `gvm-proxy::api::sandbox_list`.
#[derive(Debug, Clone)]
struct SandboxRow {
    sandbox_id: String,
    agent_id: String,
    ca_pubkey_hash: String,
    launch_event_id: String,
    launched_at: String,
    ca_not_after: String,
}

/// Pure parser for the list endpoint's response body — extracted so
/// it can be unit-tested without a running proxy.
fn parse_list_response(body: &serde_json::Value) -> Result<Vec<SandboxRow>> {
    let arr = body
        .get("sandboxes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Missing `sandboxes` array in list response"))?;

    let mut rows = Vec::with_capacity(arr.len());
    for entry in arr {
        let sandbox_id = entry
            .get("sandbox_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let agent_id = entry
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let ca_pubkey_hash = entry
            .get("ca_pubkey_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let launch_event_id = entry
            .get("launch_event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let launched_at = entry
            .get("launched_at")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let ca_not_after = entry
            .get("ca_not_after")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        rows.push(SandboxRow {
            sandbox_id,
            agent_id,
            ca_pubkey_hash,
            launch_event_id,
            launched_at,
            ca_not_after,
        });
    }
    Ok(rows)
}

async fn fetch_list(proxy: &str) -> Result<(serde_json::Value, Vec<SandboxRow>)> {
    let admin_url = crate::run::derive_admin_url(proxy);
    let url = format!("{}/gvm/sandbox", admin_url.trim_end_matches('/'));
    let resp = reqwest::get(&url)
        .await
        .with_context(|| format!("GET {} failed (is the proxy running?)", url))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Sandbox list endpoint returned HTTP {} — {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .context("Sandbox list response is not valid JSON")?;
    let rows = parse_list_response(&json)?;
    Ok((json, rows))
}

pub(crate) async fn run_list(proxy: &str, emit_json: bool) -> Result<()> {
    let (raw, rows) = fetch_list(proxy).await?;

    if emit_json {
        // For machine consumers — pass the proxy's response through
        // unchanged so format drift is detectable downstream.
        println!("{}", serde_json::to_string_pretty(&raw)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!();
        println!("  {DIM}No active sandboxes.{RESET}");
        println!("  {DIM}Hint:{RESET} {CYAN}gvm run --sandbox --agent-id <id> -- <agent>{RESET}");
        return Ok(());
    }

    println!();
    println!("  {BOLD}Active sandboxes ({}){RESET}", rows.len());
    println!();
    println!(
        "  {DIM}{:<14} {:<18} {:<18} {:<32}{RESET}",
        "SANDBOX_ID", "AGENT_ID", "CA_FINGERPRINT", "LAUNCH_EVENT_ID"
    );
    for row in &rows {
        // Truncate ids/hashes to 12-16 chars so the table fits in 80
        // cols. Full values are available via `gvm sandbox inspect`.
        println!(
            "  {GREEN}{:<14}{RESET} {:<18} {YELLOW}{:<18}{RESET} {DIM}{:<32}{RESET}",
            truncate(&row.sandbox_id, 12),
            truncate(&row.agent_id, 16),
            truncate(&row.ca_pubkey_hash, 16),
            truncate(&row.launch_event_id, 30),
        );
    }
    println!();
    println!("  {DIM}For full details:{RESET} {CYAN}gvm sandbox inspect <SANDBOX_ID>{RESET}");
    Ok(())
}

pub(crate) async fn run_inspect(proxy: &str, sandbox_id: &str) -> Result<()> {
    let (_, rows) = fetch_list(proxy).await?;
    // Match by exact id OR by prefix (for `gvm sandbox inspect <first 8 chars>`).
    // Prefix matching keeps ids tractable from the table view.
    let matches: Vec<_> = rows
        .iter()
        .filter(|r| r.sandbox_id == sandbox_id || r.sandbox_id.starts_with(sandbox_id))
        .collect();

    match matches.len() {
        0 => {
            println!();
            println!("  {RED}No sandbox matches `{}`.{RESET}", sandbox_id);
            println!("  {DIM}List active sandboxes with:{RESET} {CYAN}gvm sandbox list{RESET}");
            anyhow::bail!("sandbox not found")
        }
        1 => {
            let row = matches[0];
            println!();
            println!("  {BOLD}Sandbox {}{RESET}", row.sandbox_id);
            println!();
            print_field("sandbox_id", &row.sandbox_id);
            print_field("agent_id", &row.agent_id);
            print_field("ca_pubkey_hash", &row.ca_pubkey_hash);
            print_field("launch_event_id", &row.launch_event_id);
            print_field("launched_at", &row.launched_at);
            print_field("ca_not_after", &row.ca_not_after);
            println!();
            println!("  {DIM}Verify launch event in audit chain:{RESET}");
            println!(
                "    {CYAN}gvm proof event {} --wal data/wal.log{RESET}",
                row.launch_event_id
            );
            Ok(())
        }
        n => {
            // Prefix match was ambiguous.
            println!();
            println!(
                "  {YELLOW}Prefix `{}` matches {} sandboxes — be more specific:{RESET}",
                sandbox_id, n
            );
            for row in &matches {
                println!(
                    "    {CYAN}{}{RESET} (agent={})",
                    row.sandbox_id, row.agent_id
                );
            }
            anyhow::bail!("ambiguous sandbox id prefix")
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn print_field(key: &str, value: &str) {
    println!("    {DIM}{:<18}{RESET} {}", key, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_response_extracts_all_fields() {
        let body = serde_json::json!({
            "active": 2,
            "sandboxes": [
                {
                    "sandbox_id": "sb-aaaaaaaa-1111",
                    "agent_id": "analyst",
                    "ca_pubkey_hash": "deadbeef00112233",
                    "launch_event_id": "evt-xxx",
                    "launched_at": "2026-05-05T08:00:00Z",
                    "ca_not_after": "2026-05-05T16:00:00 +00:00:00"
                },
                {
                    "sandbox_id": "sb-bbbbbbbb-2222",
                    "agent_id": "coder-1",
                    "ca_pubkey_hash": "cafebabe44556677",
                    "launch_event_id": "evt-yyy",
                    "launched_at": "2026-05-05T09:00:00Z",
                    "ca_not_after": "2026-05-05T17:00:00 +00:00:00"
                }
            ]
        });
        let rows = parse_list_response(&body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].sandbox_id, "sb-aaaaaaaa-1111");
        assert_eq!(rows[0].agent_id, "analyst");
        assert_eq!(rows[0].ca_pubkey_hash, "deadbeef00112233");
        assert_eq!(rows[1].agent_id, "coder-1");
    }

    #[test]
    fn parse_list_response_handles_empty_array() {
        let body = serde_json::json!({"active": 0, "sandboxes": []});
        let rows = parse_list_response(&body).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_list_response_missing_array_errors() {
        // Defensive: if the proxy schema changes and drops the
        // outer key, fail loudly instead of silently showing 0
        // sandboxes (which would mislead an operator into thinking
        // their fleet is idle).
        let body = serde_json::json!({"some_other_field": []});
        let err = parse_list_response(&body).expect_err("must surface schema break");
        assert!(err.to_string().to_lowercase().contains("sandboxes"));
    }

    #[test]
    fn parse_list_response_uses_unknown_for_missing_optional_fields() {
        let body = serde_json::json!({
            "sandboxes": [
                {"sandbox_id": "sb-min"}
            ]
        });
        let rows = parse_list_response(&body).unwrap();
        assert_eq!(rows[0].sandbox_id, "sb-min");
        assert_eq!(rows[0].agent_id, "unknown");
        assert_eq!(rows[0].ca_pubkey_hash, "unknown");
        assert_eq!(rows[0].launch_event_id, "unknown");
    }

    #[test]
    fn truncate_does_not_split_inside_a_char() {
        // Korean / wide chars: 1 char in count but multi-byte. We
        // compare by `chars().count()` so the truncation never
        // produces invalid UTF-8.
        let s = "에이전트-한국어"; // 8 chars
        assert_eq!(truncate(s, 10), "에이전트-한국어");
        let trunc = truncate(s, 5);
        assert_eq!(trunc.chars().count(), 5);
        assert!(trunc.ends_with('…'));
    }
}
