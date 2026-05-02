//! `gvm proof` — compact, redactable, single-anchor proof export and
//! verification. Phase 4.
//!
//! Three subcommands:
//!   - `gvm proof event <event_id> --wal <path> [--redaction <level>]
//!     [--out <file>]` — produce a single-event proof.
//!   - `gvm proof batch <batch_id> --wal <path> [--redaction <level>]
//!     [--out <file>]` — produce a whole-batch proof.
//!   - `gvm proof verify <proof.json>` — offline-verify a proof and
//!     print a per-layer pass/fail report.
//!
//! All commands are read-only on the WAL.

use anyhow::{Context, Result};
use gvm_types::RedactionLevel;

fn parse_redaction(s: &str) -> Result<RedactionLevel> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(RedactionLevel::None),
        "standard" => Ok(RedactionLevel::Standard),
        "strict" => Ok(RedactionLevel::Strict),
        other => anyhow::bail!(
            "unknown redaction level '{}'. expected one of: none, standard, strict",
            other
        ),
    }
}

fn write_or_print(json: &str, out: Option<&str>) -> Result<()> {
    match out {
        Some(path) => {
            std::fs::write(path, json).with_context(|| format!("failed to write proof to {}", path))?;
            eprintln!("Wrote proof to {}", path);
        }
        None => {
            println!("{}", json);
        }
    }
    Ok(())
}

pub fn build_event_proof(
    wal_file: &str,
    event_id: &str,
    redaction: &str,
    out: Option<&str>,
) -> Result<()> {
    let level = parse_redaction(redaction)?;
    let proof = gvm_types::proof::build_proof(std::path::Path::new(wal_file), event_id, level)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let json = serde_json::to_string_pretty(&proof)?;
    write_or_print(&json, out)
}

pub fn build_batch_proof(
    wal_file: &str,
    batch_id: u64,
    redaction: &str,
    out: Option<&str>,
) -> Result<()> {
    let level = parse_redaction(redaction)?;
    let proof = gvm_types::proof::build_batch_proof(
        std::path::Path::new(wal_file),
        batch_id,
        level,
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    let json = serde_json::to_string_pretty(&proof)?;
    write_or_print(&json, out)
}

pub fn verify_event_proof(proof_path: &str) -> Result<()> {
    let json = std::fs::read_to_string(proof_path)
        .with_context(|| format!("failed to read proof from {}", proof_path))?;
    let proof: gvm_types::GvmProof =
        serde_json::from_str(&json).context("failed to parse GvmProof JSON")?;

    // No signature verifier supplied — anchor signature layer reports
    // None (not checked). Operators who need signature verification
    // can extend this CLI with --keys later (Phase 6 follow-up).
    let report = gvm_types::verify_proof(&proof, None);

    println!("Proof verification report — {}", proof_path);
    println!("{}", "-".repeat(50));
    println!("  Event hash recompute:        {}", layer(report.event_hash_valid));
    println!("  WAL Merkle inclusion:        {}", layer(report.wal_inclusion_valid));
    println!("  Batch root in anchor:        {}", layer(report.batch_root_in_anchor));
    println!("  Anchor self-hash:            {}", layer(report.anchor_self_hash_valid));
    println!("  Seal hash in batch root:     {}", layer(report.seal_in_batch_root));
    println!("  Config short chain:          {}", layer(report.config_chain_valid));
    println!("  Config chain anchored:       {}", layer(report.config_chain_anchored));
    print!("  Anchor signature:            ");
    match report.anchor_signature_valid {
        Some(true) => println!("PASS"),
        Some(false) => println!("FAIL"),
        None => println!("not checked (no key supplied)"),
    }
    println!();
    if report.all_pass {
        println!("OK: every layer passed.");
    } else {
        println!("FAIL: at least one layer did not validate.");
        std::process::exit(2);
    }
    Ok(())
}

fn layer(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}
