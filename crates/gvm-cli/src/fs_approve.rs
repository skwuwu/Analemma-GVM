//! `gvm fs approve` — drain pending overlayfs staging directories.
//!
//! Each `gvm run --sandbox --fs-governance` session that ends with
//! `needs_review` files leaves a staging directory under
//! `data/sandbox-staging/<pid>/` plus a `manifest.json` sidecar
//! recording the original workspace destination, the agent identity,
//! and per-file metadata. This module is the only supported way to
//! drain those staging directories without re-running the sandbox.
//!
//! Without it, staging accumulates indefinitely and silently — the
//! sandbox itself never deletes a non-empty staging dir because it
//! does not know whether the operator has finished reviewing the
//! files. The four modes (interactive, accept-all, reject-all, list)
//! cover the operator workflows: TTY review, CI auto-merge, cron
//! garbage collector, and dry-run inspection.

use crate::ui::{BOLD, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

/// What `gvm fs approve` should do with each pending entry.
pub enum Mode {
    /// One y/n prompt per file. Requires a TTY.
    Interactive,
    /// Copy every staged file to its recorded workspace destination,
    /// then delete the staging directory. Non-interactive.
    AcceptAll,
    /// Delete every staging directory without copying. The disk-leak
    /// garbage collector — safe to wire into cron.
    RejectAll,
    /// Print pending batches and exit. Modifies nothing.
    List,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)] // Fields are deserialized for forward-compat; not all are read at runtime.
struct Manifest {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    pid: u32,
    workspace: String,
    #[serde(default)]
    created_at: String,
    entries: Vec<ManifestEntry>,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct ManifestEntry {
    path: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    matched_pattern: String,
}

/// Walk the staging root, find every batch with a manifest, and apply
/// the requested mode to each. Returns Ok even if individual batches
/// fail — partial progress is logged so a single corrupted batch never
/// stalls the whole drain.
pub fn run(staging_root: &Path, mode: Mode) -> Result<()> {
    if !staging_root.exists() {
        eprintln!();
        eprintln!(
            "  {DIM}No staging root at {} — nothing to drain.{RESET}",
            staging_root.display()
        );
        return Ok(());
    }

    let batches = collect_batches(staging_root)
        .with_context(|| format!("Failed to scan {}", staging_root.display()))?;

    eprintln!();
    eprintln!(
        "  {BOLD}gvm fs approve{RESET}  {DIM}({} batch(es) found){RESET}",
        batches.len()
    );
    eprintln!();

    if batches.is_empty() {
        eprintln!("  {DIM}Nothing pending. Disk is clean.{RESET}");
        eprintln!();
        return Ok(());
    }

    // Interactive mode requires a TTY. Fail loudly instead of silently
    // skipping every batch so the operator can re-run with a flag.
    if matches!(mode, Mode::Interactive) && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "Interactive mode requires a TTY. \
             Re-run with --accept-all, --reject-all, or --list."
        );
    }

    let mut total_accepted = 0usize;
    let mut total_rejected = 0usize;
    let mut total_skipped = 0usize;
    let mut batches_drained = 0usize;

    for batch in &batches {
        let header = format!(
            "  {BOLD}Batch{RESET} {} {DIM}({} file(s), workspace={}){RESET}",
            batch.staging_dir.display(),
            batch.manifest.entries.len(),
            batch.manifest.workspace,
        );
        eprintln!("{}", header);

        match &mode {
            Mode::List => {
                for e in &batch.manifest.entries {
                    eprintln!(
                        "    {DIM}{} {} ({}){RESET}",
                        e.kind,
                        e.path,
                        format_size(e.size)
                    );
                }
                eprintln!();
            }
            Mode::AcceptAll => {
                let (accepted, _rejected) = accept_batch(batch);
                total_accepted += accepted;
                if let Err(e) = std::fs::remove_dir_all(&batch.staging_dir) {
                    eprintln!("    {RED}cleanup failed: {}{RESET}", e);
                } else {
                    batches_drained += 1;
                }
            }
            Mode::RejectAll => {
                total_rejected += batch.manifest.entries.len();
                if let Err(e) = std::fs::remove_dir_all(&batch.staging_dir) {
                    eprintln!("    {RED}cleanup failed: {}{RESET}", e);
                } else {
                    batches_drained += 1;
                    eprintln!("    {RED}\u{2717}{RESET} {DIM}deleted (--reject-all){RESET}");
                }
            }
            Mode::Interactive => {
                let (accepted, rejected, skipped) = interactive_batch(batch)?;
                total_accepted += accepted;
                total_rejected += rejected;
                total_skipped += skipped;
                // Only delete the staging dir if every entry was decided.
                // A skip leaves the manifest in place so the operator can
                // come back later — same contract as the inline pipeline
                // review.
                if skipped == 0 && std::fs::remove_dir_all(&batch.staging_dir).is_ok() {
                    batches_drained += 1;
                }
            }
        }
        eprintln!();
    }

    if !matches!(mode, Mode::List) {
        eprintln!(
            "  {BOLD}Summary:{RESET} {} batch(es) drained, {} accepted, {} rejected, {} skipped",
            batches_drained, total_accepted, total_rejected, total_skipped
        );
        eprintln!();
    }

    Ok(())
}

#[derive(Debug)]
struct StagingBatch {
    staging_dir: PathBuf,
    manifest: Manifest,
}

/// Walk `staging_root` for `<pid>/manifest.json` files and load each.
/// Batches without a manifest are reported once but otherwise left
/// alone — they were either created by an older binary (no manifest
/// support) or are mid-write from a still-running sandbox.
fn collect_batches(staging_root: &Path) -> Result<Vec<StagingBatch>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(staging_root)
        .with_context(|| format!("read_dir {}", staging_root.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            eprintln!(
                "  {YELLOW}\u{26a0}{RESET} {DIM}{} has no manifest.json — \
                 skipping (run an older sandbox build, or it is mid-write){RESET}",
                path.display()
            );
            continue;
        }
        let raw = match std::fs::read_to_string(&manifest_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "  {YELLOW}\u{26a0}{RESET} {DIM}cannot read {}: {}{RESET}",
                    manifest_path.display(),
                    e
                );
                continue;
            }
        };
        let manifest: Manifest = match serde_json::from_str(&raw) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  {YELLOW}\u{26a0}{RESET} {DIM}cannot parse {}: {}{RESET}",
                    manifest_path.display(),
                    e
                );
                continue;
            }
        };
        if manifest.version != 1 {
            eprintln!(
                "  {YELLOW}\u{26a0}{RESET} {DIM}{} has manifest version {} — \
                 unsupported, skipping{RESET}",
                manifest_path.display(),
                manifest.version
            );
            continue;
        }
        out.push(StagingBatch {
            staging_dir: path,
            manifest,
        });
    }
    // Stable order so test output and operator output are deterministic.
    out.sort_by(|a, b| a.staging_dir.cmp(&b.staging_dir));
    Ok(out)
}

/// Copy every entry in a batch to its workspace destination, then
/// remove the staged source so a follow-up `gvm fs approve` cannot
/// double-process the same file (the partial-accept case).
///
/// Failures are logged but never abort the batch — the goal is to
/// leak as few files as possible, not to fail closed on the first
/// I/O hiccup. NotFound errors get a distinct message so the
/// operator can recognise the cron-GC race rather than chasing
/// a generic OS error.
fn accept_batch(batch: &StagingBatch) -> (usize, usize) {
    let workspace = PathBuf::from(&batch.manifest.workspace);
    let mut accepted = 0;
    let mut failed = 0;
    for entry in &batch.manifest.entries {
        let staged = batch.staging_dir.join(&entry.path);

        // Pre-check: if the staged file is already gone, this entry
        // was either already accepted by a previous run or removed
        // by a concurrent `--reject-all`. Either way it is not an
        // error — just skip with a clear message.
        if !staged.exists() {
            eprintln!(
                "    {DIM}\u{2014}{RESET} {} {DIM}(staged file already gone — \
                 already processed or concurrent --reject-all){RESET}",
                entry.path
            );
            continue;
        }

        let dst = workspace.join(&entry.path);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(&staged, &dst) {
            Ok(_) => {
                // Remove the staged source. Without this, a partial
                // accept would re-prompt already-accepted files on
                // the next `gvm fs approve` run.
                if let Err(_e) = std::fs::remove_file(&staged) {
                    // Best-effort: the file is already in the workspace,
                    // a leftover staged copy is harmless on the next run
                    // (the manifest will simply re-list it). Silent.
                }
                eprintln!(
                    "    {GREEN}\u{2713}{RESET} {} {DIM}\u{2192} {}{RESET}",
                    entry.path,
                    dst.display()
                );
                accepted += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Race: staged file vanished between exists() and copy().
                // Almost certainly a concurrent --reject-all or cron GC.
                eprintln!(
                    "    {YELLOW}\u{26a0}{RESET} {} {DIM}(vanished mid-copy — \
                     concurrent gvm fs approve --reject-all or cron GC?){RESET}",
                    entry.path
                );
                failed += 1;
            }
            Err(e) => {
                eprintln!(
                    "    {RED}\u{2717}{RESET} {} {DIM}({}){RESET}",
                    entry.path, e
                );
                failed += 1;
            }
        }
    }
    (accepted, failed)
}

/// Drive a TTY prompt for one batch. Returns `(accepted, rejected, skipped)`.
fn interactive_batch(batch: &StagingBatch) -> Result<(usize, usize, usize)> {
    let workspace = PathBuf::from(&batch.manifest.workspace);
    let mut accepted = 0;
    let mut rejected = 0;
    let mut skipped = 0;
    let total = batch.manifest.entries.len();

    for (i, entry) in batch.manifest.entries.iter().enumerate() {
        let staged = batch.staging_dir.join(&entry.path);
        eprintln!(
            "    {BOLD}[{}/{}]{RESET} {} ({}, {})",
            i + 1,
            total,
            entry.path,
            entry.kind,
            format_size(entry.size),
        );
        if let Some(pattern) = Some(&entry.matched_pattern).filter(|s| !s.is_empty()) {
            eprintln!("    {DIM}matched pattern: {}{RESET}", pattern);
        }

        // Preview first 10 lines of text content. Binary files just say so.
        if staged.exists() {
            if let Ok(content) = std::fs::read_to_string(&staged) {
                let mut shown = 0;
                for line in content.lines().take(10) {
                    eprintln!("    {GREEN}+{RESET}{}", line);
                    shown += 1;
                }
                let total_lines = content.lines().count();
                if total_lines > shown {
                    eprintln!("    {DIM}... ({} more line(s)){RESET}", total_lines - shown);
                }
            } else {
                eprintln!("    {DIM}(binary file){RESET}");
            }
        }

        eprintln!();
        eprint!(
            "    ({GREEN}a{RESET})ccept  ({RED}r{RESET})eject  ({DIM}s{RESET})kip rest \u{2192} "
        );
        std::io::stderr().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        match input.trim().to_lowercase().as_str() {
            "a" | "accept" | "y" | "yes" => {
                if !staged.exists() {
                    eprintln!(
                        "    {YELLOW}\u{26a0}{RESET} {} {DIM}(staged file gone — \
                         concurrent --reject-all or cron GC; skipping){RESET}",
                        entry.path
                    );
                } else {
                    let dst = workspace.join(&entry.path);
                    if let Some(parent) = dst.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::copy(&staged, &dst) {
                        Ok(_) => {
                            // Remove the staged source so a partial-accept
                            // session does not re-prompt this file on the
                            // next `gvm fs approve` run.
                            // Best-effort: leftover staged copy is harmless
                            // on the next run (manifest will re-list it).
                            let _ = std::fs::remove_file(&staged);
                            eprintln!(
                                "    {GREEN}\u{2713}{RESET} {} {DIM}\u{2192} {}{RESET}",
                                entry.path,
                                dst.display()
                            );
                            accepted += 1;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            eprintln!(
                                "    {YELLOW}\u{26a0}{RESET} {} {DIM}(vanished mid-copy \
                                 — concurrent --reject-all or cron GC){RESET}",
                                entry.path
                            );
                        }
                        Err(e) => {
                            eprintln!("    {RED}\u{2717}{RESET} copy failed: {}", e);
                        }
                    }
                }
            }
            "s" | "skip" => {
                skipped = total - i;
                eprintln!(
                    "    {DIM}Skipping remaining {} file(s) in this batch{RESET}",
                    skipped
                );
                break;
            }
            _ => {
                eprintln!(
                    "    {RED}\u{2717}{RESET} {} rejected (deleted from staging)",
                    entry.path
                );
                rejected += 1;
                let _ = std::fs::remove_file(&staged);
            }
        }
        eprintln!();
    }

    Ok((accepted, rejected, skipped))
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
