//! Trust-on-Pattern filesystem governance — scan overlayfs upper layer
//! and classify file changes by pattern for auto-merge, manual commit, or discard.
//!
//! Analogous to SRR for network traffic: file glob patterns determine
//! how agent-generated files are handled at session end.

use crate::FilesystemPolicy;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Classification of a file change in the overlayfs upper layer.
#[derive(Debug, Clone)]
pub enum FileAction {
    /// Safe output — copy to host workspace immediately.
    AutoMerge,
    /// Potentially dangerous — show in diff report, require manual approval.
    ManualCommit,
    /// Temporary artifact — do not copy to host.
    Discard,
}

/// Type of change detected in the upper layer.
#[derive(Debug, Clone)]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
}

/// A single file change with its classification.
#[derive(Debug, Clone)]
pub struct FileChange {
    /// Relative path from workspace root (e.g., "results/data.csv").
    pub path: PathBuf,
    /// What happened to the file.
    pub kind: ChangeKind,
    /// Classified action based on Trust-on-Pattern.
    pub action: FileAction,
    /// File size in bytes.
    pub size: u64,
    /// Which pattern matched (e.g., "*.csv") or "default".
    pub matched_pattern: String,
}

/// Complete diff report for a sandbox session.
#[derive(Debug)]
pub struct FsDiffReport {
    pub auto_merged: Vec<FileChange>,
    pub needs_review: Vec<FileChange>,
    pub discarded: Vec<FileChange>,
    /// Whether overlayfs was active (false = legacy mode, no diff available).
    pub overlayfs_active: bool,
}

/// Scan the overlayfs upper directory and classify all changes.
///
/// The upper directory contains only files that the agent created or modified
/// (copy-on-write semantics). Files in lower that were not touched are absent.
///
/// `lower_dir` is the original workspace for detecting Modified vs Created.
pub fn scan_upper_layer(
    upper_dir: &Path,
    lower_dir: &Path,
    policy: &FilesystemPolicy,
) -> Result<FsDiffReport> {
    let mut auto_merged = Vec::new();
    let mut needs_review = Vec::new();
    let mut discarded = Vec::new();

    if !upper_dir.exists() {
        return Ok(FsDiffReport {
            auto_merged,
            needs_review,
            discarded,
            overlayfs_active: false,
        });
    }

    scan_dir_recursive(
        upper_dir,
        upper_dir,
        lower_dir,
        policy,
        &mut auto_merged,
        &mut needs_review,
        &mut discarded,
    )?;

    Ok(FsDiffReport {
        auto_merged,
        needs_review,
        discarded,
        overlayfs_active: true,
    })
}

fn scan_dir_recursive(
    dir: &Path,
    upper_root: &Path,
    lower_root: &Path,
    policy: &FilesystemPolicy,
    auto_merged: &mut Vec<FileChange>,
    needs_review: &mut Vec<FileChange>,
    discarded: &mut Vec<FileChange>,
) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            scan_dir_recursive(
                &path, upper_root, lower_root, policy,
                auto_merged, needs_review, discarded,
            )?;
            continue;
        }

        let rel_path = path.strip_prefix(upper_root).unwrap_or(&path).to_path_buf();
        let lower_path = lower_root.join(&rel_path);

        let kind = if lower_path.exists() {
            ChangeKind::Modified
        } else {
            ChangeKind::Created
        };

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

        let (action, pattern) = classify_file(&rel_path, policy);

        let change = FileChange {
            path: rel_path,
            kind,
            action: action.clone(),
            size,
            matched_pattern: pattern,
        };

        match action {
            FileAction::AutoMerge => auto_merged.push(change),
            FileAction::ManualCommit => needs_review.push(change),
            FileAction::Discard => discarded.push(change),
        }
    }

    Ok(())
}

/// Classify a file by matching its path against Trust-on-Pattern rules.
/// First match wins (discard → manual_commit → auto_merge → default).
fn classify_file(rel_path: &Path, policy: &FilesystemPolicy) -> (FileAction, String) {
    let path_str = rel_path.to_string_lossy();

    // Check discard patterns first (highest priority — prevent junk from reaching host)
    for pattern in &policy.discard {
        if glob_match(pattern, &path_str) {
            return (FileAction::Discard, pattern.clone());
        }
    }

    // Check manual_commit patterns (security-sensitive files)
    for pattern in &policy.manual_commit {
        if glob_match(pattern, &path_str) {
            return (FileAction::ManualCommit, pattern.clone());
        }
    }

    // Check auto_merge patterns (safe outputs)
    for pattern in &policy.auto_merge {
        if glob_match(pattern, &path_str) {
            return (FileAction::AutoMerge, pattern.clone());
        }
    }

    // Default policy
    let action = match policy.default.as_str() {
        "auto_merge" => FileAction::AutoMerge,
        "discard" => FileAction::Discard,
        _ => FileAction::ManualCommit, // safe default
    };
    (action, "default".to_string())
}

/// Simple glob matching: supports `*` (any segment) and `*.ext` patterns.
/// Not a full glob implementation — covers the common Trust-on-Pattern use cases.
fn glob_match(pattern: &str, path: &str) -> bool {
    if pattern.starts_with("*.") {
        // Extension match: "*.csv" matches "results/data.csv"
        let ext = &pattern[1..]; // ".csv"
        path.ends_with(ext)
    } else if pattern.ends_with("/*") {
        // Directory prefix match: "/tmp/*" matches "/tmp/cache.dat"
        let prefix = &pattern[..pattern.len() - 1]; // "/tmp/"
        path.starts_with(prefix) || path.starts_with(&prefix[1..]) // with or without leading /
    } else if pattern.contains('*') {
        // Wildcard in middle — simple contains check
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            path.starts_with(parts[0]) && path.ends_with(parts[1])
        } else {
            false
        }
    } else {
        // Exact match
        path == pattern
    }
}

/// Auto-merge files: copy from upper layer to host workspace.
pub fn auto_merge_files(
    changes: &[FileChange],
    upper_dir: &Path,
    host_workspace: &Path,
) -> Vec<(PathBuf, Result<()>)> {
    changes
        .iter()
        .map(|change| {
            let src = upper_dir.join(&change.path);
            let dst = host_workspace.join(&change.path);
            let result = (|| -> Result<()> {
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(&src, &dst)?;
                Ok(())
            })();
            (change.path.clone(), result)
        })
        .collect()
}

/// Commit approved files: copy from upper layer to host workspace.
pub fn commit_files(
    changes: &[FileChange],
    upper_dir: &Path,
    host_workspace: &Path,
) -> Vec<(PathBuf, Result<()>)> {
    auto_merge_files(changes, upper_dir, host_workspace)
}

/// Generate a unified diff between the lower (original) and upper (modified) versions.
/// Returns None for binary files or if either version doesn't exist.
pub fn generate_diff(lower_path: &Path, upper_path: &Path) -> Option<String> {
    let lower_content = std::fs::read_to_string(lower_path).ok()?;
    let upper_content = std::fs::read_to_string(upper_path).ok()?;

    if lower_content == upper_content {
        return None;
    }

    let mut diff_output = String::new();
    let lower_lines: Vec<&str> = lower_content.lines().collect();
    let upper_lines: Vec<&str> = upper_content.lines().collect();

    diff_output.push_str(&format!("--- {}\n", lower_path.display()));
    diff_output.push_str(&format!("+++ {}\n", upper_path.display()));

    // Simple line-by-line diff (not full unified diff algorithm, but useful for review)
    let mut added = 0;
    let mut removed = 0;

    // Find removed lines (in lower but not in upper)
    for line in &lower_lines {
        if !upper_lines.contains(line) {
            diff_output.push_str(&format!("-{}\n", line));
            removed += 1;
        }
    }
    // Find added lines (in upper but not in lower)
    for line in &upper_lines {
        if !lower_lines.contains(line) {
            diff_output.push_str(&format!("+{}\n", line));
            added += 1;
        }
    }

    if added == 0 && removed == 0 {
        return None; // Whitespace-only changes
    }

    Some(diff_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_extension_match() {
        assert!(glob_match("*.csv", "results/data.csv"));
        assert!(glob_match("*.pdf", "report.pdf"));
        assert!(!glob_match("*.csv", "results/data.txt"));
    }

    #[test]
    fn glob_directory_prefix() {
        assert!(glob_match("/tmp/*", "/tmp/cache.dat"));
        assert!(glob_match("/tmp/*", "tmp/cache.dat")); // without leading /
        assert!(!glob_match("/tmp/*", "/home/data.txt"));
    }

    #[test]
    fn glob_pycache() {
        assert!(glob_match("__pycache__/*", "__pycache__/module.cpython-312.pyc"));
    }

    #[test]
    fn classify_discard_priority() {
        let policy = FilesystemPolicy::default();
        let (action, _) = classify_file(Path::new("agent.log"), &policy);
        assert!(matches!(action, FileAction::Discard));
    }

    #[test]
    fn classify_manual_commit_for_scripts() {
        let policy = FilesystemPolicy::default();
        let (action, _) = classify_file(Path::new("install.sh"), &policy);
        assert!(matches!(action, FileAction::ManualCommit));
    }

    #[test]
    fn classify_auto_merge_for_csv() {
        let policy = FilesystemPolicy::default();
        let (action, _) = classify_file(Path::new("results/data.csv"), &policy);
        assert!(matches!(action, FileAction::AutoMerge));
    }

    #[test]
    fn classify_default_for_unknown() {
        let policy = FilesystemPolicy::default();
        let (action, pattern) = classify_file(Path::new("mysterious_binary"), &policy);
        assert!(matches!(action, FileAction::ManualCommit));
        assert_eq!(pattern, "default");
    }

    #[test]
    fn classify_json_is_manual_commit() {
        // JSON can contain executable content (package.json postinstall)
        let policy = FilesystemPolicy::default();
        let (action, _) = classify_file(Path::new("package.json"), &policy);
        assert!(matches!(action, FileAction::ManualCommit));
    }
}
