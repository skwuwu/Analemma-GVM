//! Trust-on-Pattern filesystem governance — scan overlayfs upper layer
//! and classify file changes by pattern for auto-merge, manual commit, or discard.
//!
//! Analogous to SRR for network traffic: file glob patterns determine
//! how agent-generated files are handled at session end.
//!
//! Safety principles:
//! - Created files only: auto-merge only copies NEW files. Modified files
//!   always require manual approval (protects existing workspace files).
//! - Deleted (whiteout): never auto-executed. Requires --allow-delete opt-in.
//! - Symlink defense: symlinks targeting outside upper_dir are rejected.
//! - Path traversal defense: relative paths with `..` are rejected.

use crate::FilesystemPolicy;
use anyhow::{Context, Result};
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
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // ── Phase 0-B: Detect overlayfs whiteout files ──
        // Overlayfs uses character device (0, 0) as whiteout markers for deleted files.
        // Also detect opaque directory markers (.wh..wh..opq).
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_char_device() {
                // Whiteout = file was deleted by agent in upper layer
                let rel_path = path.strip_prefix(upper_root).unwrap_or(&path).to_path_buf();
                // Strip .wh. prefix if present (overlayfs naming convention)
                let display_path = rel_path.to_string_lossy()
                    .replace(".wh.", "")
                    .into();
                needs_review.push(FileChange {
                    path: display_path,
                    kind: ChangeKind::Deleted,
                    action: FileAction::ManualCommit, // Deletions always need approval
                    size: 0,
                    matched_pattern: "whiteout".to_string(),
                });
                continue;
            }
        }

        if path.is_dir() {
            // Skip opaque directory markers
            if path.file_name().map(|n| n.to_string_lossy().contains(".wh..wh..opq")).unwrap_or(false) {
                continue;
            }
            scan_dir_recursive(
                &path, upper_root, lower_root, policy,
                auto_merged, needs_review, discarded,
            )?;
            continue;
        }

        let rel_path = path.strip_prefix(upper_root).unwrap_or(&path).to_path_buf();

        // ── Phase 0-C: Path traversal defense ──
        // Reject relative paths containing ".." to prevent escape from workspace.
        let rel_str = rel_path.to_string_lossy();
        if rel_str.contains("..") {
            discarded.push(FileChange {
                path: rel_path,
                kind: ChangeKind::Created,
                action: FileAction::Discard,
                size: 0,
                matched_pattern: "path_traversal_blocked".to_string(),
            });
            continue;
        }

        // ── Phase 0-A: Symlink traversal defense ──
        // Reject symlinks that point outside the upper directory.
        // An agent could create a symlink → /etc/passwd, and auto-merge
        // would copy that file to the host workspace.
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path).unwrap_or_default();
            let resolved = path.parent().unwrap_or(upper_root).join(&target);
            let canonical = resolved.canonicalize().unwrap_or(resolved);
            if !canonical.starts_with(upper_root) {
                discarded.push(FileChange {
                    path: rel_path,
                    kind: ChangeKind::Created,
                    action: FileAction::Discard,
                    size: 0,
                    matched_pattern: "symlink_escape_blocked".to_string(),
                });
                continue;
            }
        }

        let lower_path = lower_root.join(&rel_path);

        // ── Phase 1-A: Created vs Modified classification ──
        // Modified files are ALWAYS ManualCommit regardless of pattern.
        // Only Created files can be auto-merged (new output, no overwrite risk).
        let kind = if lower_path.exists() {
            ChangeKind::Modified
        } else {
            ChangeKind::Created
        };

        let size = metadata.len();
        let (pattern_action, pattern) = classify_file(&rel_path, policy);

        // Safety override: Modified → ManualCommit always (protects existing files)
        let is_modified = matches!(kind, ChangeKind::Modified);
        let action = if is_modified {
            FileAction::ManualCommit
        } else {
            pattern_action
        };

        let change = FileChange {
            path: rel_path,
            kind,
            action: action.clone(),
            size,
            matched_pattern: if matches!(action, FileAction::ManualCommit) && is_modified {
                "modified_file".to_string()
            } else {
                pattern
            },
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

/// Auto-merge result statistics.
pub struct MergeResult {
    pub copied: Vec<PathBuf>,
    pub skipped: Vec<(PathBuf, String)>, // (path, reason)
    pub errors: Vec<(PathBuf, String)>,  // (path, error)
}

/// Execute auto-merge: copy Created+AutoMerge files from upper to host workspace.
/// Modified files are NEVER copied here (safety: protect existing workspace files).
/// Symlinks targeting outside upper_dir are rejected.
pub fn execute_merge(
    report: &FsDiffReport,
    upper_dir: &Path,
    host_workspace: &Path,
) -> MergeResult {
    let mut result = MergeResult {
        copied: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
    };

    for change in &report.auto_merged {
        // Safety: only copy Created files. Modified should not be in auto_merged
        // (scan_dir_recursive enforces this), but double-check here.
        if matches!(change.kind, ChangeKind::Modified) {
            result.skipped.push((change.path.clone(), "modified file".into()));
            continue;
        }

        let src = upper_dir.join(&change.path);
        let dst = host_workspace.join(&change.path);

        // Path traversal defense (belt-and-suspenders with scan)
        let dst_canonical = dst.parent()
            .and_then(|p| { std::fs::create_dir_all(p).ok(); p.canonicalize().ok() })
            .unwrap_or_else(|| host_workspace.to_path_buf());
        let ws_canonical = host_workspace.canonicalize()
            .unwrap_or_else(|_| host_workspace.to_path_buf());
        if !dst_canonical.starts_with(&ws_canonical) {
            result.skipped.push((change.path.clone(), "path escape blocked".into()));
            continue;
        }

        // Symlink defense: don't copy symlinks, copy their targets (if within upper)
        if src.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            result.skipped.push((change.path.clone(), "symlink rejected".into()));
            continue;
        }

        match std::fs::copy(&src, &dst) {
            Ok(_) => result.copied.push(change.path.clone()),
            Err(e) => result.errors.push((change.path.clone(), e.to_string())),
        }
    }

    result
}

/// Commit approved files: copy from upper layer to host workspace.
/// Used for ManualCommit files after user approval.
pub fn commit_files(
    changes: &[FileChange],
    upper_dir: &Path,
    host_workspace: &Path,
) -> MergeResult {
    // Create a temporary report with just these files as auto_merged
    let report = FsDiffReport {
        auto_merged: changes.to_vec(),
        needs_review: Vec::new(),
        discarded: Vec::new(),
        overlayfs_active: true,
    };
    execute_merge(&report, upper_dir, host_workspace)
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
        assert!(glob_match(
            "__pycache__/*",
            "__pycache__/module.cpython-312.pyc"
        ));
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

    /// Priority test: when a file matches patterns in multiple categories,
    /// the stricter category wins (discard > manual_commit > auto_merge).
    /// This is consistent with SRR's max_strict principle.
    #[test]
    fn priority_stricter_category_wins() {
        // Create a policy where *.json appears in BOTH auto_merge AND manual_commit
        let policy = FilesystemPolicy {
            auto_merge: vec!["*.json".into(), "*.csv".into()],
            manual_commit: vec!["*.json".into(), "*.py".into()],
            discard: vec!["*.log".into()],
            default: "auto_merge".into(),
            upper_size_mb: 256,
        };

        // *.json is in both auto_merge and manual_commit.
        // manual_commit is checked first (stricter) → must win.
        let (action, pattern) = classify_file(Path::new("config.json"), &policy);
        assert!(
            matches!(action, FileAction::ManualCommit),
            "manual_commit must win over auto_merge for overlapping patterns (got {:?})",
            action,
        );
        assert_eq!(pattern, "*.json");
    }

    /// Priority test: discard beats manual_commit for overlapping patterns.
    #[test]
    fn priority_discard_beats_manual_commit() {
        let policy = FilesystemPolicy {
            auto_merge: vec![],
            manual_commit: vec!["*.log".into()], // also in discard
            discard: vec!["*.log".into()],
            default: "auto_merge".into(),
            upper_size_mb: 256,
        };

        let (action, _) = classify_file(Path::new("debug.log"), &policy);
        assert!(
            matches!(action, FileAction::Discard),
            "discard must win over manual_commit (got {:?})",
            action,
        );
    }

    /// Priority test: a file matching no pattern gets the default action.
    #[test]
    fn priority_default_auto_merge() {
        let policy = FilesystemPolicy {
            auto_merge: vec![],
            manual_commit: vec![],
            discard: vec![],
            default: "auto_merge".into(),
            upper_size_mb: 256,
        };

        let (action, pattern) = classify_file(Path::new("anything.xyz"), &policy);
        assert!(matches!(action, FileAction::AutoMerge));
        assert_eq!(pattern, "default");
    }

    /// Priority test: default = "discard" works.
    #[test]
    fn priority_default_discard() {
        let policy = FilesystemPolicy {
            auto_merge: vec![],
            manual_commit: vec![],
            discard: vec![],
            default: "discard".into(),
            upper_size_mb: 256,
        };

        let (action, _) = classify_file(Path::new("anything.xyz"), &policy);
        assert!(matches!(action, FileAction::Discard));
    }

    // ── Phase 0 + Phase 1 tests ──

    /// Phase 0-A: Symlink targeting outside upper_dir is discarded.
    #[test]
    fn symlink_escape_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let lower = dir.path().join("lower");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&lower).unwrap();

        // Create symlink pointing outside upper
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", upper.join("escape.txt")).unwrap();
        }
        #[cfg(not(unix))]
        {
            // Skip on non-Unix
            return;
        }

        let policy = FilesystemPolicy::default();
        let report = scan_upper_layer(&upper, &lower, &policy).unwrap();

        assert_eq!(report.discarded.len(), 1, "symlink escape must be discarded");
        assert_eq!(report.discarded[0].matched_pattern, "symlink_escape_blocked");
        assert!(report.auto_merged.is_empty(), "no auto-merge for symlinks");
    }

    /// Phase 0-C: Path with `..` is discarded.
    #[test]
    fn path_traversal_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let lower = dir.path().join("lower");
        let sneaky_dir = upper.join("..sneaky");
        std::fs::create_dir_all(&sneaky_dir).unwrap();
        std::fs::create_dir_all(&lower).unwrap();

        // File with ".." in parent dir name
        std::fs::write(sneaky_dir.join("data.csv"), "evil").unwrap();

        let policy = FilesystemPolicy::default();
        let report = scan_upper_layer(&upper, &lower, &policy).unwrap();

        // "..sneaky/data.csv" contains ".." → should be discarded
        let has_traversal = report.discarded.iter()
            .any(|f| f.matched_pattern == "path_traversal_blocked");
        assert!(has_traversal, "path traversal must be discarded");
    }

    /// Phase 1-A: Modified files are always ManualCommit regardless of pattern.
    #[test]
    fn modified_file_forced_manual_commit() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let lower = dir.path().join("lower");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&lower).unwrap();

        // Create same file in both (Modified)
        std::fs::write(lower.join("data.csv"), "original").unwrap();
        std::fs::write(upper.join("data.csv"), "modified").unwrap();

        // Create new file in upper only (Created)
        std::fs::write(upper.join("output.csv"), "new data").unwrap();

        let policy = FilesystemPolicy::default();
        let report = scan_upper_layer(&upper, &lower, &policy).unwrap();

        // Modified *.csv → ManualCommit (not AutoMerge)
        let modified = report.needs_review.iter()
            .find(|f| f.path == Path::new("data.csv"));
        assert!(modified.is_some(), "modified file must be in needs_review");
        assert!(matches!(modified.unwrap().kind, ChangeKind::Modified));
        assert_eq!(modified.unwrap().matched_pattern, "modified_file");

        // Created *.csv → AutoMerge
        let created = report.auto_merged.iter()
            .find(|f| f.path == Path::new("output.csv"));
        assert!(created.is_some(), "created csv must be auto-merged");
        assert!(matches!(created.unwrap().kind, ChangeKind::Created));
    }

    /// Phase 1-B: execute_merge only copies Created files.
    #[test]
    fn execute_merge_only_copies_created() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();

        // Create a file in upper
        std::fs::write(upper.join("output.csv"), "new data").unwrap();

        let report = FsDiffReport {
            auto_merged: vec![FileChange {
                path: PathBuf::from("output.csv"),
                kind: ChangeKind::Created,
                action: FileAction::AutoMerge,
                size: 8,
                matched_pattern: "*.csv".into(),
            }],
            needs_review: vec![],
            discarded: vec![],
            overlayfs_active: true,
        };

        let result = execute_merge(&report, &upper, &workspace);
        assert_eq!(result.copied.len(), 1);
        assert!(result.errors.is_empty());

        // Verify file was copied
        let dst = workspace.join("output.csv");
        assert!(dst.exists(), "auto-merged file must be copied to workspace");
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "new data");
    }

    /// Phase 1-B: execute_merge rejects symlinks.
    #[test]
    fn execute_merge_rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("upper");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();

        // Create a symlink in upper
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", upper.join("link.txt")).unwrap();
        }
        #[cfg(not(unix))]
        { return; }

        let report = FsDiffReport {
            auto_merged: vec![FileChange {
                path: PathBuf::from("link.txt"),
                kind: ChangeKind::Created,
                action: FileAction::AutoMerge,
                size: 0,
                matched_pattern: "*.txt".into(),
            }],
            needs_review: vec![],
            discarded: vec![],
            overlayfs_active: true,
        };

        let result = execute_merge(&report, &upper, &workspace);
        assert_eq!(result.skipped.len(), 1, "symlink must be skipped");
        assert!(result.copied.is_empty(), "symlink must not be copied");
    }
}
