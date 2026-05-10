//! Background WAL re-verification (`△-6` from
//! `docs/internal/COVERAGE_HARDENING_PLAN.md`).
//!
//! The Ledger's tamper detection is reactive: a Merkle break is
//! observed when the next durable append re-anchors, or when the
//! operator runs `gvm audit verify`. Between reboots an attacker
//! can rewrite a sealed batch and the proxy will not notice until
//! either of those events. This module closes the gap with a
//! periodic background scan.
//!
//! **Design**:
//!
//! - One `tokio::time::interval` task, spawned at startup when the
//!   operator opts in via `[wal] background_reverify_interval_secs`.
//! - Each tick reads the entire active WAL file and runs
//!   [`merkle::verify_wal`]. Cost is O(|WAL|) per tick — acceptable
//!   for WALs of a few hundred MB on operator schedules of minutes.
//!   Streaming verification is on the post-v1 roadmap; this version
//!   prioritises correctness over efficiency.
//! - On a chain break, [`set_break`] flips an `AtomicBool` that
//!   `/gvm/health` exposes. The flag is **monotonic**: once set
//!   it never clears within a process lifetime. This prevents a
//!   transient I/O hiccup in the verifier from masking a
//!   subsequent real break.
//! - Logs at `tracing::warn` with the report's tampered/invalid
//!   counts so operators with structured logs can alert on the
//!   line.
//!
//! **Default-off**. The task only spawns when
//! `background_reverify_interval_secs > 0`. Operators who run
//! `gvm audit verify` on their own schedule (e.g., a cron) don't
//! need to pay the read overhead.
//!
//! Pinned by `tests/wal_background_reverify.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Shared health flag. Reads are lock-free (`AtomicBool`).
///
/// Cloning is cheap (Arc inside). The proxy hands one clone to the
/// background task, another to the `/gvm/health` handler.
#[derive(Clone, Default)]
pub struct WalChainHealth {
    intact: Arc<AtomicBool>,
}

impl WalChainHealth {
    /// Healthy at construction. Flips to `false` only on observed
    /// break (no automatic recovery within process lifetime).
    pub fn new() -> Self {
        Self {
            intact: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Read the current intact flag. Suitable for `/gvm/health`.
    pub fn is_intact(&self) -> bool {
        self.intact.load(Ordering::Relaxed)
    }

    /// Mark the chain broken. Idempotent; subsequent calls are
    /// no-ops. Only the background task and panic recovery paths
    /// should invoke this.
    pub fn set_break(&self) {
        self.intact.store(false, Ordering::Relaxed);
    }
}

/// Spawn the background reverify task. Returns immediately. The
/// task lives for the proxy's lifetime; tokio drops it on runtime
/// shutdown.
///
/// `interval_secs == 0` is treated as "disabled" — this function
/// returns without spawning anything. The caller is expected to
/// branch on the config value before invoking.
///
/// `wal_path` is the active WAL file. Rotated segments
/// (`wal.log.<N>`) are not currently included in the scan; the
/// active segment alone contains every event since the last
/// rotation, which is sufficient to detect a recent tamper.
/// Cross-rotation re-verification is tracked separately in the
/// hardening plan as a follow-up.
pub fn spawn(wal_path: PathBuf, interval_secs: u64, health: WalChainHealth) {
    if interval_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(interval_secs);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate tick — first verification runs after
        // one full interval. Avoids spurious cold-start noise
        // (the WAL may still be empty at proxy boot).
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_one_pass(&wal_path, &health).await;
        }
    });
}

/// Single verification pass. Public for tests.
pub async fn run_one_pass(wal_path: &std::path::Path, health: &WalChainHealth) {
    if !health.is_intact() {
        // Already broken in this process. Skip the read entirely —
        // we don't waste I/O on a flag that can't recover.
        return;
    }
    let content = match tokio::fs::read_to_string(wal_path).await {
        Ok(c) => c,
        Err(e) => {
            // I/O error reading the WAL is not a chain break (the
            // WAL may have been rotated mid-tick). Log and try
            // again next interval.
            tracing::debug!(
                path = %wal_path.display(),
                error = %e,
                "WAL background reverify: read failed (transient)"
            );
            return;
        }
    };

    if content.is_empty() {
        // Empty WAL is healthy — nothing to verify.
        return;
    }

    let report = crate::merkle::verify_wal(&content);

    if !report.chain_intact
        || !report.invalid_batches.is_empty()
        || !report.tampered_events.is_empty()
    {
        tracing::warn!(
            total_events = report.total_events,
            total_batches = report.total_batches,
            valid_batches = report.valid_batches,
            invalid_batches = ?report.invalid_batches,
            tampered_events_count = report.tampered_events.len(),
            chain_intact = report.chain_intact,
            "WAL background reverify: chain break detected — \
             /gvm/health.wal_chain_intact will report false until process restart"
        );
        health.set_break();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_intact() {
        let h = WalChainHealth::new();
        assert!(h.is_intact());
    }

    #[test]
    fn set_break_is_monotonic() {
        let h = WalChainHealth::new();
        assert!(h.is_intact());
        h.set_break();
        assert!(!h.is_intact());
        // Subsequent calls don't accidentally reset.
        h.set_break();
        assert!(!h.is_intact());
    }

    #[test]
    fn clones_share_state() {
        let h = WalChainHealth::new();
        let h2 = h.clone();
        h.set_break();
        assert!(!h2.is_intact());
    }
}
