//! Token budget enforcement — lock-free sliding window for LLM cost governance.
//!
//! Replaces the per-URL rate limiter with a global token/cost budget.
//! Uses a 60-slot circular buffer (1 minute per slot, 1 hour window).
//! All operations are lock-free via AtomicU64.
//!
//! Flow:
//!   1. LLM request arrives → check() + reserve()
//!   2. Request forwarded → response received → tap-stream extracts usage
//!   3. record() releases reservation + adds actual tokens/cost to current slot

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SLOTS: usize = 60; // 60 minutes = 1 hour window

// ─── Clock abstraction (no production attack surface) ───
//
// Replaces the previous `_rotate_for_test` test-only hook (which was
// `pub` and could be reached from any code holding a TokenBudget
// reference, bypassing budget enforcement entirely). With Clock,
// production uses SystemClock — tests pass a MockClock that advances
// virtual time. The trait exposes ONLY a read of the current Unix
// second; it cannot mutate budget state, so the abstraction itself
// is not a privilege boundary that can be broken.

/// Source of "now" for `TokenBudget` slot rotation.
///
/// Production callers pass `SystemClock`. Tests can substitute a
/// fake clock to deterministically advance the sliding window without
/// `std::thread::sleep`. Read-only — no method on this trait can
/// alter budget enforcement state.
pub trait BudgetClock: Send + Sync {
    /// Current Unix epoch second.
    fn now_unix_secs(&self) -> u64;
}

/// Default real-time clock.
pub struct SystemClock;

impl BudgetClock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Atomic saturating subtract: `*counter = max(0, *counter - delta)`,
/// guaranteed race-free under concurrent callers. Replaces the
/// `load + saturating_sub + store` pattern that lost decrements when
/// two threads observed the same `prev` value (verified by
/// `tests/token_budget_contention.rs` — 47,400 token drift over
/// 80,000 balanced reserve+release pairs on 16 OS threads).
fn atomic_saturating_sub(counter: &AtomicU64, delta: u64) {
    // fetch_update retries on conflict; closure is pure so safe to
    // re-run. Returning Some(new) on success / None on no change.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
        Some(prev.saturating_sub(delta))
    });
}

/// Per-minute slot storing accumulated tokens and cost.
struct Slot {
    tokens: AtomicU64,
    /// Cost in millionths of USD (1 USD = 1_000_000). Avoids floating point.
    cost_millionths: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            tokens: AtomicU64::new(0),
            cost_millionths: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.tokens.store(0, Ordering::Relaxed);
        self.cost_millionths.store(0, Ordering::Relaxed);
    }
}

/// Budget exceeded error with current usage details.
#[derive(Debug)]
pub struct BudgetExceeded {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub cost_used_millionths: u64,
    pub cost_limit_millionths: u64,
}

impl BudgetExceeded {
    pub fn cost_used_usd(&self) -> f64 {
        self.cost_used_millionths as f64 / 1_000_000.0
    }
    pub fn cost_limit_usd(&self) -> f64 {
        self.cost_limit_millionths as f64 / 1_000_000.0
    }
}

/// Current budget status for dashboard display.
pub struct BudgetStatus {
    pub tokens_used: u64,
    pub tokens_limit: u64,
    pub cost_used_millionths: u64,
    pub cost_limit_millionths: u64,
    pub pending_reservations: u64,
}

impl BudgetStatus {
    pub fn cost_used_usd(&self) -> f64 {
        self.cost_used_millionths as f64 / 1_000_000.0
    }
    pub fn cost_limit_usd(&self) -> f64 {
        self.cost_limit_millionths as f64 / 1_000_000.0
    }
    pub fn tokens_pct(&self) -> f64 {
        if self.tokens_limit == 0 {
            return 0.0;
        }
        (self.tokens_used + self.pending_reservations) as f64 / self.tokens_limit as f64 * 100.0
    }
    pub fn cost_pct(&self) -> f64 {
        if self.cost_limit_millionths == 0 {
            return 0.0;
        }
        self.cost_used_millionths as f64 / self.cost_limit_millionths as f64 * 100.0
    }
}

pub struct TokenBudget {
    slots: [Slot; SLOTS],
    /// Current minute index (0..59).
    current_minute: AtomicU64,
    /// Epoch seconds when current_minute was last set.
    last_rotation_epoch: AtomicU64,
    /// Sum of reserved tokens for in-flight requests (not yet completed).
    pending_reservations: AtomicU64,
    /// Source of "now" — production: SystemClock; tests: MockClock.
    /// Read-only: cannot bypass enforcement by tampering through this.
    clock: Arc<dyn BudgetClock>,
    /// Config
    max_tokens_per_hour: u64,
    max_cost_per_hour_millionths: u64,
    reserve_per_request: u64,
}

impl TokenBudget {
    /// Construct with the production system clock.
    pub fn new(max_tokens_per_hour: u64, max_cost_per_hour: f64, reserve_per_request: u64) -> Self {
        Self::with_clock(
            max_tokens_per_hour,
            max_cost_per_hour,
            reserve_per_request,
            Arc::new(SystemClock),
        )
    }

    /// Construct with a caller-supplied clock. The clock is read-only;
    /// it cannot mutate budget state. Tests pass a MockClock to advance
    /// virtual time deterministically.
    pub fn with_clock(
        max_tokens_per_hour: u64,
        max_cost_per_hour: f64,
        reserve_per_request: u64,
        clock: Arc<dyn BudgetClock>,
    ) -> Self {
        let now = clock.now_unix_secs();
        let minute = (now / 60) % SLOTS as u64;

        Self {
            slots: std::array::from_fn(|_| Slot::new()),
            current_minute: AtomicU64::new(minute),
            last_rotation_epoch: AtomicU64::new(now),
            pending_reservations: AtomicU64::new(0),
            clock,
            max_tokens_per_hour,
            max_cost_per_hour_millionths: (max_cost_per_hour * 1_000_000.0) as u64,
            reserve_per_request,
        }
    }

    /// Check if budget allows another LLM request. If yes, reserves tokens.
    /// Returns Ok(reservation_id) or Err(BudgetExceeded).
    pub fn check_and_reserve(&self) -> Result<u64, BudgetExceeded> {
        self.rotate_if_needed();

        let (total_tokens, total_cost) = self.sum_window();
        let pending = self.pending_reservations.load(Ordering::Relaxed);

        // Check token limit
        if self.max_tokens_per_hour > 0
            && total_tokens + pending + self.reserve_per_request > self.max_tokens_per_hour
        {
            return Err(BudgetExceeded {
                tokens_used: total_tokens + pending,
                tokens_limit: self.max_tokens_per_hour,
                cost_used_millionths: total_cost,
                cost_limit_millionths: self.max_cost_per_hour_millionths,
            });
        }

        // Check cost limit
        if self.max_cost_per_hour_millionths > 0 && total_cost > self.max_cost_per_hour_millionths {
            return Err(BudgetExceeded {
                tokens_used: total_tokens + pending,
                tokens_limit: self.max_tokens_per_hour,
                cost_used_millionths: total_cost,
                cost_limit_millionths: self.max_cost_per_hour_millionths,
            });
        }

        // Reserve
        self.pending_reservations
            .fetch_add(self.reserve_per_request, Ordering::Relaxed);

        Ok(self.reserve_per_request)
    }

    /// Record actual token usage after LLM response. Releases reservation.
    pub fn record(&self, tokens: u64, cost_usd: f64) {
        // Release reservation. Must be a single atomic op — the prior
        // `load(); store(prev - reserve)` pattern lost decrements
        // under real CPU-parallel contention (verified at 47,400-token
        // drift over 80,000 balanced reserve+release pairs across 16
        // OS threads). fetch_update with saturating_sub closes the
        // race while preserving the underflow guard the original
        // saturating_sub provided.
        atomic_saturating_sub(&self.pending_reservations, self.reserve_per_request);

        // Add actual usage to current slot
        self.rotate_if_needed();
        let idx = self.current_minute.load(Ordering::Relaxed) as usize % SLOTS;
        self.slots[idx].tokens.fetch_add(tokens, Ordering::Relaxed);
        let cost_millionths = (cost_usd * 1_000_000.0) as u64;
        self.slots[idx]
            .cost_millionths
            .fetch_add(cost_millionths, Ordering::Relaxed);
    }

    /// Release reservation without recording (e.g., request failed before response).
    pub fn release_reservation(&self) {
        atomic_saturating_sub(&self.pending_reservations, self.reserve_per_request);
    }

    /// Current budget status for dashboard display.
    pub fn status(&self) -> BudgetStatus {
        self.rotate_if_needed();
        let (tokens, cost) = self.sum_window();
        BudgetStatus {
            tokens_used: tokens,
            tokens_limit: self.max_tokens_per_hour,
            cost_used_millionths: cost,
            cost_limit_millionths: self.max_cost_per_hour_millionths,
            pending_reservations: self.pending_reservations.load(Ordering::Relaxed),
        }
    }

    /// Whether budget enforcement is enabled (any limit > 0).
    pub fn is_enabled(&self) -> bool {
        self.max_tokens_per_hour > 0 || self.max_cost_per_hour_millionths > 0
    }

    // ─── Internal ───

    /// Sum all 60 slots for the current hour window.
    fn sum_window(&self) -> (u64, u64) {
        let mut tokens = 0u64;
        let mut cost = 0u64;
        for slot in &self.slots {
            tokens += slot.tokens.load(Ordering::Relaxed);
            cost += slot.cost_millionths.load(Ordering::Relaxed);
        }
        (tokens, cost)
    }

    /// Rotate current slot if a new minute has started. Zero expired slots.
    /// Reads "now" from the injected clock (SystemClock in production).
    fn rotate_if_needed(&self) {
        let now = self.clock.now_unix_secs();
        let new_minute = (now / 60) % SLOTS as u64;
        let old_minute = self.current_minute.load(Ordering::Relaxed);

        if new_minute == old_minute {
            return;
        }

        // Clear slots between old and new minute (they've expired)
        let steps = if new_minute > old_minute {
            new_minute - old_minute
        } else {
            SLOTS as u64 - old_minute + new_minute
        };

        // Clear at most SLOTS (full rotation = clear all)
        let clear_count = steps.min(SLOTS as u64);
        for i in 1..=clear_count {
            let idx = ((old_minute + i) % SLOTS as u64) as usize;
            self.slots[idx].reset();
        }

        self.current_minute.store(new_minute, Ordering::Relaxed);
        self.last_rotation_epoch.store(now, Ordering::Relaxed);
    }
}

// ─── Per-agent quota (single-organization N-agent isolation) ───
//
// The global `TokenBudget` above is one pool shared by every agent —
// suitable as an organization-wide ceiling but unsuitable as a
// per-agent quota: a single buggy or runaway agent can drain the
// whole budget and block every other agent in the org. Per-agent
// budgets fix this by giving each agent_id an independent
// `TokenBudget` instance.
//
// Composition with the global budget:
//   - Global budget = org-wide cap (every request counts toward it)
//   - Per-agent budget = each agent's individual quota
//   - Both must pass for a request to proceed
//   - Either can fail independently — failing the per-agent quota
//     does NOT consume from the global pool, and vice versa
//
// Memory bound: `MAX_PER_AGENT_BUDGETS = 10_000` agents tracked.
// Beyond that, new agents get a "new agent admission rejected"
// error — same pattern the checkpoint registry uses.
//
// Lifecycle: per-agent budget instances are created lazily on first
// `check_and_reserve(agent_id)`. They are NOT evicted automatically
// — for v0.5 the in-memory footprint of a TokenBudget instance is
// ~5 KB (60 slots × 16 B + overhead), so 10K agents = ~50 MB worst
// case. Adding LRU eviction is straightforward when the cap
// becomes a real constraint.

/// Maximum number of distinct agents tracked by per-agent budgets.
pub const MAX_PER_AGENT_BUDGETS: usize = 10_000;

/// Per-agent quota. Each agent_id has its own `TokenBudget` instance
/// with the per-agent limits configured at construction. Shares the
/// parent budget's clock so virtual time advances in lockstep.
pub struct PerAgentBudgets {
    agents: DashMap<String, Arc<TokenBudget>>,
    per_agent_max_tokens_per_hour: u64,
    per_agent_max_cost_per_hour_millionths: u64,
    reserve_per_request: u64,
    clock: Arc<dyn BudgetClock>,
}

impl PerAgentBudgets {
    /// Construct with the production system clock.
    pub fn new(
        per_agent_max_tokens_per_hour: u64,
        per_agent_max_cost_per_hour: f64,
        reserve_per_request: u64,
    ) -> Self {
        Self::with_clock(
            per_agent_max_tokens_per_hour,
            per_agent_max_cost_per_hour,
            reserve_per_request,
            Arc::new(SystemClock),
        )
    }

    /// Construct with a caller-supplied clock (used by tests for
    /// deterministic virtual time).
    pub fn with_clock(
        per_agent_max_tokens_per_hour: u64,
        per_agent_max_cost_per_hour: f64,
        reserve_per_request: u64,
        clock: Arc<dyn BudgetClock>,
    ) -> Self {
        Self {
            agents: DashMap::new(),
            per_agent_max_tokens_per_hour,
            per_agent_max_cost_per_hour_millionths: (per_agent_max_cost_per_hour * 1_000_000.0)
                as u64,
            reserve_per_request,
            clock,
        }
    }

    /// Whether per-agent enforcement is enabled (any limit > 0).
    pub fn is_enabled(&self) -> bool {
        self.per_agent_max_tokens_per_hour > 0 || self.per_agent_max_cost_per_hour_millionths > 0
    }

    /// Look up (or create) the per-agent budget instance.
    /// Returns `Err(BudgetExceeded { tokens_limit: 0, .. })` with all
    /// counters zero when admission is rejected because
    /// MAX_PER_AGENT_BUDGETS is full — the magic-zero `tokens_limit`
    /// flags this case to callers without inventing a new error type.
    fn get_or_create(&self, agent_id: &str) -> Result<Arc<TokenBudget>, BudgetExceeded> {
        // Fast path: agent already tracked.
        if let Some(b) = self.agents.get(agent_id) {
            return Ok(Arc::clone(&*b));
        }
        // Slow path: insert. Re-check inside the entry to avoid the
        // race where two threads both miss the fast path.
        if self.agents.len() >= MAX_PER_AGENT_BUDGETS && !self.agents.contains_key(agent_id) {
            return Err(BudgetExceeded {
                tokens_used: 0,
                tokens_limit: 0,
                cost_used_millionths: 0,
                cost_limit_millionths: 0,
            });
        }
        let entry = self.agents.entry(agent_id.to_string()).or_insert_with(|| {
            Arc::new(TokenBudget::with_clock(
                self.per_agent_max_tokens_per_hour,
                self.per_agent_max_cost_per_hour_millionths as f64 / 1_000_000.0,
                self.reserve_per_request,
                Arc::clone(&self.clock),
            ))
        });
        Ok(Arc::clone(entry.value()))
    }

    /// Per-agent check + reserve. Returns the agent's reservation id
    /// on success or `BudgetExceeded` on quota violation. Agents whose
    /// admission was rejected (MAX_PER_AGENT_BUDGETS full) get
    /// `tokens_limit: 0` in the error.
    pub fn check_and_reserve(&self, agent_id: &str) -> Result<u64, BudgetExceeded> {
        let budget = self.get_or_create(agent_id)?;
        budget.check_and_reserve()
    }

    /// Per-agent record. No-op when the agent is unknown — covers the
    /// case of `record` arriving after the agent's slot was evicted
    /// (future feature) without crashing.
    pub fn record(&self, agent_id: &str, tokens: u64, cost_usd: f64) {
        if let Some(b) = self.agents.get(agent_id) {
            b.record(tokens, cost_usd);
        }
    }

    /// Per-agent reservation release.
    pub fn release_reservation(&self, agent_id: &str) {
        if let Some(b) = self.agents.get(agent_id) {
            b.release_reservation();
        }
    }

    /// Status snapshot for one agent. Returns `None` if the agent has
    /// never made a reservation.
    pub fn status(&self, agent_id: &str) -> Option<BudgetStatus> {
        self.agents.get(agent_id).map(|b| b.status())
    }

    /// Number of agents currently tracked.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_budget_allows() {
        let b = TokenBudget::new(100_000, 1.0, 500);
        assert!(b.check_and_reserve().is_ok());
    }

    #[test]
    fn unlimited_budget_always_allows() {
        let b = TokenBudget::new(0, 0.0, 500);
        assert!(!b.is_enabled());
        // check_and_reserve still works (no limit to exceed)
        assert!(b.check_and_reserve().is_ok());
    }

    #[test]
    fn budget_exceeded_after_record() {
        let b = TokenBudget::new(1000, 0.0, 100);
        // Record 900 tokens
        b.record(900, 0.0);
        // Reserve 100 → total 1000 → still ok
        assert!(b.check_and_reserve().is_ok());
        // Now at 900 + 100 reserved = 1000. Next check: 1000 + 100 > 1000
        assert!(b.check_and_reserve().is_err());
    }

    #[test]
    fn reservation_released_on_failure() {
        let b = TokenBudget::new(1000, 0.0, 500);
        assert!(b.check_and_reserve().is_ok()); // 500 reserved
        b.release_reservation(); // back to 0
        assert!(b.check_and_reserve().is_ok()); // 500 reserved again
    }

    #[test]
    fn cost_limit_enforced() {
        let b = TokenBudget::new(0, 0.01, 0); // $0.01 limit, no token limit
        b.record(100, 0.009); // $0.009
        assert!(b.check_and_reserve().is_ok());
        b.record(100, 0.002); // $0.011 total > $0.01
        assert!(b.check_and_reserve().is_err());
    }

    #[test]
    fn status_reflects_usage() {
        let b = TokenBudget::new(100_000, 1.0, 500);
        b.record(5000, 0.05);
        let s = b.status();
        assert_eq!(s.tokens_used, 5000);
        assert_eq!(s.tokens_limit, 100_000);
        assert!(s.cost_used_usd() > 0.04 && s.cost_used_usd() < 0.06);
    }
}
