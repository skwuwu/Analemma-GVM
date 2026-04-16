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

use std::sync::atomic::{AtomicU64, Ordering};

const SLOTS: usize = 60; // 60 minutes = 1 hour window

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
    /// Config
    max_tokens_per_hour: u64,
    max_cost_per_hour_millionths: u64,
    reserve_per_request: u64,
}

impl TokenBudget {
    pub fn new(max_tokens_per_hour: u64, max_cost_per_hour: f64, reserve_per_request: u64) -> Self {
        // Initialize slots with const fn
        const EMPTY: Slot = Slot::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let minute = (now / 60) % SLOTS as u64;

        Self {
            slots: [
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
            ],
            current_minute: AtomicU64::new(minute),
            last_rotation_epoch: AtomicU64::new(now),
            pending_reservations: AtomicU64::new(0),
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
        // Release reservation
        let reserve = self.reserve_per_request;
        let prev = self.pending_reservations.load(Ordering::Relaxed);
        self.pending_reservations
            .store(prev.saturating_sub(reserve), Ordering::Relaxed);

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
        let reserve = self.reserve_per_request;
        let prev = self.pending_reservations.load(Ordering::Relaxed);
        self.pending_reservations
            .store(prev.saturating_sub(reserve), Ordering::Relaxed);
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
    fn rotate_if_needed(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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
