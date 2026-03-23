#![allow(clippy::manual_is_multiple_of)]
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fixed-point scale: 1 token = 1000 millitokens.
/// All arithmetic uses u64 to eliminate floating-point non-determinism.
const MILLIS_PER_TOKEN: u64 = 1000;

/// Token-bucket rate limiter keyed by agent ID.
/// Uses millitoken (u64) fixed-point arithmetic for deterministic decisions.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    /// Counter for periodic stale bucket cleanup.
    check_count: std::sync::atomic::AtomicU64,
}

struct TokenBucket {
    /// Current tokens in millitokens (1000 = 1 token).
    millitokens: u64,
    /// Maximum tokens in millitokens.
    max_millitokens: u64,
    /// Refill rate in millitokens per second.
    refill_rate_millis_per_sec: u64,
    last_refill: Instant,
    last_access: Instant,
}

/// Duration after which idle buckets are evicted.
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(600); // 10 minutes
/// Clean up stale buckets every N check() calls.
const CLEANUP_INTERVAL: u64 = 1000;
/// Hard cap on bucket count. If exceeded, force an immediate cleanup
/// regardless of CLEANUP_INTERVAL. Prevents unbounded memory growth
/// from a flood of unique agent IDs (e.g., agent ID spoofing attack).
const MAX_BUCKETS: usize = 10_000;

impl TokenBucket {
    fn new(max_per_minute: u64) -> Self {
        let max_millitokens = max_per_minute.saturating_mul(MILLIS_PER_TOKEN);
        let now = Instant::now();
        Self {
            millitokens: max_millitokens,
            max_millitokens,
            // rate = max_per_minute tokens / 60 seconds, in millitokens/sec
            // = max_per_minute * 1000 / 60
            refill_rate_millis_per_sec: max_per_minute.saturating_mul(MILLIS_PER_TOKEN) / 60,
            last_refill: now,
            last_access: now,
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate exceeded.
    fn try_consume(&mut self) -> bool {
        self.refill();
        self.last_access = Instant::now();

        if self.millitokens >= MILLIS_PER_TOKEN {
            self.millitokens -= MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.last_refill).as_millis() as u64;
        // Compute refill: rate_millis_per_sec * elapsed_ms / 1000
        // Use checked arithmetic to avoid overflow on very long idle periods.
        let refill_amount = self.refill_rate_millis_per_sec.saturating_mul(elapsed_ms) / 1000;
        self.millitokens = self
            .millitokens
            .saturating_add(refill_amount)
            .min(self.max_millitokens);
        self.last_refill = now;
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            check_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check rate limit for a given agent. Returns true if the request is allowed.
    /// Fail-close: if the mutex is poisoned, deny the request.
    pub fn check(&self, agent_id: &str, max_per_minute: u64) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(b) => b,
            Err(_) => {
                tracing::error!("Rate limiter mutex poisoned — denying request (fail-close)");
                return false;
            }
        };

        // Periodic cleanup of stale buckets to prevent unbounded memory growth.
        // Also triggers immediately if bucket count exceeds MAX_BUCKETS (DoS defense).
        let count = self
            .check_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let force_cleanup = buckets.len() >= MAX_BUCKETS;
        if force_cleanup || (count % CLEANUP_INTERVAL == 0 && count > 0) {
            if force_cleanup {
                tracing::warn!(
                    buckets = buckets.len(),
                    "Rate limiter bucket count at capacity ({}) — forcing cleanup",
                    MAX_BUCKETS
                );
            }
            let before = buckets.len();
            buckets.retain(|_, b| b.last_access.elapsed() < BUCKET_IDLE_TTL);
            let evicted = before - buckets.len();
            if evicted > 0 {
                tracing::debug!(
                    evicted = evicted,
                    remaining = buckets.len(),
                    "Evicted stale rate limit buckets"
                );
            }
            // If still at capacity after TTL eviction, evict oldest entries
            if buckets.len() >= MAX_BUCKETS {
                let mut entries: Vec<(String, Instant)> = buckets
                    .iter()
                    .map(|(k, b)| (k.clone(), b.last_access))
                    .collect();
                entries.sort_by_key(|(_, t)| *t);
                let to_remove = buckets.len() - (MAX_BUCKETS * 3 / 4); // evict 25%
                for (key, _) in entries.iter().take(to_remove) {
                    buckets.remove(key);
                }
                tracing::warn!(
                    force_evicted = to_remove,
                    remaining = buckets.len(),
                    "Force-evicted oldest rate limit buckets (capacity overflow)"
                );
            }
        }

        let bucket = buckets
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(max_per_minute));

        // Update max if policy changed, and clamp current tokens to new max
        let new_max_millis = max_per_minute.saturating_mul(MILLIS_PER_TOKEN);
        if bucket.max_millitokens != new_max_millis {
            bucket.max_millitokens = new_max_millis;
            bucket.refill_rate_millis_per_sec =
                max_per_minute.saturating_mul(MILLIS_PER_TOKEN) / 60;
            bucket.millitokens = bucket.millitokens.min(new_max_millis);
        }

        bucket.try_consume()
    }
}
