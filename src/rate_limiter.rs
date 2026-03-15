use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Token-bucket rate limiter keyed by agent ID.
/// Used for Throttle enforcement decisions.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    /// Counter for periodic stale bucket cleanup.
    check_count: std::sync::atomic::AtomicU64,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
    last_access: Instant,
}

/// Duration after which idle buckets are evicted.
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(600); // 10 minutes
/// Clean up stale buckets every N check() calls.
const CLEANUP_INTERVAL: u64 = 1000;

impl TokenBucket {
    fn new(max_per_minute: u64) -> Self {
        let max_tokens = max_per_minute as f64;
        let now = Instant::now();
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: max_tokens / 60.0,
            last_refill: now,
            last_access: now,
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate exceeded.
    fn try_consume(&mut self) -> bool {
        self.refill();
        self.last_access = Instant::now();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
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

        // Periodic cleanup of stale buckets to prevent unbounded memory growth
        let count = self.check_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % CLEANUP_INTERVAL == 0 && count > 0 {
            let before = buckets.len();
            buckets.retain(|_, b| b.last_access.elapsed() < BUCKET_IDLE_TTL);
            let evicted = before - buckets.len();
            if evicted > 0 {
                tracing::debug!(evicted = evicted, remaining = buckets.len(), "Evicted stale rate limit buckets");
            }
        }

        let bucket = buckets
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(max_per_minute));

        // Update max if policy changed, and clamp current tokens to new max
        let new_max = max_per_minute as f64;
        if (bucket.max_tokens - new_max).abs() > f64::EPSILON {
            bucket.max_tokens = new_max;
            bucket.refill_rate = new_max / 60.0;
            bucket.tokens = bucket.tokens.min(new_max);
        }

        bucket.try_consume()
    }
}
