use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Token-bucket rate limiter keyed by agent ID.
/// Used for Throttle enforcement decisions.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_per_minute: u64) -> Self {
        let max_tokens = max_per_minute as f64;
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate: max_tokens / 60.0,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate exceeded.
    fn try_consume(&mut self) -> bool {
        self.refill();

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
        }
    }

    /// Check rate limit for a given agent. Returns true if the request is allowed.
    pub fn check(&self, agent_id: &str, max_per_minute: u64) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(max_per_minute));

        // Update max if policy changed
        let new_max = max_per_minute as f64;
        if (bucket.max_tokens - new_max).abs() > f64::EPSILON {
            bucket.max_tokens = new_max;
            bucket.refill_rate = new_max / 60.0;
        }

        bucket.try_consume()
    }
}
