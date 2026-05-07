//! Bounded HTTP/1.1 upstream-connection pool for the MITM relay.
//!
//! Without pooling, every MITM-intercepted request triggered a fresh
//! `TcpStream::connect` + TLS handshake + `hyper::client::conn::http1::handshake`
//! to the upstream server (see `src/tls_proxy_hyper.rs::handle_request`).
//! That added ~200 ms of latency to every HTTP/1.1 request —
//! measured at +215 ms median against `httpbin.org` from EC2 Seoul
//! (n=20 fresh-TLS curl). The whole delta was the redundant upstream
//! handshake the proxy was doing on every request.
//!
//! With pooling the cost is amortised: agents that send multiple
//! requests to the same host (every realistic agent flow) reuse
//! the existing TCP + TLS + HTTP/1.1 keep-alive connection,
//! collapsing per-request overhead to the body forward latency
//! alone.
//!
//! **Design choices.**
//! - **Pool key: `host:port`.** Same scope hyper-util's
//!   `client::legacy::Client` uses. Different upstream hosts get
//!   different pools.
//! - **LIFO take, drop on TTL expiry.** A connection that has been
//!   idle for over `idle_ttl` is more likely to have been closed by
//!   the upstream than a fresh one. Pop from the back so the most
//!   recently used (= most likely still alive) sender is reused
//!   first.
//! - **Per-host cap.** `max_idle_per_host` caps idle connections
//!   per host so a misbehaving agent flooding a single host can't
//!   leak unbounded sockets.
//! - **Sender returned by body finalizer.** After the proxy hands a
//!   `Response<Body>` back to the agent, the body is streamed
//!   asynchronously and the SendRequest can ONLY be reused after
//!   the body has been fully drained (HTTP/1.1 framing). We wrap
//!   the upstream `Incoming` body in [`SenderReturnerBody`], which
//!   returns the sender to the pool when its frame stream ends.
//! - **Liveness check on take.** The caller calls `sender.ready()`
//!   before sending; if the connection has died since being pooled,
//!   `ready()` returns Err and the caller falls back to a fresh
//!   connection.

use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Bytes};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Concrete `SendRequest` type produced by `hyper::client::conn::http1::handshake`
/// on the request body shape the MITM relay actually sends. The proxy
/// collapses the agent's request body into `Full<Bytes>`, then boxes
/// it into `BoxBody<Bytes, String>` so that error responses (which
/// also use a `BoxBody` over `Bytes`) share a single body type
/// throughout the relay path. See
/// `src/tls_proxy_hyper.rs::handle_request` for the body construction
/// site.
pub type SendRequestT = hyper::client::conn::http1::SendRequest<BoxBody<Bytes, String>>;

/// Bounded LIFO pool of `SendRequest` handles, keyed by upstream
/// `host:port`. Cloning is cheap (Arc inside).
#[derive(Clone)]
pub struct UpstreamPool {
    inner: Arc<Mutex<HashMap<String, Vec<PooledSender>>>>,
    max_idle_per_host: usize,
    idle_ttl: Duration,
}

struct PooledSender {
    sender: SendRequestT,
    last_used: Instant,
}

impl UpstreamPool {
    /// Default pool: 4 idle connections per host, 30 s TTL. Tuned
    /// for the typical agent workload (a handful of upstream hosts,
    /// short bursts of requests). Production deployments with very
    /// high fan-in to one host can raise the cap.
    pub fn new() -> Self {
        Self::with_limits(4, Duration::from_secs(30))
    }

    pub fn with_limits(max_idle_per_host: usize, idle_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host,
            idle_ttl,
        }
    }

    /// Try to take a sender that has been idle for less than the
    /// configured TTL. Returns `None` when the pool is empty for
    /// `host` or every entry has expired (expired entries are
    /// dropped as a side effect — closing the underlying connection
    /// when the SendRequest is dropped).
    ///
    /// Caller is responsible for verifying the returned sender's
    /// liveness via `SendRequestT::ready()` before sending.
    pub fn try_take(&self, host: &str) -> Option<SendRequestT> {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return None, // poisoned mutex — bail; caller fresh-connects
        };
        let entry = g.get_mut(host)?;
        while let Some(p) = entry.pop() {
            if p.last_used.elapsed() < self.idle_ttl {
                return Some(p.sender);
            }
            // expired — drop, which closes the underlying connection
            // via the SendRequest -> Connection driver chain.
        }
        None
    }

    /// Return a sender to the pool. If the per-host cap is
    /// exceeded, the oldest entry is dropped (its connection
    /// closes). Returning `false` means the sender was dropped
    /// without being pooled — used by tests and observability.
    pub fn put_back(&self, host: String, sender: SendRequestT) -> bool {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let entry = g.entry(host).or_default();
        if entry.len() >= self.max_idle_per_host {
            // Drop oldest at index 0; LIFO take ensures most recent
            // is preferred.
            entry.remove(0);
        }
        entry.push(PooledSender {
            sender,
            last_used: Instant::now(),
        });
        true
    }

    /// Diagnostic: total idle senders held across all hosts.
    /// Useful for `gvm status` -style observability.
    pub fn total_idle(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps an upstream `Incoming` body. When the body's frame stream
/// ends (Ready(None) — clean EOF), the held `SendRequest` is
/// returned to the pool. On error or premature drop the SendRequest
/// is also dropped — closing the underlying connection.
///
/// HTTP/1.1 keep-alive requires the response body be fully drained
/// before the connection is reusable, so EOF is the correct signal.
pub struct SenderReturnerBody {
    body: hyper::body::Incoming,
    /// Held until the response body completes; then moved into the
    /// pool by `poll_frame`. `None` after completion.
    sender_slot: Option<SendRequestT>,
    pool: UpstreamPool,
    host: String,
}

impl SenderReturnerBody {
    pub fn new(
        body: hyper::body::Incoming,
        sender: SendRequestT,
        pool: UpstreamPool,
        host: String,
    ) -> Self {
        Self {
            body,
            sender_slot: Some(sender),
            pool,
            host,
        }
    }
}

impl Body for SenderReturnerBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let result = Pin::new(&mut self.body).poll_frame(cx);
        match &result {
            Poll::Ready(None) => {
                // Clean EOF — return sender to pool.
                if let Some(s) = self.sender_slot.take() {
                    self.pool.put_back(self.host.clone(), s);
                }
            }
            Poll::Ready(Some(Ok(_frame))) => {
                // Successful frame. For Content-Length-bounded HTTP/1.1
                // responses, hyper's `Incoming` returns the body as a
                // single data frame and then signals completion via
                // `is_end_stream()` rather than a follow-up
                // `Ready(None)`. Hyper's server-side writer checks
                // `is_end_stream()` after each frame and stops polling
                // when it returns true — so a finalizer that only
                // fires on `Ready(None)` will be missed.
                //
                // Ask the inner body if it's now exhausted; if so,
                // return the sender immediately rather than waiting
                // for a `Ready(None)` that will never arrive.
                if self.body.is_end_stream() {
                    if let Some(s) = self.sender_slot.take() {
                        self.pool.put_back(self.host.clone(), s);
                    }
                }
            }
            Poll::Ready(Some(Err(_))) => {
                // Error — drop sender (sender_slot Drop closes the
                // connection via SendRequest -> Connection chain).
                self.sender_slot = None;
            }
            _ => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_total_idle_starts_at_zero() {
        let pool = UpstreamPool::new();
        assert_eq!(pool.total_idle(), 0);
    }

    #[test]
    fn pool_take_on_empty_returns_none() {
        let pool = UpstreamPool::new();
        assert!(pool.try_take("missing.example.com:443").is_none());
    }

    #[test]
    fn default_uses_sane_caps() {
        // Pin the default tuning so a future refactor doesn't quietly
        // change the contract operators rely on.
        let pool = UpstreamPool::new();
        assert_eq!(pool.max_idle_per_host, 4);
        assert_eq!(pool.idle_ttl, Duration::from_secs(30));
    }
}
