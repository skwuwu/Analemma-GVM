//! DNS soft governance — Delay-Alert, no Deny.
//!
//! Design rationale: GVM's position shifted from "governance proxy" to "secure
//! runtime." Leaving DNS as an unmonitored bypass channel is a gap the project
//! can't justify. However, DNS Deny kills the entire agent (one FP = outage),
//! so enforcement uses graduated delay + alert only:
//!
//!   Tier 1 (known)   → free pass, 0ms
//!   Tier 2 (unknown) → 200ms delay + log
//!   Tier 3 (repeat)  → 3s delay + alert  (unique subdomain burst on unknown base)
//!   Tier 4 (flood)   → 10s delay + alert + RequireApproval
//!
//! Decay: when the anomalous pattern stops, the tier decays back toward Tier 2
//! over time (sliding window expiry). The system never permanently escalates.
//!
//! Disable: `--no-dns-governance` CLI flag or `dns.enabled = false` in proxy.toml.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

// ─── Tier thresholds ───

/// Delay applied to unknown domains on first encounter.
const TIER2_DELAY: Duration = Duration::from_millis(200);
/// Delay for repeated anomalous queries on the same base domain.
const TIER3_DELAY: Duration = Duration::from_secs(3);
/// Delay for query flood (global unique subdomain burst).
const TIER4_DELAY: Duration = Duration::from_secs(10);

/// Sliding window duration for per-domain unique subdomain counting.
/// Override with `GVM_TEST_DNS_WINDOW_SEC` for E2E tests (e.g. 5 seconds
/// instead of 60 so decay can be verified without a 60-second wait).
fn window_duration() -> Duration {
    if let Ok(v) = std::env::var("GVM_TEST_DNS_WINDOW_SEC") {
        if let Ok(secs) = v.parse::<u64>() {
            return Duration::from_secs(secs);
        }
    }
    Duration::from_secs(60)
}

/// Unique subdomains on an unknown base domain within the window to trigger Tier 3.
const TIER3_UNIQUE_THRESHOLD: usize = 5;
/// Global unique subdomain queries across all domains within the window to trigger Tier 4.
const TIER4_GLOBAL_THRESHOLD: usize = 20;

/// Maximum tracked domains before oldest are evicted.
const MAX_TRACKED_DOMAINS: usize = 5_000;

// ─── DNS question parser (minimal, no external crate) ───

/// Extract the queried domain name from a raw DNS packet.
/// Returns None if the packet is too short or malformed.
/// Extract the queried domain name from a raw DNS packet.
/// Returns None if the packet is too short or malformed.
/// Public for fuzz target access.
pub fn parse_dns_question(packet: &[u8]) -> Option<String> {
    // DNS header is 12 bytes. Question section starts after that.
    if packet.len() < 13 {
        return None;
    }
    // QDCOUNT at bytes 4-5. We only care about the first question.
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }
        // Pointer compression (0xC0) — shouldn't appear in questions but guard
        if len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&packet[pos..pos + len])
                .ok()?
                .to_lowercase(),
        );
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Split a domain into (subdomain_labels, base_domain).
/// "a1b2.c3d4.attacker.com" → ("a1b2.c3d4", "attacker.com")
/// "api.github.com" → ("api", "github.com")
/// "example.com" → ("", "example.com")
fn split_domain(domain: &str) -> (&str, &str) {
    let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
    if parts.len() < 2 {
        return ("", domain);
    }
    // parts (reversed): [tld, sld, rest]
    // base = sld.tld
    let base_end = parts[0].len() + 1 + parts[1].len(); // "com" + "." + "example"
    let base_start = domain.len() - base_end;
    let base = &domain[base_start..];
    if base_start > 0 {
        // subdomain is everything before the dot preceding base
        let sub = &domain[..base_start.saturating_sub(1)];
        (sub, base)
    } else {
        ("", base)
    }
}

// ─── Sliding window tracker ───

/// Tracks unique subdomains seen for a single base domain within the sliding window.
struct DomainWindow {
    /// (subdomain, timestamp) entries within the window.
    entries: Vec<(String, Instant)>,
}

impl DomainWindow {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a subdomain query. Returns the current unique subdomain count
    /// within the window after adding this entry.
    fn record(&mut self, subdomain: &str, now: Instant) -> usize {
        // Expire old entries
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts) < window_duration());
        self.entries.push((subdomain.to_string(), now));
        // Count unique subdomains
        let uniques: HashSet<&str> = self.entries.iter().map(|(s, _)| s.as_str()).collect();
        uniques.len()
    }

    /// Check if the window is idle (all entries expired). Used for cleanup.
    fn is_idle(&self, now: Instant) -> bool {
        self.entries
            .last()
            .map(|(_, ts)| now.duration_since(*ts) >= window_duration())
            .unwrap_or(true)
    }
}

// ─── Global sliding window (cross-domain burst detection) ───

struct GlobalWindow {
    /// (full_domain, timestamp) entries.
    entries: Vec<(String, Instant)>,
}

impl GlobalWindow {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn record(&mut self, domain: &str, now: Instant) -> usize {
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts) < window_duration());
        self.entries.push((domain.to_string(), now));
        let uniques: HashSet<&str> = self.entries.iter().map(|(s, _)| s.as_str()).collect();
        uniques.len()
    }
}

// ─── Tier classification result ───

/// The governance tier assigned to a DNS query, determining the delay applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTier {
    /// Known domain — free pass, no delay.
    Known,
    /// Unknown domain, first encounter — short delay + log.
    Unknown,
    /// Repeated anomalous pattern on unknown base domain — medium delay + alert.
    Anomalous,
    /// Query flood — long delay + alert.
    Flood,
}

impl DnsTier {
    pub fn delay(&self) -> Duration {
        match self {
            DnsTier::Known => Duration::ZERO,
            DnsTier::Unknown => TIER2_DELAY,
            DnsTier::Anomalous => TIER3_DELAY,
            DnsTier::Flood => TIER4_DELAY,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            DnsTier::Known => "known",
            DnsTier::Unknown => "unknown",
            DnsTier::Anomalous => "anomalous",
            DnsTier::Flood => "flood",
        }
    }
}

/// Full classification result with audit-relevant window state.
/// Satisfies Code Standard 4.5 ("No Hidden State"): every decision-relevant
/// input is captured so an auditor can reproduce *why* this tier was assigned.
#[derive(Debug, Clone)]
pub struct DnsClassification {
    pub tier: DnsTier,
    pub domain: String,
    pub base_domain: String,
    /// Unique subdomain count on the base domain within the sliding window
    /// at the moment of classification. 0 for Tier 1/2.
    pub unique_subdomain_count: usize,
    /// Global unique query count across all domains within the window.
    pub global_unique_count: usize,
    /// Age (seconds) of the oldest entry in the per-domain window.
    /// Tells the auditor how far into the window the burst extends.
    pub window_age_secs: u64,
}

// ─── DNS Governance Engine ───

pub struct DnsGovernance {
    /// Known (learned) hosts — queries to these get Tier 1 (free pass).
    /// Shared with SRR known_hosts via Arc<RwLock>.
    known_hosts: Arc<std::sync::RwLock<HashSet<String>>>,
    /// Per-base-domain sliding window trackers.
    domain_windows: Mutex<HashMap<String, DomainWindow>>,
    /// Global sliding window for cross-domain burst detection.
    global_window: Mutex<GlobalWindow>,
    /// Monotonic counter for periodic cleanup.
    query_count: std::sync::atomic::AtomicU64,
}

impl DnsGovernance {
    pub fn new(known_hosts: Arc<std::sync::RwLock<HashSet<String>>>) -> Self {
        Self {
            known_hosts,
            domain_windows: Mutex::new(HashMap::new()),
            global_window: Mutex::new(GlobalWindow::new()),
            query_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Classify a DNS query and return the full classification with audit state.
    ///
    /// This is synchronous (std::sync::Mutex, not tokio::sync::Mutex) because
    /// no I/O happens under lock — only in-memory HashMap lookups and Vec
    /// retain/push. Code Standard 5.3 prohibits tokio::sync::Mutex on hot
    /// paths; DNS classify() is called on every DNS query.
    pub fn classify(&self, domain: &str) -> DnsClassification {
        let now = Instant::now();

        // Normalize: lowercase + strip trailing dot (DNS root label).
        // This prevents case-based bypass (ATTACKER.COM vs attacker.com)
        // and ensures consistent keying in the sliding window HashMap.
        let domain = domain.to_ascii_lowercase();
        let domain = domain.strip_suffix('.').unwrap_or(&domain);

        let (subdomain, base) = split_domain(domain);

        // Tier 1: known host — free pass
        if self.is_known(domain) {
            return DnsClassification {
                tier: DnsTier::Known,
                domain: domain.to_string(),
                base_domain: base.to_string(),
                unique_subdomain_count: 0,
                global_unique_count: 0,
                window_age_secs: 0,
            };
        }

        // Acquire both locks. Code Standard 5.2 says "never hold two locks
        // simultaneously." We satisfy this by acquiring global_window first,
        // extracting the count, then dropping it before acquiring
        // domain_windows. The two scopes are sequential, not nested.
        let global_uniques = {
            let mut global = match self.global_window.lock() {
                Ok(g) => g,
                Err(_) => {
                    tracing::error!("DNS global_window mutex poisoned — fail-open");
                    return DnsClassification {
                        tier: DnsTier::Unknown,
                        domain: domain.to_string(),
                        base_domain: base.to_string(),
                        unique_subdomain_count: 0,
                        global_unique_count: 0,
                        window_age_secs: 0,
                    };
                }
            };
            global.record(domain, now)
        }; // global lock dropped here

        // Tier 4 check: global unique query flood
        if global_uniques > TIER4_GLOBAL_THRESHOLD {
            tracing::warn!(
                domain = domain,
                unique_queries = global_uniques,
                window_secs = window_duration().as_secs(),
                "DNS flood detected — Tier 4 (10s delay)"
            );
            return DnsClassification {
                tier: DnsTier::Flood,
                domain: domain.to_string(),
                base_domain: base.to_string(),
                unique_subdomain_count: 0,
                global_unique_count: global_uniques,
                window_age_secs: 0,
            };
        }

        // Tier 3 check: repeated unique subdomains on the same unknown base domain
        if !subdomain.is_empty() {
            let mut windows = match self.domain_windows.lock() {
                Ok(w) => w,
                Err(_) => {
                    tracing::error!("DNS domain_windows mutex poisoned — fail-open");
                    return DnsClassification {
                        tier: DnsTier::Unknown,
                        domain: domain.to_string(),
                        base_domain: base.to_string(),
                        unique_subdomain_count: 0,
                        global_unique_count: global_uniques,
                        window_age_secs: 0,
                    };
                }
            };

            // Periodic cleanup
            let count = self
                .query_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count.is_multiple_of(500) {
                let before = windows.len();
                windows.retain(|_, w| !w.is_idle(now));
                if windows.len() < before {
                    tracing::debug!(
                        evicted = before - windows.len(),
                        "DNS domain windows cleanup"
                    );
                }
                if windows.len() >= MAX_TRACKED_DOMAINS {
                    let oldest: Vec<String> = windows
                        .iter()
                        .filter_map(|(k, w)| w.entries.last().map(|(_, ts)| (k.clone(), *ts)))
                        .collect::<Vec<_>>()
                        .into_iter()
                        .take(windows.len() / 4)
                        .map(|(k, _)| k)
                        .collect();
                    for k in &oldest {
                        windows.remove(k);
                    }
                }
            }

            let window = windows
                .entry(base.to_string())
                .or_insert_with(DomainWindow::new);
            let unique_count = window.record(subdomain, now);

            // Window age: how old is the oldest surviving entry?
            let window_age_secs = window
                .entries
                .first()
                .map(|(_, ts)| now.duration_since(*ts).as_secs())
                .unwrap_or(0);

            if unique_count > TIER3_UNIQUE_THRESHOLD {
                tracing::warn!(
                    base_domain = base,
                    subdomain = subdomain,
                    unique_subdomains = unique_count,
                    window_secs = window_duration().as_secs(),
                    "DNS subdomain burst detected — Tier 3 (3s delay)"
                );
                return DnsClassification {
                    tier: DnsTier::Anomalous,
                    domain: domain.to_string(),
                    base_domain: base.to_string(),
                    unique_subdomain_count: unique_count,
                    global_unique_count: global_uniques,
                    window_age_secs,
                };
            }

            // Tier 2 with subdomain context
            tracing::info!(domain = domain, "DNS unknown domain — Tier 2 (200ms delay)");
            return DnsClassification {
                tier: DnsTier::Unknown,
                domain: domain.to_string(),
                base_domain: base.to_string(),
                unique_subdomain_count: unique_count,
                global_unique_count: global_uniques,
                window_age_secs,
            };
        }

        // Tier 2: unknown domain, no subdomain
        tracing::info!(domain = domain, "DNS unknown domain — Tier 2 (200ms delay)");
        DnsClassification {
            tier: DnsTier::Unknown,
            domain: domain.to_string(),
            base_domain: base.to_string(),
            unique_subdomain_count: 0,
            global_unique_count: global_uniques,
            window_age_secs: 0,
        }
    }

    /// Check if a domain (or its base domain) is in the known hosts set.
    fn is_known(&self, domain: &str) -> bool {
        let hosts = match self.known_hosts.read() {
            Ok(h) => h,
            Err(_) => return false, // fail-open for known check (fail-close would block everything)
        };
        // Exact match
        if hosts.contains(domain) {
            return true;
        }
        // Base domain match: "api.github.com" known if "github.com" is known
        let (_, base) = split_domain(domain);
        if base != domain && hosts.contains(base) {
            return true;
        }
        // Suffix match: "v1.api.stripe.com" known if "api.stripe.com" is known
        // Walk up the domain labels
        let mut d = domain;
        while let Some(pos) = d.find('.') {
            d = &d[pos + 1..];
            if hosts.contains(d) {
                return true;
            }
        }
        false
    }
}

// ─── UDP DNS Proxy ───

/// Run the DNS governance proxy. Binds to `listen_addr`, forwards to `upstream`.
/// Each query is classified and delayed according to its tier before forwarding.
///
/// This function runs forever (until the task is cancelled).
pub async fn run_dns_proxy(
    listen_addr: SocketAddr,
    upstream: SocketAddr,
    governance: Arc<DnsGovernance>,
    ledger: Arc<crate::ledger::Ledger>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    tracing::info!(
        listen = %listen_addr,
        upstream = %upstream,
        "DNS governance proxy started"
    );

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "DNS recv error");
                continue;
            }
        };

        let packet = buf[..len].to_vec();
        let governance = governance.clone();
        let ledger = ledger.clone();
        let upstream_addr = upstream;
        // Share the listen socket so responses go back from the same
        // address:port the sandbox sent the query to. If we used a
        // new socket (random port), the response's source address
        // wouldn't match what the sandbox firewall allows (only
        // host_ip:53 or the DNAT'd host_ip:5353 — new random ports
        // are dropped by the OUTPUT chain's ESTABLISHED,RELATED rule
        // or simply don't reach the sandbox).
        let reply_socket = socket.clone();

        tokio::spawn(async move {
            let domain = parse_dns_question(&packet).unwrap_or_default();

            if domain.is_empty() {
                // Can't parse — forward without governance (fail-open for DNS)
                if let Err(e) = forward_dns(&packet, src, upstream_addr, &reply_socket).await {
                    tracing::debug!(error = %e, "DNS forward failed (unparseable)");
                }
                return;
            }

            // Layer 0: DNS classification (synchronous — no I/O under lock)
            let classification = governance.classify(&domain);
            let delay = classification.tier.delay();

            // WAL audit entry for non-known queries, including window state
            // snapshot so auditors can reproduce *why* this tier was assigned
            // (Code Standard 4.5 — No Hidden State).
            if classification.tier != DnsTier::Known {
                let event = crate::ledger::build_dns_event(
                    &classification.domain,
                    classification.tier.label(),
                    delay,
                    classification.unique_subdomain_count,
                    classification.global_unique_count,
                    classification.window_age_secs,
                    &classification.base_domain,
                );
                if matches!(classification.tier, DnsTier::Flood | DnsTier::Anomalous) {
                    // Durable WAL for high-tier events (IC-2)
                    let _ = ledger.append_durable(&event).await;
                } else {
                    // Async WAL for Tier 2 (IC-1, loss tolerated)
                    ledger.append_async(event).await;
                }
            }

            // Apply delay
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            // Forward to upstream and relay response via the listen socket
            if let Err(e) = forward_dns(&packet, src, upstream_addr, &reply_socket).await {
                tracing::debug!(error = %e, domain = domain, "DNS forward failed");
            }
        });
    }
}

/// Forward a DNS packet to upstream and relay the response back to the client.
///
/// The `reply_socket` MUST be the same socket that received the query (the
/// listen socket, shared via Arc). The sandbox's iptables only allows traffic
/// from/to host_ip:5353 — a response from a random ephemeral port would be
/// silently dropped by the sandbox OUTPUT chain's ESTABLISHED,RELATED rule.
async fn forward_dns(
    query: &[u8],
    client: SocketAddr,
    upstream: SocketAddr,
    reply_socket: &UdpSocket,
) -> anyhow::Result<()> {
    // Each query gets its own ephemeral socket for the upstream leg so
    // concurrent queries don't interleave responses.
    let fwd_socket = UdpSocket::bind("0.0.0.0:0").await?;
    fwd_socket.send_to(query, upstream).await?;

    let mut resp_buf = vec![0u8; 4096];
    let recv = tokio::time::timeout(Duration::from_secs(5), fwd_socket.recv_from(&mut resp_buf));
    let (resp_len, _) = recv.await??;

    // Reply via the listen socket so the source address matches what the
    // sandbox expects (host_ip:5353 after DNAT reversal).
    reply_socket.send_to(&resp_buf[..resp_len], client).await?;

    Ok(())
}

/// Resolve the upstream DNS server address for forwarding.
/// Checks `GVM_DNS_TARGET` env var, then resolv.conf, falls back to 8.8.8.8.
pub fn resolve_upstream_dns() -> SocketAddr {
    if let Ok(target) = std::env::var("GVM_DNS_TARGET") {
        if let Ok(addr) = target.parse::<SocketAddr>() {
            return addr;
        }
        if let Ok(ip) = target.parse::<std::net::IpAddr>() {
            return SocketAddr::new(ip, 53);
        }
    }

    // Try resolv.conf
    for path in &["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if let Some(ip_str) = line.strip_prefix("nameserver") {
                    let ip_str = ip_str.trim();
                    // Skip loopback (systemd-resolved stub)
                    if ip_str == "127.0.0.53" || ip_str == "127.0.0.1" || ip_str == "::1" {
                        continue;
                    }
                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                        return SocketAddr::new(ip, 53);
                    }
                }
            }
        }
    }

    // Fallback
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
        53,
    )
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_question_simple() {
        // DNS query for "example.com" type A class IN
        let mut packet = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        // Question: example.com
        packet.push(7); // label length
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0); // end of name
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN

        assert_eq!(parse_dns_question(&packet), Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_question_subdomain() {
        let mut packet = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // a1b2c3.attacker.com
        packet.push(6);
        packet.extend_from_slice(b"a1b2c3");
        packet.push(8);
        packet.extend_from_slice(b"attacker");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        assert_eq!(
            parse_dns_question(&packet),
            Some("a1b2c3.attacker.com".to_string())
        );
    }

    #[test]
    fn test_parse_dns_question_too_short() {
        assert_eq!(parse_dns_question(&[0; 5]), None);
    }

    #[test]
    fn test_split_domain() {
        assert_eq!(split_domain("api.github.com"), ("api", "github.com"));
        assert_eq!(
            split_domain("a1b2.c3d4.attacker.com"),
            ("a1b2.c3d4", "attacker.com")
        );
        assert_eq!(split_domain("example.com"), ("", "example.com"));
    }

    #[test]
    fn test_domain_window_decay() {
        let mut w = DomainWindow::new();
        let start = Instant::now();
        // Add 6 unique subdomains (over threshold)
        for i in 0..6 {
            w.record(&format!("sub{}", i), start);
        }
        assert!(w.record("sub6", start) > TIER3_UNIQUE_THRESHOLD);

        // After window expires, count should reset
        let future = start + window_duration() + Duration::from_secs(1);
        let count = w.record("newsub", future);
        assert_eq!(
            count, 1,
            "Window should have decayed — only the new entry remains"
        );
    }

    #[test]
    fn test_known_host_free_pass() {
        let hosts = Arc::new(std::sync::RwLock::new(HashSet::from([
            "api.github.com".to_string(),
            "httpbin.org".to_string(),
        ])));
        let gov = DnsGovernance::new(hosts);

        assert_eq!(gov.classify("api.github.com").tier, DnsTier::Known);
        assert_eq!(gov.classify("httpbin.org").tier, DnsTier::Known);
        // Suffix match: sub.httpbin.org is known because httpbin.org is
        assert_eq!(gov.classify("sub.httpbin.org").tier, DnsTier::Known);
        // Unknown
        assert_eq!(gov.classify("evil.com").tier, DnsTier::Unknown);
        // Case-insensitive: HTTPBIN.ORG should match known httpbin.org
        assert_eq!(gov.classify("HTTPBIN.ORG").tier, DnsTier::Known);
        assert_eq!(gov.classify("Api.GitHub.COM").tier, DnsTier::Known);
        // Trailing dot normalization (DNS root label)
        assert_eq!(gov.classify("httpbin.org.").tier, DnsTier::Known);
    }

    #[test]
    fn test_case_insensitive_counting() {
        // ATTACKER.COM and attacker.com must count as the same base domain
        let hosts = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let gov = DnsGovernance::new(hosts);

        for i in 0..3 {
            gov.classify(&format!("sub{}.ATTACKER.COM", i));
        }
        for i in 3..=TIER3_UNIQUE_THRESHOLD + 1 {
            gov.classify(&format!("sub{}.attacker.com", i));
        }
        // Should trigger Tier 3 because all queries hit the same normalized base
        let c = gov.classify("another.Attacker.Com");
        assert_eq!(
            c.tier,
            DnsTier::Anomalous,
            "Mixed-case domains must be normalized to the same base for counting"
        );
    }

    #[test]
    fn test_tier3_subdomain_burst() {
        let hosts = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let gov = DnsGovernance::new(hosts);

        // Send 6 unique subdomains to the same base domain
        for i in 0..=TIER3_UNIQUE_THRESHOLD {
            let domain = format!("sub{}.attacker.com", i);
            gov.classify(&domain);
        }
        // Next query should trigger Tier 3
        let c = gov.classify("sub99.attacker.com");
        assert_eq!(c.tier, DnsTier::Anomalous);
        assert!(
            c.unique_subdomain_count > TIER3_UNIQUE_THRESHOLD,
            "WAL audit context must capture the subdomain count"
        );
    }

    #[test]
    fn test_tier3_decay_to_tier2() {
        let hosts = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let gov = DnsGovernance::new(hosts);

        // Trigger Tier 3
        for i in 0..=TIER3_UNIQUE_THRESHOLD + 2 {
            let domain = format!("sub{}.attacker.com", i);
            gov.classify(&domain);
        }
        let c = gov.classify("another.attacker.com");
        assert_eq!(c.tier, DnsTier::Anomalous, "Should be Tier 3 during burst");

        // Manually expire the window entries to simulate time passing
        {
            let mut windows = gov.domain_windows.lock().unwrap();
            if let Some(w) = windows.get_mut("attacker.com") {
                w.entries.clear(); // simulate full window expiry
            }
        }

        // After decay, should be back to Tier 2 (unknown, not anomalous)
        let c = gov.classify("fresh.attacker.com");
        assert_eq!(
            c.tier,
            DnsTier::Unknown,
            "Should decay back to Tier 2 after window expires"
        );
    }
}
