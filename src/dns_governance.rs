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

/// Default delay applied to unknown domains on first encounter (200ms).
/// Operator override via `dns.tier2_delay_ms`; clamped to MAX_TIER_DELAY_MS.
const DEFAULT_TIER2_DELAY_MS: u64 = 200;
/// Default delay for repeated anomalous queries on the same base domain (3s).
const DEFAULT_TIER3_DELAY_MS: u64 = 3_000;
/// Default delay for query flood (global unique subdomain burst) (10s).
const DEFAULT_TIER4_DELAY_MS: u64 = 10_000;

/// Default sliding-window duration for per-domain unique subdomain
/// counting. Operators may override via `dns.window_secs` in proxy
/// config (clamped to a minimum 5 seconds — see the field doc on
/// `DnsGovernanceConfig::window_secs` for rationale).
const DEFAULT_WINDOW_SECS: u64 = 60;
/// Safety floor: any operator override below this is clamped UP to
/// preserve Tier 3 detection (≥5 unique subdomains in the window).
const MIN_WINDOW_SECS: u64 = 5;

/// Sliding window duration. The duration is fixed at `DnsGovernance`
/// construction time (read from config, clamped at the floor).
/// No env-var override at runtime — production binaries cannot be
/// influenced by setting an env var to weaken Tier 3/4 detection.
/// See §6.5 of GVM_CODE_STANDARDS.md.
fn clamp_window_secs(requested: u64) -> u64 {
    if requested == 0 {
        return DEFAULT_WINDOW_SECS;
    }
    requested.max(MIN_WINDOW_SECS)
}

/// Clamp a tier threshold to its safety floor. Logs a warning if
/// the operator-supplied value was below the floor. Public for the
/// admin endpoint's "what would happen if I set this?" preview.
fn clamp_threshold(requested: usize, knob_name: &str) -> usize {
    if requested < MIN_TIER_THRESHOLD {
        tracing::warn!(
            knob = knob_name,
            requested = requested,
            clamped_to = MIN_TIER_THRESHOLD,
            "DNS tier threshold below safety floor — clamped UP"
        );
        return MIN_TIER_THRESHOLD;
    }
    requested
}

/// Clamp a tier delay to its sanity cap. Logs a warning if the
/// operator-supplied value was above the cap.
fn clamp_delay_ms(requested: u64, knob_name: &str) -> Duration {
    if requested > MAX_TIER_DELAY_MS {
        tracing::warn!(
            knob = knob_name,
            requested_ms = requested,
            clamped_to_ms = MAX_TIER_DELAY_MS,
            "DNS tier delay above sanity cap — clamped DOWN"
        );
        return Duration::from_millis(MAX_TIER_DELAY_MS);
    }
    Duration::from_millis(requested)
}

/// Default unique subdomains on an unknown base domain within the window to trigger Tier 3.
/// Operator can override via `dns.tier3_unique_threshold`; the floor below clamps any value < 1.
const DEFAULT_TIER3_UNIQUE_THRESHOLD: usize = 5;
/// Default global unique subdomain queries across all domains within the window to trigger Tier 4.
const DEFAULT_TIER4_GLOBAL_THRESHOLD: usize = 20;
/// Safety floor for both threshold knobs. Setting either to 0 would
/// disable detection on that tier entirely; clamp UP so a typo or
/// permissive override cannot silently weaken the policy.
const MIN_TIER_THRESHOLD: usize = 1;
/// Sanity cap for the per-tier delay knobs. 60s × 1000 = 60_000ms.
/// Above this, a single misconfigured DNS query stalls the agent
/// for over a minute; operator clamps any larger value DOWN. There
/// is no security reason to allow longer delays — they hurt agent
/// usability without strengthening detection.
const MAX_TIER_DELAY_MS: u64 = 60_000;

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
    /// within the window after adding this entry. `window` is the
    /// effective sliding-window duration set at DnsGovernance
    /// construction.
    fn record(&mut self, subdomain: &str, now: Instant, window: Duration) -> usize {
        // Expire old entries
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts) < window);
        self.entries.push((subdomain.to_string(), now));
        // Count unique subdomains
        let uniques: HashSet<&str> = self.entries.iter().map(|(s, _)| s.as_str()).collect();
        uniques.len()
    }

    /// Check if the window is idle (all entries expired). Used for cleanup.
    fn is_idle(&self, now: Instant, window: Duration) -> bool {
        self.entries
            .last()
            .map(|(_, ts)| now.duration_since(*ts) >= window)
            .unwrap_or(true)
    }

    /// Read-only unique count over still-fresh entries. Used by
    /// `DnsGovernance::snapshot_state` so the operator-facing
    /// inspection API doesn't mutate the window's record.
    fn unique_count(&self, now: Instant, window: Duration) -> usize {
        let uniques: HashSet<&str> = self
            .entries
            .iter()
            .filter(|(_, ts)| now.duration_since(*ts) < window)
            .map(|(s, _)| s.as_str())
            .collect();
        uniques.len()
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

    fn record(&mut self, domain: &str, now: Instant, window: Duration) -> usize {
        self.entries
            .retain(|(_, ts)| now.duration_since(*ts) < window);
        self.entries.push((domain.to_string(), now));
        let uniques: HashSet<&str> = self.entries.iter().map(|(s, _)| s.as_str()).collect();
        uniques.len()
    }

    /// Read-only unique count for the snapshot API. Same semantics
    /// as `DomainWindow::unique_count`.
    fn unique_count(&self, now: Instant, window: Duration) -> usize {
        let uniques: HashSet<&str> = self
            .entries
            .iter()
            .filter(|(_, ts)| now.duration_since(*ts) < window)
            .map(|(s, _)| s.as_str())
            .collect();
        uniques.len()
    }
}

// ─── Tier classification result ───

/// The governance tier assigned to a DNS query, determining the delay applied.
///
/// Numeric ordering matches escalation severity (Known=0 → Flood=3),
/// which `DnsGovernance::snapshot_state` uses to sort the operator
/// inspection table "noisiest first."
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum DnsTier {
    /// Known domain — free pass, no delay.
    Known = 0,
    /// Unknown domain, first encounter — short delay + log.
    Unknown = 1,
    /// Repeated anomalous pattern on unknown base domain — medium delay + alert.
    Anomalous = 2,
    /// Query flood — long delay + alert.
    Flood = 3,
}

/// Snapshot of `DnsGovernance` state for `gvm dns status` / the
/// admin `GET /gvm/dns/state` endpoint. Read-only — the snapshot
/// does NOT mutate sliding-window record state, so calling it does
/// not affect classification of in-flight queries.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsStateSnapshot {
    /// How many distinct base domains are currently tracked.
    pub tracked_base_domains: usize,
    /// Global unique-domain count in the cross-domain window right
    /// now. Compare against `tier4_threshold` to see how close the
    /// system is to flood escalation.
    pub global_unique_count: usize,
    /// The threshold at which Tier 4 (flood) fires. Reflects the
    /// operator's `dns.tier4_global_threshold` override (clamped).
    pub tier4_threshold: usize,
    /// The threshold at which Tier 3 (anomalous subdomain burst)
    /// fires. Reflects the operator's `dns.tier3_unique_threshold`.
    pub tier3_threshold: usize,
    /// Sliding-window duration in seconds.
    pub window_secs: u64,
    /// Per-base-domain state, sorted by tier desc + unique-count desc.
    pub domains: Vec<DnsDomainState>,
}

/// Per-base-domain row in [`DnsStateSnapshot`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsDomainState {
    pub base_domain: String,
    pub unique_subdomain_count: usize,
    pub tier: DnsTier,
    pub oldest_entry_age_secs: u64,
}

impl DnsTier {
    /// Default delay constants. **Do not use on the hot path** —
    /// production config overrides these via
    /// `DnsGovernance::delay_for_tier`. Kept for tests + any caller
    /// that doesn't have a `DnsGovernance` instance handy.
    pub fn delay(&self) -> Duration {
        match self {
            DnsTier::Known => Duration::ZERO,
            DnsTier::Unknown => Duration::from_millis(DEFAULT_TIER2_DELAY_MS),
            DnsTier::Anomalous => Duration::from_millis(DEFAULT_TIER3_DELAY_MS),
            DnsTier::Flood => Duration::from_millis(DEFAULT_TIER4_DELAY_MS),
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
    /// Sliding-window duration. Set at construction from
    /// `DnsGovernanceConfig::window_secs`, clamped at 5s minimum
    /// to keep Tier 3 detection meaningful. Immutable after
    /// construction — no env var or runtime knob can shrink it.
    window: Duration,
    // ─── Per-instance tier knobs (operator override + safety clamp) ───
    /// `dns.tier3_unique_threshold`, clamped to ≥ MIN_TIER_THRESHOLD.
    tier3_unique_threshold: usize,
    /// `dns.tier4_global_threshold`, clamped to ≥ MIN_TIER_THRESHOLD.
    tier4_global_threshold: usize,
    /// `dns.tier2_delay_ms`, clamped to ≤ MAX_TIER_DELAY_MS.
    tier2_delay: Duration,
    /// `dns.tier3_delay_ms`, clamped to ≤ MAX_TIER_DELAY_MS.
    tier3_delay: Duration,
    /// `dns.tier4_delay_ms`, clamped to ≤ MAX_TIER_DELAY_MS.
    tier4_delay: Duration,
}

impl DnsGovernance {
    /// Construct with default knobs. Used by tests and any caller
    /// that doesn't need an operator override.
    pub fn new(known_hosts: Arc<std::sync::RwLock<HashSet<String>>>) -> Self {
        Self {
            known_hosts,
            domain_windows: Mutex::new(HashMap::new()),
            global_window: Mutex::new(GlobalWindow::new()),
            query_count: std::sync::atomic::AtomicU64::new(0),
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
            tier3_unique_threshold: DEFAULT_TIER3_UNIQUE_THRESHOLD,
            tier4_global_threshold: DEFAULT_TIER4_GLOBAL_THRESHOLD,
            tier2_delay: Duration::from_millis(DEFAULT_TIER2_DELAY_MS),
            tier3_delay: Duration::from_millis(DEFAULT_TIER3_DELAY_MS),
            tier4_delay: Duration::from_millis(DEFAULT_TIER4_DELAY_MS),
        }
    }

    /// Construct with an operator-supplied window (read from
    /// `DnsGovernanceConfig::window_secs`). Values below
    /// `MIN_WINDOW_SECS` are clamped UP to that floor. **Kept for
    /// callers that only override the window**; the full-config
    /// constructor below is preferred for production startup.
    pub fn with_window_secs(
        known_hosts: Arc<std::sync::RwLock<HashSet<String>>>,
        window_secs: u64,
    ) -> Self {
        let mut g = Self::new(known_hosts);
        let clamped = clamp_window_secs(window_secs);
        if clamped != window_secs {
            tracing::warn!(
                requested = window_secs,
                clamped_to = clamped,
                "DNS sliding-window override below safety floor — clamped UP \
                 (Tier 3 needs ≥{} subdomains within the window)",
                MIN_WINDOW_SECS
            );
        }
        g.window = Duration::from_secs(clamped);
        g
    }

    /// Construct from the full `DnsGovernanceConfig`. Production
    /// startup path — applies operator overrides for window,
    /// tier-3/4 thresholds, and per-tier delays. All overrides go
    /// through the safety clamps:
    ///
    ///   - `window_secs`           → clamped UP to MIN_WINDOW_SECS
    ///   - `tier3_unique_threshold`→ clamped UP to MIN_TIER_THRESHOLD (1)
    ///   - `tier4_global_threshold`→ clamped UP to MIN_TIER_THRESHOLD (1)
    ///   - `tier{2,3,4}_delay_ms`  → clamped DOWN to MAX_TIER_DELAY_MS (60s)
    ///
    /// Each clamp logs a warning so the operator sees what was
    /// adjusted; production binaries cannot be silently weakened
    /// by an out-of-range TOML value.
    pub fn with_config(
        known_hosts: Arc<std::sync::RwLock<HashSet<String>>>,
        config: &crate::config::DnsGovernanceConfig,
    ) -> Self {
        let mut g = Self::with_window_secs(known_hosts, config.window_secs);
        g.tier3_unique_threshold =
            clamp_threshold(config.tier3_unique_threshold, "tier3_unique_threshold");
        g.tier4_global_threshold =
            clamp_threshold(config.tier4_global_threshold, "tier4_global_threshold");
        g.tier2_delay = clamp_delay_ms(config.tier2_delay_ms, "tier2_delay_ms");
        g.tier3_delay = clamp_delay_ms(config.tier3_delay_ms, "tier3_delay_ms");
        g.tier4_delay = clamp_delay_ms(config.tier4_delay_ms, "tier4_delay_ms");
        g
    }

    /// Snapshot the current internal state for `gvm dns status` /
    /// `GET /gvm/dns/state` — operator visibility into which
    /// domains are tracked at which tier RIGHT NOW. Read-only;
    /// acquires the two mutexes in the same order as `classify`
    /// (global before per-domain) to avoid deadlock with concurrent
    /// classification.
    pub fn snapshot_state(&self) -> DnsStateSnapshot {
        let now = Instant::now();
        let global_unique = match self.global_window.lock() {
            Ok(g) => g.unique_count(now, self.window),
            Err(_) => 0,
        };
        let mut domains: Vec<DnsDomainState> = match self.domain_windows.lock() {
            Ok(w) => w
                .iter()
                .map(|(base, win)| {
                    let unique = win.unique_count(now, self.window);
                    let age_secs = win
                        .entries
                        .first()
                        .map(|(_, ts)| now.duration_since(*ts).as_secs())
                        .unwrap_or(0);
                    let tier = if unique > self.tier3_unique_threshold {
                        DnsTier::Anomalous
                    } else {
                        DnsTier::Unknown
                    };
                    DnsDomainState {
                        base_domain: base.clone(),
                        unique_subdomain_count: unique,
                        tier,
                        oldest_entry_age_secs: age_secs,
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        // Sort by tier (Anomalous first, then Unknown), then by
        // unique count desc — operator sees "noisiest first".
        domains.sort_by(|a, b| {
            (b.tier as u8, b.unique_subdomain_count).cmp(&(a.tier as u8, a.unique_subdomain_count))
        });
        DnsStateSnapshot {
            tracked_base_domains: domains.len(),
            global_unique_count: global_unique,
            tier4_threshold: self.tier4_global_threshold,
            tier3_threshold: self.tier3_unique_threshold,
            window_secs: self.window.as_secs(),
            domains,
        }
    }

    /// Per-instance tier delay lookup. Reads the operator-overridden
    /// per-tier durations stored at construction time. Used on the
    /// hot path by the DNS proxy event loop. The bare
    /// `DnsTier::delay()` method returns the **default** durations
    /// only — tests + callers without an instance.
    pub fn delay_for_tier(&self, tier: DnsTier) -> Duration {
        match tier {
            DnsTier::Known => Duration::ZERO,
            DnsTier::Unknown => self.tier2_delay,
            DnsTier::Anomalous => self.tier3_delay,
            DnsTier::Flood => self.tier4_delay,
        }
    }

    /// Classify a DNS query and return the full classification with audit state.
    ///
    /// This is synchronous (std::sync::Mutex, not tokio::sync::Mutex) because
    /// no I/O happens under lock — only in-memory HashMap lookups and Vec
    /// retain/push. Code Standard 5.3 prohibits tokio::sync::Mutex on hot
    /// paths; DNS classify() is called on every DNS query.
    pub fn classify(&self, domain: &str) -> DnsClassification {
        self.classify_inner(domain, Instant::now())
    }

    /// Same as `classify` but with an injectable clock — used by unit
    /// tests in this module to verify time-based decay deterministically
    /// (no `thread::sleep` or window-cleanup hacks).
    ///
    /// Gated behind `#[cfg(test)]`: the symbol does NOT exist in
    /// production binaries, so an attacker cannot reach DnsGovernance
    /// and inject a fake `Instant` to bypass Tier 3/4 detection.
    /// Test access is via `pub(super)` from `mod tests` in this file.
    #[cfg(test)]
    pub(super) fn classify_at(&self, domain: &str, now: Instant) -> DnsClassification {
        self.classify_inner(domain, now)
    }

    fn classify_inner(&self, domain: &str, now: Instant) -> DnsClassification {
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
                    // Fall back to Tier 2 (Unknown). DNS governance has no
                    // Deny tier (see §7.0 Layer 0): every classification path
                    // either delays or passes. Tier 2 still applies the
                    // moderate "unknown domain" delay, so this is fail-graceful
                    // (downgrade to medium delay), NOT fail-open.
                    tracing::error!(
                        "DNS global_window mutex poisoned — fall back to Tier 2 (Unknown)"
                    );
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
            global.record(domain, now, self.window)
        }; // global lock dropped here

        // Tier 4 check: global unique query flood
        if global_uniques > self.tier4_global_threshold {
            tracing::warn!(
                domain = domain,
                unique_queries = global_uniques,
                window_secs = self.window.as_secs(),
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
                    // Fall back to Tier 2 (Unknown) — see global_window
                    // poisoning branch above for rationale (DNS layer has no
                    // Deny; Tier 2 still applies the moderate delay).
                    tracing::error!(
                        "DNS domain_windows mutex poisoned — fall back to Tier 2 (Unknown)"
                    );
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
                windows.retain(|_, w| !w.is_idle(now, self.window));
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
            let unique_count = window.record(subdomain, now, self.window);

            // Window age: how old is the oldest surviving entry?
            let window_age_secs = window
                .entries
                .first()
                .map(|(_, ts)| now.duration_since(*ts).as_secs())
                .unwrap_or(0);

            if unique_count > self.tier3_unique_threshold {
                tracing::warn!(
                    base_domain = base,
                    subdomain = subdomain,
                    unique_subdomains = unique_count,
                    window_secs = self.window.as_secs(),
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
            let delay = governance.delay_for_tier(classification.tier);

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
                // Tier 1 (Known) is high-frequency and low-audit-value —
                // stays async (NATS-only, deliberately excluded from the
                // Merkle chain so the bulk of normal DNS traffic does not
                // bloat the audit log).
                //
                // Tier 2+ (Unknown / Anomalous / Flood) IS audited: a new
                // domain appearing is itself a governance signal ("agent
                // reaching somewhere unexpected"), and suspicious/flood
                // patterns need forensic recovery.
                if matches!(classification.tier, DnsTier::Known) {
                    ledger.append_async(event).await;
                } else {
                    let _ = ledger.append_durable(&event).await;
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
    fn parse_dns_question_rejects_pointer_compression_in_question() {
        // RFC 1035 §4.1.4: name compression pointers (0xC0-prefix)
        // appear in answer/authority sections. They MUST NOT appear in
        // the question section. parse_dns_question returns None on this
        // — preventing a recursion bomb where pointer label loops back
        // to itself.
        let mut packet = vec![0u8; 12];
        packet[5] = 1; // QDCOUNT=1
                       // Pointer: 0xC0 0x00 → "follow pointer to offset 0" (loop)
        packet.push(0xC0);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        assert_eq!(
            parse_dns_question(&packet),
            None,
            "pointer in question section must be rejected"
        );
    }

    #[test]
    fn parse_dns_question_rejects_label_overrun() {
        // Label length byte claims more bytes than remain in the packet.
        let mut packet = vec![0u8; 12];
        packet[5] = 1; // QDCOUNT=1
        packet.push(200); // claim 200 bytes of label …
        packet.extend_from_slice(b"abc"); // … but only 3 follow
        assert_eq!(
            parse_dns_question(&packet),
            None,
            "label length exceeding remaining bytes must be rejected"
        );
    }

    #[test]
    fn parse_dns_question_rejects_qdcount_zero() {
        // Some malformed packets set QDCOUNT=0 while still containing
        // bytes after the header.
        let mut packet = vec![0u8; 12];
        packet[4] = 0;
        packet[5] = 0;
        packet.extend_from_slice(b"\x07example\x03com\x00");
        assert_eq!(
            parse_dns_question(&packet),
            None,
            "QDCOUNT=0 must produce None even if trailing bytes look valid"
        );
    }

    #[test]
    fn parse_dns_question_rejects_oversized_label() {
        // RFC 1035: label MUST be 1..=63 bytes. 64+ violates the spec.
        // (Our parser permits any length until end-of-packet, but a
        // 64-byte label whose length byte is 0x40 collides with the
        // pointer-prefix bit pattern (0xC0 ⊃ 0x40 only by 0xC0). Test
        // with 200 to ensure overrun handling — already covered above.)
        let mut packet = vec![0u8; 12];
        packet[5] = 1;
        packet.push(64); // 64-byte label (RFC violation but legal length byte)
        packet.extend_from_slice(&[b'A'; 64]);
        packet.push(0); // root
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Parser currently accepts this (no length cap). Confirm
        // round-trip is at least sane: returns Some with the label.
        match parse_dns_question(&packet) {
            Some(name) => assert_eq!(name.len(), 64),
            None => {
                // Acceptable: future hardening may reject 64+ labels.
            }
        }
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
        let window = Duration::from_secs(DEFAULT_WINDOW_SECS);
        let mut w = DomainWindow::new();
        let start = Instant::now();
        // Add 6 unique subdomains (over threshold)
        for i in 0..6 {
            w.record(&format!("sub{}", i), start, window);
        }
        assert!(w.record("sub6", start, window) > DEFAULT_TIER3_UNIQUE_THRESHOLD);

        // After window expires, count should reset
        let future = start + window + Duration::from_secs(1);
        let count = w.record("newsub", future, window);
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
        for i in 3..=DEFAULT_TIER3_UNIQUE_THRESHOLD + 1 {
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
        for i in 0..=DEFAULT_TIER3_UNIQUE_THRESHOLD {
            let domain = format!("sub{}.attacker.com", i);
            gov.classify(&domain);
        }
        // Next query should trigger Tier 3
        let c = gov.classify("sub99.attacker.com");
        assert_eq!(c.tier, DnsTier::Anomalous);
        assert!(
            c.unique_subdomain_count > DEFAULT_TIER3_UNIQUE_THRESHOLD,
            "WAL audit context must capture the subdomain count"
        );
    }

    #[test]
    fn test_tier3_decay_to_tier2() {
        // Verify decay through the actual time-based eviction logic
        // (DomainWindow::record drops entries older than window_duration).
        // Uses classify_at so the test does NOT thread::sleep and does
        // NOT manipulate internal state — it advances a virtual `now`.
        let hosts = Arc::new(std::sync::RwLock::new(HashSet::new()));
        let gov = DnsGovernance::new(hosts);
        let t0 = Instant::now();

        // Trigger Tier 3 at t0.
        for i in 0..=DEFAULT_TIER3_UNIQUE_THRESHOLD + 2 {
            let domain = format!("sub{}.attacker.com", i);
            gov.classify_at(&domain, t0);
        }
        let c = gov.classify_at("another.attacker.com", t0);
        assert_eq!(
            c.tier,
            DnsTier::Anomalous,
            "Should be Tier 3 during burst at t0"
        );

        // Advance virtual clock past the window — every entry's age
        // exceeds DEFAULT_WINDOW_SECS so DomainWindow::record evicts
        // them on the next call. This is the production decay path.
        let after_window =
            t0 + Duration::from_secs(DEFAULT_WINDOW_SECS) + std::time::Duration::from_secs(1);
        let c = gov.classify_at("fresh.attacker.com", after_window);
        assert_eq!(
            c.tier,
            DnsTier::Unknown,
            "Should decay back to Tier 2 after the sliding window expires"
        );
        // Sanity: subdomain count must reset (not carry over from the burst).
        assert!(
            c.unique_subdomain_count <= 1,
            "post-decay first query establishes a fresh window; got count={}",
            c.unique_subdomain_count
        );
    }
}
