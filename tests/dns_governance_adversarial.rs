//! DNS governance adversarial regression suite — Phase 2 of the pentest plan.
//!
//! Targets the engine surface at `gvm_proxy::dns_governance::DnsGovernance`
//! (production: `src/dns_governance.rs`). All tests are pure-Rust and run on
//! every platform — no sandbox, no root required. The end-to-end DNAT path
//! through a live sandbox is covered separately by
//! `scripts/dns-bypass-pentest.sh`.
//!
//! Threat coverage:
//!   - Tier 4 (flood) trigger via global unique-query threshold
//!   - Tier 3 (anomalous) trigger via subdomain enumeration burst on one base
//!   - Parser rejects malformed and adversarially-crafted DNS packets
//!   - Parser rejects pointer-compression in the question section (known
//!     unsupported attack surface — guards against parser-quirk bypasses)
//!   - Case-variant normalization: `EVIL.COM` and `evil.com` share a window
//!     slot (otherwise an attacker mixes cases to dilute Tier 3 counters)
//!   - IDN-homograph distinct classification: Cyrillic `еvil.com` and Latin
//!     `evil.com` are different domains. Documents the current behavior so a
//!     future "normalize IDN" change doesn't silently break it without a test
//!     update.

use gvm_proxy::dns_governance::{parse_dns_question, DnsGovernance, DnsTier};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Build a fresh `DnsGovernance` engine with no known hosts and default knobs.
///
/// Each test calls this in isolation — the sliding-window state is per-engine,
/// so cross-test pollution is impossible by construction.
fn fresh_engine() -> DnsGovernance {
    let hosts = Arc::new(RwLock::new(HashSet::new()));
    DnsGovernance::new(hosts)
}

/// Construct a minimal valid DNS query packet for the given domain.
///
/// Layout (RFC 1035 §4.1):
///   - 12-byte header (id, flags, qdcount=1, ancount=0, nscount=0, arcount=0)
///   - Question: label-encoded name + qtype(A=1) + qclass(IN=1)
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut packet: Vec<u8> = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ];
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        assert!(bytes.len() <= 63, "label too long for test fixture");
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0x00); // null terminator
    packet.extend_from_slice(&[0x00, 0x01]); // qtype = A
    packet.extend_from_slice(&[0x00, 0x01]); // qclass = IN
    packet
}

// ─── Case 1: Tier 4 flood via global unique-query threshold ────────────────

#[test]
fn tier4_flood_global_threshold_triggers_after_burst() {
    let gov = fresh_engine();
    let snapshot = gov.snapshot_state();
    let threshold = snapshot.tier4_threshold;
    assert!(
        threshold >= 1 && threshold < 10_000,
        "tier4_threshold sanity: got {threshold}"
    );

    // Issue one classification per unique base domain. The Nth unique
    // domain where N > tier4_threshold must produce Tier::Flood.
    let mut last_tier = DnsTier::Unknown;
    let mut floods_seen = 0;
    let burst_size = threshold + 5;
    for i in 0..burst_size {
        let base = format!("attacker-flood-{i}.test");
        let result = gov.classify(&base);
        if result.tier == DnsTier::Flood {
            floods_seen += 1;
        }
        last_tier = result.tier;
    }

    assert!(
        floods_seen >= 1,
        "Expected at least one Tier::Flood classification after \
         {burst_size} unique base domains (threshold={threshold}). \
         Last observed tier: {last_tier:?}",
    );
}

// ─── Case 2: Tier 3 anomalous via subdomain burst on a single base ─────────

#[test]
fn tier3_anomalous_via_subdomain_burst() {
    let gov = fresh_engine();
    let threshold = gov.snapshot_state().tier3_threshold;
    assert!(
        threshold >= 1 && threshold < 10_000,
        "tier3_threshold sanity: got {threshold}"
    );

    // Hammer one base domain with `threshold + 1` distinct subdomains. The
    // last classification must escalate to Tier::Anomalous (or Tier::Flood
    // if the cross-domain counter happens to cross — also acceptable since
    // it represents a stricter response).
    let mut last = None;
    for i in 0..=threshold {
        let dom = format!("c2-{i}.beacon-target.test");
        last = Some(gov.classify(&dom));
    }

    let result = last.expect("at least one classification must happen");
    assert!(
        matches!(result.tier, DnsTier::Anomalous | DnsTier::Flood),
        "Expected Anomalous (or stricter Flood) after {} subdomains of one \
         base, got tier={:?}, unique_subdomain_count={}, base_domain={}",
        threshold + 1,
        result.tier,
        result.unique_subdomain_count,
        result.base_domain,
    );
    assert_eq!(
        result.base_domain, "beacon-target.test",
        "base_domain extraction must group subdomains of beacon-target.test \
         under that base (got: {})",
        result.base_domain
    );
}

// ─── Case 3: Parser rejects malformed packets ──────────────────────────────

#[test]
fn parser_rejects_malformed_packets() {
    // Each case must return `None`. A `Some(_)` here means the parser
    // accepted hostile input, which is an arbitrary-classification bypass
    // (an attacker fakes a domain string that classify() then trusts).
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("under_minimum_length", vec![0u8; 12]),
        (
            "header_claims_no_question",
            // qdcount = 0 → parser should refuse to extract a question.
            vec![
                0x00, 0x00, 0x00, 0x00, // id + flags
                0x00, 0x00, // qdcount = 0
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
                0x00, // single zero where question would start
            ],
        ),
        (
            "truncated_mid_label",
            // Header + label length 7 but packet ends before 7 bytes.
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, // header (qdcount=1)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', // claim 7-byte label, deliver 2 bytes
            ],
        ),
        (
            "label_length_exceeds_packet",
            // Length byte = 200, far beyond what's left.
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, // header
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 200, b'a', b'b', b'c',
            ],
        ),
        (
            "invalid_utf8_in_label",
            // Label bytes are not valid UTF-8.
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, // header
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xfe,
                0xfd, // garbage 3-byte label
                0x00, // null terminator
            ],
        ),
    ];

    for (name, packet) in cases {
        let result = parse_dns_question(&packet);
        assert!(
            result.is_none(),
            "parser must reject malformed packet '{name}', got Some({:?}). \
             Packet bytes: {:?}",
            result.unwrap_or_default(),
            packet,
        );
    }
}

// ─── Case 4: Parser rejects pointer compression in question section ────────

#[test]
fn parser_rejects_pointer_compression_in_question() {
    // RFC 1035 §4.1.4 allows pointer compression in responses but NOT in the
    // question section. A length byte with high two bits set (0xC0..) is a
    // compression pointer; production parser must reject it to prevent
    // crafted questions that "point at" arbitrary offsets.
    let packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, // header (qdcount = 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0xC0, 0x0C, // pointer to offset 12 (the start of question section)
        0x00, 0x01, 0x00, 0x01, // qtype, qclass
    ];
    let result = parse_dns_question(&packet);
    assert!(
        result.is_none(),
        "parser must reject pointer compression in question section, got Some({:?})",
        result.unwrap_or_default()
    );
}

// ─── Case 5: Case-variant normalization (anti-evasion) ─────────────────────

#[test]
fn case_variants_share_tier_window_slot() {
    let gov = fresh_engine();
    let threshold = gov.snapshot_state().tier3_threshold;

    // Mix case variants of subdomains under one base. If the engine did NOT
    // case-fold, an attacker could send `Sub1.evil.com`, `SUB1.evil.com`,
    // `sub1.evil.com` ... and the window would count them as 3 distinct
    // subdomains. The current engine lowercases at classify_inner() entry,
    // so all variants collapse to one slot.

    // Send the same lowercase subdomain `threshold` times in different cases —
    // unique_subdomain_count must stay at 1.
    let variants = [
        "sub.MIXED-CASE.test",
        "SUB.mixed-case.TEST",
        "Sub.Mixed-Case.Test",
    ];
    let mut last = None;
    for _ in 0..threshold {
        for v in &variants {
            last = Some(gov.classify(v));
        }
    }

    let result = last.expect("at least one classification");
    assert_eq!(
        result.base_domain, "mixed-case.test",
        "base_domain must be lowercased ({})",
        result.base_domain
    );
    assert_eq!(
        result.unique_subdomain_count, 1,
        "case variants must collapse into one subdomain slot; got count={}",
        result.unique_subdomain_count
    );
    assert!(
        !matches!(result.tier, DnsTier::Anomalous | DnsTier::Flood),
        "case-variant probing must not escalate to Anomalous/Flood \
         (got tier={:?}); a Tier 3+ result here means the case-fold \
         normalization broke and an attacker can dilute counters with case variation.",
        result.tier
    );
}

// ─── Case 6: IDN homograph — distinct classification (documented limit) ────

#[test]
fn idn_homograph_treated_as_distinct_domain() {
    // Latin `anthropic.com` and Cyrillic `аnthropic.com` (Cyrillic 'а' U+0430)
    // are visually identical but are different byte sequences. The current
    // engine does NOT perform IDN normalization — it keys the sliding window
    // by raw bytes (lowercased ASCII only). This test pins that behavior so
    // a future change that *adds* IDN normalization shows up here, prompting
    // a deliberate decision rather than a silent semantics shift.
    //
    // Security implication: an attacker can register the Cyrillic variant
    // and let it be classified independently of the genuine site. This is
    // documented as a known limitation in `docs/security-model.md`.

    let gov = fresh_engine();
    let latin = gov.classify("anthropic.com");
    let cyrillic = gov.classify("\u{0430}nthropic.com"); // Cyrillic 'а' replacing 'a'

    assert_ne!(
        latin.domain, cyrillic.domain,
        "Latin and Cyrillic variants must currently be treated as distinct \
         byte strings. If this changes, update the security-model doc."
    );
    assert_ne!(
        latin.base_domain, cyrillic.base_domain,
        "Distinct domains must yield distinct base_domain keys; got \
         latin='{}' cyrillic='{}'",
        latin.base_domain, cyrillic.base_domain
    );
}

// ─── Round-trip sanity: parser accepts well-formed queries ─────────────────

#[test]
fn parser_accepts_well_formed_query() {
    // Positive control for the malformed-packet test: the same parser must
    // still accept a valid packet, otherwise we have a regression where
    // every test in this file passes vacuously because the parser became
    // overly strict.
    let packet = build_dns_query("api.anthropic.com");
    let result = parse_dns_question(&packet);
    assert_eq!(
        result.as_deref(),
        Some("api.anthropic.com"),
        "well-formed packet must parse to its domain; got {:?}",
        result
    );
}
