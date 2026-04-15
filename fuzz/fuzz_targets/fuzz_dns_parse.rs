#![no_main]
//! Fuzz target for DNS packet parser (parse_dns_question).
//!
//! Feeds raw bytes as UDP DNS packets. Tests that malformed packets
//! (truncated, oversized labels, pointer compression, zero QDCOUNT)
//! never cause panics or unbounded allocation.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // parse_dns_question extracts the domain name from a raw DNS packet.
    // Must return None gracefully for any malformed input — never panic.
    let _ = gvm_proxy::dns_governance::parse_dns_question(data);
});
