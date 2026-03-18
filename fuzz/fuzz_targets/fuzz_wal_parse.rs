#![no_main]
//! Fuzz target for WAL event JSON parsing.
//!
//! Feeds arbitrary bytes as WAL lines to serde_json::from_str::<GVMEvent>().
//! Goals:
//! - No panics on any input
//! - Graceful rejection of malformed JSON
//! - No unbounded memory allocation from crafted payloads

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Simulate WAL recovery: parse each line as a GVMEvent
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // WAL is text-based, non-UTF8 is immediately rejected
    };

    for line in input.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Skip MerkleBatchRecord lines (same logic as recovery)
        if line.contains("\"merkle_root\"") {
            continue;
        }

        // This must never panic — invalid JSON is expected and must be handled gracefully
        let _result: Result<gvm_types::GVMEvent, _> = serde_json::from_str(line);
    }
});
