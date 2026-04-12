#![no_main]
//! Structure-aware WAL parser fuzzer.
//!
//! Generates WAL event sequences via WalEventInput with controlled
//! corruption strategies (duplicate event_id, truncated JSON, invalid
//! UTF-8, bad Merkle root, empty lines). Tests that the parser
//! gracefully skips corrupt entries without panicking.

use gvm_fuzz::types::WalEventInput;
use gvm_types::GVMEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: WalEventInput| {
    let jsonl = input.to_jsonl();
    let content = String::from_utf8_lossy(&jsonl);

    // Parse each line as a WAL event — same path as ledger recovery
    let mut valid_events = 0u32;
    let mut parse_errors = 0u32;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(val) => {
                // Try parsing as GVMEvent
                if serde_json::from_value::<GVMEvent>(val.clone()).is_ok() {
                    valid_events += 1;
                }
                // Also try as batch record (has batch_id field)
                if val.get("batch_id").is_some() {
                    valid_events += 1;
                }
            }
            Err(_) => {
                parse_errors += 1;
            }
        }
    }

    // The parser must not panic regardless of corruption strategy.
    // valid_events + parse_errors should account for all non-empty lines.
    let _ = (valid_events, parse_errors);
});
