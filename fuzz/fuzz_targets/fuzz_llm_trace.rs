#![no_main]
//! Fuzz target for LLM thinking trace extraction.
//!
//! Feeds arbitrary bytes to extract_thinking_trace() and extract_thinking_trace_from_sse().
//! Goals:
//! - No panics on malformed JSON or SSE data
//! - No unbounded memory allocation from crafted response bodies
//! - Graceful None return on invalid input

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Limit input to 1MB (matches MAX_SSE_TRACE_CAPTURE_BYTES)
    if data.len() > 1024 * 1024 {
        return;
    }

    // Test all provider paths with the same input
    let providers = ["openai", "anthropic", "gemini", "unknown"];

    for provider in &providers {
        // JSON response extraction (both privacy modes)
        let _ = gvm_proxy::llm_trace::extract_thinking_trace(provider, data);
        let _ = gvm_proxy::llm_trace::extract_thinking_trace_with_privacy(provider, data, true);

        // SSE streaming extraction (both privacy modes)
        let _ = gvm_proxy::llm_trace::extract_thinking_trace_from_sse(provider, data);
        let _ = gvm_proxy::llm_trace::extract_thinking_trace_from_sse_with_privacy(
            provider, data, true,
        );
    }

    // Also fuzz provider identification with arbitrary host strings
    if let Ok(host) = std::str::from_utf8(data) {
        let _ = gvm_proxy::llm_trace::identify_llm_provider(host);
    }
});
