#![no_main]
//! Fuzz target for MITM HTTP request parsing.
//!
//! Feeds arbitrary bytes into read_http_request() via an in-memory async reader.
//! Goals:
//! - No panics on any input (including binary, partial headers, smuggling attempts)
//! - No unbounded memory allocation
//! - Correct rejection of malformed requests (CL/TE conflicts, oversized headers)

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeout from overly large inputs.
    // 128KB covers MAX_HEADER (64KB) + body + overhead.
    if data.len() > 128 * 1024 {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);

        // This must never panic — malformed HTTP is expected and must be handled gracefully.
        // Timeout is 30s in production; we use tokio::time::timeout to bound the fuzzer.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            gvm_proxy::tls_proxy::read_http_request(&mut reader),
        )
        .await;

        // We don't care about the result — only that it didn't panic.
        let _ = result;
    });
});
