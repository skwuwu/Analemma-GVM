#![no_main]
//! Structure-aware HTTP request parser fuzzer.
//!
//! Generates structurally valid HTTP requests via HttpWireInput, then
//! serializes them to HTTP/1.1 wire format bytes before feeding to the
//! parser. This catches protocol-level bugs (smuggling, CRLF injection,
//! CL/TE conflicts) that raw-byte fuzzing takes hours to discover.

use gvm_fuzz::types::HttpWireInput;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: HttpWireInput| {
    let wire = input.to_wire();

    // Feed to httparse (same parser the MITM proxy uses)
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let _ = req.parse(&wire);
});
