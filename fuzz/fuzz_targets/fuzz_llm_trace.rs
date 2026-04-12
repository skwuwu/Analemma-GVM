#![no_main]
//! Structure-aware LLM thinking trace extraction fuzzer.
//!
//! Generates plausible LLM response JSON/SSE fragments and feeds them
//! to the trace extraction functions. Tests partial chunks, malformed
//! JSON, interleaved thinking blocks, and provider-specific formats.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// LLM response fragment with provider-specific structure.
#[derive(Debug)]
struct LlmFragment {
    provider: Provider,
    content: String,
}

#[derive(Arbitrary, Debug)]
enum Provider {
    Anthropic,
    OpenAI,
    Generic,
}

impl<'a> Arbitrary<'a> for LlmFragment {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let provider: Provider = u.arbitrary()?;
        let strategy: u8 = u.int_in_range(0..=4)?;
        let content = match (&provider, strategy) {
            // Anthropic thinking block
            (Provider::Anthropic, 0) => {
                let text_len: usize = u.int_in_range(10..=500)?;
                let text: String = (0..text_len)
                    .map(|_| {
                        let c: u8 = u.int_in_range(0x20..=0x7e)?;
                        Ok(c as char)
                    })
                    .collect::<arbitrary::Result<String>>()?;
                format!(
                    r#"{{"type":"content_block_delta","delta":{{"type":"thinking","thinking":"{}"}}}}"#,
                    text.replace('"', "'")
                )
            }
            // OpenAI reasoning_content
            (Provider::OpenAI, 0) => {
                let text_len: usize = u.int_in_range(10..=200)?;
                let text: String = (0..text_len)
                    .map(|_| Ok(u.int_in_range(b'a'..=b'z')? as char))
                    .collect::<arbitrary::Result<String>>()?;
                format!(
                    r#"{{"choices":[{{"delta":{{"reasoning_content":"{}"}}}}]}}"#,
                    text
                )
            }
            // SSE format
            (_, 1) => {
                let data_len: usize = u.int_in_range(5..=200)?;
                let data: String = (0..data_len)
                    .map(|_| Ok(u.int_in_range(b'a'..=b'z')? as char))
                    .collect::<arbitrary::Result<String>>()?;
                format!("data: {}\n\n", data)
            }
            // Truncated JSON (partial chunk)
            (_, 2) => {
                let full = r#"{"type":"content_block_delta","delta":{"type":"thinking","thinking":"partial"#;
                full[..full.len().min(u.int_in_range(5..=full.len())?)].to_string()
            }
            // Malformed
            (_, 3) => {
                let len: usize = u.int_in_range(1..=100)?;
                (0..len)
                    .map(|_| Ok(u.int_in_range(0x20u8..=0x7eu8)? as char))
                    .collect::<arbitrary::Result<String>>()?
            }
            // [DONE] marker
            _ => "data: [DONE]\n\n".to_string(),
        };
        Ok(Self { provider, content })
    }
}

fuzz_target!(|fragments: Vec<LlmFragment>| {
    for frag in &fragments {
        let provider = match frag.provider {
            Provider::Anthropic => "anthropic",
            Provider::OpenAI => "openai",
            Provider::Generic => "unknown",
        };
        // Feed to trace extraction — must not panic
        let _ =
            gvm_proxy::llm_trace::extract_thinking_trace(provider, frag.content.as_bytes());
    }

    // Also test SSE accumulation
    let combined: String = fragments.iter().map(|f| f.content.as_str()).collect();
    let _ =
        gvm_proxy::llm_trace::extract_thinking_trace_from_sse("anthropic", combined.as_bytes());
});
