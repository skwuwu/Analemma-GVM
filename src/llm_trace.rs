//! LLM thinking/reasoning trace extraction for governance audit.
//!
//! Extracts reasoning content from LLM API responses during IC-2/IC-3 enforcement.
//! Only invoked when the target host is a known LLM provider AND the proxy
//! already buffers the response (Delay path with WAL write).
//!
//! Supports both non-streaming (single JSON body) and SSE streaming responses.
//! SSE responses (`text/event-stream`) are reconstructed by parsing `data:` lines,
//! concatenating thinking/reasoning deltas, and extracting usage from the final chunk.
//!
//! Supported providers:
//! - OpenAI: `reasoning_content` field in message choices / delta chunks
//! - Anthropic: `thinking` content blocks / `thinking_delta` events
//! - Google Gemini: `thought` parts in candidates
//!
//! Privacy: Thinking content is stored as a SHA-256 hash by default
//! (`thinking_hash` field) to prevent leaking internal LLM reasoning into
//! the audit trail. Raw thinking storage requires explicit opt-in.

use gvm_types::{strip_port, LLMTrace, LLMUsage};
use sha2::{Digest, Sha256};

/// Maximum thinking content size stored in WAL (2KB).
const MAX_THINKING_BYTES: usize = 2048;

/// Maximum SSE body size we will attempt to parse (1MB).
/// Streaming responses can be large; beyond this limit we skip trace extraction.
const MAX_SSE_BODY_BYTES: usize = 1024 * 1024;

/// Known LLM provider hosts for response body inspection.
const LLM_PROVIDERS: &[(&str, &str)] = &[
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("generativelanguage.googleapis.com", "gemini"),
];

/// Check if a host is a known LLM provider.
/// Returns the provider name if matched.
pub fn identify_llm_provider(host: &str) -> Option<&'static str> {
    let host_only = strip_port(host);
    LLM_PROVIDERS
        .iter()
        .find(|(h, _)| *h == host_only)
        .map(|(_, name)| *name)
}

/// Check if a content-type header indicates an SSE streaming response.
pub fn is_sse_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/event-stream")
}

/// Extract thinking/reasoning trace from an LLM API response body (non-streaming).
/// Returns None if the body is not valid JSON or contains no thinking content.
///
/// Thinking content is hashed (SHA-256) for privacy. Only the hash is stored
/// in the WAL unless `store_raw` is true.
pub fn extract_thinking_trace(provider: &str, body: &[u8]) -> Option<LLMTrace> {
    extract_thinking_trace_with_privacy(provider, body, false)
}

/// Extract trace with explicit privacy control.
/// When `store_raw` is false, thinking content is replaced with its SHA-256 hash.
pub fn extract_thinking_trace_with_privacy(
    provider: &str,
    body: &[u8],
    store_raw: bool,
) -> Option<LLMTrace> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;

    let trace = match provider {
        "openai" => extract_openai(&json),
        "anthropic" => extract_anthropic(&json),
        "gemini" => extract_gemini(&json),
        _ => None,
    };

    if store_raw {
        trace
    } else {
        trace.map(apply_thinking_privacy)
    }
}

/// Extract thinking/reasoning trace from an SSE streaming response body.
/// Parses `data: <json>` lines, reconstructs thinking content from deltas,
/// and extracts usage from the final chunk.
///
/// Thinking content is hashed for privacy by default.
pub fn extract_thinking_trace_from_sse(provider: &str, body: &[u8]) -> Option<LLMTrace> {
    extract_thinking_trace_from_sse_with_privacy(provider, body, false)
}

/// SSE extraction with explicit privacy control.
pub fn extract_thinking_trace_from_sse_with_privacy(
    provider: &str,
    body: &[u8],
    store_raw: bool,
) -> Option<LLMTrace> {
    if body.len() > MAX_SSE_BODY_BYTES {
        tracing::warn!(
            size = body.len(),
            "SSE body exceeds size limit, skipping trace extraction"
        );
        return None;
    }

    let body_str = std::str::from_utf8(body).ok()?;
    let chunks = parse_sse_data_lines(body_str);

    if chunks.is_empty() {
        return None;
    }

    let trace = match provider {
        "openai" => reconstruct_openai_sse(&chunks),
        "anthropic" => reconstruct_anthropic_sse(&chunks),
        "gemini" => reconstruct_gemini_sse(&chunks),
        _ => None,
    };

    if store_raw {
        trace
    } else {
        trace.map(apply_thinking_privacy)
    }
}

/// Replace raw thinking content with its SHA-256 hash for WAL privacy.
/// The hash allows correlation (same thinking = same hash) without
/// storing the raw LLM reasoning in the audit trail.
fn apply_thinking_privacy(mut trace: LLMTrace) -> LLMTrace {
    if let Some(ref thinking) = trace.thinking {
        let mut hasher = Sha256::new();
        hasher.update(b"gvm-thinking-v1|");
        hasher.update(thinking.as_bytes());
        let hash = hex::encode(hasher.finalize());
        trace.thinking = Some(format!("sha256:{}", hash));
    }
    trace
}

/// Parse SSE `data:` lines from a buffered response body.
/// Returns parsed JSON values from each `data:` line (skips `data: [DONE]`).
fn parse_sse_data_lines(body: &str) -> Vec<serde_json::Value> {
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if let Some(data) = trimmed.strip_prefix("data:") {
                let data = data.trim();
                if data == "[DONE]" || data.is_empty() {
                    return None;
                }
                serde_json::from_str(data).ok()
            } else {
                None
            }
        })
        .collect()
}

// ─── Non-streaming extractors ───

/// OpenAI: Extract `reasoning_content` from chat completion choices.
fn extract_openai(json: &serde_json::Value) -> Option<LLMTrace> {
    let model = json.get("model").and_then(|v| v.as_str()).map(String::from);
    let usage = extract_openai_usage(json);

    let thinking = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|msg| msg.get("reasoning_content"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "openai".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

/// Anthropic: Extract `thinking` content blocks from messages response.
fn extract_anthropic(json: &serde_json::Value) -> Option<LLMTrace> {
    let model = json.get("model").and_then(|v| v.as_str()).map(String::from);
    let usage = extract_anthropic_usage(json);

    let thinking_text: String = json
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| {
                    block.get("type").and_then(|t| t.as_str()) == Some("thinking")
                })
                .filter_map(|block| block.get("thinking").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n---\n")
        })
        .unwrap_or_default();

    let thinking = if thinking_text.is_empty() {
        None
    } else {
        Some(thinking_text)
    };

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "anthropic".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

/// Google Gemini: Extract `thought` parts from candidates.
fn extract_gemini(json: &serde_json::Value) -> Option<LLMTrace> {
    let model = json
        .get("modelVersion")
        .and_then(|v| v.as_str())
        .map(String::from);
    let usage = extract_gemini_usage(json);

    let thinking_text: String = json
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|cand| cand.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(|parts| parts.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter(|part| part.get("thought").and_then(|t| t.as_bool()) == Some(true))
                .filter_map(|part| part.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n---\n")
        })
        .unwrap_or_default();

    let thinking = if thinking_text.is_empty() {
        None
    } else {
        Some(thinking_text)
    };

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "gemini".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

// ─── SSE streaming reconstructors ───

/// Reconstruct trace from OpenAI SSE chunks.
/// Streaming format: `choices[0].delta.reasoning_content` for thinking,
/// `usage` object in the final chunk (when `stream_options.include_usage` is true).
fn reconstruct_openai_sse(chunks: &[serde_json::Value]) -> Option<LLMTrace> {
    let mut thinking_parts: Vec<String> = Vec::new();
    let mut model: Option<String> = None;
    let mut usage: Option<LLMUsage> = None;

    for chunk in chunks {
        // Capture model from any chunk
        if model.is_none() {
            model = chunk.get("model").and_then(|v| v.as_str()).map(String::from);
        }

        // Accumulate reasoning_content deltas
        if let Some(reasoning) = chunk
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("delta"))
            .and_then(|delta| delta.get("reasoning_content"))
            .and_then(|v| v.as_str())
        {
            if !reasoning.is_empty() {
                thinking_parts.push(reasoning.to_string());
            }
        }

        // Extract usage from final chunk
        if let Some(u) = extract_openai_usage(chunk) {
            usage = Some(u);
        }
    }

    let thinking = if thinking_parts.is_empty() {
        None
    } else {
        Some(thinking_parts.join(""))
    };

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "openai".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

/// Reconstruct trace from Anthropic SSE chunks.
/// Streaming events:
/// - `message_start`: contains `message.model` and `message.usage.input_tokens`
/// - `content_block_start`: `content_block.type == "thinking"` starts a thinking block
/// - `content_block_delta`: `delta.type == "thinking_delta"` with `delta.thinking` text
/// - `message_delta`: contains `usage.output_tokens`
fn reconstruct_anthropic_sse(chunks: &[serde_json::Value]) -> Option<LLMTrace> {
    let mut thinking_parts: Vec<String> = Vec::new();
    let mut model: Option<String> = None;
    let mut input_tokens: Option<u64> = None;
    let mut output_tokens: Option<u64> = None;
    let mut in_thinking_block = false;

    for chunk in chunks {
        let event_type = chunk.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match event_type {
            "message_start" => {
                if let Some(msg) = chunk.get("message") {
                    model = msg.get("model").and_then(|v| v.as_str()).map(String::from);
                    input_tokens = msg
                        .get("usage")
                        .and_then(|u| u.get("input_tokens"))
                        .and_then(|v| v.as_u64());
                }
            }
            "content_block_start" => {
                in_thinking_block = chunk
                    .get("content_block")
                    .and_then(|b| b.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("thinking");
            }
            "content_block_delta" => {
                if in_thinking_block {
                    if let Some(thinking) = chunk
                        .get("delta")
                        .and_then(|d| d.get("thinking"))
                        .and_then(|t| t.as_str())
                    {
                        if !thinking.is_empty() {
                            thinking_parts.push(thinking.to_string());
                        }
                    }
                }
            }
            "content_block_stop" => {
                in_thinking_block = false;
            }
            "message_delta" => {
                output_tokens = chunk
                    .get("usage")
                    .and_then(|u| u.get("output_tokens"))
                    .and_then(|v| v.as_u64());
            }
            _ => {}
        }
    }

    let thinking = if thinking_parts.is_empty() {
        None
    } else {
        Some(thinking_parts.join(""))
    };

    let usage = if input_tokens.is_some() || output_tokens.is_some() {
        Some(LLMUsage {
            prompt_tokens: input_tokens,
            completion_tokens: output_tokens,
            total_tokens: None, // Anthropic does not provide total_tokens
        })
    } else {
        None
    };

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "anthropic".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

/// Reconstruct trace from Gemini SSE chunks.
/// Each SSE chunk is a complete candidates array. Thought parts have `thought: true`.
/// Usage is in `usageMetadata` of the final chunk.
fn reconstruct_gemini_sse(chunks: &[serde_json::Value]) -> Option<LLMTrace> {
    let mut thinking_parts: Vec<String> = Vec::new();
    let mut model: Option<String> = None;
    let mut usage: Option<LLMUsage> = None;

    for chunk in chunks {
        if model.is_none() {
            model = chunk
                .get("modelVersion")
                .and_then(|v| v.as_str())
                .map(String::from);
        }

        // Extract thought parts from candidates
        if let Some(parts) = chunk
            .get("candidates")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|cand| cand.get("content"))
            .and_then(|content| content.get("parts"))
            .and_then(|parts| parts.as_array())
        {
            for part in parts {
                if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        if !text.is_empty() {
                            thinking_parts.push(text.to_string());
                        }
                    }
                }
            }
        }

        if let Some(u) = extract_gemini_usage(chunk) {
            usage = Some(u);
        }
    }

    let thinking = if thinking_parts.is_empty() {
        None
    } else {
        Some(thinking_parts.join(""))
    };

    if thinking.is_none() && usage.is_none() {
        return None;
    }

    let (thinking, truncated) = truncate_thinking(thinking);

    Some(LLMTrace {
        provider: "gemini".to_string(),
        model,
        thinking,
        truncated,
        usage,
    })
}

// ─── Shared utilities ───

/// Truncate thinking content to MAX_THINKING_BYTES, respecting UTF-8 boundaries.
fn truncate_thinking(thinking: Option<String>) -> (Option<String>, bool) {
    match thinking {
        Some(text) if text.len() > MAX_THINKING_BYTES => {
            // Find the last valid UTF-8 char boundary at or before MAX_THINKING_BYTES
            let mut end = MAX_THINKING_BYTES;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            (Some(format!("{}...[truncated]", &text[..end])), true)
        }
        other => (other, false),
    }
}

fn extract_openai_usage(json: &serde_json::Value) -> Option<LLMUsage> {
    let usage = json.get("usage")?;
    Some(LLMUsage {
        prompt_tokens: usage.get("prompt_tokens").and_then(|v| v.as_u64()),
        completion_tokens: usage.get("completion_tokens").and_then(|v| v.as_u64()),
        total_tokens: usage.get("total_tokens").and_then(|v| v.as_u64()),
    })
}

fn extract_anthropic_usage(json: &serde_json::Value) -> Option<LLMUsage> {
    let usage = json.get("usage")?;
    Some(LLMUsage {
        prompt_tokens: usage.get("input_tokens").and_then(|v| v.as_u64()),
        completion_tokens: usage.get("output_tokens").and_then(|v| v.as_u64()),
        total_tokens: None, // Anthropic does not provide total_tokens
    })
}

fn extract_gemini_usage(json: &serde_json::Value) -> Option<LLMUsage> {
    let usage = json.get("usageMetadata")?;
    Some(LLMUsage {
        prompt_tokens: usage.get("promptTokenCount").and_then(|v| v.as_u64()),
        completion_tokens: usage
            .get("candidatesTokenCount")
            .and_then(|v| v.as_u64()),
        total_tokens: usage.get("totalTokenCount").and_then(|v| v.as_u64()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Non-streaming tests ───

    #[test]
    fn test_identify_llm_provider() {
        assert_eq!(identify_llm_provider("api.openai.com"), Some("openai"));
        assert_eq!(
            identify_llm_provider("api.anthropic.com"),
            Some("anthropic")
        );
        assert_eq!(
            identify_llm_provider("generativelanguage.googleapis.com"),
            Some("gemini")
        );
        assert_eq!(identify_llm_provider("api.bank.com"), None);
        assert_eq!(
            identify_llm_provider("api.openai.com:443"),
            Some("openai")
        );
    }

    #[test]
    fn test_extract_openai_reasoning() {
        let body = serde_json::json!({
            "id": "chatcmpl-abc",
            "model": "o1-preview",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "reasoning_content": "Let me think step by step...",
                    "content": "The answer is 42."
                }
            }],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        });

        // With raw storage enabled for test assertions
        let trace = extract_thinking_trace_with_privacy(
            "openai", body.to_string().as_bytes(), true,
        ).expect("valid OpenAI response must parse");
        assert_eq!(trace.provider, "openai");
        assert_eq!(trace.model.as_deref(), Some("o1-preview"));
        assert_eq!(
            trace.thinking.as_deref(),
            Some("Let me think step by step...")
        );
        assert!(!trace.truncated);
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(150));
    }

    #[test]
    fn test_extract_anthropic_thinking() {
        let body = serde_json::json!({
            "id": "msg_abc",
            "model": "claude-sonnet-4-20250514",
            "content": [
                { "type": "thinking", "thinking": "First, I need to consider..." },
                { "type": "text", "text": "Here is the answer." }
            ],
            "usage": {
                "input_tokens": 200,
                "output_tokens": 100
            }
        });

        let trace = extract_thinking_trace_with_privacy(
            "anthropic", body.to_string().as_bytes(), true,
        ).expect("valid Anthropic response must parse");
        assert_eq!(trace.provider, "anthropic");
        assert_eq!(trace.model.as_deref(), Some("claude-sonnet-4-20250514"));
        assert_eq!(
            trace.thinking.as_deref(),
            Some("First, I need to consider...")
        );
        assert_eq!(trace.usage.as_ref().expect("usage").prompt_tokens, Some(200));
        // Anthropic: computed_total should work since both fields present
        assert_eq!(trace.usage.as_ref().unwrap().computed_total(), Some(300));
    }

    #[test]
    fn test_extract_gemini_thought() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        { "thought": true, "text": "Reasoning through the problem..." },
                        { "text": "Final answer here." }
                    ]
                }
            }],
            "modelVersion": "gemini-2.0-flash-thinking",
            "usageMetadata": {
                "promptTokenCount": 50,
                "candidatesTokenCount": 30,
                "totalTokenCount": 80
            }
        });

        let trace = extract_thinking_trace_with_privacy(
            "gemini", body.to_string().as_bytes(), true,
        ).expect("valid Gemini response must parse");
        assert_eq!(trace.provider, "gemini");
        assert_eq!(
            trace.model.as_deref(),
            Some("gemini-2.0-flash-thinking")
        );
        assert_eq!(
            trace.thinking.as_deref(),
            Some("Reasoning through the problem...")
        );
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(80));
    }

    #[test]
    fn test_no_thinking_content_returns_usage_only() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "choices": [{
                "message": { "role": "assistant", "content": "Hello!" }
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });

        let trace = extract_thinking_trace_with_privacy(
            "openai", body.to_string().as_bytes(), true,
        ).expect("valid OpenAI response must parse");
        assert!(trace.thinking.is_none());
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(15));
    }

    #[test]
    fn test_non_llm_body_returns_none() {
        let body = b"<html>Not JSON</html>";
        assert!(extract_thinking_trace("openai", body).is_none());
    }

    #[test]
    fn test_truncation() {
        let long_text = "a".repeat(3000);
        let (result, truncated) = truncate_thinking(Some(long_text));
        assert!(truncated);
        assert!(result.expect("truncated text must be Some").len() < 3000);
    }

    #[test]
    fn test_empty_provider_returns_none() {
        let body = serde_json::json!({"key": "value"});
        assert!(extract_thinking_trace("unknown_provider", body.to_string().as_bytes()).is_none());
    }

    // ─── Privacy tests ───

    #[test]
    fn test_default_extract_hashes_thinking() {
        let body = serde_json::json!({
            "model": "o1-preview",
            "choices": [{
                "message": {
                    "reasoning_content": "secret reasoning here",
                    "content": "answer"
                }
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });

        let trace = extract_thinking_trace("openai", body.to_string().as_bytes())
            .expect("must parse");
        // Default mode: thinking is hashed, not raw
        let thinking = trace.thinking.as_deref().expect("must have thinking");
        assert!(thinking.starts_with("sha256:"), "thinking must be hashed: {}", thinking);
        assert!(!thinking.contains("secret reasoning"));
    }

    #[test]
    fn test_raw_mode_preserves_thinking() {
        let body = serde_json::json!({
            "model": "o1-preview",
            "choices": [{
                "message": {
                    "reasoning_content": "secret reasoning here",
                    "content": "answer"
                }
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });

        let trace = extract_thinking_trace_with_privacy(
            "openai", body.to_string().as_bytes(), true,
        ).expect("must parse");
        assert_eq!(trace.thinking.as_deref(), Some("secret reasoning here"));
    }

    #[test]
    fn test_privacy_hash_is_deterministic() {
        let body = serde_json::json!({
            "model": "o1",
            "choices": [{"message": {"reasoning_content": "same input", "content": "x"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        });
        let bytes = body.to_string();

        let t1 = extract_thinking_trace("openai", bytes.as_bytes()).unwrap();
        let t2 = extract_thinking_trace("openai", bytes.as_bytes()).unwrap();
        assert_eq!(t1.thinking, t2.thinking, "same input must produce same hash");
    }

    #[test]
    fn test_privacy_hash_domain_separated() {
        // Verify the hash includes the domain prefix
        let thinking = "test content".to_string();
        let trace = apply_thinking_privacy(LLMTrace {
            provider: "openai".to_string(),
            model: None,
            thinking: Some(thinking.clone()),
            truncated: false,
            usage: None,
        });

        // Compute expected hash
        let mut hasher = Sha256::new();
        hasher.update(b"gvm-thinking-v1|");
        hasher.update(thinking.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(trace.thinking.as_deref(), Some(expected.as_str()));
    }

    // ─── SSE streaming tests ───

    #[test]
    fn test_is_sse_content_type() {
        assert!(is_sse_content_type("text/event-stream"));
        assert!(is_sse_content_type("text/event-stream; charset=utf-8"));
        assert!(!is_sse_content_type("application/json"));
    }

    #[test]
    fn test_parse_sse_data_lines() {
        let body = "data: {\"id\":\"1\"}\n\ndata: {\"id\":\"2\"}\n\ndata: [DONE]\n\n";
        let chunks = parse_sse_data_lines(body);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["id"], "1");
        assert_eq!(chunks[1]["id"], "2");
    }

    #[test]
    fn test_parse_sse_skips_event_lines() {
        let body = "event: message\ndata: {\"id\":\"1\"}\n\nevent: done\ndata: [DONE]\n\n";
        let chunks = parse_sse_data_lines(body);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_openai_sse_streaming() {
        let body = concat!(
            "data: {\"id\":\"1\",\"model\":\"o1-preview\",\"choices\":[{\"delta\":{\"reasoning_content\":\"Let me \"}}]}\n\n",
            "data: {\"id\":\"1\",\"model\":\"o1-preview\",\"choices\":[{\"delta\":{\"reasoning_content\":\"think...\"}}]}\n\n",
            "data: {\"id\":\"1\",\"model\":\"o1-preview\",\"choices\":[{\"delta\":{\"content\":\"Answer.\"}}]}\n\n",
            "data: {\"id\":\"1\",\"model\":\"o1-preview\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}\n\n",
            "data: [DONE]\n\n",
        );

        let trace = extract_thinking_trace_from_sse_with_privacy(
            "openai", body.as_bytes(), true,
        ).expect("must parse OpenAI SSE");
        assert_eq!(trace.provider, "openai");
        assert_eq!(trace.model.as_deref(), Some("o1-preview"));
        assert_eq!(trace.thinking.as_deref(), Some("Let me think..."));
        assert!(!trace.truncated);
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(150));
    }

    #[test]
    fn test_anthropic_sse_streaming() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":200}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"First, \"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"consider...\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\"}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Answer.\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\"}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":100}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );

        let trace = extract_thinking_trace_from_sse_with_privacy(
            "anthropic", body.as_bytes(), true,
        ).expect("must parse Anthropic SSE");
        assert_eq!(trace.provider, "anthropic");
        assert_eq!(trace.model.as_deref(), Some("claude-sonnet-4-20250514"));
        assert_eq!(trace.thinking.as_deref(), Some("First, consider..."));
        let usage = trace.usage.as_ref().expect("usage");
        assert_eq!(usage.prompt_tokens, Some(200));
        assert_eq!(usage.completion_tokens, Some(100));
        assert_eq!(usage.total_tokens, None);
        // computed_total normalizes the missing total
        assert_eq!(usage.computed_total(), Some(300));
    }

    #[test]
    fn test_gemini_sse_streaming() {
        let body = concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"thought\":true,\"text\":\"Thinking \"}]}}],\"modelVersion\":\"gemini-2.0-flash-thinking\"}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"thought\":true,\"text\":\"deeply...\"}]}}],\"modelVersion\":\"gemini-2.0-flash-thinking\"}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Final answer.\"}]}}],\"modelVersion\":\"gemini-2.0-flash-thinking\",\"usageMetadata\":{\"promptTokenCount\":50,\"candidatesTokenCount\":30,\"totalTokenCount\":80}}\n\n",
        );

        let trace = extract_thinking_trace_from_sse_with_privacy(
            "gemini", body.as_bytes(), true,
        ).expect("must parse Gemini SSE");
        assert_eq!(trace.provider, "gemini");
        assert_eq!(trace.thinking.as_deref(), Some("Thinking deeply..."));
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(80));
    }

    #[test]
    fn test_sse_no_thinking_returns_usage_only() {
        let body = concat!(
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hello!\"}}]}\n\n",
            "data: {\"id\":\"1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n",
        );

        let trace = extract_thinking_trace_from_sse_with_privacy(
            "openai", body.as_bytes(), true,
        ).expect("must parse");
        assert!(trace.thinking.is_none());
        assert_eq!(trace.usage.as_ref().expect("usage").total_tokens, Some(15));
    }

    #[test]
    fn test_sse_default_hashes_thinking() {
        let body = concat!(
            "data: {\"id\":\"1\",\"model\":\"o1\",\"choices\":[{\"delta\":{\"reasoning_content\":\"secret\"}}]}\n\n",
            "data: {\"id\":\"1\",\"model\":\"o1\",\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n",
            "data: [DONE]\n\n",
        );

        let trace = extract_thinking_trace_from_sse("openai", body.as_bytes())
            .expect("must parse");
        let thinking = trace.thinking.as_deref().expect("must have thinking");
        assert!(thinking.starts_with("sha256:"), "SSE thinking must be hashed");
        assert!(!thinking.contains("secret"));
    }

    #[test]
    fn test_sse_empty_body_returns_none() {
        assert!(extract_thinking_trace_from_sse("openai", b"").is_none());
    }

    #[test]
    fn test_sse_invalid_utf8_returns_none() {
        assert!(extract_thinking_trace_from_sse("openai", &[0xFF, 0xFE]).is_none());
    }

    // ─── computed_total tests ───

    #[test]
    fn test_computed_total_prefers_explicit() {
        let usage = LLMUsage {
            prompt_tokens: Some(100),
            completion_tokens: Some(50),
            total_tokens: Some(200), // explicit, even if != sum
        };
        assert_eq!(usage.computed_total(), Some(200));
    }

    #[test]
    fn test_computed_total_falls_back_to_sum() {
        let usage = LLMUsage {
            prompt_tokens: Some(200),
            completion_tokens: Some(100),
            total_tokens: None, // Anthropic-style
        };
        assert_eq!(usage.computed_total(), Some(300));
    }

    #[test]
    fn test_computed_total_partial_returns_none() {
        let usage = LLMUsage {
            prompt_tokens: Some(100),
            completion_tokens: None,
            total_tokens: None,
        };
        assert_eq!(usage.computed_total(), None);
    }

    #[test]
    fn test_computed_total_all_none() {
        let usage = LLMUsage {
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
        };
        assert_eq!(usage.computed_total(), None);
    }
}
