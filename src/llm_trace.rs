//! LLM thinking/reasoning trace extraction for governance audit.
//!
//! Extracts reasoning content from LLM API responses during IC-2/IC-3 enforcement.
//! Only invoked when the target host is a known LLM provider AND the proxy
//! already buffers the response (Delay path with WAL write).
//!
//! Supported providers:
//! - OpenAI: `reasoning_content` field in message choices
//! - Anthropic: `thinking` content blocks in messages response
//! - Google Gemini: `thought` parts in candidates

use gvm_types::{LLMTrace, LLMUsage};

/// Maximum thinking content size stored in WAL (2KB).
const MAX_THINKING_BYTES: usize = 2048;

/// Known LLM provider hosts for response body inspection.
const LLM_PROVIDERS: &[(&str, &str)] = &[
    ("api.openai.com", "openai"),
    ("api.anthropic.com", "anthropic"),
    ("generativelanguage.googleapis.com", "gemini"),
];

/// Check if a host is a known LLM provider.
/// Returns the provider name if matched.
pub fn identify_llm_provider(host: &str) -> Option<&'static str> {
    // Strip port if present
    let host_only = host.split(':').next().unwrap_or(host);
    LLM_PROVIDERS
        .iter()
        .find(|(h, _)| *h == host_only)
        .map(|(_, name)| *name)
}

/// Extract thinking/reasoning trace from an LLM API response body.
/// Returns None if the body is not valid JSON or contains no thinking content.
pub fn extract_thinking_trace(provider: &str, body: &[u8]) -> Option<LLMTrace> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;

    match provider {
        "openai" => extract_openai(&json),
        "anthropic" => extract_anthropic(&json),
        "gemini" => extract_gemini(&json),
        _ => None,
    }
}

/// OpenAI: Extract `reasoning_content` from chat completion choices.
/// Response format:
/// ```json
/// { "choices": [{ "message": { "reasoning_content": "...", "content": "..." } }],
///   "model": "o1-preview", "usage": { ... } }
/// ```
fn extract_openai(json: &serde_json::Value) -> Option<LLMTrace> {
    let model = json.get("model").and_then(|v| v.as_str()).map(String::from);
    let usage = extract_openai_usage(json);

    // Look for reasoning_content in the first choice
    let thinking = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|msg| msg.get("reasoning_content"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    // Only produce a trace if we found thinking content or usage
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
/// Response format:
/// ```json
/// { "content": [
///     { "type": "thinking", "thinking": "step-by-step reasoning..." },
///     { "type": "text", "text": "final answer" }
///   ], "model": "claude-sonnet-4-20250514", "usage": { ... } }
/// ```
fn extract_anthropic(json: &serde_json::Value) -> Option<LLMTrace> {
    let model = json.get("model").and_then(|v| v.as_str()).map(String::from);
    let usage = extract_anthropic_usage(json);

    // Collect all thinking blocks
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
/// Response format:
/// ```json
/// { "candidates": [{ "content": { "parts": [
///     { "thought": true, "text": "reasoning..." },
///     { "text": "final answer" }
///   ] } }], "modelVersion": "gemini-2.0-flash-thinking" }
/// ```
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

        let trace =
            extract_thinking_trace("openai", body.to_string().as_bytes()).expect("valid OpenAI response must parse");
        assert_eq!(trace.provider, "openai");
        assert_eq!(trace.model.as_deref(), Some("o1-preview"));
        assert_eq!(
            trace.thinking.as_deref(),
            Some("Let me think step by step...")
        );
        assert!(!trace.truncated);
        assert_eq!(trace.usage.as_ref().expect("trace must contain usage data").total_tokens, Some(150));
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

        let trace =
            extract_thinking_trace("anthropic", body.to_string().as_bytes()).expect("valid Anthropic response must parse");
        assert_eq!(trace.provider, "anthropic");
        assert_eq!(trace.model.as_deref(), Some("claude-sonnet-4-20250514"));
        assert_eq!(
            trace.thinking.as_deref(),
            Some("First, I need to consider...")
        );
        assert_eq!(trace.usage.as_ref().expect("trace must contain usage data").prompt_tokens, Some(200));
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

        let trace =
            extract_thinking_trace("gemini", body.to_string().as_bytes()).expect("valid Gemini response must parse");
        assert_eq!(trace.provider, "gemini");
        assert_eq!(
            trace.model.as_deref(),
            Some("gemini-2.0-flash-thinking")
        );
        assert_eq!(
            trace.thinking.as_deref(),
            Some("Reasoning through the problem...")
        );
        assert_eq!(trace.usage.as_ref().expect("trace must contain usage data").total_tokens, Some(80));
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

        let trace =
            extract_thinking_trace("openai", body.to_string().as_bytes()).expect("valid OpenAI response must parse");
        assert!(trace.thinking.is_none());
        assert_eq!(trace.usage.as_ref().expect("trace must contain usage data").total_tokens, Some(15));
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
}
