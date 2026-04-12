//! Structured fuzz input types with wire format serialization.
//!
//! Design principles:
//! - Arbitrary generates structurally valid inputs (~95% parse success)
//! - Wire serialization introduces realistic protocol-level mutations
//! - Custom Arbitrary impls inject adversarial patterns at controlled rates
//!   (ReDoS-triggering paths, Merkle chain corruption, smuggling pivots)

use arbitrary::{Arbitrary, Unstructured};

// ═══════════════════════════════════════════════════════════════════
// HTTP primitives
// ═══════════════════════════════════════════════════════════════════

/// HTTP method — always valid, no parsing waste.
#[derive(Arbitrary, Debug, Clone)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// ASCII string that won't fail UTF-8 validation. Bounded length.
#[derive(Debug, Clone)]
pub struct AsciiString(pub String);

impl<'a> Arbitrary<'a> for AsciiString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(1..=128)?;
        let chars: Vec<u8> = (0..len)
            .map(|_| {
                let b: u8 = u.int_in_range(0x21..=0x7e)?; // printable ASCII
                Ok(b)
            })
            .collect::<arbitrary::Result<Vec<u8>>>()?;
        Ok(Self(String::from_utf8(chars).unwrap_or_else(|_| "fallback".into())))
    }
}

/// Valid hostname — lowercase alpha + dots + optional port.
#[derive(Debug, Clone)]
pub struct ValidHost(pub String);

impl<'a> Arbitrary<'a> for ValidHost {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let labels: u8 = u.int_in_range(1..=4)?;
        let mut parts = Vec::new();
        for _ in 0..labels {
            let len: usize = u.int_in_range(1..=12)?;
            let label: String = (0..len)
                .map(|_| {
                    let c: u8 = u.int_in_range(b'a'..=b'z')?;
                    Ok(c as char)
                })
                .collect::<arbitrary::Result<String>>()?;
            parts.push(label);
        }
        let host = parts.join(".");
        // Optionally add port
        let has_port: bool = u.arbitrary()?;
        if has_port {
            let port: u16 = u.int_in_range(80..=9999)?;
            Ok(Self(format!("{}:{}", host, port)))
        } else {
            Ok(Self(host))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SRR fuzzing
// ═══════════════════════════════════════════════════════════════════

/// Path that is structurally valid but includes adversarial patterns
/// at controlled rates to target:
/// - Path normalization (dot-segment, percent-encoding, null bytes)
/// - Regex backtracking (repeated characters)
/// - Query string / fragment stripping
#[derive(Debug, Clone)]
pub struct FuzzPath(pub String);

impl<'a> Arbitrary<'a> for FuzzPath {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let strategy: u8 = u.int_in_range(0..=6)?;
        let path = match strategy {
            // Normal path segments
            0 => {
                let depth: usize = u.int_in_range(1..=5)?;
                let segments: Vec<String> = (0..depth)
                    .map(|_| {
                        let len: usize = u.int_in_range(1..=20)?;
                        (0..len)
                            .map(|_| {
                                let c: u8 = u.int_in_range(b'a'..=b'z')?;
                                Ok(c as char)
                            })
                            .collect::<arbitrary::Result<String>>()
                    })
                    .collect::<arbitrary::Result<Vec<String>>>()?;
                format!("/{}", segments.join("/"))
            }
            // Dot-segment traversal
            1 => {
                let prefix: AsciiString = u.arbitrary()?;
                format!("/{}/../../../etc/passwd", &prefix.0[..prefix.0.len().min(10)])
            }
            // Percent-encoded traversal
            2 => "/a/%2e%2e/%2e%2e/etc/shadow".to_string(),
            // Double-slash collapse
            3 => "///api///v1///users".to_string(),
            // Null byte injection
            4 => "/api/transfer\x00/../../etc/hosts".to_string(),
            // ReDoS trigger: repeated 'a' characters that may cause
            // catastrophic backtracking in vulnerable regex engines.
            // Rust's regex crate is Thompson NFA (immune), but this
            // tests that the immunity claim holds.
            5 => {
                let repeat: usize = u.int_in_range(10..=200)?;
                format!("/{}{}", "a".repeat(repeat), "!")
            }
            // Query string + fragment
            _ => {
                let base: AsciiString = u.arbitrary()?;
                format!(
                    "/{}?key=value&foo=bar#section",
                    &base.0[..base.0.len().min(20)]
                )
            }
        };
        Ok(Self(path))
    }
}

/// Complete SRR check input.
#[derive(Debug, Clone)]
pub struct SrrInput {
    pub method: HttpMethod,
    pub host: ValidHost,
    pub path: FuzzPath,
    pub body: Option<Vec<u8>>,
}

impl<'a> Arbitrary<'a> for SrrInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let method: HttpMethod = u.arbitrary()?;
        let host: ValidHost = u.arbitrary()?;
        let path: FuzzPath = u.arbitrary()?;
        let has_body: bool = u.arbitrary()?;
        let body = if has_body {
            // Sometimes valid JSON, sometimes garbage
            let is_json: bool = u.arbitrary()?;
            if is_json {
                let op: AsciiString = u.arbitrary()?;
                Some(
                    format!(
                        r#"{{"operationName":"{}","query":"mutation {{ transferFunds }}"}}"#,
                        &op.0[..op.0.len().min(30)]
                    )
                    .into_bytes(),
                )
            } else {
                let len: usize = u.int_in_range(0..=1024)?;
                Some(u.bytes(len)?.to_vec())
            }
        } else {
            None
        };
        Ok(Self {
            method,
            host,
            path,
            body,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// HTTP wire format (for fuzz_http_parse)
// ═══════════════════════════════════════════════════════════════════

/// HTTP header with potential smuggling mutations.
#[derive(Debug, Clone)]
pub struct FuzzHeader {
    pub name: String,
    pub value: String,
}

impl<'a> Arbitrary<'a> for FuzzHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let strategy: u8 = u.int_in_range(0..=3)?;
        match strategy {
            // Normal header
            0 => {
                let names = [
                    "Host",
                    "Content-Type",
                    "Accept",
                    "User-Agent",
                    "Authorization",
                    "Cookie",
                    "X-GVM-Agent-Id",
                ];
                let name = names[u.int_in_range(0..=names.len() - 1)?].to_string();
                let val: AsciiString = u.arbitrary()?;
                Ok(Self {
                    name,
                    value: val.0,
                })
            }
            // Content-Length (smuggling pivot)
            1 => {
                let cl: u32 = u.int_in_range(0..=65536)?;
                Ok(Self {
                    name: "Content-Length".into(),
                    value: cl.to_string(),
                })
            }
            // Transfer-Encoding (smuggling pivot)
            2 => Ok(Self {
                name: "Transfer-Encoding".into(),
                value: "chunked".into(),
            }),
            // CRLF injection attempt
            _ => {
                let val: AsciiString = u.arbitrary()?;
                Ok(Self {
                    name: "X-Injected".into(),
                    value: format!("{}\r\nEvil: header", &val.0[..val.0.len().min(10)]),
                })
            }
        }
    }
}

/// Body framing strategy for HTTP wire format.
#[derive(Arbitrary, Debug, Clone)]
pub enum BodyStrategy {
    /// No body
    None,
    /// Content-Length framed
    ContentLength,
    /// Transfer-Encoding: chunked
    Chunked,
    /// Both CL and TE (smuggling trigger)
    Both,
}

/// Complete HTTP request that serializes to wire format.
#[derive(Debug, Clone)]
pub struct HttpWireInput {
    pub method: HttpMethod,
    pub path: FuzzPath,
    pub host: ValidHost,
    pub headers: Vec<FuzzHeader>,
    pub body_strategy: BodyStrategy,
    pub body: Vec<u8>,
}

impl<'a> Arbitrary<'a> for HttpWireInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let method: HttpMethod = u.arbitrary()?;
        let path: FuzzPath = u.arbitrary()?;
        let host: ValidHost = u.arbitrary()?;
        let header_count: usize = u.int_in_range(0..=8)?;
        let headers: Vec<FuzzHeader> = (0..header_count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let body_strategy: BodyStrategy = u.arbitrary()?;
        let body_len: usize = match body_strategy {
            BodyStrategy::None => 0,
            _ => u.int_in_range(0..=4096)?,
        };
        let body = if body_len > 0 {
            u.bytes(body_len)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            method,
            path,
            host,
            headers,
            body_strategy,
            body,
        })
    }
}

impl HttpWireInput {
    /// Serialize to HTTP/1.1 wire format bytes.
    /// This is where smuggling mutations naturally emerge — the fuzzer
    /// can produce conflicting Content-Length and Transfer-Encoding,
    /// duplicate headers, CRLF injection in values, etc.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(512);

        // Request line
        wire.extend_from_slice(self.method.as_str().as_bytes());
        wire.extend_from_slice(b" ");
        wire.extend_from_slice(self.path.0.as_bytes());
        wire.extend_from_slice(b" HTTP/1.1\r\n");

        // Host header
        wire.extend_from_slice(b"Host: ");
        wire.extend_from_slice(self.host.0.as_bytes());
        wire.extend_from_slice(b"\r\n");

        // Body framing headers
        match self.body_strategy {
            BodyStrategy::None => {}
            BodyStrategy::ContentLength => {
                wire.extend_from_slice(
                    format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
                );
            }
            BodyStrategy::Chunked => {
                wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            BodyStrategy::Both => {
                // Intentional CL+TE conflict — HTTP request smuggling
                wire.extend_from_slice(
                    format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
                );
                wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
        }

        // Custom headers
        for h in &self.headers {
            wire.extend_from_slice(h.name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(h.value.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }

        // End of headers
        wire.extend_from_slice(b"\r\n");

        // Body
        match self.body_strategy {
            BodyStrategy::Chunked | BodyStrategy::Both => {
                // Chunked encoding
                wire.extend_from_slice(format!("{:x}\r\n", self.body.len()).as_bytes());
                wire.extend_from_slice(&self.body);
                wire.extend_from_slice(b"\r\n0\r\n\r\n");
            }
            _ => {
                wire.extend_from_slice(&self.body);
            }
        }

        wire
    }
}

// ═══════════════════════════════════════════════════════════════════
// WAL event fuzzing (with Merkle chain corruption)
// ═══════════════════════════════════════════════════════════════════

/// WAL event with optional corruption for Merkle integrity testing.
#[derive(Debug, Clone)]
pub struct WalEventInput {
    pub events: Vec<WalEvent>,
    pub corruption: WalCorruption,
}

/// Single WAL event line.
#[derive(Arbitrary, Debug, Clone)]
pub struct WalEvent {
    pub event_id: u64,
    pub agent_id_suffix: u8,
    pub method: HttpMethod,
    pub host_label: u8,
    pub path_label: u8,
    pub decision: WalDecision,
    pub status: WalStatus,
    pub is_batch_record: bool,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum WalDecision {
    Allow,
    Delay300,
    Deny,
    RequireApproval,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum WalStatus {
    Pending,
    Executed,
    Confirmed,
    Failed,
    Expired,
}

/// Corruption strategies for WAL parsing resilience.
#[derive(Arbitrary, Debug, Clone)]
pub enum WalCorruption {
    /// No corruption — valid WAL
    None,
    /// Duplicate event_id (state machine dedup test)
    DuplicateEventId,
    /// Truncated JSON line (simulate crash mid-write)
    TruncatedLine,
    /// Invalid UTF-8 bytes injected
    InvalidUtf8,
    /// Empty lines between events
    EmptyLines,
    /// Batch record with wrong merkle_root
    BadMerkleRoot,
}

impl WalEventInput {
    /// Serialize to JSONL (one JSON line per event).
    pub fn to_jsonl(&self) -> Vec<u8> {
        let mut output = Vec::new();
        let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";

        for (i, ev) in self.events.iter().enumerate() {
            if ev.is_batch_record {
                let batch = format!(
                    r#"{{"batch_id":{},"merkle_root":"{}","prev_batch_root":"{}","event_count":{},"timestamp":"2026-04-13T00:00:00Z"}}"#,
                    i,
                    if matches!(self.corruption, WalCorruption::BadMerkleRoot) {
                        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    } else {
                        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    },
                    prev_hash,
                    self.events.len(),
                );
                output.extend_from_slice(batch.as_bytes());
                output.push(b'\n');
                continue;
            }

            let event_id = match self.corruption {
                WalCorruption::DuplicateEventId if i > 0 => {
                    format!("evt-{:08x}", self.events[0].event_id)
                }
                _ => format!("evt-{:08x}", ev.event_id),
            };

            let decision = match ev.decision {
                WalDecision::Allow => "Allow",
                WalDecision::Delay300 => "Delay { milliseconds: 300 }",
                WalDecision::Deny => "Deny",
                WalDecision::RequireApproval => "RequireApproval { urgency: 1 }",
            };

            let status = match ev.status {
                WalStatus::Pending => "Pending",
                WalStatus::Executed => "Executed",
                WalStatus::Confirmed => "Confirmed",
                WalStatus::Failed => r#"Failed { reason: "test" }"#,
                WalStatus::Expired => "Expired",
            };

            let line = format!(
                r#"{{"event_id":"{}","trace_id":"trace-{}","parent_event_id":null,"agent_id":"agent-{}","tenant_id":null,"session_id":"sess-{}","timestamp":"2026-04-13T00:00:{:02}Z","operation":"test.op","resource":{{"service":"test","identifier":null,"tier":"External","sensitivity":"Medium"}},"context":{{}},"transport":{{"method":"{}","host":"host-{}.example.com","path":"/path-{}","status_code":null}},"decision":"{}","decision_source":"SRR","matched_rule_id":null,"enforcement_point":"proxy","status":"{}","payload":{{"content_hash":"","size_bytes":0,"flagged_patterns":[]}},"nats_sequence":null,"event_hash":"{}","default_caution":true}}"#,
                event_id,
                i,
                ev.agent_id_suffix,
                i,
                i % 60,
                ev.method.as_str(),
                ev.host_label,
                ev.path_label,
                decision,
                status,
                prev_hash,
            );

            match self.corruption {
                WalCorruption::TruncatedLine if i == self.events.len() / 2 => {
                    // Truncate mid-JSON
                    output.extend_from_slice(&line.as_bytes()[..line.len() / 2]);
                    output.push(b'\n');
                }
                WalCorruption::InvalidUtf8 if i == 0 => {
                    let mut bytes = line.into_bytes();
                    if bytes.len() > 10 {
                        bytes[5] = 0xFF;
                        bytes[6] = 0xFE;
                    }
                    output.extend_from_slice(&bytes);
                    output.push(b'\n');
                }
                WalCorruption::EmptyLines => {
                    output.extend_from_slice(line.as_bytes());
                    output.push(b'\n');
                    output.push(b'\n'); // extra empty line
                    output.push(b'\n');
                }
                _ => {
                    output.extend_from_slice(line.as_bytes());
                    output.push(b'\n');
                }
            }

            prev_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        }

        output
    }
}

impl<'a> Arbitrary<'a> for WalEventInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let count: usize = u.int_in_range(1..=20)?;
        let events: Vec<WalEvent> = (0..count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let corruption: WalCorruption = u.arbitrary()?;
        Ok(Self { events, corruption })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Path normalization fuzzing
// ═══════════════════════════════════════════════════════════════════

/// Path segment with adversarial encoding variations.
#[derive(Arbitrary, Debug, Clone)]
pub enum PathSegment {
    /// Normal literal segment
    Literal(u8), // index into a small word list
    /// Dot-segment: "." or ".."
    DotSingle,
    DotDouble,
    /// Percent-encoded dot: "%2e" or "%2E"
    PercentDot,
    /// Double-encoded: "%252e" (decodes to "%2e" then ".")
    DoubleEncoded,
    /// Null byte: "%00" or literal \0
    NullByte,
    /// Slash encoding: "%2f" or "%2F"
    EncodedSlash,
    /// Repeated 'a' for regex stress
    ReDoSPayload(u8), // repeat count
}

/// Fuzzy path from segments — more targeted than raw FuzzPath.
#[derive(Debug, Clone)]
pub struct NormalizePath(pub String);

impl<'a> Arbitrary<'a> for NormalizePath {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let words = ["api", "v1", "users", "transfer", "repos", "graphql"];
        let seg_count: usize = u.int_in_range(1..=10)?;
        let segments: Vec<PathSegment> = (0..seg_count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<_>>>()?;

        let mut path = String::from("/");
        for seg in &segments {
            match seg {
                PathSegment::Literal(idx) => {
                    path.push_str(words[(*idx as usize) % words.len()]);
                }
                PathSegment::DotSingle => path.push('.'),
                PathSegment::DotDouble => path.push_str(".."),
                PathSegment::PercentDot => path.push_str("%2e"),
                PathSegment::DoubleEncoded => path.push_str("%252e"),
                PathSegment::NullByte => path.push_str("%00"),
                PathSegment::EncodedSlash => path.push_str("%2f"),
                PathSegment::ReDoSPayload(n) => {
                    let count = (*n as usize).max(10).min(200);
                    for _ in 0..count {
                        path.push('a');
                    }
                }
            }
            path.push('/');
        }

        // Optionally append query string
        let has_query: bool = u.arbitrary()?;
        if has_query {
            path.push_str("?key=val&foo=bar");
        }

        Ok(Self(path))
    }
}
