//! URL path canonicalization and IPv6 host normalization.
//!
//! Extracted from src/srr.rs during the LOC cleanup pass. These are
//! the input-canonicalization defenses that run on every SRR check
//! before pattern matching, so an attacker cannot bypass a Deny rule
//! by encoding the same target in a different form
//! (`%2F` vs `/`, `[::1]` vs `localhost`, `[::ffff:127.0.0.1]` vs
//! `127.0.0.1`, etc.).
//!
//! Pure helpers: every function here is a `fn` with no shared state.
//! Cross-callable inside the module (`percent_decode_path` →
//! `percent_decode_once` → `hex_val`; `normalize_host` →
//! `is_ipv6_loopback` / `extract_ipv4_mapped` / `is_cloud_metadata_ipv6`
//! → `expand_ipv6`).

/// Canonicalize a request path to prevent SRR bypass via path manipulation.
///
/// Defenses:
/// - Percent-decoding: `%2F` → `/`, `%2e` → `.` (prevents encoded bypass)
/// - Null byte stripping: `/transfer%00` → `/transfer` (prevents null injection)
/// - Double-slash collapse: `//transfer` → `/transfer`
/// - Dot-segment resolution: `/a/../transfer` → `/transfer` (RFC 3986 §5.2.4)
/// - Trailing normalization: preserves trailing slash semantics
///
/// Returns None if the path is already in canonical form (avoids allocation).
pub(super) fn normalize_path(path: &str) -> Option<String> {
    // Step 0: Strip query string and fragment before any normalization.
    // SRR rules match on path only — query params (?per_page=5) and
    // fragments (#section) must not affect regex matching.
    // Without this, path_regex = "^/repos/.../commits$" fails on
    // "/repos/.../commits?per_page=5" because $ requires end-of-string.
    let (path_only, _query) = path.split_once('?').unwrap_or((path, ""));
    let (path_only, _fragment) = path_only.split_once('#').unwrap_or((path_only, ""));

    // Step 1: Percent-decode the path (iterative — catches double encoding %2525 → %25 → %)
    let decoded = percent_decode_path(path_only);
    let working = decoded.as_deref().unwrap_or(path_only);

    // Step 2: Strip null bytes
    let has_null = working.contains('\0');

    // Step 3: Check if any normalization is actually needed
    let has_double_slash = working.contains("//");
    let has_dot_segment = working.contains("/./")
        || working.contains("/../")
        || working.ends_with("/..")
        || working.ends_with("/.");

    // If query/fragment was stripped, we must return the stripped path
    // even if no other normalization is needed. Otherwise the caller
    // falls back to the original path (with query string).
    let query_stripped = path_only.len() < path.len();

    if decoded.is_none() && !has_null && !has_double_slash && !has_dot_segment {
        if query_stripped {
            return Some(path_only.to_string());
        }
        return None; // Already canonical, no query/fragment present
    }

    // Step 4: Build canonical path
    let clean: String = if has_null {
        working.replace('\0', "")
    } else {
        working.to_string()
    };

    // Step 5: Collapse double slashes
    let mut result = String::with_capacity(clean.len());
    let mut prev_slash = false;
    for ch in clean.chars() {
        if ch == '/' {
            if !prev_slash {
                result.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            result.push(ch);
        }
    }

    // Step 6: Resolve dot segments (RFC 3986 §5.2.4)
    let resolved = resolve_dot_segments(&result);

    Some(resolved)
}

/// Percent-decode path-relevant characters, iteratively.
/// Decodes %XX sequences to their byte values. Loops up to 3 times to
/// catch double-encoding attacks (%2525 → %25 → %). Stops when no
/// further decoding occurs (fixpoint).
/// Returns None if no percent-encoded sequences are found.
fn percent_decode_path(path: &str) -> Option<String> {
    if !path.contains('%') {
        return None;
    }

    let mut current = path.to_string();
    let mut changed = false;

    for _ in 0..3 {
        let decoded = percent_decode_once(&current);
        match decoded {
            Some(d) if d != current => {
                changed = true;
                current = d;
                if !current.contains('%') {
                    break; // No more percent sequences
                }
            }
            _ => break, // No change or decode error → fixpoint reached
        }
    }

    if changed {
        Some(current)
    } else {
        None
    }
}

/// Single pass of percent decoding.
fn percent_decode_once(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(result).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Resolve dot segments per RFC 3986 §5.2.4.
/// "/a/b/../c" → "/a/c", "/a/./b" → "/a/b"
fn resolve_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {} // Skip current-directory references
            ".." => {
                // Go up one level, but never above root
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    let resolved = segments.join("/");
    if resolved.starts_with('/') || resolved.is_empty() {
        resolved
    } else {
        format!("/{}", resolved)
    }
}

/// Normalize IPv6 host addresses so SSRF rules written for their
/// canonical (usually IPv4) form still match.
///
/// Coverage matrix (each row maps a class of IPv6 bypass attempt to
/// a sentinel that SRR rules can pattern-match):
///
/// | Class | Example | Sentinel |
/// |---|---|---|
/// | Loopback | `[::1]`, `[0:0:0:0:0:0:0:1]` | `localhost` |
/// | Unspecified | `[::]` | `unspecified.ipv6.invalid` |
/// | IPv4-mapped | `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]` | underlying IPv4 |
/// | IPv4-compatible (deprecated) | `[::127.0.0.1]` | underlying IPv4 |
/// | 6to4 encapsulation | `[2002:7f00:1::]` | underlying IPv4 |
/// | Link-local | `[fe80::1]`, `[fe80::1%eth0]` | `link-local.ipv6.invalid` |
/// | Unique Local (ULA) | `[fd12:3456:789a::1]`, `[fc00::1]` | `unique-local.ipv6.invalid` |
/// | Multicast | `[ff02::1]`, `[ff05::1]` | `multicast.ipv6.invalid` |
/// | Cloud metadata (AWS IPv6) | `[fd00:ec2::254]` | `169.254.169.254` |
/// | Cloud metadata (IPv4-mapped) | `[::ffff:169.254.169.254]` | `169.254.169.254` |
///
/// The `.invalid` sentinels use RFC 2606's reserved TLD so they can
/// never collide with a real domain. Operators are expected to add
/// SRR deny rules that pattern-match these sentinels for the range
/// classes; see [docs/security-model.md § 9](../../docs/security-model.md#9-ipv6-ssrf-mitigated)
/// for the recommended starter rule pack.
///
/// Returns None if no normalization was applied (the host is either
/// not an IPv6 address, or is a public IPv6 outside any of these
/// classes).
pub(super) fn normalize_host(host: &str) -> Option<String> {
    // Strip brackets if present: [::1] → ::1
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .or_else(|| {
            // Also handle [::1]:port → ::1
            host.strip_prefix('[').and_then(|h| h.split(']').next())
        });

    let ipv6 = inner?;

    // Strip zone ID (RFC 4007) — `fe80::1%eth0` → `fe80::1`. A zone
    // ID is meaningful at the OS level but is not part of the IPv6
    // address itself, and an attacker can slap one on to try to skip
    // range detection.
    let without_zone = ipv6.split('%').next().unwrap_or(ipv6);

    // Normalize: remove leading zeros, lowercase
    let normalized = without_zone.to_lowercase();
    let segments = expand_ipv6(&normalized);

    // Check for loopback variants (::1)
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return Some("localhost".to_string());
    }

    // Unspecified :: — some stacks route this to loopback.
    if segments == [0; 8] {
        return Some("unspecified.ipv6.invalid".to_string());
    }

    // IPv4-mapped ::ffff:a.b.c.d (segments 0-4 zero, seg 5 = 0xffff)
    if let Some(v4) = extract_ipv4_mapped(&normalized, &segments) {
        return Some(v4);
    }

    // IPv4-compatible ::a.b.c.d (deprecated RFC 4291 form: segs 0-5
    // all zero, IPv4 in the low 32 bits). Some legacy resolvers still
    // handle this even though it was deprecated in 2006 — treat as
    // IPv4-mapped for range-check purposes.
    if let Some(v4) = extract_ipv4_compatible(&normalized, &segments) {
        return Some(v4);
    }

    // 6to4 encapsulation 2002:AABB:CCDD::/48 — segments 1 and 2
    // hex-encode the public IPv4 the tunnel exits from. An attacker
    // can craft `[2002:7f00:1::]` to embed 127.0.0.1 and evade the
    // IPv4-mapped detector.
    if let Some(v4) = extract_6to4_ipv4(&segments) {
        return Some(v4);
    }

    // Known cloud metadata IPv6 addresses (currently AWS-specific).
    if is_cloud_metadata_ipv6(&segments) {
        return Some("169.254.169.254".to_string());
    }

    // Range-class checks (return categorical sentinels rather than
    // extracting an underlying IPv4 — these ranges don't embed one).
    if is_ipv6_link_local(&segments) {
        return Some("link-local.ipv6.invalid".to_string());
    }
    if is_ipv6_unique_local(&segments) {
        return Some("unique-local.ipv6.invalid".to_string());
    }
    if is_ipv6_multicast(&segments) {
        return Some("multicast.ipv6.invalid".to_string());
    }

    None
}

/// Extract IPv4 address from an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
/// Preserves dotted-decimal notation when the original used it, otherwise
/// reassembles from the hex segments.
fn extract_ipv4_mapped(addr: &str, segments: &[u16; 8]) -> Option<String> {
    // IPv4-mapped: first 5 segments zero, 6th = 0xffff
    if segments[0..5] != [0, 0, 0, 0, 0] || segments[5] != 0xffff {
        return None;
    }
    Some(ipv4_from_low32(addr, segments))
}

/// Extract IPv4 from the deprecated IPv4-compatible IPv6 form `::a.b.c.d`
/// (RFC 4291 §2.5.5.1, deprecated in RFC 4291 §2.5.5). Segments 0-5 all
/// zero, IPv4 in the low 32 bits. Distinct from IPv4-mapped by seg 5:
/// 0xffff for mapped, 0x0000 for compatible.
fn extract_ipv4_compatible(addr: &str, segments: &[u16; 8]) -> Option<String> {
    if segments[0..6] != [0, 0, 0, 0, 0, 0] {
        return None;
    }
    // Exclude ::, ::1 which are unspecified/loopback and handled earlier.
    if segments[6] == 0 && (segments[7] == 0 || segments[7] == 1) {
        return None;
    }
    Some(ipv4_from_low32(addr, segments))
}

/// Extract IPv4 from 6to4 encapsulation `2002:AABB:CCDD::/48`.
/// Segments 1 and 2 hex-encode the public IPv4 the tunnel exits from.
fn extract_6to4_ipv4(segments: &[u16; 8]) -> Option<String> {
    if segments[0] != 0x2002 {
        return None;
    }
    let a = (segments[1] >> 8) as u8;
    let b = (segments[1] & 0xff) as u8;
    let c = (segments[2] >> 8) as u8;
    let d = (segments[2] & 0xff) as u8;
    Some(format!("{}.{}.{}.{}", a, b, c, d))
}

/// Reassemble an IPv4 dotted-decimal string from the low 32 bits of the
/// IPv6 segments. Prefers the original dotted notation if the address
/// used it — avoids re-encoding `[::ffff:127.0.0.1]` as `127.0.0.1`
/// via hex (which is lossless but harder to audit-diff).
fn ipv4_from_low32(addr: &str, segments: &[u16; 8]) -> String {
    if let Some(dot_pos) = addr.rfind('.') {
        if let Some(colon_before_v4) = addr[..dot_pos].rfind(':') {
            let v4_str = &addr[colon_before_v4 + 1..];
            if v4_str.contains('.') {
                return v4_str.to_string();
            }
        }
    }
    let a = (segments[6] >> 8) as u8;
    let b = (segments[6] & 0xff) as u8;
    let c = (segments[7] >> 8) as u8;
    let d = (segments[7] & 0xff) as u8;
    format!("{}.{}.{}.{}", a, b, c, d)
}

/// Link-local range `fe80::/10` (RFC 4291 §2.5.6). First 10 bits are
/// `1111111010`. Common attack payloads target the default gateway
/// (`[fe80::1]`) or neighbor-discovery services.
fn is_ipv6_link_local(segments: &[u16; 8]) -> bool {
    (segments[0] & 0xffc0) == 0xfe80
}

/// Unique Local Address (ULA) range `fc00::/7` (RFC 4193). First 7
/// bits are `1111110`. Used for private internal networks; SSRF into
/// these hits sandbox neighbors and internal services.
fn is_ipv6_unique_local(segments: &[u16; 8]) -> bool {
    (segments[0] & 0xfe00) == 0xfc00
}

/// Multicast range `ff00::/8` (RFC 4291 §2.7). First 8 bits are all 1.
/// Includes all-nodes `[ff02::1]`, all-routers, site-local scopes.
fn is_ipv6_multicast(segments: &[u16; 8]) -> bool {
    (segments[0] & 0xff00) == 0xff00
}

/// Check if an IPv6 address is a known cloud metadata endpoint. AWS is
/// the only cloud provider with a documented IPv6 metadata address
/// (`fd00:ec2::254`); GCP and Azure metadata services are IPv4-only or
/// DNS-resolved and are covered by the DNS-governance layer.
fn is_cloud_metadata_ipv6(segments: &[u16; 8]) -> bool {
    // AWS IPv6 metadata: fd00:ec2::254
    *segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
}

/// Expand an IPv6 address string into 8 u16 segments.
/// Handles :: zero-compression and IPv4-mapped dotted notation.
pub(super) fn expand_ipv6(addr: &str) -> [u16; 8] {
    let mut result = [0u16; 8];

    // Handle IPv4-mapped with dotted notation (e.g., ::ffff:127.0.0.1)
    let (ipv6_part, ipv4_tail) = if let Some(last_colon) = addr.rfind(':') {
        let after = &addr[last_colon + 1..];
        if after.contains('.') {
            // Parse IPv4 part
            let parts: Vec<&str> = after.split('.').collect();
            if parts.len() == 4 {
                if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                    parts[0].parse::<u8>(),
                    parts[1].parse::<u8>(),
                    parts[2].parse::<u8>(),
                    parts[3].parse::<u8>(),
                ) {
                    let seg6 = ((a as u16) << 8) | (b as u16);
                    let seg7 = ((c as u16) << 8) | (d as u16);
                    (&addr[..last_colon], Some((seg6, seg7)))
                } else {
                    (addr, None)
                }
            } else {
                (addr, None)
            }
        } else {
            (addr, None)
        }
    } else {
        (addr, None)
    };

    // Split on :: for zero-compression
    let parts: Vec<&str> = ipv6_part.split("::").collect();
    let max_segments = if ipv4_tail.is_some() { 6 } else { 8 };

    match parts.len() {
        1 => {
            // No :: — parse all segments
            for (i, seg) in parts[0].split(':').enumerate() {
                if i < max_segments && !seg.is_empty() {
                    result[i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }
        }
        2 => {
            // Has :: — left segments + gap + right segments
            let left: Vec<&str> = if parts[0].is_empty() {
                vec![]
            } else {
                parts[0].split(':').collect()
            };
            let right: Vec<&str> = if parts[1].is_empty() {
                vec![]
            } else {
                parts[1].split(':').collect()
            };

            // Length guard MUST run before we touch `result[i]`. The left
            // loop below indexes `result` by `i` directly, so a malformed
            // input with > max_segments left tokens (e.g. "1:2:3:4:5:6:7:8:9::")
            // would panic with index out of bounds before we ever reach
            // the post-loop check. Discovered by libFuzzer (fuzz_srr,
            // fuzz_path_normalize) — bounds_check panic at this exact site.
            if left.len() > max_segments
                || right.len() > max_segments
                || left.len() + right.len() > max_segments
            {
                return result; // Malformed — fail closed to all zeros
            }

            for (i, seg) in left.iter().enumerate() {
                if !seg.is_empty() {
                    result[i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }

            let right_start = max_segments - right.len();
            for (i, seg) in right.iter().enumerate() {
                if !seg.is_empty() {
                    result[right_start + i] = u16::from_str_radix(seg, 16).unwrap_or(0);
                }
            }
        }
        _ => {} // Invalid — return all zeros
    }

    if let Some((seg6, seg7)) = ipv4_tail {
        result[6] = seg6;
        result[7] = seg7;
    }

    result
}
