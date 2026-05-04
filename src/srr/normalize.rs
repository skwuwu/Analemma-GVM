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

/// Normalize IPv6 host addresses to their canonical IPv4 equivalents.
///
/// This prevents SSRF bypass via IPv6 variants:
/// - `[::1]` → `localhost` (IPv6 loopback)
/// - `[::ffff:127.0.0.1]` → `127.0.0.1` (IPv4-mapped IPv6)
/// - `[0:0:0:0:0:ffff:127.0.0.1]` → `127.0.0.1` (full-form IPv4-mapped)
/// - `[::ffff:7f00:1]` → `127.0.0.1` (hex IPv4-mapped)
/// - `[fd00:ec2::254]` → `metadata.aws.ipv6` (AWS IPv6 metadata)
/// - `[::ffff:169.254.169.254]` → `169.254.169.254` (cloud metadata IPv4-mapped)
///
/// Returns None if no normalization needed (host is already in canonical form).
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

    // Normalize: remove leading zeros, lowercase
    let normalized = ipv6.to_lowercase();

    // Check for loopback variants
    if is_ipv6_loopback(&normalized) {
        return Some("localhost".to_string());
    }

    // Check for IPv4-mapped addresses: ::ffff:a.b.c.d or 0:0:0:0:0:ffff:a.b.c.d
    if let Some(v4) = extract_ipv4_mapped(&normalized) {
        return Some(v4);
    }

    // Check for known cloud metadata IPv6 addresses
    if is_cloud_metadata_ipv6(&normalized) {
        return Some("169.254.169.254".to_string());
    }

    None
}

/// Check if an IPv6 address (without brackets) is a loopback.
/// Covers: ::1, 0::1, 0:0:0:0:0:0:0:1 and all zero-compression variants.
fn is_ipv6_loopback(addr: &str) -> bool {
    // Parse by expanding :: and checking if result is 0:0:0:0:0:0:0:1
    let expanded = expand_ipv6(addr);
    expanded == [0, 0, 0, 0, 0, 0, 0, 1]
}

/// Extract IPv4 address from an IPv4-mapped IPv6 address.
/// ::ffff:127.0.0.1 → Some("127.0.0.1")
/// ::ffff:7f00:1 → Some("127.0.0.1")
/// 0:0:0:0:0:ffff:a9fe:a9fe → Some("169.254.169.254")
fn extract_ipv4_mapped(addr: &str) -> Option<String> {
    let segments = expand_ipv6(addr);

    // IPv4-mapped: first 5 segments zero, 6th = 0xffff
    if segments[0..5] != [0, 0, 0, 0, 0] || segments[5] != 0xffff {
        return None;
    }

    // Check if the original has dotted-decimal notation (::ffff:1.2.3.4)
    if let Some(dot_pos) = addr.rfind('.') {
        // Find the IPv4 part after the last colon before the dotted section
        let colon_before_v4 = addr[..dot_pos].rfind(':')?;
        let v4_str = &addr[colon_before_v4 + 1..];
        if v4_str.contains('.') {
            return Some(v4_str.to_string());
        }
    }

    // Hex form: segments 6 and 7 encode the IPv4 address
    let a = (segments[6] >> 8) as u8;
    let b = (segments[6] & 0xff) as u8;
    let c = (segments[7] >> 8) as u8;
    let d = (segments[7] & 0xff) as u8;
    Some(format!("{}.{}.{}.{}", a, b, c, d))
}

/// Check if an IPv6 address is a known cloud metadata endpoint.
fn is_cloud_metadata_ipv6(addr: &str) -> bool {
    let segments = expand_ipv6(addr);
    // AWS IPv6 metadata: fd00:ec2::254
    // Expanded: fd00:ec2:0:0:0:0:0:254 → [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
    if segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
        return true;
    }
    false
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
