//! `gvm import openapi <spec.{yaml,json}>` — emit a deny-by-default SRR
//! ruleset from an OpenAPI spec.
//!
//! Tier-2 P2-b from the strategic-audit roadmap. Combined with the
//! provider action packs (P2-a) this means an operator can spin up a
//! baseline policy for any internal or third-party API without
//! hand-writing one path_regex per endpoint. The audit vocabulary
//! stays the same — `operationId` becomes the rule's `description`,
//! which surfaces in the WAL as `matched_rule_id`.
//!
//! Conservative defaults:
//!   * every operation gets `decision = { type = "Deny",
//!     reason = "outside imported baseline" }`
//!   * the host comes from `servers[0].url`
//!   * path templates (`/users/{id}`) become path_regex
//!     (`^/users/[^/]+$`)
//!   * `operationId` becomes both `description` (canonical action name)
//!     and `label` (snake_case form)
//!
//! Operators run `gvm import openapi spec.yaml > srr_network.toml`,
//! review the file, and promote individual rules to Allow / Delay /
//! RequireApproval by hand (or with a follow-up lease). The importer
//! deliberately does NOT try to be smart about read/write/destructive
//! risk classes — the OpenAPI spec doesn't carry that information
//! reliably (you cannot infer "destructive" from HTTP method alone in
//! every API), and a wrong guess that produces an Allow rule is the
//! worst-of-all-worlds.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The subset of OpenAPI 3.x we read. Anything else is ignored.
#[derive(Debug, Deserialize)]
struct OpenApi {
    #[serde(default)]
    servers: Vec<Server>,
    #[serde(default)]
    paths: BTreeMap<String, PathItem>,
}

#[derive(Debug, Deserialize)]
struct Server {
    url: String,
}

/// One path → potentially multiple operations (GET, POST, PUT, ...).
/// We deserialise each HTTP verb individually so unknown fields stay
/// unparsed without failing the whole file.
#[derive(Debug, Default, Deserialize)]
struct PathItem {
    #[serde(default)]
    get: Option<Operation>,
    #[serde(default)]
    post: Option<Operation>,
    #[serde(default)]
    put: Option<Operation>,
    #[serde(default)]
    patch: Option<Operation>,
    #[serde(default)]
    delete: Option<Operation>,
    #[serde(default)]
    head: Option<Operation>,
    #[serde(default)]
    options: Option<Operation>,
}

impl PathItem {
    fn operations(&self) -> impl Iterator<Item = (&'static str, &Operation)> {
        [
            ("GET", self.get.as_ref()),
            ("POST", self.post.as_ref()),
            ("PUT", self.put.as_ref()),
            ("PATCH", self.patch.as_ref()),
            ("DELETE", self.delete.as_ref()),
            ("HEAD", self.head.as_ref()),
            ("OPTIONS", self.options.as_ref()),
        ]
        .into_iter()
        .filter_map(|(verb, op)| op.map(|o| (verb, o)))
    }
}

#[derive(Debug, Deserialize)]
struct Operation {
    /// Required by OpenAPI for code-generators; we use it as the
    /// canonical action name in the rule's `description`. When
    /// missing, we synthesise a placeholder from method + path so the
    /// importer still produces a usable file — the operator is
    /// expected to rename it.
    #[serde(rename = "operationId", default)]
    operation_id: Option<String>,
    /// Optional human-readable summary, used as a TOML comment above
    /// the rule.
    #[serde(default)]
    summary: Option<String>,
}

/// Imported rule, ready to be serialised as a TOML block.
struct ImportedRule {
    method: String,
    host: String,
    path_regex: String,
    description: String,
    label: String,
    summary: Option<String>,
}

/// Parse an OpenAPI spec file and return the rules it produces.
///
/// The file extension picks the parser: `.yaml` / `.yml` use the YAML
/// parser, `.json` and anything else fall through to the YAML parser
/// too (YAML is a superset of JSON for our purposes). Errors at parse
/// time include the file path and the original parser error.
pub fn import_openapi(spec_path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(spec_path)
        .with_context(|| format!("read OpenAPI spec {}", spec_path.display()))?;
    let spec: OpenApi = serde_yaml::from_str(&content)
        .with_context(|| format!("parse OpenAPI spec {}", spec_path.display()))?;

    let (host, base_path) = extract_host_and_base_path(&spec)?;

    let mut rules = Vec::new();
    for (path_template, item) in &spec.paths {
        for (method, op) in item.operations() {
            let path_regex = path_template_to_regex(&base_path, path_template);
            let action_name = op
                .operation_id
                .clone()
                .unwrap_or_else(|| synthesised_operation_id(method, path_template));
            let label = to_snake_case(&action_name);
            rules.push(ImportedRule {
                method: method.to_string(),
                host: host.clone(),
                path_regex,
                description: action_name,
                label,
                summary: op.summary.clone(),
            });
        }
    }

    Ok(rules.into_iter().map(render_rule).collect())
}

/// Public entry: take a spec, return the full TOML body (file header +
/// rule blocks). Callers either print this to stdout or write it to a
/// file.
pub fn import_openapi_to_toml(spec_path: &Path) -> Result<String> {
    let mut out = String::new();
    out.push_str(&file_header(spec_path));
    for block in import_openapi(spec_path)? {
        out.push('\n');
        out.push_str(&block);
    }
    Ok(out)
}

/// Pull `host` and any base path out of `servers[0].url`.
///
/// `https://api.example.com/v1` → (`api.example.com`, `/v1`).
/// `https://internal.corp` → (`internal.corp`, ``).
/// Missing scheme → assume the operator wrote a bare host.
fn extract_host_and_base_path(spec: &OpenApi) -> Result<(String, String)> {
    let server = spec
        .servers
        .first()
        .context("OpenAPI spec has no `servers` entries; cannot infer host")?;
    let url = server.url.trim();
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let (host, base_path) = match stripped.find('/') {
        Some(idx) => (stripped[..idx].to_string(), stripped[idx..].to_string()),
        None => (stripped.to_string(), String::new()),
    };
    // Normalise trailing slash so concatenation with the path template
    // never produces `//`.
    let base_path = base_path.trim_end_matches('/').to_string();
    Ok((host, base_path))
}

/// Turn `/users/{id}/posts/{post_id}` into the corresponding regex
/// `^/v1/users/[^/]+/posts/[^/]+$` (with the base_path prepended).
///
/// `{name}` segments become `[^/]+` (one or more non-slash characters);
/// everything else is taken verbatim. Regex metacharacters in the path
/// (rare but legal — e.g. literal dots in version paths) are escaped
/// so they match themselves.
fn path_template_to_regex(base_path: &str, path_template: &str) -> String {
    let mut out = String::with_capacity(path_template.len() * 2 + base_path.len() + 4);
    out.push('^');
    // base_path is empty-or-leading-slash form by construction.
    for ch in base_path.chars() {
        escape_regex_char(ch, &mut out);
    }
    let mut chars = path_template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            // Consume until the matching close brace; replace the whole
            // {name} with the single-segment wildcard.
            for inner in chars.by_ref() {
                if inner == '}' {
                    break;
                }
            }
            out.push_str("[^/]+");
        } else {
            escape_regex_char(ch, &mut out);
        }
    }
    out.push('$');
    out
}

fn escape_regex_char(ch: char, out: &mut String) {
    // Subset of regex metacharacters we may see in URL paths. Slashes
    // are safe and emitted verbatim; everything else with regex
    // semantics is backslash-escaped.
    match ch {
        '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
            out.push('\\');
            out.push(ch);
        }
        _ => out.push(ch),
    }
}

/// When an operation has no `operationId`, build one from method +
/// path so the generated rule is still serialisable and editable.
///
/// `GET /users/{id}` → `get_users_id`. Operators are expected to
/// rename these placeholders before shipping the file.
fn synthesised_operation_id(method: &str, path_template: &str) -> String {
    let cleaned: String = path_template
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c,
            _ => '_',
        })
        .collect();
    let collapsed = cleaned
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    format!("{}_{}", method.to_lowercase(), collapsed)
}

/// `listUsers` → `list_users`, `users.list` → `users_list`. Preserves
/// ASCII letters and digits, lower-cases, replaces every other char
/// with `_`, collapses runs of `_`.
fn to_snake_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_under = false;
    let mut prev_lower = false;
    for ch in input.chars() {
        let push = match ch {
            'A'..='Z' => {
                // Insert separator before a new word when the previous
                // char was lowercase or a digit.
                if prev_lower && !prev_under {
                    out.push('_');
                }
                ch.to_ascii_lowercase()
            }
            'a'..='z' | '0'..='9' => ch.to_ascii_lowercase(),
            _ => '_',
        };
        if push == '_' {
            if !prev_under && !out.is_empty() {
                out.push('_');
                prev_under = true;
            }
            prev_lower = false;
        } else {
            out.push(push);
            prev_under = false;
            prev_lower = push.is_ascii_lowercase();
        }
    }
    out.trim_end_matches('_').to_string()
}

fn file_header(spec_path: &Path) -> String {
    format!(
        "# Generated by `gvm import openapi {}`\n\
         #\n\
         # Conservative deny-by-default baseline. Every operation in\n\
         # the spec produces one [[rules]] block with `decision = {{ type = \"Deny\" }}`.\n\
         # Review each rule and promote to Allow / Delay / RequireApproval\n\
         # explicitly; pair with `principal_filter` + `expires_at` to\n\
         # issue per-task leases.\n\
         #\n\
         # Action names in `description` are taken verbatim from the\n\
         # spec's `operationId`. Operations without an `operationId`\n\
         # get a method+path placeholder you should rename.\n",
        spec_path.display()
    )
}

fn render_rule(r: ImportedRule) -> String {
    let mut out = String::with_capacity(256);
    if let Some(summary) = &r.summary {
        for line in summary.lines() {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("[[rules]]\n");
    out.push_str(&format!("method = {:?}\n", r.method));
    out.push_str(&format!("pattern = \"{}/{{any}}\"\n", r.host));
    out.push_str(&format!("path_regex = {:?}\n", r.path_regex));
    out.push_str("decision = { type = \"Deny\", reason = \"outside imported baseline\" }\n");
    out.push_str(&format!("description = {:?}\n", r.description));
    out.push_str(&format!("label = {:?}\n", r.label));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_template_to_regex_basic_param() {
        let r = path_template_to_regex("/v1", "/users/{id}");
        assert_eq!(r, "^/v1/users/[^/]+$");
    }

    #[test]
    fn path_template_to_regex_multiple_params() {
        let r = path_template_to_regex("", "/users/{user_id}/posts/{post_id}");
        assert_eq!(r, "^/users/[^/]+/posts/[^/]+$");
    }

    #[test]
    fn path_template_escapes_regex_metacharacters() {
        // OpenAPI paths can legitimately contain dots (rare, but legal
        // for things like `/v1.0/users`) — must be regex-escaped.
        let r = path_template_to_regex("", "/v1.0/users");
        assert_eq!(r, "^/v1\\.0/users$");
    }

    #[test]
    fn extract_host_strips_scheme_and_base_path() {
        let spec = OpenApi {
            servers: vec![Server {
                url: "https://api.example.com/v1".to_string(),
            }],
            paths: Default::default(),
        };
        let (host, base) = extract_host_and_base_path(&spec).unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(base, "/v1");
    }

    #[test]
    fn extract_host_handles_no_base_path() {
        let spec = OpenApi {
            servers: vec![Server {
                url: "https://internal.corp".to_string(),
            }],
            paths: Default::default(),
        };
        let (host, base) = extract_host_and_base_path(&spec).unwrap();
        assert_eq!(host, "internal.corp");
        assert_eq!(base, "");
    }

    #[test]
    fn snake_case_camel_to_snake() {
        assert_eq!(to_snake_case("listUsers"), "list_users");
        assert_eq!(to_snake_case("getUserById"), "get_user_by_id");
    }

    #[test]
    fn snake_case_dotted_to_snake() {
        assert_eq!(to_snake_case("users.list"), "users_list");
        assert_eq!(to_snake_case("github.pr.merge"), "github_pr_merge");
    }
}
