# Rego policy — semantic equivalent of scripts/comparison/srr-bench.toml.
#
# The package name `envoy.authz` matches what envoy-extauthz.yaml and
# envoy-wasm.yaml expect. Decision is exposed via `allow` (default false)
# and `result` (rich object for ext_authz).
#
# Logical rules (same as SRR side):
#   1. Allow  api.anthropic.com/*  any method
#   2. Deny   POST api.bank.com/transfer
#   3. Default: Allow with audit (Rego cannot natively express "audit
#      only" the way SRR does — closest match is `allow = true` with
#      an `audit: true` marker on the result object.)
#
# Input shape (Envoy ext_authz):
#   input.attributes.request.http = { host, path, method, ... }
# Input shape (OPA-WASM filter):
#   same shape via Envoy's WASM context — the filter populates the
#   identical envelope.

package envoy.authz

import future.keywords.if
import future.keywords.in

default allow := true

default result := {
    "allowed": true,
    "rule": "default-allow-audit",
    "audit": true,
}

# Rule 1 — Allow LLM API (any method).
result := r if {
    input.attributes.request.http.host == "api.anthropic.com"
    r := {
        "allowed": true,
        "rule": "anthropic-allow",
        "audit": false,
    }
}

allow if {
    input.attributes.request.http.host == "api.anthropic.com"
}

# Rule 2 — Deny POST api.bank.com/transfer.
deny if {
    input.attributes.request.http.host == "api.bank.com"
    input.attributes.request.http.path == "/transfer"
    input.attributes.request.http.method == "POST"
}

result := r if {
    deny
    r := {
        "allowed": false,
        "rule": "bank-transfer-deny",
        "audit": true,
        "reason": "Payment endpoint requires explicit approval",
    }
}

allow := false if {
    deny
}
