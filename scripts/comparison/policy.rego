# Rego policy — semantic equivalent of srr-bench.toml.
#
# Bench target is the synthetic hostname `bench.local`, mapped to the
# EC2 host's primary IP at the system layer (host /etc/hosts on the GVM
# side; `docker run --add-host` for the OPA+Envoy side). The agent
# inside isolation uses HTTP_PROXY=envoy to forward requests through
# Envoy; OPA receives the Host header as `bench.local:9999` and matches
# on that string.
#
# Allow / Deny discrimination is by path + method (host is constant
# across scenarios). Matches the SRR rules in srr-bench.toml.

package envoy.authz

import future.keywords.if

default allow := true

default result := {
    "allowed": true,
    "rule": "bench-allow",
}

# Deny POST /transfer on the bench host.
deny if {
    input.attributes.request.http.host == "bench.local:9999"
    input.attributes.request.http.path == "/transfer"
    input.attributes.request.http.method == "POST"
}

result := r if {
    deny
    r := {
        "allowed": false,
        "rule": "bench-deny",
        "reason": "Bench deny scenario",
    }
}

allow := false if {
    deny
}
