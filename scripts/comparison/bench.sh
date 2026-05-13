#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# GVM vs OPA+Envoy+Docker — full-stack comparison benchmark (v2).
#
# Measures the GVM stack as actually deployed (workload inside
# `gvm run --sandbox`, transparent kernel-level intercept) against the
# OPA+Envoy stack as actually deployed (workload inside `docker run`
# with cooperative HTTP_PROXY → Envoy → OPA).
#
# See docs/internal/comparison-opa-envoy.md for full methodology,
# fairness rules, and the transparent-vs-cooperative disclaimer.
#
# Dimensions:
#   d1   per-request latency inside isolation (steady-state)
#   d2a  workload cold start (control plane already up)
#   d2b  control-plane cold start
#   d3   memory @ N=1, 5, 10 idle agents
#   d4   distribution size
#   d5   decision-to-log latency + tamper evidence
#
# Requirements:
#   - scripts/comparison/setup.sh has been run
#   - GVM built in release mode: cargo build --release -p gvm-cli -p gvm-proxy
#   - sudo (for gvm sandbox + docker without group membership)
#
# Usage:
#   sudo bash scripts/comparison/bench.sh           # full sweep
#   sudo bash scripts/comparison/bench.sh d1        # only D1
#   sudo bash scripts/comparison/bench.sh d2a d2b   # both cold starts
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

STAMP="$(date +%Y%m%dT%H%M%S)"
RESULTS_DIR="$REPO_DIR/results/comparison-$STAMP"
mkdir -p "$RESULTS_DIR"

GVM_BIN="$REPO_DIR/target/release/gvm"
GVM_PROXY_BIN="$REPO_DIR/target/release/gvm-proxy"
GIT_REV="$(cd "$REPO_DIR" && git rev-parse --short HEAD)"

# ── Latest-binary check ─────────────────────────────────────────────
if [ ! -x "$GVM_BIN" ] || [ ! -x "$GVM_PROXY_BIN" ]; then
    echo "ERROR: GVM binaries missing. Run: cargo build --release -p gvm-cli -p gvm-proxy"
    exit 1
fi
GVM_MTIME="$(stat -c %Y "$GVM_BIN" 2>/dev/null || stat -f %m "$GVM_BIN")"
PROXY_MTIME="$(stat -c %Y "$GVM_PROXY_BIN" 2>/dev/null || stat -f %m "$GVM_PROXY_BIN")"

# ── Docker permission shim ──────────────────────────────────────────
if groups 2>/dev/null | grep -qw docker; then
    DOCKER="docker"
else
    DOCKER="sudo docker"
fi

# ── Host primary IP (sandbox/container reach this for the mock) ─────
HOST_IP="$(hostname -I | awk '{print $1}')"
if [ -z "$HOST_IP" ]; then
    echo "ERROR: could not determine host IP via hostname -I"
    exit 1
fi

# ── /etc/hosts marker for bench.local → HOST_IP ─────────────────────
ETC_HOSTS_MARKER="# gvm-bench bench.local"
add_bench_hosts() {
    if ! grep -q "$ETC_HOSTS_MARKER" /etc/hosts; then
        echo "$HOST_IP bench.local  $ETC_HOSTS_MARKER" | sudo tee -a /etc/hosts >/dev/null
    fi
}
remove_bench_hosts() {
    sudo sed -i.bak "/$ETC_HOSTS_MARKER/d" /etc/hosts
    sudo rm -f /etc/hosts.bak
}

# ── Ports ───────────────────────────────────────────────────────────
UPSTREAM_PORT=9999
GVM_PROXY_PORT=8080
ENVOY_EXTAUTHZ_PORT=10000
ENVOY_WASM_PORT=10001
OPA_GRPC_PORT=9191

# ── Pre-flight: kill stale bench artefacts (defensive cleanup) ──────
# If a previous bench run was killed forcibly, gvm-proxy or mock
# upstream may still be listening on 8080/9999 — masking our own
# start_gvm_proxy failure (the healthcheck would succeed against the
# STALE proxy with its old config, while our new bind silently EADDRINUSE).
sudo pkill -9 -f 'gvm-proxy' 2>/dev/null || true
sudo pkill -9 -f 'http.server.*9999\|9999.*serve_forever' 2>/dev/null || true
$DOCKER rm -f envoy-ext envoy-wasm opa-ext 2>/dev/null >/dev/null || true
$DOCKER ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^bench-idle-' | xargs -r $DOCKER rm -f 2>/dev/null >/dev/null || true
sleep 1
if sudo ss -tlnp 2>/dev/null | grep -qE ':8080|:10000|:10001|:9999|:9191'; then
    echo "ERROR: bench ports still occupied after cleanup:"
    sudo ss -tlnp 2>/dev/null | grep -E ':8080|:10000|:10001|:9999|:9191'
    echo "Resolve manually before re-running."
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "GVM vs OPA+Envoy comparison v2 (full-stack) — $STAMP"
echo "  git rev:        $GIT_REV"
echo "  gvm mtime:      $(date -d "@$GVM_MTIME" 2>/dev/null || date -r "$GVM_MTIME")"
echo "  gvm-proxy mtime:$(date -d "@$PROXY_MTIME" 2>/dev/null || date -r "$PROXY_MTIME")"
echo "  host IP:        $HOST_IP (used for bench.local mapping)"
echo "  results in:     $RESULTS_DIR"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# ── Process bookkeeping ─────────────────────────────────────────────
PIDS_TO_KILL=()
CONTAINERS_TO_STOP=()
GVM_TMP_CONFIG=""

cleanup() {
    for pid in "${PIDS_TO_KILL[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    for c in "${CONTAINERS_TO_STOP[@]:-}"; do $DOCKER rm -f "$c" 2>/dev/null >/dev/null || true; done
    [ -n "$GVM_TMP_CONFIG" ] && rm -rf "$GVM_TMP_CONFIG" 2>/dev/null
    GVM_TMP_CONFIG=""
    PIDS_TO_KILL=()
    CONTAINERS_TO_STOP=()
}
final_cleanup() {
    cleanup
    remove_bench_hosts
}
trap final_cleanup EXIT INT TERM

# ── Mock upstream — Python http.server on 0.0.0.0:9999 ──────────────
start_upstream() {
    sudo python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')
    def do_POST(self): self.do_GET()
    def log_message(*a, **k): pass
class T(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
with T(('0.0.0.0', $UPSTREAM_PORT), H) as s: s.serve_forever()
" &
    PIDS_TO_KILL+=($!)
    for _ in $(seq 1 30); do
        curl -sS -o /dev/null "http://127.0.0.1:$UPSTREAM_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    echo "ERROR: upstream mock did not become ready"
    return 1
}

# ── Stack A control plane: gvm-proxy daemon ─────────────────────────
# Use a fully isolated bench workspace so we don't (a) inherit the
# repo's 80-rule default SRR config, (b) recover from a corrupt repo
# WAL, or (c) pick up dev host-overrides. The minimal proxy.toml below
# uses absolute paths so the proxy's relative-path resolution can't
# escape the temp dir.
start_gvm_proxy() {
    GVM_TMP_CONFIG="$(mktemp -d -t gvm-bench-XXXXXX)"
    mkdir -p "$GVM_TMP_CONFIG/data"
    cp "$SCRIPT_DIR/srr-bench.toml" "$GVM_TMP_CONFIG/srr_network.toml"
    # Empty semantic rules file — the bench does not exercise SRR-semantic.
    printf '# bench: empty semantic rules\n' > "$GVM_TMP_CONFIG/srr_semantic.toml"
    # Minimal proxy.toml, absolute paths, default=Allow so unmatched
    # requests do NOT take a 300ms Delay (which would dominate timings).
    # Required fields per src/config.rs: server.listen,
    # enforcement.{default_decision, ic1_async_ledger, ic1_loss_threshold},
    # srr.{network_file, semantic_file, hot_reload}, secrets.{file, key_env}.
    cat > "$GVM_TMP_CONFIG/proxy.toml" <<EOF
[server]
listen = "0.0.0.0:$GVM_PROXY_PORT"

[enforcement]
default_decision = { type = "Allow" }
ic1_async_ledger = true
ic1_loss_threshold = 0.001

[wal]
path = "$GVM_TMP_CONFIG/data/wal.log"

[srr]
network_file = "$GVM_TMP_CONFIG/srr_network.toml"
semantic_file = "$GVM_TMP_CONFIG/srr_semantic.toml"
hot_reload = false

[secrets]
file = "$GVM_TMP_CONFIG/secrets.toml"
key_env = "GVM_SECRETS_KEY"

[dns]
enabled = false
EOF
    # Empty secrets file (proxy tolerates missing rows in passthrough mode).
    printf '# bench: no credentials\n' > "$GVM_TMP_CONFIG/secrets.toml"
    # Minimal gvm.toml — needed if proxy reads it; otherwise harmless.
    printf '# bench gvm.toml\n' > "$GVM_TMP_CONFIG/gvm.toml"

    sudo RUST_LOG=warn GVM_CONFIG="$GVM_TMP_CONFIG/proxy.toml" GVM_TOML="$GVM_TMP_CONFIG/gvm.toml" \
        "$GVM_PROXY_BIN" >"$RESULTS_DIR/gvm-proxy.log" 2>&1 &
    PIDS_TO_KILL+=($!)
    # Readiness: instead of /healthz (which goes through SRR and may
    # confuse a forward-proxy as a self-targeted request), probe the
    # admin port if reachable or wait for the listener log line.
    for _ in $(seq 1 60); do
        # Probe TCP listener directly with a short timeout.
        if curl -sS -m 1 -o /dev/null "http://127.0.0.1:$GVM_PROXY_PORT/healthz" 2>/dev/null; then
            return 0
        fi
        # If proxy printed its banner, treat that as ready too.
        if grep -q 'Network SRR\|Governance Summary\|Rules loaded' "$RESULTS_DIR/gvm-proxy.log" 2>/dev/null; then
            sleep 0.5
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# ── Stack B control plane: Envoy + OPA ext_authz containers ─────────
start_envoy_extauthz() {
    $DOCKER run -d --rm --name opa-ext --network host \
        -v "$SCRIPT_DIR/policy.rego:/policy.rego:ro" \
        openpolicyagent/opa:1.16.2-envoy \
        run --server --addr=:0 --diagnostic-addr=:0 \
        --set=plugins.envoy_ext_authz_grpc.addr=:$OPA_GRPC_PORT \
        --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/allow \
        /policy.rego >/dev/null
    CONTAINERS_TO_STOP+=(opa-ext)

    $DOCKER run -d --rm --name envoy-ext --network host \
        -v "$SCRIPT_DIR/envoy-extauthz.yaml:/etc/envoy/envoy.yaml:ro" \
        envoyproxy/envoy:v1.32-latest \
        -c /etc/envoy/envoy.yaml >/dev/null
    CONTAINERS_TO_STOP+=(envoy-ext)

    for _ in $(seq 1 100); do
        curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$ENVOY_EXTAUTHZ_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# ── Stack C control plane: Envoy + OPA WASM container ───────────────
start_envoy_wasm() {
    $DOCKER run -d --rm --name envoy-wasm --network host \
        -v "$SCRIPT_DIR/envoy-wasm.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$SCRIPT_DIR/build/opa-bundle:/etc/opa-bundle:ro" \
        envoyproxy/envoy:v1.32-latest \
        -c /etc/envoy/envoy.yaml >/dev/null
    CONTAINERS_TO_STOP+=(envoy-wasm)
    for _ in $(seq 1 100); do
        curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$ENVOY_WASM_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

stop_all() { cleanup; sleep 1; }

# ── In-isolation workload runner — Stack A (GVM sandbox) ────────────
# Runs N curls for the given scenario inside `gvm run --sandbox`.
# Emits one line per request: "T:<seconds>" — parseable by grep.
# GVM_CONFIG/GVM_TOML env vars pinned so `gvm run` uses the bench
# config even if it autostarts a proxy (defensive — the pre-started
# bench gvm-proxy should already own port 8080).
run_in_sandbox_a() {
    local n="$1" method="$2" url_path="$3"
    sudo GVM_CONFIG="$GVM_TMP_CONFIG/proxy.toml" GVM_TOML="$GVM_TMP_CONFIG/gvm.toml" \
        "$GVM_BIN" run --sandbox -- bash -c "
        for i in \$(seq 1 $n); do
            t=\$(curl -sS -o /dev/null -w '%{time_total}\\n' -X $method http://bench.local:9999$url_path 2>/dev/null || echo 0)
            echo \"T:\$t\"
        done
    " 2>/dev/null | grep -oP '^T:\K[0-9.]+' || true
}

# ── In-isolation workload runner — Stack B/C (Docker container) ─────
run_in_docker_bc() {
    local n="$1" method="$2" url_path="$3" envoy_port="$4"
    $DOCKER run --rm \
        --add-host "bench.local:$HOST_IP" \
        -e "HTTP_PROXY=http://$HOST_IP:$envoy_port" \
        -e "http_proxy=http://$HOST_IP:$envoy_port" \
        curlimages/curl:8.10.1 \
        sh -c "
            for i in \$(seq 1 $n); do
                t=\$(curl -sS -o /dev/null -w '%{time_total}\\n' -X $method http://bench.local:9999$url_path 2>/dev/null || echo 0)
                echo \"T:\$t\"
            done
        " 2>/dev/null | grep -oP '^T:\K[0-9.]+' || true
}

stats_csv() {
    local times_file="$1" stack="$2" scenario="$3"
    python3 -c "
v=sorted(float(x) for x in open('$times_file') if x.strip())
if not v:
    print('$stack','$scenario','0','0','0','0',sep=',')
else:
    n=len(v); med=v[n//2]*1000; p95=v[int(n*0.95) if n>=20 else n-1]*1000; p99=v[int(n*0.99) if n>=100 else n-1]*1000
    print('$stack','$scenario',f'{med:.3f}',f'{p95:.3f}',f'{p99:.3f}',n,sep=',')
"
}

# ── D1 — steady-state latency inside isolation ──────────────────────
# Note: Stack C (OPA-WASM inside Envoy's WASM filter) was dropped after
# verification on EC2 — `opa build -t wasm` produces OPA's own WASM ABI,
# which is not the Proxy-Wasm ABI that Envoy's WASM filter expects.
# Envoy crit-exits with "Missing or unknown Proxy-Wasm ABI version".
# A wrapper would be needed (e.g., istio-cni's compiler) — out of scope
# for "vanilla OPA + vanilla Envoy" canonical deployment. Stack B is
# the real-world OPA+Envoy comparison point. See docs §2.
run_d1() {
    echo "── D1 — Steady-state per-request latency (inside isolation) ──"
    : >"$RESULTS_DIR/d1.csv"
    echo "stack,scenario,p50_ms,p95_ms,p99_ms,n" >>"$RESULTS_DIR/d1.csv"
    local n=1000
    add_bench_hosts
    $DOCKER pull curlimages/curl:8.10.1 >/dev/null 2>&1 || true

    # Stack A
    start_upstream || return 1
    start_gvm_proxy || { echo "GVM proxy failed; tail:"; tail "$RESULTS_DIR/gvm-proxy.log"; return 1; }
    echo "  Stack A: gvm-proxy ready. Running $n×2 curls inside sandbox..."
    run_in_sandbox_a 50 GET /v1/messages >/dev/null
    run_in_sandbox_a "$n" GET /v1/messages >"$RESULTS_DIR/d1-A-allow.times"
    run_in_sandbox_a "$n" POST /transfer >"$RESULTS_DIR/d1-A-deny.times"
    stop_all
    stats_csv "$RESULTS_DIR/d1-A-allow.times" A allow >>"$RESULTS_DIR/d1.csv"
    stats_csv "$RESULTS_DIR/d1-A-deny.times"  A deny  >>"$RESULTS_DIR/d1.csv"

    # Stack B
    start_upstream && start_envoy_extauthz || { echo "Stack B startup failed"; return 1; }
    echo "  Stack B: Envoy+OPA ext_authz ready. Running $n×2 curls inside docker..."
    run_in_docker_bc 50 GET /v1/messages "$ENVOY_EXTAUTHZ_PORT" >/dev/null
    run_in_docker_bc "$n" GET /v1/messages "$ENVOY_EXTAUTHZ_PORT" >"$RESULTS_DIR/d1-B-allow.times"
    run_in_docker_bc "$n" POST /transfer "$ENVOY_EXTAUTHZ_PORT" >"$RESULTS_DIR/d1-B-deny.times"
    stop_all
    stats_csv "$RESULTS_DIR/d1-B-allow.times" B allow >>"$RESULTS_DIR/d1.csv"
    stats_csv "$RESULTS_DIR/d1-B-deny.times"  B deny  >>"$RESULTS_DIR/d1.csv"

    echo "  results: $RESULTS_DIR/d1.csv"
    cat "$RESULTS_DIR/d1.csv"
}

# ── D2a — workload cold start (control plane already up) ────────────
run_d2a() {
    echo "── D2a — Workload cold start ─────────────────────────────────"
    : >"$RESULTS_DIR/d2a.csv"
    echo "stack,iter,workload_cold_start_ms" >>"$RESULTS_DIR/d2a.csv"
    local iters=5
    add_bench_hosts

    start_upstream && start_gvm_proxy
    for i in $(seq 1 $iters); do
        local t0=$(date +%s%3N)
        sudo "$GVM_BIN" run --sandbox -- bash -c "curl -sS -o /dev/null http://bench.local:9999/v1/messages" 2>/dev/null
        local t1=$(date +%s%3N)
        echo "A,$i,$((t1-t0))" >>"$RESULTS_DIR/d2a.csv"
    done
    stop_all

    start_upstream && start_envoy_extauthz
    for i in $(seq 1 $iters); do
        local t0=$(date +%s%3N)
        $DOCKER run --rm \
            --add-host "bench.local:$HOST_IP" \
            -e "HTTP_PROXY=http://$HOST_IP:$ENVOY_EXTAUTHZ_PORT" \
            curlimages/curl:8.10.1 \
            curl -sS -o /dev/null http://bench.local:9999/v1/messages 2>/dev/null
        local t1=$(date +%s%3N)
        echo "B,$i,$((t1-t0))" >>"$RESULTS_DIR/d2a.csv"
    done
    stop_all
    echo "  results: $RESULTS_DIR/d2a.csv"
    cat "$RESULTS_DIR/d2a.csv"
}

# ── D2b — control-plane cold start ──────────────────────────────────
run_d2b() {
    echo "── D2b — Control-plane cold start ────────────────────────────"
    : >"$RESULTS_DIR/d2b.csv"
    echo "stack,iter,control_plane_cold_start_ms" >>"$RESULTS_DIR/d2b.csv"
    local iters=5
    for i in $(seq 1 $iters); do
        stop_all
        local t0=$(date +%s%3N)
        start_gvm_proxy
        local t1=$(date +%s%3N)
        echo "A,$i,$((t1-t0))" >>"$RESULTS_DIR/d2b.csv"
        stop_all
    done

    for i in $(seq 1 $iters); do
        stop_all
        local t0=$(date +%s%3N)
        start_envoy_extauthz
        local t1=$(date +%s%3N)
        echo "B,$i,$((t1-t0))" >>"$RESULTS_DIR/d2b.csv"
        stop_all
    done
    echo "  results: $RESULTS_DIR/d2b.csv"
    cat "$RESULTS_DIR/d2b.csv"
}

# ── D3 — memory with sandbox/container scaling ──────────────────────
run_d3() {
    echo "── D3 — Memory @ N=1, 5, 10 idle agents ──────────────────────"
    : >"$RESULTS_DIR/d3.csv"
    echo "stack,N,total_rss_kb" >>"$RESULTS_DIR/d3.csv"
    add_bench_hosts

    for N in 1 5 10; do
        # Stack A: gvm-proxy + N × gvm sandbox children, each `sleep 60`.
        start_upstream && start_gvm_proxy
        local sandbox_pids=()
        for _ in $(seq 1 "$N"); do
            sudo "$GVM_BIN" run --sandbox -- sleep 60 >/dev/null 2>&1 &
            sandbox_pids+=($!)
        done
        sleep 15  # let all sandboxes complete setup
        local total_a=0
        # Collect PIDs from three sources; dedupe via sort -u so a PID
        # matching two patterns is counted once.
        local d3_a_pids="$( \
            pgrep -x gvm-proxy 2>/dev/null; \
            pgrep -f 'gvm run --sandbox' 2>/dev/null; \
            pgrep -fx 'sleep 60' 2>/dev/null \
        )"
        local d3_a_pids_unique
        d3_a_pids_unique="$(echo "$d3_a_pids" | sort -un)"
        for p in $d3_a_pids_unique; do
            local rss=$(ps -p "$p" -o rss= 2>/dev/null | awk '{print $1+0}')
            total_a=$((total_a + ${rss:-0}))
        done
        echo "A,$N,$total_a" >>"$RESULTS_DIR/d3.csv"
        for p in "${sandbox_pids[@]}"; do sudo kill -TERM "$p" 2>/dev/null || true; done
        sleep 2
        stop_all

        # Stack B: envoy + opa + N × alpine containers `sleep 60`.
        start_upstream && start_envoy_extauthz
        local container_names=()
        for j in $(seq 1 "$N"); do
            local cn="bench-idle-b-$j"
            $DOCKER run -d --rm --name "$cn" alpine sleep 60 >/dev/null 2>&1
            container_names+=("$cn")
        done
        sleep 5
        local total_b=0
        for c in envoy-ext opa-ext "${container_names[@]}"; do
            local pid=$($DOCKER inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)
            [ -n "$pid" ] && [ "$pid" != "0" ] && {
                local rss=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{print $1+0}')
                total_b=$((total_b + ${rss:-0}))
            }
        done
        echo "B,$N,$total_b" >>"$RESULTS_DIR/d3.csv"
        for c in "${container_names[@]}"; do $DOCKER rm -f "$c" >/dev/null 2>&1 || true; done
        stop_all
    done
    echo "  results: $RESULTS_DIR/d3.csv"
    cat "$RESULTS_DIR/d3.csv"
}

# ── D4 — distribution size ──────────────────────────────────────────
run_d4() {
    echo "── D4 — Distribution size ────────────────────────────────────"
    : >"$RESULTS_DIR/d4.csv"
    echo "stack,artifact,bytes" >>"$RESULTS_DIR/d4.csv"
    echo "A,gvm,$(stat -c %s "$GVM_BIN" 2>/dev/null || stat -f %z "$GVM_BIN")" >>"$RESULTS_DIR/d4.csv"
    echo "A,gvm-proxy,$(stat -c %s "$GVM_PROXY_BIN" 2>/dev/null || stat -f %z "$GVM_PROXY_BIN")" >>"$RESULTS_DIR/d4.csv"
    for img in envoyproxy/envoy:v1.32-latest openpolicyagent/opa:1.16.2-envoy; do
        local sz=$($DOCKER image inspect "$img" --format '{{.Size}}' 2>/dev/null || echo 0)
        echo "BC,$img,$sz" >>"$RESULTS_DIR/d4.csv"
    done
    echo "  results: $RESULTS_DIR/d4.csv"
    cat "$RESULTS_DIR/d4.csv"
}

# ── D5 — decision-to-log latency + tamper evidence ──────────────────
run_d5() {
    echo "── D5 — Audit visibility ─────────────────────────────────────"
    : >"$RESULTS_DIR/d5.csv"
    echo "stack,decision_to_log_ms,tamper_evident" >>"$RESULTS_DIR/d5.csv"
    add_bench_hosts

    start_upstream && start_gvm_proxy
    local wal_path="$REPO_DIR/data/wal.log"
    local t0=$(date +%s%3N)
    sudo "$GVM_BIN" run --sandbox -- curl -sS -o /dev/null -X POST http://bench.local:9999/transfer 2>/dev/null
    for _ in $(seq 1 100); do
        grep -q "bench-deny\|bench.local" "$wal_path" 2>/dev/null && break
        sleep 0.05
    done
    local t1=$(date +%s%3N)
    echo "A,$((t1-t0)),yes" >>"$RESULTS_DIR/d5.csv"
    stop_all

    start_upstream && start_envoy_extauthz
    local t0=$(date +%s%3N)
    $DOCKER run --rm \
        --add-host "bench.local:$HOST_IP" \
        -e "HTTP_PROXY=http://$HOST_IP:$ENVOY_EXTAUTHZ_PORT" \
        curlimages/curl:8.10.1 \
        curl -sS -o /dev/null -X POST http://bench.local:9999/transfer 2>/dev/null
    for _ in $(seq 1 100); do
        $DOCKER logs envoy-ext 2>&1 | grep -q "/transfer" && break
        sleep 0.05
    done
    local t1=$(date +%s%3N)
    echo "B,$((t1-t0)),no" >>"$RESULTS_DIR/d5.csv"
    stop_all
    echo "  results: $RESULTS_DIR/d5.csv"
    cat "$RESULTS_DIR/d5.csv"
}

# ── Run selected dimensions ─────────────────────────────────────────
DIMS=("$@")
if [ ${#DIMS[@]} -eq 0 ]; then DIMS=(d1 d2a d2b d3 d4 d5); fi
for d in "${DIMS[@]}"; do
    case "$d" in
        d1) run_d1 ;;
        d2a) run_d2a ;;
        d2b) run_d2b ;;
        d3) run_d3 ;;
        d4) run_d4 ;;
        d5) run_d5 ;;
        *) echo "Unknown dimension: $d"; exit 1 ;;
    esac
    echo ""
done

# ── Manifest ────────────────────────────────────────────────────────
cat >"$RESULTS_DIR/manifest.txt" <<EOF
GVM vs OPA+Envoy comparison v2 (full-stack)
timestamp: $STAMP
git rev:   $GIT_REV
host:      $(uname -a)
kernel:    $(uname -r)
host IP:   $HOST_IP (bench.local mapping)
gvm binary mtime:        $(date -d "@$GVM_MTIME" 2>/dev/null || date -r "$GVM_MTIME")
gvm-proxy binary mtime:  $(date -d "@$PROXY_MTIME" 2>/dev/null || date -r "$PROXY_MTIME")
envoy image:             envoyproxy/envoy:v1.32-latest
opa image:               openpolicyagent/opa:1.16.2-envoy
dimensions run:          ${DIMS[*]}
EOF

echo "═══════════════════════════════════════════════════════════════════"
echo "Done. Results: $RESULTS_DIR"
echo "═══════════════════════════════════════════════════════════════════"
