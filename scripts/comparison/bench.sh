#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# GVM vs OPA+Envoy+Docker — multi-dimensional comparison benchmark.
#
# Measures D1-D5 (see docs/internal/comparison-opa-envoy.md §4) across
# three stacks:
#   A — GVM       (gvm-proxy + sandbox + WAL)
#   B — Envoy + OPA ext_authz (gRPC)
#   C — Envoy + OPA WASM (in-process)
#
# Mock upstream on 127.0.0.1:9999 — local, so no network jitter.
#
# Requirements:
#   - bash scripts/comparison/setup.sh has been run on this host
#   - GVM built in release mode: cargo build --release -p gvm-cli -p gvm-proxy
#   - User in `docker` group (or run with sudo)
#
# Usage:
#   bash scripts/comparison/bench.sh           # full sweep
#   bash scripts/comparison/bench.sh d1        # only D1 (latency)
#   bash scripts/comparison/bench.sh d2 d3     # only D2 + D3
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

# Sanity: latest binary (anti-stale-binary check per CLAUDE.md)
if [ ! -x "$GVM_BIN" ] || [ ! -x "$GVM_PROXY_BIN" ]; then
    echo "ERROR: GVM binaries missing. Run: cargo build --release -p gvm-cli -p gvm-proxy"
    exit 1
fi
GVM_MTIME="$(stat -c %Y "$GVM_BIN" 2>/dev/null || stat -f %m "$GVM_BIN")"
PROXY_MTIME="$(stat -c %Y "$GVM_PROXY_BIN" 2>/dev/null || stat -f %m "$GVM_PROXY_BIN")"

echo "═══════════════════════════════════════════════════════════════════"
echo "GVM vs OPA+Envoy comparison — $STAMP"
echo "  git rev:        $GIT_REV"
echo "  gvm mtime:      $(date -d "@$GVM_MTIME" 2>/dev/null || date -r "$GVM_MTIME")"
echo "  gvm-proxy mtime:$(date -d "@$PROXY_MTIME" 2>/dev/null || date -r "$PROXY_MTIME")"
echo "  results in:     $RESULTS_DIR"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# ── Stack ports ─────────────────────────────────────────────────────
UPSTREAM_PORT=9999
GVM_PROXY_PORT=8080
ENVOY_EXTAUTHZ_PORT=10000
ENVOY_WASM_PORT=10001
OPA_GRPC_PORT=9191

# ── Process bookkeeping ─────────────────────────────────────────────
PIDS_TO_KILL=()
CONTAINERS_TO_STOP=()

cleanup() {
    for pid in "${PIDS_TO_KILL[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for c in "${CONTAINERS_TO_STOP[@]:-}"; do
        docker rm -f "$c" 2>/dev/null >/dev/null || true
    done
}
trap cleanup EXIT INT TERM

# ── Mock upstream — Python http.server on 9999 ──────────────────────
start_upstream() {
    python3 -c "
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')
    def do_POST(self): self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')
    def log_message(*a, **k): pass
with socketserver.TCPServer(('127.0.0.1', $UPSTREAM_PORT), H) as s: s.serve_forever()
" &
    PIDS_TO_KILL+=($!)
    # readiness wait
    for _ in $(seq 1 20); do
        curl -sS -o /dev/null "http://127.0.0.1:$UPSTREAM_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# ── Stack A — GVM ─────────────────────────────────────────────────────
# Use a per-run temp config directory so the operator's real
# config/srr_network.toml is never touched.
GVM_TMP_CONFIG=""

start_stack_a() {
    GVM_TMP_CONFIG="$(mktemp -d -t gvm-bench-XXXXXX)"
    # Mirror just what gvm-proxy needs from config/.
    cp "$REPO_DIR/config/proxy.toml" "$GVM_TMP_CONFIG/proxy.toml" 2>/dev/null || true
    cp "$REPO_DIR/config/gvm.toml" "$GVM_TMP_CONFIG/gvm.toml" 2>/dev/null || true
    cp "$SCRIPT_DIR/srr-bench.toml" "$GVM_TMP_CONFIG/srr_network.toml"
    GVM_CONFIG="$GVM_TMP_CONFIG/proxy.toml" \
    GVM_TOML="$GVM_TMP_CONFIG/gvm.toml" \
        "$GVM_PROXY_BIN" >"$RESULTS_DIR/gvm-proxy.log" 2>&1 &
    PIDS_TO_KILL+=($!)
    for _ in $(seq 1 50); do
        curl -sS -o /dev/null "http://127.0.0.1:$GVM_PROXY_PORT/healthz" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

cleanup_stack_a() {
    [ -n "$GVM_TMP_CONFIG" ] && rm -rf "$GVM_TMP_CONFIG" 2>/dev/null
    GVM_TMP_CONFIG=""
}

# ── Stack B — Envoy + OPA ext_authz ─────────────────────────────────
start_stack_b() {
    docker run -d --rm --name opa-ext --network host \
        -v "$SCRIPT_DIR/policy.rego:/policy.rego:ro" \
        openpolicyagent/opa:0.71.0-envoy \
        run --server --addr=:0 --diagnostic-addr=:0 \
        --set=plugins.envoy_ext_authz_grpc.addr=:$OPA_GRPC_PORT \
        --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/allow \
        /policy.rego >/dev/null
    CONTAINERS_TO_STOP+=(opa-ext)

    docker run -d --rm --name envoy-ext --network host \
        -v "$SCRIPT_DIR/envoy-extauthz.yaml:/etc/envoy/envoy.yaml:ro" \
        envoyproxy/envoy:v1.32-latest \
        -c /etc/envoy/envoy.yaml >/dev/null
    CONTAINERS_TO_STOP+=(envoy-ext)

    for _ in $(seq 1 100); do
        curl -sS -o /dev/null "http://127.0.0.1:$ENVOY_EXTAUTHZ_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# ── Stack C — Envoy + OPA WASM ──────────────────────────────────────
start_stack_c() {
    docker run -d --rm --name envoy-wasm --network host \
        -v "$SCRIPT_DIR/envoy-wasm.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$SCRIPT_DIR/build/opa-bundle:/etc/opa-bundle:ro" \
        envoyproxy/envoy:v1.32-latest \
        -c /etc/envoy/envoy.yaml >/dev/null
    CONTAINERS_TO_STOP+=(envoy-wasm)
    for _ in $(seq 1 100); do
        curl -sS -o /dev/null "http://127.0.0.1:$ENVOY_WASM_PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

stop_all_stacks() { cleanup; cleanup_stack_a; sleep 1; }

# ── D1 — Per-request latency ────────────────────────────────────────
run_d1() {
    echo "── D1 — Per-request enforcement latency ──────────────────────"
    : >"$RESULTS_DIR/d1.csv"
    echo "stack,scenario,p50_ms,p95_ms,p99_ms,n" >>"$RESULTS_DIR/d1.csv"
    local n=1000

    for stack in A B C; do
        case "$stack" in
            A) start_upstream && start_stack_a; port=$GVM_PROXY_PORT ;;
            B) start_upstream && start_stack_b; port=$ENVOY_EXTAUTHZ_PORT ;;
            C) start_upstream && start_stack_c; port=$ENVOY_WASM_PORT ;;
        esac

        # warm up
        for _ in $(seq 1 100); do curl -sS -o /dev/null "http://127.0.0.1:$port/v1/messages" -H "Host: api.anthropic.com" 2>/dev/null || true; done

        for scenario in allow deny; do
            local host path
            case "$scenario" in
                allow) host=api.anthropic.com; path=/v1/messages; method=GET ;;
                deny)  host=api.bank.com;      path=/transfer;     method=POST ;;
            esac
            local times="$RESULTS_DIR/d1-$stack-$scenario.times"
            : >"$times"
            for _ in $(seq 1 $n); do
                t=$(curl -sS -o /dev/null -w '%{time_total}\n' \
                    -X "$method" "http://127.0.0.1:$port$path" \
                    -H "Host: $host" 2>/dev/null || echo 0)
                echo "$t" >>"$times"
            done
            python3 -c "
v=sorted(float(x)*1000 for x in open('$times') if x.strip())
n=len(v)
print('$stack','$scenario',f'{v[n//2]:.3f}',f'{v[int(n*0.95)]:.3f}',f'{v[int(n*0.99)]:.3f}',n,sep=',')" \
                >>"$RESULTS_DIR/d1.csv"
        done
        stop_all_stacks
    done

    echo "  results: $RESULTS_DIR/d1.csv"
    cat "$RESULTS_DIR/d1.csv"
}

# ── D2 — Cold start ─────────────────────────────────────────────────
run_d2() {
    echo "── D2 — Cold start to first decision ─────────────────────────"
    : >"$RESULTS_DIR/d2.csv"
    echo "stack,iter,cold_start_ms" >>"$RESULTS_DIR/d2.csv"
    local iters=5
    for stack in A B C; do
        for i in $(seq 1 $iters); do
            stop_all_stacks
            start_upstream
            local t0=$(date +%s%3N)
            case "$stack" in
                A) start_stack_a; port=$GVM_PROXY_PORT ;;
                B) start_stack_b; port=$ENVOY_EXTAUTHZ_PORT ;;
                C) start_stack_c; port=$ENVOY_WASM_PORT ;;
            esac
            curl -sS -o /dev/null "http://127.0.0.1:$port/v1/messages" -H "Host: api.anthropic.com" 2>/dev/null
            local t1=$(date +%s%3N)
            echo "$stack,$i,$((t1-t0))" >>"$RESULTS_DIR/d2.csv"
        done
    done
    stop_all_stacks
    echo "  results: $RESULTS_DIR/d2.csv"
    cat "$RESULTS_DIR/d2.csv"
}

# ── D3 — Memory footprint ───────────────────────────────────────────
run_d3() {
    echo "── D3 — Memory footprint ─────────────────────────────────────"
    : >"$RESULTS_DIR/d3.csv"
    echo "stack,state,process,rss_kb" >>"$RESULTS_DIR/d3.csv"
    for stack in A B C; do
        start_upstream
        case "$stack" in A) start_stack_a; port=$GVM_PROXY_PORT;; B) start_stack_b; port=$ENVOY_EXTAUTHZ_PORT;; C) start_stack_c; port=$ENVOY_WASM_PORT;; esac
        sleep 30  # idle settle
        sample_d3 "$stack" idle "$port"
        for _ in $(seq 1 500); do curl -sS -o /dev/null "http://127.0.0.1:$port/v1/messages" -H "Host: api.anthropic.com" 2>/dev/null || true; done
        sample_d3 "$stack" loaded "$port"
        stop_all_stacks
    done
    echo "  results: $RESULTS_DIR/d3.csv"
    cat "$RESULTS_DIR/d3.csv"
}

sample_d3() {
    local stack="$1" state="$2" port="$3"
    case "$stack" in
        A)
            for proc in gvm-proxy; do
                local rss=$(ps -C "$proc" -o rss= 2>/dev/null | awk '{s+=$1} END {print s+0}')
                echo "$stack,$state,$proc,$rss" >>"$RESULTS_DIR/d3.csv"
            done
            ;;
        B|C)
            for c in $(docker ps --format '{{.Names}}' | grep -E 'envoy|opa-ext|envoy-wasm'); do
                local pid=$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)
                local rss=$(ps -p "$pid" -o rss= 2>/dev/null | awk '{print $1+0}')
                echo "$stack,$state,$c,$rss" >>"$RESULTS_DIR/d3.csv"
            done
            ;;
    esac
}

# ── D4 — Distribution size ──────────────────────────────────────────
run_d4() {
    echo "── D4 — Distribution size ────────────────────────────────────"
    : >"$RESULTS_DIR/d4.csv"
    echo "stack,artifact,bytes" >>"$RESULTS_DIR/d4.csv"
    echo "A,gvm,$(stat -c %s "$GVM_BIN" 2>/dev/null || stat -f %z "$GVM_BIN")" >>"$RESULTS_DIR/d4.csv"
    echo "A,gvm-proxy,$(stat -c %s "$GVM_PROXY_BIN" 2>/dev/null || stat -f %z "$GVM_PROXY_BIN")" >>"$RESULTS_DIR/d4.csv"
    for img in envoyproxy/envoy:v1.32-latest openpolicyagent/opa:0.71.0-envoy; do
        local sz=$(docker image inspect "$img" --format '{{.Size}}' 2>/dev/null || echo 0)
        echo "BC,$img,$sz" >>"$RESULTS_DIR/d4.csv"
    done
    echo "  results: $RESULTS_DIR/d4.csv"
    cat "$RESULTS_DIR/d4.csv"
}

# ── D5 — Audit visibility ───────────────────────────────────────────
run_d5() {
    echo "── D5 — Audit visibility ─────────────────────────────────────"
    : >"$RESULTS_DIR/d5.csv"
    echo "stack,decision_to_log_ms,tamper_evident" >>"$RESULTS_DIR/d5.csv"
    # GVM: WAL is in REPO_DIR/data/wal/wal.log (per default proxy.toml).
    start_upstream && start_stack_a
    local wal_path="$REPO_DIR/data/wal/wal.log"
    local t0=$(date +%s%3N)
    curl -sS -o /dev/null -X POST "http://127.0.0.1:$GVM_PROXY_PORT/transfer" -H "Host: api.bank.com" 2>/dev/null
    # Wait for the deny event to appear in WAL.
    for _ in $(seq 1 100); do
        if grep -q "bank-transfer-deny\|api.bank.com" "$wal_path" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
    local t1=$(date +%s%3N)
    echo "A,$((t1-t0)),yes" >>"$RESULTS_DIR/d5.csv"
    stop_all_stacks

    for stack_label in B:start_stack_b:$ENVOY_EXTAUTHZ_PORT C:start_stack_c:$ENVOY_WASM_PORT; do
        IFS=: read -r tag fn port <<<"$stack_label"
        start_upstream && $fn
        # Envoy access log path inside containers, mapped via stdout — tail through `docker logs`.
        local cname
        case "$tag" in B) cname=envoy-ext;; C) cname=envoy-wasm;; esac
        local t0=$(date +%s%3N)
        curl -sS -o /dev/null -X POST "http://127.0.0.1:$port/transfer" -H "Host: api.bank.com" 2>/dev/null
        for _ in $(seq 1 100); do
            docker logs "$cname" 2>&1 | grep -q "api.bank.com" && break
            sleep 0.05
        done
        local t1=$(date +%s%3N)
        echo "$tag,$((t1-t0)),no" >>"$RESULTS_DIR/d5.csv"
        stop_all_stacks
    done
    echo "  results: $RESULTS_DIR/d5.csv"
    cat "$RESULTS_DIR/d5.csv"
}

# ── Run selected dimensions ─────────────────────────────────────────
DIMS=("$@")
if [ ${#DIMS[@]} -eq 0 ]; then DIMS=(d1 d2 d3 d4 d5); fi
for d in "${DIMS[@]}"; do
    case "$d" in
        d1) run_d1 ;;
        d2) run_d2 ;;
        d3) run_d3 ;;
        d4) run_d4 ;;
        d5) run_d5 ;;
        *) echo "Unknown dimension: $d"; exit 1 ;;
    esac
    echo ""
done

# ── Manifest ────────────────────────────────────────────────────────
cat >"$RESULTS_DIR/manifest.txt" <<EOF
GVM vs OPA+Envoy comparison
timestamp: $STAMP
git rev:   $GIT_REV
host:      $(uname -a)
kernel:    $(uname -r)
gvm binary mtime:        $(date -d "@$GVM_MTIME" 2>/dev/null || date -r "$GVM_MTIME")
gvm-proxy binary mtime:  $(date -d "@$PROXY_MTIME" 2>/dev/null || date -r "$PROXY_MTIME")
envoy image:             envoyproxy/envoy:v1.32-latest
opa image:               openpolicyagent/opa:0.71.0-envoy
dimensions run:          ${DIMS[*]}
EOF

echo "═══════════════════════════════════════════════════════════════════"
echo "Done. Results: $RESULTS_DIR"
echo "═══════════════════════════════════════════════════════════════════"
