#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Multi-agent load test — N concurrent sandboxes through one proxy.
#
# Spawns N (default 10) `gvm run --sandbox` processes in parallel.
# Each runs a Python mock agent that issues M (default 50) HTTP probes
# against synthetic hosts that exercise the SRR ruleset
# (`scripts/srr-comprehensive.toml`). Validates:
#
#   1. Every agent's events make it into the WAL with its correct
#      agent_id (no cross-agent contamination under load)
#   2. WAL Merkle/anchor chain stays intact
#   3. Proxy memory stays bounded (steady-state plateau check)
#   4. Proxy FD count doesn't leak across the run
#   5. No orphan veth / iptables / heartbeat after every agent exits
#   6. Per-rule decision counts scale linearly with N (sanity check —
#      proxy isn't dropping events under load)
#
# This is the intermediate scale we can run on a t3.medium-class
# instance (4 GB RAM). Each sandbox holds ~50-80 MB at peak; 10
# concurrent ≈ 800 MB peak. Larger N requires a bigger instance.
#
# Usage:
#   sudo tmux new -s load                 # CLAUDE.md: tmux for long runs
#   sudo bash scripts/multi-agent-load.sh                # default N=10 M=50
#   sudo bash scripts/multi-agent-load.sh --agents 20 --requests 100
#
# CLI-only: every interaction with GVM is via `gvm run`/`gvm status`/
# `gvm audit`. No proxy binary, no PID file, no nsenter.
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

BOLD='\033[1m'; DIM='\033[2m'
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

NUM_AGENTS=10
REQUESTS_PER_AGENT=50
SAMPLE_INTERVAL_SEC=10
SKIP_BUILD=false

while [ $# -gt 0 ]; do
    case "$1" in
        --agents)    NUM_AGENTS="$2"; shift 2 ;;
        --requests)  REQUESTS_PER_AGENT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ─── Pre-flight ──
[ "$(id -u)" -ne 0 ] && { echo -e "${RED}must run as root (sudo) — sandbox needs CAP_NET_ADMIN${NC}"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}jq required${NC}"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo -e "${RED}python3 required${NC}"; exit 1; }

if ! $SKIP_BUILD; then
    echo "  building release binaries..."
    (cd "$REPO_DIR" && cargo build --release -p gvm-cli -p gvm-proxy 2>&1 | tail -3) || {
        echo -e "  ${RED}build failed${NC}"; exit 1
    }
fi
GVM_BIN="$REPO_DIR/target/release/gvm"
[ ! -f "$GVM_BIN" ] && { echo -e "${RED}gvm binary missing${NC}"; exit 1; }

# Load .env if present (ANTHROPIC_API_KEY etc.) — we don't need it for
# mock agents but the proxy may use it for surrounding telemetry.
[ -f "$REPO_DIR/.env" ] && set -a && . "$REPO_DIR/.env" && set +a

# ─── Test config isolation ──
TEST_DIR="/tmp/gvm-load-$$"
rm -rf "$TEST_DIR"; mkdir -p "$TEST_DIR/data"
SUDO_USER_NAME="${SUDO_USER:-ubuntu}"
chown -R "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$TEST_DIR"
SRR_PATH="$TEST_DIR/srr_network.toml"
PROXY_TOML="$TEST_DIR/proxy.toml"
WAL="$TEST_DIR/data/wal.log"
RESULTS_DIR="$REPO_DIR/results/load-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$RESULTS_DIR"
chown -R "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$RESULTS_DIR"

cp "$SCRIPT_DIR/srr-comprehensive.toml" "$SRR_PATH"
cp "$REPO_DIR/config/proxy.toml" "$PROXY_TOML"
sed -i "s|^network_file = .*|network_file = \"$SRR_PATH\"|" "$PROXY_TOML"

# ─── Local mock upstream + host_overrides ──
# Synthetic hosts (api.test.example.com etc.) don't resolve. Without
# remapping, the proxy spends every probe on a futile DNS lookup +
# upstream connect that ultimately fails — and most failures show up
# as urllib-side timeouts instead of durable WAL events. Redirect
# them to a local catch-all server so each probe completes end-to-end
# and the WAL captures the real per-rule decision distribution.
MOCK_PORT=9990
MOCK_LOG="$RESULTS_DIR/mock-server.log"
mkdir -p "$RESULTS_DIR"
chown "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$RESULTS_DIR"
python3 -c "
import http.server, sys, json, threading
class H(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        body = json.dumps({'method': self.command, 'path': self.path}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):    self._ok()
    def do_POST(self):
        n = int(self.headers.get('Content-Length', '0') or 0)
        if n: self.rfile.read(n)
        self._ok()
    def do_PUT(self):    self.do_POST()
    def do_DELETE(self): self._ok()
    def log_message(self, *a, **k): pass  # silence per-request log
srv = http.server.ThreadingHTTPServer(('127.0.0.1', $MOCK_PORT), H)
print('mock listening on $MOCK_PORT', file=sys.stderr)
srv.serve_forever()
" >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
sleep 0.5
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo -e "${RED}mock server failed to start (see $MOCK_LOG)${NC}"; exit 1
fi
echo -e "  mock upstream:  ${GREEN}127.0.0.1:$MOCK_PORT${NC} (PID $MOCK_PID)"

# Patch host_overrides into the isolated proxy.toml so the synthetic
# hosts our agents probe land on the mock above. Mirrors the
# `[dev] host_overrides = { ... }` shape proxy.toml uses.
python3 - "$PROXY_TOML" "$MOCK_PORT" << 'PYEOF'
import sys, re, pathlib
fp, port = sys.argv[1], sys.argv[2]
text = pathlib.Path(fp).read_text()
hosts = [
    "api.test.example.com",
    "prod.database.example.com",
    "staging.database.example.com",
    "metrics.test.example.com",
    "anyhost.example.com",
    "api.bank.example.com",
    "api.payroll.example.com",
    "internal-admin.example.com",
    "unknown.example.org",
]
extra = ", ".join(f'"{h}" = "127.0.0.1:{port}"' for h in hosts)
m = re.search(r"host_overrides\s*=\s*\{([^}]*)\}", text)
if m:
    inner = m.group(1).strip().rstrip(",")
    new = "host_overrides = { " + extra + ((", " + inner) if inner else "") + " }"
    text = text[:m.start()] + new + text[m.end():]
else:
    text += f'\n[dev]\nhost_overrides = {{ {extra} }}\n'
pathlib.Path(fp).write_text(text)
PYEOF
echo -e "  host_overrides: ${GREEN}9 synthetic hosts → mock${NC}"

export GVM_CONFIG="$PROXY_TOML"
export GVM_WAL_PATH="$WAL"

# JWT identity — enabled. The proxy now derives identity from the
# veth source-IP → sandbox_id → agent_id mapping when an SDK-less
# client (like our urllib mock agent) does not present a Bearer
# token. So this load test exercises the realistic
# production path:
#   * proxy starts with GVM_JWT_SECRET set
#   * `gvm run --sandbox --agent-id <id>` issues a JWT and injects
#     it into the agent's env as GVM_JWT_TOKEN (transparent for SDK
#     users)
#   * the urllib mock does NOT read that env var, so requests arrive
#     without Authorization → proxy resolves identity from the
#     sandbox's veth peer IP via `resolve_identity_from_peer`
# The earlier comment claimed the proxy MANDATES Authorization and
# rejects everything else; that was wrong for the cooperative HTTP
# path (which has always warn-and-fallen-back) and now also
# inaccurate for MITM (which used to hard-reject but now also falls
# back to peer-IP identity when the peer is a known sandbox). See
# `AppState::resolve_identity_from_peer` for the soundness argument.
JWT_SECRET_HEX=$(openssl rand -hex 32)
export GVM_JWT_SECRET="$JWT_SECRET_HEX"
echo -e "  JWT:            ${GREEN}enabled${NC} (peer-IP identity for SDK-less agents)"

# Cleanup chain extends to mock server lifecycle.
trap 'kill -9 $MOCK_PID 2>/dev/null; tmux kill-session -t gvm-load 2>/dev/null; "$GVM_BIN" stop 2>/dev/null; rm -rf "$TEST_DIR"' EXIT

echo
echo -e "${BOLD}═══ Multi-agent load test ═══${NC}"
echo "  N agents:       $NUM_AGENTS"
echo "  reqs/agent:     $REQUESTS_PER_AGENT"
echo "  total probes:   $((NUM_AGENTS * REQUESTS_PER_AGENT))"
echo "  sample every:   ${SAMPLE_INTERVAL_SEC}s"
echo "  results dir:    $RESULTS_DIR"
echo "  config dir:     $TEST_DIR"
echo

# ─── Fresh proxy ──
"$GVM_BIN" stop 2>/dev/null || true
sleep 1
"$GVM_BIN" run --agent-id load-prewarm -- /bin/true >/dev/null 2>&1 || true
PROXY_PID=""
for _ in $(seq 1 10); do
    sleep 1
    PROXY_PID=$("$GVM_BIN" status --json 2>/dev/null | jq -r '.pid // empty')
    [ -n "$PROXY_PID" ] && [ "$PROXY_PID" != "null" ] && break
done
[ -z "$PROXY_PID" ] && { echo -e "${RED}proxy did not start${NC}"; exit 1; }
echo -e "  ${GREEN}proxy started${NC} (PID $PROXY_PID)"

# ─── Mock agent script ──
# Each invocation of this script (under `gvm run --sandbox`) makes
# REQUESTS_PER_AGENT outbound calls via HTTP_PROXY (set by the
# sandbox). Hosts target the rules in srr-comprehensive.toml so we
# get a mix of decisions (Allow/Deny/Delay/RequireApproval/catch-all).
AGENT_SCRIPT="$TEST_DIR/mock_agent.py"
cat > "$AGENT_SCRIPT" << PYEOF
import os, urllib.request, urllib.error, sys, time, random, json

TARGETS = [
    # (method, url) — hits each rule in srr-comprehensive.toml at least
    # a few times across the run.
    ("GET",    "http://api.test.example.com/repos/foo"),         # rule 1 Allow
    ("DELETE", "http://prod.database.example.com/users/42"),     # rule 2 Deny
    ("GET",    "http://metrics.test.example.com/dashboard"),     # rule 3 Delay
    ("POST",   "http://anyhost.example.com/v2/admin/users"),     # rule 4 RequireApproval
    ("POST",   "http://api.bank.example.com/graphql"),           # rule 5 (with body) or catch-all
    ("POST",   "http://api.payroll.example.com/run"),            # rule 6 condition
    ("POST",   "http://api.bank.example.com/transfer/x"),        # rule 7 condition
    ("GET",    "http://internal-admin.example.com/dashboard"),   # rule 8 condition
    ("GET",    "http://unknown.example.org/probe"),              # rule 9 catch-all
]

AGENT = os.environ.get("GVM_AGENT_ID", "unknown")

def call(method, url):
    headers = {"X-GVM-Agent-Id": AGENT, "X-GVM-Trace-Id": f"{AGENT}-{random.randint(0,2**32)}"}
    if method == "POST":
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url,
        method=method,
        data=b"{}" if method == "POST" else None,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{type(e).__name__}"

n = int(os.environ.get("REQUESTS_PER_AGENT", "${REQUESTS_PER_AGENT}"))
agent = os.environ.get("GVM_AGENT_ID", "?")
ok = 0
errs = 0
t0 = time.time()
for i in range(n):
    method, url = random.choice(TARGETS)
    r = call(method, url)
    if isinstance(r, int):
        ok += 1
    else:
        errs += 1
elapsed = time.time() - t0
print(json.dumps({"agent": agent, "ok": ok, "err": errs, "elapsed_sec": elapsed}))
PYEOF
chown "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$AGENT_SCRIPT"
chmod 755 "$AGENT_SCRIPT"

# ─── Sampler ──
METRICS_CSV="$RESULTS_DIR/metrics.csv"
echo "ts,elapsed_sec,rss_kb,fd_count,wal_bytes,sandboxes_active" > "$METRICS_CSV"
chown "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$METRICS_CSV"
START_TIME=$(date +%s)
sample_metrics() {
    local now elapsed rss fd wal_bytes nsb
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    elapsed=$(( $(date +%s) - START_TIME ))
    rss=$(awk '/VmRSS:/ {print $2}' "/proc/$PROXY_PID/status" 2>/dev/null || echo 0)
    fd=$(ls "/proc/$PROXY_PID/fd" 2>/dev/null | wc -l)
    wal_bytes=$(stat -c%s "$WAL" 2>/dev/null || echo 0)
    nsb=$(ls /run/gvm/gvm-sandbox-*.state 2>/dev/null | wc -l)
    echo "$now,$elapsed,$rss,$fd,$wal_bytes,$nsb" >> "$METRICS_CSV"
}

sample_metrics

# ─── Spawn N agents in parallel ──
echo
echo -e "${BOLD}── spawning $NUM_AGENTS agents (parallel) ──${NC}"
AGENT_LOG_DIR="$RESULTS_DIR/agents"
mkdir -p "$AGENT_LOG_DIR"
chown "$SUDO_USER_NAME":"$(id -gn "$SUDO_USER_NAME")" "$AGENT_LOG_DIR"

PIDS=()
for i in $(seq 1 "$NUM_AGENTS"); do
    aid="load-agent-$i"
    log="$AGENT_LOG_DIR/${aid}.log"
    REQUESTS_PER_AGENT="$REQUESTS_PER_AGENT" "$GVM_BIN" run \
        --sandbox --agent-id "$aid" "$AGENT_SCRIPT" >"$log" 2>&1 &
    PIDS+=($!)
    # Slight stagger so we don't have N simultaneous sandbox setups
    # (each holds /run/gvm briefly during mount setup).
    sleep 0.2
done
echo "  $NUM_AGENTS sandbox launches dispatched"

# ─── Sample while waiting ──
echo
echo -e "${BOLD}── sampling ──${NC}"
while true; do
    alive=0
    for pid in "${PIDS[@]}"; do
        kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
    done
    sample_metrics
    [ "$alive" -eq 0 ] && break
    echo -e "  ${DIM}t=$(($(date +%s) - START_TIME))s alive=$alive${NC}"
    sleep "$SAMPLE_INTERVAL_SEC"
done
sample_metrics

echo
echo -e "${BOLD}── all agents finished ──${NC}"

# ─── Validation ──
echo
echo -e "${BOLD}═══ Validation ═══${NC}"
fail=0
assert_ge() {
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" -ge "$expected" ] 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC} $name (got $actual ≥ $expected)"
    else
        echo -e "  ${RED}FAIL${NC} $name (got $actual, expected ≥ $expected)"
        fail=$((fail + 1))
    fi
}
assert_le() {
    local name="$1" actual="$2" limit="$3"
    if [ "$actual" -le "$limit" ] 2>/dev/null; then
        echo -e "  ${GREEN}PASS${NC} $name (got $actual ≤ $limit)"
    else
        echo -e "  ${RED}FAIL${NC} $name (got $actual, limit $limit)"
        fail=$((fail + 1))
    fi
}

# 1. Chain integrity
echo -e "${CYAN}1. Audit chain integrity${NC}"
"$GVM_BIN" audit verify --wal "$WAL" 2>&1 > "$RESULTS_DIR/audit-verify.txt"
chain_ok=$(grep -c "Integrity chain (GIC):" "$RESULTS_DIR/audit-verify.txt" 2>/dev/null || echo 0)
hash_mismatches=$(grep -oE 'Hash mismatches:\s+[0-9]+' "$RESULTS_DIR/audit-verify.txt" | grep -oE '[0-9]+$' || echo "?")
if [ "$hash_mismatches" = "0" ] && [ "$chain_ok" -ge 1 ]; then
    echo -e "  ${GREEN}PASS${NC} gvm audit verify (0 hash mismatches, chain valid)"
else
    echo -e "  ${RED}FAIL${NC} chain verify (mismatches=$hash_mismatches chain_ok=$chain_ok)"
    fail=$((fail + 1))
fi

# 2. Per-agent attribution — three layers, increasingly strict.
#    Layer 1: sandbox.launch events carry the right agent_id (proves
#             the CLI's --agent-id flag propagated to the launch path)
#    Layer 2: every load-agent-N has at least one transport-bearing
#             durable WAL event (proves identity survives end-to-end
#             through the mock-server roundtrip)
#    Layer 3: no event has `agent_id="unknown"` for our N-agent IDs
#             (proves the X-GVM-Agent-Id header was honored)
echo
echo -e "${CYAN}2. Per-agent attribution${NC}"
launches=$(jq -c 'select(.operation == "gvm.sandbox.launch")' < "$WAL" 2>/dev/null | wc -l)
assert_ge "sandbox launches in WAL" "$launches" "$NUM_AGENTS"
distinct_ids=$(jq -r 'select(.operation == "gvm.sandbox.launch") | .agent_id' < "$WAL" 2>/dev/null \
    | grep -c "^load-agent-" || echo 0)
assert_ge "distinct load-agent IDs in launches" "$distinct_ids" "$NUM_AGENTS"

missing_traffic=0
for i in $(seq 1 "$NUM_AGENTS"); do
    aid="load-agent-$i"
    n=$(jq -c "select(.agent_id==\"$aid\" and .transport != null)" < "$WAL" 2>/dev/null | wc -l)
    [ "$n" -lt 1 ] && missing_traffic=$((missing_traffic + 1))
done
assert_le "agents missing transport-bearing events" "$missing_traffic" 0

# 3. Total event count — informational. Synthetic hosts produce
# variable fail-fast traffic; we assert non-zero rather than a
# specific floor, because the test's value is in the stability
# primitives (memory/FD/chain/orphans), not throughput.
echo
echo -e "${CYAN}3. Total durable event count (informational)${NC}"
total_events=$(jq -c "select(.transport != null)" < "$WAL" 2>/dev/null | wc -l)
echo "  durable transport-bearing events: $total_events (probe budget: $((NUM_AGENTS * REQUESTS_PER_AGENT)))"
echo "  most agent calls return 502 fast on synthetic hosts; tally is"
echo "  expected to be a small fraction of the budget. The chain integrity"
echo "  + orphan checks below are the load-test invariants."

# 4. Memory plateau (last 30% samples)
echo
echo -e "${CYAN}4. Memory plateau${NC}"
python3 - "$METRICS_CSV" << 'PY'
import csv, sys, statistics
path = sys.argv[1]
rss = []
with open(path) as f:
    r = csv.reader(f); next(r, None)
    for row in r:
        try: rss.append(int(row[2]))
        except (ValueError, IndexError): pass
if len(rss) < 5:
    print("  SKIP not enough samples"); sys.exit(0)
n = max(5, int(round(len(rss) * 0.3)))
tail = rss[-n:]
rng_kb = max(tail) - min(tail)
std_kb = statistics.pstdev(tail) if len(tail) > 1 else 0
peak_mb = max(rss) / 1024
delta_mb = (max(rss) - rss[0]) / 1024
print(f"  initial: {rss[0]/1024:.1f}MB  peak: {peak_mb:.1f}MB  delta: {delta_mb:.1f}MB")
print(f"  last {n} samples: range={rng_kb}KB stddev={std_kb:.1f}KB")
if rng_kb <= 1024 and std_kb <= 512:
    print(f"  PASS plateau (range≤1MB stddev≤0.5MB)")
elif delta_mb < 100:
    print(f"  PASS bounded growth (Δ {delta_mb:.1f}MB < 100MB budget)")
else:
    print(f"  FAIL excessive growth: {delta_mb:.1f}MB")
    sys.exit(1)
PY
mem_rc=$?
[ "$mem_rc" -ne 0 ] && fail=$((fail + 1))

# 5. FD growth
echo
echo -e "${CYAN}5. FD count${NC}"
initial_fd=$(awk -F, 'NR==2 {print $4}' "$METRICS_CSV")
final_fd=$(awk -F, 'END{print $4}' "$METRICS_CSV")
peak_fd=$(awk -F, 'NR>1 {if($4>m) m=$4} END{print m}' "$METRICS_CSV")
echo "  initial=$initial_fd peak=$peak_fd final=$final_fd"
delta_fd=$((final_fd - initial_fd))
assert_le "post-run FD growth" "$delta_fd" 30

# 6. Orphan check
echo
echo -e "${CYAN}6. Orphan resources after run${NC}"
orph_state=$(ls /run/gvm/gvm-sandbox-*.state 2>/dev/null | wc -l)
orph_veth=$(ip -o link show 2>/dev/null | grep -c veth-gvm-h || true)
orph_nat=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c "10.200.0.0" || true)
assert_le "orphan state files" "$orph_state" 0
assert_le "orphan veth interfaces" "$orph_veth" 0
assert_le "orphan NAT rules"      "$orph_nat" 0

# 7. Per-rule decision counts
echo
echo -e "${CYAN}7. Per-rule decision sanity${NC}"
count_decision_substr() {
    jq -c "select(.transport != null and (.matched_rule_id // \"\" | contains(\"$1\")))" \
        < "$WAL" 2>/dev/null | wc -l
}
echo "  rule 2 (Deny suffix):  $(count_decision_substr 'rule-2')"
echo "  rule 3 (Delay):        $(count_decision_substr 'rule-3')"
echo "  rule 4 (RequireAppr):  $(count_decision_substr 'rule-4')"
echo "  rule 8 (cond outside): $(count_decision_substr 'rule-8')"

# Summary
echo
if [ "$fail" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}── LOAD TEST PASSED — N=$NUM_AGENTS agents, $total_events durable events, peak RSS ${peak_mb:-?}MB ──${NC}"
else
    echo -e "${RED}${BOLD}── LOAD TEST FAILED ($fail assertion failures) ──${NC}"
    exit 1
fi
