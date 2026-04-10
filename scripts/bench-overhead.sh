#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Overhead Benchmark
#
# Measures actual latency overhead of GVM proxy and sandbox.
# Compares with/without GVM for HTTP and LLM requests.
#
# Results:
#   - Proxy overhead per request (MITM TLS + SRR + WAL)
#   - Sandbox startup (one-time: namespace + mount + veth + seccomp)
#   - Concurrent throughput
#
# Usage:
#   sudo bash scripts/bench-overhead.sh
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GVM_BIN="$REPO_DIR/target/release/gvm"
RESULTS_DIR="$REPO_DIR/results/bench-$(date +%Y%m%dT%H%M%S)"
PROXY_URL="http://127.0.0.1:8080"
ITERATIONS=20
LLM_ITERATIONS=5
CONCURRENT=10

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

mkdir -p "$RESULTS_DIR"

[ ! -f "$GVM_BIN" ] && echo "Build first: cargo build --release" && exit 1
[ "$(id -u)" -ne 0 ] && echo "Run with sudo" && exit 1

calc_stats() {
    local file="$1"
    python3 -c "
import sys
vals = sorted([float(x.strip()) for x in open('$file') if x.strip()])
if not vals:
    print('n=0')
    sys.exit()
n = len(vals)
med = vals[n//2]
p95 = vals[int(n*0.95)] if n >= 5 else vals[-1]
p99 = vals[int(n*0.99)] if n >= 10 else vals[-1]
avg = sum(vals)/n
print(f'n={n} avg={avg:.3f} med={med:.3f} p95={p95:.3f} p99={p99:.3f} min={vals[0]:.3f} max={vals[-1]:.3f}')
" 2>/dev/null
}

echo -e "${BOLD}${CYAN}═══ GVM Overhead Benchmark ═══${NC}"
echo -e "  Iterations: $ITERATIONS (HTTP), $LLM_ITERATIONS (LLM)"
echo -e "  Results:    $RESULTS_DIR"
echo ""

# ── Ensure proxy is running ──
"$GVM_BIN" status --proxy "$PROXY_URL" > /dev/null 2>&1 || {
    echo "Starting proxy..."
    timeout 10 "$GVM_BIN" run --agent-id warmup -- echo ok > /dev/null 2>&1
}

# ═══════════════════════════════════════
# Test A: HTTP Overhead (httpbin.org)
# ═══════════════════════════════════════
echo -e "${BOLD}Test A: HTTP Request Overhead${NC}"

# A1: Baseline (direct, no proxy)
echo -e "  ${DIM}A1: Direct HTTPS (baseline)...${NC}"
for i in $(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w "%{time_starttransfer}\n" https://httpbin.org/get
done > "$RESULTS_DIR/a1-direct-ttfb.txt"

for i in $(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w "%{time_total}\n" https://httpbin.org/get
done > "$RESULTS_DIR/a1-direct-total.txt"

echo -e "  TTFB:  $(calc_stats "$RESULTS_DIR/a1-direct-ttfb.txt")"
echo -e "  Total: $(calc_stats "$RESULTS_DIR/a1-direct-total.txt")"

# A2: Via GVM proxy (CONNECT tunnel, cooperative)
echo -e "  ${DIM}A2: Via GVM proxy (CONNECT)...${NC}"
for i in $(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w "%{time_starttransfer}\n" -x "$PROXY_URL" https://httpbin.org/get
done > "$RESULTS_DIR/a2-proxy-ttfb.txt"

for i in $(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w "%{time_total}\n" -x "$PROXY_URL" https://httpbin.org/get
done > "$RESULTS_DIR/a2-proxy-total.txt"

echo -e "  TTFB:  $(calc_stats "$RESULTS_DIR/a2-proxy-ttfb.txt")"
echo -e "  Total: $(calc_stats "$RESULTS_DIR/a2-proxy-total.txt")"

# A3: Via GVM sandbox MITM (DNAT path, inside sandbox)
# Write results to /workspace/output/ (writable inside sandbox)
echo -e "  ${DIM}A3: Via sandbox MITM (DNAT)...${NC}"
"$GVM_BIN" cleanup > /dev/null 2>&1
timeout 90 "$GVM_BIN" run --sandbox --agent-id bench-http --sandbox-timeout 60 \
    -- bash -c "
for i in \$(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w '%{time_starttransfer}\n' https://httpbin.org/get
done > /workspace/output/ttfb.txt
for i in \$(seq 1 $ITERATIONS); do
    curl -sf -o /dev/null -w '%{time_total}\n' https://httpbin.org/get
done > /workspace/output/total.txt
cat /workspace/output/ttfb.txt
echo '---'
cat /workspace/output/total.txt
" > /tmp/a3-raw.txt 2>/dev/null

# Split output
sed -n '1,/^---$/p' /tmp/a3-raw.txt | grep -v "^---$" | grep "^[0-9]" > "$RESULTS_DIR/a3-sandbox-ttfb.txt"
sed -n '/^---$/,$ p' /tmp/a3-raw.txt | grep -v "^---$" | grep "^[0-9]" > "$RESULTS_DIR/a3-sandbox-total.txt"

echo -e "  TTFB:  $(calc_stats "$RESULTS_DIR/a3-sandbox-ttfb.txt")"
echo -e "  Total: $(calc_stats "$RESULTS_DIR/a3-sandbox-total.txt")"

echo ""

# ═══════════════════════════════════════
# Test B: Sandbox Startup Overhead
# ═══════════════════════════════════════
echo -e "${BOLD}Test B: Sandbox Startup (one-time)${NC}"

for i in $(seq 1 5); do
    "$GVM_BIN" cleanup > /dev/null 2>&1
    START=$(date +%s%N)
    timeout 30 "$GVM_BIN" run --sandbox --agent-id "bench-startup-$i" --sandbox-timeout 10 \
        -- echo "ready" > /dev/null 2>&1
    END=$(date +%s%N)
    echo "$(( (END - START) / 1000000 ))"
done > "$RESULTS_DIR/b-sandbox-startup-ms.txt"

echo -e "  Startup: $(calc_stats "$RESULTS_DIR/b-sandbox-startup-ms.txt") ms"
echo ""

# ═══════════════════════════════════════
# Test C: LLM Proxy Overhead
# ═══════════════════════════════════════
echo -e "${BOLD}Test C: LLM Call Overhead (Anthropic API)${NC}"

# C1: Baseline (direct, no proxy)
echo -e "  ${DIM}C1: Direct LLM call (baseline)...${NC}"
OC="node /usr/lib/node_modules/openclaw/openclaw.mjs"
for i in $(seq 1 $LLM_ITERATIONS); do
    START=$(date +%s%N)
    timeout 60 $OC agent --local --session-id "bench-direct-$i" -m "Say hi" > /dev/null 2>&1
    END=$(date +%s%N)
    echo "$(( (END - START) / 1000000 ))"
done > "$RESULTS_DIR/c1-llm-direct-ms.txt"

echo -e "  Time: $(calc_stats "$RESULTS_DIR/c1-llm-direct-ms.txt") ms"

# C2: Via sandbox MITM (proxy overhead only, sandbox already running)
echo -e "  ${DIM}C2: LLM via sandbox MITM (proxy overhead)...${NC}"
"$GVM_BIN" cleanup > /dev/null 2>&1
timeout 180 "$GVM_BIN" run --sandbox --agent-id bench-llm --sandbox-timeout 150 \
    -- bash -c "
OC='node /usr/lib/node_modules/openclaw/openclaw.mjs'
for i in \$(seq 1 $LLM_ITERATIONS); do
    START=\$(date +%s%N)
    timeout 60 \$OC agent --local --session-id bench-sandbox-\$i -m 'Say hi' > /dev/null 2>&1
    END=\$(date +%s%N)
    echo \$(( (END - START) / 1000000 ))
done > /workspace/output/llm-times.txt
cat /workspace/output/llm-times.txt
" > /tmp/c2-raw.txt 2>/dev/null

grep "^[0-9]" /tmp/c2-raw.txt > "$RESULTS_DIR/c2-llm-sandbox-ms.txt"
echo -e "  Time: $(calc_stats "$RESULTS_DIR/c2-llm-sandbox-ms.txt") ms"
echo ""

# ═══════════════════════════════════════
# Test D: Concurrent Throughput
# ═══════════════════════════════════════
echo -e "${BOLD}Test D: Concurrent Throughput ($CONCURRENT parallel)${NC}"

# D1: Direct
echo -e "  ${DIM}D1: Direct concurrent...${NC}"
START=$(date +%s%N)
for i in $(seq 1 $CONCURRENT); do
    curl -sf -o /dev/null https://httpbin.org/get &
done
wait
END=$(date +%s%N)
DIRECT_MS=$(( (END - START) / 1000000 ))
echo "$DIRECT_MS" > "$RESULTS_DIR/d1-concurrent-direct-ms.txt"
echo -e "  Direct: ${DIRECT_MS}ms"

# D2: Via proxy
echo -e "  ${DIM}D2: Via proxy concurrent...${NC}"
START=$(date +%s%N)
for i in $(seq 1 $CONCURRENT); do
    curl -sf -o /dev/null -x "$PROXY_URL" https://httpbin.org/get &
done
wait
END=$(date +%s%N)
PROXY_MS=$(( (END - START) / 1000000 ))
echo "$PROXY_MS" > "$RESULTS_DIR/d2-concurrent-proxy-ms.txt"
echo -e "  Proxy:  ${PROXY_MS}ms"

echo ""

# ═══════════════════════════════════════
# Test E: Memory (RSS) Measurement
# ═══════════════════════════════════════
echo -e "${BOLD}Test E: Memory Usage (RSS)${NC}"

# E1: gvm-proxy idle RSS
echo -e "  ${DIM}E1: gvm-proxy idle RSS...${NC}"
# Kill any existing proxy, start fresh, wait for startup, measure
pkill -f gvm-proxy 2>/dev/null
sleep 1
"$GVM_BIN" run --agent-id rss-warmup -- echo ok > /dev/null 2>&1
sleep 2
PROXY_PID=$(pgrep -f "gvm-proxy" | head -1)
if [ -n "$PROXY_PID" ]; then
    PROXY_RSS_KB=$(awk '/^VmRSS:/ {print $2}' /proc/$PROXY_PID/status 2>/dev/null)
    PROXY_RSS_MB=$(python3 -c "print(f'{${PROXY_RSS_KB:-0}/1024:.1f}')")
    echo -e "  gvm-proxy PID $PROXY_PID: ${PROXY_RSS_MB}MB RSS (idle)"
    echo "$PROXY_RSS_KB" > "$RESULTS_DIR/e1-proxy-idle-rss-kb.txt"
else
    echo -e "  (proxy not found)"
fi

# E2: gvm-proxy RSS after load (send 50 requests through it)
echo -e "  ${DIM}E2: gvm-proxy RSS after 50 requests...${NC}"
for i in $(seq 1 50); do
    curl -sf -o /dev/null -x "$PROXY_URL" https://httpbin.org/get &
done
wait
sleep 1
if [ -n "$PROXY_PID" ] && [ -d "/proc/$PROXY_PID" ]; then
    PROXY_RSS_LOADED_KB=$(awk '/^VmRSS:/ {print $2}' /proc/$PROXY_PID/status 2>/dev/null)
    PROXY_RSS_LOADED_MB=$(python3 -c "print(f'{${PROXY_RSS_LOADED_KB:-0}/1024:.1f}')")
    echo -e "  gvm-proxy PID $PROXY_PID: ${PROXY_RSS_LOADED_MB}MB RSS (after 50 reqs)"
    echo "$PROXY_RSS_LOADED_KB" > "$RESULTS_DIR/e2-proxy-loaded-rss-kb.txt"
else
    echo -e "  (proxy exited)"
fi

# E3: Sandbox agent RSS (the agent process itself inside sandbox)
echo -e "  ${DIM}E3: Sandbox overhead (agent RSS inside sandbox vs direct)...${NC}"
"$GVM_BIN" cleanup > /dev/null 2>&1
timeout 30 "$GVM_BIN" run --sandbox --agent-id bench-rss --sandbox-timeout 15 \
    -- bash -c "
# Measure this shell's own RSS as a proxy for 'sandbox overhead on the agent'
awk '/^VmRSS:/ {print \$2}' /proc/self/status
" > /tmp/e3-raw.txt 2>/dev/null
SANDBOX_AGENT_RSS_KB=$(grep "^[0-9]" /tmp/e3-raw.txt | head -1)
if [ -n "$SANDBOX_AGENT_RSS_KB" ]; then
    SANDBOX_AGENT_RSS_MB=$(python3 -c "print(f'{${SANDBOX_AGENT_RSS_KB}/1024:.1f}')")
    echo -e "  Agent inside sandbox: ${SANDBOX_AGENT_RSS_MB}MB RSS"
    echo "$SANDBOX_AGENT_RSS_KB" > "$RESULTS_DIR/e3-sandbox-agent-rss-kb.txt"
fi

# E4: Direct agent RSS (same bash -c, no sandbox) for comparison
DIRECT_AGENT_RSS_KB=$(bash -c "awk '/^VmRSS:/ {print \$2}' /proc/self/status" 2>/dev/null)
if [ -n "$DIRECT_AGENT_RSS_KB" ]; then
    DIRECT_AGENT_RSS_MB=$(python3 -c "print(f'{${DIRECT_AGENT_RSS_KB}/1024:.1f}')")
    echo -e "  Agent without sandbox: ${DIRECT_AGENT_RSS_MB}MB RSS"
    echo "$DIRECT_AGENT_RSS_KB" > "$RESULTS_DIR/e4-direct-agent-rss-kb.txt"
fi

echo ""

# ═══════════════════════════════════════
# Summary
# ═══════════════════════════════════════
echo -e "${BOLD}═══ Summary ═══${NC}"

python3 << PYEOF > "$RESULTS_DIR/summary.txt"
import os

def load(path):
    try:
        vals = sorted([float(x.strip()) for x in open(path) if x.strip()])
        if not vals: return None
        n = len(vals)
        return {
            'n': n, 'avg': sum(vals)/n, 'med': vals[n//2],
            'p95': vals[int(n*0.95)] if n>=5 else vals[-1],
            'min': vals[0], 'max': vals[-1]
        }
    except: return None

R = "$RESULTS_DIR"

print("GVM Overhead Benchmark Results")
print("=" * 60)

# HTTP TTFB
d = load(f"{R}/a1-direct-ttfb.txt")
p = load(f"{R}/a2-proxy-ttfb.txt")
s = load(f"{R}/a3-sandbox-ttfb.txt")
if d and p:
    oh_p = (p['med'] - d['med']) * 1000
    print(f"\nHTTP TTFB (httpbin.org/get):")
    print(f"  Direct:        {d['med']*1000:.1f}ms (median)")
    print(f"  Proxy:         {p['med']*1000:.1f}ms (median)")
    print(f"  Proxy overhead: +{oh_p:.1f}ms")
if s:
    oh_s = (s['med'] - d['med']) * 1000 if d else 0
    print(f"  Sandbox MITM:  {s['med']*1000:.1f}ms (median)")
    print(f"  MITM overhead:  +{oh_s:.1f}ms")

# Sandbox startup
ss = load(f"{R}/b-sandbox-startup-ms.txt")
if ss:
    print(f"\nSandbox Startup (one-time):")
    print(f"  Median: {ss['med']:.0f}ms")
    print(f"  Range:  {ss['min']:.0f}-{ss['max']:.0f}ms")

# LLM
ld = load(f"{R}/c1-llm-direct-ms.txt")
ls = load(f"{R}/c2-llm-sandbox-ms.txt")
if ld and ls:
    oh_l = ls['med'] - ld['med']
    print(f"\nLLM Call (Anthropic API, 'Say hi'):")
    print(f"  Direct:         {ld['med']:.0f}ms (median)")
    print(f"  Sandbox MITM:   {ls['med']:.0f}ms (median)")
    print(f"  Proxy overhead: +{oh_l:.0f}ms (per request, sandbox already running)")

# Concurrent
try:
    cd = float(open(f"{R}/d1-concurrent-direct-ms.txt").read().strip())
    cp = float(open(f"{R}/d2-concurrent-proxy-ms.txt").read().strip())
    print(f"\nConcurrent Throughput ({int('$CONCURRENT')} parallel):")
    print(f"  Direct: {cd:.0f}ms")
    print(f"  Proxy:  {cp:.0f}ms")
    print(f"  Overhead: +{cp-cd:.0f}ms")
except: pass

# RSS
print(f"\nMemory (RSS):")
try:
    idle_kb = float(open(f"{R}/e1-proxy-idle-rss-kb.txt").read().strip())
    print(f"  gvm-proxy idle:       {idle_kb/1024:.1f}MB")
except: pass
try:
    loaded_kb = float(open(f"{R}/e2-proxy-loaded-rss-kb.txt").read().strip())
    print(f"  gvm-proxy after load: {loaded_kb/1024:.1f}MB")
except: pass
try:
    sb_kb = float(open(f"{R}/e3-sandbox-agent-rss-kb.txt").read().strip())
    print(f"  Agent in sandbox:     {sb_kb/1024:.1f}MB")
except: pass
try:
    dr_kb = float(open(f"{R}/e4-direct-agent-rss-kb.txt").read().strip())
    print(f"  Agent direct:         {dr_kb/1024:.1f}MB")
except: pass

print()
PYEOF

cat "$RESULTS_DIR/summary.txt"
echo -e "\n  Results: $RESULTS_DIR"
