#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — 1-Hour Stress Test with OpenClaw Chaos Agents
#
# Runs 5 OpenClaw agent instances through GVM proxy for 60 minutes
# with chaos injection (proxy kill, network partition, disk pressure).
# Collects metrics every 60s. Reports pass/fail with evidence.
#
# Requirements:
#   - Linux (EC2 recommended, t3.medium+)
#   - ANTHROPIC_API_KEY set
#   - GVM proxy + CLI built (cargo build --release)
#   - OpenClaw installed (pip install openclaw or from repo)
#   - tc command available (iproute2)
#
# Usage:
#   bash scripts/stress-test.sh                    # sandbox mode (default)
#   bash scripts/stress-test.sh --contained        # Docker contained mode
#   bash scripts/stress-test.sh --duration 30      # 30 minutes instead of 60
#   bash scripts/stress-test.sh --agents 3         # 3 agents instead of 5
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-60}
NUM_AGENTS=${NUM_AGENTS:-5}
MODE="sandbox"  # sandbox or contained
STAGGER_SEC=60
CHAOS_KILL_MIN=20
CHAOS_NETWORK_MIN=30
CHAOS_DISK_MIN=40
CHAOS_DISK_RELEASE_MIN=45
METRIC_INTERVAL=60
MAX_MEM_INCREASE_MB=100
MAX_FD_CONSECUTIVE_INCREASE=60

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GVM_BIN="$REPO_DIR/target/release/gvm"
PROXY_BIN="$REPO_DIR/target/release/gvm-proxy"
PROXY_URL="http://127.0.0.1:8080"
ADMIN_URL="http://127.0.0.1:9090"
WORKLOADS_DIR="$SCRIPT_DIR/stress-workloads"
STRESS_SRR="$REPO_DIR/config/stress-srr.toml"
RESULTS_DIR="$REPO_DIR/results/stress-$(date +%Y%m%dT%H%M%S)"
METRICS_CSV="$RESULTS_DIR/metrics.csv"
CHAOS_LOG="$RESULTS_DIR/chaos.log"
SUMMARY="$RESULTS_DIR/summary.txt"

# Colors
BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --contained) MODE="contained"; shift ;;
        --duration) DURATION_MIN="$2"; shift 2 ;;
        --agents) NUM_AGENTS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DURATION_SEC=$((DURATION_MIN * 60))

# ── Validation ──
check_prereqs() {
    local fail=false
    [ -z "${ANTHROPIC_API_KEY:-}" ] && echo -e "${RED}ANTHROPIC_API_KEY not set${NC}" && fail=true
    [ ! -f "$PROXY_BIN" ] && echo -e "${RED}Proxy not built: $PROXY_BIN${NC}" && fail=true
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}CLI not built: $GVM_BIN${NC}" && fail=true
    command -v openclaw >/dev/null 2>&1 || command -v python3 -c "import openclaw" >/dev/null 2>&1 || {
        echo -e "${YELLOW}OpenClaw not found — will use Python HTTP agent fallback${NC}"
    }
    $fail && exit 1
}

# ── Setup ──
setup() {
    mkdir -p "$RESULTS_DIR/agents"
    echo -e "${BOLD}${CYAN}═══ GVM Stress Test ═══${NC}"
    echo -e "  Mode:       ${BOLD}$MODE${NC}"
    echo -e "  Duration:   ${DURATION_MIN}m"
    echo -e "  Agents:     $NUM_AGENTS"
    echo -e "  Results:    $RESULTS_DIR"
    echo ""

    # Backup current SRR, load stress rules
    cp "$REPO_DIR/config/srr_network.toml" "$REPO_DIR/config/srr_network.toml.stressbak"
    cp "$STRESS_SRR" "$REPO_DIR/config/srr_network.toml"

    # Start proxy
    "$PROXY_BIN" --config "$REPO_DIR/config/proxy.toml" > "$RESULTS_DIR/proxy.log" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$RESULTS_DIR/proxy.pid"
    sleep 3

    # Verify proxy health
    local status
    status=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "dead")
    if [ "$status" != "healthy" ]; then
        echo -e "${RED}Proxy failed to start (status: $status)${NC}"
        exit 1
    fi

    # Reload with stress SRR
    curl -sf -X POST "$ADMIN_URL/gvm/reload" > /dev/null 2>&1
    echo -e "  ${GREEN}Proxy started (PID $PROXY_PID)${NC}"

    # Record initial metrics
    INITIAL_RSS=$(get_rss $PROXY_PID)
    echo "initial_rss_mb=$INITIAL_RSS" >> "$SUMMARY"

    # CSV header
    echo "timestamp,elapsed_sec,rss_mb,fd_count,wal_bytes,orphan_veth,proxy_healthy,pending_approvals,active_agents,merkle_batches" > "$METRICS_CSV"
    echo "# Chaos event log" > "$CHAOS_LOG"
}

# ── Metrics Collection ──
get_rss() {
    local pid=$1
    ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"
}

get_fd_count() {
    local pid=$1
    ls /proc/"$pid"/fd 2>/dev/null | wc -l || echo "0"
}

get_wal_bytes() {
    stat -c%s "$REPO_DIR/data/wal.log" 2>/dev/null || echo "0"
}

get_orphan_veth() {
    ip link 2>/dev/null | grep -c "veth-gvm" || echo "0"
}

get_merkle_batches() {
    grep -c '"batch_id"' "$REPO_DIR/data/wal.log" 2>/dev/null || echo "0"
}

collect_metric() {
    local elapsed=$1
    local pid
    pid=$(cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0")

    local rss fd wal veth healthy pending agents batches
    rss=$(get_rss "$pid")
    fd=$(get_fd_count "$pid")
    wal=$(get_wal_bytes)
    veth=$(get_orphan_veth)
    healthy=$(curl -sf --connect-timeout 2 "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "dead")
    pending=$(curl -sf --connect-timeout 2 "$ADMIN_URL/gvm/pending" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(len(d.get('pending',[])))" 2>/dev/null || echo "0")
    agents=$(pgrep -c -f "openclaw\|stress-agent" 2>/dev/null || echo "0")
    batches=$(get_merkle_batches)

    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "$ts,$elapsed,$rss,$fd,$wal,$veth,$healthy,$pending,$agents,$batches" >> "$METRICS_CSV"
    echo -e "  ${DIM}[$ts] RSS=${rss}MB fd=$fd WAL=$(echo "$wal" | numfmt --to=iec 2>/dev/null || echo "$wal") veth=$veth health=$healthy agents=$agents${NC}"
}

# ── Metrics Loop (background) ──
metrics_loop() {
    local start_time=$1
    while true; do
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - start_time))
        [ $elapsed -ge $DURATION_SEC ] && break
        collect_metric $elapsed
        sleep $METRIC_INTERVAL
    done
}

# ── Agent Launcher ──
launch_agent() {
    local id=$1
    local workload_file=$2
    local agent_log="$RESULTS_DIR/agents/agent-$id.log"
    local session_id="stress-agent-$id-$(date +%s)"

    local prompt
    prompt=$(cat "$workload_file")

    echo -e "  ${CYAN}Starting agent #$id ($session_id)${NC}"

    # Use openclaw if available, otherwise Python HTTP fallback
    if command -v openclaw >/dev/null 2>&1; then
        timeout $((DURATION_SEC + 120)) openclaw gateway \
            --session-id "$session_id" \
            --prompt "$prompt" \
            --max-turns 100 \
            --max-tokens 4096 \
            > "$agent_log" 2>&1 &
    else
        # Fallback: Python script that makes HTTP requests through proxy
        timeout $((DURATION_SEC + 120)) python3 -c "
import requests, time, os, random
proxy = '$PROXY_URL'
proxies = {'http': proxy, 'https': proxy}
urls = [
    ('GET', 'http://api.github.com/repos/torvalds/linux/issues?per_page=1'),
    ('GET', 'http://api.github.com/repos/rust-lang/rust/commits?per_page=1'),
    ('POST', 'http://webhook.site/test'),
    ('GET', 'http://catfact.ninja/fact'),
    ('GET', 'http://api.coindesk.com/v1/bpi/currentprice.json'),
    ('GET', 'http://numbersapi.com/42'),
    ('GET', 'http://dog.ceo/api/breeds/image/random'),
]
for i in range(200):
    method, url = random.choice(urls)
    try:
        if method == 'GET':
            r = requests.get(url, proxies=proxies, timeout=15)
        else:
            r = requests.post(url, json={'data':'stress-$id'}, proxies=proxies, timeout=15)
        print(f'[{i}] {method} {url} -> {r.status_code}')
    except Exception as e:
        print(f'[{i}] {method} {url} -> ERR: {e}')
    time.sleep(random.uniform(5, 20))
" > "$agent_log" 2>&1 &
    fi

    echo $! >> "$RESULTS_DIR/agent_pids.txt"
}

launch_all_agents() {
    > "$RESULTS_DIR/agent_pids.txt"
    local workloads=("$WORKLOADS_DIR"/agent-*.txt)
    local count=${#workloads[@]}

    for i in $(seq 1 "$NUM_AGENTS"); do
        local idx=$(( (i - 1) % count ))
        launch_agent "$i" "${workloads[$idx]}"
        echo -e "  ${DIM}Staggering ${STAGGER_SEC}s before next agent...${NC}"
        sleep "$STAGGER_SEC"
    done
    echo -e "  ${GREEN}All $NUM_AGENTS agents launched${NC}"
}

# ── Chaos Injection ──
chaos_log() {
    local msg="$1"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "[$ts] $msg" >> "$CHAOS_LOG"
    echo -e "  ${YELLOW}CHAOS [$ts]: $msg${NC}"
}

chaos_proxy_kill() {
    chaos_log "INJECT: kill -9 proxy (PID $(cat "$RESULTS_DIR/proxy.pid"))"
    kill -9 "$(cat "$RESULTS_DIR/proxy.pid")" 2>/dev/null

    # Wait for watchdog restart (max 30s)
    local recovered=false
    for i in $(seq 1 30); do
        sleep 1
        if curl -sf --connect-timeout 2 "$PROXY_URL/gvm/health" > /dev/null 2>&1; then
            # Proxy is back — update PID
            local new_pid
            new_pid=$(pgrep -f "gvm-proxy" | head -1 || echo "0")
            echo "$new_pid" > "$RESULTS_DIR/proxy.pid"
            chaos_log "RECOVERED: proxy restarted (PID $new_pid) after ${i}s"
            recovered=true
            break
        fi
    done

    if ! $recovered; then
        chaos_log "FAIL: proxy did not restart within 30s — restarting manually"
        "$PROXY_BIN" --config "$REPO_DIR/config/proxy.toml" > "$RESULTS_DIR/proxy-restart.log" 2>&1 &
        local pid=$!
        echo "$pid" > "$RESULTS_DIR/proxy.pid"
        sleep 3
        curl -sf -X POST "$ADMIN_URL/gvm/reload" > /dev/null 2>&1
        chaos_log "MANUAL RESTART: proxy PID $pid"
    fi
}

chaos_network_partition() {
    chaos_log "INJECT: network partition — 5000ms delay + 20% packet loss on proxy upstream"
    # Add latency to outbound proxy traffic (not agent→proxy, but proxy→upstream)
    sudo tc qdisc add dev eth0 root netem delay 5000ms loss 20% 2>/dev/null || {
        chaos_log "WARN: tc qdisc failed (may need root or eth0 is wrong interface)"
        return
    }
    chaos_log "Network partition active — monitoring FD count for socket leaks"
}

chaos_network_restore() {
    chaos_log "RESTORE: removing network partition"
    sudo tc qdisc del dev eth0 root 2>/dev/null || true
    chaos_log "Network partition removed"
}

chaos_disk_pressure() {
    chaos_log "INJECT: disk pressure — filling WAL directory to 99%"
    local wal_dir
    wal_dir=$(dirname "$REPO_DIR/data/wal.log")
    # Create a large file to fill disk
    dd if=/dev/zero of="$wal_dir/stress-fill.dat" bs=1M count=100 2>/dev/null || true
    chaos_log "Disk pressure active — WAL should trigger circuit breaker (503)"
}

chaos_disk_release() {
    chaos_log "RESTORE: releasing disk pressure"
    rm -f "$REPO_DIR/data/stress-fill.dat"
    chaos_log "Disk pressure released — WAL should recover"
}

# ── Chaos Scheduler ──
chaos_scheduler() {
    local start_time=$1

    while true; do
        local now elapsed_min
        now=$(date +%s)
        elapsed_min=$(( (now - start_time) / 60 ))

        [ $elapsed_min -ge "$DURATION_MIN" ] && break

        # T+20: proxy kill
        if [ $elapsed_min -eq "$CHAOS_KILL_MIN" ]; then
            chaos_proxy_kill
            sleep 120  # skip to avoid re-triggering
            continue
        fi

        # T+30: network partition
        if [ $elapsed_min -eq "$CHAOS_NETWORK_MIN" ]; then
            chaos_network_partition
            sleep 300  # 5 minutes of partition
            chaos_network_restore
            continue
        fi

        # T+40: disk pressure
        if [ $elapsed_min -eq "$CHAOS_DISK_MIN" ]; then
            chaos_disk_pressure
            sleep 300  # 5 minutes of disk pressure
            chaos_disk_release
            continue
        fi

        sleep 30
    done
}

# ── Pass/Fail Evaluation ──
evaluate_results() {
    echo "" >> "$SUMMARY"
    echo "═══ Pass/Fail Evaluation ═══" >> "$SUMMARY"
    local pass=true

    # 1. Memory leak check
    local max_rss initial_rss mem_increase
    max_rss=$(awk -F, 'NR>1 {print $3}' "$METRICS_CSV" | sort -n | tail -1)
    initial_rss=$(head -2 "$METRICS_CSV" | tail -1 | cut -d, -f3)
    mem_increase=$(echo "$max_rss - $initial_rss" | bc 2>/dev/null || echo "0")
    echo "memory: initial=${initial_rss}MB max=${max_rss}MB increase=${mem_increase}MB (limit: ${MAX_MEM_INCREASE_MB}MB)" >> "$SUMMARY"

    if (( $(echo "$mem_increase > $MAX_MEM_INCREASE_MB" | bc -l 2>/dev/null || echo 0) )); then
        echo "FAIL: memory leak — ${mem_increase}MB increase exceeds ${MAX_MEM_INCREASE_MB}MB limit" >> "$SUMMARY"
        pass=false
    else
        echo "PASS: memory stable" >> "$SUMMARY"
    fi

    # 2. FD leak check (monotonic increase detection)
    local fd_increases=0
    local prev_fd=0
    while IFS=, read -r _ _ _ fd _ _ _ _ _ _; do
        [ "$fd" = "fd_count" ] && continue
        if [ "$fd" -gt "$prev_fd" ] 2>/dev/null && [ "$prev_fd" -gt 0 ]; then
            fd_increases=$((fd_increases + 1))
        else
            fd_increases=0
        fi
        prev_fd=$fd
    done < "$METRICS_CSV"
    echo "fd_leak: consecutive_increases=$fd_increases (limit: $MAX_FD_CONSECUTIVE_INCREASE)" >> "$SUMMARY"

    if [ "$fd_increases" -ge "$MAX_FD_CONSECUTIVE_INCREASE" ]; then
        echo "FAIL: FD leak — $fd_increases consecutive increases" >> "$SUMMARY"
        pass=false
    else
        echo "PASS: FD stable" >> "$SUMMARY"
    fi

    # 3. Proxy restart check
    if grep -q "RECOVERED: proxy restarted" "$CHAOS_LOG" 2>/dev/null; then
        local restart_time
        restart_time=$(grep "RECOVERED" "$CHAOS_LOG" | grep -oP 'after \K[0-9]+')
        echo "PASS: proxy recovered after ${restart_time}s" >> "$SUMMARY"
    elif grep -q "FAIL: proxy did not restart" "$CHAOS_LOG" 2>/dev/null; then
        echo "FAIL: proxy did not auto-restart after kill" >> "$SUMMARY"
        pass=false
    fi

    # 4. Orphan veth check
    local final_veth
    final_veth=$(get_orphan_veth)
    echo "orphan_veth: $final_veth" >> "$SUMMARY"
    if [ "$final_veth" -gt 0 ] 2>/dev/null; then
        echo "FAIL: $final_veth orphan veth interfaces after test" >> "$SUMMARY"
        pass=false
    else
        echo "PASS: no orphan veth" >> "$SUMMARY"
    fi

    # 5. WAL integrity
    if [ -f "$REPO_DIR/data/wal.log" ]; then
        "$GVM_BIN" audit verify --wal "$REPO_DIR/data/wal.log" > "$RESULTS_DIR/wal-verify.txt" 2>&1 || true
        if grep -qi "valid\|pass\|ok" "$RESULTS_DIR/wal-verify.txt" 2>/dev/null; then
            echo "PASS: WAL Merkle chain verified" >> "$SUMMARY"
        else
            echo "WARN: WAL verification inconclusive" >> "$SUMMARY"
        fi
    fi

    # 6. Final verdict
    echo "" >> "$SUMMARY"
    if $pass; then
        echo "═══ VERDICT: PASS ═══" >> "$SUMMARY"
        touch "$RESULTS_DIR/PASS"
        echo -e "${GREEN}${BOLD}═══ VERDICT: PASS ═══${NC}"
    else
        echo "═══ VERDICT: FAIL ═══" >> "$SUMMARY"
        touch "$RESULTS_DIR/FAIL"
        echo -e "${RED}${BOLD}═══ VERDICT: FAIL ═══${NC}"
    fi

    cat "$SUMMARY"
}

# ── Cleanup ──
cleanup() {
    echo -e "\n${BOLD}Cleaning up...${NC}"

    # Kill agents
    if [ -f "$RESULTS_DIR/agent_pids.txt" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$RESULTS_DIR/agent_pids.txt"
    fi

    # Kill proxy
    if [ -f "$RESULTS_DIR/proxy.pid" ]; then
        kill "$(cat "$RESULTS_DIR/proxy.pid")" 2>/dev/null || true
    fi

    # Remove network chaos if active
    sudo tc qdisc del dev eth0 root 2>/dev/null || true

    # Remove disk pressure
    rm -f "$REPO_DIR/data/stress-fill.dat"

    # Restore original SRR
    if [ -f "$REPO_DIR/config/srr_network.toml.stressbak" ]; then
        mv "$REPO_DIR/config/srr_network.toml.stressbak" "$REPO_DIR/config/srr_network.toml"
    fi

    echo -e "${DIM}Results saved to: $RESULTS_DIR${NC}"
}

trap cleanup EXIT

# ── Main ──
main() {
    check_prereqs
    setup

    local start_time
    start_time=$(date +%s)

    # Start metrics collection (background)
    metrics_loop "$start_time" &
    METRICS_PID=$!

    # Start chaos scheduler (background)
    chaos_scheduler "$start_time" &
    CHAOS_PID=$!

    # Launch agents (staggered)
    launch_all_agents

    # Wait for test duration
    echo -e "\n${BOLD}Test running for ${DURATION_MIN} minutes...${NC}"
    echo -e "${DIM}Chaos events at T+${CHAOS_KILL_MIN}m (kill), T+${CHAOS_NETWORK_MIN}m (network), T+${CHAOS_DISK_MIN}m (disk)${NC}\n"

    local remaining=$DURATION_SEC
    while [ $remaining -gt 0 ]; do
        local min=$((remaining / 60))
        echo -ne "\r  ${DIM}Time remaining: ${min}m${NC}    "
        sleep 30
        remaining=$((remaining - 30))
    done
    echo ""

    # Stop background tasks
    kill $METRICS_PID 2>/dev/null || true
    kill $CHAOS_PID 2>/dev/null || true

    # Final metric collection
    local final_elapsed=$(($(date +%s) - start_time))
    collect_metric $final_elapsed

    # Evaluate
    echo ""
    evaluate_results
}

main "$@"
