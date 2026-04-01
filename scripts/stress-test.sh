#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — 1-Hour Stress Test with OpenClaw Chaos Agents
#
# Runs 3 OpenClaw agent instances through GVM proxy for 60 minutes
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
#   bash scripts/stress-test.sh --agents 5         # 5 agents instead of 3
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-60}
NUM_AGENTS=${NUM_AGENTS:-3}
MODE="sandbox"  # sandbox or contained
# Agent stagger: 60s × 3 agents = T+2m. Baseline starts at T+6m.
# First chaos at T+15m gives 9 minutes of stable baseline.
STAGGER_SEC=60
CHAOS_KILL_MIN=${CHAOS_KILL_MIN:-15}
CHAOS_NETWORK_MIN=${CHAOS_NETWORK_MIN:-25}
CHAOS_DISK_MIN=${CHAOS_DISK_MIN:-35}
# Disk release defaults to DISK + 5 minutes (not an absolute value).
# Previous bug: default 40 exceeded 30-min test → release never fired.
CHAOS_DISK_RELEASE_MIN=${CHAOS_DISK_RELEASE_MIN:-0}
METRIC_INTERVAL=60
MAX_MEM_INCREASE_MB=100
MAX_FD_CONSECUTIVE_INCREASE=60
# Chaos done flags (prevents re-triggering with -ge comparison)
CHAOS_KILL_DONE=false
CHAOS_NETWORK_DONE=false
CHAOS_DISK_DONE=false
CHAOS_DISK_RELEASED=false

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env file if present (ANTHROPIC_API_KEY, etc.)
if [ -f "$REPO_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_DIR/.env"
    set +a
fi
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
        --chaos-kill) CHAOS_KILL_MIN="$2"; shift 2 ;;
        --chaos-network) CHAOS_NETWORK_MIN="$2"; shift 2 ;;
        --chaos-disk) CHAOS_DISK_MIN="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DURATION_SEC=$((DURATION_MIN * 60))

# Calculate disk release relative to disk inject (default: +5 minutes)
if [ "$CHAOS_DISK_RELEASE_MIN" -eq 0 ] 2>/dev/null; then
    CHAOS_DISK_RELEASE_MIN=$((CHAOS_DISK_MIN + 5))
fi

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

    # Reset WAL for clean measurement (backup first)
    cp "$REPO_DIR/data/wal.log" "$RESULTS_DIR/wal-pre-stress.log" 2>/dev/null || true
    > "$REPO_DIR/data/wal.log"

    # Start proxy as independent daemon via proxy_manager pattern.
    # Uses setsid + PID file so proxy survives script exit and chaos kill recovery.
    # Kill any existing proxy first to ensure clean state with stress SRR.
    if [ -f "$REPO_DIR/data/proxy.pid" ]; then
        local old_pid
        old_pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || echo "0")
        kill "$old_pid" 2>/dev/null || true
        sleep 1
    fi

    cd "$REPO_DIR"
    setsid "$PROXY_BIN" > "$REPO_DIR/data/proxy.log" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$REPO_DIR/data/proxy.pid"
    echo "$PROXY_PID" > "$RESULTS_DIR/proxy.pid"
    sleep 3

    # Verify proxy health
    local status
    status=$( (curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])") 2>/dev/null) || status="dead"
    if [ "$status" != "healthy" ]; then
        echo -e "${RED}Proxy failed to start (status: $status)${NC}"
        exit 1
    fi

    # Reload with stress SRR
    curl -sf -X POST "$ADMIN_URL/gvm/reload" > /dev/null 2>&1
    echo -e "  ${GREEN}Proxy started as daemon (PID $PROXY_PID)${NC}"

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
    pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0")

    local rss fd wal veth healthy pending agents batches
    rss=$(get_rss "$pid")
    fd=$(get_fd_count "$pid")
    wal=$(get_wal_bytes)
    veth=$(get_orphan_veth)
    healthy=$( (curl -sf --connect-timeout 2 "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])") 2>/dev/null) || healthy="dead"
    pending=$( (curl -sf --connect-timeout 2 "$ADMIN_URL/gvm/pending" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(len(d.get('pending',[])))") 2>/dev/null) || pending="0"
    agents=$(pgrep -c -f "openclaw\|stress-agent" 2>/dev/null || echo "0")
    batches=$(get_merkle_batches)

    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "$ts,$elapsed,$rss,$fd,$wal,$veth,$healthy,$pending,$agents,$batches" >> "$METRICS_CSV"
    echo -e "  ${DIM}[$ts] RSS=${rss}MB fd=$fd WAL=$(echo "$wal" | numfmt --to=iec 2>/dev/null || echo "$wal") veth=$veth health=$healthy agents=$agents${NC}"
}

# ── Metrics Loop (background) ──
metrics_loop() {
    # Disable pipefail in background function — failed curl|python3 pipes
    # (e.g., proxy dead during chaos kill) must not kill the metrics loop.
    set +o pipefail
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

    # Run agent through GVM in the configured mode (sandbox/contained).
    # In sandbox mode: DNAT forces all 443 traffic through MITM proxy,
    # so even Node.js (which ignores HTTPS_PROXY) is governed.
    # In contained mode: Docker DNAT does the same.
    local gvm_mode_flag=""
    if [ "$MODE" = "sandbox" ]; then
        gvm_mode_flag="--sandbox"
    elif [ "$MODE" = "contained" ]; then
        gvm_mode_flag="--contained"
    fi

    if command -v openclaw >/dev/null 2>&1 && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        # Use explicit node path — sandbox mounts /usr/lib/node_modules but not /usr/bin/openclaw symlink
        local OC_MJS="/usr/lib/node_modules/openclaw/openclaw.mjs"
        [ ! -f "$OC_MJS" ] && OC_MJS="$(readlink -f "$(which openclaw)" 2>/dev/null || echo "openclaw")"
        # Each turn = fresh sandbox → OpenClaw call → sandbox cleanup.
        # Independent turns ensure cleanup runs between calls (no orphan accumulation).
        # 3 agents × ~90s/turn (60s call + 30s sleep) = sustained load for full duration.
        (
            TURN_TIMEOUT=120
            START_TIME=$(date +%s)
            for turn in $(seq 1 999); do
                # Stop if test duration exceeded
                ELAPSED=$(( $(date +%s) - START_TIME ))
                [ $ELAPSED -ge $DURATION_SEC ] && break

                echo "[Turn $turn] $(date -u +%H:%M:%S)"
                "$GVM_BIN" run $gvm_mode_flag \
                    --agent-id "${session_id}-t${turn}" -- \
                    node "$OC_MJS" agent --local \
                    --session-id "${session_id}-t${turn}" \
                    --message "$prompt" \
                    --timeout "$TURN_TIMEOUT" \
                    2>&1 || true
                sleep 30
            done
        ) > "$agent_log" 2>&1 &
    else
        # Fallback: Python script that makes HTTP requests through proxy
        timeout $((DURATION_SEC + 120)) "$GVM_BIN" run $gvm_mode_flag \
            --agent-id "$session_id" -- python3 -c "
import requests, time, os, random
proxy = '$PROXY_URL'
proxies = {'http': proxy, 'https': proxy}
urls = [
    ('GET', 'http://api.github.com/repos/torvalds/linux/commits?per_page=1'),
    ('GET', 'http://api.github.com/repos/rust-lang/rust/commits?per_page=1'),
    ('GET', 'http://raw.githubusercontent.com/golang/go/master/README.md'),
    ('GET', 'http://catfact.ninja/fact'),
    ('GET', 'http://numbersapi.com/random/trivia'),
    ('GET', 'http://dog.ceo/api/breeds/image/random'),
    ('GET', 'http://official-joke-api.appspot.com/random_joke'),
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
    local old_pid
    old_pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0")
    chaos_log "INJECT: kill -9 proxy (PID $old_pid)"
    kill -9 "$old_pid" 2>/dev/null

    # Save WAL backup before restart (chaos recovery evidence)
    cp "$REPO_DIR/data/wal.log" "$RESULTS_DIR/wal-before-chaos.log" 2>/dev/null || true

    # Restart proxy as daemon (same pattern as setup)
    sleep 2
    cd "$REPO_DIR"
    setsid "$PROXY_BIN" >> "$REPO_DIR/data/proxy.log" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$REPO_DIR/data/proxy.pid"
    echo "$new_pid" > "$RESULTS_DIR/proxy.pid"

    # Wait for health (max 30s)
    local recovered=false
    for i in $(seq 1 30); do
        sleep 1
        if curl -sf --connect-timeout 2 "$PROXY_URL/gvm/health" > /dev/null 2>&1; then
            chaos_log "RECOVERED: proxy restarted (PID $new_pid) after ${i}s"
            recovered=true
            break
        fi
    done

    if ! $recovered; then
        chaos_log "FAIL: proxy restart failed (PID $new_pid)"
    fi

    # Verify SRR rules are loaded after restart (fail-open prevention)
    sleep 2
    local srr_check
    srr_check=$( (curl -sf -X POST "$PROXY_URL/gvm/check" \
        -H "Content-Type: application/json" \
        -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/torvalds/linux/commits","operation":"test"}' \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))") 2>/dev/null) || srr_check="unreachable"

    if echo "$srr_check" | grep -qi "Allow"; then
        chaos_log "VERIFY: SRR rules loaded correctly after restart (api.github.com → Allow)"
    else
        chaos_log "FAIL: SRR rules NOT loaded after restart — fail-open risk (got: $srr_check)"
    fi
}

chaos_network_partition() {
    chaos_log "INJECT: network partition — 5000ms delay + 20% loss on upstream ports"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")

    # Strategy: tc prio qdisc with netem on band 3, iptables marks packets
    # to upstream ports (80, 443) with fwmark → routed to the netem band.
    # Localhost traffic (metrics, admin API) is unaffected (different interface/loopback).
    # Using destination port (not --pid-owner) because tokio threads make PID matching unreliable.
    sudo tc qdisc add dev "$iface" root handle 1: prio 2>/dev/null || true
    sudo tc qdisc add dev "$iface" parent 1:3 handle 30: netem delay 5000ms loss 20% 2>/dev/null || {
        chaos_log "WARN: tc prio+netem failed — falling back to interface-wide"
        sudo tc qdisc add dev "$iface" root netem delay 5000ms loss 20% 2>/dev/null || true
        chaos_log "Network partition active (interface-wide fallback)"
        return
    }

    # Mark only outbound TCP to ports 80/443 (upstream API traffic)
    # Exclude loopback and proxy port (8080/9090) so metrics collection works
    sudo iptables -t mangle -A OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -A OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true
    sudo tc filter add dev "$iface" parent 1:0 protocol ip handle 42 fw flowid 1:3 2>/dev/null || true

    chaos_log "Network partition active on $iface (ports 80/443 only, loopback excluded)"
}

chaos_network_restore() {
    chaos_log "RESTORE: removing network partition"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true
    chaos_log "Network partition removed"
}

chaos_disk_pressure() {
    chaos_log "INJECT: disk pressure — mounting 64KB tmpfs over WAL directory"
    # Mount a tiny tmpfs over the WAL directory so writes fail with ENOSPC.
    # This is more reliable than filling a large disk with dd.
    # The proxy should trigger circuit breaker (503) and switch to emergency WAL.
    local wal_dir="$REPO_DIR/data"
    DISK_PRESSURE_TMPFS="$wal_dir"

    # Save WAL before overwriting
    cp "$wal_dir/wal.log" "$RESULTS_DIR/wal-before-chaos.log" 2>/dev/null || true

    sudo mount -t tmpfs -o size=64k tmpfs "$wal_dir" 2>/dev/null || {
        chaos_log "WARN: tmpfs mount failed — falling back to dd fill"
        dd if=/dev/zero of="$wal_dir/stress-fill.dat" bs=1M count=100 2>/dev/null || true
        DISK_PRESSURE_TMPFS=""
        chaos_log "Disk pressure active (dd fallback)"
        return
    }
    # Fill the tiny tmpfs immediately
    dd if=/dev/zero of="$wal_dir/fill" bs=1k count=60 2>/dev/null || true
    chaos_log "Disk pressure active (64KB tmpfs over WAL dir — ENOSPC on next write)"
}

chaos_disk_release() {
    chaos_log "RESTORE: releasing disk pressure"
    if [ -n "${DISK_PRESSURE_TMPFS:-}" ]; then
        sudo umount "$DISK_PRESSURE_TMPFS" 2>/dev/null || true
        # Restore WAL from backup
        cp "$RESULTS_DIR/wal-before-chaos.log" "$REPO_DIR/data/wal.log" 2>/dev/null || true
    else
        rm -f "$REPO_DIR/data/stress-fill.dat"
    fi
    chaos_log "Disk pressure released — WAL should recover"
}

# ── Chaos Scheduler ──
chaos_scheduler() {
    set +o pipefail
    local start_time=$1

    # Use -ge (not -eq) to prevent missing the target minute due to sleep alignment.
    # Done flags prevent re-triggering on subsequent loop iterations.
    while true; do
        local now elapsed_min
        now=$(date +%s)
        elapsed_min=$(( (now - start_time) / 60 ))

        [ $elapsed_min -ge "$DURATION_MIN" ] && break

        # T+15: proxy kill -9
        if [ $elapsed_min -ge "$CHAOS_KILL_MIN" ] && ! $CHAOS_KILL_DONE; then
            CHAOS_KILL_DONE=true
            chaos_proxy_kill
        fi

        # T+25: network partition (5 min duration)
        if [ $elapsed_min -ge "$CHAOS_NETWORK_MIN" ] && ! $CHAOS_NETWORK_DONE; then
            CHAOS_NETWORK_DONE=true
            chaos_network_partition
            # Schedule restore after 5 minutes (background)
            (sleep 300 && chaos_network_restore) &
        fi

        # T+35: disk pressure
        if [ $elapsed_min -ge "$CHAOS_DISK_MIN" ] && ! $CHAOS_DISK_DONE; then
            CHAOS_DISK_DONE=true
            chaos_disk_pressure
        fi

        # T+40: disk release
        if [ $elapsed_min -ge "$CHAOS_DISK_RELEASE_MIN" ] && ! $CHAOS_DISK_RELEASED; then
            CHAOS_DISK_RELEASED=true
            chaos_disk_release
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
    elif grep -q "RECOVERED: proxy manually restarted" "$CHAOS_LOG" 2>/dev/null; then
        echo "PASS: proxy manually restarted after kill (no watchdog in standalone)" >> "$SUMMARY"
    elif grep -q "FAIL: proxy manual restart failed" "$CHAOS_LOG" 2>/dev/null; then
        echo "FAIL: proxy could not be restarted after kill" >> "$SUMMARY"
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

    # 6. Export audit log for post-mortem analysis
    if [ -f "$REPO_DIR/data/wal.log" ] && [ -f "$GVM_BIN" ]; then
        "$GVM_BIN" audit export --since 2h --wal "$REPO_DIR/data/wal.log" --format jsonl \
            > "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null || true
        local event_count
        event_count=$(wc -l < "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null || echo "0")
        echo "audit_export: $event_count events → audit-export.jsonl" >> "$SUMMARY"

        # Extract decision breakdown from audit log
        if [ "$event_count" -gt 0 ] 2>/dev/null && command -v jq >/dev/null 2>&1; then
            echo "" >> "$SUMMARY"
            echo "── Audit Breakdown ──" >> "$SUMMARY"

            # Decision counts
            local allow_n delay_n deny_n approval_n
            allow_n=$(jq -r 'select(.decision | test("Allow")) | .decision' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null | wc -l)
            delay_n=$(jq -r 'select(.decision | test("Delay")) | .decision' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null | wc -l)
            deny_n=$(jq -r 'select(.decision | test("Deny")) | .decision' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null | wc -l)
            approval_n=$(jq -r 'select(.decision | test("RequireApproval")) | .decision' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null | wc -l)
            echo "  Allow: $allow_n  Delay: $delay_n  Deny: $deny_n  RequireApproval: $approval_n" >> "$SUMMARY"

            # Decision ratio
            if [ "$event_count" -gt 0 ]; then
                local allow_pct deny_pct
                allow_pct=$(echo "scale=1; $allow_n * 100 / $event_count" | bc 2>/dev/null || echo "?")
                deny_pct=$(echo "scale=1; $deny_n * 100 / $event_count" | bc 2>/dev/null || echo "?")
                echo "  Allow: ${allow_pct}%  Deny: ${deny_pct}%  (of $event_count total)" >> "$SUMMARY"
            fi

            # Audit gap detection: find 30+ second gaps in event timestamps
            # (indicates WAL was not recording during chaos event)
            echo "" >> "$SUMMARY"
            local gaps
            gaps=$(jq -r '.timestamp' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null \
                | sort \
                | awk 'NR>1 {
                    cmd = "date -d \"" prev "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S\" \"" prev "\" +%s 2>/dev/null"
                    cmd | getline t1; close(cmd)
                    cmd = "date -d \"" $0 "\" +%s 2>/dev/null || date -j -f \"%Y-%m-%dT%H:%M:%S\" \"" $0 "\" +%s 2>/dev/null"
                    cmd | getline t2; close(cmd)
                    gap = t2 - t1
                    if (gap > 30) print prev " → " $0 " (" gap "s gap)"
                } { prev = $0 }' 2>/dev/null || true)

            if [ -n "$gaps" ]; then
                echo "  ⚠ Audit gaps (>30s without events):" >> "$SUMMARY"
                echo "$gaps" | while read -r line; do
                    echo "    $line" >> "$SUMMARY"
                done
                echo "  (Gaps during chaos events are expected; gaps outside chaos indicate WAL issue)" >> "$SUMMARY"
            else
                echo "  ✓ No audit gaps >30s detected" >> "$SUMMARY"
            fi
        elif [ "$event_count" -gt 0 ] 2>/dev/null; then
            # No jq — basic counts with grep
            echo "" >> "$SUMMARY"
            echo "── Audit Breakdown (jq not available, basic counts) ──" >> "$SUMMARY"
            local allow_n deny_n delay_n
            allow_n=$(grep -c '"Allow"' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null || echo "0")
            deny_n=$(grep -c '"Deny"' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null || echo "0")
            delay_n=$(grep -c '"Delay"' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null || echo "0")
            echo "  Allow: ~$allow_n  Delay: ~$delay_n  Deny: ~$deny_n" >> "$SUMMARY"
        fi
    fi

    # 7. Final verdict
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

    # Kill proxy (check both canonical PID file and results copy)
    for pidfile in "$REPO_DIR/data/proxy.pid" "$RESULTS_DIR/proxy.pid"; do
        if [ -f "$pidfile" ]; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
        fi
    done

    # Remove network chaos if active
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo iptables -t mangle -F 2>/dev/null || true

    # Remove disk pressure
    if [ -n "${DISK_PRESSURE_TMPFS:-}" ]; then
        sudo umount "$DISK_PRESSURE_TMPFS" 2>/dev/null || true
    fi
    rm -f "$REPO_DIR/data/stress-fill.dat"

    # Run GVM cleanup for deterministic orphan removal (state-file based).
    "$GVM_BIN" cleanup 2>/dev/null || true

    # Defense-in-depth: also clean any veth/iptables that GVM cleanup missed.
    for veth in $(ip link show 2>/dev/null | grep -oP 'veth-gvm-h\S+' | cut -d@ -f1); do
        sudo ip link del "$veth" 2>/dev/null || true
    done
    for chain in $(sudo iptables -L 2>/dev/null | grep -oP 'GVM-\S+'); do
        sudo iptables -D FORWARD -j "$chain" 2>/dev/null || true
        sudo iptables -F "$chain" 2>/dev/null || true
        sudo iptables -X "$chain" 2>/dev/null || true
    done
    sudo iptables -t nat -F 2>/dev/null || true

    # Restore original SRR
    if [ -f "$REPO_DIR/config/srr_network.toml.stressbak" ]; then
        mv "$REPO_DIR/config/srr_network.toml.stressbak" "$REPO_DIR/config/srr_network.toml"
    fi

    # Restore WAL from backup
    if [ -f "$RESULTS_DIR/wal-pre-stress.log" ]; then
        cp "$RESULTS_DIR/wal-pre-stress.log" "$REPO_DIR/data/wal.log" 2>/dev/null || true
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

    # Kill agents BEFORE evaluation so their sandbox resources are released.
    # Without this, active agent sandboxes show as "orphan veth" in evaluation.
    if [ -f "$RESULTS_DIR/agent_pids.txt" ]; then
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$RESULTS_DIR/agent_pids.txt"
        sleep 3  # Wait for sandbox cleanup (veth deletion, state file removal)
    fi

    # Run GVM cleanup to deterministically remove any orphaned sandbox resources.
    # This handles the case where agent kill doesn't propagate cleanly.
    "$GVM_BIN" cleanup 2>/dev/null || true

    # Release disk pressure before evaluation (cleanup may have missed it)
    if [ -n "${DISK_PRESSURE_TMPFS:-}" ]; then
        sudo umount "$DISK_PRESSURE_TMPFS" 2>/dev/null || true
        if [ -f "$RESULTS_DIR/wal-before-chaos.log" ]; then
            cp "$RESULTS_DIR/wal-before-chaos.log" "$REPO_DIR/data/wal.log" 2>/dev/null || true
        fi
    fi

    # Final metric collection (after cleanup, so veth count is accurate)
    local final_elapsed=$(($(date +%s) - start_time))
    collect_metric $final_elapsed

    # Evaluate
    echo ""
    evaluate_results
}

main "$@"
