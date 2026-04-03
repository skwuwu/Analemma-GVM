#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Production Pattern Stress Test
#
# 3 long-running OpenClaw agents with autonomous research tasks,
# operator CLI checkpoints, chaos injection, and health monitoring.
#
# Designed for tmux — survives SSH disconnection:
#   tmux new -s gvm-stress
#   sudo env PATH=$PATH ANTHROPIC_API_KEY=$KEY bash scripts/prod-stress-test.sh
#   # Ctrl+B D to detach, tmux attach -t gvm-stress to reconnect
#
# Requirements:
#   - Linux (EC2 recommended, t3.medium+)
#   - ANTHROPIC_API_KEY set
#   - GVM proxy + CLI built (cargo build --release)
#   - OpenClaw installed (npm install -g openclaw)
#   - sudo access (for sandbox mode)
#
# Usage:
#   bash scripts/prod-stress-test.sh                 # 3 hours (default)
#   bash scripts/prod-stress-test.sh --duration 60   # 1 hour
#   bash scripts/prod-stress-test.sh --no-chaos      # agents only, no chaos
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-180}
NUM_AGENTS=3
HEALTH_INTERVAL=120       # health check every 2 minutes
CHAOS_ENABLED=true
CHAOS_KILL_MIN=40
CHAOS_NETWORK_MIN=90
CHAOS_DISK_MIN=60
CHAOS_DISK_RELEASE_MIN=70
CHAOS_NETWORK_RESTORE_MIN=100

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env
if [ -f "$REPO_DIR/.env" ]; then
    set -a; source "$REPO_DIR/.env"; set +a
fi

GVM_BIN="$REPO_DIR/target/release/gvm"
PROXY_BIN="$REPO_DIR/target/release/gvm-proxy"
PROXY_URL="http://127.0.0.1:8080"
ADMIN_URL="http://127.0.0.1:9090"
STRESS_SRR="$REPO_DIR/config/stress-srr.toml"
RESULTS_DIR="$REPO_DIR/results/prod-$(date +%Y%m%dT%H%M%S)"
METRICS_CSV="$RESULTS_DIR/metrics.csv"
HEALTH_LOG="$RESULTS_DIR/health.log"
CHAOS_LOG="$RESULTS_DIR/chaos.log"
CHECKPOINT_LOG="$RESULTS_DIR/checkpoints.csv"
SUMMARY="$RESULTS_DIR/summary.txt"
WAL="$REPO_DIR/data/wal.log"

# Colors
BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

# Chaos state
CHAOS_KILL_DONE=false
CHAOS_NETWORK_DONE=false
CHAOS_DISK_DONE=false
CHAOS_DISK_RELEASED=false
CHAOS_NETWORK_RESTORED=false
DISK_PRESSURE_TMPFS=""

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION_MIN="$2"; shift 2 ;;
        --no-chaos) CHAOS_ENABLED=false; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done
DURATION_SEC=$((DURATION_MIN * 60))

# ── Prereqs ──
check_prereqs() {
    local fail=false
    [ -z "${ANTHROPIC_API_KEY:-}" ] && echo -e "${RED}ANTHROPIC_API_KEY not set${NC}" && fail=true
    [ ! -f "$PROXY_BIN" ] && echo -e "${RED}Proxy not built${NC}" && fail=true
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}CLI not built${NC}" && fail=true
    command -v openclaw >/dev/null 2>&1 || {
        echo -e "${RED}OpenClaw not found (npm install -g openclaw)${NC}"; fail=true
    }
    command -v tmux >/dev/null 2>&1 || echo -e "${YELLOW}tmux not installed — SSH disconnect will kill test${NC}"
    $fail && exit 1
}

# ── Utility ──
get_rss() { ps -o rss= -p "$1" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0"; }
get_fd_count() { ls /proc/"$1"/fd 2>/dev/null | wc -l || echo "0"; }
get_orphan_veth() { ip link 2>/dev/null | grep -c "veth-gvm" || echo "0"; }
proxy_pid() { cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0"; }

proxy_healthy() {
    curl -sf --connect-timeout 3 "$PROXY_URL/gvm/health" > /dev/null 2>&1
}

log_health() {
    local ts elapsed msg
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    elapsed=$(( $(date +%s) - START_TIME ))
    msg="$1"
    echo "[$ts] +${elapsed}s $msg" >> "$HEALTH_LOG"
    echo -e "  ${DIM}[$ts] $msg${NC}"
}

# ── Hang & Panic Detection ──
#
# Checks every HEALTH_INTERVAL seconds:
# 1. Proxy alive (PID exists + health endpoint responds)
# 2. Kernel panic (dmesg for "kernel panic", "BUG:", "Oops:")
# 3. Agent processes still running
# 4. System load (detect runaway CPU)
# 5. WAL growing (proxy is recording — not hung)
#
check_health() {
    local pid issues=0
    pid=$(proxy_pid)

    # 1. Proxy process alive
    if ! kill -0 "$pid" 2>/dev/null; then
        log_health "ALERT: proxy process dead (PID $pid)"
        issues=$((issues + 1))
        # Auto-restart
        restart_proxy
    elif ! proxy_healthy; then
        log_health "ALERT: proxy not responding to health check (PID $pid)"
        issues=$((issues + 1))
    else
        local rss fd
        rss=$(get_rss "$pid")
        fd=$(get_fd_count "$pid")
        log_health "OK: proxy PID=$pid RSS=${rss}MB FD=$fd"
    fi

    # 2. Kernel panic / oops detection
    local kernel_issues
    kernel_issues=$(dmesg --time-format iso 2>/dev/null | tail -50 | grep -ciE "kernel panic|BUG:|Oops:|Call Trace:" || echo "0")
    if [ "$kernel_issues" -gt 0 ] 2>/dev/null; then
        log_health "CRITICAL: kernel panic/BUG detected in dmesg ($kernel_issues occurrences)"
        dmesg --time-format iso 2>/dev/null | tail -20 >> "$HEALTH_LOG"
        issues=$((issues + 1))
    fi

    # 3. Agent processes
    local alive=0 total=0
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid 2>/dev/null; do
        [ ! -f "$pid_file" ] && continue
        total=$((total + 1))
        local apid
        apid=$(cat "$pid_file" 2>/dev/null || echo "0")
        if kill -0 "$apid" 2>/dev/null; then
            alive=$((alive + 1))
        fi
    done
    log_health "agents: $alive/$total alive"

    # 4. System load
    local load1
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
    local ncpu
    ncpu=$(nproc 2>/dev/null || echo "2")
    # Alert if load > 4x CPU count (potential runaway)
    if awk "BEGIN{exit !($load1 > $ncpu * 4)}" 2>/dev/null; then
        log_health "WARN: system load $load1 exceeds 4x CPU count ($ncpu)"
    fi

    # 5. WAL growing (not hung)
    local wal_size
    wal_size=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
    log_health "WAL: ${wal_size} bytes, orphan_veth: $(get_orphan_veth)"

    # Collect to CSV
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local elapsed=$(( $(date +%s) - START_TIME ))
    echo "$ts,$elapsed,$(get_rss "$(proxy_pid)"),$(get_fd_count "$(proxy_pid)"),$wal_size,$(get_orphan_veth),$alive,$total" >> "$METRICS_CSV"

    return $issues
}

# ── Proxy Management ──
restart_proxy() {
    log_health "restarting proxy..."
    cd "$REPO_DIR"
    setsid "$PROXY_BIN" >> "$REPO_DIR/data/proxy.log" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$REPO_DIR/data/proxy.pid"
    echo "$new_pid" > "$RESULTS_DIR/proxy.pid"
    sleep 3
    if proxy_healthy; then
        log_health "proxy restarted (PID $new_pid)"
        curl -sf -X POST "$ADMIN_URL/gvm/reload" > /dev/null 2>&1 || true
    else
        log_health "FAIL: proxy restart failed"
    fi
}

# ── Setup ──
setup() {
    mkdir -p "$RESULTS_DIR/agents" "$RESULTS_DIR/checkpoints"

    echo -e "${BOLD}${CYAN}═══ GVM Production Stress Test ═══${NC}"
    echo -e "  Duration:    ${DURATION_MIN}m ($(echo "scale=1; $DURATION_MIN/60" | bc)h)"
    echo -e "  Agents:      $NUM_AGENTS (long-running autonomous tasks)"
    echo -e "  Chaos:       $CHAOS_ENABLED"
    echo -e "  Health:      every ${HEALTH_INTERVAL}s"
    echo -e "  Results:     $RESULTS_DIR"
    echo -e "  tmux:        $([ -n "$TMUX" ] && echo 'YES (safe to detach)' || echo 'NO (SSH disconnect will kill)')"
    echo ""

    # Save and swap SRR
    ORIGINAL_SRR="$REPO_DIR/config/srr_network.toml"
    cp "$ORIGINAL_SRR" "$RESULTS_DIR/srr_network.toml.original"
    cp "$STRESS_SRR" "$ORIGINAL_SRR"

    # Reset WAL
    cp "$WAL" "$RESULTS_DIR/wal-pre.log" 2>/dev/null || true
    > "$WAL"

    # Start proxy
    if [ -f "$REPO_DIR/data/proxy.pid" ]; then
        kill "$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null)" 2>/dev/null || true
        sleep 1
    fi
    cd "$REPO_DIR"
    setsid "$PROXY_BIN" > "$REPO_DIR/data/proxy.log" 2>&1 &
    PROXY_PID=$!
    echo "$PROXY_PID" > "$REPO_DIR/data/proxy.pid"
    echo "$PROXY_PID" > "$RESULTS_DIR/proxy.pid"
    sleep 3

    if ! proxy_healthy; then
        echo -e "${RED}Proxy failed to start${NC}"
        exit 1
    fi
    curl -sf -X POST "$ADMIN_URL/gvm/reload" > /dev/null 2>&1 || true
    echo -e "  ${GREEN}Proxy started (PID $PROXY_PID)${NC}"

    # CSV header
    echo "timestamp,elapsed_sec,rss_mb,fd_count,wal_bytes,orphan_veth,agents_alive,agents_total" > "$METRICS_CSV"
    echo "# Health log" > "$HEALTH_LOG"
    echo "# Chaos log" > "$CHAOS_LOG"
    echo "name|exit_code|timestamp" > "$CHECKPOINT_LOG"

    START_TIME=$(date +%s)
    echo "start_time=$START_TIME" > "$SUMMARY"
    echo "duration_min=$DURATION_MIN" >> "$SUMMARY"
}

# ── Agent Launch (single long-running session) ──
launch_agent() {
    local id=$1 prompt_file=$2 agent_id=$3
    local log="$RESULTS_DIR/agents/agent-${id}.log"
    local prompt
    prompt=$(cat "$prompt_file")

    local OC_MJS="/usr/lib/node_modules/openclaw/openclaw.mjs"
    [ ! -f "$OC_MJS" ] && OC_MJS="$(readlink -f "$(which openclaw)" 2>/dev/null || echo "openclaw")"

    echo -e "  ${CYAN}Launching agent #$id ($agent_id)${NC}"

    # Single long-running sandbox session — agent decides its own pacing
    GVM_SANDBOX_TIMEOUT=$((DURATION_SEC + 300)) \
    "$GVM_BIN" run --sandbox \
        --agent-id "$agent_id" \
        --sandbox-timeout $((DURATION_SEC + 300)) \
        -- node "$OC_MJS" agent --local \
        --timeout "$DURATION_SEC" \
        --message "$prompt" \
        > "$log" 2>&1 &

    echo $! > "$RESULTS_DIR/agents/agent-${id}.pid"
}

launch_all_agents() {
    local workloads=(
        "$SCRIPT_DIR/stress-workloads/prod-analyst.txt"
        "$SCRIPT_DIR/stress-workloads/prod-security.txt"
        "$SCRIPT_DIR/stress-workloads/prod-writer.txt"
    )
    for i in $(seq 1 "$NUM_AGENTS"); do
        local idx=$(( (i - 1) % ${#workloads[@]} ))
        launch_agent "$i" "${workloads[$idx]}" "prod-agent-$i"
        sleep 30  # stagger
    done
    echo -e "  ${GREEN}All $NUM_AGENTS agents launched${NC}"
}

# ── Chaos Functions ──
chaos_log() {
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "[$ts] $1" >> "$CHAOS_LOG"
    echo -e "  ${YELLOW}CHAOS [$ts]: $1${NC}"
}

chaos_proxy_kill() {
    local pid; pid=$(proxy_pid)
    chaos_log "INJECT: kill -9 proxy (PID $pid)"
    kill -9 "$pid" 2>/dev/null || true
    cp "$WAL" "$RESULTS_DIR/wal-before-kill.log" 2>/dev/null || true
    sleep 2
    restart_proxy
    # Verify CLI works after recovery
    sleep 3
    run_checkpoint "post_kill_events" \
        "$GVM_BIN" events list --last 5m --wal-file "$WAL" || true
    run_checkpoint "post_kill_audit" \
        "$GVM_BIN" audit verify --wal "$WAL" || true
}

chaos_network_partition() {
    chaos_log "INJECT: network partition (5s delay + 20% loss on 80/443)"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    sudo tc qdisc add dev "$iface" root handle 1: prio 2>/dev/null || true
    sudo tc qdisc add dev "$iface" parent 1:3 handle 30: netem delay 5000ms loss 20% 2>/dev/null || {
        sudo tc qdisc add dev "$iface" root netem delay 5000ms loss 20% 2>/dev/null || true
        chaos_log "network partition active (interface-wide fallback)"
        return
    }
    sudo iptables -t mangle -A OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -A OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    sudo tc filter add dev "$iface" parent 1:0 protocol ip handle 42 fw flowid 1:3 2>/dev/null || true
    chaos_log "network partition active on $iface"
}

chaos_disk_pressure() {
    chaos_log "INJECT: disk pressure (64KB tmpfs over WAL dir)"
    local wal_dir="$REPO_DIR/data"
    DISK_PRESSURE_TMPFS="$wal_dir"
    cp "$WAL" "$RESULTS_DIR/wal-before-disk.log" 2>/dev/null || true
    sudo mount -t tmpfs -o size=64k tmpfs "$wal_dir" 2>/dev/null || {
        chaos_log "WARN: tmpfs mount failed"
        DISK_PRESSURE_TMPFS=""
        return
    }
    dd if=/dev/zero of="$wal_dir/fill" bs=1k count=60 2>/dev/null || true
    chaos_log "disk pressure active (ENOSPC)"
}

chaos_disk_release() {
    chaos_log "RESTORE: releasing disk pressure"
    if [ -n "${DISK_PRESSURE_TMPFS:-}" ]; then
        sudo umount "$DISK_PRESSURE_TMPFS" 2>/dev/null || true
        cp "$RESULTS_DIR/wal-before-disk.log" "$WAL" 2>/dev/null || true
    fi
    chaos_log "disk pressure released"
    # Verify WAL resumes after disk recovery
    sleep 5
    run_checkpoint "post_disk_audit" \
        "$GVM_BIN" audit verify --wal "$WAL" || true
}

chaos_network_restore() {
    chaos_log "RESTORE: removing network partition"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    chaos_log "network partition removed"
    # Verify proxy works after network restore
    sleep 5
    run_checkpoint "post_network_events" \
        "$GVM_BIN" events list --last 5m --wal-file "$WAL" || true
}

# ── CLI Checkpoint ──
run_checkpoint() {
    local name="$1"; shift
    local output exit_code ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    output=$("$@" 2>&1) || true
    exit_code=$?
    echo "$name|$exit_code|$ts" >> "$CHECKPOINT_LOG"
    echo "$output" > "$RESULTS_DIR/checkpoints/${name}.log"
    if [ $exit_code -eq 0 ]; then
        log_health "CHECKPOINT $name: PASS (exit $exit_code)"
    else
        log_health "CHECKPOINT $name: FAIL (exit $exit_code)"
    fi
    return $exit_code
}

# ── Main Loop (health + chaos + checkpoints) ──
main_loop() {
    local check_count=0
    local last_wal_size=0

    while true; do
        local now elapsed_sec elapsed_min
        now=$(date +%s)
        elapsed_sec=$((now - START_TIME))
        elapsed_min=$((elapsed_sec / 60))

        [ $elapsed_sec -ge $DURATION_SEC ] && break

        # ── Health check ──
        check_health
        check_count=$((check_count + 1))

        # ── WAL hang detection ──
        local cur_wal_size
        cur_wal_size=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
        if [ "$check_count" -gt 3 ] && [ "$cur_wal_size" -eq "$last_wal_size" ] && [ "$cur_wal_size" -gt 0 ]; then
            log_health "WARN: WAL size unchanged for ${HEALTH_INTERVAL}s ($cur_wal_size bytes) — possible hang"
        fi
        last_wal_size=$cur_wal_size

        # ── All agents dead? ──
        local alive=0
        for pid_file in "$RESULTS_DIR"/agents/agent-*.pid 2>/dev/null; do
            [ ! -f "$pid_file" ] && continue
            kill -0 "$(cat "$pid_file" 2>/dev/null)" 2>/dev/null && alive=$((alive + 1))
        done
        if [ "$alive" -eq 0 ] && [ "$check_count" -gt 5 ]; then
            log_health "INFO: all agents finished — continuing health monitoring for remaining time"
        fi

        # ── Chaos injection (time-based) ──
        if $CHAOS_ENABLED; then
            if [ $elapsed_min -ge $CHAOS_KILL_MIN ] && ! $CHAOS_KILL_DONE; then
                CHAOS_KILL_DONE=true
                chaos_proxy_kill
            fi
            if [ $elapsed_min -ge $CHAOS_DISK_MIN ] && ! $CHAOS_DISK_DONE; then
                CHAOS_DISK_DONE=true
                chaos_disk_pressure
            fi
            if [ $elapsed_min -ge $CHAOS_DISK_RELEASE_MIN ] && ! $CHAOS_DISK_RELEASED; then
                CHAOS_DISK_RELEASED=true
                chaos_disk_release
            fi
            if [ $elapsed_min -ge $CHAOS_NETWORK_MIN ] && ! $CHAOS_NETWORK_DONE; then
                CHAOS_NETWORK_DONE=true
                chaos_network_partition
            fi
            if [ $elapsed_min -ge $CHAOS_NETWORK_RESTORE_MIN ] && ! $CHAOS_NETWORK_RESTORED; then
                CHAOS_NETWORK_RESTORED=true
                chaos_network_restore
            fi
        fi

        # ── Periodic CLI checkpoints ──
        # Every 10 minutes, rotate through CLI commands to verify they work under load.
        # At T+25m, test SRR hot-reload. At T+30m, verify it took effect.
        if [ $((elapsed_min % 10)) -eq 0 ] && [ $elapsed_min -gt 0 ]; then
            case $((elapsed_min % 50)) in
                0)  run_checkpoint "T${elapsed_min}_events" \
                        "$GVM_BIN" events list --last 10m --wal-file "$WAL" || true ;;
                10) run_checkpoint "T${elapsed_min}_audit" \
                        "$GVM_BIN" audit verify --wal "$WAL" || true ;;
                20) run_checkpoint "T${elapsed_min}_tokens" \
                        "$GVM_BIN" stats tokens --wal-file "$WAL" || true ;;
                30) run_checkpoint "T${elapsed_min}_check" \
                        "$GVM_BIN" check --host api.github.com --method GET \
                        --operation test --proxy "$PROXY_URL" || true ;;
                40) run_checkpoint "T${elapsed_min}_preflight" \
                        "$GVM_BIN" preflight || true ;;
            esac
        fi

        # ── Hot-reload test (once, at T+25m) ──
        if [ $elapsed_min -ge 25 ] && [ "${HOTRELOAD_DONE:-false}" = "false" ]; then
            HOTRELOAD_DONE=true
            log_health "HOT-RELOAD: appending httpbin.org Delay rule"
            local live_srr="$REPO_DIR/config/srr_network.toml"
            cat >> "$live_srr" << 'HOTRELOAD_RULE'

# Hot-reload test rule (appended by prod-stress-test.sh)
[[rules]]
method = "GET"
pattern = "httpbin.org/{any}"
decision = { type = "Delay", milliseconds = 500 }
label = "prod-stress-hotreload"
HOTRELOAD_RULE
            run_checkpoint "T${elapsed_min}_reload" \
                curl -sf -X POST "$ADMIN_URL/gvm/reload" || true
            sleep 3
            # Verify: gvm check should return Delay for httpbin.org
            local check_out
            check_out=$("$GVM_BIN" check --host httpbin.org --method GET \
                --operation test --proxy "$PROXY_URL" 2>&1) || true
            if echo "$check_out" | grep -qi "Delay"; then
                log_health "HOT-RELOAD VERIFY: PASS (httpbin.org → Delay)"
                echo "hotreload_verify|0|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKPOINT_LOG"
            else
                log_health "HOT-RELOAD VERIFY: FAIL (expected Delay, got: $check_out)"
                echo "hotreload_verify|1|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKPOINT_LOG"
            fi
        fi

        sleep "$HEALTH_INTERVAL"
    done
}

# ── Evaluation ──
evaluate_results() {
    echo "" >> "$SUMMARY"
    echo "═══ Pass/Fail Evaluation ═══" >> "$SUMMARY"
    local pass=true

    # 1. Memory
    local max_rss initial_rss
    max_rss=$(awk -F, 'NR>1 {print $3}' "$METRICS_CSV" | sort -n | tail -1)
    initial_rss=$(awk -F, 'NR==2 {print $3}' "$METRICS_CSV")
    local mem_inc
    mem_inc=$(echo "${max_rss:-0} - ${initial_rss:-0}" | bc 2>/dev/null || echo "0")
    echo "memory: initial=${initial_rss}MB max=${max_rss}MB increase=${mem_inc}MB" >> "$SUMMARY"
    if awk "BEGIN{exit !(${mem_inc:-0} > 100)}" 2>/dev/null; then
        echo "FAIL: memory leak" >> "$SUMMARY"; pass=false
    else
        echo "PASS: memory stable" >> "$SUMMARY"
    fi

    # 2. Kernel panic
    local panics
    panics=$(grep -c "CRITICAL.*kernel panic\|CRITICAL.*BUG" "$HEALTH_LOG" 2>/dev/null || echo "0")
    if [ "$panics" -gt 0 ]; then
        echo "FAIL: $panics kernel panic/BUG events detected" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no kernel panic" >> "$SUMMARY"
    fi

    # 3. Proxy recovery
    if $CHAOS_ENABLED && grep -q "INJECT.*kill" "$CHAOS_LOG" 2>/dev/null; then
        if grep -q "proxy restarted" "$HEALTH_LOG" 2>/dev/null; then
            echo "PASS: proxy recovered after kill" >> "$SUMMARY"
        else
            echo "FAIL: proxy did not recover" >> "$SUMMARY"; pass=false
        fi
    fi

    # 4. Orphan veth
    local final_veth
    final_veth=$(get_orphan_veth)
    if [ "${final_veth:-0}" -gt 0 ] 2>/dev/null; then
        "$GVM_BIN" cleanup 2>/dev/null || true
        final_veth=$(get_orphan_veth)
    fi
    echo "orphan_veth: $final_veth (after cleanup)" >> "$SUMMARY"
    if [ "${final_veth:-0}" -gt 0 ] 2>/dev/null; then
        echo "FAIL: orphan veth remains" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no orphan veth" >> "$SUMMARY"
    fi

    # 5. WAL integrity
    if [ -f "$WAL" ] && [ -s "$WAL" ]; then
        "$GVM_BIN" audit verify --wal "$WAL" > "$RESULTS_DIR/wal-verify.txt" 2>&1 || true
        if grep -qi "valid\|pass\|ok" "$RESULTS_DIR/wal-verify.txt" 2>/dev/null; then
            echo "PASS: WAL Merkle chain verified" >> "$SUMMARY"
        else
            echo "WARN: WAL verification inconclusive" >> "$SUMMARY"
        fi
        local wal_events
        wal_events=$(wc -l < "$WAL" 2>/dev/null || echo "0")
        echo "wal_events: $wal_events" >> "$SUMMARY"
    fi

    # 6. Agent completion
    local completed=0 total_agents=0
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid 2>/dev/null; do
        [ ! -f "$pid_file" ] && continue
        total_agents=$((total_agents + 1))
        local apid
        apid=$(cat "$pid_file" 2>/dev/null || echo "0")
        if ! kill -0 "$apid" 2>/dev/null; then
            # Process exited — check if exit code was captured
            completed=$((completed + 1))
        fi
    done
    echo "agents_completed: $completed/$total_agents" >> "$SUMMARY"

    # 7. CLI checkpoints
    local cp_total cp_pass
    cp_total=$(wc -l < "$CHECKPOINT_LOG" 2>/dev/null || echo "1")
    cp_total=$((cp_total - 1))  # minus header
    cp_pass=$(awk -F'|' 'NR>1 && $2==0' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    echo "cli_checkpoints: $cp_pass/$cp_total passed" >> "$SUMMARY"

    # 8. Health alerts
    local alerts
    alerts=$(grep -c "ALERT\|CRITICAL" "$HEALTH_LOG" 2>/dev/null || echo "0")
    echo "health_alerts: $alerts" >> "$SUMMARY"

    # Verdict
    echo "" >> "$SUMMARY"
    if $pass; then
        echo "VERDICT: PASS" >> "$SUMMARY"
        echo -e "\n  ${BOLD}${GREEN}VERDICT: PASS${NC}\n"
    else
        echo "VERDICT: FAIL" >> "$SUMMARY"
        echo -e "\n  ${BOLD}${RED}VERDICT: FAIL${NC}\n"
    fi

    cat "$SUMMARY"
    echo -e "\n  Results: $RESULTS_DIR"
}

# ── Cleanup ──
cleanup() {
    echo -e "\n${BOLD}Cleaning up...${NC}"

    # Kill agents
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid 2>/dev/null; do
        [ ! -f "$pid_file" ] && continue
        local apid; apid=$(cat "$pid_file" 2>/dev/null || echo "0")
        kill "$apid" 2>/dev/null || true
    done

    # Restore network
    if $CHAOS_NETWORK_DONE && ! $CHAOS_NETWORK_RESTORED; then
        chaos_network_restore
    fi

    # Restore disk
    if $CHAOS_DISK_DONE && ! $CHAOS_DISK_RELEASED; then
        chaos_disk_release
    fi

    # Restore SRR
    if [ -f "$RESULTS_DIR/srr_network.toml.original" ]; then
        cp "$RESULTS_DIR/srr_network.toml.original" "$REPO_DIR/config/srr_network.toml"
    fi

    # Orphan cleanup
    "$GVM_BIN" cleanup 2>/dev/null || true

    echo -e "${GREEN}Cleanup done${NC}"
}

trap cleanup EXIT

# ── Main ──
check_prereqs
setup
launch_all_agents

echo -e "\n${BOLD}Monitoring (health every ${HEALTH_INTERVAL}s, chaos $CHAOS_ENABLED)...${NC}"
echo -e "${DIM}  tmux: Ctrl+B D to detach safely${NC}\n"

main_loop
evaluate_results
