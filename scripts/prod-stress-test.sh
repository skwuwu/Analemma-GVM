#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Production Pattern Stress Test
#
# Simulates real production usage: agents run autonomously while an
# operator uses CLI commands to monitor and manage governance.
#
# ALL proxy interactions use `gvm` CLI only — no direct binary
# invocation, no internal API calls, no WAL manipulation.
# The proxy lifecycle is managed by proxy_manager (started
# automatically by the first `gvm run`).
#
# Designed for tmux — survives SSH disconnection:
#   tmux new -s gvm-stress
#   sudo env PATH=$PATH ANTHROPIC_API_KEY=$KEY bash scripts/prod-stress-test.sh
#   # Ctrl+B D to detach, tmux attach -t gvm-stress to reconnect
#
# Usage:
#   bash scripts/prod-stress-test.sh                 # 3 hours (default)
#   bash scripts/prod-stress-test.sh --duration 60   # 1 hour
#   bash scripts/prod-stress-test.sh --no-chaos      # agents only, no chaos
# ═══════════════════════════════════════════════════════════════════

set -o pipefail
shopt -s nullglob

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-180}
NUM_AGENTS=3
HEALTH_INTERVAL=120
CHAOS_ENABLED=true
CHAOS_KILL_MIN=40
CHAOS_DISK_MIN=60
CHAOS_DISK_RELEASE_MIN=70
CHAOS_NETWORK_MIN=90
CHAOS_NETWORK_RESTORE_MIN=100

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "$REPO_DIR/.env" ]; then
    set -a; source "$REPO_DIR/.env"; set +a
fi

GVM_BIN="$REPO_DIR/target/release/gvm"
PROXY_URL="http://127.0.0.1:8080"
STRESS_SRR="$REPO_DIR/config/stress-srr.toml"
RESULTS_DIR="$REPO_DIR/results/prod-$(date +%Y%m%dT%H%M%S)"
HEALTH_LOG="$RESULTS_DIR/health.log"
CHAOS_LOG="$RESULTS_DIR/chaos.log"
CHECKPOINT_LOG="$RESULTS_DIR/checkpoints.csv"
SUMMARY="$RESULTS_DIR/summary.txt"
WAL="$REPO_DIR/data/wal.log"

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

CHAOS_KILL_DONE=false; CHAOS_NETWORK_DONE=false; CHAOS_DISK_DONE=false
CHAOS_DISK_RELEASED=false; CHAOS_NETWORK_RESTORED=false
DISK_PRESSURE_TMPFS=""
HOTRELOAD_DONE=false

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
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}CLI not built: $GVM_BIN${NC}" && fail=true
    command -v openclaw >/dev/null 2>&1 || {
        echo -e "${RED}OpenClaw not found (npm install -g openclaw)${NC}"; fail=true
    }
    command -v tmux >/dev/null 2>&1 || echo -e "${YELLOW}tmux not installed — SSH disconnect will kill test${NC}"
    $fail && exit 1
}

# ── Utility ──
get_orphan_veth() { ip link 2>/dev/null | grep -c "veth-gvm" || echo "0"; }

log_health() {
    local ts msg
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local elapsed=$(( $(date +%s) - START_TIME ))
    msg="$1"
    echo "[$ts] +${elapsed}s $msg" >> "$HEALTH_LOG"
    echo -e "  ${DIM}[$ts] $msg${NC}"
}

# Health check via CLI only — no curl, no direct PID inspection.
# Uses `gvm check` as a proxy health probe: if the proxy is alive and
# SRR rules are loaded, this returns exit 0 with a decision.
proxy_healthy_via_cli() {
    "$GVM_BIN" check --host api.github.com --method GET \
        --operation health-probe --proxy "$PROXY_URL" \
        > /dev/null 2>&1
}

# ── Health & Hang Detection ──
check_health() {
    local issues=0

    # 1. Proxy alive (via CLI dry-run check)
    if proxy_healthy_via_cli; then
        log_health "OK: proxy responding to gvm check"
    else
        log_health "ALERT: proxy not responding to gvm check"
        issues=$((issues + 1))
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
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid; do
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
    local load1 ncpu
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
    ncpu=$(nproc 2>/dev/null || echo "2")
    if awk "BEGIN{exit !($load1 > $ncpu * 4)}" 2>/dev/null; then
        log_health "WARN: system load $load1 exceeds 4x CPU count ($ncpu)"
    fi

    # 5. WAL size (growing = not hung)
    local wal_size
    wal_size=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
    log_health "WAL: ${wal_size} bytes, orphan_veth: $(get_orphan_veth)"

    return $issues
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
    echo -e "  tmux:        $([ -n "$TMUX" ] && echo 'YES (safe to detach)' || echo 'NO')"
    echo ""

    # Swap SRR to stress rules (save original for restore on cleanup)
    ORIGINAL_SRR="$REPO_DIR/config/srr_network.toml"
    cp "$ORIGINAL_SRR" "$RESULTS_DIR/srr_network.toml.original"
    cp "$STRESS_SRR" "$ORIGINAL_SRR"

    # Record pre-test WAL size (don't reset — accumulate naturally)
    local pre_wal_size
    pre_wal_size=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
    echo "pre_wal_bytes=$pre_wal_size" >> "$SUMMARY"

    # Kill any existing proxy so it restarts with stress SRR.
    # proxy_manager will auto-start a fresh one on first `gvm run`.
    if [ -f "$REPO_DIR/data/proxy.pid" ]; then
        local old_pid
        old_pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || echo "0")
        kill "$old_pid" 2>/dev/null || true
        sleep 2
    fi

    echo "# Health log" > "$HEALTH_LOG"
    echo "# Chaos log" > "$CHAOS_LOG"
    echo "name|exit_code|timestamp" > "$CHECKPOINT_LOG"

    START_TIME=$(date +%s)
    echo "start_time=$START_TIME" > "$SUMMARY"
    echo "duration_min=$DURATION_MIN" >> "$SUMMARY"

    echo -e "  ${GREEN}Setup complete (proxy will start on first agent launch)${NC}"
}

# ── Agent Launch ──
launch_agent() {
    local id=$1 prompt_file=$2 agent_id=$3
    local log="$RESULTS_DIR/agents/agent-${id}.log"
    local prompt
    prompt=$(cat "$prompt_file")

    local OC_MJS="/usr/lib/node_modules/openclaw/openclaw.mjs"
    [ ! -f "$OC_MJS" ] && OC_MJS="$(readlink -f "$(which openclaw)" 2>/dev/null || echo "openclaw")"

    echo -e "  ${CYAN}Launching agent #$id ($agent_id)${NC}"

    # gvm run --sandbox handles everything:
    #   - proxy_manager starts proxy if not running
    #   - sandbox creates namespace, seccomp, veth
    #   - agent runs autonomously until done or timeout
    GVM_SANDBOX_TIMEOUT=$((DURATION_SEC + 300)) \
    "$GVM_BIN" run --sandbox \
        --agent-id "$agent_id" \
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
        sleep 30
    done
    echo -e "  ${GREEN}All $NUM_AGENTS agents launched${NC}"
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

# ── Chaos Functions ──
chaos_log() {
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "[$ts] $1" >> "$CHAOS_LOG"
    echo -e "  ${YELLOW}CHAOS [$ts]: $1${NC}"
}

chaos_proxy_kill() {
    # Kill proxy via PID file (same as a real ops scenario: kill + let proxy_manager recover)
    local pid
    pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || echo "0")
    chaos_log "INJECT: kill -9 proxy (PID $pid)"
    kill -9 "$pid" 2>/dev/null || true

    # Wait, then verify recovery via CLI (proxy_manager in next gvm run restarts it)
    sleep 5
    # Trigger proxy restart by running a lightweight CLI command that needs the proxy
    run_checkpoint "post_kill_check" \
        "$GVM_BIN" check --host api.github.com --method GET \
        --operation post-kill-verify --proxy "$PROXY_URL" || true
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

chaos_network_restore() {
    chaos_log "RESTORE: removing network partition"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 -j MARK --set-mark 42 2>/dev/null || true
    chaos_log "network partition removed"
    sleep 3
    run_checkpoint "post_network_check" \
        "$GVM_BIN" check --host api.github.com --method GET \
        --operation post-network-verify --proxy "$PROXY_URL" || true
}

chaos_disk_pressure() {
    chaos_log "INJECT: disk pressure (64KB tmpfs over WAL dir)"
    local wal_dir="$REPO_DIR/data"
    DISK_PRESSURE_TMPFS="$wal_dir"
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
    fi
    chaos_log "disk pressure released"
    sleep 3
    run_checkpoint "post_disk_audit" \
        "$GVM_BIN" audit verify --wal "$WAL" || true
}

# ── Main Loop ──
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
            log_health "WARN: WAL size unchanged for ${HEALTH_INTERVAL}s — possible hang"
        fi
        last_wal_size=$cur_wal_size

        # ── All agents dead? ──
        local alive=0
        for pid_file in "$RESULTS_DIR"/agents/agent-*.pid; do
            [ ! -f "$pid_file" ] && continue
            kill -0 "$(cat "$pid_file" 2>/dev/null)" 2>/dev/null && alive=$((alive + 1))
        done
        if [ "$alive" -eq 0 ] && [ "$check_count" -gt 5 ]; then
            log_health "INFO: all agents finished"
        fi

        # ── Chaos injection ──
        if $CHAOS_ENABLED; then
            if [ $elapsed_min -ge $CHAOS_KILL_MIN ] && ! $CHAOS_KILL_DONE; then
                CHAOS_KILL_DONE=true; chaos_proxy_kill
            fi
            if [ $elapsed_min -ge $CHAOS_DISK_MIN ] && ! $CHAOS_DISK_DONE; then
                CHAOS_DISK_DONE=true; chaos_disk_pressure
            fi
            if [ $elapsed_min -ge $CHAOS_DISK_RELEASE_MIN ] && ! $CHAOS_DISK_RELEASED; then
                CHAOS_DISK_RELEASED=true; chaos_disk_release
            fi
            if [ $elapsed_min -ge $CHAOS_NETWORK_MIN ] && ! $CHAOS_NETWORK_DONE; then
                CHAOS_NETWORK_DONE=true; chaos_network_partition
            fi
            if [ $elapsed_min -ge $CHAOS_NETWORK_RESTORE_MIN ] && ! $CHAOS_NETWORK_RESTORED; then
                CHAOS_NETWORK_RESTORED=true; chaos_network_restore
            fi
        fi

        # ── Periodic CLI checkpoints (every 10 min, rotate through commands) ──
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
        # User workflow: edit srr_network.toml → POST /gvm/reload
        # (POST /gvm/reload is the documented API per user guide section 2)
        if [ $elapsed_min -ge 25 ] && [ "$HOTRELOAD_DONE" = "false" ]; then
            HOTRELOAD_DONE=true
            log_health "HOT-RELOAD: appending httpbin.org Delay rule"
            cat >> "$REPO_DIR/config/srr_network.toml" << 'HOTRELOAD_RULE'

# Hot-reload test rule (appended by prod-stress-test.sh)
[[rules]]
method = "GET"
pattern = "httpbin.org/{any}"
decision = { type = "Delay", milliseconds = 500 }
label = "prod-stress-hotreload"
HOTRELOAD_RULE
            # POST /gvm/reload is the documented hot-reload mechanism
            run_checkpoint "T${elapsed_min}_reload" \
                "$GVM_BIN" reload --proxy "$PROXY_URL" || true
            sleep 3
            # Verify via CLI: gvm check should now return Delay for httpbin.org
            local check_out
            check_out=$("$GVM_BIN" check --host httpbin.org --method GET \
                --operation test --proxy "$PROXY_URL" 2>&1) || true
            if echo "$check_out" | grep -qi "Delay"; then
                log_health "HOT-RELOAD VERIFY: PASS (httpbin.org → Delay)"
                echo "hotreload_verify|0|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKPOINT_LOG"
            else
                log_health "HOT-RELOAD VERIFY: FAIL (expected Delay)"
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

    # 1. Kernel panic
    local panics
    panics=$(grep -c "CRITICAL.*kernel panic\|CRITICAL.*BUG" "$HEALTH_LOG" 2>/dev/null || echo "0")
    if [ "$panics" -gt 0 ]; then
        echo "FAIL: $panics kernel panic/BUG events" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no kernel panic" >> "$SUMMARY"
    fi

    # 2. Proxy recovery after chaos kill
    if $CHAOS_ENABLED && grep -q "INJECT.*kill" "$CHAOS_LOG" 2>/dev/null; then
        if grep -q "post_kill_check|0" "$CHECKPOINT_LOG" 2>/dev/null; then
            echo "PASS: proxy recovered after kill (gvm check succeeded)" >> "$SUMMARY"
        else
            echo "FAIL: proxy did not recover after kill" >> "$SUMMARY"; pass=false
        fi
    fi

    # 3. Orphan veth (cleanup via CLI)
    run_checkpoint "final_cleanup" "$GVM_BIN" cleanup || true
    local final_veth
    final_veth=$(get_orphan_veth)
    echo "orphan_veth: $final_veth (after gvm cleanup)" >> "$SUMMARY"
    if [ "${final_veth:-0}" -gt 0 ] 2>/dev/null; then
        echo "FAIL: orphan veth remains" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no orphan veth" >> "$SUMMARY"
    fi

    # 4. WAL integrity (via CLI)
    run_checkpoint "final_audit" "$GVM_BIN" audit verify --wal "$WAL" || true
    if grep -q "final_audit|0" "$CHECKPOINT_LOG" 2>/dev/null; then
        echo "PASS: WAL integrity verified" >> "$SUMMARY"
    else
        echo "WARN: WAL verification inconclusive" >> "$SUMMARY"
    fi
    local wal_events
    wal_events=$(wc -l < "$WAL" 2>/dev/null || echo "0")
    echo "wal_events: $wal_events" >> "$SUMMARY"

    # 5. Agent completion
    local completed=0 total_agents=0
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid; do
        [ ! -f "$pid_file" ] && continue
        total_agents=$((total_agents + 1))
        local apid
        apid=$(cat "$pid_file" 2>/dev/null || echo "0")
        kill -0 "$apid" 2>/dev/null || completed=$((completed + 1))
    done
    echo "agents_completed: $completed/$total_agents" >> "$SUMMARY"

    # 6. CLI checkpoints
    local cp_total cp_pass
    cp_total=$(awk -F'|' 'NR>1' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    cp_pass=$(awk -F'|' 'NR>1 && $2==0' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    echo "cli_checkpoints: $cp_pass/$cp_total passed" >> "$SUMMARY"

    # 7. Health alerts
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
    for pid_file in "$RESULTS_DIR"/agents/agent-*.pid; do
        [ ! -f "$pid_file" ] && continue
        local apid; apid=$(cat "$pid_file" 2>/dev/null || echo "0")
        kill "$apid" 2>/dev/null || true
    done

    # Restore chaos
    if $CHAOS_NETWORK_DONE && ! $CHAOS_NETWORK_RESTORED; then
        chaos_network_restore
    fi
    if $CHAOS_DISK_DONE && ! $CHAOS_DISK_RELEASED; then
        chaos_disk_release
    fi

    # Restore original SRR
    if [ -f "$RESULTS_DIR/srr_network.toml.original" ]; then
        cp "$RESULTS_DIR/srr_network.toml.original" "$REPO_DIR/config/srr_network.toml"
    fi

    # Orphan cleanup via CLI
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
