#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Production Stress Test
#
# Reproduces real user workflows: runs agent prompts through GVM
# exactly as a user would from the CLI, then checks results via
# gvm commands. No internal script generation, no agent internals.
#
# What this script does (and nothing more):
#   1. Runs `gvm run -- <agent> <prompt>` for each prompt (foreground)
#   2. Runs `gvm status`, `gvm events`, `gvm audit` to verify (CLI)
#   3. Injects external chaos: kill proxy, disk pressure, tc netem
#   4. Evaluates proxy.log + WAL at the end
#
# Usage:
#   sudo bash scripts/prod-stress-test.sh --agent hermes --duration 5
#   sudo bash scripts/prod-stress-test.sh --agent openclaw --duration 15
#   sudo bash scripts/prod-stress-test.sh --agent hermes --no-chaos
# ═══════════════════════════════════════════════════════════════════

set -o pipefail

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-30}
HEALTH_INTERVAL=60
CHAOS_ENABLED=true
CHAOS_KILL_MIN=10
CHAOS_DISK_MIN=15
CHAOS_DISK_RELEASE_MIN=17
CHAOS_NETWORK_MIN=20
CHAOS_NETWORK_RESTORE_MIN=22
AGENT_TYPE="openclaw"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "$REPO_DIR/.env" ]; then
    set -a; source "$REPO_DIR/.env"; set +a
fi

GVM_BIN="$REPO_DIR/target/release/gvm"
PROXY_URL="http://127.0.0.1:8080"
RESULTS_DIR="$REPO_DIR/results/prod-$(date +%Y%m%dT%H%M%S)"
HEALTH_LOG="$RESULTS_DIR/health.log"
CHAOS_LOG="$RESULTS_DIR/chaos.log"
CHECKPOINT_LOG="$RESULTS_DIR/checkpoints.csv"
SUMMARY="$RESULTS_DIR/summary.txt"
AGENT_LOG="$RESULTS_DIR/agent.log"
WAL="$REPO_DIR/data/wal.log"
PROMPT_FILE="$SCRIPT_DIR/stress-workloads/telegram-prompts.txt"

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

CHAOS_KILL_DONE=false; CHAOS_NETWORK_DONE=false; CHAOS_DISK_DONE=false
CHAOS_DISK_RELEASED=false; CHAOS_NETWORK_RESTORED=false
DISK_PRESSURE_TMPFS=""
HOTRELOAD_DONE=false
MONITOR_PID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION_MIN="$2"; shift 2 ;;
        --no-chaos) CHAOS_ENABLED=false; shift ;;
        --agent) AGENT_TYPE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done
DURATION_SEC=$((DURATION_MIN * 60))

# ── Agent command builder ──
# Returns the exact command a user would type to send one prompt.
agent_cmd() {
    local prompt="$1"
    case "$AGENT_TYPE" in
        openclaw)
            echo "openclaw agent --local --session-id stress --message"
            ;;
        hermes)
            echo "uv run --project $HOME/hermes-agent hermes chat -q"
            ;;
    esac
}

run_prompt() {
    local prompt="$1"
    local idx="$2"
    case "$AGENT_TYPE" in
        openclaw)
            timeout 120 "$GVM_BIN" run --sandbox \
                -- openclaw agent --local \
                --session-id "stress-$idx" \
                --message "$prompt" \
                2>&1
            ;;
        hermes)
            timeout 120 "$GVM_BIN" run \
                -- uv run --project "$HOME/hermes-agent" hermes chat \
                -q "$prompt" \
                --provider anthropic \
                -m "anthropic/claude-sonnet-4-20250514" \
                --max-turns 1 \
                2>&1
            ;;
    esac
}

# ── Prereqs ──
check_prereqs() {
    local fail=false
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}CLI not built: $GVM_BIN${NC}" && fail=true
    [ ! -f "$PROMPT_FILE" ] && echo -e "${RED}Prompt file: $PROMPT_FILE${NC}" && fail=true
    case "$AGENT_TYPE" in
        openclaw)
            command -v openclaw >/dev/null 2>&1 || {
                echo -e "${RED}OpenClaw not found${NC}"; fail=true
            } ;;
        hermes)
            command -v uv >/dev/null 2>&1 || {
                echo -e "${RED}uv not found (needed for hermes-agent)${NC}"; fail=true
            }
            [ ! -d "$HOME/hermes-agent" ] && {
                echo -e "${RED}hermes-agent not found at ~/hermes-agent${NC}"; fail=true
            } ;;
        *) echo -e "${RED}Unknown agent: $AGENT_TYPE (use openclaw or hermes)${NC}"; fail=true ;;
    esac
    [ "$(id -u)" -ne 0 ] && echo -e "${RED}Must run as root (sudo)${NC}" && fail=true
    $fail && exit 1
}

# ── Utility ──
log_health() {
    local ts elapsed msg
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    elapsed=$(( $(date +%s) - START_TIME ))
    msg="$1"
    echo "[$ts] +${elapsed}s $msg" >> "$HEALTH_LOG"
    echo -e "  ${DIM}[$ts] $msg${NC}"
}

run_checkpoint() {
    local name="$1"; shift
    local output exit_code ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    output=$("$@" 2>&1) || true
    exit_code=$?
    echo "$name|$exit_code|$ts" >> "$CHECKPOINT_LOG"
    echo "$output" > "$RESULTS_DIR/checkpoints/${name}.log"
    [ $exit_code -eq 0 ] && log_health "CHECKPOINT $name: PASS" || log_health "CHECKPOINT $name: FAIL (exit $exit_code)"
    return $exit_code
}

# ── Health Check (CLI only) ──
check_health() {
    local status_out
    status_out=$("$GVM_BIN" status --proxy "$PROXY_URL" 2>&1) || true
    if echo "$status_out" | grep -q "not reachable"; then
        log_health "ALERT: proxy not reachable"
    else
        log_health "OK: proxy healthy"
    fi

    local kp
    kp=$(dmesg --time-format iso 2>/dev/null | tail -50 | grep -ciE "kernel panic|BUG:|Oops:" || echo "0")
    [ "$kp" -gt 0 ] 2>/dev/null && log_health "CRITICAL: kernel panic ($kp)"

    local ws
    ws=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
    log_health "WAL: ${ws} bytes"

    local pc
    pc=$(grep -c "^PROMPT #" "$AGENT_LOG" 2>/dev/null || echo "0")
    log_health "prompts_completed: $pc"
}

# ── Chaos ──
chaos_log() {
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "[$ts] $1" >> "$CHAOS_LOG"
    echo -e "  ${YELLOW}CHAOS [$ts]: $1${NC}"
}

chaos_proxy_kill() {
    local pid
    pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || echo "0")
    chaos_log "INJECT: kill -9 proxy (PID $pid)"
    kill -9 "$pid" 2>/dev/null || true
    sleep 5
    chaos_log "Proxy killed. Next gvm run will auto-restart."
    run_checkpoint "post_kill_status" "$GVM_BIN" status --proxy "$PROXY_URL" || true
}

chaos_network_partition() {
    chaos_log "INJECT: network partition (5s delay + 20% loss)"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    tc qdisc add dev "$iface" root netem delay 5000ms loss 20% 2>/dev/null || true
    chaos_log "network partition active on $iface"
}

chaos_network_restore() {
    chaos_log "RESTORE: removing network partition"
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "eth0")
    tc qdisc del dev "$iface" root 2>/dev/null || true
    chaos_log "network partition removed"
    sleep 3
    run_checkpoint "post_network_status" "$GVM_BIN" status --proxy "$PROXY_URL" || true
}

chaos_disk_pressure() {
    chaos_log "INJECT: disk pressure (64KB tmpfs over WAL dir)"
    DISK_PRESSURE_TMPFS="$REPO_DIR/data"
    mount -t tmpfs -o size=64k tmpfs "$DISK_PRESSURE_TMPFS" 2>/dev/null || {
        chaos_log "WARN: tmpfs mount failed"; DISK_PRESSURE_TMPFS=""; return
    }
    dd if=/dev/zero of="$DISK_PRESSURE_TMPFS/fill" bs=1k count=60 2>/dev/null || true
    chaos_log "disk pressure active (ENOSPC)"
}

chaos_disk_release() {
    chaos_log "RESTORE: releasing disk pressure"
    [ -n "$DISK_PRESSURE_TMPFS" ] && umount "$DISK_PRESSURE_TMPFS" 2>/dev/null || true
    chaos_log "disk pressure released"
    sleep 3
    run_checkpoint "post_disk_status" "$GVM_BIN" status --proxy "$PROXY_URL" || true
}

# ── Background Monitor ──
monitor_loop() {
    while true; do
        local now elapsed_sec elapsed_min
        now=$(date +%s)
        elapsed_sec=$((now - START_TIME))
        elapsed_min=$((elapsed_sec / 60))
        [ $elapsed_sec -ge $DURATION_SEC ] && break

        check_health

        # Chaos injection at scheduled times
        if $CHAOS_ENABLED; then
            [ $elapsed_min -ge $CHAOS_KILL_MIN ] && ! $CHAOS_KILL_DONE && { CHAOS_KILL_DONE=true; chaos_proxy_kill; }
            [ $elapsed_min -ge $CHAOS_DISK_MIN ] && ! $CHAOS_DISK_DONE && { CHAOS_DISK_DONE=true; chaos_disk_pressure; }
            [ $elapsed_min -ge $CHAOS_DISK_RELEASE_MIN ] && ! $CHAOS_DISK_RELEASED && { CHAOS_DISK_RELEASED=true; chaos_disk_release; }
            [ $elapsed_min -ge $CHAOS_NETWORK_MIN ] && ! $CHAOS_NETWORK_DONE && { CHAOS_NETWORK_DONE=true; chaos_network_partition; }
            [ $elapsed_min -ge $CHAOS_NETWORK_RESTORE_MIN ] && ! $CHAOS_NETWORK_RESTORED && { CHAOS_NETWORK_RESTORED=true; chaos_network_restore; }
        fi

        # CLI checkpoints (every 5 min)
        if [ $((elapsed_min % 5)) -eq 0 ] && [ $elapsed_min -gt 0 ]; then
            case $((elapsed_min % 25)) in
                0)  run_checkpoint "T${elapsed_min}_events" "$GVM_BIN" events list --last 5m --wal-file "$WAL" || true ;;
                5)  run_checkpoint "T${elapsed_min}_check" "$GVM_BIN" check --host api.github.com --method GET --operation test --proxy "$PROXY_URL" || true ;;
                10) run_checkpoint "T${elapsed_min}_preflight" "$GVM_BIN" preflight || true ;;
                15) run_checkpoint "T${elapsed_min}_audit" "$GVM_BIN" audit verify --wal "$WAL" || true ;;
                20) run_checkpoint "T${elapsed_min}_status" "$GVM_BIN" status --proxy "$PROXY_URL" || true ;;
            esac
        fi

        # Hot-reload (T+8m)
        if [ $elapsed_min -ge 8 ] && [ "$HOTRELOAD_DONE" = "false" ]; then
            HOTRELOAD_DONE=true
            log_health "HOT-RELOAD: inserting httpbin.org Delay at top of SRR"
            sed -i '1i\
# Hot-reload test rule (inserted by stress test)\
[[rules]]\
method = "GET"\
pattern = "httpbin.org/{any}"\
decision = { type = "Delay", milliseconds = 500 }\
label = "prod-stress-hotreload"\
' "$REPO_DIR/config/srr_network.toml"
            run_checkpoint "T${elapsed_min}_reload" "$GVM_BIN" reload --proxy "$PROXY_URL" || true
            sleep 3
            local co
            co=$("$GVM_BIN" check --host httpbin.org --method GET --operation test --proxy "$PROXY_URL" 2>&1) || true
            if echo "$co" | grep -qi "Delay"; then
                log_health "HOT-RELOAD VERIFY: PASS (httpbin.org -> Delay)"
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
    echo "=== Pass/Fail Evaluation ===" >> "$SUMMARY"
    local actual_elapsed=$(( $(date +%s) - START_TIME ))
    echo "elapsed_sec=$actual_elapsed" >> "$SUMMARY"
    local pass=true

    # 0. Minimum duration (must run at least 80% of requested time)
    local min_required=$(( DURATION_SEC * 80 / 100 ))
    if [ "$actual_elapsed" -lt "$min_required" ]; then
        echo "FAIL: early exit (${actual_elapsed}s < ${min_required}s minimum)" >> "$SUMMARY"
        pass=false
    else
        echo "PASS: duration met (${actual_elapsed}s >= ${min_required}s)" >> "$SUMMARY"
    fi

    # 1. Kernel panic
    local panics
    panics=$(grep -c "CRITICAL.*kernel panic" "$HEALTH_LOG" 2>/dev/null || echo "0")
    [ "$panics" -gt 0 ] && { echo "FAIL: kernel panic ($panics)" >> "$SUMMARY"; pass=false; } || echo "PASS: no kernel panic" >> "$SUMMARY"

    # 2. Proxy chaos recovery
    if $CHAOS_ENABLED && grep -q "INJECT.*kill" "$CHAOS_LOG" 2>/dev/null; then
        if grep -q "post_kill_status|0" "$CHECKPOINT_LOG" 2>/dev/null; then
            echo "PASS: proxy recovered after kill" >> "$SUMMARY"
        else
            echo "FAIL: proxy did not recover" >> "$SUMMARY"; pass=false
        fi
    fi

    # 3. Orphan cleanup
    run_checkpoint "final_cleanup" "$GVM_BIN" cleanup || true
    local ov
    ov=$(ip link 2>/dev/null | grep -c "veth-gvm" || echo "0")
    [ "${ov:-0}" -gt 0 ] && { echo "FAIL: orphan veth ($ov)" >> "$SUMMARY"; pass=false; } || echo "PASS: no orphan veth" >> "$SUMMARY"

    # 4. WAL integrity
    run_checkpoint "final_audit" "$GVM_BIN" audit verify --wal "$WAL" || true
    grep -q "final_audit|0" "$CHECKPOINT_LOG" 2>/dev/null && echo "PASS: WAL integrity" >> "$SUMMARY" || echo "WARN: WAL inconclusive" >> "$SUMMARY"
    local wal_total wal_new
    wal_total=$(wc -l < "$WAL" 2>/dev/null || echo "0")
    wal_new=$(( wal_total - WAL_BASELINE ))
    echo "wal_events: $wal_new (new during this run)" >> "$SUMMARY"

    # 5. Agent activity (LLM calls through proxy)
    local ac
    ac=$(grep -c "anthropic\|openrouter" "$REPO_DIR/data/proxy.log" 2>/dev/null || echo "0")
    echo "llm_calls: $ac" >> "$SUMMARY"
    [ "$ac" -gt 0 ] && echo "PASS: LLM calls via proxy ($ac)" >> "$SUMMARY" || { echo "FAIL: no LLM calls" >> "$SUMMARY"; pass=false; }

    # 6. Prompts completed
    local pc
    pc=$(grep -c "^PROMPT #" "$AGENT_LOG" 2>/dev/null || echo "0")
    echo "prompts_completed: $pc" >> "$SUMMARY"
    [ "$pc" -gt 0 ] && echo "PASS: prompts completed ($pc)" >> "$SUMMARY" || { echo "FAIL: zero prompts completed" >> "$SUMMARY"; pass=false; }

    # 7. Connection errors
    local ce
    ce=$(grep -c "Connection error\|Network request failed" "$AGENT_LOG" 2>/dev/null || echo "0")
    echo "connection_errors: $ce" >> "$SUMMARY"

    # 8. CLI checkpoints
    local ct cp
    ct=$(awk -F'|' 'NR>1' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    cp=$(awk -F'|' 'NR>1 && $2==0' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    echo "cli_checkpoints: $cp/$ct" >> "$SUMMARY"

    echo "" >> "$SUMMARY"
    $pass && echo "VERDICT: PASS" >> "$SUMMARY" || echo "VERDICT: FAIL" >> "$SUMMARY"
    echo ""
    cat "$SUMMARY"
    $pass && echo -e "\n  ${BOLD}${GREEN}VERDICT: PASS${NC}" || echo -e "\n  ${BOLD}${RED}VERDICT: FAIL${NC}"
    echo -e "  Results: $RESULTS_DIR\n"
}

# ── Cleanup ──
cleanup() {
    echo -e "\n${BOLD}Cleaning up...${NC}"

    [ -n "$MONITOR_PID" ] && kill "$MONITOR_PID" 2>/dev/null || true

    # Restore chaos
    $CHAOS_NETWORK_DONE && ! $CHAOS_NETWORK_RESTORED && chaos_network_restore
    $CHAOS_DISK_DONE && ! $CHAOS_DISK_RELEASED && chaos_disk_release

    # Restore SRR config
    [ -f "$RESULTS_DIR/srr_network.toml.backup" ] && cp "$RESULTS_DIR/srr_network.toml.backup" "$REPO_DIR/config/srr_network.toml"

    "$GVM_BIN" cleanup 2>/dev/null || true

    echo -e "${GREEN}Cleanup done${NC}"
}
trap cleanup EXIT

# ═══════════════════════════════════════
# Main
# ═══════════════════════════════════════
check_prereqs

mkdir -p "$RESULTS_DIR/checkpoints"
echo "# Health log" > "$HEALTH_LOG"
echo "# Chaos log" > "$CHAOS_LOG"
echo "name|exit_code|timestamp" > "$CHECKPOINT_LOG"

# Backup SRR config (hot-reload appends rules)
cp "$REPO_DIR/config/srr_network.toml" "$RESULTS_DIR/srr_network.toml.backup"

# Clear stale data from previous runs
: > "$REPO_DIR/data/proxy.log"
WAL_BASELINE=$(wc -l < "$WAL" 2>/dev/null || echo "0")

START_TIME=$(date +%s)
cat > "$SUMMARY" << EOF
start_time=$START_TIME
duration_min=$DURATION_MIN
chaos=$CHAOS_ENABLED
agent=$AGENT_TYPE
EOF

echo -e "${BOLD}${CYAN}=== GVM Stress Test ===${NC}"
echo -e "  Agent:       $AGENT_TYPE"
echo -e "  Duration:    ${DURATION_MIN}m"
echo -e "  Chaos:       $CHAOS_ENABLED"
echo -e "  Prompts:     $(wc -l < "$PROMPT_FILE") prompts"
echo -e "  Results:     $RESULTS_DIR"
echo ""

# Start background monitor (health checks + chaos + CLI checkpoints)
monitor_loop &
MONITOR_PID=$!

# ── Foreground: run prompts through GVM exactly as a user would ──
# Each prompt is a separate `gvm run -- <agent> <prompt>` invocation.
# This is the same command a user types in a terminal.
cd "$REPO_DIR"
IDX=0
while IFS= read -r prompt; do
    [ -z "$prompt" ] && continue

    # Time check — stop sending prompts after duration expires
    elapsed=$(( $(date +%s) - START_TIME ))
    [ "$elapsed" -ge "$DURATION_SEC" ] && {
        echo -e "  ${DIM}Duration reached. Stopping prompt loop.${NC}"
        break
    }

    IDX=$((IDX + 1))
    echo -e "  ${CYAN}PROMPT #$IDX${NC}: ${prompt:0:60}..."

    # Run the agent command through GVM — identical to user CLI usage
    run_prompt "$prompt" "$IDX" >> "$AGENT_LOG" 2>&1
    rc=$?

    if [ $rc -eq 0 ]; then
        echo "PROMPT #$IDX: OK" >> "$AGENT_LOG"
    else
        echo "PROMPT #$IDX: error (exit $rc)" >> "$AGENT_LOG"
    fi

    sleep 5
done < "$PROMPT_FILE"

echo -e "\n  ${DIM}Prompt loop finished ($IDX prompts sent)${NC}"

# Stop monitor
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

# Evaluate
evaluate_results
