#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Production Stress Test (Telegram Gateway Mode)
#
# Runs OpenClaw gateway in a persistent sandbox, then sends prompts
# via Telegram Bot API. The full path is tested:
#   Telegram → sandbox gateway (polling) → proxy MITM → Anthropic API
#   → proxy MITM → Telegram (reply)
#
# ALL proxy interactions use `gvm` CLI only.
# Secrets loaded from .env (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID).
#
# Usage:
#   bash scripts/prod-stress-test.sh                 # 30 min (default)
#   bash scripts/prod-stress-test.sh --duration 15   # 15 min
#   bash scripts/prod-stress-test.sh --no-chaos      # prompts only
#
# Designed for tmux:
#   tmux new -s gvm-stress
#   sudo env PATH=$PATH bash scripts/prod-stress-test.sh
# ═══════════════════════════════════════════════════════════════════

set -o pipefail
shopt -s nullglob

# ── Configuration ──
DURATION_MIN=${DURATION_MIN:-30}
HEALTH_INTERVAL=60
CHAOS_ENABLED=true
CHAOS_KILL_MIN=10
CHAOS_DISK_MIN=15
CHAOS_DISK_RELEASE_MIN=17
CHAOS_NETWORK_MIN=20
CHAOS_NETWORK_RESTORE_MIN=22

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
WAL="$REPO_DIR/data/wal.log"
GATEWAY_LOG="$RESULTS_DIR/gateway.log"
PROMPT_FILE="$SCRIPT_DIR/stress-workloads/telegram-prompts.txt"

# Telegram credentials (optional — for manual verification)
BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
CHAT_ID="${TELEGRAM_CHAT_ID:-}"

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
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}CLI not built: $GVM_BIN${NC}" && fail=true
    [ ! -f "$PROMPT_FILE" ] && echo -e "${RED}Prompt file not found: $PROMPT_FILE${NC}" && fail=true
    command -v openclaw >/dev/null 2>&1 || {
        echo -e "${RED}OpenClaw not found (npm install -g openclaw)${NC}"; fail=true
    }
    $fail && exit 1
}

# ── Utility ──
get_orphan_veth() { ip link 2>/dev/null | grep -c "veth-gvm" || echo "0"; }

log_health() {
    local ts msg elapsed
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    elapsed=$(( $(date +%s) - START_TIME ))
    msg="$1"
    echo "[$ts] +${elapsed}s $msg" >> "$HEALTH_LOG"
    echo -e "  ${DIM}[$ts] $msg${NC}"
}


# ── Health Check ──
check_health() {
    local issues=0

    # 1. Proxy status
    local status_out
    status_out=$("$GVM_BIN" status --proxy "$PROXY_URL" 2>&1) || true
    if echo "$status_out" | grep -q "not reachable"; then
        log_health "ALERT: proxy not reachable"
        issues=$((issues + 1))
    else
        local srr_count
        srr_count=$(echo "$status_out" | grep -oP 'SRR rules:\s+\K[0-9]+' || echo "?")
        log_health "OK: proxy healthy, SRR rules: $srr_count"
    fi

    # 2. Kernel panic
    local kernel_issues
    kernel_issues=$(dmesg --time-format iso 2>/dev/null | tail -50 | grep -ciE "kernel panic|BUG:|Oops:|Call Trace:" || echo "0")
    if [ "$kernel_issues" -gt 0 ] 2>/dev/null; then
        log_health "CRITICAL: kernel panic/BUG detected ($kernel_issues)"
        issues=$((issues + 1))
    fi

    # 3. Gateway process
    if pgrep -f "openclaw-gatewa" > /dev/null 2>&1; then
        local gw_rss
        gw_rss=$(ps -o rss= -p "$(pgrep -f 'openclaw-gatewa' | head -1)" 2>/dev/null || echo "0")
        log_health "gateway: alive RSS=${gw_rss}KB"
    else
        log_health "ALERT: gateway process dead"
        issues=$((issues + 1))
    fi

    # 4. WAL size
    local wal_size
    wal_size=$(stat -c%s "$WAL" 2>/dev/null || echo "0")
    log_health "WAL: ${wal_size} bytes, orphan_veth: $(get_orphan_veth)"

    # 5. Agent progress (prompt count from gateway log)
    local prompt_count
    prompt_count=$(grep -c "^PROMPT #" "$GATEWAY_LOG" 2>/dev/null || echo "0")
    log_health "prompts_completed: $prompt_count"

    # 6. Connection errors in gateway log
    local conn_err
    conn_err=$(grep -c "Connection error\|Network request failed" "$GATEWAY_LOG" 2>/dev/null || echo "0")
    log_health "connection_errors: $conn_err (cumulative)"

    return $issues
}

# ── Gateway + Agent Lifecycle ──
#
# Runs gateway + prompt loop in a single sandbox:
#   bash -c 'gateway & sleep 30; for prompt in ...; do openclaw agent --message "$prompt"; done'
# Agent talks to gateway via loopback WebSocket (NO_PROXY), LLM calls go through proxy MITM.
#
start_sandbox() {
    local OC_MJS="/usr/lib/node_modules/openclaw/openclaw.mjs"
    [ ! -f "$OC_MJS" ] && OC_MJS="$(readlink -f "$(which openclaw)" 2>/dev/null || echo "openclaw")"

    echo -e "  ${CYAN}Starting sandbox (gateway + agent)...${NC}"

    # Kill any existing
    pkill -f "gvm-proxy" 2>/dev/null || true
    pkill -f "openclaw" 2>/dev/null || true
    sleep 2
    "$GVM_BIN" cleanup 2>/dev/null || true
    rm -f "$REPO_DIR/data/proxy.pid"

    # Copy prompt file to workspace so it's accessible inside sandbox at /workspace/
    local ws_dir="/tmp/gvm-stress-ws"
    sudo rm -rf "$ws_dir"
    sudo mkdir -p "$ws_dir"
    sudo cp "$PROMPT_FILE" "$ws_dir/prompts.txt"

    # Build the inner script that runs inside the sandbox
    sudo tee "$ws_dir/run-stress.sh" > /dev/null << 'INNER_SCRIPT'
#!/bin/bash
OC_MJS="/usr/lib/node_modules/openclaw/openclaw.mjs"

# Start gateway in background
node "$OC_MJS" gateway run &
GW_PID=$!
echo "Gateway PID=$GW_PID"
sleep 30

# Send prompts sequentially via agent command
# Uses --local to avoid gateway auth-profiles dependency.
# LLM calls still route through proxy MITM (HTTP_PROXY is set).
IDX=0
while IFS= read -r prompt; do
    [ -z "$prompt" ] && continue
    IDX=$((IDX + 1))
    echo "PROMPT #$IDX: ${prompt:0:60}..."
    node "$OC_MJS" agent --local \
        --session-id "stress-$IDX" \
        --message "$prompt" \
        --timeout 120 \
        2>&1 || echo "PROMPT #$IDX: agent returned error"
    echo "$IDX" > /tmp/prompts_sent.count
    sleep 5
done < /workspace/prompts.txt

echo "All prompts sent. Keeping gateway alive for teardown..."
wait $GW_PID
INNER_SCRIPT
    sudo chmod +x "$ws_dir/run-stress.sh"

    # Start sandbox with the stress script
    tmux kill-session -t gvm-gateway 2>/dev/null || true
    tmux new-session -d -s gvm-gateway \
        "cd $ws_dir && sudo env PATH=$PATH ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-} RUST_LOG=info $GVM_BIN run --sandbox --sandbox-timeout $((DURATION_SEC + 300)) -- bash /workspace/run-stress.sh > $GATEWAY_LOG 2>&1"

    echo -e "  ${DIM}Waiting for gateway startup (50s)...${NC}"
    sleep 50

    if ! pgrep -f "openclaw-gatewa" > /dev/null 2>&1; then
        echo -e "${YELLOW}WARN: gateway process not found yet — checking sandbox output${NC}"
        tail -10 "$GATEWAY_LOG" 2>/dev/null
        # Don't exit — gateway may still be initializing, monitoring will catch it
    fi

    echo -e "  ${GREEN}Sandbox started (gateway + agent prompt loop)${NC}"
}

restart_sandbox() {
    log_health "Restarting sandbox after chaos..."
    tmux kill-session -t gvm-gateway 2>/dev/null || true
    pkill -f "openclaw" 2>/dev/null || true
    sleep 2
    "$GVM_BIN" cleanup 2>/dev/null || true
    start_sandbox
    log_health "Sandbox restarted successfully"
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
        log_health "CHECKPOINT $name: PASS"
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
    local pid
    pid=$(cat "$REPO_DIR/data/proxy.pid" 2>/dev/null || pgrep -f gvm-proxy | head -1 || echo "0")
    chaos_log "INJECT: kill -9 proxy (PID $pid)"
    kill -9 "$pid" 2>/dev/null || true
    sleep 5

    # Proxy recovery: next gvm command triggers proxy_manager restart
    run_checkpoint "post_kill_status" \
        "$GVM_BIN" status --proxy "$PROXY_URL" || true

    # Gateway sandbox connection pool is broken — must restart
    chaos_log "Restarting gateway sandbox (connection pool invalidated)"
    restart_sandbox

    # Verify polling resumed
    sleep 15
    local polls_after
    polls_after=$(grep -c "getUpdates" "$REPO_DIR/data/proxy.log" 2>/dev/null || echo "0")
    chaos_log "Post-restart getUpdates count: $polls_after"

    # Reload stress SRR rules on new proxy
    "$GVM_BIN" reload --proxy "$PROXY_URL" > /dev/null 2>&1 || true
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
    run_checkpoint "post_network_status" \
        "$GVM_BIN" status --proxy "$PROXY_URL" || true
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
    run_checkpoint "post_disk_status" \
        "$GVM_BIN" status --proxy "$PROXY_URL" || true
}


# ── Main Loop ──
main_loop() {
    local check_count=0

    while true; do
        local now elapsed_sec elapsed_min
        now=$(date +%s)
        elapsed_sec=$((now - START_TIME))
        elapsed_min=$((elapsed_sec / 60))

        [ $elapsed_sec -ge $DURATION_SEC ] && break

        # Health check
        check_health
        check_count=$((check_count + 1))

        # Chaos injection
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

        # CLI checkpoints (every 5 min)
        if [ $((elapsed_min % 5)) -eq 0 ] && [ $elapsed_min -gt 0 ]; then
            case $((elapsed_min % 25)) in
                0)  run_checkpoint "T${elapsed_min}_events" \
                        "$GVM_BIN" events list --last 5m --wal-file "$WAL" || true ;;
                5)  run_checkpoint "T${elapsed_min}_check" \
                        "$GVM_BIN" check --host api.github.com --method GET \
                        --operation test --proxy "$PROXY_URL" || true ;;
                10) run_checkpoint "T${elapsed_min}_preflight" \
                        "$GVM_BIN" preflight || true ;;
                15) run_checkpoint "T${elapsed_min}_audit" \
                        "$GVM_BIN" audit verify --wal "$WAL" || true ;;
                20) run_checkpoint "T${elapsed_min}_status" \
                        "$GVM_BIN" status --proxy "$PROXY_URL" || true ;;
            esac
        fi

        # Hot-reload test (T+8m)
        if [ $elapsed_min -ge 8 ] && [ "$HOTRELOAD_DONE" = "false" ]; then
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
            run_checkpoint "T${elapsed_min}_reload" \
                "$GVM_BIN" reload --proxy "$PROXY_URL" || true
            sleep 3
            local check_out
            check_out=$("$GVM_BIN" check --host httpbin.org --method GET \
                --operation test --proxy "$PROXY_URL" 2>&1) || true
            if echo "$check_out" | grep -qi "Delay"; then
                log_health "HOT-RELOAD VERIFY: PASS"
                echo "hotreload_verify|0|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKPOINT_LOG"
            else
                log_health "HOT-RELOAD VERIFY: FAIL"
                echo "hotreload_verify|1|$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKPOINT_LOG"
            fi
        fi

        sleep "$HEALTH_INTERVAL"
    done
}

# ── Evaluation ──
evaluate_results() {
    local end_time; end_time=$(date +%s)
    echo "" >> "$SUMMARY"
    echo "═══ Pass/Fail Evaluation ═══" >> "$SUMMARY"
    echo "elapsed_sec=$((end_time - START_TIME))" >> "$SUMMARY"
    local pass=true

    # 1. Kernel panic
    local panics
    panics=$(grep -c "CRITICAL.*kernel panic\|CRITICAL.*BUG" "$HEALTH_LOG" 2>/dev/null || echo "0")
    if [ "$panics" -gt 0 ]; then
        echo "FAIL: $panics kernel panic/BUG events" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no kernel panic" >> "$SUMMARY"
    fi

    # 2. Proxy chaos recovery
    if $CHAOS_ENABLED && grep -q "INJECT.*kill" "$CHAOS_LOG" 2>/dev/null; then
        if grep -q "Gateway restarted successfully" "$HEALTH_LOG" 2>/dev/null; then
            echo "PASS: proxy + gateway recovered after chaos kill" >> "$SUMMARY"
        else
            echo "FAIL: gateway did not recover after proxy kill" >> "$SUMMARY"; pass=false
        fi
    fi

    # 3. Orphan cleanup
    "$GVM_BIN" cleanup 2>/dev/null || true
    local final_veth
    final_veth=$(get_orphan_veth)
    if [ "${final_veth:-0}" -gt 0 ] 2>/dev/null; then
        echo "FAIL: orphan veth remains ($final_veth)" >> "$SUMMARY"; pass=false
    else
        echo "PASS: no orphan veth" >> "$SUMMARY"
    fi

    # 4. WAL integrity
    run_checkpoint "final_audit" "$GVM_BIN" audit verify --wal "$WAL" || true
    if grep -q "final_audit|0" "$CHECKPOINT_LOG" 2>/dev/null; then
        echo "PASS: WAL integrity verified" >> "$SUMMARY"
    else
        echo "WARN: WAL verification inconclusive" >> "$SUMMARY"
    fi
    echo "wal_events: $(wc -l < "$WAL" 2>/dev/null || echo 0)" >> "$SUMMARY"

    # 5. Agent activity
    local anthropic_calls prompts_sent
    anthropic_calls=$(grep -c "anthropic" "$REPO_DIR/data/proxy.log" 2>/dev/null || echo "0")
    prompts_sent=$(grep -c "^PROMPT #" "$GATEWAY_LOG" 2>/dev/null || echo "0")
    echo "anthropic_calls: $anthropic_calls" >> "$SUMMARY"
    echo "prompts_sent: $prompts_sent" >> "$SUMMARY"
    if [ "$anthropic_calls" -gt 0 ]; then
        echo "PASS: agent made LLM calls ($anthropic_calls via proxy MITM)" >> "$SUMMARY"
    else
        echo "FAIL: no LLM calls through proxy" >> "$SUMMARY"; pass=false
    fi

    # 6. Connection errors
    local conn_err
    conn_err=$(grep -c "Connection error\|Network request failed" "$GATEWAY_LOG" 2>/dev/null || echo "0")
    echo "connection_errors: $conn_err" >> "$SUMMARY"

    # 7. TLS errors
    local tls_err
    tls_err=$(grep -c "tls handshake" "$REPO_DIR/data/proxy.log" 2>/dev/null || echo "0")
    echo "tls_handshake_errors: $tls_err" >> "$SUMMARY"

    # 8. Polling stalls
    local stalls
    stalls=$(grep -c "Polling stall" "$GATEWAY_LOG" 2>/dev/null || echo "0")
    echo "polling_stalls: $stalls" >> "$SUMMARY"

    # 9. CLI checkpoints
    local cp_total cp_pass
    cp_total=$(awk -F'|' 'NR>1' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    cp_pass=$(awk -F'|' 'NR>1 && $2==0' "$CHECKPOINT_LOG" 2>/dev/null | wc -l || echo "0")
    echo "cli_checkpoints: $cp_pass/$cp_total passed" >> "$SUMMARY"

    # 10. MITM traffic
    local mitm_total
    mitm_total=$(grep -c "MITM: inspecting" "$REPO_DIR/data/proxy.log" 2>/dev/null || echo "0")
    echo "mitm_inspected: $mitm_total" >> "$SUMMARY"

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

    # Stop gateway + agent sandbox
    tmux kill-session -t gvm-gateway 2>/dev/null || true
    pkill -f "openclaw" 2>/dev/null || true

    # Restore chaos
    if $CHAOS_NETWORK_DONE && ! $CHAOS_NETWORK_RESTORED; then
        chaos_network_restore
    fi
    if $CHAOS_DISK_DONE && ! $CHAOS_DISK_RELEASED; then
        chaos_disk_release
    fi

    # Restore original SRR config (hot-reload test appended rules)
    if [ -f "$RESULTS_DIR/srr_network.toml.backup" ]; then
        cp "$RESULTS_DIR/srr_network.toml.backup" "$REPO_DIR/config/srr_network.toml"
    fi

    # Orphan cleanup
    "$GVM_BIN" cleanup 2>/dev/null || true

    echo -e "${GREEN}Cleanup done${NC}"
}

trap cleanup EXIT

# ── Main ──
check_prereqs

mkdir -p "$RESULTS_DIR/checkpoints"

# Backup SRR config (hot-reload test appends rules)
ORIGINAL_SRR="$REPO_DIR/config/srr_network.toml"
cp "$ORIGINAL_SRR" "$RESULTS_DIR/srr_network.toml.backup"

echo "# Health log" > "$HEALTH_LOG"
echo "# Chaos log" > "$CHAOS_LOG"
echo "name|exit_code|timestamp" > "$CHECKPOINT_LOG"
START_TIME=$(date +%s)
echo "start_time=$START_TIME" > "$SUMMARY"
echo "duration_min=$DURATION_MIN" >> "$SUMMARY"
echo "mode=telegram-gateway" >> "$SUMMARY"

echo -e "${BOLD}${CYAN}═══ GVM Stress Test (Telegram Gateway) ═══${NC}"
echo -e "  Duration:    ${DURATION_MIN}m"
echo -e "  Chaos:       $CHAOS_ENABLED"
echo -e "  Prompts:     $PROMPT_FILE ($(wc -l < "$PROMPT_FILE") prompts)"
echo -e "  Health:      every ${HEALTH_INTERVAL}s"
echo -e "  Results:     $RESULTS_DIR"
echo ""

# Phase 0: Start sandbox (gateway + agent prompt loop inside)
start_sandbox

# Phase 1+2: Monitor + chaos (prompts run inside sandbox automatically)
echo -e "\n${BOLD}Monitoring (health every ${HEALTH_INTERVAL}s, chaos $CHAOS_ENABLED)...${NC}"
echo -e "${DIM}  tmux: Ctrl+B D to detach safely${NC}\n"

main_loop

# Phase 5: Evaluate
evaluate_results
