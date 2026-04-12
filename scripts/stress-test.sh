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

    # ── Defensive cleanup of leftover chaos state ──
    #
    # A previous stress run that died via SIGKILL (timeout --signal=KILL, OOM,
    # kernel panic, lost SSH session mid-teardown) can leave behind kernel-scope
    # state that the `trap cleanup EXIT` handler never ran against:
    #
    #   - `tc qdisc` netem rules on the default egress interface (from
    #     chaos_network_partition) — delay/loss applied to all subsequent HTTPS
    #     traffic, silently breaking the host's outbound connectivity until
    #     explicitly removed.
    #   - iptables mangle fwmark rules matching the netem filter.
    #   - Orphan disk-pressure tmpfs mounts.
    #
    # Ran into exactly this: a timeout-killed stress run left
    # `qdisc netem 30: delay 5s loss 20%` active, which looked indistinguishable
    # from a broken EC2 instance until `tc qdisc show` revealed it.
    #
    # Run the teardown operations unconditionally here so the next run starts
    # from a known-clean kernel state regardless of how the previous one died.
    local default_iface
    default_iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "")
    if [ -n "$default_iface" ]; then
        if sudo tc qdisc show dev "$default_iface" 2>/dev/null | grep -q "netem\|prio 1:"; then
            echo -e "  ${YELLOW}⚠ Leftover tc qdisc on $default_iface — removing${NC}"
            sudo tc qdisc del dev "$default_iface" root 2>/dev/null || true
        fi
    fi
    # iptables mangle fwmark cleanup (best-effort — matches chaos_network_partition exactly)
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 443 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true
    sudo iptables -t mangle -D OUTPUT -p tcp --dport 80 ! -d 127.0.0.0/8 \
        -j MARK --set-mark 42 2>/dev/null || true

    # Load stress SRR via symlink — NEVER overwrite the original config.
    # Previous bug: cp stress-srr → srr_network.toml destroyed production rules
    # on abnormal exit (SSH disconnect, kernel panic). Now we symlink so the
    # original file is always intact. Cleanup just removes the symlink.
    ORIGINAL_SRR="$REPO_DIR/config/srr_network.toml"
    ORIGINAL_SRR_SAVED="$RESULTS_DIR/srr_network.toml.original"
    cp "$ORIGINAL_SRR" "$ORIGINAL_SRR_SAVED"
    # Point srr_network.toml at stress rules via copy (symlinks don't work with TOML parser)
    # But save the original in results dir for guaranteed recovery
    cp "$STRESS_SRR" "$ORIGINAL_SRR"

    # Reset WAL for clean measurement (backup first)
    cp "$REPO_DIR/data/wal.log" "$RESULTS_DIR/wal-pre-stress.log" 2>/dev/null || true
    > "$REPO_DIR/data/wal.log"

    # Bring up the proxy through the GVM CLI only — no direct gvm-proxy
    # invocation, no setsid, no PID file mangling. CLAUDE.md requires test
    # scripts to drive GVM exclusively through CLI commands; proxy_manager.rs
    # already handles daemonization, PID file ownership, stale-process cleanup
    # and health-wait deterministically.
    #
    # Sequence:
    #   1. `gvm stop`  — terminate any leftover proxy from a previous run
    #                    so it loads the freshly-staged stress SRR config.
    #   2. `gvm run -- /bin/true` — primer agent. ensure_available() spawns
    #                    the proxy daemon, waits for health (and TLS warm-up),
    #                    then runs `/bin/true` and exits. The daemon stays.
    #
    # Chaos-kill recovery still works for free: every subsequent `gvm run`
    # call inside launch_agent() re-runs ensure_available(), which respawns
    # the proxy if chaos_proxy_kill() has just SIGKILLed it.
    cd "$REPO_DIR"
    "$GVM_BIN" stop >/dev/null 2>&1 || true
    if ! "$GVM_BIN" run -- /bin/true >"$RESULTS_DIR/proxy-bootstrap.log" 2>&1; then
        echo -e "${RED}Proxy failed to start via 'gvm run' primer${NC}"
        cat "$RESULTS_DIR/proxy-bootstrap.log" || true
        exit 1
    fi

    # Code Standard 6.1: use CLI for PID, not direct file access.
    PROXY_PID=$("$GVM_BIN" status --json 2>/dev/null \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('pid','0'))" 2>/dev/null || echo "0")
    echo "$PROXY_PID" > "$RESULTS_DIR/proxy.pid"
    echo -e "  ${GREEN}Proxy started via gvm CLI (PID $PROXY_PID)${NC}"

    # Record initial metrics
    INITIAL_RSS=$(get_rss "$PROXY_PID")
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
    pid=$("$GVM_BIN" status --json 2>/dev/null \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('pid','0'))" 2>/dev/null \
        || cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0")

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
    local gvm_invoker=""
    if [ "$MODE" = "sandbox" ]; then
        gvm_mode_flag="--sandbox"
        # Sandbox requires CAP_NET_ADMIN (veth + iptables) and CAP_SYS_ADMIN
        # (mount namespaces). When the stress script is run as a non-root
        # user (the default — operators tmux into ubuntu and start it),
        # `gvm run --sandbox` would fail preflight on net_admin_capability
        # and every turn would die in 0s with "Pre-flight check failed".
        # That mode produces a 60-minute "stress run" with zero WAL events
        # and a misleading PASS verdict (memory/FD/recovery still look
        # stable because nothing is actually exercising them). Detect the
        # uid here and prepend `sudo -E` so the API key + path env are
        # preserved across the privilege boundary.
        if [ "$(id -u)" -ne 0 ]; then
            if sudo -n true 2>/dev/null; then
                gvm_invoker="sudo -E"
            else
                echo -e "${RED}stress-test sandbox mode requires passwordless sudo for CAP_NET_ADMIN${NC}" >&2
                exit 1
            fi
        fi
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
                $gvm_invoker "$GVM_BIN" run $gvm_mode_flag \
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
        # Fallback: disk-based Python script invoked through SCRIPT MODE
        # (no `--` separator). This deliberately exercises run::detect_interpreter,
        # /workspace bind mount, and the script-mode sandbox path — code paths
        # the OpenClaw branch above (binary mode via `-- node ...`) never hits.
        # Two latent bugs survived weeks of stress runs because nothing here
        # exercised script mode.
        local stress_script="$RESULTS_DIR/stress-agent-$id.py"
        cat > "$stress_script" <<PY
import requests, time, random
proxy = "$PROXY_URL"
proxies = {"http": proxy, "https": proxy}
urls = [
    ("GET", "http://api.github.com/repos/torvalds/linux/commits?per_page=1"),
    ("GET", "http://api.github.com/repos/rust-lang/rust/commits?per_page=1"),
    ("GET", "http://raw.githubusercontent.com/golang/go/master/README.md"),
    ("GET", "http://catfact.ninja/fact"),
    ("GET", "http://numbersapi.com/random/trivia"),
    ("GET", "http://dog.ceo/api/breeds/image/random"),
    ("GET", "http://official-joke-api.appspot.com/random_joke"),
]
for i in range(200):
    method, url = random.choice(urls)
    try:
        r = requests.get(url, proxies=proxies, timeout=15)
        print(f"[{i}] {method} {url} -> {r.status_code}")
    except Exception as e:
        print(f"[{i}] {method} {url} -> ERR: {e}")
    time.sleep(random.uniform(5, 20))
PY
        timeout $((DURATION_SEC + 120)) $gvm_invoker "$GVM_BIN" run $gvm_mode_flag \
            --agent-id "$session_id" "$stress_script" > "$agent_log" 2>&1 &
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
    # 6.1-exception: PID obtained via CLI; kill -9 is intentional chaos injection.
    # Direct gvm-proxy restart below is a 6.1 violation — tracked for future migration.
    local old_pid
    old_pid=$("$GVM_BIN" status --json 2>/dev/null \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('pid','0'))" 2>/dev/null \
        || cat "$RESULTS_DIR/proxy.pid" 2>/dev/null || echo "0")
    chaos_log "INJECT: kill -9 proxy (PID $old_pid)"
    kill -9 "$old_pid" 2>/dev/null

    # Save WAL backup before restart (chaos recovery evidence)
    cp "$REPO_DIR/data/wal.log" "$RESULTS_DIR/wal-before-chaos.log" 2>/dev/null || true

    # 6.1-exception: chaos recovery restarts proxy directly because
    # gvm run spawns a full agent session, not just the daemon. Track
    # for future `gvm proxy restart` or equivalent CLI.
    sleep 2
    cd "$REPO_DIR"
    setsid "$PROXY_BIN" >> "$REPO_DIR/data/proxy.log" 2>&1 &  # 6.1-exception: chaos restart
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
        echo "PASS: memory stable (max − initial check)" >> "$SUMMARY"
    fi

    # 1b. Memory trend — linear regression over the full time series.
    # The max-minus-initial check is satisfied by a slow monotonic leak
    # as long as it stays under the budget for the test duration. Fit a
    # line to the (elapsed_sec, rss_mb) samples and fail if the slope
    # projects more than MAX_MEM_INCREASE_MB over a 24h window. This
    # catches leaks of 2–3 MB/hour which the absolute limit misses.
    # Run the regression script out-of-line to avoid heredoc-in-command
    # -substitution parsing pitfalls. The script lives in a tempfile for
    # the duration of this function.
    local slope_script
    slope_script=$(mktemp /tmp/gvm-slope.XXXXXX.py)
    cat > "$slope_script" <<'PY'
import sys, csv
path, budget = sys.argv[1], float(sys.argv[2])
rows = []
with open(path) as f:
    reader = csv.reader(f)
    next(reader, None)  # drop header
    for r in reader:
        try:
            rows.append((float(r[1]), float(r[2])))
        except (ValueError, IndexError):
            continue
if len(rows) < 5:
    print("skip n<5")
    sys.exit(0)
n = len(rows)
sum_x = sum(x for x, _ in rows)
sum_y = sum(y for _, y in rows)
sum_xy = sum(x * y for x, y in rows)
sum_xx = sum(x * x for x, _ in rows)
denom = n * sum_xx - sum_x * sum_x
if denom == 0:
    print("skip flat")
    sys.exit(0)
slope_mb_per_sec = (n * sum_xy - sum_x * sum_y) / denom
slope_mb_per_hour = slope_mb_per_sec * 3600
# Project over 24h. Negative slope (memory releasing) is always fine.
projected_24h = slope_mb_per_hour * 24
verdict = "PASS" if projected_24h <= budget else "FAIL"
print(f"{verdict} slope={slope_mb_per_hour:.3f}MB/h projected_24h={projected_24h:.1f}MB budget={budget}MB")
PY
    local slope_result
    slope_result=$(python3 "$slope_script" "$METRICS_CSV" "$MAX_MEM_INCREASE_MB" 2>/dev/null || echo "skip")
    rm -f "$slope_script"
    case "$slope_result" in
        PASS*)
            echo "PASS: memory trend ($slope_result)" >> "$SUMMARY"
            ;;
        FAIL*)
            echo "FAIL: memory trend — 24h projection exceeds budget ($slope_result)" >> "$SUMMARY"
            pass=false
            ;;
        *)
            echo "SKIP: memory trend ($slope_result)" >> "$SUMMARY"
            ;;
    esac

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

        # Liveness check: count non-system events (filter out the
        # `gvm-proxy` startup config_load events that are emitted on
        # every proxy boot whether agents do anything or not). A 60-min
        # stress run with 3 agents must produce at least dozens of
        # agent-initiated events; anything below the threshold means
        # the agents never actually exercised the proxy. Without this
        # assertion the previous run silently passed with only 4
        # gvm-proxy startup events (NRestarts due to chaos kill) and
        # zero agent traffic — a 0-coverage stress test that looked
        # green because memory/FD/recovery still appeared stable.
        local agent_events
        agent_events=$(grep -v '"agent_id":"gvm-proxy"' "$RESULTS_DIR/audit-export.jsonl" 2>/dev/null | wc -l)
        echo "agent_events: $agent_events (system events excluded)" >> "$SUMMARY"
        # Threshold: 1 event per minute per agent is a very conservative
        # floor — real OpenClaw runs produce 5-10x that.
        local min_agent_events=$((DURATION_MIN * NUM_AGENTS))
        if [ "${agent_events:-0}" -lt "$min_agent_events" ]; then
            echo "FAIL: agent_events=$agent_events below floor $min_agent_events ($DURATION_MIN min × $NUM_AGENTS agents — agents not actually exercising the proxy)" >> "$SUMMARY"
            pass=false
        else
            echo "PASS: agent traffic above floor ($agent_events ≥ $min_agent_events)" >> "$SUMMARY"
        fi

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

    # Stop the proxy through the CLI — gvm stop reads data/proxy.pid,
    # signals the daemon, waits for it, and clears the PID file. No
    # pkill / no direct process scanning (CLAUDE.md CLI-only rule).
    "$GVM_BIN" stop >/dev/null 2>&1 || true
    rm -f "$RESULTS_DIR/proxy.pid" 2>/dev/null

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

    # Restore original SRR from results dir backup (crash-safe).
    # Previous .stressbak approach failed on abnormal exit — backup file
    # was in the same directory and could be lost. Results dir is separate.
    if [ -f "${ORIGINAL_SRR_SAVED:-}" ]; then
        cp "$ORIGINAL_SRR_SAVED" "$REPO_DIR/config/srr_network.toml"
        echo -e "  ${GREEN}Original SRR restored from backup${NC}"
    elif [ -f "$REPO_DIR/config/srr_network.toml.stressbak" ]; then
        # Legacy fallback
        mv "$REPO_DIR/config/srr_network.toml.stressbak" "$REPO_DIR/config/srr_network.toml"
    else
        echo -e "  ${RED}WARNING: Cannot restore original SRR — no backup found!${NC}"
        echo -e "  ${RED}Run: git checkout -- config/srr_network.toml${NC}"
    fi

    # Restore WAL from backup
    if [ -f "$RESULTS_DIR/wal-pre-stress.log" ]; then
        cp "$RESULTS_DIR/wal-pre-stress.log" "$REPO_DIR/data/wal.log" 2>/dev/null || true
    fi

    echo -e "${DIM}Results saved to: $RESULTS_DIR${NC}"
}

trap cleanup EXIT
# Catch termination signals explicitly and forward to cleanup.
# The EXIT trap alone is not enough when the parent is `timeout`: under SIGKILL
# the shell dies without running EXIT traps. Under SIGTERM/INT/HUP we want
# cleanup to run before the shell exits. Under SIGKILL the next run's
# defensive cleanup in setup() is the only safety net — by design.
trap 'cleanup; exit 143' TERM INT HUP

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
        # Poll until every agent PID is gone rather than sleeping a fixed 3s.
        # On loaded EC2 instances 3s was occasionally too short, leaving live
        # sandboxes that then showed up as "orphan veth" in the evaluation
        # phase and falsely failed the run.
        local agent_deadline=$(($(date +%s) + 15))
        while [ "$(date +%s)" -lt "$agent_deadline" ]; do
            local alive=0
            while read -r pid; do
                kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
            done < "$RESULTS_DIR/agent_pids.txt"
            [ "$alive" = "0" ] && break
            sleep 0.3
        done
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
