#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Watch Discovery: API Pattern Collection
#
# Runs OpenClaw agents through gvm watch to discover API call patterns.
# Three phases: allow-all observation → with-rules verification → long-run stability.
#
# Requirements:
#   - Linux (EC2 recommended, t3.medium+)
#   - ANTHROPIC_API_KEY set
#   - GVM proxy + CLI built (cargo build --release)
#   - OpenClaw installed (npm install -g openclaw)
#   - Root access for sandbox mode
#
# Usage:
#   sudo env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY bash scripts/watch-discovery.sh
#   sudo env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY bash scripts/watch-discovery.sh --phase 1
#   sudo env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY bash scripts/watch-discovery.sh --phase 2
#   sudo env ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY bash scripts/watch-discovery.sh --phase 3
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail

# ── Configuration ──
PHASE=${PHASE:-0}              # 0 = all, 1/2/3 = specific phase
AGENT_TIMEOUT=${AGENT_TIMEOUT:-600}  # 10 minutes per agent
LONG_TIMEOUT=${LONG_TIMEOUT:-1800}   # 30 minutes for Phase 3
HANG_CHECK_INTERVAL=30         # Check for hangs every 30s
HANG_THRESHOLD=120             # No new WAL events for 120s = hang
MAX_WATCH_RSS_MB=200           # Watch process RSS limit

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GVM_BIN="$REPO_DIR/target/release/gvm"
RESULTS_DIR="$REPO_DIR/results/watch-$(date +%Y%m%dT%H%M%S)"

# Colors
BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# Load .env file if present
if [ -f "$REPO_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_DIR/.env"
    set +a
fi

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --phase) PHASE="$2"; shift 2 ;;
        --timeout) AGENT_TIMEOUT="$2"; shift 2 ;;
        --long-timeout) LONG_TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Validation ──
preflight() {
    local fail=false
    echo -e "${BOLD}${CYAN}═══ GVM Watch Discovery ═══${NC}"

    # API key
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        echo -e "${RED}  ANTHROPIC_API_KEY not set${NC}"
        echo -e "${DIM}  Usage: sudo env ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY bash $0${NC}"
        fail=true
    else
        echo -e "  ${GREEN}API key: set${NC}"
    fi

    # Binaries
    [ ! -f "$GVM_BIN" ] && echo -e "${RED}  gvm CLI not built: $GVM_BIN${NC}" && fail=true
    [ -f "$GVM_BIN" ] && echo -e "  ${GREEN}gvm CLI: $GVM_BIN${NC}"

    # Root check (sandbox needs root)
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}  Root required for sandbox mode${NC}"
        echo -e "${DIM}  Usage: sudo env ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY bash $0${NC}"
        fail=true
    else
        echo -e "  ${GREEN}Root: yes${NC}"
    fi

    # OpenClaw path resolution
    OC_MJS=""
    if command -v openclaw >/dev/null 2>&1; then
        local oc_real
        oc_real=$(readlink -f "$(which openclaw)" 2>/dev/null || echo "")
        if [ -n "$oc_real" ] && [ -f "$oc_real" ]; then
            OC_MJS="$oc_real"
        fi
    fi
    # Fallback: common npm global paths
    for candidate in \
        /usr/lib/node_modules/openclaw/openclaw.mjs \
        /usr/local/lib/node_modules/openclaw/openclaw.mjs \
        "$HOME/.npm-global/lib/node_modules/openclaw/openclaw.mjs"; do
        if [ -z "$OC_MJS" ] && [ -f "$candidate" ]; then
            OC_MJS="$candidate"
        fi
    done

    if [ -z "$OC_MJS" ]; then
        echo -e "${RED}  OpenClaw not found — install with: npm install -g openclaw${NC}"
        fail=true
    else
        echo -e "  ${GREEN}OpenClaw: $OC_MJS${NC}"
    fi

    # SRR field check
    echo -e "  ${DIM}SRR field format:${NC}"
    grep -E 'pattern|host' "$REPO_DIR/config/srr_network.toml" 2>/dev/null | head -3 | while read -r line; do
        echo -e "    ${DIM}$line${NC}"
    done

    $fail && exit 1

    mkdir -p "$RESULTS_DIR"/{phase1,phase2,phase3}
    echo -e "  Results: $RESULTS_DIR"
    echo ""
}

# ── Hang Detection ──
# Monitors WAL file growth. If no new bytes for HANG_THRESHOLD seconds,
# considers the agent hung and kills it.
hang_monitor() {
    local label=$1
    local pid=$2
    local wal_path="$REPO_DIR/data/wal.log"
    local last_size=0
    local stale_seconds=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep "$HANG_CHECK_INTERVAL"

        # Check if process still alive
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi

        local current_size
        current_size=$(stat -c%s "$wal_path" 2>/dev/null || echo "0")

        if [ "$current_size" -eq "$last_size" ]; then
            stale_seconds=$((stale_seconds + HANG_CHECK_INTERVAL))
            if [ "$stale_seconds" -ge "$HANG_THRESHOLD" ]; then
                echo -e "  ${RED}HANG detected: [$label] no WAL activity for ${stale_seconds}s — killing${NC}"
                echo "HANG: $label after ${stale_seconds}s stale WAL" >> "$RESULTS_DIR/hang.log"
                kill "$pid" 2>/dev/null
                sleep 2
                kill -9 "$pid" 2>/dev/null || true
                return 1
            else
                echo -e "  ${DIM}[$label] WAL stale for ${stale_seconds}s (threshold: ${HANG_THRESHOLD}s)${NC}"
            fi
        else
            stale_seconds=0
            last_size=$current_size
        fi
    done
    return 0
}

# ── Watch RSS Monitor ──
# Track RSS of gvm watch process in background.
watch_rss_monitor() {
    local pid=$1
    local label=$2
    local log_file="$3"
    echo "timestamp,rss_mb" > "$log_file"

    while kill -0 "$pid" 2>/dev/null; do
        sleep 10
        local rss
        rss=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f", $1/1024}' || echo "0")
        local ts
        ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        echo "$ts,$rss" >> "$log_file"

        # Check RSS limit
        local rss_int
        rss_int=$(echo "$rss" | cut -d. -f1)
        if [ "${rss_int:-0}" -gt "$MAX_WATCH_RSS_MB" ]; then
            echo -e "  ${RED}[$label] watch RSS ${rss}MB exceeds ${MAX_WATCH_RSS_MB}MB limit${NC}"
            echo "RSS_EXCEEDED: $label ${rss}MB" >> "$RESULTS_DIR/hang.log"
        fi
    done
}

# ── Run Single Watch Agent ──
# Runs gvm watch with an agent, monitors for hangs, collects results.
run_watch_agent() {
    local label=$1
    local output_dir=$2
    local timeout=$3
    local with_rules=$4  # "true" or "false"
    local prompt=$5

    local jsonl_file="$output_dir/${label}.jsonl"
    local log_file="$output_dir/${label}.log"
    local rss_file="$output_dir/${label}-rss.csv"

    echo -e "  ${CYAN}Starting [$label] (timeout: ${timeout}s, rules: $with_rules)${NC}"

    # Set sandbox timeout slightly longer than agent timeout to allow cleanup
    export GVM_SANDBOX_TIMEOUT=$((timeout + 30))

    # Build gvm watch command
    local watch_args=(watch --sandbox --output json --agent-id "$label")
    if [ "$with_rules" = "true" ]; then
        watch_args+=(--with-rules)
    fi
    watch_args+=(-- node "$OC_MJS" agent --local
        --session-id "$label-$(date +%s)"
        --message "$prompt"
        --timeout "$timeout")

    # Run with timeout (agent timeout + 60s buffer for cleanup)
    timeout $((timeout + 60)) "$GVM_BIN" "${watch_args[@]}" \
        > "$jsonl_file" 2>"$log_file" &
    local watch_pid=$!

    # Start monitors
    hang_monitor "$label" "$watch_pid" &
    local hang_pid=$!

    watch_rss_monitor "$watch_pid" "$label" "$rss_file" &
    local rss_pid=$!

    # Wait for watch to complete
    local exit_code=0
    wait "$watch_pid" || exit_code=$?

    # Stop monitors
    kill "$hang_pid" 2>/dev/null || true
    kill "$rss_pid" 2>/dev/null || true
    wait "$hang_pid" 2>/dev/null || true
    wait "$rss_pid" 2>/dev/null || true

    # Report
    local event_count
    event_count=$(wc -l < "$jsonl_file" 2>/dev/null || echo "0")
    local max_rss
    max_rss=$(awk -F, 'NR>1 {print $2}' "$rss_file" 2>/dev/null | sort -n | tail -1 || echo "0")

    if [ "$exit_code" -eq 0 ]; then
        echo -e "  ${GREEN}[$label] completed: ${event_count} events, peak RSS ${max_rss}MB${NC}"
    elif [ "$exit_code" -eq 124 ]; then
        echo -e "  ${YELLOW}[$label] timeout after ${timeout}s: ${event_count} events${NC}"
    else
        echo -e "  ${RED}[$label] exit code $exit_code: ${event_count} events${NC}"
    fi

    return 0
}

# ── Analysis Functions ──

analyze_schema() {
    local jsonl_file=$1
    echo -e "\n  ${BOLD}Event Schema (first event keys):${NC}"
    head -1 "$jsonl_file" 2>/dev/null | python3 -c "
import sys, json
try:
    event = json.loads(sys.stdin.read())
    for k in sorted(event.keys()):
        v = event[k]
        t = type(v).__name__
        if isinstance(v, dict):
            sub = ', '.join(sorted(v.keys())[:5])
            print(f'    {k}: dict({sub}...)')
        elif isinstance(v, str) and len(v) > 50:
            print(f'    {k}: \"{v[:50]}...\"')
        else:
            print(f'    {k}: {json.dumps(v)[:60]}')
except: pass
" 2>/dev/null || echo -e "    ${DIM}(no events)${NC}"
}

analyze_phase1() {
    local dir=$1
    echo -e "\n${BOLD}═══ Phase 1 Analysis ═══${NC}"

    # Merge all jsonl files
    cat "$dir"/*.jsonl > "$dir/merged.jsonl" 2>/dev/null || true
    local total
    total=$(wc -l < "$dir/merged.jsonl" 2>/dev/null || echo "0")
    echo -e "  Total events: $total"

    if [ "$total" -eq 0 ]; then
        echo -e "  ${RED}No events collected — check logs${NC}"
        for f in "$dir"/*.log; do
            echo -e "  ${DIM}$(basename "$f"):${NC}"
            tail -5 "$f" 2>/dev/null | sed 's/^/    /'
        done
        return
    fi

    # Schema check (first event)
    analyze_schema "$dir/merged.jsonl"

    # Host frequency
    echo -e "\n  ${BOLD}Host Frequency:${NC}"
    python3 -c "
import sys, json
from collections import Counter
hosts = Counter()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        h = (e.get('transport') or {}).get('host', '???')
        hosts[h] += 1
    except: pass
for host, count in hosts.most_common(20):
    print(f'    {count:>4}  {host}')
" 2>/dev/null

    # Default-to-caution (unknown hosts)
    echo -e "\n  ${BOLD}Unknown Hosts (default_caution=true):${NC}"
    python3 -c "
import sys, json
seen = set()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        if e.get('default_caution'):
            t = e.get('transport') or {}
            key = f\"{t.get('method','?')} {t.get('host','?')}{t.get('path','')}\"
            host = t.get('host','?')
            if host not in seen:
                seen.add(host)
                print(f'    {key[:80]}')
    except: pass
if not seen:
    print('    (none — all hosts matched SRR rules)')
" 2>/dev/null

    # Method distribution
    echo -e "\n  ${BOLD}Method Distribution:${NC}"
    python3 -c "
import sys, json
from collections import Counter
methods = Counter()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        m = (e.get('transport') or {}).get('method', '???')
        methods[m] += 1
    except: pass
for method, count in methods.most_common():
    print(f'    {count:>4}  {method}')
" 2>/dev/null

    # Hosts not in current SRR
    echo -e "\n  ${BOLD}Hosts NOT in current SRR:${NC}"
    python3 -c "
import sys, json, re

# Extract known hosts from SRR config
srr_hosts = set()
with open('$REPO_DIR/config/srr_network.toml') as f:
    for line in f:
        # pattern = \"api.github.com/...\" or pattern = \"{any}\"
        m = re.search(r'pattern\s*=\s*\"([^\"]+)\"', line)
        if m:
            host = m.group(1).split('/')[0]
            if host not in ('{any}', '*', 'localhost', '127.0.0.1'):
                srr_hosts.add(host.lower())

# Collect observed hosts
observed = set()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        h = (e.get('transport') or {}).get('host', '')
        if h:
            observed.add(h.lower().split(':')[0])
    except: pass

# Diff
unknown = sorted(observed - srr_hosts - {'localhost', '127.0.0.1', ''})
if unknown:
    for h in unknown:
        print(f'    {h}')
else:
    print('    (all observed hosts are covered by SRR)')
" 2>/dev/null

    # Save unknown hosts list
    python3 -c "
import json, re
srr_hosts = set()
with open('$REPO_DIR/config/srr_network.toml') as f:
    for line in f:
        m = re.search(r'pattern\s*=\s*\"([^\"]+)\"', line)
        if m:
            host = m.group(1).split('/')[0]
            if host not in ('{any}', '*', 'localhost', '127.0.0.1'):
                srr_hosts.add(host.lower())
observed = set()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        h = (e.get('transport') or {}).get('host', '')
        if h: observed.add(h.lower().split(':')[0])
    except: pass
unknown = sorted(observed - srr_hosts - {'localhost', '127.0.0.1', ''})
with open('$dir/unknown-hosts.txt', 'w') as f:
    for h in unknown:
        f.write(h + '\n')
" 2>/dev/null
    echo -e "\n  ${DIM}Saved: $dir/unknown-hosts.txt, $dir/merged.jsonl${NC}"
}

analyze_phase2() {
    local dir=$1
    echo -e "\n${BOLD}═══ Phase 2 Analysis ═══${NC}"

    cat "$dir"/*.jsonl > "$dir/merged.jsonl" 2>/dev/null || true
    local total
    total=$(wc -l < "$dir/merged.jsonl" 2>/dev/null || echo "0")
    echo -e "  Total events: $total"

    if [ "$total" -eq 0 ]; then
        echo -e "  ${RED}No events — check logs${NC}"
        return
    fi

    # Decision distribution
    echo -e "\n  ${BOLD}Decision Distribution:${NC}"
    python3 -c "
import json
from collections import Counter
decisions = Counter()
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        d = e.get('decision', '???')
        # Bucket
        if 'Allow' in d: decisions['Allow'] += 1
        elif 'Delay' in d: decisions['Delay'] += 1
        elif 'Deny' in d: decisions['Deny'] += 1
        else: decisions[d] += 1
    except: pass
for d, c in decisions.most_common():
    print(f'    {c:>4}  {d}')
" 2>/dev/null

    # Denied requests (potential false denies)
    echo -e "\n  ${BOLD}Denied Requests (check for false positives):${NC}"
    python3 -c "
import json
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        d = e.get('decision', '')
        if 'Deny' in d:
            t = e.get('transport') or {}
            rule = e.get('matched_rule_id', 'no-rule')
            print(f\"    {t.get('method','?')} {t.get('host','?')}{t.get('path','')} | rule: {rule}\")
    except: pass
" 2>/dev/null || echo -e "    ${DIM}(none)${NC}"

    # Default-to-caution (Delay without explicit rule)
    echo -e "\n  ${BOLD}Default-to-Caution Delays (no matching rule):${NC}"
    python3 -c "
import json
count = 0
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        if e.get('default_caution'):
            t = e.get('transport') or {}
            d = e.get('decision', '')
            count += 1
            if count <= 10:
                print(f\"    {t.get('method','?')} {t.get('host','?')}{t.get('path','')[:40]} → {d}\")
    except: pass
if count > 10:
    print(f'    ... and {count - 10} more')
if count == 0:
    print('    (none — all requests matched explicit rules)')
" 2>/dev/null

    echo -e "\n  ${DIM}Saved: $dir/merged.jsonl${NC}"
}

analyze_phase3() {
    local dir=$1
    echo -e "\n${BOLD}═══ Phase 3 Analysis ═══${NC}"

    cat "$dir"/*.jsonl > "$dir/merged.jsonl" 2>/dev/null || true
    local total
    total=$(wc -l < "$dir/merged.jsonl" 2>/dev/null || echo "0")
    echo -e "  Total events: $total"

    if [ "$total" -eq 0 ]; then
        echo -e "  ${RED}No events — check logs${NC}"
        return
    fi

    # Summary stats
    python3 -c "
import json
from collections import Counter
hosts = Counter()
decisions = Counter()
default_caution = 0
llm_calls = 0
total_tokens = 0
for line in open('$dir/merged.jsonl'):
    try:
        e = json.loads(line)
        h = (e.get('transport') or {}).get('host', '???')
        hosts[h] += 1
        d = e.get('decision', '???')
        if 'Allow' in d: decisions['Allow'] += 1
        elif 'Delay' in d: decisions['Delay'] += 1
        elif 'Deny' in d: decisions['Deny'] += 1
        else: decisions[d] += 1
        if e.get('default_caution'): default_caution += 1
        if e.get('llm_trace'):
            llm_calls += 1
            usage = e.get('llm_trace', {}).get('usage', {})
            total_tokens += usage.get('total_tokens', 0)
    except: pass

print(f'  Hosts: {len(hosts)} unique')
print(f'  Decisions: {dict(decisions)}')
print(f'  Default caution: {default_caution}')
print(f'  LLM calls: {llm_calls}')
print(f'  Total tokens: {total_tokens:,}')
print()
print('  Top 10 hosts:')
for h, c in hosts.most_common(10):
    print(f'    {c:>4}  {h}')
" 2>/dev/null

    # Watch process RSS summary
    echo -e "\n  ${BOLD}Watch Process RSS:${NC}"
    for rss_file in "$dir"/*-rss.csv; do
        if [ -f "$rss_file" ]; then
            local label
            label=$(basename "$rss_file" -rss.csv)
            local max_rss min_rss
            max_rss=$(awk -F, 'NR>1 && $2+0>0 {print $2}' "$rss_file" | sort -n | tail -1 || echo "?")
            min_rss=$(awk -F, 'NR>1 && $2+0>0 {print $2}' "$rss_file" | sort -n | head -1 || echo "?")
            echo -e "    $label: ${min_rss}MB → ${max_rss}MB"
        fi
    done

    # Hang events
    if [ -f "$RESULTS_DIR/hang.log" ]; then
        echo -e "\n  ${RED}Hang Events:${NC}"
        cat "$RESULTS_DIR/hang.log" | sed 's/^/    /'
    fi

    echo -e "\n  ${DIM}Saved: $dir/merged.jsonl${NC}"
}

# ── Phase Implementations ──

phase1() {
    echo -e "${BOLD}Phase 1: Allow-All Observation (10 min × 3 agents)${NC}"
    echo -e "${DIM}Collecting API call patterns without policy enforcement${NC}\n"

    local dir="$RESULTS_DIR/phase1"

    # Agent 1: GitHub research (predictable)
    run_watch_agent "watch-github" "$dir" "$AGENT_TIMEOUT" "false" \
        "Compare open-source projects torvalds/linux and rust-lang/rust. Fetch their README files from raw.githubusercontent.com, check recent commits via api.github.com, and compare their contributor documentation."

    # Agent 2: Public APIs (moderate variability)
    run_watch_agent "watch-apis" "$dir" "$AGENT_TIMEOUT" "false" \
        "Collect interesting facts from public APIs: get a random cat fact from catfact.ninja, a random dog image from dog.ceo, a number trivia from numbersapi.com, and a random joke from official-joke-api.appspot.com. Compile the results into a fun digest."

    # Agent 3: Free exploration (maximum variability — highest value)
    run_watch_agent "watch-explore" "$dir" "$AGENT_TIMEOUT" "false" \
        "Research the latest developments in AI safety and alignment. Find and summarize 3 recent papers or blog posts. Look at sources like research blogs, paper repositories, and technical discussion forums."

    analyze_phase1 "$dir"
}

phase2() {
    echo -e "${BOLD}Phase 2: Cooperative Mode — With Rules (10 min × 2 agents)${NC}"
    echo -e "${DIM}Applying existing SRR rules while observing — verifying rule accuracy${NC}\n"

    local dir="$RESULTS_DIR/phase2"

    # Re-run the most predictable agent (baseline comparison with Phase 1)
    run_watch_agent "coop-github" "$dir" "$AGENT_TIMEOUT" "true" \
        "Compare open-source projects torvalds/linux and rust-lang/rust. Fetch their README files from raw.githubusercontent.com, check recent commits via api.github.com, and compare their contributor documentation."

    # Re-run the free exploration agent (highest value — will hit unknown hosts with rules active)
    run_watch_agent "coop-explore" "$dir" "$AGENT_TIMEOUT" "true" \
        "Research the latest developments in AI safety and alignment. Find and summarize 3 recent papers or blog posts. Look at sources like research blogs, paper repositories, and technical discussion forums."

    analyze_phase2 "$dir"
}

phase3() {
    echo -e "${BOLD}Phase 3: Long-Run Stability (30 min, 3 concurrent agents)${NC}"
    echo -e "${DIM}Sustained cooperative mode with cost tracking and RSS monitoring${NC}\n"

    local dir="$RESULTS_DIR/phase3"

    # Run 3 agents concurrently (reuse stress workload prompts)
    local prompts=(
        "Compare open-source projects torvalds/linux, rust-lang/rust, golang/go, python/cpython, nodejs/node, and denoland/deno. Fetch READMEs, check contributor docs, fetch recent commits. Rotate through repository pairs every 3 minutes."
        "Collect data from public APIs in rotation: catfact.ninja/fact, dog.ceo/api/breeds/image/random, numbersapi.com/random/trivia, official-joke-api.appspot.com/random_joke. Repeat every 2 minutes and compile a Fun Facts Digest."
        "Technical research: fetch Rust RELEASES.md and Go next-release-notes.md from their GitHub repos. Compare release cadence and feature focus areas. Repeat every 3 minutes alternating with CONTRIBUTING.md and LICENSE analysis."
    )

    local pids=()
    for i in 1 2 3; do
        run_watch_agent "coop-agent-$i" "$dir" "$LONG_TIMEOUT" "true" "${prompts[$((i-1))]}" &
        pids+=($!)
        echo -e "  ${DIM}Staggering 30s before next agent...${NC}"
        sleep 30
    done

    echo -e "\n  ${DIM}Waiting for all agents to complete (up to ${LONG_TIMEOUT}s)...${NC}"
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    analyze_phase3 "$dir"
}

# ── Main ──
main() {
    preflight

    case $PHASE in
        0)
            phase1
            echo ""
            echo -e "${YELLOW}Review Phase 1 results. If unknown hosts need SRR rules, add them now.${NC}"
            echo -e "${YELLOW}Then run: sudo env ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY bash $0 --phase 2${NC}"
            echo ""
            phase2
            echo ""
            echo -e "${YELLOW}Review Phase 2 results. Fix false denies if any.${NC}"
            echo -e "${YELLOW}Then run: sudo env ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY bash $0 --phase 3${NC}"
            echo ""
            phase3
            ;;
        1) phase1 ;;
        2) phase2 ;;
        3) phase3 ;;
        *) echo "Unknown phase: $PHASE (use 0, 1, 2, or 3)"; exit 1 ;;
    esac

    echo -e "\n${BOLD}${GREEN}═══ Discovery Complete ═══${NC}"
    echo -e "Results: $RESULTS_DIR"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. Review unknown hosts: cat $RESULTS_DIR/phase1/unknown-hosts.txt"
    echo -e "  2. Add Allow rules for legitimate hosts to config/srr_network.toml"
    echo -e "  3. Re-run Phase 2 to verify: bash $0 --phase 2"
    echo -e "  4. Run Phase 3 for stability: bash $0 --phase 3"
}

main "$@"
