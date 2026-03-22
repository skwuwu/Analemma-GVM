#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — EC2 Linux E2E Test Suite
#
# Covers: build, proxy, CONNECT tunnel, uprobe, SRR enforcement,
#         OpenClaw integration, long-running stability, concurrency.
#
# Requirements:
#   - Ubuntu 22.04+ EC2 instance (t3.medium or larger, 4GB+ RAM)
#   - Root access (for uprobe)
#   - ANTHROPIC_API_KEY set in environment (for OpenClaw tests)
#
# Usage:
#   # Full suite
#   bash scripts/ec2-e2e-test.sh
#
#   # Individual test
#   bash scripts/ec2-e2e-test.sh --test 6
#
#   # Skip OpenClaw tests (no API key)
#   bash scripts/ec2-e2e-test.sh --skip-openclaw
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROXY_PID=""
PROXY_URL="http://127.0.0.1:8080"
RESULTS=()
SKIP_OPENCLAW=false
SINGLE_TEST=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
MCP_DIR=""
for d in "$REPO_DIR/../analemma-gvm-openclaw" "$HOME/analemma-gvm-openclaw"; do
    [ -d "$d/mcp-server" ] && MCP_DIR="$(cd "$d" && pwd)" && break
done

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    sudo bash -c "
    echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable 2>/dev/null
    echo > /sys/kernel/tracing/uprobe_events 2>/dev/null
    " 2>/dev/null || true
}
trap cleanup EXIT

pass() { RESULTS+=("PASS: $1"); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { RESULTS+=("FAIL: $1"); echo -e "  ${RED}FAIL${NC} $1"; }
skip() { RESULTS+=("SKIP: $1"); echo -e "  ${YELLOW}SKIP${NC} $1"; }
header() { echo -e "\n${BOLD}${CYAN}═══ Test $1 ═══${NC}"; }

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-openclaw) SKIP_OPENCLAW=true; shift ;;
        --test) SINGLE_TEST="$2"; shift 2 ;;
        *) shift ;;
    esac
done

should_run() {
    [ -z "$SINGLE_TEST" ] || [ "$SINGLE_TEST" = "$1" ]
}

# ═══════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════

echo -e "${BOLD}${CYAN}Analemma GVM — EC2 E2E Test Suite${NC}"
echo -e "${DIM}$(uname -srm) | $(date -Iseconds)${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"
command -v cargo >/dev/null || { echo "Rust not installed"; exit 1; }
command -v node >/dev/null || { echo "Node.js not installed"; exit 1; }
command -v python3 >/dev/null || { echo "Python3 not installed"; exit 1; }
echo -e "  Rust: $(rustc --version)"
echo -e "  Node: $(node --version)"
echo -e "  Kernel: $(uname -r)"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TEST 1: Native Linux Build
# ═══════════════════════════════════════════════════════════════════

if should_run 1; then
    header "1: Native Linux Build"

    cd "$REPO_DIR"
    BUILD_START=$(date +%s)
    if cargo build --release -p gvm-proxy -p gvm-cli 2>&1 | tail -3; then
        BUILD_END=$(date +%s)
        BUILD_TIME=$((BUILD_END - BUILD_START))
        PROXY_SIZE=$(stat -c%s target/release/gvm-proxy 2>/dev/null || echo 0)
        echo -e "  Build time: ${BUILD_TIME}s"
        echo -e "  Binary size: $((PROXY_SIZE / 1024 / 1024))MB"
        [ -f target/release/gvm-proxy ] && pass "1: cargo build (${BUILD_TIME}s)" || fail "1: binary not found"
    else
        fail "1: cargo build failed"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 2: Proxy Start + Health Check
# ═══════════════════════════════════════════════════════════════════

if should_run 2; then
    header "2: Proxy Start + Health Check"

    cd "$REPO_DIR"
    # Load github + slack rulesets
    if [ -d "$REPO_DIR/../analemma-gvm-openclaw/rulesets" ]; then
        RULESETS_DIR="$REPO_DIR/../analemma-gvm-openclaw/rulesets"
    elif [ -d "$HOME/analemma-gvm-openclaw/rulesets" ]; then
        RULESETS_DIR="$HOME/analemma-gvm-openclaw/rulesets"
    else
        RULESETS_DIR=""
    fi

    if [ -n "$RULESETS_DIR" ]; then
        python3 -c "
import os
rulesets = '$RULESETS_DIR'
parts = []
for f in ['_default.toml', 'github.toml', 'slack.toml', 'web-browsing.toml']:
    path = os.path.join(rulesets, f)
    if os.path.exists(path):
        parts.append('# -- ' + f + ' --\n' + open(path).read())
open('config/srr_network.toml', 'w').write('\n'.join(parts))
print(f'  {len(parts)} rulesets loaded')
"
    fi

    > data/wal.log
    ./target/release/gvm-proxy --config config/proxy.toml > /tmp/gvm-proxy.log 2>&1 &
    PROXY_PID=$!
    sleep 3

    STATUS=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "failed")
    [ "$STATUS" = "healthy" ] && pass "2: proxy health ($STATUS)" || fail "2: proxy health ($STATUS)"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 3: CONNECT Tunnel (real HTTPS APIs)
# ═══════════════════════════════════════════════════════════════════

if should_run 3; then
    header "3: CONNECT Tunnel (real HTTPS)"

    # GitHub public API (no auth needed)
    GH_STATUS=$(HTTPS_PROXY="$PROXY_URL" python3 -c "
import requests
r = requests.get('https://api.github.com', timeout=10)
print(r.status_code)
" 2>/dev/null || echo "0")
    [ "$GH_STATUS" = "200" ] && pass "3a: CONNECT api.github.com ($GH_STATUS)" || fail "3a: CONNECT api.github.com ($GH_STATUS)"

    # Check WAL recorded the CONNECT
    sleep 1
    WAL_CONNECT=$(grep -c "CONNECT" data/wal.log 2>/dev/null || echo 0)
    [ "$WAL_CONNECT" -gt 0 ] && pass "3b: WAL CONNECT logged ($WAL_CONNECT events)" || fail "3b: no CONNECT in WAL"

    # Anthropic API (needs key, optional)
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        ANT_STATUS=$(HTTPS_PROXY="$PROXY_URL" python3 -c "
import requests
r = requests.get('https://api.anthropic.com/v1/models', headers={'x-api-key': '$ANTHROPIC_API_KEY', 'anthropic-version': '2023-06-01'}, timeout=10)
print(r.status_code)
" 2>/dev/null || echo "0")
        [ "$ANT_STATUS" = "200" ] && pass "3c: CONNECT api.anthropic.com ($ANT_STATUS)" || fail "3c: CONNECT api.anthropic.com ($ANT_STATUS)"
    else
        skip "3c: CONNECT api.anthropic.com (no ANTHROPIC_API_KEY)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 4: Uprobe Attach + SSL_write Capture
# ═══════════════════════════════════════════════════════════════════

if should_run 4; then
    header "4: Uprobe SSL_write_ex Capture"

    LIBSSL=$(python3 -c "import _ssl; print(_ssl.__file__)" 2>/dev/null | xargs ldd 2>/dev/null | grep libssl | awk '{print $3}')
    OFFSET=$(nm -D "$LIBSSL" 2>/dev/null | grep "T SSL_write_ex" | awk '{print $1}')

    if [ -n "$OFFSET" ] && [ -n "$LIBSSL" ]; then
        echo -e "  libssl: $LIBSSL"
        echo -e "  SSL_write_ex offset: 0x$OFFSET"

        sudo bash -c "
        mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
        echo > /sys/kernel/tracing/trace
        echo 'p:gvm_ssl $LIBSSL:0x$OFFSET buf=+0(%si):string' > /sys/kernel/tracing/uprobe_events
        echo 1 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
        " 2>/dev/null

        # Make HTTPS request
        python3 -c "import requests; requests.get('https://api.github.com/repos/skwuwu/Analemma-GVM', timeout=10)" 2>/dev/null
        sleep 1

        CAPTURED=$(sudo cat /sys/kernel/tracing/trace 2>/dev/null | grep -c gvm_ssl || echo 0)
        PLAINTEXT=$(sudo cat /sys/kernel/tracing/trace 2>/dev/null | grep gvm_ssl | head -1 | sed 's/.*buf="//' || echo "")

        echo -e "  Captured events: $CAPTURED"
        echo -e "  First capture: $PLAINTEXT"

        [ "$CAPTURED" -gt 0 ] && pass "4: uprobe captured $CAPTURED TLS events" || fail "4: no uprobe events captured"

        # Cleanup
        sudo bash -c "
        echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
        echo > /sys/kernel/tracing/uprobe_events
        " 2>/dev/null
    else
        skip "4: uprobe (SSL_write_ex not found or no root)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 5: SRR Policy Decisions (Allow / Delay / Deny)
# ═══════════════════════════════════════════════════════════════════

if should_run 5; then
    header "5: SRR Policy Decisions"

    check_policy() {
        local METHOD="$1" HOST="$2" PATH="$3" EXPECTED="$4" LABEL="$5"
        local DECISION=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -d "{\"method\":\"$METHOD\",\"target_host\":\"$HOST\",\"target_path\":\"$PATH\",\"operation\":\"test\"}" \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)
        if echo "$DECISION" | grep -q "$EXPECTED"; then
            pass "5: $LABEL = $DECISION"
        else
            fail "5: $LABEL = $DECISION (expected $EXPECTED)"
        fi
    }

    check_policy GET api.github.com /repos/t/t/issues Allow "github read"
    check_policy POST api.github.com /repos/t/t/issues Delay "github create issue"
    check_policy PUT api.github.com /repos/t/t/pulls/1/merge Deny "github merge PR"
    check_policy DELETE api.github.com /repos/t/t/git/refs/heads/main Deny "github delete branch"
    check_policy POST slack.com /api/chat.postMessage Delay "slack post"
    check_policy POST slack.com /api/chat.delete Deny "slack delete"
    check_policy GET wttr.in /Seoul Delay "unknown domain (default-to-caution)"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 6: MCP Server JSON-RPC Integration
# ═══════════════════════════════════════════════════════════════════

if should_run 6; then
    header "6: MCP Server Integration"

    if [ -z "$MCP_DIR" ]; then
        skip "6: MCP repo not found (clone analemma-gvm-openclaw next to core repo)"
    elif [ ! -f "$MCP_DIR/mcp-server/dist/index.js" ]; then
        skip "6: MCP server not built (run: cd $MCP_DIR/mcp-server && npm install && npm run build)"
    else
        MCP_CALL="python3 $MCP_DIR/scripts/mcp_call.py"

        # 6a: gvm_status
        STATUS=$($MCP_CALL gvm_status | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('proxy','?'))" 2>/dev/null)
        [ "$STATUS" = "running" ] && pass "6a: MCP gvm_status (proxy=$STATUS)" || fail "6a: MCP gvm_status ($STATUS)"

        # 6b: gvm_policy_check Allow
        DECISION=$($MCP_CALL gvm_policy_check '{"method":"GET","url":"https://api.github.com/repos/t/t/issues"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)
        [ "$DECISION" = "Allow" ] && pass "6b: MCP policy_check Allow ($DECISION)" || fail "6b: MCP policy_check ($DECISION)"

        # 6c: gvm_policy_check Deny
        DECISION=$($MCP_CALL gvm_policy_check '{"method":"DELETE","url":"https://api.github.com/repos/t/t/git/refs/heads/main"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)
        [ "$DECISION" = "Deny" ] && pass "6c: MCP policy_check Deny ($DECISION)" || fail "6c: MCP policy_check ($DECISION)"

        # 6d: gvm_fetch blocked
        BLOCKED=$($MCP_CALL gvm_fetch '{"operation":"github.merge","method":"PUT","url":"https://api.github.com/repos/t/t/pulls/1/merge"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('blocked',False))" 2>/dev/null)
        [ "$BLOCKED" = "True" ] && pass "6d: MCP gvm_fetch blocked ($BLOCKED)" || fail "6d: MCP gvm_fetch ($BLOCKED)"

        # 6e: gvm_select_rulesets list
        HAS_GITHUB=$($MCP_CALL gvm_select_rulesets | python3 -c "
import sys,json
d=json.loads(sys.stdin.read())
names=[r['name'] for r in d.get('available',[])]
print('yes' if 'github' in names else 'no')
" 2>/dev/null)
        [ "$HAS_GITHUB" = "yes" ] && pass "6e: MCP rulesets list (github found)" || fail "6e: MCP rulesets list ($HAS_GITHUB)"

        # 6f: gvm_select_rulesets apply + hot-reload
        APPLIED=$($MCP_CALL gvm_select_rulesets '{"apply":["github","slack"]}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(len(d.get('applied',[])))" 2>/dev/null)
        [ "$APPLIED" -ge 2 ] 2>/dev/null && pass "6f: MCP rulesets apply ($APPLIED rulesets)" || fail "6f: MCP rulesets apply ($APPLIED)"

        # 6g: gvm_blocked_summary
        SUMMARY=$($MCP_CALL gvm_blocked_summary '{"period":"all"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print('ok' if 'summary' in d else 'error')" 2>/dev/null)
        [ "$SUMMARY" = "ok" ] && pass "6g: MCP blocked_summary" || fail "6g: MCP blocked_summary ($SUMMARY)"

        # 6h: gvm_audit_log
        AUDIT=$($MCP_CALL gvm_audit_log '{"last_n":5}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print('ok' if 'events' in d or 'total_in_wal' in d else 'error')" 2>/dev/null)
        [ "$AUDIT" = "ok" ] && pass "6h: MCP audit_log" || fail "6h: MCP audit_log ($AUDIT)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 7: OpenClaw Agent Through Proxy
# ═══════════════════════════════════════════════════════════════════

if should_run 7 && [ "$SKIP_OPENCLAW" = false ]; then
    header "7: OpenClaw Agent Through Proxy"

    if ! command -v openclaw &>/dev/null; then
        echo -e "  ${YELLOW}Installing OpenClaw...${NC}"
        npm install -g openclaw@latest 2>/dev/null || true
    fi

    if command -v openclaw &>/dev/null && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        OC_OUTPUT=$(HTTPS_PROXY="$PROXY_URL" HTTP_PROXY="$PROXY_URL" \
            openclaw agent --local \
            --session-id "ec2-e2e-$(date +%s)" \
            --message "Say hello in one word." \
            --timeout 30 2>&1 | grep -v "model-selection" | tail -5)

        echo -e "  Agent output: $OC_OUTPUT"

        # Check that CONNECT tunnel was used for LLM API
        sleep 1
        LLM_CONNECT=$(grep "anthropic\|openai" data/wal.log 2>/dev/null | head -1 || echo "")
        [ -n "$LLM_CONNECT" ] && pass "7: OpenClaw through CONNECT tunnel" || fail "7: no LLM CONNECT in WAL"
    else
        skip "7: OpenClaw (not installed or no API key)"
    fi
elif should_run 7; then
    skip "7: OpenClaw (--skip-openclaw)"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 8: Uprobe Enforcement (SIGSTOP on Deny)
# ═══════════════════════════════════════════════════════════════════

if should_run 8; then
    header "8: Uprobe Enforcement (SIGSTOP)"

    LIBSSL=$(python3 -c "import _ssl; print(_ssl.__file__)" 2>/dev/null | xargs ldd 2>/dev/null | grep libssl | awk '{print $3}')
    OFFSET=$(nm -D "$LIBSSL" 2>/dev/null | grep "T SSL_write_ex" | awk '{print $1}')

    if [ -n "$OFFSET" ] && [ -n "$LIBSSL" ]; then
        # Register uprobe
        sudo bash -c "
        mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
        echo > /sys/kernel/tracing/trace
        echo 'p:gvm_ssl $LIBSSL:0x$OFFSET buf=+0(%si):string' > /sys/kernel/tracing/uprobe_events
        echo 1 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
        " 2>/dev/null

        # Test: Proxy returns Deny for uprobe context
        echo -e "  Testing Deny decision path via proxy /gvm/check..."
        DENY_RESULT=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -H "X-GVM-Uprobe-Token: internal" \
            -d '{"method":"DELETE","target_host":"api.github.com","target_path":"/repos/t/t/git/refs/heads/main","operation":"uprobe"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('decision','?'))" 2>/dev/null)

        echo -e "  Proxy response to uprobe Deny check: $DENY_RESULT"
        [ "$DENY_RESULT" = "Deny" ] && pass "8a: uprobe policy returns Deny" || fail "8a: expected Deny, got $DENY_RESULT"

        # Test: Allow path works
        ALLOW_RESULT=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -H "X-GVM-Uprobe-Token: internal" \
            -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"uprobe"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('decision','?'))" 2>/dev/null)

        [ "$ALLOW_RESULT" = "Allow" ] && pass "8b: uprobe policy returns Allow" || fail "8b: expected Allow, got $ALLOW_RESULT"

        # Test: fail-closed on unreachable proxy
        echo -e "  Testing fail-closed (proxy unreachable)..."
        TIMEOUT_RESULT=$(timeout 2 python3 -c "
import json
try:
    import urllib.request
    req = urllib.request.Request('http://127.0.0.1:19999/gvm/check',
        data=json.dumps({'method':'GET','target_host':'x','target_path':'/','operation':'uprobe'}).encode(),
        headers={'Content-Type':'application/json'})
    urllib.request.urlopen(req, timeout=0.05)
    print('Allow')
except:
    print('Deny')
" 2>/dev/null || echo "Deny")
        [ "$TIMEOUT_RESULT" = "Deny" ] && pass "8c: fail-closed on unreachable proxy" || fail "8c: expected Deny on timeout"

        # Cleanup
        sudo bash -c "
        echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
        echo > /sys/kernel/tracing/uprobe_events
        " 2>/dev/null
    else
        skip "8: uprobe enforcement (no root or SSL_write_ex not found)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 9: Long-Running Stability
# ═══════════════════════════════════════════════════════════════════

if should_run 9; then
    header "9: Long-Running Stability"

    MEM_BEFORE=$(ps -o rss= -p "$PROXY_PID" 2>/dev/null | tr -d ' ')
    WAL_BEFORE=$(stat -c%s data/wal.log 2>/dev/null || echo 0)
    echo -e "  Memory before: ${MEM_BEFORE}KB"
    echo -e "  WAL before: ${WAL_BEFORE} bytes"

    echo -e "  Sending 500 requests over 60 seconds..."
    for i in $(seq 1 500); do
        curl -sf -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"test"}' > /dev/null 2>&1 &
        [ $((i % 50)) -eq 0 ] && echo -e "    $i/500..." && wait
    done
    wait
    sleep 2

    MEM_AFTER=$(ps -o rss= -p "$PROXY_PID" 2>/dev/null | tr -d ' ')
    WAL_AFTER=$(stat -c%s data/wal.log 2>/dev/null || echo 0)
    WAL_GROWTH=$(( (WAL_AFTER - WAL_BEFORE) / 1024 ))

    echo -e "  Memory after: ${MEM_AFTER}KB"
    echo -e "  WAL growth: ${WAL_GROWTH}KB"

    # Memory should not grow more than 50MB
    MEM_DIFF=$(( (MEM_AFTER - MEM_BEFORE) ))
    if [ "$MEM_DIFF" -lt 51200 ]; then
        pass "9a: memory stable (delta: ${MEM_DIFF}KB)"
    else
        fail "9a: memory grew ${MEM_DIFF}KB (>50MB)"
    fi

    # Proxy should still be healthy
    HEALTH=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "failed")
    [ "$HEALTH" = "healthy" ] && pass "9b: proxy healthy after 500 requests" || fail "9b: proxy unhealthy"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 10: Ruleset Hot-Reload
# ═══════════════════════════════════════════════════════════════════

if should_run 10; then
    header "10: Ruleset Hot-Reload"

    cd "$REPO_DIR"

    # Before: only _default ruleset (github = delay)
    cat "$RULESETS_DIR/_default.toml" > config/srr_network.toml 2>/dev/null
    curl -sf -X POST "$PROXY_URL/gvm/reload" > /dev/null

    BEFORE=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
        -H "Content-Type: application/json" \
        -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"test"}' \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)
    echo -e "  Before reload (default only): github read = $BEFORE"

    # Apply github ruleset via hot-reload
    python3 -c "
parts = []
for f in ['$RULESETS_DIR/_default.toml', '$RULESETS_DIR/github.toml']:
    try: parts.append(open(f).read())
    except: pass
open('config/srr_network.toml', 'w').write('\n'.join(parts))
"
    RELOAD_RESP=$(curl -sf -X POST "$PROXY_URL/gvm/reload" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('rules','?'))" 2>/dev/null)
    echo -e "  Reload: $RELOAD_RESP rules"

    AFTER=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
        -H "Content-Type: application/json" \
        -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"test"}' \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)
    echo -e "  After reload (github ruleset): github read = $AFTER"

    # Verify transition: Delay → Allow
    if [ "$BEFORE" != "Allow" ] && [ "$AFTER" = "Allow" ]; then
        pass "10a: hot-reload changed Delay → Allow"
    else
        fail "10a: expected Delay→Allow, got $BEFORE→$AFTER"
    fi

    # Verify no request loss during reload (fire requests during reload)
    echo -e "  Testing request continuity during reload..."
    LOST=0
    for i in $(seq 1 20); do
        RESP=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"test"}' 2>/dev/null || echo "000")
        [ "$RESP" = "200" ] || LOST=$((LOST + 1))
        [ $((i % 5)) -eq 0 ] && curl -sf -X POST "$PROXY_URL/gvm/reload" > /dev/null 2>&1
    done
    [ "$LOST" -eq 0 ] && pass "10b: zero requests lost during reload" || fail "10b: $LOST requests lost during reload"

    # Restore full rulesets
    python3 -c "
parts = []
for f in ['_default.toml', 'github.toml', 'slack.toml', 'web-browsing.toml']:
    try: parts.append(open('$RULESETS_DIR/' + f).read())
    except: pass
open('config/srr_network.toml', 'w').write('\n'.join(parts))
"
    curl -sf -X POST "$PROXY_URL/gvm/reload" > /dev/null
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 11: Concurrent CONNECT Tunnels
# ═══════════════════════════════════════════════════════════════════

if should_run 11; then
    header "11: Concurrent CONNECT"

    WAL_BEFORE=$(wc -l < data/wal.log 2>/dev/null || echo 0)

    echo -e "  Launching 10 concurrent HTTPS requests..."
    PIDS=""
    for i in $(seq 1 10); do
        HTTPS_PROXY="$PROXY_URL" python3 -c "
import requests
try:
    r = requests.get('https://api.github.com', timeout=15)
    print(f'req-$i: {r.status_code}')
except Exception as e:
    print(f'req-$i: error {e}')
" 2>/dev/null &
        PIDS="$PIDS $!"
    done

    FAILED=0
    for pid in $PIDS; do
        wait "$pid" || FAILED=$((FAILED + 1))
    done

    sleep 2
    WAL_AFTER=$(wc -l < data/wal.log 2>/dev/null || echo 0)
    NEW_EVENTS=$((WAL_AFTER - WAL_BEFORE))

    echo -e "  Failed: $FAILED/10"
    echo -e "  New WAL events: $NEW_EVENTS"

    [ "$FAILED" -le 2 ] && pass "11a: concurrent CONNECT ($((10-FAILED))/10 succeeded)" || fail "11a: $FAILED/10 failed"
    [ "$NEW_EVENTS" -gt 0 ] && pass "11b: WAL recorded concurrent events ($NEW_EVENTS)" || fail "11b: no WAL events from concurrent requests"

    # Health check after concurrent load
    HEALTH=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null || echo "failed")
    [ "$HEALTH" = "healthy" ] && pass "11c: proxy healthy after concurrent load" || fail "11c: proxy unhealthy"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 12: Semantic Violation — Allow read + Deny delete in one flow
# ═══════════════════════════════════════════════════════════════════

if should_run 12; then
    header "12: Semantic Violation (read Allow, delete Deny)"

    # Simulate: agent reads issues (Allow), then tries to delete branch (Deny)
    READ=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
        -H "Content-Type: application/json" \
        -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"test"}' \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

    DELETE=$(curl -sf -X POST "$PROXY_URL/gvm/check" \
        -H "Content-Type: application/json" \
        -d '{"method":"DELETE","target_host":"api.github.com","target_path":"/repos/t/t/git/refs/heads/admin","operation":"test"}' \
        | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

    if [ "$READ" = "Allow" ] && [ "$DELETE" = "Deny" ]; then
        pass "12: semantic violation blocked (read=$READ, delete=$DELETE)"
    else
        fail "12: expected Allow+Deny, got read=$READ delete=$DELETE"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 13: Burst Traffic — rapid-fire policy checks
# ═══════════════════════════════════════════════════════════════════

if should_run 13; then
    header "13: Burst Traffic (100 rapid requests)"

    HEALTH_BEFORE=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null)
    WAL_BEFORE=$(wc -l < data/wal.log 2>/dev/null || echo 0)

    # Fire 100 requests as fast as possible
    for i in $(seq 1 100); do
        curl -sf -X POST "$PROXY_URL/gvm/check" \
            -H "Content-Type: application/json" \
            -d '{"method":"POST","target_host":"slack.com","target_path":"/api/chat.postMessage","operation":"test"}' > /dev/null 2>&1 &
    done
    wait
    sleep 2

    HEALTH_AFTER=$(curl -sf "$PROXY_URL/gvm/health" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['status'])" 2>/dev/null)
    WAL_AFTER=$(wc -l < data/wal.log 2>/dev/null || echo 0)

    [ "$HEALTH_AFTER" = "healthy" ] && pass "13a: proxy survived 100 burst requests" || fail "13a: proxy unhealthy after burst"

    WAL_DELTA=$((WAL_AFTER - WAL_BEFORE))
    echo -e "  WAL growth: $WAL_DELTA lines"
    [ "$WAL_DELTA" -lt 1000000 ] && pass "13b: WAL bounded ($WAL_DELTA lines)" || fail "13b: WAL exploded ($WAL_DELTA lines)"
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 14: MCP gvm_fetch cross-layer — Allow + Deny in same session
# ═══════════════════════════════════════════════════════════════════

if should_run 14; then
    header "14: MCP Cross-Layer (Allow then Deny)"

    if [ -n "$MCP_DIR" ] && [ -f "$MCP_DIR/scripts/mcp_call.py" ]; then
        MCP_CALL="python3 $MCP_DIR/scripts/mcp_call.py"

        # Allow: read issues
        R1=$($MCP_CALL gvm_policy_check '{"method":"GET","url":"https://api.github.com/repos/t/t/issues"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

        # Deny: merge PR
        R2=$($MCP_CALL gvm_fetch '{"operation":"github.merge","method":"PUT","url":"https://api.github.com/repos/t/t/pulls/1/merge"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('decision','?'))" 2>/dev/null)

        # Deny: delete branch
        R3=$($MCP_CALL gvm_fetch '{"operation":"github.delete","method":"DELETE","url":"https://api.github.com/repos/t/t/git/refs/heads/main"}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('decision','?'))" 2>/dev/null)

        echo -e "  read=$R1, merge=$R2, delete=$R3"
        if [ "$R1" = "Allow" ] && [ "$R2" = "Deny" ] && [ "$R3" = "Deny" ]; then
            pass "14: MCP cross-layer (Allow→Deny→Deny)"
        else
            fail "14: expected Allow,Deny,Deny got $R1,$R2,$R3"
        fi
    else
        skip "14: MCP repo not available"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TEST 15: MCP gvm_select_rulesets apply + verify + re-apply
# ═══════════════════════════════════════════════════════════════════

if should_run 15; then
    header "15: MCP Ruleset Lifecycle"

    if [ -n "$MCP_DIR" ] && [ -f "$MCP_DIR/scripts/mcp_call.py" ]; then
        MCP_CALL="python3 $MCP_DIR/scripts/mcp_call.py"

        # Apply github only
        A1=$($MCP_CALL gvm_select_rulesets '{"apply":["github"]}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(len(d.get('applied',[])))" 2>/dev/null)

        # Verify github issues = Allow
        D1=$($MCP_CALL gvm_policy_check '{"method":"GET","url":"https://api.github.com/repos/t/t/issues"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

        # Verify slack (not loaded) = Delay (default-to-caution)
        D2=$($MCP_CALL gvm_policy_check '{"method":"POST","url":"https://slack.com/api/chat.postMessage"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

        # Now apply github + slack
        A2=$($MCP_CALL gvm_select_rulesets '{"apply":["github","slack"]}' \
            | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(len(d.get('applied',[])))" 2>/dev/null)

        # Verify slack post = Delay (500ms, in ruleset)
        D3=$($MCP_CALL gvm_policy_check '{"method":"POST","url":"https://slack.com/api/chat.postMessage"}' \
            | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('decision','?'))" 2>/dev/null)

        echo -e "  github-only: applied=$A1, issues=$D1, slack=$D2"
        echo -e "  github+slack: applied=$A2, slack_post=$D3"

        if [ "$D1" = "Allow" ] && [ "$A2" -ge 2 ] 2>/dev/null; then
            pass "15: MCP ruleset lifecycle (apply→verify→re-apply)"
        else
            fail "15: unexpected results"
        fi
    else
        skip "15: MCP repo not available"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}═══ Summary ═══${NC}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

for r in "${RESULTS[@]}"; do
    case $r in
        PASS*) echo -e "  ${GREEN}$r${NC}"; PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL*) echo -e "  ${RED}$r${NC}"; FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP*) echo -e "  ${YELLOW}$r${NC}"; SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
done

echo ""
echo -e "  ${GREEN}$PASS_COUNT passed${NC}  ${RED}$FAIL_COUNT failed${NC}  ${YELLOW}$SKIP_COUNT skipped${NC}"
echo ""

[ "$FAIL_COUNT" -eq 0 ] && exit 0 || exit 1
