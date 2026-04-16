#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Docker containment E2E — host-side iptables enforcement
#
# Exercises the full `gvm run --contained` pipeline on a real Linux
# host with Docker + iptables. Validates the core promise of the
# refactor: non-cooperative HTTP clients (Node.js raw https) cannot
# bypass the proxy even without MITM; cooperative clients (Python
# requests) route through the proxy normally.
#
# Requirements: Linux + Docker + iptables + sudo + Python 3 + built
# gvm binaries (`cargo build --release -p gvm-cli -p gvm-proxy`).
#
# Usage:
#   bash scripts/docker-contained-e2e.sh
#
# Exits non-zero on any test failure.
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GVM_BIN="$REPO_DIR/target/release/gvm"
FAIL_COUNT=0
PASS_COUNT=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo -e "  ${DIM}• $1${NC}"; }

cleanup_all() {
    echo ""
    echo "=== Cleanup ==="
    "$GVM_BIN" stop 2>/dev/null || true
    "$GVM_BIN" cleanup 2>/dev/null || true
    # Defense-in-depth: nuke any surviving gvm-docker-* bridges + chains
    for bridge in $(docker network ls --filter name=gvm-docker- --format '{{.Name}}' 2>/dev/null); do
        docker network rm "$bridge" 2>/dev/null || true
    done
    for chain in $(sudo iptables -L -n 2>/dev/null | awk '/^Chain GVM-gvm-docker-/ {print $2}'); do
        sudo iptables -F "$chain" 2>/dev/null || true
        sudo iptables -X "$chain" 2>/dev/null || true
    done
}
trap cleanup_all EXIT

echo "=== Docker containment E2E ==="
[[ -x "$GVM_BIN" ]] || { echo "gvm binary not found — build with cargo first"; exit 1; }
command -v docker >/dev/null || { echo "docker not installed"; exit 1; }
command -v iptables >/dev/null || { echo "iptables not installed"; exit 1; }
# gvm reads config/proxy.toml relative to CWD. Without cd'ing to the
# project root, proxy.log lands in the wrong directory and subsequent
# `gvm run` invocations cannot detect a running proxy.
cd "$REPO_DIR"

# Start orphan cleanup first to clear any stale state from prior runs.
echo ""
echo "--- Pre-flight cleanup ---"
"$GVM_BIN" cleanup 2>&1 | head -5 || true

# ─── Agent scripts ─────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
trap "rm -rf $TMP_DIR; cleanup_all" EXIT

# Python agent — uses requests (HTTP_PROXY-respecting) + raw socket.
# Expected: requests succeeds, raw socket to external IP fails.
cat > "$TMP_DIR/agent_py.py" <<'PYEOF'
import os, socket, sys
import urllib.request

proxy_url = os.environ.get("HTTP_PROXY", "")
print(f"[agent_py] HTTP_PROXY={proxy_url}")

# Test 1: cooperative HTTP (should route via proxy)
try:
    req = urllib.request.Request("http://example.com")
    resp = urllib.request.urlopen(req, timeout=5)
    print(f"[agent_py] PY-PROXY-OK status={resp.status}")
except Exception as e:
    print(f"[agent_py] PY-PROXY-FAIL {type(e).__name__}: {e}")

# Test 2: raw TCP bypass attempt (should be DROPPED by host iptables)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("1.1.1.1", 443))
    s.close()
    print("[agent_py] PY-RAW-LEAK (bypass succeeded — BUG)")
except (TimeoutError, OSError, socket.timeout) as e:
    print(f"[agent_py] PY-RAW-BLOCKED ({type(e).__name__})")

sys.exit(0)
PYEOF

# Node.js agent — uses built-in `https` (ignores HTTP_PROXY by default).
# Expected: https.get to external host fails because host iptables DROPs
# the packet even though the Node.js client never read HTTP_PROXY.
cat > "$TMP_DIR/agent_node.js" <<'JSEOF'
const https = require('https');
const proxyUrl = process.env.HTTP_PROXY || '';
console.log(`[agent_node] HTTP_PROXY=${proxyUrl}`);

const req = https.get('https://1.1.1.1', { timeout: 3000 }, (res) => {
    console.log(`[agent_node] NODE-RAW-LEAK status=${res.statusCode} (bypass succeeded — BUG)`);
    res.resume();
});
req.on('timeout', () => { console.log('[agent_node] NODE-RAW-BLOCKED (timeout)'); req.destroy(); process.exit(0); });
req.on('error',   (e) => { console.log(`[agent_node] NODE-RAW-BLOCKED (${e.code || e.message})`); process.exit(0); });
JSEOF

# ─── Start the proxy ───────────────────────────────────────────────
echo ""
echo "--- Starting gvm proxy ---"
# Use `gvm run` once on a trivial no-op to bring the proxy up.
echo 'print("boot")' > "$TMP_DIR/boot.py"
"$GVM_BIN" run "$TMP_DIR/boot.py" >/dev/null 2>&1 || true
sleep 1

# ─── Test 1: Python cooperative client routes through proxy ────────
echo ""
echo "--- Test 1: Python requests must route through proxy ---"
OUT_PY=$(sudo "$GVM_BIN" run --contained --image python:3.12-slim "$TMP_DIR/agent_py.py" 2>&1 || true)
echo "$OUT_PY" | grep -E 'PY-(PROXY|RAW)-' | sed 's/^/    /'

if echo "$OUT_PY" | grep -q 'PY-PROXY-OK'; then
    pass "Python cooperative HTTP reached target via proxy"
else
    fail "Python cooperative HTTP did not route through proxy"
fi

if echo "$OUT_PY" | grep -q 'PY-RAW-BLOCKED'; then
    pass "Python raw socket to external IP blocked by host iptables"
elif echo "$OUT_PY" | grep -q 'PY-RAW-LEAK'; then
    fail "Python raw socket LEAKED — iptables DROP rule not enforced"
else
    fail "Python raw socket test inconclusive (no marker found)"
fi

# ─── Test 2: Node.js bypass attempt blocked ────────────────────────
echo ""
echo "--- Test 2: Node.js raw HTTPS must be blocked ---"
if command -v node >/dev/null 2>&1; then
    OUT_NODE=$(sudo "$GVM_BIN" run --contained --image node:20-alpine "$TMP_DIR/agent_node.js" 2>&1 || true)
    echo "$OUT_NODE" | grep -E 'NODE-RAW-' | sed 's/^/    /'
    if echo "$OUT_NODE" | grep -q 'NODE-RAW-BLOCKED'; then
        pass "Node.js raw https (HTTP_PROXY-ignoring) blocked by host iptables"
    elif echo "$OUT_NODE" | grep -q 'NODE-RAW-LEAK'; then
        fail "Node.js raw https LEAKED — bypass succeeded (REGRESSION)"
    else
        fail "Node.js raw test inconclusive"
    fi
else
    info "node not installed — skipping Test 2"
fi

# ─── Test 3: Bridge + iptables chain isolation ─────────────────────
echo ""
echo "--- Test 3: iptables rules scoped to gvm-docker-* only ---"
# While the containers above ran, rules should have been installed and
# cleaned up. Now verify no stale rules remain (post-cleanup).
STALE_CHAINS=$(sudo iptables -L -n 2>/dev/null | awk '/^Chain GVM-gvm-docker-/ {print $2}' | wc -l)
STALE_BRIDGES=$(docker network ls --filter name=gvm-docker- --format '{{.Name}}' 2>/dev/null | wc -l)

if [[ "$STALE_CHAINS" -eq 0 ]] && [[ "$STALE_BRIDGES" -eq 0 ]]; then
    pass "No stale GVM Docker chains or bridges after clean exit"
else
    fail "Stale resources: $STALE_CHAINS chains, $STALE_BRIDGES bridges left behind"
fi

# ─── Test 4: DOCKER-USER isolation — other docker traffic unaffected ─
echo ""
echo "--- Test 4: Non-GVM Docker containers unaffected ---"
# Run a plain alpine on default docker0 — must reach the internet unblocked.
OUT_DEFAULT=$(docker run --rm alpine:3.19 sh -c "apk add --no-cache curl >/dev/null 2>&1 && curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://1.1.1.1" 2>&1 || true)
if [[ "$OUT_DEFAULT" == "200" ]] || [[ "$OUT_DEFAULT" == "301" ]]; then
    pass "Default docker network reaches internet normally (no GVM contamination)"
else
    fail "Default docker network blocked — GVM rules leaked outside gvm-docker-* scope (http_code=$OUT_DEFAULT)"
fi

# ─── Test 5: Orphan cleanup recovers from SIGKILL ──────────────────
echo ""
echo "--- Test 5: Orphan cleanup after SIGKILL ---"
# Launch a contained run in background, SIGKILL it mid-run, verify cleanup runs.
sudo "$GVM_BIN" run --contained --image python:3.12-slim --detach "$TMP_DIR/agent_py.py" >/dev/null 2>&1 &
GVM_PID=$!
sleep 1
sudo kill -9 "$GVM_PID" 2>/dev/null || true
sleep 1

# Count stale resources before cleanup
BEFORE_CHAINS=$(sudo iptables -L -n 2>/dev/null | awk '/^Chain GVM-gvm-docker-/ {print $2}' | wc -l)
BEFORE_BRIDGES=$(docker network ls --filter name=gvm-docker- --format '{{.Name}}' 2>/dev/null | wc -l)
info "Before cleanup: $BEFORE_CHAINS chains, $BEFORE_BRIDGES bridges"

sudo "$GVM_BIN" cleanup >/dev/null 2>&1 || true

AFTER_CHAINS=$(sudo iptables -L -n 2>/dev/null | awk '/^Chain GVM-gvm-docker-/ {print $2}' | wc -l)
AFTER_BRIDGES=$(docker network ls --filter name=gvm-docker- --format '{{.Name}}' 2>/dev/null | wc -l)
if [[ "$AFTER_CHAINS" -eq 0 ]] && [[ "$AFTER_BRIDGES" -eq 0 ]]; then
    pass "gvm cleanup swept stale Docker resources after SIGKILL"
else
    fail "Post-cleanup leaked: $AFTER_CHAINS chains, $AFTER_BRIDGES bridges"
fi

# ─── Summary ───────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e "  ${BOLD}Passed:${NC} $PASS_COUNT    ${BOLD}Failed:${NC} $FAIL_COUNT"
echo "═══════════════════════════════════════════════════════════════"

exit "$FAIL_COUNT"
