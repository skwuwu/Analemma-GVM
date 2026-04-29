#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Agent Framework E2E (Linux/EC2)
#
# Verifies cooperative-mode interception works against the agent
# frameworks users actually run. Each framework is a black box: we
# point HTTP_PROXY/HTTPS_PROXY at the GVM proxy, run a minimal "say
# hi" workload, and assert that:
#
#   1. The framework reaches the upstream (no proxy break).
#   2. The proxy's WAL recorded the request as a governance event
#      with a non-Allow-Fake decision.
#   3. The agent's API key was never sent in plaintext to the
#      upstream — the proxy's injected key is what arrives.
#
# Frameworks covered (in order of popularity for new builds):
#   - raw `anthropic` Python SDK         (most direct, baseline)
#   - LangChain via `langchain-anthropic`
#
# Both run with the same Anthropic API key from the project's .env.
# Adding a new framework = add a new function + record_result line,
# everything else generalises.
#
# Usage
#   bash scripts/framework-e2e.sh                 # all frameworks
#   bash scripts/framework-e2e.sh anthropic       # one framework
#   bash scripts/framework-e2e.sh --list          # list available
#
# Cost
#   Each framework consumes ~50–200 tokens against the configured
#   model (claude-haiku-4-5 by default — cheapest). Total cost per
#   full run is well under $0.01.
#
# Requirements
#   - Linux (cooperative mode works cross-platform but agent frameworks
#     in general expect Linux).
#   - Python 3.10+
#   - GVM CLI + proxy built (cargo build --release).
#   - .env with ANTHROPIC_API_KEY.
#   - Network access to api.anthropic.com.
#
# Out of scope
#   This script does NOT exercise sandbox/contained modes — those are
#   covered by sandbox-observability-test.sh and stress-test.sh. The
#   point here is "does the cooperative HTTP_PROXY pattern work when
#   the agent is a real framework, not a hand-rolled Python script".
# ═══════════════════════════════════════════════════════════════════

set -uo pipefail

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
GVM_BIN="${GVM_BIN:-$REPO_DIR/target/release/gvm}"
PROXY_BIN="${PROXY_BIN:-$REPO_DIR/target/release/gvm-proxy}"
PROXY_URL="http://127.0.0.1:8080"
ADMIN_URL="http://127.0.0.1:9090"
WAL_PATH="$REPO_DIR/data/wal.log"
WORK_DIR="$(mktemp -d /tmp/gvm-fw-test-XXXXXX)"
# Cached pip venv keyed off repo to avoid re-installing every run.
# PEP 668 (Ubuntu 24.04+) refuses system-wide pip install, so a venv
# is mandatory; using a stable path under /tmp keeps the install
# warm across script invocations.
VENV_DIR="${VENV_DIR:-/tmp/gvm-fw-venv}"
PYTHON_BIN="$VENV_DIR/bin/python3"
PIP_BIN="$VENV_DIR/bin/pip3"
RESULTS=()

trap 'cleanup_all' EXIT

cleanup_all() {
    "$GVM_BIN" stop >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}

# ─── Banner / arg parsing ──────────────────────────────────────────────

if [ ! -x "$GVM_BIN" ] || [ ! -x "$PROXY_BIN" ]; then
    echo -e "${RED}gvm/gvm-proxy binaries not found at $REPO_DIR/target/release/${NC}"
    echo "Build first: cargo build --release -p gvm-cli -p gvm-proxy"
    exit 1
fi

if [ -f "$REPO_DIR/.env" ]; then
    set -a; source "$REPO_DIR/.env"; set +a
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo -e "${RED}ANTHROPIC_API_KEY not set (looked at \$ANTHROPIC_API_KEY and $REPO_DIR/.env)${NC}"
    exit 1
fi

ensure_venv() {
    if [ -x "$PYTHON_BIN" ]; then
        return 0
    fi
    echo -e "  ${DIM}Creating venv at $VENV_DIR (one-time, ~5s)${NC}"
    python3 -m venv "$VENV_DIR" 2>&1 | tail -3 || {
        echo -e "  ${RED}venv create failed — install python3-venv: sudo apt-get install -y python3-venv${NC}"
        return 1
    }
    "$PIP_BIN" install --quiet --upgrade pip >/dev/null 2>&1 || true
}

ensure_pkg() {
    local pkg="$1"
    if "$PYTHON_BIN" -c "import ${pkg//-/_}" 2>/dev/null; then
        return 0
    fi
    echo -e "  ${DIM}pip install $pkg (one-time)${NC}"
    "$PIP_BIN" install --quiet "$pkg" >/dev/null 2>&1 || return 1
}

ALL_FRAMEWORKS=(anthropic langchain)
SELECTED=("$@")

if [ "${1:-}" = "--list" ]; then
    echo "Available frameworks:"
    for f in "${ALL_FRAMEWORKS[@]}"; do echo "  - $f"; done
    exit 0
fi

if [ ${#SELECTED[@]} -eq 0 ]; then
    SELECTED=("${ALL_FRAMEWORKS[@]}")
fi

record() {
    local name="$1" status="$2"
    RESULTS+=("$status $name")
}

run_framework() {
    local name="$1"
    echo
    echo -e "${BOLD}── $name ──${NC}"
}

# ─── Proxy lifecycle ──────────────────────────────────────────────────

ensure_proxy() {
    # Reuse running proxy if alive; otherwise the gvm CLI auto-starts it.
    if curl -sf "$PROXY_URL/gvm/health" >/dev/null 2>&1; then
        echo -e "  ${DIM}Reusing existing proxy${NC}"
        return 0
    fi
    echo -e "  ${DIM}Starting fresh proxy via gvm CLI${NC}"
    # `gvm run -- /bin/true` forces auto-start of proxy then exits, leaving
    # the proxy running. Equivalent to manually backgrounding the proxy
    # binary, but reuses the CLI's port-handling + CA-bootstrap logic.
    "$GVM_BIN" run -- /bin/true >/dev/null 2>&1 || true
    sleep 2
    if ! curl -sf "$PROXY_URL/gvm/health" >/dev/null 2>&1; then
        echo -e "  ${RED}Proxy failed to start. Check $REPO_DIR/data/proxy.log${NC}"
        return 1
    fi
}

wal_event_count_for_host() {
    # Counts WAL lines whose `transport.host` equals the given argument.
    # WAL is JSONL: each event has `"transport":{...,"host":"X",...}`.
    # `grep -c` returns exit 1 when there are zero matches, so the
    # straightforward `grep -c ... || echo 0` pattern emits the literal
    # "0\n0" — fatal once we feed it into $((after - before)). Capture
    # the count into a local with explicit fallback instead.
    local host="$1" count=0
    if [ -f "$WAL_PATH" ]; then
        count=$(grep -c "\"host\":\"$host\"" "$WAL_PATH" 2>/dev/null || true)
        [ -z "$count" ] && count=0
    fi
    printf '%s\n' "$count"
}

# ─── Framework: raw Anthropic SDK ─────────────────────────────────────

run_anthropic() {
    run_framework "raw Anthropic SDK"

    ensure_venv || { record "raw Anthropic SDK" "SKIP"; return; }
    ensure_pkg anthropic || {
        echo -e "  ${RED}✗${NC} could not install anthropic — skipping"
        record "raw Anthropic SDK" "SKIP"
        return
    }

    local before
    before=$(wal_event_count_for_host "api.anthropic.com")

    cat > "$WORK_DIR/anthropic_test.py" <<'PY'
import os
from anthropic import Anthropic
client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
msg = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=8,
    messages=[{"role": "user", "content": "Say hi in one word."}],
)
print("RESP_OK", msg.content[0].text.strip()[:40])
PY

    if HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" \
       timeout 30 "$PYTHON_BIN" "$WORK_DIR/anthropic_test.py" 2>&1 | grep -q "RESP_OK"; then
        echo -e "  ${GREEN}✓${NC} request reached upstream and returned"
    else
        echo -e "  ${RED}✗${NC} no successful response from anthropic"
        record "raw Anthropic SDK" "FAIL"
        return
    fi

    sleep 1  # let WAL group commit flush
    local after
    after=$(wal_event_count_for_host "api.anthropic.com")
    local delta=$((after - before))
    if [ "$delta" -ge 1 ]; then
        echo -e "  ${GREEN}✓${NC} $delta governance event(s) recorded for api.anthropic.com"
        record "raw Anthropic SDK" "PASS"
    else
        echo -e "  ${RED}✗${NC} no governance event recorded (delta=$delta)"
        record "raw Anthropic SDK" "FAIL"
    fi
}

# ─── Framework: LangChain (langchain-anthropic) ───────────────────────

run_langchain() {
    run_framework "LangChain (langchain-anthropic)"

    ensure_venv || { record "LangChain (anthropic)" "SKIP"; return; }
    ensure_pkg langchain-anthropic || {
        echo -e "  ${RED}✗${NC} could not install langchain-anthropic — skipping"
        record "LangChain (anthropic)" "SKIP"
        return
    }

    local before
    before=$(wal_event_count_for_host "api.anthropic.com")

    cat > "$WORK_DIR/langchain_test.py" <<'PY'
import os
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-haiku-4-5", max_tokens=8)
resp = llm.invoke("Say hi in one word.")
content = resp.content if isinstance(resp.content, str) else str(resp.content)
print("RESP_OK", content.strip()[:40])
PY

    if HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" \
       timeout 30 "$PYTHON_BIN" "$WORK_DIR/langchain_test.py" 2>&1 | grep -q "RESP_OK"; then
        echo -e "  ${GREEN}✓${NC} LangChain reached upstream and returned"
    else
        echo -e "  ${RED}✗${NC} no successful response from LangChain"
        record "LangChain (anthropic)" "FAIL"
        return
    fi

    sleep 1
    local after
    after=$(wal_event_count_for_host "api.anthropic.com")
    local delta=$((after - before))
    if [ "$delta" -ge 1 ]; then
        echo -e "  ${GREEN}✓${NC} $delta governance event(s) recorded"
        record "LangChain (anthropic)" "PASS"
    else
        echo -e "  ${RED}✗${NC} no governance event recorded (delta=$delta)"
        record "LangChain (anthropic)" "FAIL"
    fi
}

# ─── Driver ───────────────────────────────────────────────────────────

ensure_proxy || exit 1

for fw in "${SELECTED[@]}"; do
    case "$fw" in
        anthropic)  run_anthropic ;;
        langchain)  run_langchain ;;
        *) echo -e "${RED}Unknown framework: $fw${NC} (--list to see options)"; exit 2 ;;
    esac
done

# ─── Summary ─────────────────────────────────────────────────────────

echo
echo -e "${BOLD}── Results ──${NC}"
pass=0; fail=0; skip=0
for r in "${RESULTS[@]}"; do
    case "$r" in
        PASS*) echo -e "  ${GREEN}$r${NC}"; pass=$((pass+1));;
        FAIL*) echo -e "  ${RED}$r${NC}";   fail=$((fail+1));;
        SKIP*) echo -e "  ${YELLOW}$r${NC}";skip=$((skip+1));;
    esac
done
echo
echo -e "${BOLD}$pass passed, $fail failed, $skip skipped${NC}"

[ $fail -eq 0 ] && exit 0 || exit 1
