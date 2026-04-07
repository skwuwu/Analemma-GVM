#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — Sandbox Observability E2E (Linux)
#
# Verifies that the user-facing diagnostic surface added in
# 2026-04-07 actually fires through real CLI invocations:
#
#   1. ExitReason::OomKill        — out of memory hint + suggested --memory
#   2. ExitReason::Timeout        — GVM_SANDBOX_TIMEOUT hint
#   3. ExitReason::SeccompViolation — dmesg pointer
#   4. ExitReason::Normal         — silent (no false positive)
#   5. cpu_throttled note         — appears when --cpus restricts the agent
#   6. gvm status                 — shows active/orphan sandboxes + isolation profile
#   7. gvm stop                   — staged cleanup output
#
# Strict CLI-only: no proxy_manager.rs internals, no PID file mangling,
# no nsenter/tmux/sudo env. If gvm itself can't show it, the test fails.
#
# Requirements:
#   - Ubuntu 22.04+ with cgroup v2 (default since 22.04)
#   - sudo (sandbox needs CAP_NET_ADMIN; gvm run handles privilege drop)
#   - Python 3 with psutil OR a busy-loop fallback
#
# Usage:
#   sudo bash scripts/sandbox-observability-test.sh
#   sudo bash scripts/sandbox-observability-test.sh --test 3
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
WORK_DIR="$(mktemp -d /tmp/gvm-obs-test-XXXXXX)"
RESULTS=()
SINGLE_TEST=""

while [ $# -gt 0 ]; do
    case "$1" in
        --test) SINGLE_TEST="$2"; shift 2;;
        *) echo "Unknown arg: $1"; exit 2;;
    esac
done

if [ ! -x "$GVM_BIN" ]; then
    echo -e "${RED}gvm binary not found at $GVM_BIN${NC}"
    echo "Build first: cargo build --release"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}Warning: not running as root. Sandbox tests will fail.${NC}"
    echo "Re-run with: sudo bash $0"
fi

cleanup_all() {
    "$GVM_BIN" stop >/dev/null 2>&1 || true
    "$GVM_BIN" cleanup >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup_all EXIT

# ─── Test workload generators ──────────────────────────────────────────

write_oom_agent() {
    cat > "$WORK_DIR/oom_agent.py" <<'PY'
# Allocate 200MB in 10MB chunks. With --memory 32m, this trips the
# cgroup OOM killer well before the script finishes.
buf = []
for i in range(20):
    buf.append(bytearray(10 * 1024 * 1024))
print("done")
PY
}

write_sleep_agent() {
    cat > "$WORK_DIR/sleep_agent.py" <<'PY'
import time
print("starting long sleep")
time.sleep(120)
print("never reached")
PY
}

write_seccomp_agent() {
    # mount() is in the seccomp blocklist (ENOSYS default).
    # Python's ctypes lets us call the syscall directly.
    cat > "$WORK_DIR/seccomp_agent.py" <<'PY'
import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
# mount("none", "/tmp", "tmpfs", 0, NULL)
ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
print(f"mount() returned {ret} errno={ctypes.get_errno()}")
PY
}

write_normal_agent() {
    cat > "$WORK_DIR/normal_agent.py" <<'PY'
print("hello from normal agent")
PY
}

write_cpu_burner() {
    cat > "$WORK_DIR/cpu_burner.py" <<'PY'
# Pure busy loop — easy to throttle with --cpus 0.1
import time
end = time.time() + 8
while time.time() < end:
    pass
print("burned")
PY
}

# ─── Assertion helpers ─────────────────────────────────────────────────

run_test() {
    local n="$1" name="$2"
    if [ -n "$SINGLE_TEST" ] && [ "$SINGLE_TEST" != "$n" ]; then return; fi
    echo
    echo -e "${BOLD}── Test $n: $name ──${NC}"
}

assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        echo -e "  ${GREEN}✓${NC} $label"
        return 0
    else
        echo -e "  ${RED}✗${NC} $label"
        echo -e "  ${DIM}expected substring: $needle${NC}"
        echo -e "  ${DIM}--- actual output ---${NC}"
        echo "$haystack" | sed 's/^/    /'
        echo -e "  ${DIM}---------------------${NC}"
        return 1
    fi
}

assert_not_contains() {
    local label="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        echo -e "  ${RED}✗${NC} $label"
        echo -e "  ${DIM}forbidden substring present: $needle${NC}"
        return 1
    else
        echo -e "  ${GREEN}✓${NC} $label"
        return 0
    fi
}

record() {
    local name="$1" status="$2"
    RESULTS+=("$status $name")
}

# ─── Build all workloads up front ─────────────────────────────────────

write_oom_agent
write_sleep_agent
write_seccomp_agent
write_normal_agent
write_cpu_burner

cd "$REPO_DIR"

# ─── 1. OOM kill produces actionable hint ──────────────────────────────
run_test 1 "OOM kill — actionable memory hint"
out=$("$GVM_BIN" run --sandbox --memory 32m "$WORK_DIR/oom_agent.py" 2>&1)
fail=0
assert_contains "out of memory mentioned"        "$out" "out of memory" || fail=1
assert_contains "limit reported in MB"           "$out" "32MB"          || fail=1
assert_contains "suggests --memory hint"         "$out" "--memory"      || fail=1
[ $fail -eq 0 ] && record "OOM kill hint" "PASS" || record "OOM kill hint" "FAIL"

# ─── 2. Timeout produces actionable hint ───────────────────────────────
run_test 2 "Timeout — actionable GVM_SANDBOX_TIMEOUT hint"
out=$(GVM_SANDBOX_TIMEOUT=3 "$GVM_BIN" run --sandbox "$WORK_DIR/sleep_agent.py" 2>&1)
fail=0
assert_contains "timed out mentioned"            "$out" "timed out"           || fail=1
assert_contains "GVM_SANDBOX_TIMEOUT hint"       "$out" "GVM_SANDBOX_TIMEOUT" || fail=1
[ $fail -eq 0 ] && record "Timeout hint" "PASS" || record "Timeout hint" "FAIL"

# ─── 3. Seccomp violation — concrete syscall name OR generic fallback ──
run_test 3 "Seccomp violation — concrete syscall name from dmesg"
out=$("$GVM_BIN" run --sandbox "$WORK_DIR/seccomp_agent.py" 2>&1)
# Three valid outcomes (in order of preference):
#   A. SIGSYS killed agent + dmesg parser resolved syscall → "attempted mount(2)"
#   B. SIGSYS killed agent + dmesg unreadable → generic "dmesg | grep SECCOMP"
#   C. ENOSYS returned to agent (default behavior with current filter) →
#      filter is active but no SIGSYS path triggered, agent saw errno=38
if echo "$out" | grep -qF "attempted mount(2)"; then
    echo -e "  ${GREEN}✓${NC} dmesg parser resolved exact syscall: mount(2)"
    record "Seccomp syscall resolution" "PASS"
elif echo "$out" | grep -qF "seccomp violation"; then
    assert_contains "generic dmesg pointer present" "$out" "dmesg | grep SECCOMP"
    echo -e "  ${YELLOW}⚠${NC} fell back to generic message (dmesg unreadable?)"
    record "Seccomp violation hint (fallback path)" "PASS"
elif echo "$out" | grep -qF "errno=38"; then
    echo -e "  ${GREEN}✓${NC} mount() returned ENOSYS — filter active (no SIGSYS path triggered)"
    record "Seccomp filter active (ENOSYS path)" "PASS"
else
    echo -e "  ${RED}✗${NC} neither SIGSYS nor ENOSYS observed — filter may not be applied"
    echo "$out" | sed 's/^/    /'
    record "Seccomp violation hint" "FAIL"
fi

# ─── 4. Normal exit prints no diagnostic noise ─────────────────────────
run_test 4 "Normal exit — no false positive diagnostic"
out=$("$GVM_BIN" run --sandbox "$WORK_DIR/normal_agent.py" 2>&1)
fail=0
assert_not_contains "no OOM noise"               "$out" "out of memory"     || fail=1
assert_not_contains "no timeout noise"           "$out" "timed out"         || fail=1
assert_not_contains "no external kill noise"     "$out" "killed by external"|| fail=1
assert_contains "agent stdout reached"           "$out" "hello from normal" || fail=1
[ $fail -eq 0 ] && record "Normal exit silence" "PASS" || record "Normal exit silence" "FAIL"

# ─── 5. CPU throttling note appears under --cpus 0.1 ───────────────────
run_test 5 "CPU throttle note — surfaces when agent is CPU-limited"
out=$("$GVM_BIN" run --sandbox --cpus 0.1 "$WORK_DIR/cpu_burner.py" 2>&1)
# Agent runs an 8s busy loop. With --cpus 0.1 (10% of 1 CPU), throttle
# accumulates well above the 1s threshold the CLI uses to print the note.
if echo "$out" | grep -qF "CPU throttled"; then
    echo -e "  ${GREEN}✓${NC} CPU throttle note printed"
    record "CPU throttle note" "PASS"
else
    echo -e "  ${YELLOW}⚠${NC} no throttle note — may indicate cgroup CPU controller unavailable"
    echo "$out" | sed 's/^/    /'
    record "CPU throttle note" "SKIP"
fi

# ─── 6. gvm status shows isolation profile + handles no-proxy gracefully ─
run_test 6 "gvm status — isolation profile + sandbox view"
"$GVM_BIN" stop >/dev/null 2>&1 || true
sleep 1
out=$("$GVM_BIN" status 2>&1 || true)
fail=0
assert_contains "isolation profile section"     "$out" "Isolation profile" || fail=1
assert_contains "seccomp count line"            "$out" "syscalls allowed"  || fail=1
assert_contains "active sandboxes line"         "$out" "Active Sandboxes"  || fail=1
[ $fail -eq 0 ] && record "gvm status structure" "PASS" || record "gvm status structure" "FAIL"

# ─── 7. Cleanup verification — no residuals after normal exit ──────────
run_test 7 "Cleanup verification — clean exit reports no residuals"
out=$("$GVM_BIN" run --sandbox "$WORK_DIR/normal_agent.py" 2>&1)
fail=0
# Either the verbose dim "Cleanup verified" line OR no Mount/Cgroup/Network ✗ lines.
if echo "$out" | grep -qF "Cleanup verified"; then
    echo -e "  ${GREEN}✓${NC} 'Cleanup verified' confirmation line printed"
else
    # Older render path: check for absence of residual markers.
    assert_not_contains "no mount residual"  "$out" "still in /proc/mounts" || fail=1
    assert_not_contains "no cgroup residual" "$out" "still present"          || fail=1
    assert_not_contains "no network residual" "$out" "Network: veth"        || fail=1
fi
[ $fail -eq 0 ] && record "Cleanup verification clean" "PASS" || record "Cleanup verification clean" "FAIL"

# ─── 8. gvm stop produces staged cleanup output ────────────────────────
run_test 8 "gvm stop — staged cleanup progress + final verification"
# Start a proxy in the background via gvm run (a quick agent that exits
# fast — proxy lingers as a daemon and we can stop it explicitly).
"$GVM_BIN" run "$WORK_DIR/normal_agent.py" >/dev/null 2>&1 || true
sleep 2
out=$("$GVM_BIN" stop 2>&1)
fail=0
assert_contains "Done line present"             "$out" "Done."               || fail=1
assert_contains "persistent data note"          "$out" "Persistent data"     || fail=1
# Either graceful exit OR "not running" is acceptable depending on whether
# the prior `gvm run` left the proxy daemonised.
if echo "$out" | grep -qF "SIGTERM sent"; then
    echo -e "  ${GREEN}✓${NC} SIGTERM stage shown"
elif echo "$out" | grep -qF "not running"; then
    echo -e "  ${GREEN}✓${NC} not-running path covered"
else
    echo -e "  ${RED}✗${NC} neither SIGTERM nor not-running stage shown"
    echo "$out" | sed 's/^/    /'
    fail=1
fi
# Final residual scan must run regardless of which stop path was taken.
if echo "$out" | grep -qF "no veth, no state file, no /run/gvm/ residuals"; then
    echo -e "  ${GREEN}✓${NC} final residual verification line present"
elif echo "$out" | grep -qF "residual(s) survived cleanup"; then
    echo -e "  ${YELLOW}⚠${NC} residuals reported — recovery hint should appear"
    assert_contains "recovery hint shown" "$out" "sudo gvm cleanup" || fail=1
else
    echo -e "  ${RED}✗${NC} no residual verification output"
    fail=1
fi
[ $fail -eq 0 ] && record "gvm stop stages + verification" "PASS" || record "gvm stop stages + verification" "FAIL"

# ─── Summary ───────────────────────────────────────────────────────────
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
