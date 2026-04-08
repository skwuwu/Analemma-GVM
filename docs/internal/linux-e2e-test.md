# Linux E2E Test Guide (Codespace / VM)

## Session management on remote hosts

Every long-running command on an EC2 instance, cloud VM, or any SSH'd
host **must** be hosted inside a `tmux` (or `screen`) session. Never
launch a multi-minute pipeline with `nohup ... &`.

Why: `nohup` loses races around SSH disconnect. We have repeatedly
hit the failure mode where the child is killed between starting its
work and installing its signal handlers, which strands `tc netem`
rules, `/run/gvm/` directories, and orphan `gvm-proxy` processes
that the test script never had a chance to clean up. `tmux` survives
SSH death independently, lets you reattach to watch progress, and
gives a deterministic teardown path (`tmux kill-session -t gvm`).

```bash
# On the remote host, before starting anything expensive:
tmux new -s gvm
cd ~/Analemma-GVM

# Inside the tmux session, run the pipeline:
sudo bash scripts/stress-test.sh --duration 60

# Detach: Ctrl-b d
# Reattach from a new SSH session:
ssh <host>
tmux attach -t gvm
```

## Prerequisites

```bash
# Ubuntu 22.04+ / kernel 5.5+
sudo apt-get update && sudo apt-get install -y build-essential pkg-config libssl-dev python3-requests curl

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Use rustc 1.85 (1.94 has ICE bug with hyper service_fn)
rustup install 1.85.0 && rustup default 1.85.0
```

## Build

```bash
git clone https://github.com/skwuwu/Analemma-GVM.git && cd Analemma-GVM
cargo build --release -j 2
# Binary: target/release/gvm-proxy (~17MB)
```

## Test 1: Proxy + CONNECT Tunnel

```bash
# Terminal 1: Start proxy
./target/release/gvm-proxy --config config/proxy.toml &
sleep 2
curl -s http://localhost:8080/gvm/health

# Terminal 2: HTTPS through proxy
HTTPS_PROXY=http://127.0.0.1:8080 python3 -c "
import requests
r = requests.get('https://api.github.com')
print(f'Status: {r.status_code}')
print(f'GitHub API: {r.json().get(\"current_user_url\", \"OK\")}')
"

# Check WAL
tail -5 data/wal.log | python3 -c "
import sys, json
for l in sys.stdin:
    try:
        e = json.loads(l)
        t = e.get('transport', {}) or {}
        print(f'{e.get(\"decision\",\"?\")} | {t.get(\"method\",\"?\")} {t.get(\"host\",\"?\")}')
    except: pass
"
```

Expected: `Allow | CONNECT api.github.com`

## Test 2: eBPF uprobe TLS Capture

```bash
# Find SSL_write_ex offset
nm -D /lib/x86_64-linux-gnu/libssl.so.3 | grep "T SSL_write_ex"
# Note the offset (e.g., 0x36bb0)

# Register uprobe (needs root)
OFFSET=0x36bb0  # Replace with actual offset
sudo bash -c "
echo > /sys/kernel/tracing/trace
echo 'p:gvm_ssl /lib/x86_64-linux-gnu/libssl.so.3:$OFFSET buf=+0(%si):string' > /sys/kernel/tracing/uprobe_events
echo 1 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
"

# Make HTTPS request
python3 -c "import requests; requests.get('https://api.github.com/repos/skwuwu/Analemma-GVM')"

# Check captured plaintext
sudo cat /sys/kernel/tracing/trace | grep gvm_ssl | sed 's/.*buf="//'
# Expected: GET /repos/skwuwu/Analemma-GVM HTTP/1.1

# Cleanup
sudo bash -c "
echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
echo > /sys/kernel/tracing/uprobe_events
"
```

## Test 3: SRR Ruleset Policy Check

```bash
# Load google-workspace ruleset
cat > /tmp/test-srr.toml << 'EOF'
[[rules]]
pattern = "localhost/*"
method = "*"
decision = { type = "Allow" }

[[rules]]
pattern = "gmail.googleapis.com/gmail/v1/users/me/messages"
method = "GET"
decision = { type = "Allow" }
description = "Gmail read"

[[rules]]
pattern = "gmail.googleapis.com/gmail/v1/users/me/messages/*"
method = "DELETE"
decision = { type = "Deny", reason = "Email deletion blocked" }
description = "Gmail delete blocked"
EOF

cp /tmp/test-srr.toml config/srr_network.toml
kill -HUP $(pgrep gvm-proxy) 2>/dev/null  # or POST /gvm/reload
curl -s -X POST http://localhost:8080/gvm/reload

# Policy checks
echo "Gmail read:"
curl -s -X POST http://localhost:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","target_host":"gmail.googleapis.com","target_path":"/gmail/v1/users/me/messages","operation":"test"}'

echo ""
echo "Gmail delete:"
curl -s -X POST http://localhost:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"method":"DELETE","target_host":"gmail.googleapis.com","target_path":"/gmail/v1/users/me/messages/123","operation":"test"}'
```

Expected: Gmail read → Allow, Gmail delete → Deny

## Test 4: Shadow Mode + Intent

```bash
# Start proxy with Shadow Mode
GVM_SHADOW_MODE=strict ./target/release/gvm-proxy --config config/proxy.toml &
sleep 2

# Register intent
curl -s -X POST http://localhost:8080/gvm/intent \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","host":"api.github.com","path":"/","operation":"github.read","agent_id":"test"}'

# Check proxy info (should show active intent)
curl -s http://localhost:8080/gvm/info | python3 -m json.tool
```

## Test 5: Full Pipeline (Proxy + uprobe + Python agent)

```bash
# This test requires root for uprobe

# 1. Start proxy with google-workspace + llm-providers
# 2. Register uprobe on SSL_write_ex
# 3. Run Python agent through proxy
# 4. Verify:
#    - CONNECT tunnel logged in WAL
#    - uprobe captures HTTP method + path
#    - Policy decisions match ruleset

sudo bash << 'SCRIPT'
# Start proxy
./target/release/gvm-proxy --config config/proxy.toml &
PROXY_PID=$!
sleep 2

# Register uprobe
OFFSET=$(nm -D /lib/x86_64-linux-gnu/libssl.so.3 | grep "T SSL_write_ex" | awk '{print $1}')
echo > /sys/kernel/tracing/trace
echo "p:gvm_ssl /lib/x86_64-linux-gnu/libssl.so.3:0x$OFFSET buf=+0(%si):string" > /sys/kernel/tracing/uprobe_events
echo 1 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable

# Run agent
HTTPS_PROXY=http://127.0.0.1:8080 python3 -c "
import requests
# Read (should Allow)
r = requests.get('https://api.github.com')
print(f'GitHub: {r.status_code}')
# POST (captured by uprobe)
try:
    r = requests.post('https://httpbin.org/post', json={'test': True}, timeout=5)
    print(f'httpbin: {r.status_code}')
except: print('httpbin: timeout (expected if not in ruleset)')
"

# Check results
echo ""
echo "=== uprobe captures ==="
cat /sys/kernel/tracing/trace | grep gvm_ssl | sed 's/.*buf="//'

echo ""
echo "=== WAL CONNECT events ==="
grep -o '"method":"CONNECT"[^}]*"host":"[^"]*"' data/wal.log

# Cleanup
echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
echo > /sys/kernel/tracing/uprobe_events
kill $PROXY_PID
SCRIPT
```

## Test 6: Uprobe Policy Enforcement (Proxy + uprobe SRR callback)

Tests the full uprobe enforcement path: SSL_write_ex capture → HTTP parse → proxy /gvm/check → SIGSTOP on Deny.

Requires: root, kernel 5.5+, proxy running with github ruleset.

```bash
cd ~/Analemma-GVM

# Load github ruleset (Allow reads, Deny merges/deletes)
python3 -c "
import os
rulesets = os.path.expanduser('~/analemma-gvm-openclaw/rulesets')
parts = []
for f in ['_default.toml', 'github.toml']:
    path = os.path.join(rulesets, f)
    if os.path.exists(path): parts.append(open(path).read())
open('config/srr_network.toml', 'w').write('\n'.join(parts))
print(f'{len(parts)} rulesets loaded')
"

./target/release/gvm-proxy --config config/proxy.toml &
PROXY_PID=$!
sleep 2
curl -sf http://127.0.0.1:8080/gvm/health && echo " OK"

# Register uprobe on SSL_write_ex
LIBSSL=$(python3 -c "import _ssl; print(_ssl.__file__)" | xargs ldd | grep libssl | awk '{print $3}')
OFFSET=$(nm -D $LIBSSL | grep "T SSL_write_ex" | awk '{print $1}')
echo "libssl: $LIBSSL offset: 0x$OFFSET"

sudo bash -c "
echo > /sys/kernel/tracing/trace
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
echo 'p:gvm_ssl $LIBSSL:0x$OFFSET buf=+0(%si):string' > /sys/kernel/tracing/uprobe_events
echo 1 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
"

# Test 6a: GitHub read (should capture plaintext, proxy returns Allow)
echo "=== Test 6a: GitHub read (Allow) ==="
HTTPS_PROXY=http://127.0.0.1:8080 python3 -c "
import requests
r = requests.get('https://api.github.com/repos/skwuwu/Analemma-GVM/issues', timeout=10)
print(f'Status: {r.status_code}')
"
sleep 1
echo "uprobe capture:"
sudo cat /sys/kernel/tracing/trace | grep gvm_ssl | tail -3 | sed 's/.*buf="//'

# Test 6b: Verify proxy policy check returns correct decisions
echo ""
echo "=== Test 6b: Policy check (read=Allow, merge=Deny) ==="
curl -sf -X POST http://127.0.0.1:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","target_host":"api.github.com","target_path":"/repos/t/t/issues","operation":"uprobe"}' \
  | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'Read issues: {d[\"decision\"]}')"

curl -sf -X POST http://127.0.0.1:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"method":"PUT","target_host":"api.github.com","target_path":"/repos/t/t/pulls/1/merge","operation":"uprobe"}' \
  | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'Merge PR: {d[\"decision\"]}')"

curl -sf -X POST http://127.0.0.1:8080/gvm/check \
  -H "Content-Type: application/json" \
  -d '{"method":"DELETE","target_host":"api.github.com","target_path":"/repos/t/t/git/refs/heads/main","operation":"uprobe"}' \
  | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f'Delete branch: {d[\"decision\"]}')"

# Expected:
#   Test 6a: Status 200, uprobe captures "GET /repos/skwuwu/Analemma-GVM/issues HTTP/1.1"
#   Test 6b: Read issues = Allow, Merge PR = Deny, Delete branch = Deny

# Cleanup
sudo bash -c "
echo 0 > /sys/kernel/tracing/events/uprobes/gvm_ssl/enable
echo > /sys/kernel/tracing/uprobe_events
"
kill $PROXY_PID 2>/dev/null
```

## Uprobe Security Model

| Property | Status | Notes |
|----------|--------|-------|
| Plaintext capture | Working | SSL_write_ex fetcharg `+0(%si):string` |
| HTTP parsing | Working | Method + path + Host from first write |
| SRR policy check | Working | Callback queries proxy `/gvm/check` |
| SIGSTOP enforcement | Working | Process frozen on Deny decision |
| Fail-closed | Working | Proxy timeout/unreachable = Deny |
| Real-time block | **Limitation** | SSL_write fires after kernel queues packet. SIGSTOP freezes process but first write may be on wire. This is "immediate session freeze", not "pre-transmission block". |
| Auth | Partial | `X-GVM-Uprobe-Token` header, but not cryptographically verified yet |

## Known Issues

- **rustc 1.94.0 ICE**: hyper service_fn closures trigger compiler panic on Linux. Use `rustup default 1.85.0`.
- **WSL2 memory**: wasmtime needs ~3GB RAM. Set `memory=8GB` in `.wslconfig`.
- **OpenSSL 3.x**: use `SSL_write_ex` (not `SSL_write`). Offset differs per build.
- **OpenSSL 1.x**: use `SSL_write`. `nm -D libssl.so.1.1 | grep SSL_write`.
- **uprobe race condition**: SSL_write_ex fires after kernel queues packet. SIGSTOP cannot prevent the triggering write from reaching the wire. Proxy CONNECT-level enforcement is the primary gate; uprobe is defense-in-depth.
