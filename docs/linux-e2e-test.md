# Linux E2E Test Guide (Codespace / VM)

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

## Known Issues

- **rustc 1.94.0 ICE**: Linux에서 `main.rs`의 hyper service_fn이 컴파일러 패닉 유발. `rustup default 1.85.0` 사용.
- **WSL2 메모리**: wasmtime 빌드에 ~3GB RAM 필요. `.wslconfig`에서 `memory=8GB` 설정.
- **OpenSSL 3.x**: `SSL_write_ex` 사용 (not `SSL_write`). offset이 다름.
- **OpenSSL 1.x**: `SSL_write` 사용. `nm -D libssl.so.1.1 | grep SSL_write` 로 확인.
