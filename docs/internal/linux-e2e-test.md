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

## Default Execution Mode

Unless explicitly stated otherwise, **all tests run in sandbox mode** (`--sandbox`). Sandbox provides:
- Full MITM HTTPS inspection (L7 path/body visibility)
- Network namespace isolation (veth + TC filter)
- Seccomp-BPF syscall whitelist
- WAL records all enforcement decisions including HTTPS

Cooperative mode (`gvm run` without `--sandbox`) only captures HTTP traffic and HTTPS CONNECT tunnels (domain-level, no path/body). Use sandbox for complete visibility.

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

## ~~Test 2: eBPF uprobe TLS Capture~~ (Removed v0.5.0)

> uprobe-based TLS interception has been removed. MITM (transparent TLS proxy) is the sole HTTPS inspection mechanism. See `security-model.md` for details.

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

## ~~Test 5: Full Pipeline (Proxy + uprobe + Python agent)~~ (Removed v0.5.0)

> uprobe-based TLS interception has been removed. Use MITM mode instead. CONNECT tunnel + MITM inspection covers this test's intent.

## ~~Test 6: Uprobe Policy Enforcement (Proxy + uprobe SRR callback)~~ (Removed v0.5.0)

> uprobe-based enforcement has been removed. SRR policy enforcement is now handled entirely through MITM TLS proxy + proxy `/gvm/check` endpoint.

## ~~Uprobe Security Model~~ (Removed v0.5.0)

> The uprobe security model table and related properties are no longer applicable.
> MITM TLS proxy is the sole HTTPS inspection mechanism as of v0.5.0.

## Test 7: Watch Mode TUI Dashboard

Tests the `--output tui` terminal dashboard for agent debugging.

### Prerequisites

API keys must be loaded from the project's `.env` file:

```bash
# .env file in project root (not committed to git)
ANTHROPIC_API_KEY=sk-ant-...

# Load into current shell
export $(cat .env | xargs)

# For sandbox mode (sudo), pass env with -E:
sudo -E target/release/gvm watch --output tui --sandbox -- python3 agent.py
```

### 7a: Cooperative mode (HTTP traffic)

```bash
cd ~/Analemma-GVM
export $(cat .env | xargs)

# TUI mode — interactive terminal dashboard
target/release/gvm watch --output tui -- python3 agent.py

# Text mode — line-by-line output (for scripted tests)
target/release/gvm watch --output text -- python3 agent.py
```

**What to verify**: Timeline shows HTTP requests. Host stats, decision distribution, anomaly detection all update in real-time. HTTPS requests appear only as CONNECT events (domain-level, no path/body inspection without MITM).

### 7b: Sandbox mode (MITM HTTPS inspection)

```bash
sudo -E target/release/gvm watch --output text --sandbox -- python3 agent.py
```

**What to verify**: HTTPS requests (e.g., `POST api.anthropic.com /v1/messages`) appear in Timeline with method + path. MITM CA injected. LLM Usage panel shows token counts and estimated cost.

**Note**: Sandbox MITM strips and re-injects API credentials. For Anthropic API calls to succeed, configure `config/secrets.toml`:

```toml
[credentials."api.anthropic.com"]
type = "ApiKey"
header = "x-api-key"
value = "sk-ant-..."
```

### 7c: TUI keyboard interaction

| Key | Action | Verify |
|-----|--------|--------|
| `↑↓` | Scroll timeline | Selected row highlights |
| `t` | Toggle trace view | Events grouped by trace_id in tree format |
| `Esc` | Exit trace view | Returns to flat timeline |
| `q` | Quit TUI | Terminal restored cleanly |

### 7d: Known limitations

- **sudo without `-E`**: TUI fails with `ENXIO` (errno 6) because `sudo` doesn't inherit the PTY. Always use `sudo -E` or run without sudo (cooperative mode).
- **Cooperative HTTPS**: Only domain-level CONNECT events recorded. Use `--sandbox` for full L7 HTTPS inspection.
- **asciinema**: Cannot capture alternate screen output. Use `tmux capture-pane` or direct SSH for visual verification.

### Test Results (2026-04-15)

| Test | Mode | Result |
|------|------|--------|
| TUI rendering | Cooperative | PASS — 5 panels, clean layout |
| Timeline dedup | Cooperative | PASS — N events = N rows |
| Agent stdout suppression | Cooperative | PASS — no header corruption |
| Anomaly detection | Cooperative | PASS — loop/burst detected |
| MITM HTTPS inspection | Sandbox | PASS — api.anthropic.com visible |
| LLM token tracking | Sandbox | Pending — requires secrets.toml |
| Text mode regression | Cooperative | PASS — unchanged behavior |

## Test 8: Web Dashboard

Tests the browser-based governance dashboard served from admin API (port 9090).

### 8a: CLI command

```bash
gvm dashboard                   # opens browser to localhost:9090/gvm/dashboard
gvm dashboard --proxy http://127.0.0.1:8080   # custom proxy URL
```

Starts proxy if not running, derives admin URL (port +1010), opens default browser. On headless servers, access `http://localhost:9090/gvm/dashboard` directly.

### 8b: Dashboard with real agent traffic (sandbox)

```bash
# 1. Ensure secrets.toml has API credentials
cat config/secrets.toml
# [credentials."api.anthropic.com"]
# type = "ApiKey"
# header = "x-api-key"
# value = "sk-ant-..."

# 2. Run agent in sandbox (MITM captures HTTPS)
sudo gvm run --sandbox agent.py

# 3. Open dashboard in another terminal
gvm dashboard
# Or: curl http://localhost:9090/gvm/dashboard > snapshot.html
```

### 8c: API endpoints

```bash
# Dashboard HTML
curl http://localhost:9090/gvm/dashboard

# Events (incremental, offset-based polling)
curl 'http://localhost:9090/gvm/dashboard/events?since_offset=0&limit=100'

# Aggregated stats
curl http://localhost:9090/gvm/dashboard/stats
```

### 8d: Polling verification

The dashboard polls every 2 seconds. Verify by watching the stats endpoint before and after generating traffic:

```bash
# Before
curl -s http://localhost:9090/gvm/dashboard/stats | python3 -c "import sys,json; print(json.load(sys.stdin)['total_requests'])"

# Generate traffic
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# After (wait 2s for poll cycle)
curl -s http://localhost:9090/gvm/dashboard/stats | python3 -c "import sys,json; print(json.load(sys.stdin)['total_requests'])"
```

### Test Results (2026-04-15)

| Test | Result |
|------|--------|
| `gvm dashboard` CLI | PASS — prints URL, opens browser |
| Dashboard HTML (GET /gvm/dashboard) | PASS — HTTP 200, 21KB |
| Events API with sandbox agent | PASS — api.anthropic.com captured via MITM |
| Stats API | PASS — hosts, decisions, WAL offset correct |
| Polling (2s interval) | PASS — new events detected between polls |
| Filter buttons (Allow/Delay/Deny) | PASS — exclusive select |
| Share button | PASS — standalone HTML export |

**Known limitation**: MITM WAL currently writes Pending status only (no Confirmed update with llm_trace). LLM token/cost tracking requires the MITM response-phase WAL update to be implemented.

## Known Issues

- **rustc 1.94.0 ICE**: hyper service_fn closures trigger compiler panic on Linux. Use `rustup default 1.85.0`.
- **WSL2 memory**: wasmtime needs ~3GB RAM. Set `memory=8GB` in `.wslconfig`.
