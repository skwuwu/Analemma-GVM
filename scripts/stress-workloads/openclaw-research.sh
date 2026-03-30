#!/bin/bash
# OpenClaw agent: Technical research (Allow path)
# Fetches documentation from major language repos and compares trends.
export OPENCLAW_STATE_DIR=/tmp/openclaw
export HOME=/tmp
mkdir -p /tmp/openclaw/agents/main/agent

if [ -n "$ANTHROPIC_API_KEY" ]; then
    cat > /tmp/openclaw/agents/main/agent/auth-profiles.json << EOF
{"version":1,"profiles":{"anthropic-default":{"provider":"anthropic","type":"api_key","key":"$ANTHROPIC_API_KEY"}},"lastGood":{"anthropic":"anthropic-default"}}
EOF
    echo "Auth bootstrapped from env"
else
    echo "WARNING: ANTHROPIC_API_KEY not set"
fi

for i in $(seq 1 60); do
    echo "[Turn $i/60] $(date -u +%H:%M:%S)"
    openclaw agent --local \
        --message "Fetch Rust release notes from https://raw.githubusercontent.com/rust-lang/rust/master/RELEASES.md and Go docs from https://raw.githubusercontent.com/golang/go/master/doc/next-release-notes.md. Summarize the latest release highlights from each and compare their feature focus." \
        --timeout 120 \
        --session-id "stress-research-$i-$$" \
        2>&1 || echo "[Turn $i] failed"
    sleep 30
done
echo "Agent research complete"
