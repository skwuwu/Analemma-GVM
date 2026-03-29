#!/bin/bash
# OpenClaw agent: GitHub repository analysis (Allow path)
# Runs for ~60 minutes (60 turns × ~60s each)
export OPENCLAW_STATE_DIR=/tmp/openclaw
export HOME=/tmp
mkdir -p /tmp/openclaw/agents/main/agent

# Bootstrap OpenClaw auth from ANTHROPIC_API_KEY env var
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
        --message "Fetch the content from https://catfact.ninja/fact and https://dog.ceo/api/breeds/image/random. Summarize what each API returned." \
        --timeout 120 \
        --session-id "stress-gh-$i-$$" \
        2>&1 || echo "[Turn $i] failed"
    sleep 30
done
echo "Agent github complete"
