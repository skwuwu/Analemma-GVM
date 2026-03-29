#!/bin/bash
# OpenClaw agent: API exploration (Default-to-Caution path)
# Fetches from multiple public APIs, triggering delay on unknown hosts.
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
        --message "Fetch data from https://catfact.ninja/fact and https://dog.ceo/api/breeds/image/random. Summarize what each returned." \
        --timeout 120 \
        --session-id "stress-explore-$i-$$" \
        2>&1 || echo "[Turn $i] failed"
    sleep 30
done
echo "Agent explore complete"
