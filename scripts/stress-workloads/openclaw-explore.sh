#!/bin/bash
# OpenClaw agent: API exploration (Default-to-Caution path, high volume)
# Runs for ~60 minutes with shorter intervals (more requests per minute)
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

for i in $(seq 1 120); do
    echo "[Turn $i/120] $(date -u +%H:%M:%S)"
    openclaw agent --local \
        --message "Make HTTP requests to these public APIs and report what each returns: catfact.ninja/fact, dog.ceo/api/breeds/image/random, api.agify.io/?name=michael, worldtimeapi.org/api/ip. Summarize all results." \
        --timeout 90 \
        --session-id "stress-explore-$i-$$" \
        2>&1 || echo "[Turn $i] failed"
    sleep 15
done
echo "Agent explore complete"
