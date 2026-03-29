#!/bin/bash
# OpenClaw agent: API exploration (Default-to-Caution path, high volume)
export OPENCLAW_STATE_DIR=/tmp/openclaw
export HOME=/tmp
mkdir -p /tmp/openclaw/agents/main/agent

if [ -n "$ANTHROPIC_API_KEY" ]; then
    cat > /tmp/openclaw/agents/main/agent/auth-profiles.json << EOF
{"profiles":{"anthropic":{"provider":"anthropic","apiKey":"$ANTHROPIC_API_KEY"}},"default":"anthropic"}
EOF
fi

for i in $(seq 1 8); do
    openclaw agent --local \
        --message "You are an API explorer. Make HTTP requests to these APIs and summarize what each returns: catfact.ninja/fact, dog.ceo/api/breeds/image/random, api.coindesk.com/v1/bpi/currentprice.json, numbersapi.com/42, api.agify.io/?name=test. Try to find 2 more interesting public APIs." \
        --timeout 90 \
        --session-id "stress-explore-$i-$(date +%s)" \
        2>&1 || echo "Turn $i failed"
    sleep 15
done
