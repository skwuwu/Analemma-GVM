#!/bin/bash
# OpenClaw agent: Public API data collection (Allow path)
# Fetches from multiple fun/educational public APIs.
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
        --message "Fetch a random cat fact from https://catfact.ninja/fact, a random dog image from https://dog.ceo/api/breeds/image/random, number trivia from http://numbersapi.com/random/trivia, and a random joke from https://official-joke-api.appspot.com/random_joke. Compile all results into a Fun Facts Digest with bullet points." \
        --timeout 120 \
        --session-id "stress-public-apis-$i-$$" \
        2>&1 || echo "[Turn $i] failed"
    sleep 30
done
echo "Agent public-apis complete"
