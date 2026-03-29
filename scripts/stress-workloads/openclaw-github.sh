#!/bin/bash
# OpenClaw agent: GitHub repository analysis (Allow path)
export OPENCLAW_STATE_DIR=/tmp/openclaw
export HOME=/tmp
mkdir -p /tmp/openclaw/agents/main/agent

# Bootstrap auth from environment
if [ -n "$ANTHROPIC_API_KEY" ]; then
    cat > /tmp/openclaw/agents/main/agent/auth-profiles.json << EOF
{"profiles":{"anthropic":{"provider":"anthropic","apiKey":"$ANTHROPIC_API_KEY"}},"default":"anthropic"}
EOF
fi

for i in $(seq 1 4); do
    openclaw agent --local \
        --message "Read the issues list from GitHub repository torvalds/linux. Pick the 3 most recent issues and summarize each in one sentence. Then check the latest commit." \
        --timeout 120 \
        --session-id "stress-github-$i-$(date +%s)" \
        2>&1 || echo "Turn $i failed"
    sleep 30
done
