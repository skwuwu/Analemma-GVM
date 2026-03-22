#!/usr/bin/env bash
# EC2 instance setup for Analemma GVM E2E testing.
#
# Target: Ubuntu 22.04+ (t3.medium, 4GB RAM minimum)
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/skwuwu/Analemma-GVM/master/scripts/ec2-setup.sh | bash
#   # Then: bash scripts/ec2-e2e-test.sh

set -euo pipefail

echo "=== System packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev python3-pip python3-requests curl git

echo "=== Rust (1.85.0 — avoids 1.94 ICE) ==="
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
rustup install 1.85.0 2>/dev/null || true
rustup default 1.85.0
echo "Rust: $(rustc --version)"

echo "=== Node.js 22 ==="
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y -qq nodejs
fi
echo "Node: $(node --version)"

echo "=== Clone repos ==="
cd "$HOME"

if [ ! -d Analemma-GVM ]; then
    git clone https://github.com/skwuwu/Analemma-GVM.git
fi

if [ ! -d analemma-gvm-openclaw ]; then
    git clone https://github.com/skwuwu/analemma-gvm-openclaw.git
fi

echo "=== Build proxy ==="
cd "$HOME/Analemma-GVM"
cargo build --release -p gvm-proxy -p gvm-cli -j 2

echo "=== OpenClaw (optional) ==="
npm install -g openclaw@latest 2>/dev/null || echo "OpenClaw install failed (optional)"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Run the full test suite:"
echo "  cd ~/Analemma-GVM"
echo "  export ANTHROPIC_API_KEY='sk-ant-...'"
echo "  bash scripts/ec2-e2e-test.sh"
echo ""
echo "Run without OpenClaw tests:"
echo "  bash scripts/ec2-e2e-test.sh --skip-openclaw"
echo ""
echo "Run a single test:"
echo "  bash scripts/ec2-e2e-test.sh --test 4"
