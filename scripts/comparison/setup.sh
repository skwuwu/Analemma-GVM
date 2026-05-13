#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# OPA + Envoy + Docker stack setup for the GVM vs OPA+Envoy comparison.
#
# Target: Ubuntu 22.04+ on EC2 t3.medium (matches the existing GVM
# bench host so cross-stack numbers are on identical hardware).
#
# Installs:
#   - Docker (for running Envoy + OPA + mock upstream)
#   - opa CLI (host-side, to compile policy.rego to WASM)
#   - hyperfine + jq + curl (bench tooling)
#
# Pulls (lazy, at bench time):
#   - envoyproxy/envoy:v1.32-latest
#   - openpolicyagent/opa:0.71.0-envoy
#
# Usage:
#   bash scripts/comparison/setup.sh
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

OPA_VERSION="0.71.0"
ENVOY_VERSION="v1.32-latest"

echo "=== System packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release \
    jq python3 net-tools procps

echo "=== Docker ==="
if ! command -v docker &>/dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo usermod -aG docker "$USER"
    echo "Docker installed. NOTE: re-login or run \`newgrp docker\` to use without sudo."
fi
docker --version

echo "=== opa CLI ==="
if ! command -v opa &>/dev/null; then
    curl -fsSL -o /tmp/opa "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static"
    sudo install -m 0755 /tmp/opa /usr/local/bin/opa
fi
echo "opa: $(opa version | head -1)"

echo "=== hyperfine (bench tooling) ==="
if ! command -v hyperfine &>/dev/null; then
    HF_VERSION="1.18.0"
    curl -fsSL "https://github.com/sharkdp/hyperfine/releases/download/v${HF_VERSION}/hyperfine_${HF_VERSION}_amd64.deb" -o /tmp/hyperfine.deb
    sudo dpkg -i /tmp/hyperfine.deb
fi
hyperfine --version

echo "=== Pre-pull Docker images (so cold-start measurement is image-cached) ==="
sudo docker pull "envoyproxy/envoy:${ENVOY_VERSION}"
sudo docker pull "openpolicyagent/opa:${OPA_VERSION}-envoy"

echo "=== Compile policy.rego to WASM (used by Stack C) ==="
mkdir -p "$REPO_DIR/scripts/comparison/build"
opa build \
    -t wasm \
    -e envoy/authz/allow \
    -o "$REPO_DIR/scripts/comparison/build/bundle.tar.gz" \
    "$REPO_DIR/scripts/comparison/policy.rego"

# Extract the .wasm out of the bundle so envoy-wasm.yaml can mount it.
mkdir -p "$REPO_DIR/scripts/comparison/build/opa-bundle"
tar -xzf "$REPO_DIR/scripts/comparison/build/bundle.tar.gz" \
    -C "$REPO_DIR/scripts/comparison/build/opa-bundle" \
    /policy.wasm 2>/dev/null || \
    tar -xzf "$REPO_DIR/scripts/comparison/build/bundle.tar.gz" \
    -C "$REPO_DIR/scripts/comparison/build/opa-bundle" \
    policy.wasm

echo "=== Verify policy compiles + simulates ==="
opa eval -d "$REPO_DIR/scripts/comparison/policy.rego" \
    --input <(echo '{"attributes":{"request":{"http":{"host":"api.bank.com","path":"/transfer","method":"POST"}}}}') \
    'data.envoy.authz.allow' | jq -e '.result[0].expressions[0].value == false' >/dev/null && \
    echo "  Rego deny path verified."

opa eval -d "$REPO_DIR/scripts/comparison/policy.rego" \
    --input <(echo '{"attributes":{"request":{"http":{"host":"api.anthropic.com","path":"/v1/messages","method":"POST"}}}}') \
    'data.envoy.authz.allow' | jq -e '.result[0].expressions[0].value == true' >/dev/null && \
    echo "  Rego allow path verified."

echo ""
echo "=== Setup complete. ==="
echo "Next steps:"
echo "  1. Build latest GVM:  (cd $REPO_DIR && cargo build --release -p gvm-cli -p gvm-proxy)"
echo "  2. Run benchmark:     bash scripts/comparison/bench.sh"
echo "  3. Results land in:   results/comparison-<timestamp>/"
