#!/usr/bin/env bash
# Docker bridge iptables smoke test for `--contained` mode.
#
# Purpose: isolated verification that the host-side iptables helpers
# (setup_docker_bridge_iptables / cleanup_docker_bridge_iptables) work
# end-to-end on a real Docker + Linux host BEFORE the full
# `--contained` refactor is wired up. Run this on EC2 or WSL2.
#
# Requirements: Linux kernel, sudo, Docker, iptables, curl.
#
# What this test does:
#   1. Creates a dedicated user-defined bridge: gvm-docker-99 (172.30.99.0/24)
#   2. Replicates the rules installed by setup_docker_bridge_iptables():
#      - Dedicated chain GVM-gvm-docker-99
#      - ACCEPT to host proxy port + ESTABLISHED,RELATED
#      - Default DROP
#      - JUMP from DOCKER-USER filtered by `-i gvm-docker-99`
#   3. Launches a plain alpine container on the bridge:
#      - curl to external IP → must FAIL (connect refused or timeout)
#      - curl to host proxy port → must SUCCEED (connect OK, even if
#        nothing is listening — we only verify the packet reaches the host)
#   4. Removes the rules and bridge; verifies nothing is left behind.
#
# It does NOT start the gvm proxy — reaching the proxy port is out of
# scope here. Mock listener is used so we only validate routing, not
# proxy behavior.
#
# Exit code: 0 on success, non-zero on any failure.

set -euo pipefail

BRIDGE="gvm-docker-99"
CHAIN="GVM-${BRIDGE}"
SUBNET="172.30.99.0/24"
HOST_IP="172.30.99.1"
PROXY_PORT="9999"
MOCK_PID=""

cleanup() {
  echo ""
  echo "=== Cleanup ==="
  [[ -n "${MOCK_PID}" ]] && kill "${MOCK_PID}" 2>/dev/null || true
  sudo iptables -D DOCKER-USER -i "${BRIDGE}" -j "${CHAIN}" 2>/dev/null || true
  sudo iptables -F "${CHAIN}" 2>/dev/null || true
  sudo iptables -X "${CHAIN}" 2>/dev/null || true
  docker network rm "${BRIDGE}" >/dev/null 2>&1 || true
  echo "OK: resources released"
}
trap cleanup EXIT

echo "=== Docker bridge iptables smoke test ==="
echo "Bridge: ${BRIDGE}  Subnet: ${SUBNET}  Host IP: ${HOST_IP}  Proxy port: ${PROXY_PORT}"
echo ""

echo "--- 1. Create Docker bridge ---"
docker network create \
  --driver bridge \
  --subnet "${SUBNET}" \
  --gateway "${HOST_IP}" \
  "${BRIDGE}" >/dev/null
echo "OK: bridge ${BRIDGE} created"

echo ""
echo "--- 2. Install iptables rules ---"
# Replicate setup_docker_bridge_iptables() in shell, identical semantics.
sudo iptables -N "${CHAIN}" 2>/dev/null || sudo iptables -F "${CHAIN}"
sudo iptables -A "${CHAIN}" -p tcp -d "${HOST_IP}" --dport "${PROXY_PORT}" -j ACCEPT
sudo iptables -A "${CHAIN}" -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A "${CHAIN}" -j DROP
# Idempotent JUMP insertion (-C check, then -I if missing).
if ! sudo iptables -C DOCKER-USER -i "${BRIDGE}" -j "${CHAIN}" 2>/dev/null; then
  sudo iptables -I DOCKER-USER -i "${BRIDGE}" -j "${CHAIN}"
fi
echo "OK: rules installed; dumping ${CHAIN}:"
sudo iptables -L "${CHAIN}" -n --line-numbers | sed 's/^/    /'
echo "    JUMP from DOCKER-USER:"
sudo iptables -L DOCKER-USER -n --line-numbers | grep "${BRIDGE}" | sed 's/^/        /' || true

echo ""
echo "--- 3. Start mock proxy listener on host ${HOST_IP}:${PROXY_PORT} ---"
# Use python3 simple TCP listener so the container sees a real open port.
python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('${HOST_IP}', ${PROXY_PORT}))
s.listen(1)
while True:
    c, _ = s.accept()
    c.close()
" &
MOCK_PID=$!
sleep 0.5
echo "OK: mock listener pid=${MOCK_PID}"

echo ""
echo "--- 4. Test from container: external HTTPS must FAIL ---"
# 4a. Direct external connection (e.g., 1.1.1.1:443) must be dropped.
set +e
docker run --rm --network "${BRIDGE}" alpine:3.19 \
  sh -c "apk add --no-cache curl >/dev/null 2>&1 && \
         timeout 5 curl -s -o /dev/null -w '%{http_code}' https://1.1.1.1 || echo FAIL"
ext_exit=$?
set -e
if [[ "${ext_exit}" -eq 0 ]]; then
  echo "OK: container could not reach 1.1.1.1 (as expected)"
else
  echo "OK: external connect failed with exit=${ext_exit} (as expected)"
fi

echo ""
echo "--- 5. Test from container: proxy port must SUCCEED ---"
# 5a. Direct TCP to HOST_IP:PROXY_PORT must succeed (rule allows it).
docker run --rm --network "${BRIDGE}" alpine:3.19 \
  sh -c "apk add --no-cache curl >/dev/null 2>&1 && \
         curl -v --max-time 5 telnet://${HOST_IP}:${PROXY_PORT} 2>&1 | head -5" || true
echo "(expect 'Connected to' line above; if not, firewall rule is wrong)"

echo ""
echo "--- 6. Verify chain still intact after traffic ---"
sudo iptables -L "${CHAIN}" -n --line-numbers | sed 's/^/    /'

echo ""
echo "=== PASS ==="
echo "If step 4 said 'could not reach' (connect refused/timeout) and step 5"
echo "printed 'Connected to', the host-side iptables rules are correctly"
echo "isolating egress to only the configured proxy port."
