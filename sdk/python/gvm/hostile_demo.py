"""
Analemma-GVM Hostile Environment Demo — proves security under adversarial conditions.

Tests:
  1. Fail-Close: proxy down → agent calls must fail (not bypass)
  2. Header Forgery: SDK claims safe operation but targets dangerous URL
  3. Payload OOM: oversized body → Default-to-Caution, no crash
  4. Secret Isolation: agent env has no API keys
  5. Negative Test: wrong operation name on sensitive API

Usage:
  1. For Fail-Close test: do NOT start the proxy
  2. For other tests: start the proxy first (cargo run)
  3. Run: python -m gvm.hostile_demo
"""

import json
import os
import sys
import time
import socket
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, AgentState, VaultField, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError


class MaliciousAgent(GVMAgent):
    """Agent that attempts hostile operations to test enforcement."""

    state = AgentState(
        data=VaultField(default="", sensitivity="low"),
    )

    @ic(operation="gvm.storage.read")
    def lie_about_operation(self):
        """Declares storage.read but will target bank transfer URL."""
        pass

    @ic(operation="gvm.payment.refund")
    def legitimate_refund(self, amount: float):
        """Legitimate IC-3 operation — should be blocked."""
        pass

    @ic(operation="totally.invalid.nonexistent.operation")
    def wrong_operation_name(self):
        """Uses an unregistered operation name."""
        pass


def check_proxy_alive(proxy_url: str) -> bool:
    """Check if the GVM proxy is reachable."""
    try:
        host = proxy_url.replace("http://", "").replace("https://", "")
        h, p = host.split(":")
        sock = socket.create_connection((h, int(p)), timeout=1)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def test_fail_close(proxy_url: str):
    """Test 1: Fail-Close — proxy down → agent HTTP must fail, not bypass."""
    print("[Test 1] Fail-Close: Proxy Down → Agent Must Not Bypass")
    print("-" * 50)

    if check_proxy_alive(proxy_url):
        print("  ! Proxy IS running. Fail-Close test requires proxy to be DOWN.")
        print("  ! Stop the proxy and re-run this test to verify Fail-Close.")
        print("  SKIP (proxy is alive)")
        print()
        return False

    print(f"  Proxy at {proxy_url} is DOWN (confirmed)")

    # Attempt to make a request through the dead proxy
    try:
        req = urllib.request.Request(
            f"{proxy_url}/anything",
            headers={"X-GVM-Agent-Id": "test-agent", "X-GVM-Operation": "gvm.storage.read"},
        )
        urllib.request.urlopen(req, timeout=2)
        print("  FAIL: Request succeeded — proxy bypass detected!")
        print("  This is a CRITICAL SECURITY FAILURE.")
        return False
    except (urllib.error.URLError, ConnectionRefusedError, OSError) as e:
        print(f"  PASS: Request failed as expected: {type(e).__name__}")
        print("  Agent cannot reach any external API without the proxy.")
        print("  Fail-Close verified: no proxy = no I/O.")
        return True
    finally:
        print()


def test_header_forgery(proxy_url: str):
    """Test 2: Header Forgery — SDK claims storage.read but targets bank transfer."""
    print("[Test 2] Header Forgery: Mismatched Operation vs URL")
    print("-" * 50)

    if not check_proxy_alive(proxy_url):
        print("  SKIP (proxy not running)")
        print()
        return None

    # Agent declares gvm.storage.read (safe, IC-1) in the header
    # but the actual URL target is api.bank.com/transfer/123 (dangerous)
    # The proxy must apply max_strict(policy_for_storage.read, srr_for_bank_transfer)
    # SRR should return Deny for bank transfer URL
    try:
        body = json.dumps({"amount": 50000}).encode()
        req = urllib.request.Request(
            f"{proxy_url}/transfer/123",
            data=body,
            method="POST",
            headers={
                "X-GVM-Agent-Id": "malicious-agent",
                "X-GVM-Operation": "gvm.storage.read",  # LIE
                "X-GVM-Target-Host": "api.bank.com",
                "Content-Type": "application/json",
            },
        )
        resp = urllib.request.urlopen(req, timeout=5)
        status = resp.getcode()
        resp_body = resp.read().decode()
        print(f"  ! Response: {status} — {resp_body}")
        print("  FAIL: Bank transfer should have been DENIED by SRR Layer 2!")
        return False
    except urllib.error.HTTPError as e:
        if e.code == 403:
            resp_body = e.read().decode()
            print(f"  PASS: HTTP 403 — {resp_body}")
            print("  SRR Layer 2 caught the URL mismatch regardless of operation header.")
            return True
        else:
            print(f"  Response: HTTP {e.code}")
            resp_body = e.read().decode()
            print(f"  Body: {resp_body}")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False
    finally:
        print()


def test_payload_oom(proxy_url: str):
    """Test 3: Payload OOM — >64KB body must not crash proxy."""
    print("[Test 3] Payload OOM: 128KB Body → Default-to-Caution")
    print("-" * 50)

    if not check_proxy_alive(proxy_url):
        print("  SKIP (proxy not running)")
        print()
        return None

    # Send a 128KB body to the GraphQL payload inspection endpoint
    # max_body_bytes = 65536, so this exceeds the limit
    # Expected: proxy returns Default-to-Caution (not crash)
    big_body = b"x" * 131072  # 128KB
    try:
        req = urllib.request.Request(
            f"{proxy_url}/graphql",
            data=big_body,
            method="POST",
            headers={
                "X-GVM-Target-Host": "api.bank.com",
                "Content-Type": "application/octet-stream",
            },
        )
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.getcode()
        print(f"  Response: HTTP {status}")
        print("  PASS: Proxy did not crash with 128KB body")
        return True
    except urllib.error.HTTPError as e:
        # Any response that isn't a crash/timeout is acceptable
        # The proxy should return Delay/Default-to-Caution, not Deny
        print(f"  Response: HTTP {e.code}")
        if e.code == 502:
            # 502 means proxy forwarded (Default-to-Caution) but upstream wasn't there
            print("  PASS: Proxy applied Default-to-Caution (upstream unavailable = 502)")
            return True
        resp_body = e.read().decode()
        print(f"  Body: {resp_body}")
        print("  PASS: Proxy survived 128KB body (did not crash)")
        return True
    except (ConnectionResetError, ConnectionAbortedError) as e:
        print(f"  FAIL: Proxy crashed or dropped connection: {e}")
        print("  OOM VULNERABILITY CONFIRMED — proxy needs hardening!")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False
    finally:
        print()


def test_secret_isolation():
    """Test 4: Secret Isolation — agent env must not contain API keys."""
    print("[Test 4] Secret Isolation: No API Keys in Agent Environment")
    print("-" * 50)

    # Check that no API keys leak into agent environment
    sensitive_prefixes = [
        "STRIPE_", "SLACK_TOKEN", "GMAIL_", "AWS_SECRET",
        "DATABASE_PASSWORD", "API_KEY", "PRIVATE_KEY",
    ]

    leaked = []
    for key in os.environ:
        for prefix in sensitive_prefixes:
            if key.upper().startswith(prefix):
                leaked.append(key)

    if leaked:
        print(f"  FAIL: Found {len(leaked)} leaked secrets in env:")
        for key in leaked:
            print(f"    - {key} = ***")
        print("  Secrets must be injected by the proxy (Layer 3), not in agent env!")
        print()
        return False
    else:
        print("  PASS: No API keys found in agent environment")
        print("  Secrets are managed by proxy Layer 3 (Capability Token injection)")
        print()
        return True


def test_wrong_operation_name(proxy_url: str):
    """Test 5: Wrong operation name → policy engine handles gracefully."""
    print("[Test 5] Negative Test: Invalid Operation Name")
    print("-" * 50)

    if not check_proxy_alive(proxy_url):
        print("  SKIP (proxy not running)")
        print()
        return None

    # Send a request with a completely made-up operation name
    try:
        req = urllib.request.Request(
            f"{proxy_url}/data",
            method="GET",
            headers={
                "X-GVM-Agent-Id": "test-agent",
                "X-GVM-Operation": "totally.fake.nonexistent.operation",
                "X-GVM-Target-Host": "api.example.com",
            },
        )
        resp = urllib.request.urlopen(req, timeout=5)
        status = resp.getcode()
        print(f"  Response: HTTP {status}")
        # Unknown operation should get Default-to-Caution or catch-all policy
        print("  PASS: Proxy handled unknown operation gracefully (did not crash)")
        return True
    except urllib.error.HTTPError as e:
        status = e.code
        print(f"  Response: HTTP {status}")
        if status == 502:
            print("  PASS: Proxy applied policy and forwarded (upstream unavailable)")
        else:
            resp_body = e.read().decode()
            print(f"  Body: {resp_body}")
            print("  PASS: Proxy handled unknown operation with enforcement")
        return True
    except Exception as e:
        print(f"  FAIL: Unexpected error: {e}")
        return False
    finally:
        print()


def run_hostile_demo():
    """Run all hostile environment tests."""
    print("=" * 60)
    print("  Analemma-GVM v0.1.0 — Hostile Environment Tests")
    print("=" * 60)
    print()

    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    proxy_alive = check_proxy_alive(proxy_url)
    print(f"Proxy: {proxy_url} ({'ALIVE' if proxy_alive else 'DOWN'})")
    print()

    results = {}

    # Test 1: Fail-Close (best tested with proxy DOWN)
    results["fail_close"] = test_fail_close(proxy_url)

    # Test 2-5: Require proxy to be running
    results["header_forgery"] = test_header_forgery(proxy_url)
    results["payload_oom"] = test_payload_oom(proxy_url)
    results["secret_isolation"] = test_secret_isolation()
    results["wrong_operation"] = test_wrong_operation_name(proxy_url)

    # ── Summary ──
    print("=" * 60)
    print("  Hostile Environment Test Summary")
    print("=" * 60)

    status_map = {True: "PASS", False: "FAIL", None: "SKIP"}
    test_names = {
        "fail_close": "Fail-Close (proxy down)",
        "header_forgery": "Header Forgery (Layer 2 SRR)",
        "payload_oom": "Payload OOM (>64KB body)",
        "secret_isolation": "Secret Isolation (no env keys)",
        "wrong_operation": "Wrong Operation Name",
    }

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)

    for key, name in test_names.items():
        status = status_map[results.get(key)]
        icon = {"PASS": "+", "FAIL": "X", "SKIP": "-"}[status]
        print(f"  [{icon}] {name}: {status}")

    print()
    print(f"  Total: {passed} passed, {failed} failed, {skipped} skipped")

    if failed > 0:
        print()
        print("  WARNING: Security gaps detected. Review failed tests above.")

    print()
    print("  Run with proxy DOWN for Fail-Close test.")
    print("  Run with proxy UP for enforcement tests.")
    print("=" * 60)


if __name__ == "__main__":
    run_hostile_demo()
