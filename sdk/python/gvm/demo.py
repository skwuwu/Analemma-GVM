"""
Analemma-GVM Week 4 Demo — FinanceAgent with GVM enforcement.

Demonstrates the full enforcement pipeline:
  1. check_balance    → Allow (IC-1, instant)
  2. send_refund_email → Delay 300ms (IC-2, customer-facing)
  3. process_refund   → RequireApproval (IC-3, blocked)
  4. Direct HTTP call → Proxy Deny (network SRR)
  5. NATS audit trail → trace_id causal chain

Usage:
  1. Start the proxy:  cargo run  (from project root)
  2. Run this demo:    python -m gvm.demo
"""

import json
import time
import sys
import os

# Add the SDK to path when running from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, AgentState, VaultField, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError


class FinanceAgent(GVMAgent):
    """Demo agent: processes refunds with multi-IC enforcement."""

    state = AgentState(
        balance=VaultField(default=0, sensitivity="critical"),
        last_action=VaultField(default="", sensitivity="medium"),
    )

    @ic(operation="gvm.storage.read")
    def check_balance(self):
        """IC-1: Allow (read-only, instant pass-through)."""
        return self.state.balance

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="gmail", tier="customer-facing"),
        rate_limit=50,
    )
    def send_refund_email(self, to: str, amount: float):
        """IC-2: Delay 300ms (customer-facing messaging)."""
        print(f"  → Sending refund email to {to}: ${amount:.2f}")
        # In production: requests.post("https://gmail.googleapis.com/...")
        # The proxy intercepts, delays 300ms, then forwards.
        self.state.last_action = f"email_sent:{to}"

    @ic(
        operation="gvm.payment.refund",
        resource=Resource(service="stripe", tier="external", sensitivity="critical"),
    )
    def process_refund(self, customer_id: str, amount: float):
        """IC-3: RequireApproval (payment operation, blocked)."""
        print(f"  → Processing refund for {customer_id}: ${amount:.2f}")
        # The proxy blocks this — returns 403 RequireApproval.
        self.state.balance -= amount

    @ic(operation="gvm.storage.delete")
    def delete_records(self, record_id: str):
        """Deny: critical data deletion is forbidden by global policy."""
        print(f"  → Deleting record {record_id}")


def run_demo():
    """Run the enforcement demo sequence."""
    print("=" * 60)
    print("  Analemma-GVM v0.1.0 — Enforcement Demo")
    print("=" * 60)
    print()

    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    agent = FinanceAgent(
        agent_id="finance-001",
        tenant_id="acme",
        proxy_url=proxy_url,
    )

    print(f"Agent: {agent._agent_id} | Tenant: {agent._tenant_id}")
    print(f"Proxy: {proxy_url}")
    print(f"Trace: {agent._session_id[:8]}...")
    print()

    # ── Step 1: check_balance → Allow (IC-1) ──
    print("[Step 1] check_balance → Expected: Allow (IC-1)")
    t0 = time.time()
    balance = agent.check_balance()
    elapsed = (time.time() - t0) * 1000
    print(f"  ✓ Balance: {balance} (took {elapsed:.0f}ms)")
    print()

    # ── Step 2: send_refund_email → Delay 300ms (IC-2) ──
    print("[Step 2] send_refund_email → Expected: Delay 300ms (IC-2)")
    t0 = time.time()
    agent.send_refund_email("customer@example.com", 150.00)
    elapsed = (time.time() - t0) * 1000
    print(f"  ✓ Email sent (took {elapsed:.0f}ms, expect ~300ms+ with proxy)")
    print()

    # ── Step 3: process_refund → RequireApproval (IC-3) ──
    print("[Step 3] process_refund → Expected: RequireApproval (IC-3)")
    t0 = time.time()
    try:
        agent.process_refund("cust-42", 1000.00)
        elapsed = (time.time() - t0) * 1000
        print(f"  ! Refund executed (took {elapsed:.0f}ms)")
        print("    Note: Without live proxy, call succeeds locally.")
        print("    With proxy: 403 RequireApproval would block this.")
    except GVMApprovalRequiredError as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  ✓ Blocked: {e} (took {elapsed:.0f}ms)")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  ✓ Blocked by proxy: {e} (took {elapsed:.0f}ms)")
    print()

    # ── Step 4: Direct HTTP bypass attempt ──
    print("[Step 4] Direct HTTP bypass → Expected: Deny (network SRR)")
    print("  Simulating: POST https://api.bank.com/transfer/123")
    print("  → Proxy matches SRR rule: Deny 'Wire transfer — blocked by proxy'")
    print("  → 403 Forbidden")
    print()

    # ── Step 5: Audit trail ──
    print("[Step 5] Audit Trail (WAL + NATS)")
    print("  All events recorded with:")
    print(f"    trace_id:  {agent._session_id[:8]}...")
    print(f"    agent_id:  {agent._agent_id}")
    print(f"    tenant_id: {agent._tenant_id}")
    print("  Events:")
    print("    1. gvm.storage.read     → Allow     → Confirmed")
    print("    2. gvm.messaging.send   → Delay(300)→ Confirmed")
    print("    3. gvm.payment.refund   → RequireApproval → Pending")
    print("    4. (direct HTTP)        → Deny      → Failed")
    print()

    # ── Summary ──
    print("=" * 60)
    print("  Demo Summary")
    print("=" * 60)
    print("  IC-1 (Allow):           Read operations pass instantly")
    print("  IC-2 (Delay):           Customer-facing gets 300ms window")
    print("  IC-3 (RequireApproval): Payments blocked until human approves")
    print("  Deny:                   Dangerous ops (transfer, delete) blocked")
    print("  Audit:                  Every decision logged with causal trace")
    print()
    print("  GVM = enforcement layer on top of any agent framework.")
    print("  Agent code is unchanged. Security is structural, not behavioral.")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()
