"""Finance Agent — quickstart example.

Uses the finance template to demonstrate strict payment governance:
- Balance checks pass instantly (IC-1)
- Refund emails are delayed 500ms (IC-2)
- Wire transfers are denied (IC-3 / SRR)

Setup:
  1. Copy config/templates/finance/ to config/
  2. Start proxy: GVM_CONFIG=config/templates/finance/proxy.toml cargo run
  3. Run: python examples/finance_agent.py
"""

from gvm import GVMAgent, AgentState, VaultField, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError


class FinanceAgent(GVMAgent):
    state = AgentState(
        balance=VaultField(default=0, sensitivity="critical"),
    )

    @ic(operation="gvm.storage.read")
    def check_balance(self):
        """IC-1: Read-only, instant."""
        return self.state.balance

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="gmail", tier="customer-facing"),
    )
    def send_receipt(self, to: str, amount: float):
        """IC-2: Customer-facing email, delayed 500ms."""
        print(f"  Sending receipt to {to}: ${amount:.2f}")

    @ic(
        operation="gvm.payment.charge",
        resource=Resource(service="bank", tier="external", sensitivity="critical"),
    )
    def wire_transfer(self, to: str, amount: float):
        """Denied: wire transfers are blocked."""
        print(f"  Transferring ${amount:.2f} to {to}")


if __name__ == "__main__":
    agent = FinanceAgent(agent_id="finance-001", tenant_id="acme")

    print("[1] check_balance → Allow (IC-1)")
    balance = agent.check_balance()
    print(f"  Balance: {balance}\n")

    print("[2] send_receipt → Delay 500ms (IC-2)")
    agent.send_receipt("customer@example.com", 99.99)
    print()

    print("[3] wire_transfer → Deny")
    try:
        agent.wire_transfer("offshore-account", 50000)
    except (GVMDeniedError, GVMApprovalRequiredError) as e:
        print(f"  Blocked: {e}")
        if hasattr(e, "next_action") and e.next_action:
            print(f"  Next action: {e.next_action}")
