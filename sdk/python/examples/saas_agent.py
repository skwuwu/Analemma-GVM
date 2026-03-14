"""SaaS Agent — quickstart example.

Uses the SaaS template to demonstrate balanced governance:
- Reading CRM data passes instantly (IC-1)
- Sending Slack messages is delayed 300ms (IC-2)
- Data exports require approval (IC-3)

Setup:
  1. Start proxy: GVM_CONFIG=config/templates/saas/proxy.toml cargo run
  2. Run: python examples/saas_agent.py
"""

from gvm import GVMAgent, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError


class SaaSAgent(GVMAgent):

    @ic(
        operation="gvm.storage.read",
        resource=Resource(service="crm", tier="internal", sensitivity="medium"),
    )
    def read_customers(self):
        """IC-1: Read CRM data, instant."""
        return {"customers": ["acme", "globex", "initech"]}

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="slack", tier="customer-facing"),
    )
    def notify_slack(self, channel: str, message: str):
        """IC-2: Slack notification, delayed 300ms."""
        print(f"  Posting to {channel}: {message}")

    @ic(
        operation="gvm.data.export",
        resource=Resource(service="analytics", tier="external", sensitivity="high"),
    )
    def export_report(self, destination: str):
        """IC-3: Data export requires approval."""
        print(f"  Exporting report to {destination}")


if __name__ == "__main__":
    agent = SaaSAgent(agent_id="saas-001", tenant_id="startup")

    print("[1] read_customers → Allow (IC-1)")
    data = agent.read_customers()
    print(f"  Customers: {data}\n")

    print("[2] notify_slack → Delay 300ms (IC-2)")
    agent.notify_slack("#alerts", "Weekly report ready")
    print()

    print("[3] export_report → RequireApproval (IC-3)")
    try:
        agent.export_report("s3://external-bucket/reports/")
    except GVMApprovalRequiredError as e:
        print(f"  Blocked: {e}")
        if hasattr(e, "next_action") and e.next_action:
            print(f"  Next action: {e.next_action}")
    except GVMDeniedError as e:
        print(f"  Denied: {e}")
