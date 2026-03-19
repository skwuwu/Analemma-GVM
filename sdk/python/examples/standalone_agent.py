"""Standalone GVM usage — no inheritance required.

Demonstrates how to add GVM governance to any existing code
with just two imports and zero class structure changes.

Setup:
  1. Start proxy: cargo run (or gvm proxy start)
  2. Run: python examples/standalone_agent.py

This is the recommended pattern for integrating GVM into existing
agent frameworks (CrewAI, AutoGen, OpenAI Agents SDK, etc.).
"""

from gvm import ic, gvm_session, configure, Resource
from gvm.errors import GVMDeniedError

# One-time configuration (or use GVM_AGENT_ID / GVM_PROXY_URL env vars)
configure(agent_id="standalone-001", tenant_id="acme")


# --- Just add @ic to existing functions ---


@ic(operation="gvm.messaging.read")
def read_inbox():
    """IC-1: Read-only operation, allowed instantly."""
    session = gvm_session()
    resp = session.get("http://gmail.googleapis.com/gmail/v1/users/me/messages")
    return resp.json()


@ic(
    operation="gvm.messaging.send",
    resource=Resource(service="gmail", tier="customer-facing"),
)
def send_email(to: str, subject: str, body: str):
    """IC-2: Customer-facing email, delayed 300ms by proxy."""
    session = gvm_session()
    resp = session.post(
        "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        json={"to": to, "subject": subject, "body": body},
    )
    return resp.json()


@ic(
    operation="gvm.payment.charge",
    resource=Resource(service="bank", tier="external", sensitivity="critical"),
)
def wire_transfer(to_account: str, amount: float):
    """IC-3: Wire transfer, denied by SRR (network layer)."""
    session = gvm_session()
    resp = session.post(
        "http://api.bank.com/transfer/123",
        json={"to": to_account, "amount": amount},
    )
    return resp.json()


# --- Works with any framework ---


# Example: adding GVM to a CrewAI agent (hypothetical)
#
#   class ResearchAgent(CrewAIAgent):  # keeps CrewAI inheritance
#       @ic(operation="gvm.search.web")
#       def search(self, query):
#           session = gvm_session()
#           return session.get(f"http://api.search.com/?q={query}").json()
#
# Example: LangChain @tool stacking
#
#   from langchain_core.tools import tool
#
#   @tool
#   @ic(operation="gvm.messaging.send")
#   def send_email(to: str, subject: str, body: str):
#       """Send an email via Gmail."""
#       session = gvm_session()
#       return session.post(...).json()
#
#   tools = [send_email]  # standard LangChain tool list


if __name__ == "__main__":
    print("=== GVM Standalone Mode (no inheritance) ===\n")

    print("[1] read_inbox → Allow (IC-1)")
    try:
        result = read_inbox()
        print(f"  Result: {result}\n")
    except Exception as e:
        print(f"  {e}\n")

    print("[2] send_email → Delay 300ms (IC-2)")
    try:
        result = send_email("user@example.com", "Hello", "Test email")
        print(f"  Result: {result}\n")
    except Exception as e:
        print(f"  {e}\n")

    print("[3] wire_transfer → Deny (IC-3)")
    try:
        wire_transfer("offshore-account", 50000)
    except GVMDeniedError as e:
        print(f"  Blocked: {e}")
        if hasattr(e, "next_action") and e.next_action:
            print(f"  Next action: {e.next_action}")
    except Exception as e:
        print(f"  {e}")
