"""GmailAgent + LangChain tool wrappers for GVM demo.

Provides a GVMAgent subclass with @ic-decorated methods for Gmail and Bank
operations, plus LangChain @tool wrappers that delegate to the agent.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError


class GmailAgent(GVMAgent):
    """AI agent with Gmail and financial tools, all routed through GVM proxy."""

    @ic(
        operation="gvm.messaging.read",
        resource=Resource(service="gmail", tier="external", sensitivity="low"),
    )
    def read_inbox(self) -> dict:
        """IC-1: Read inbox messages. Should be allowed instantly."""
        session = self.create_session()
        resp = session.get(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages"
        )
        _check_response(resp)
        return resp.json()

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="gmail", tier="customer-facing", sensitivity="medium"),
    )
    def send_email(self, to: str, subject: str, body: str) -> dict:
        """IC-2: Send email. Should be delayed 300ms by proxy."""
        session = self.create_session()
        resp = session.post(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            json={"to": to, "subject": subject, "body": body},
        )
        _check_response(resp)
        return resp.json()

    @ic(
        operation="gvm.payment.charge",
        resource=Resource(service="bank", tier="external", sensitivity="critical"),
    )
    def wire_transfer(self, to_account: str, amount: float) -> dict:
        """Deny: Wire transfer. Blocked by SRR (network layer)."""
        session = self.create_session()
        resp = session.post(
            "http://api.bank.com/transfer/123",
            json={"to": to_account, "amount": amount},
        )
        _check_response(resp)
        return resp.json()

    @ic(
        operation="gvm.storage.delete",
        resource=Resource(service="gmail", tier="external", sensitivity="critical"),
    )
    def delete_emails(self, message_id: str) -> dict:
        """Deny: Delete emails. Blocked by ABAC policy (critical data deletion)."""
        session = self.create_session()
        resp = session.delete(
            f"http://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
        )
        _check_response(resp)
        return resp.json()


# Thread-local storage for the last GVM response metadata.
# Updated on every proxied request (Allow, Delay, or Deny).
last_gvm_response = {}


def _check_response(resp):
    """Check proxy response; capture GVM metadata headers; raise on error."""
    global last_gvm_response

    # Capture GVM metadata from response headers (present on all decisions)
    last_gvm_response = {
        "decision": resp.headers.get("X-GVM-Decision"),
        "decision_source": resp.headers.get("X-GVM-Decision-Source"),
        "event_id": resp.headers.get("X-GVM-Event-Id"),
        "trace_id": resp.headers.get("X-GVM-Trace-Id"),
        "engine_ms": resp.headers.get("X-GVM-Engine-Ms"),
        "safety_delay_ms": resp.headers.get("X-GVM-Safety-Delay-Ms"),
        "matched_rule": resp.headers.get("X-GVM-Matched-Rule"),
    }

    if resp.status_code == 200:
        return

    try:
        error_body = resp.json()
    except Exception:
        raise GVMDeniedError(reason=f"HTTP {resp.status_code}", status_code=resp.status_code)

    # Enrich error with proxy response fields
    from gvm.errors import GVMError
    err = GVMError.from_response(error_body, status_code=resp.status_code)
    # Attach GVM headers to the error for inspection
    err.gvm_response = last_gvm_response
    raise err


def gvm_tool(func):
    """Wrap a GVM agent method as a LangChain-compatible tool.

    Handles GVMRollbackError by returning a structured error message
    that instructs the LLM to choose an alternative action path.

    Usage:
        tools = [gvm_tool(agent.read_inbox), gvm_tool(agent.wire_transfer)]
    """

    def wrapped(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
        except GVMRollbackError as e:
            return json.dumps({
                "error": "ACTION_BLOCKED_AND_ROLLED_BACK",
                "blocked_action": e.operation,
                "reason": e.reason,
                "state_restored_to": f"checkpoint #{e.rolled_back_to}" if e.rolled_back_to is not None else "none",
                "instruction": (
                    "This action was blocked by governance policy. "
                    "Your state has been restored to the last safe checkpoint. "
                    "Please choose an alternative approach."
                ),
            })
        except (GVMDeniedError, GVMApprovalRequiredError) as e:
            return json.dumps({
                "error": "ACTION_BLOCKED",
                "reason": str(e),
            })

    wrapped.__name__ = func.__name__
    wrapped.__doc__ = func.__doc__
    return wrapped
