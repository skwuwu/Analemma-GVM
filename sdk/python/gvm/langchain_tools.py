"""GmailAgent + LangChain tool wrappers for GVM demo.

Provides a GVMAgent subclass with @ic-decorated methods for Gmail and Bank
operations, plus LangChain @tool wrappers that delegate to the agent.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError


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


def _check_response(resp):
    """Raise GVM errors based on HTTP status codes from the proxy."""
    if resp.status_code == 200:
        return

    try:
        error_body = resp.json()
        error_msg = error_body.get("error", f"HTTP {resp.status_code}")
    except Exception:
        error_msg = f"HTTP {resp.status_code}"

    if resp.status_code == 403:
        if "approval" in error_msg.lower():
            raise GVMApprovalRequiredError(urgency="Immediate")
        raise GVMDeniedError(reason=error_msg)
    elif resp.status_code == 429:
        from gvm.errors import GVMRateLimitError
        raise GVMRateLimitError()
    else:
        raise GVMDeniedError(reason=error_msg, status_code=resp.status_code)
