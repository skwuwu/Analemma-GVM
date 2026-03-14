"""GVMAgent base class — proxy-aware agent with state management (PART 7)."""

import os
import uuid
from typing import Optional

import gvm.decorator as decorator
from gvm.state import AgentState


class GVMAgent:
    """Base class for GVM-controlled agents.

    Handles:
    - Automatic proxy configuration (all HTTP goes through GVM proxy)
    - Agent identity (agent_id, tenant_id, session_id)
    - State binding (VaultField ↔ Vault)
    - Trace context initialization

    Usage:
        class FinanceAgent(GVMAgent):
            state = AgentState(
                balance=VaultField(default=0, sensitivity="critical"),
            )

            @ic(operation="gvm.payment.refund")
            def process_refund(self, customer_id, amount):
                ...

        agent = FinanceAgent(agent_id="finance-001")
    """

    state: Optional[AgentState] = None

    def __init__(
        self,
        agent_id: str,
        tenant_id: str = None,
        session_id: str = None,
        proxy_url: str = None,
    ):
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._session_id = session_id or str(uuid.uuid4())
        self._proxy_url = proxy_url or os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")

        # Current GVM headers for the next outgoing request
        self._pending_headers = {}

        # Bind state if declared
        if self.state is not None:
            self.state._bind(self)

        # Register the header setter so @ic decorator can inject headers
        decorator._gvm_header_setter = self._apply_gvm_headers

        # Initialize trace context for this agent session
        decorator.set_trace_id(str(uuid.uuid4()))

    def _apply_gvm_headers(self, headers: dict):
        """Store GVM headers to be injected into the next HTTP request.

        The proxy configuration (env HTTP_PROXY / requests session) ensures
        all HTTP traffic goes through the GVM proxy, which reads these headers.
        """
        self._pending_headers = headers

    def get_proxy_url(self) -> str:
        """Return the configured GVM proxy URL."""
        return self._proxy_url

    def get_pending_headers(self) -> dict:
        """Return and clear pending GVM headers for the next request."""
        headers = self._pending_headers
        self._pending_headers = {}
        return headers

    def create_session(self):
        """Create a requests.Session pre-configured to route through the GVM proxy.

        Usage:
            session = agent.create_session()
            session.get("https://api.example.com/data")
            # → routed through GVM proxy with headers

        Requires: pip install requests
        """
        try:
            import requests
        except ImportError:
            raise ImportError(
                "requests library required for create_session(). Install: pip install requests"
            )

        session = requests.Session()
        session.proxies = {
            "http": self._proxy_url,
            "https": self._proxy_url,
        }

        # Hook to inject GVM headers into every request
        original_prepare = session.prepare_request

        def prepare_with_gvm(request):
            prepared = original_prepare(request)
            headers = self.get_pending_headers()
            for key, value in headers.items():
                if value:  # Skip empty values
                    prepared.headers[key] = value
            # Set target host for the proxy
            if "Host" in prepared.headers:
                prepared.headers["X-GVM-Target-Host"] = prepared.headers["Host"]
            return prepared

        session.prepare_request = prepare_with_gvm
        return session
