"""GVMAgent base class — proxy-aware agent with state management (PART 7)."""

import os
import uuid
from typing import Optional

import gvm.decorator as decorator
from gvm.checkpoint import CheckpointManager
from gvm.state import AgentState


class GVMAgent:
    """Base class for GVM-controlled agents.

    Handles:
    - Automatic proxy configuration (all HTTP goes through GVM proxy)
    - Agent identity (agent_id, tenant_id, session_id)
    - State binding (VaultField -> Vault)
    - Trace context initialization
    - Checkpoint/rollback (auto or manual via @ic(checkpoint=True))

    Checkpoint modes (set via class attribute or constructor):
        auto_checkpoint = None      # disabled (default)
        auto_checkpoint = "ic2+"    # checkpoint before IC-2 and IC-3 operations
        auto_checkpoint = "ic3"     # checkpoint before IC-3 only
        auto_checkpoint = "all"     # checkpoint before every @ic operation

    Usage:
        class FinanceAgent(GVMAgent):
            auto_checkpoint = "ic2+"

            state = AgentState(
                balance=VaultField(default=0, sensitivity="critical"),
            )

            @ic(operation="gvm.payment.refund")
            def process_refund(self, customer_id, amount):
                ...

        agent = FinanceAgent(agent_id="finance-001")
    """

    state: Optional[AgentState] = None
    auto_checkpoint: Optional[str] = None  # None, "ic2+", "ic3", "all"

    def __init__(
        self,
        agent_id: str,
        tenant_id: str = None,
        session_id: str = None,
        proxy_url: str = None,
        auto_checkpoint: str = None,
    ):
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._session_id = session_id or str(uuid.uuid4())
        self._proxy_url = proxy_url or os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")

        # Checkpoint mode: constructor overrides class attribute
        if auto_checkpoint is not None:
            self.auto_checkpoint = auto_checkpoint

        # Checkpoint manager for state rollback
        self._checkpoint_mgr = CheckpointManager(self._agent_id, self._proxy_url)

        # Conversation history for LLM agents
        self._conversation_history = []

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

    def _get_checkpointable_state(self) -> dict:
        """Collect agent state for checkpoint serialization."""
        state = {
            "_conversation_history": self._conversation_history.copy(),
            "_step": self._checkpoint_mgr.current_step,
        }
        # Collect VaultField values
        if self.state is not None:
            for name in self.state.get_vault_fields():
                state[f"vault:{name}"] = getattr(self.state, name, None)
            for name in self.state._local_fields:
                state[f"local:{name}"] = getattr(self.state, name, None)
        return state

    def _restore_from_state(self, checkpoint_state: dict):
        """Apply checkpoint state to this agent."""
        self._conversation_history = checkpoint_state.get(
            "_conversation_history", []
        )
        if self.state is not None:
            for name in self.state.get_vault_fields():
                key = f"vault:{name}"
                if key in checkpoint_state:
                    setattr(self.state, name, checkpoint_state[key])
            for name in self.state._local_fields:
                key = f"local:{name}"
                if key in checkpoint_state:
                    setattr(self.state, name, checkpoint_state[key])

    def _should_auto_checkpoint(self, ic_level: int) -> bool:
        """Determine if auto-checkpoint is enabled for this IC level."""
        if self.auto_checkpoint is None:
            return False
        if self.auto_checkpoint == "all":
            return True
        if self.auto_checkpoint == "ic2+" and ic_level >= 2:
            return True
        if self.auto_checkpoint == "ic3" and ic_level >= 3:
            return True
        return False

    def create_session(self):
        """Create a requests.Session pre-configured to route through the GVM proxy.

        Usage:
            session = agent.create_session()
            session.get("https://api.example.com/data")
            # -> routed through GVM proxy with headers

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
