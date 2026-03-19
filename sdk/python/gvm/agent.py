"""GVMAgent base class — proxy-aware agent with state management.

Use GVMAgent when you need advanced features (checkpoint, state, rollback).
For simple governance without inheritance, use @ic + gvm_session() directly.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from gvm.checkpoint import CheckpointManager
from gvm.decorator import set_trace_id
from gvm.session import gvm_session, configure as _configure_session
from gvm.state import AgentState

# Maximum conversation history turns to include in a checkpoint.
# Older turns are truncated to prevent checkpoint bloat.
# Override per-agent via class attribute or constructor.
MAX_HISTORY_TURNS = 50


class GVMAgent:
    """Base class for GVM-controlled agents with full lifecycle management.

    Provides checkpoint/rollback, state management, and trace context on top
    of the core @ic + gvm_session() primitives.

    For simple governance without inheritance, use standalone mode instead:

        from gvm import ic, gvm_session, configure
        configure(agent_id="my-agent")

        @ic(operation="gvm.messaging.send")
        def send_email(to, subject, body):
            session = gvm_session()
            return session.post(...).json()

    GVMAgent is for when you need:
        - auto_checkpoint: automatic state snapshots before risky operations
        - AgentState + VaultField: encrypted sensitive state management
        - Conversation history tracking for LLM agents
        - Automatic rollback on denied operations

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
    max_history_turns: int = MAX_HISTORY_TURNS

    def __init__(
        self,
        agent_id: str,
        tenant_id: str = None,
        session_id: str = None,
        proxy_url: str = None,
        auto_checkpoint: str = None,
        max_history_turns: int = None,
    ):
        self._agent_id = agent_id
        self._tenant_id = tenant_id
        self._session_id = session_id or str(uuid.uuid4())
        self._proxy_url = proxy_url or os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
        self._actions_taken = []
        self._last_llm_response = None

        # Checkpoint mode: constructor overrides class attribute
        if auto_checkpoint is not None:
            self.auto_checkpoint = auto_checkpoint
        if max_history_turns is not None:
            self.max_history_turns = max_history_turns

        # Checkpoint manager for state rollback
        self._checkpoint_mgr = CheckpointManager(self._agent_id, self._proxy_url)

        # Conversation history for LLM agents
        self._conversation_history = []

        # Bind state if declared
        if self.state is not None:
            self.state._bind(self)

        # Configure the session module with this agent's identity so that
        # @ic can pick up agent_id/tenant_id when building headers.
        # (When @ic detects a GVMAgent instance, it reads directly from self,
        #  so this is mainly for gvm_session() proxy URL.)
        _configure_session(
            agent_id=self._agent_id,
            tenant_id=self._tenant_id,
            proxy_url=self._proxy_url,
        )

        # Initialize trace context for this agent session
        set_trace_id(str(uuid.uuid4()))

    def create_session(self):
        """Create a requests.Session pre-configured to route through the GVM proxy.

        Delegates to gvm_session() with this agent's proxy URL.
        Headers set by @ic are automatically injected.

        Usage:
            session = agent.create_session()
            session.get("https://api.example.com/data")
            # -> routed through GVM proxy with governance headers

        Requires: pip install requests
        """
        return gvm_session(proxy_url=self._proxy_url)

    def get_proxy_url(self) -> str:
        """Return the configured GVM proxy URL."""
        return self._proxy_url

    def _get_checkpointable_state(self) -> dict:
        """Collect agent state for checkpoint serialization.

        Snapshot targets (minimum set for agent to resume after rollback):
          1. Conversation history — without this, rollback is meaningless
          2. Execution position — step counter, actions taken
          3. Business state — VaultField + local field values
          4. Last LLM response — for replay fidelity
          5. Metadata — version, timestamp, identity

        Explicitly excluded (and why):
          - Local variables: not serializable, LLM reconstructs from history
          - File handles / sockets / DB connections: not serializable, reconnect
          - Third-party library state: inaccessible
          - Vector DB contents: external service, outside GVM scope
          - Already-executed side effects: irreversible (proxy prevents these)
        """
        # Truncate history to prevent checkpoint bloat
        history = self._conversation_history
        if len(history) > self.max_history_turns:
            history = history[-self.max_history_turns:]

        state = {
            # 1. LLM context (most important — rollback is meaningless without this)
            "_conversation_history": [h.copy() if isinstance(h, dict) else h for h in history],
            # 2. Execution position
            "_step": self._checkpoint_mgr.current_step,
            "_actions_taken": self._actions_taken.copy(),
            # 3. Last LLM response (replay fidelity)
            "_last_llm_response": self._last_llm_response,
            # 4. Metadata
            "_checkpoint_version": "gvm-checkpoint-v1",
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_agent_id": self._agent_id,
            "_session_id": self._session_id,
        }

        # 3. Business state: VaultField + local field values
        if self.state is not None:
            for name in self.state.get_vault_fields():
                state[f"vault:{name}"] = getattr(self.state, name, None)
            for name in self.state._local_fields:
                state[f"local:{name}"] = getattr(self.state, name, None)

        return state

    def _restore_from_state(self, checkpoint_state: dict):
        """Apply checkpoint state to this agent.

        Restores conversation history, execution position, business state,
        and last LLM response. Validates checkpoint version for compatibility.
        """
        # Version check
        version = checkpoint_state.get("_checkpoint_version")
        if version and version != "gvm-checkpoint-v1":
            import logging
            logging.getLogger("gvm.agent").warning(
                "Checkpoint version mismatch: expected gvm-checkpoint-v1, got %s",
                version,
            )

        # 1. Conversation history (most important)
        self._conversation_history = checkpoint_state.get(
            "_conversation_history", []
        )

        # 2. Execution position
        self._actions_taken = checkpoint_state.get("_actions_taken", [])

        # 3. Last LLM response
        self._last_llm_response = checkpoint_state.get("_last_llm_response")

        # 4. Business state: VaultField + local field values
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
