"""@ic decorator — semantic operation declaration for GVM proxy.

Works on standalone functions, class methods, and GVMAgent methods:

    # Standalone (no inheritance required)
    @ic(operation="gvm.messaging.send")
    def send_email(to, subject, body):
        session = gvm_session()
        return session.post(...).json()

    # GVMAgent method (full features: checkpoint, state, rollback)
    class MyAgent(GVMAgent):
        @ic(operation="gvm.messaging.send")
        def send_email(self, to, subject, body):
            session = self.create_session()
            ...

    # Stackable with LangChain @tool
    @tool
    @ic(operation="gvm.messaging.send")
    def send_email(to: str, subject: str, body: str):
        \"\"\"Send an email via Gmail.\"\"\"
        ...
"""

import functools
import json
import re
import uuid
import warnings
import threading
from typing import Optional

from gvm.errors import GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError
from gvm.resource import Resource
from gvm.session import (
    set_pending_headers,
    has_pending_headers,
    get_and_clear_pending_headers,
    get_agent_id,
    get_tenant_id,
)

# Operation names must match: alphanumeric, dots, hyphens, underscores only.
# Prevents header injection via newlines or special characters in operation names.
_OPERATION_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

# Thread-local storage for trace context propagation
_trace_context = threading.local()


def get_trace_id() -> str:
    """Get or create the current trace ID for causal tracking."""
    if not hasattr(_trace_context, "trace_id") or _trace_context.trace_id is None:
        _trace_context.trace_id = str(uuid.uuid4())
    return _trace_context.trace_id


def set_trace_id(trace_id: str):
    """Set the trace ID for the current thread (used in multi-step workflows)."""
    _trace_context.trace_id = trace_id


def get_current_event_id() -> Optional[str]:
    """Get the event ID of the currently executing operation (for parent linking)."""
    return getattr(_trace_context, "current_event_id", None)


def _set_current_event_id(event_id: str):
    _trace_context.current_event_id = event_id


def _infer_ic_level(operation: str) -> int:
    """Infer IC level from operation name for auto-checkpoint decisions.

    IC-1: read operations (instant allow)
    IC-2: send/write operations (delay)
    IC-3: payment/identity/delete operations (require approval or deny)
    """
    if operation.endswith(".read") or operation.endswith(".list"):
        return 1
    if (
        operation.startswith("gvm.payment")
        or operation.startswith("gvm.identity")
        or operation.endswith(".delete")
    ):
        return 3
    return 2


def _is_gvm_agent(obj) -> bool:
    """Duck-type check for GVMAgent instance (avoids circular import)."""
    return (
        hasattr(obj, "_agent_id")
        and hasattr(obj, "_checkpoint_mgr")
        and hasattr(obj, "_session_id")
    )


def ic(
    operation: str = None,
    rate_limit: int = None,
    resource: Resource = None,
    checkpoint: bool = None,
    **context_kwargs,
):
    """Declare a function or method as a GVM-controlled operation.

    Works on standalone functions and class methods (with or without GVMAgent).
    Preserves function signature for compatibility with LangChain @tool and
    other decorator-based frameworks.

    Args:
        operation: Operation name (e.g. "gvm.messaging.send").
                   If omitted, auto-generated as "custom.auto.{func_name}".
        rate_limit: Max invocations per minute (optional).
        resource: Target resource descriptor (optional).
        checkpoint: If True, save a checkpoint before this operation (GVMAgent only).
                    If None, defer to agent's auto_checkpoint setting.
        **context_kwargs: Additional ABAC context attributes (e.g. amount=None).

    Usage:
        # Standalone function (no inheritance)
        @ic(operation="gvm.messaging.send",
            resource=Resource(service="slack", tier="customer-facing"))
        def send_alert(channel, message):
            session = gvm_session()
            return session.post(...).json()

        # GVMAgent method (checkpoint + rollback support)
        @ic(operation="gvm.payment.charge", checkpoint=True)
        def charge_card(self, amount):
            ...

        # Minimal version (operation auto-inferred)
        @ic()
        def send_email(to, subject, body):
            ...

        # Stackable with LangChain @tool
        @tool
        @ic(operation="gvm.messaging.send")
        def send_email(to: str, subject: str, body: str):
            \"\"\"Send an email via Gmail.\"\"\"
            ...
    """

    def decorator(func):
        # Auto-generate operation name if not specified
        op = operation or f"custom.auto.{func.__name__}"

        # Validate operation name to prevent header injection attacks.
        if not _OPERATION_PATTERN.match(op):
            raise ValueError(
                f"Invalid operation name: {op!r}. "
                f"Must match [a-zA-Z0-9._-]+ (no spaces, newlines, or special characters)."
            )

        ic_level = _infer_ic_level(op)

        # Store GVM metadata on the function for introspection
        func._gvm_operation = op
        func._gvm_resource = resource
        func._gvm_rate_limit = rate_limit
        func._gvm_context = context_kwargs
        func._gvm_ic_level = ic_level

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Detect GVMAgent instance (method call on agent subclass)
            agent = None
            if args and _is_gvm_agent(args[0]):
                agent = args[0]

            event_id = str(uuid.uuid4())
            parent_event_id = get_current_event_id()

            # Build GVM headers — source identity from agent or module config
            if agent:
                agent_id = agent._agent_id
                tenant_id = getattr(agent, "_tenant_id", None)
                session_id = getattr(agent, "_session_id", None)
            else:
                agent_id = get_agent_id()
                tenant_id = get_tenant_id()
                session_id = None

            headers = {
                "X-GVM-Agent-Id": agent_id,
                "X-GVM-Trace-Id": get_trace_id(),
                "X-GVM-Parent-Event-Id": parent_event_id or "",
                "X-GVM-Event-Id": event_id,
                "X-GVM-Operation": op,
                "X-GVM-Resource": json.dumps(resource.to_dict()) if resource else "{}",
                "X-GVM-Context": json.dumps(context_kwargs),
                "X-GVM-Rate-Limit": str(rate_limit) if rate_limit else "",
            }

            if tenant_id:
                headers["X-GVM-Tenant-Id"] = tenant_id
            if session_id:
                headers["X-GVM-Session-Id"] = session_id

            # Store headers for gvm_session() / create_session() consumption
            set_pending_headers(headers)

            # Set current event for child operations
            prev_event_id = get_current_event_id()
            _set_current_event_id(event_id)

            # Checkpoint logic (GVMAgent only)
            should_checkpoint = checkpoint
            checkpoint_step = None

            if agent:
                if should_checkpoint is None:
                    should_auto = getattr(agent, "_should_auto_checkpoint", None)
                    should_checkpoint = should_auto(ic_level) if should_auto else False
                if should_checkpoint:
                    mgr = getattr(agent, "_checkpoint_mgr", None)
                    get_state = getattr(agent, "_get_checkpointable_state", None)
                    if mgr and get_state:
                        checkpoint_step = mgr.save(get_state())
            else:
                should_checkpoint = False

            try:
                result = func(*args, **kwargs)

                # Warn if headers were not consumed by a GVM-aware session.
                # This means the developer used requests.post() directly,
                # bypassing Layer 2 (ABAC) policy enforcement.
                if has_pending_headers():
                    warnings.warn(
                        f"[GVM] @ic('{op}'): GVM headers were not consumed. "
                        f"HTTP requests inside @ic-decorated functions should use "
                        f"gvm_session() or self.create_session() to ensure "
                        f"Layer 2 (ABAC) policy enforcement. "
                        f"Direct requests.get/post() calls bypass semantic governance.",
                        stacklevel=2,
                    )
                    get_and_clear_pending_headers()

                return result

            except Exception as e:
                # Rollback on denial (GVMAgent only)
                if (
                    agent
                    and should_checkpoint
                    and checkpoint_step is not None
                    and isinstance(e, (GVMDeniedError, GVMApprovalRequiredError))
                ):
                    mgr = getattr(agent, "_checkpoint_mgr", None)
                    restore_fn = getattr(agent, "_restore_from_state", None)
                    if mgr and restore_fn:
                        restore_step = mgr.last_approved_step
                        if restore_step >= 0:
                            try:
                                restore_fn(mgr.restore(restore_step))
                            except Exception:
                                pass  # Rollback best-effort

                        history = getattr(agent, "_conversation_history", None)
                        if history is not None:
                            history.append({
                                "role": "system",
                                "content": (
                                    f"[GVM GOVERNANCE] Action '{op}' was blocked. "
                                    f"Reason: {e}. "
                                    f"Your state has been restored to before this action. "
                                    f"Please choose an alternative approach."
                                ),
                            })

                        raise GVMRollbackError(
                            operation=op,
                            reason=str(e),
                            rolled_back_to=restore_step if restore_step >= 0 else None,
                            blocked_at=checkpoint_step,
                        ) from e

                raise

            finally:
                # Restore parent event context
                _set_current_event_id(prev_event_id)
                # Clean up any unconsumed headers silently on exception path
                if has_pending_headers():
                    get_and_clear_pending_headers()

        return wrapper

    return decorator
