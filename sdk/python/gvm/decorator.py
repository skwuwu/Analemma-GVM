"""@ic decorator — semantic operation declaration for GVM proxy (PART 7.1)."""

import functools
import json
import uuid
import threading
from typing import Optional

from gvm.resource import Resource

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


# Global GVM header setter — patched by GVMAgent to inject into HTTP requests
_gvm_header_setter = None


def _set_gvm_headers(headers: dict):
    """Inject GVM headers into the outgoing HTTP request context.

    This is called by the @ic wrapper before the decorated function executes.
    The GVMAgent patches this to configure the proxy-aware HTTP session.
    """
    if _gvm_header_setter is not None:
        _gvm_header_setter(headers)


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


def ic(
    operation: str = None,
    rate_limit: int = None,
    resource: Resource = None,
    checkpoint: bool = None,
    **context_kwargs,
):
    """Declare a method as a GVM-controlled operation.

    Args:
        operation: Operation name (e.g. "gvm.messaging.send").
                   If omitted, auto-generated as "custom.auto.{func_name}".
        rate_limit: Max invocations per minute (optional).
        resource: Target resource descriptor (optional).
        checkpoint: If True, save a checkpoint before this operation.
                    If None, defer to agent's auto_checkpoint setting.
        **context_kwargs: Additional ABAC context attributes (e.g. amount=None).

    Usage:
        @ic(operation="gvm.messaging.send",
            resource=Resource(service="slack", tier="customer-facing"),
            rate_limit=100)
        def send_alert(self, channel, message):
            ...

        # With explicit checkpoint (rollback if denied)
        @ic(operation="gvm.payment.charge", checkpoint=True)
        def charge_card(self, amount):
            ...

        # Minimal version (operation auto-inferred)
        @ic()
        def send_email(self):
            ...
    """

    def decorator(func):
        # Auto-generate operation name if not specified
        op = operation or f"custom.auto.{func.__name__}"
        ic_level = _infer_ic_level(op)

        # Store GVM metadata on the function for introspection
        func._gvm_operation = op
        func._gvm_resource = resource
        func._gvm_rate_limit = rate_limit
        func._gvm_context = context_kwargs
        func._gvm_ic_level = ic_level

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            event_id = str(uuid.uuid4())
            parent_event_id = get_current_event_id()

            headers = {
                "X-GVM-Agent-Id": getattr(self, "_agent_id", "unknown"),
                "X-GVM-Trace-Id": get_trace_id(),
                "X-GVM-Parent-Event-Id": parent_event_id or "",
                "X-GVM-Event-Id": event_id,
                "X-GVM-Operation": op,
                "X-GVM-Resource": json.dumps(resource.to_dict()) if resource else "{}",
                "X-GVM-Context": json.dumps(context_kwargs),
                "X-GVM-Rate-Limit": str(rate_limit) if rate_limit else "",
            }

            # Add tenant/session if available on the agent
            tenant_id = getattr(self, "_tenant_id", None)
            if tenant_id:
                headers["X-GVM-Tenant-Id"] = tenant_id
            session_id = getattr(self, "_session_id", None)
            if session_id:
                headers["X-GVM-Session-Id"] = session_id

            # Inject headers into the HTTP context
            _set_gvm_headers(headers)

            # Set current event for child operations
            prev_event_id = get_current_event_id()
            _set_current_event_id(event_id)

            # Determine if checkpoint is needed
            should_checkpoint = checkpoint
            if should_checkpoint is None:
                checkpoint_mgr = getattr(self, "_checkpoint_mgr", None)
                if checkpoint_mgr is not None:
                    should_checkpoint = getattr(
                        self, "_should_auto_checkpoint", lambda _: False
                    )(ic_level)
                else:
                    should_checkpoint = False

            # Save checkpoint before execution
            checkpoint_step = None
            if should_checkpoint:
                checkpoint_mgr = getattr(self, "_checkpoint_mgr", None)
                get_state = getattr(self, "_get_checkpointable_state", None)
                if checkpoint_mgr and get_state:
                    state_snapshot = get_state()
                    checkpoint_step = checkpoint_mgr.save(state_snapshot)

            try:
                result = func(self, *args, **kwargs)
                return result

            except Exception as e:
                # Check if this is a GVM denial that should trigger rollback
                from gvm.errors import GVMDeniedError, GVMApprovalRequiredError

                if should_checkpoint and checkpoint_step is not None and isinstance(
                    e, (GVMDeniedError, GVMApprovalRequiredError)
                ):
                    checkpoint_mgr = getattr(self, "_checkpoint_mgr", None)
                    restore_fn = getattr(self, "_restore_from_state", None)
                    if checkpoint_mgr and restore_fn:
                        # Find the last approved step to roll back to
                        restore_step = checkpoint_mgr.last_approved_step
                        if restore_step >= 0:
                            try:
                                restored = checkpoint_mgr.restore(restore_step)
                                restore_fn(restored)
                            except Exception:
                                pass  # Rollback best-effort

                        from gvm.errors import GVMRollbackError
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

        return wrapper

    return decorator
