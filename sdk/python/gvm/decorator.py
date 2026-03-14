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


def ic(
    operation: str = None,
    rate_limit: int = None,
    resource: Resource = None,
    **context_kwargs,
):
    """Declare a method as a GVM-controlled operation.

    Args:
        operation: Operation name (e.g. "gvm.messaging.send").
                   If omitted, auto-generated as "custom.auto.{func_name}".
        rate_limit: Max invocations per minute (optional).
        resource: Target resource descriptor (optional).
        **context_kwargs: Additional ABAC context attributes (e.g. amount=None).

    Usage:
        @ic(operation="gvm.messaging.send",
            resource=Resource(service="slack", tier="customer-facing"),
            rate_limit=100)
        def send_alert(self, channel, message):
            ...

        # Minimal version (operation auto-inferred)
        @ic()
        def send_email(self):
            ...
    """

    def decorator(func):
        # Auto-generate operation name if not specified
        op = operation or f"custom.auto.{func.__name__}"

        # Store GVM metadata on the function for introspection
        func._gvm_operation = op
        func._gvm_resource = resource
        func._gvm_rate_limit = rate_limit
        func._gvm_context = context_kwargs

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

            try:
                return func(self, *args, **kwargs)
            finally:
                # Restore parent event context
                _set_current_event_id(prev_event_id)

        return wrapper

    return decorator
