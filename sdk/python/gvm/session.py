"""Standalone GVM session — proxy-aware HTTP without GVMAgent inheritance.

Enables GVM governance on any Python code without class inheritance:

    from gvm import ic, gvm_session, configure

    configure(agent_id="my-agent")

    @ic(operation="gvm.messaging.send")
    def send_email(to, subject, body):
        session = gvm_session()
        return session.post("http://gmail.googleapis.com/...", json={...}).json()

For advanced features (checkpoint, state, rollback), use GVMAgent instead.
"""

import os
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# Module-level configuration (set once via configure())
# ---------------------------------------------------------------------------

_config_lock = threading.Lock()
_config = {
    "agent_id": None,
    "tenant_id": None,
    "proxy_url": None,
}


def configure(
    agent_id: str = None,
    tenant_id: str = None,
    proxy_url: str = None,
):
    """Set module-level GVM defaults for standalone (non-GVMAgent) usage.

    Call once at startup:
        gvm.configure(agent_id="my-agent", proxy_url="http://localhost:8080")

    Or use environment variables instead:
        GVM_AGENT_ID, GVM_TENANT_ID, GVM_PROXY_URL
    """
    with _config_lock:
        if agent_id is not None:
            _config["agent_id"] = agent_id
        if tenant_id is not None:
            _config["tenant_id"] = tenant_id
        if proxy_url is not None:
            _config["proxy_url"] = proxy_url


def get_agent_id() -> str:
    """Return configured agent ID (config > env > default)."""
    return _config["agent_id"] or os.environ.get("GVM_AGENT_ID", "default-agent")


def get_tenant_id() -> Optional[str]:
    """Return configured tenant ID (config > env > None)."""
    return _config["tenant_id"] or os.environ.get("GVM_TENANT_ID")


def get_proxy_url() -> str:
    """Return configured proxy URL (config > env > localhost:8080)."""
    return _config["proxy_url"] or os.environ.get(
        "GVM_PROXY_URL", "http://127.0.0.1:8080"
    )


# ---------------------------------------------------------------------------
# Thread-local pending headers (set by @ic, consumed by gvm_session requests)
# ---------------------------------------------------------------------------

_header_store = threading.local()


def set_pending_headers(headers: dict):
    """Store GVM headers to be injected into the next HTTP request.

    Called by the @ic decorator before the decorated function executes.
    """
    _header_store.pending = headers


def get_and_clear_pending_headers() -> dict:
    """Retrieve and clear pending headers.

    Called by gvm_session's prepare_request hook on each outgoing request.
    """
    headers = getattr(_header_store, "pending", {})
    _header_store.pending = {}
    return headers


def has_pending_headers() -> bool:
    """Check if headers are still pending (not yet consumed by a GVM session)."""
    return bool(getattr(_header_store, "pending", {}))


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------


def gvm_session(proxy_url: str = None):
    """Create a requests.Session routed through the GVM proxy.

    Headers set by @ic are automatically injected into each outgoing request.
    Works with or without GVMAgent:

        from gvm import ic, gvm_session

        @ic(operation="gvm.messaging.send")
        def send_email(to, subject, body):
            session = gvm_session()
            return session.post("http://api.example.com/send", json={...}).json()

    Args:
        proxy_url: Override proxy URL (default: module config or GVM_PROXY_URL).

    Requires: pip install requests
    """
    try:
        import requests
    except ImportError:
        raise ImportError(
            "requests library required for gvm_session(). "
            "Install: pip install requests"
        )

    from gvm.errors import GVMError

    proxy = proxy_url or get_proxy_url()
    session = requests.Session()
    session.proxies = {"http": proxy, "https": proxy}

    original_prepare = session.prepare_request

    def prepare_with_gvm(request):
        prepared = original_prepare(request)
        headers = get_and_clear_pending_headers()
        for key, value in headers.items():
            if value:
                prepared.headers[key] = value
        return prepared

    session.prepare_request = prepare_with_gvm

    def _enforce_response(resp, *args, **kwargs):
        """Raise a GVMError subclass on governance block responses (403, 429)."""
        if resp.status_code in (403, 429):
            # Only raise for GVM governance blocks (check header or JSON body)
            decision_header = resp.headers.get("X-GVM-Decision", "")
            if decision_header or resp.headers.get("Content-Type", "").startswith("application/json"):
                try:
                    body = resp.json()
                    if body.get("blocked") or decision_header:
                        raise GVMError.from_response(body, status_code=resp.status_code)
                except (ValueError, KeyError):
                    pass

    session.hooks["response"].append(_enforce_response)
    return session
