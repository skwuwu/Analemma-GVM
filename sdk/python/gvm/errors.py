"""GVM error hierarchy for enforcement decisions."""


class GVMError(Exception):
    """Base exception for all GVM enforcement errors."""

    def __init__(self, message: str, status_code: int = None, event_id: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.event_id = event_id


class GVMDeniedError(GVMError):
    """Raised when an operation is denied by policy (Deny decision)."""

    def __init__(self, reason: str, status_code: int = 403, event_id: str = None):
        super().__init__(f"Operation denied: {reason}", status_code, event_id)
        self.reason = reason


class GVMApprovalRequiredError(GVMError):
    """Raised when an operation requires human approval (IC-3 RequireApproval)."""

    def __init__(self, urgency: str = "standard", status_code: int = 403, event_id: str = None):
        super().__init__(
            f"Operation requires approval (urgency: {urgency})", status_code, event_id
        )
        self.urgency = urgency


class GVMRateLimitError(GVMError):
    """Raised when an agent exceeds its rate limit (Throttle decision)."""

    def __init__(self, status_code: int = 429, event_id: str = None):
        super().__init__("Rate limit exceeded", status_code, event_id)
