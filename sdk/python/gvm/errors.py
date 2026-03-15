"""GVM error hierarchy for enforcement decisions."""


class GVMError(Exception):
    """Base exception for all GVM enforcement errors."""

    def __init__(
        self,
        message: str,
        status_code: int = None,
        event_id: str = None,
        next_action: str = None,
        retry_after: int = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.event_id = event_id
        self.next_action = next_action
        self.retry_after = retry_after

    @classmethod
    def from_response(cls, resp_json: dict, status_code: int = None):
        """Create the appropriate GVMError subclass from a proxy error response."""
        decision = resp_json.get("decision", "")
        error_msg = resp_json.get("error", "Unknown error")
        event_id = resp_json.get("event_id")
        next_action = resp_json.get("next_action")
        retry_after = resp_json.get("retry_after")

        if decision == "RequireApproval":
            err = GVMApprovalRequiredError(
                urgency=error_msg, status_code=status_code, event_id=event_id
            )
        elif decision == "Deny":
            err = GVMDeniedError(
                reason=error_msg, status_code=status_code, event_id=event_id
            )
        elif decision == "Throttle" or status_code == 429:
            err = GVMRateLimitError(
                status_code=status_code, event_id=event_id
            )
        else:
            err = cls(
                message=error_msg, status_code=status_code, event_id=event_id
            )

        err.next_action = next_action
        err.retry_after = retry_after
        return err


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


class GVMRollbackError(GVMError):
    """Raised when an operation was blocked and state was rolled back.

    The agent can catch this error to choose an alternative action path.
    For LLM agents, include this error message in the conversation history
    so the LLM selects a different approach.

    Attributes:
        operation: The blocked operation name.
        reason: Why the operation was blocked.
        rolled_back_to: Checkpoint step the state was restored to (None if no prior checkpoint).
        blocked_at: Checkpoint step saved before the blocked operation.
    """

    def __init__(
        self,
        operation: str,
        reason: str,
        rolled_back_to: int = None,
        blocked_at: int = None,
    ):
        self.operation = operation
        self.reason = reason
        self.rolled_back_to = rolled_back_to
        self.blocked_at = blocked_at

        if rolled_back_to is not None:
            msg = (
                f"Action '{operation}' blocked: {reason}. "
                f"State rolled back to checkpoint #{rolled_back_to}. "
                f"Agent can continue from alternative path."
            )
        else:
            msg = (
                f"Action '{operation}' blocked: {reason}. "
                f"No prior checkpoint available for rollback."
            )

        super().__init__(msg, status_code=403)
