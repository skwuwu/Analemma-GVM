"""Resource descriptor for GVM operations."""


class Resource:
    """Describes the target resource of an operation.

    Attributes:
        service: Resource service name (e.g. "slack", "gmail", "postgres").
        identifier: Resource identifier (e.g. "#customer-support", "user@example.com").
        tier: Resource tier — "internal", "external", or "customer-facing".
        sensitivity: Data sensitivity — "low", "medium", "high", or "critical".
    """

    VALID_TIERS = {"internal", "external", "customer-facing"}
    VALID_SENSITIVITIES = {"low", "medium", "high", "critical"}

    def __init__(
        self,
        service: str,
        identifier: str = None,
        tier: str = "external",
        sensitivity: str = "medium",
    ):
        if tier not in self.VALID_TIERS:
            raise ValueError(f"Invalid tier '{tier}'. Must be one of {self.VALID_TIERS}")
        if sensitivity not in self.VALID_SENSITIVITIES:
            raise ValueError(
                f"Invalid sensitivity '{sensitivity}'. Must be one of {self.VALID_SENSITIVITIES}"
            )

        self.service = service
        self.identifier = identifier
        self.tier = tier
        self.sensitivity = sensitivity

    # Maps SDK-facing names (lowercase) to Rust serde enum variants (PascalCase)
    _TIER_TO_RUST = {
        "internal": "Internal",
        "external": "External",
        "customer-facing": "CustomerFacing",
    }
    _SENSITIVITY_TO_RUST = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "identifier": self.identifier,
            "tier": self._TIER_TO_RUST.get(self.tier, self.tier),
            "sensitivity": self._SENSITIVITY_TO_RUST.get(self.sensitivity, self.sensitivity),
        }
