"""Agent state management with VaultField for encrypted persistence (PART 7)."""

from typing import Any


class VaultField:
    """Declares a field that should be stored encrypted in the GVM Vault.

    Attributes:
        default: Default value when no stored value exists.
        sensitivity: Data sensitivity level ("low", "medium", "high", "critical").
                     Determines audit and policy behavior.
    """

    VALID_SENSITIVITIES = {"low", "medium", "high", "critical"}

    def __init__(self, default: Any = None, sensitivity: str = "medium"):
        if sensitivity not in self.VALID_SENSITIVITIES:
            raise ValueError(
                f"Invalid sensitivity '{sensitivity}'. Must be one of {self.VALID_SENSITIVITIES}"
            )
        self.default = default
        self.sensitivity = sensitivity
        self.field_name = None  # Set by AgentState.__init_subclass__

    def __set_name__(self, owner, name):
        self.field_name = name


class AgentState:
    """Declarative agent state container with VaultField support.

    VaultField values are stored encrypted in the proxy's Vault.
    Regular attributes are stored in-memory only.

    Usage:
        class MyAgent(GVMAgent):
            state = AgentState(
                balance=VaultField(default=0, sensitivity="critical"),
                last_action=VaultField(default=""),
                temp_data="not persisted"
            )
    """

    def __init__(self, **fields):
        self._vault_fields = {}
        self._local_fields = {}

        for name, value in fields.items():
            if isinstance(value, VaultField):
                value.field_name = name
                self._vault_fields[name] = value
            else:
                self._local_fields[name] = value

        # Runtime values (populated when bound to an agent)
        self._values = {}
        self._agent = None

    def _bind(self, agent):
        """Bind state to a GVMAgent instance for Vault I/O."""
        self._agent = agent
        # Initialize with defaults
        for name, field in self._vault_fields.items():
            self._values[name] = field.default
        for name, value in self._local_fields.items():
            self._values[name] = value

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._values:
            return self._values[name]
        raise AttributeError(f"AgentState has no field '{name}'")

    def __setattr__(self, name, value):
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        if name in self._vault_fields or name in self._local_fields:
            self._values[name] = value
            return
        super().__setattr__(name, value)

    def get_vault_fields(self) -> dict:
        """Return all VaultField definitions."""
        return dict(self._vault_fields)

    def get_sensitivity_counts(self) -> dict:
        """Return count of vault fields by sensitivity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for field in self._vault_fields.values():
            counts[field.sensitivity] = counts.get(field.sensitivity, 0) + 1
        return counts
