"""Checkpoint manager for agent state rollback (Merkle-verified).

Saves/restores agent state snapshots via the GVM Vault checkpoint API.
Checkpoints are encrypted at rest (AES-256-GCM) and Merkle-verified on restore.

Architecture:
    Agent (SDK)  -->  PUT /gvm/vault/checkpoint/:agent_id/:step  -->  Vault (encrypted)
    Agent (SDK)  <--  GET /gvm/vault/checkpoint/:agent_id/:step  <--  Vault (Merkle-verified)

The proxy is stateless — it stores/retrieves, the SDK decides when to checkpoint
and when to roll back.
"""

import json
import logging

import requests

logger = logging.getLogger("gvm.checkpoint")


class CheckpointManager:
    """Manages agent state checkpoints via GVM Vault API.

    Each checkpoint is a JSON-serialized snapshot of the agent's state
    (conversation history, vault fields, step counter). Checkpoints are
    stored encrypted in the Vault and verified via Merkle hash on restore.

    Usage:
        mgr = CheckpointManager("agent-001", "http://localhost:8080")
        step = mgr.save({"balance": 10000, "history": [...]})
        state = mgr.restore(step)
    """

    def __init__(self, agent_id: str, proxy_url: str):
        self._agent_id = agent_id
        self._proxy_url = proxy_url.rstrip("/")
        self._current_step = 0
        self._last_approved_step = -1
        self._checkpoint_sizes = {}  # step -> bytes for token savings calc

    def save(self, state: dict) -> int:
        """Save current state as a checkpoint. Returns the step number.

        The state dict is JSON-serialized and stored encrypted in the Vault.
        On failure, logs a warning but does not raise — checkpointing is
        best-effort and should not block agent execution.
        """
        step = self._current_step
        serialized = json.dumps(state, default=str).encode("utf-8")

        try:
            resp = requests.put(
                f"{self._proxy_url}/gvm/vault/checkpoint/"
                f"{self._agent_id}/{step}",
                data=serialized,
                headers={"Content-Type": "application/octet-stream"},
                timeout=5,
            )
            resp.raise_for_status()
        except Exception as e:
            logger.warning("Checkpoint save failed (step %d): %s", step, e)
            # Best-effort: still increment step to avoid collision
            self._current_step += 1
            return step

        self._last_approved_step = step
        self._checkpoint_sizes[step] = len(serialized)
        self._current_step += 1

        logger.debug(
            "Checkpoint saved: agent=%s step=%d size=%d bytes",
            self._agent_id, step, len(serialized),
        )
        return step

    def restore(self, step: int) -> dict:
        """Restore state from a checkpoint. Verifies Merkle integrity.

        Raises:
            ValueError: if checkpoint not found or integrity check fails.
        """
        resp = requests.get(
            f"{self._proxy_url}/gvm/vault/checkpoint/"
            f"{self._agent_id}/{step}",
            timeout=5,
        )

        if resp.status_code == 404:
            raise ValueError(f"Checkpoint not found: step {step}")
        resp.raise_for_status()

        # Verify Merkle integrity header
        merkle_ok = resp.headers.get("X-GVM-Merkle-Verified", "false")
        if merkle_ok != "true":
            raise ValueError(
                f"Checkpoint integrity check failed at step {step}"
            )

        # Reset step counter to resume from this checkpoint
        self._current_step = step + 1

        logger.debug(
            "Checkpoint restored: agent=%s step=%d merkle=%s",
            self._agent_id, step, merkle_ok,
        )
        return json.loads(resp.content)

    @property
    def current_step(self) -> int:
        """Current step counter (next checkpoint will use this number)."""
        return self._current_step

    @property
    def last_approved_step(self) -> int:
        """Last successfully saved checkpoint step. -1 if none."""
        return self._last_approved_step

    def get_checkpoint_size(self, step: int) -> int:
        """Return the serialized size (bytes) of a checkpoint."""
        return self._checkpoint_sizes.get(step, 0)
