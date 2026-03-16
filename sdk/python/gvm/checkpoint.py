"""Checkpoint manager for agent state rollback (Merkle tree verified).

Saves/restores agent state snapshots via the GVM Vault checkpoint API.
Checkpoints are encrypted at rest (AES-256-GCM) and Merkle-tree verified
on restore. Each checkpoint's content hash is a leaf in a per-agent Merkle
tree — the same tree structure used for WAL audit batch verification.

Architecture:
    Agent (SDK)  -->  PUT /gvm/vault/checkpoint/:agent_id/:step  -->  Vault (encrypted)
                      Proxy computes: content_hash = SHA-256(plaintext)  (leaf)
                                      merkle_root = MerkleTree(all leaves)
    Agent (SDK)  <--  GET /gvm/vault/checkpoint/:agent_id/:step  <--  Vault (Merkle-verified)
                      Proxy verifies: SHA-256(decrypted) == stored leaf hash
                                      O(log N) Merkle proof against root

The proxy manages the Merkle tree — the SDK decides when to checkpoint
and when to roll back.
"""

import hashlib
import json
import logging

import requests

logger = logging.getLogger("gvm.checkpoint")


class CheckpointManager:
    """Manages agent state checkpoints via GVM Vault API.

    Each checkpoint is a JSON-serialized snapshot of the agent's state
    (conversation history, vault fields, step counter). Checkpoints are
    stored encrypted in the Vault and Merkle-tree verified on restore.

    The proxy maintains a per-agent Merkle tree:
        leaf[0] = SHA-256(checkpoint_0_plaintext)
        leaf[1] = SHA-256(checkpoint_1_plaintext)
        ...
        merkle_root = MerkleTree(leaf[0], leaf[1], ..., leaf[N])

    On restore, the proxy generates an O(log N) Merkle proof for the
    requested leaf and verifies it against the stored root. Tampering
    with any checkpoint invalidates the root, detected on any restore.

    Usage:
        mgr = CheckpointManager("agent-001", "http://localhost:8080")
        step = mgr.save({"balance": 10000, "history": [...]})
        state = mgr.restore(step)
    """

    CHECKPOINT_VERSION = "gvm-checkpoint-v1"
    MAX_CHECKPOINT_SIZE = 5 * 1024 * 1024  # 5MB upper bound
    MAX_CHECKPOINTS = 10  # Retain only the most recent N checkpoints

    def __init__(self, agent_id: str, proxy_url: str):
        self._agent_id = agent_id
        self._proxy_url = proxy_url.rstrip("/")
        self._current_step = 0
        self._last_approved_step = -1
        self._checkpoint_sizes = {}  # step -> bytes for token savings calc
        self._checkpoint_hashes = {}  # step -> (content_hash, merkle_root) for client-side audit

    def save(self, state: dict) -> int:
        """Save current state as a checkpoint. Returns the step number.

        The state dict is JSON-serialized and stored encrypted in the Vault.
        The proxy computes a content hash (Merkle leaf) and adds it to the
        agent's Merkle tree for integrity verification.

        On failure, logs a warning but does not raise — checkpointing is
        best-effort and should not block agent execution.
        """
        step = self._current_step
        serialized = json.dumps(state, default=str).encode("utf-8")

        # Size validation — reject before sending to proxy
        if len(serialized) > self.MAX_CHECKPOINT_SIZE:
            logger.warning(
                "Checkpoint too large at step %d: %d bytes (max %d). Skipping.",
                step, len(serialized), self.MAX_CHECKPOINT_SIZE,
            )
            self._current_step += 1
            return step

        # Compute client-side content hash for local verification
        client_hash = hashlib.sha256(serialized).hexdigest()

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

        # Parse server response for Merkle tree verification
        try:
            resp_data = resp.json()
            server_content_hash = resp_data.get("content_hash")
            server_merkle_root = resp_data.get("merkle_root")

            # Verify server computed the same content hash (leaf)
            if server_content_hash and server_content_hash != client_hash:
                logger.error(
                    "Content hash mismatch at step %d: "
                    "client=%s server=%s — possible data corruption in transit",
                    step, client_hash, server_content_hash,
                )

            self._checkpoint_hashes[step] = (
                server_content_hash or client_hash,
                server_merkle_root,
            )
        except Exception:
            # Server response parsing is best-effort
            self._checkpoint_hashes[step] = (client_hash, None)

        self._last_approved_step = step
        self._checkpoint_sizes[step] = len(serialized)
        self._current_step += 1

        logger.debug(
            "Checkpoint saved: agent=%s step=%d size=%d bytes hash=%s",
            self._agent_id, step, len(serialized), client_hash[:16],
        )

        # TTL cleanup: delete old checkpoints to prevent Vault bloat
        if step >= self.MAX_CHECKPOINTS:
            old_step = step - self.MAX_CHECKPOINTS
            try:
                requests.delete(
                    f"{self._proxy_url}/gvm/vault/checkpoint/"
                    f"{self._agent_id}/{old_step}",
                    timeout=3,
                )
                self._checkpoint_sizes.pop(old_step, None)
                self._checkpoint_hashes.pop(old_step, None)
            except Exception:
                pass  # Cleanup failure is non-critical

        return step

    def restore(self, step: int) -> dict:
        """Restore state from a checkpoint. Verifies Merkle tree integrity.

        The proxy decrypts the checkpoint, recomputes the content hash,
        generates an O(log N) Merkle proof for the leaf, and verifies
        it against the tree root. If verification fails, the checkpoint
        may have been tampered with.

        Raises:
            ValueError: if checkpoint not found or Merkle verification fails.
        """
        resp = requests.get(
            f"{self._proxy_url}/gvm/vault/checkpoint/"
            f"{self._agent_id}/{step}",
            timeout=5,
        )

        if resp.status_code == 404:
            raise ValueError(f"Checkpoint not found: step {step}")
        resp.raise_for_status()

        # Verify Merkle tree integrity (proxy-side verification)
        merkle_ok = resp.headers.get("X-GVM-Merkle-Verified", "false")
        merkle_root = resp.headers.get("X-GVM-Merkle-Root")

        if merkle_ok != "true":
            logger.error(
                "Checkpoint Merkle verification FAILED at step %d "
                "(agent=%s) — possible state tampering detected",
                step, self._agent_id,
            )
            raise ValueError(
                f"Checkpoint integrity check failed at step {step}. "
                f"The checkpoint data may have been tampered with. "
                f"Merkle proof verification returned: {merkle_ok}"
            )

        # Client-side verification: hash the decrypted content locally
        content = resp.content
        client_hash = hashlib.sha256(content).hexdigest()

        # Cross-check with previously stored hash (if we saved this checkpoint)
        saved = self._checkpoint_hashes.get(step)
        if saved and saved[0] != client_hash:
            logger.error(
                "Client-side hash mismatch at step %d: "
                "saved=%s restored=%s — data changed between save and restore",
                step, saved[0], client_hash,
            )
            raise ValueError(
                f"Client-side integrity check failed at step {step}. "
                f"Restored data does not match original checkpoint."
            )

        # Reset step counter to resume from this checkpoint
        self._current_step = step + 1

        logger.debug(
            "Checkpoint restored: agent=%s step=%d merkle=%s root=%s",
            self._agent_id, step, merkle_ok,
            merkle_root[:16] if merkle_root else "none",
        )
        return json.loads(content)

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

    def get_checkpoint_hash(self, step: int) -> tuple:
        """Return (content_hash, merkle_root) for a checkpoint step.

        Returns (None, None) if the checkpoint was not saved in this session.
        """
        return self._checkpoint_hashes.get(step, (None, None))
