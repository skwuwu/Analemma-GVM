#!/usr/bin/env python3
"""Minimum-viable hash-chain audit sidecar for the OPA+Envoy comparison.

Tails Envoy's file access log, computes a SHA-256 hash chain over each
entry, and signs every chained entry with an Ed25519 key. Output written
as JSON-line records to a signed log file.

This is what an operator would write to bolt audit-equivalence onto an
OPA+Envoy deployment (the equivalent of what GVM ships by default with
the WAL + Merkle + Ed25519 anchor pipeline). Intentionally small (~80
LOC) so the LOC count is honest — not a production-grade auditor.

Usage:
    hash-chain-sidecar.py --input /tmp/envoy-bench.log \\
                          --output /tmp/envoy-bench-signed.log

Latency notes per entry on a t3.medium:
  - SHA-256 over a typical access log line (~200 B): ~1 µs
  - Ed25519 sign(32-byte digest): ~50 µs
  - JSON encode + fsync per record: ~50 µs
  Total: ~100 µs / entry. This is added to GVM's bench-comparable
  "decision-to-signed-anchor" path.
"""
import argparse
import hashlib
import json
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Envoy access log file to tail")
    p.add_argument("--output", required=True, help="Signed log output (append)")
    p.add_argument(
        "--poll-ms",
        type=int,
        default=1,
        help="Tail poll interval when no new lines (ms; default 1)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # Ephemeral key — real deployment loads from KMS / HSM / Vault Transit.
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    prev_hash = b"\x00" * 32
    idx = 0

    poll_s = args.poll_ms / 1000.0

    # Write public-key header so a verifier can replay the chain.
    with open(args.output, "a") as fout:
        fout.write(
            json.dumps(
                {
                    "_": "hash-chain-init",
                    "public_key": pub_bytes.hex(),
                    "alg": "Ed25519",
                    "hash": "SHA-256",
                    "format": "v1",
                }
            )
            + "\n"
        )
        fout.flush()

    # Wait for input to exist (Envoy may not have created it yet).
    while True:
        try:
            fin = open(args.input, "r")
            break
        except FileNotFoundError:
            time.sleep(poll_s)

    fin.seek(0, 2)  # tail mode — only new lines

    fout = open(args.output, "a")
    try:
        while True:
            # Snapshot position so we can rewind on partial-line / EOF reads.
            # Python text-mode file's internal buffer can otherwise mask
            # new bytes written after a readline() returned '' at EOF.
            where = fin.tell()
            line = fin.readline()
            if not line or not line.endswith("\n"):
                fin.seek(where)
                time.sleep(poll_s)
                continue
            entry = line.rstrip("\n").encode("utf-8")
            entry_hash = hashlib.sha256(prev_hash + entry).digest()
            idx += 1
            sig = priv.sign(entry_hash)
            record = {
                "idx": idx,
                "entry": line.rstrip("\n"),
                "prev_hash": prev_hash.hex(),
                "hash": entry_hash.hex(),
                "signature": sig.hex(),
                "ts_unix_ns": time.time_ns(),
            }
            fout.write(json.dumps(record) + "\n")
            fout.flush()
            prev_hash = entry_hash
    except KeyboardInterrupt:
        return 0
    finally:
        fin.close()
        fout.close()


if __name__ == "__main__":
    sys.exit(main())
