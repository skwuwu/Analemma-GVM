"""Generate an asciicast v2 (.cast) recording of the unified demo.

Works on Windows (no pty/fcntl required). Captures real demo output with
realistic typing delays for an authentic terminal recording.

Usage:
    python scripts/record_demo.py          # -> demo.cast
    python scripts/record_demo.py out.cast # -> out.cast
"""

import io
import json
import subprocess
import sys
import time
import os


def make_cast(output_path: str):
    """Run the unified demo and capture output into asciicast v2 format."""

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Run the demo and capture raw output
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["TERM"] = "xterm-256color"
    # Force color output even when not a tty
    env["FORCE_COLOR"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-m", "gvm.unified_demo"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=project_root,
        env=env,
    )
    raw_output, _ = proc.communicate(timeout=60)

    # Decode output
    try:
        output = raw_output.decode("utf-8")
    except UnicodeDecodeError:
        output = raw_output.decode("cp949", errors="replace")

    lines = output.split("\n")

    # Build asciicast v2 events with realistic timing
    width = 80
    height = 55
    timestamp = int(time.time())

    header = {
        "version": 2,
        "width": width,
        "height": height,
        "timestamp": timestamp,
        "title": "Analemma-GVM: Unified Finance Agent Demo",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    }

    events = []
    t = 0.0

    # Simulate typing the command first
    command = "python -m gvm.unified_demo"
    prompt = "$ "

    # Show prompt
    events.append([t, "o", f"\x1b[1;32m{prompt}\x1b[0m"])
    t += 0.3

    # Type command character by character
    for ch in command:
        events.append([t, "o", ch])
        t += 0.04 + (0.02 if ch == " " else 0)
    t += 0.2
    events.append([t, "o", "\r\n"])
    t += 0.5

    # Emit captured output line by line with realistic delays
    for i, line in enumerate(lines):
        # Determine delay based on content
        if line.strip() == "":
            delay = 0.08
        elif "=====" in line or "-----" in line:
            delay = 0.05
        elif "[Step" in line:
            delay = 0.6  # Pause before each step
        elif "Allow" in line or "Delay" in line or "BLOCKED" in line:
            delay = 0.15
        elif "Checkpoint" in line or "Rollback" in line:
            delay = 0.2
        elif "Why blocked" in line or "Semantic forgery" in line:
            delay = 0.3
        elif "Features Demonstrated" in line:
            delay = 0.5
        elif line.strip().startswith("Layer") or "max_strict" in line:
            delay = 0.15
        elif "Token Savings" in line:
            delay = 0.4
        elif "Saved:" in line:
            delay = 0.3
        elif "Starting mock" in line or "Checking GVM" in line:
            delay = 0.8  # Simulate startup wait
        else:
            delay = 0.06

        t += delay
        # Escape the line for JSON and add newline
        events.append([t, "o", line + "\r\n"])

    # Final pause
    t += 1.0
    events.append([t, "o", f"\x1b[1;32m$ \x1b[0m"])

    # Write asciicast v2 file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for event in events:
            f.write(json.dumps(event) + "\n")

    total_duration = t
    print(f"Recording saved: {output_path}")
    print(f"Duration: {total_duration:.1f}s, {len(events)} events, {len(lines)} lines")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.cast"
    make_cast(out)
