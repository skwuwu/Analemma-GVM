#!/usr/bin/env python3
"""Extract p50 / p95 / p99 / max from Criterion sample.json outputs.

Criterion reports median + 95 % CI by default. Median hides tail
behavior — a bench that's 500 ns median but occasionally 3 µs
under CPU credit exhaustion looks identical to one that's 500 ns
median flat. For any hot-path work under agent burst pressure,
tail (p99 / max) is the operative metric.

Reads every `target/criterion/<group>/<bench>/new/sample.json`
(the current run) and prints a markdown table of p50 / p95 / p99
/ max per bench. Also compares against `base/sample.json` (the
previous baseline) when present.

Sample.json format (from Criterion docs):
    {
      "iters":  [n_iterations_batched_together_per_sample_0, ...],
      "times":  [total_ns_for_that_sample_0, ...]
    }

Per-iteration ns for sample i = times[i] / iters[i]. This is what
Criterion feeds into its median estimator; we sort and pick
percentiles ourselves.

Usage:
    cargo bench --bench pipeline -- cooperative_lease
    python3 scripts/bench-tail-report.py

    # Or restrict to one group:
    python3 scripts/bench-tail-report.py cooperative_lease
"""
from __future__ import annotations

import glob
import io
import json
import os
import sys
from pathlib import Path

# The µs / — glyphs need UTF-8. Windows consoles default to CP949 (Korean)
# or CP1252 and choke on µ; reconfigure stdout instead of dumbing the output
# down to "us".
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
else:  # older Pythons
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def per_iteration_samples(sample_path: Path) -> list[float]:
    """Return the sorted per-iteration nanosecond list for one bench run."""
    with open(sample_path) as f:
        data = json.load(f)
    iters = data.get("iters", [])
    times = data.get("times", [])
    if not iters or len(iters) != len(times):
        return []
    return sorted(t / i for t, i in zip(times, iters))


def percentile(sorted_samples: list[float], p: float) -> float:
    """p in [0, 1]. Uses nearest-rank; good enough for 100-500 samples."""
    if not sorted_samples:
        return 0.0
    k = max(0, min(len(sorted_samples) - 1, int(p * len(sorted_samples))))
    return sorted_samples[k]


def format_ns(ns: float) -> str:
    """Human-readable ns / µs / ms."""
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.2f} µs"
    return f"{ns:.0f} ns"


def scan_criterion(target_dir: Path, group_filter: str | None) -> list[dict]:
    """Walk target/criterion and yield one dict per bench with new + base
    percentile summaries."""
    rows = []
    pattern = str(target_dir / "**" / "new" / "sample.json")
    for path in sorted(glob.glob(pattern, recursive=True)):
        p = Path(path)
        # p = target/criterion/<group>/<bench>/new/sample.json
        # → bench_name = <group>/<bench>
        parts = p.relative_to(target_dir).parts
        if len(parts) < 4:
            continue
        bench_name = "/".join(parts[:-2])
        if group_filter and not bench_name.startswith(group_filter):
            continue

        new_samples = per_iteration_samples(p)
        if not new_samples:
            continue

        base_path = p.parent.parent / "base" / "sample.json"
        base_samples = (
            per_iteration_samples(base_path) if base_path.exists() else []
        )

        row = {
            "name": bench_name,
            "new_p50": percentile(new_samples, 0.50),
            "new_p95": percentile(new_samples, 0.95),
            "new_p99": percentile(new_samples, 0.99),
            "new_max": new_samples[-1],
            "new_n": len(new_samples),
        }
        if base_samples:
            row.update(
                {
                    "base_p50": percentile(base_samples, 0.50),
                    "base_p95": percentile(base_samples, 0.95),
                    "base_p99": percentile(base_samples, 0.99),
                    "base_max": base_samples[-1],
                    "base_n": len(base_samples),
                }
            )
        rows.append(row)
    return rows


def print_markdown_table(rows: list[dict]) -> None:
    if not rows:
        print("no bench samples found — run `cargo bench` first")
        return

    has_base = any("base_p50" in r for r in rows)
    if has_base:
        print(
            "| bench | p50 new (base) | p95 new (base) | p99 new (base) | "
            "max new (base) | n |"
        )
        print("|---|---:|---:|---:|---:|---:|")
        for r in rows:
            base = r.get("base_p50") is not None
            b50 = f" ({format_ns(r['base_p50'])})" if base else ""
            b95 = f" ({format_ns(r['base_p95'])})" if base else ""
            b99 = f" ({format_ns(r['base_p99'])})" if base else ""
            bmx = f" ({format_ns(r['base_max'])})" if base else ""
            print(
                f"| `{r['name']}` "
                f"| {format_ns(r['new_p50'])}{b50} "
                f"| {format_ns(r['new_p95'])}{b95} "
                f"| {format_ns(r['new_p99'])}{b99} "
                f"| {format_ns(r['new_max'])}{bmx} "
                f"| {r['new_n']} |"
            )
    else:
        print("| bench | p50 | p95 | p99 | max | n |")
        print("|---|---:|---:|---:|---:|---:|")
        for r in rows:
            print(
                f"| `{r['name']}` "
                f"| {format_ns(r['new_p50'])} "
                f"| {format_ns(r['new_p95'])} "
                f"| {format_ns(r['new_p99'])} "
                f"| {format_ns(r['new_max'])} "
                f"| {r['new_n']} |"
            )

    # Regression heuristic — p99 delta > 10 % worth flagging.
    if has_base:
        print()
        print("**Regression check (p99 delta > 10 %)**:")
        found = False
        for r in rows:
            if r.get("base_p99") is None:
                continue
            delta = (r["new_p99"] - r["base_p99"]) / r["base_p99"]
            if delta > 0.10:
                print(
                    f"- `{r['name']}`: p99 "
                    f"{format_ns(r['base_p99'])} → {format_ns(r['new_p99'])} "
                    f"(+{delta * 100:.1f} %)"
                )
                found = True
        if not found:
            print("- none")


def main() -> int:
    group = sys.argv[1] if len(sys.argv) > 1 else None
    target = Path(os.environ.get("CARGO_TARGET_DIR", "target")) / "criterion"
    if not target.exists():
        print(f"no criterion output at {target} — run `cargo bench` first")
        return 1
    rows = scan_criterion(target, group)
    print_markdown_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
