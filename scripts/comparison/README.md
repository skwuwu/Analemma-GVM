# GVM vs OPA+Envoy comparison — run instructions

This directory holds the benchmark infrastructure that compares GVM to
the canonical OPA+Envoy+Docker stack across five dimensions. Full
methodology: [`../../docs/internal/comparison-opa-envoy.md`](../../docs/internal/comparison-opa-envoy.md).
Public summary: [`../../docs/comparison-opa-envoy.md`](../../docs/comparison-opa-envoy.md).

## What's here

| File | Purpose |
|---|---|
| `setup.sh` | Installs Docker, OPA CLI, hyperfine; pulls Envoy + OPA images; compiles `policy.rego` to WASM. Run once per host. |
| `bench.sh` | Runs the benchmark sweep (D1-D5) against all three stacks. Writes CSV to `results/comparison-<timestamp>/`. |
| `policy.rego` | Rego policy — semantic equivalent of `srr-bench.toml`. |
| `srr-bench.toml` | SRR rules — semantic equivalent of `policy.rego`. |
| `envoy-extauthz.yaml` | Envoy config for Stack B (OPA over gRPC ext_authz). Listens on `:10000`. |
| `envoy-wasm.yaml` | Envoy config for Stack C (OPA-WASM in-process). Listens on `:10001`. |
| `build/` | Generated WASM bundle from `setup.sh` (gitignored). |

## Run on EC2

Target host: Ubuntu 22.04+ on EC2 t3.medium (same hardware as the
existing GVM benchmarks for cross-comparable numbers).

### 1. Sync the latest source

```bash
# Locally:
git push

# On EC2:
cd ~/Analemma-GVM
git fetch && git reset --hard origin/master
```

This step is non-negotiable. See `feedback_bench_origin_sync.md` —
benching against a stale tree wastes the run.

### 2. Build the GVM binaries

```bash
cargo build --release -p gvm-cli -p gvm-proxy
```

The bench script prints binary mtime + git rev at startup; a stale
binary surfaces loudly there.

### 3. Set up the OPA+Envoy stack

```bash
bash scripts/comparison/setup.sh
```

This will (a) install Docker if missing, (b) install `opa` and
`hyperfine`, (c) pull `envoyproxy/envoy:v1.32-latest` and
`openpolicyagent/opa:0.71.0-envoy`, (d) compile `policy.rego` to a
WASM bundle for Stack C, (e) verify the Rego policy passes a smoke
test on both allow and deny paths.

If Docker was newly installed, run `newgrp docker` or re-login so the
shell picks up the group membership.

### 4. Run the comparison

Long-running pipeline — **use tmux per CLAUDE.md** (never `nohup`):

```bash
tmux new -s gvm-compare
bash scripts/comparison/bench.sh         # full D1-D5 sweep
# detach with Ctrl-b d; reattach with `tmux attach -t gvm-compare`
```

Subset runs are fine:

```bash
bash scripts/comparison/bench.sh d1      # only latency
bash scripts/comparison/bench.sh d3 d4   # only memory + distribution size
```

Results land in `results/comparison-<timestamp>/`:

```
d1.csv       per-request latency by stack × scenario
d2.csv       cold start by stack × iteration
d3.csv       memory RSS by stack × state × process
d4.csv       distribution size by stack × artifact
d5.csv       audit decision-to-log latency + tamper evidence flag
manifest.txt run metadata (git rev, mtimes, kernel, image versions)
gvm-proxy.log proxy log from Stack A runs
```

### 5. Archive results

After a successful run, copy the timestamped result directory under
`docs/internal/raw/` for future reference:

```bash
mkdir -p docs/internal/raw
cp -r results/comparison-<timestamp> docs/internal/raw/
git add docs/internal/raw/comparison-<timestamp>
```

Then update the result tables in
`docs/internal/comparison-opa-envoy.md` §6 with the new numbers and
update the public summary table in `docs/comparison-opa-envoy.md`.

## Troubleshooting

**"Docker daemon not running"**: `sudo systemctl start docker`.

**Envoy container exits immediately**: `docker logs envoy-ext` (or
`envoy-wasm`). Most common cause: a typo in the YAML that the parser
rejects at startup. Fix the YAML, re-run.

**OPA container exits immediately**: `docker logs opa-ext`. Most common
cause: Rego policy fails to compile. Re-run `opa eval` from `setup.sh`
to surface the error.

**Stack C (WASM) hangs or all-deny**: the WASM bundle path or entrypoint
in `envoy-wasm.yaml` does not match what `setup.sh` produced. Verify
`scripts/comparison/build/opa-bundle/policy.wasm` exists.

**Port already in use**: another GVM run is on `:8080`, or a previous
bench did not clean up. `bash scripts/comparison/bench.sh` traps EXIT
and cleans up its own processes/containers, but a SIGKILL or crashed
run leaves residue:

```bash
docker rm -f envoy-ext envoy-wasm opa-ext 2>/dev/null
pkill -f gvm-proxy 2>/dev/null
```

## Known limitations

The four `Known Limitations` items in
[`../../docs/internal/comparison-opa-envoy.md` §9](../../docs/internal/comparison-opa-envoy.md#9-known-limitations)
apply. Most important for running the bench:

- Single-host topology only — no multi-node OPA bundle distribution.
- TLS is not included in D1 (latency); MITM/TLS cost is measured
  separately in `scripts/bench-overhead.sh`.
- One policy shape (three logical rules) — does not exercise complex
  Rego expressiveness or large rule sets except in D1c (10K fallthrough).
