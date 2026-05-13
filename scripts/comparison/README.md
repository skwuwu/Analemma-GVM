# GVM vs OPA+Envoy comparison — run instructions

This directory holds the benchmark infrastructure that compares GVM to
the canonical OPA+Envoy+Docker stack across five dimensions, with both
stacks measured as **full deployments** — agent process running inside
an isolation boundary, egress intercepted by the policy plane.

Full methodology: [`../../docs/internal/comparison-opa-envoy.md`](../../docs/internal/comparison-opa-envoy.md).
Public summary: [`../../docs/comparison-opa-envoy.md`](../../docs/comparison-opa-envoy.md).

## What's here

| File | Purpose |
|---|---|
| `setup.sh` | Installs Docker, OPA CLI, hyperfine; pulls Envoy + OPA images; compiles `policy.rego` to WASM. Run once per host. |
| `bench.sh` | Runs the benchmark sweep (D1, D2a, D2b, D3, D4, D5). Writes CSV to `results/comparison-<timestamp>/`. |
| `policy.rego` | Rego policy — semantic equivalent of `srr-bench.toml`. |
| `srr-bench.toml` | SRR rules — semantic equivalent of `policy.rego`. |
| `envoy-extauthz.yaml` | Envoy config for Stack B (OPA over gRPC ext_authz). Listens on `:10000`. |
| `envoy-wasm.yaml` | Envoy config for Stack C (OPA-WASM in-process). Listens on `:10001`. |
| `build/` | Generated WASM bundle from `setup.sh` (gitignored). |

## How the bench is shaped

Each request goes through:

```
agent inside isolation ──> policy plane ──> mock upstream
       (sandbox/         (gvm-proxy /        (Python http.server
        container)        Envoy + OPA)         on 0.0.0.0:9999)
```

The mock upstream binds to `0.0.0.0:9999` so it is reachable from every
network namespace (sandbox, container, host). The agent inside isolation
addresses it as `bench.local:9999`; bench.sh maps `bench.local` to the
host's primary IP via `/etc/hosts` (added at run start, removed at end).

## Run on EC2

Target host: Ubuntu 22.04+ on EC2 t3.medium (same hardware as the
existing GVM benchmarks).

### 1. Sync the latest source

```bash
# Local:  git push
# EC2:
cd ~/Analemma-GVM
git fetch && git reset --hard origin/master
```

### 2. Build the GVM binaries

```bash
cargo build --release -p gvm-cli -p gvm-proxy
```

The bench prints binary mtime + git rev at startup; stale binaries
surface loudly.

### 3. Set up the OPA+Envoy stack (first run only)

```bash
bash scripts/comparison/setup.sh
```

Installs `opa` and `hyperfine`, pulls `envoyproxy/envoy:v1.32-latest`
and `openpolicyagent/opa:1.16.2-envoy`, compiles `policy.rego` to a
WASM bundle for Stack C, runs a Rego smoke test.

### 4. Run the comparison (use tmux)

bench.sh needs **sudo** because `gvm run --sandbox` requires root and
Docker without group membership also does. Long-running, so use tmux:

```bash
tmux new -s gvm-compare
sudo bash scripts/comparison/bench.sh         # full sweep, ~30-45 min
# detach: Ctrl-b d ; reattach: tmux attach -t gvm-compare
```

Subset runs:

```bash
sudo bash scripts/comparison/bench.sh d1          # latency
sudo bash scripts/comparison/bench.sh d2a d2b     # both cold starts
sudo bash scripts/comparison/bench.sh d3          # memory scaling
```

Results in `results/comparison-<timestamp>/`:

```
d1.csv            steady-state latency by stack × scenario
d2a.csv           workload cold start by stack × iteration
d2b.csv           control-plane cold start by stack × iteration
d3.csv            memory RSS by stack × N agents
d4.csv            distribution size
d5.csv            decision-to-log latency
gvm-proxy.log     proxy log from Stack A runs
manifest.txt      run metadata
```

### 5. Archive + write up results

```bash
mkdir -p docs/internal/raw
cp -r results/comparison-<timestamp> docs/internal/raw/
```

Then fill `docs/internal/comparison-opa-envoy.md` §6 with numbers and
update the public summary table.

## What this bench does NOT measure

- **TLS overhead** — D1 measures plain HTTP. MITM TLS overhead is
  measured separately in `scripts/bench-overhead.sh`.
- **Multi-host policy distribution** — single-host only on both sides.
- **L7 features Envoy ships and GVM does not** — circuit breaking,
  retries, load balancing, gRPC-Web transcoding, mTLS termination.

The transparent vs cooperative interception asymmetry is documented
explicitly in
[`../../docs/internal/comparison-opa-envoy.md` §2](../../docs/internal/comparison-opa-envoy.md#2-stacks-under-test)
and surfaced next to every D1 result.

## Troubleshooting

**"sudo: gvm: command not found"**: sudo path doesn't include
~/.cargo/bin. Use absolute path or run from repo: bench.sh uses
`$REPO_DIR/target/release/gvm` already.

**`gvm run --sandbox` fails at startup**: check kernel version
(needs ≥ 6.5 for full sandbox functionality) and that
`/proc/sys/kernel/unprivileged_userns_clone == 1`.

**Envoy container exits immediately**: `sudo docker logs envoy-ext`
(or `envoy-wasm`). Most common: YAML typo. Fix, re-run.

**OPA container exits immediately**: `sudo docker logs opa-ext`.
Most common: Rego compile error — re-run `setup.sh` to surface.

**Stack C all-deny or all-allow**: WASM bundle path/entrypoint
mismatch. Verify `scripts/comparison/build/opa-bundle/policy.wasm`
exists and `envoy-wasm.yaml` references the right entry.

**Port already in use**:
```bash
sudo docker rm -f envoy-ext envoy-wasm opa-ext 2>/dev/null
sudo pkill -f gvm-proxy 2>/dev/null
```

**/etc/hosts has stale `bench.local` entry**: bench.sh removes on
clean exit, but a SIGKILL leaves it. Remove with:
```bash
sudo sed -i '/# gvm-bench bench.local/d' /etc/hosts
```
