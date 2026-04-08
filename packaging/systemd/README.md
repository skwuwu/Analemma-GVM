# GVM systemd integration

Two units that turn `gvm run --sandbox` into a production-grade daemon
without changing a single line of GVM code. Both pieces are pure
packaging — they just wrap the existing CLI.

## Files

| File | Type | Purpose |
|---|---|---|
| `gvm-cleanup.service` | oneshot | Boot-time orphan sweep. Releases any veth / iptables / mount / cgroup state left behind by a sandbox that crashed before reboot. |
| `gvm-sandbox@.service` | template | Per-agent sandbox supervisor. Instance name `%i` selects which script under `/etc/gvm/agents/<name>.py` to launch. |

## Install

```bash
# 1. Drop the units into the system unit directory.
sudo install -m 0644 packaging/systemd/gvm-cleanup.service     /etc/systemd/system/
sudo install -m 0644 packaging/systemd/gvm-sandbox@.service    /etc/systemd/system/

# 2. Make sure the binary lives at the path the units expect.
sudo install -m 0755 target/release/gvm /usr/local/bin/gvm

# 3. Set up the agents directory.
sudo mkdir -p /etc/gvm/agents
sudo cp my-agent.py /etc/gvm/agents/my-agent.py
sudo chmod 0644 /etc/gvm/agents/my-agent.py

# 4. Reload systemd, enable cleanup at boot, and start your first agent.
sudo systemctl daemon-reload
sudo systemctl enable --now gvm-cleanup.service
sudo systemctl enable --now gvm-sandbox@my-agent.service
```

Verify:

```bash
sudo systemctl status gvm-cleanup.service
sudo systemctl status gvm-sandbox@my-agent.service
journalctl -u gvm-sandbox@my-agent.service -f
gvm status
```

## Lifecycle

```
boot
 │
 ├── network-pre.target
 ├── gvm-cleanup.service          (sweeps any pre-reboot orphans)
 ├── network.target
 ├── multi-user.target
 │     │
 │     └── gvm-sandbox@my-agent.service
 │           ExecStartPre=gvm cleanup     ← second sweep, defense in depth
 │           ExecStart=gvm run --sandbox  ← long-running
 │           on crash → SIGTERM → 30s grace → SIGKILL
 │           ExecStopPost=gvm cleanup     ← release whatever the run leaked
 │
 └── on `systemctl stop`: same stop sequence as crash
```

## Override per agent

Use a drop-in instead of editing the unit file directly:

```bash
sudo systemctl edit gvm-sandbox@my-agent.service
```

```ini
[Service]
Environment=AgentScript=/srv/agents/my-agent/main.py
Environment=GVM_SANDBOX_TIMEOUT=3600
MemoryMax=2G
```

The `MemoryMax=` line is enforced by systemd's cgroup, layered *on top of*
GVM's own `--memory` flag. Either limit kicks in first depending on which
is tighter.

## tmux vs systemd — pick one per use case

| Use case | Recommended |
|---|---|
| Interactive debugging, short-lived tests | `tmux new -s work; gvm run --sandbox …` |
| Long-running production agents | `systemctl enable --now gvm-sandbox@…` |
| Survives SSH disconnect | both |
| Survives host reboot | systemd only |
| Auto-restart on crash | systemd only |
| Auto-cleanup on boot | systemd only (`gvm-cleanup.service`) |
| Single command, no setup | tmux |

GVM is identical in both modes — the orphan-detection state file
(`/run/gvm/gvm-sandbox-<pid>.state`) records the tmux session name when
present, so `gvm status` shows you which session owns each sandbox even
when the system is running a mix of both.

## Uninstall

```bash
sudo systemctl disable --now gvm-sandbox@my-agent.service
sudo systemctl disable --now gvm-cleanup.service
sudo rm /etc/systemd/system/gvm-cleanup.service
sudo rm /etc/systemd/system/gvm-sandbox@.service
sudo systemctl daemon-reload
sudo gvm cleanup    # safety net for any final stragglers
```
