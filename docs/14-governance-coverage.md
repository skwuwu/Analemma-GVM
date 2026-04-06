# Governance Coverage by Mode

> What GVM controls, what it doesn't, and why — for each isolation mode.

---

## Mode Overview

All agent execution uses `gvm run` with flags:

| Mode | Command | Enforcement | Status |
|------|---------|-------------|--------|
| **Observe** | `gvm run --watch agent.py` | Observation only (no blocking) | Production |
| **Enforce** | `gvm run agent.py` | Agent respects `HTTP_PROXY` | Production |
| **Discover** | `gvm run -i agent.py` | Enforce + suggest rules after exit | Production |
| **Sandbox** | `gvm run --sandbox agent.py` | Kernel-level (namespace + seccomp + MITM) | Production, Linux |
| **Contained** | `gvm run --contained agent.py` | Docker network isolation + MITM | **Unsupported** — experimental only |

> **Contained mode (`--contained`)** is implemented as a proof-of-concept but is **not supported for production use**. Known issues: WSL2 network instability, iptables missing in slim images, `NET_ADMIN` capability abuse, Windows path failures. Use `--sandbox` on Linux. Contained mode may be stabilized in a future release.

> **Wasm policy engine** (`--features wasm`) is disabled by default. The native Rust policy engine is used for all enforcement. Wasm support is an **unsupported experimental feature** for future third-party policy plugin scenarios. Enabling it adds ~10MB to the binary and includes 5 known wasmtime CVEs.

All modes share the same SRR rules, ABAC policies, and config files.

---

## Mode 1: Cooperative (`gvm run`)

The agent runs on the host with `HTTP_PROXY`/`HTTPS_PROXY` environment variables pointing to the GVM proxy. The agent **can** bypass this by ignoring the proxy or making direct connections.

### What's governed

| Channel | Governed? | Mechanism |
|---------|-----------|-----------|
| HTTP API calls | **Yes** | Routed through proxy via `HTTP_PROXY` |
| HTTPS API calls (Python) | **Yes** | Python `requests`/`httpx` respect `HTTPS_PROXY` → CONNECT tunnel |
| HTTPS API calls (Node.js) | **No** | Node.js `https` module ignores `HTTPS_PROXY` by default |
| File system | No | Agent has full host filesystem access |
| Process execution | No | Agent can spawn any process |
| Network (non-HTTP) | No | Agent can use UDP, raw sockets, etc. |

### Runtime-specific HTTPS behavior

| Runtime | HTTPS_PROXY respected? | Coverage |
|---------|----------------------|----------|
| Python (`requests`, `httpx`, `urllib3`) | **Yes** (automatic) | Full — CONNECT tunnel to proxy |
| Python (`aiohttp`) | **Yes** (with `trust_env=True`) | Full |
| Node.js (`https`, `fetch`) | **No** (ignores env var) | HTTP only |
| Node.js (`undici` with `EnvHttpProxyAgent`) | Yes | Full |
| Go (`net/http`) | **Yes** (automatic) | Full |
| curl | **Yes** | Full |
| Ruby (`net/http`) | **Yes** | Full |

**GVM detects Node.js agents** in cooperative mode and warns:
```
⚠ Node.js agent detected in cooperative mode.
  Node.js does not respect HTTPS_PROXY by default — HTTPS traffic may bypass the proxy.
  Use --contained or --sandbox for full HTTPS coverage via DNAT.
```

### Who this is for

Python agent developers testing policies locally. For Node.js/TypeScript agents (OpenClaw, custom Node.js), use `--contained` or `--sandbox`.

### Honest limitation

Cooperative mode depends on the agent's HTTP library respecting proxy environment variables. Python does; Node.js doesn't. This is not a GVM limitation — it's a Node.js design choice. Use `--contained` or `--sandbox` for runtime-agnostic coverage.

---

## Mode 2: Contained (`gvm run --contained`)

> **Status: Experimental — not production-ready.** Contained mode is implemented but unstable due to Docker environment limitations: WSL2 network bridge issues with large responses, iptables unavailability in slim base images, `NET_ADMIN` capability constraints, and Windows path translation failures. Use `--sandbox` on Linux for production isolation. Contained mode stabilization is planned for a future release.

The agent runs inside a Docker container with network-level isolation and transparent HTTPS MITM inspection.

### What's governed

| Channel | Governed? | Mechanism |
|---------|-----------|-----------|
| HTTP API calls | **Yes** | Routed through proxy via `HTTP_PROXY` |
| HTTPS API calls | **Full L7** | Ephemeral CA injected, DNAT 443 → MITM listener |
| API key injection (HTTPS) | **Yes** | MITM strips agent auth headers, injects from `secrets.toml` |
| Proxy bypass (direct HTTPS) | **Hardened** | Docker `--internal` network + DNAT redirect |
| File system reads | Read-only root | `--read-only` Docker flag |
| File system writes | `/tmp` only | tmpfs, destroyed on exit |
| Resource limits | **Yes** | `--memory`, `--cpus` Docker resource limits |
| Process execution | Allowed | Docker default seccomp profile |
| UDP/ICMP | Blocked | Docker `--internal` network has no external route |

### HTTPS MITM — CA trust coverage

| Runtime | Mechanism | Supported |
|---------|-----------|-----------|
| Python (requests, urllib3) | `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` env var | Yes |
| Node.js | `NODE_EXTRA_CA_CERTS` env var | Yes |
| Go (net/http) | System trust store (`/etc/ssl/certs/`) | Yes |
| curl / libcurl | `CURL_CA_BUNDLE` env var | Yes |
| Ruby (net/http) | `SSL_CERT_FILE` env var | Yes |
| Java (HttpsURLConnection) | Requires JKS keystore import (`keytool`) | Manual only |
| Certificate pinning apps | Reject any MITM CA | Cannot intercept |

### Trade-off: `NET_ADMIN` capability

`--contained` grants `NET_ADMIN` to the container for iptables DNAT setup (HTTPS redirect to MITM listener). This means the agent could theoretically modify iptables rules inside the container. Mitigated by:
- `--no-new-privileges` Docker flag
- `--internal` Docker network (no external route even if rules are modified)

For stronger isolation, use `--sandbox`.

---

## Mode 3: Sandbox (`gvm run --sandbox`)

The agent runs in isolated Linux namespaces (user, PID, mount, network) with seccomp-BPF syscall filtering, TC ingress filter network enforcement (kernel-level, unbypassable), and overlayfs filesystem governance. This is the **production security boundary**.

**Resource lifecycle**: Each sandbox writes a per-PID state file (`/run/gvm/gvm-sandbox-{pid}.state`) listing all created resources (veth, iptables rules, mounts, cgroups). On normal exit, cleanup + delete. On crash, the next `gvm run --sandbox` auto-cleans orphaned resources. Manual cleanup: `gvm cleanup`.

### Network governance

| Channel | Governed? | Mechanism |
|---------|-----------|-----------|
| HTTP API calls | **Yes** | `HTTP_PROXY` + iptables OUTPUT ACCEPT only to proxy |
| HTTPS API calls | **Full L7** | DNAT 443 → MITM listener (iptables + veth) |
| HTTPS direct bypass attempt | **Blocked** | DNAT forces all TCP 443 through MITM |
| API key injection (HTTPS) | **Yes** | MITM strips + injects, agent never sees keys |
| UDP (except DNS) | **Blocked** | iptables OUTPUT DROP |
| DNS | **Allowed** | UDP 53 to host veth IP only |
| DNS tunneling | **Out of scope** | Use DNS security (Route 53 DNS Firewall, Cloudflare Gateway). GVM logs DNS queries for audit. |
| QUIC / HTTP3 (UDP 443) | **Blocked** | UDP DROP (browser falls back to TCP/TLS) |
| ICMP | **Blocked** | iptables OUTPUT DROP |
| WebRTC / P2P | **Blocked** | UDP DROP + no STUN server reachable |
| IPv6 | **Blocked** | sysctl disabled + ip6tables DROP all |
| Raw sockets (AF_PACKET) | **Blocked** | seccomp KILL |
| Netlink (iptables modification) | **Blocked** | seccomp KILL + capabilities dropped |

**Defense layers (from outermost):**
1. **TC ingress filter** on host-side veth (tc u32 classifier) — kernel-level, agent cannot touch
2. **iptables OUTPUT chain** — proxy TCP + DNS UDP only, all else DROP
3. **seccomp-BPF** — AF_NETLINK/AF_PACKET killed, prevents firewall modification
4. **Capability drop** — all capabilities removed after setup

### Filesystem governance

| Path | Permission | Mechanism |
|------|-----------|-----------|
| `/workspace` (with `fs_policy`) | **Copy-on-write** | overlayfs: writes go to upper layer (tmpfs), originals untouched |
| `/workspace` (legacy mode) | **Read-only** | bind-mount with `MS_RDONLY` |
| `/workspace/output` | **Writable** (host-visible) | writable bind-mount (backward compat) |
| `/tmp` | **Writable** (volatile) | tmpfs 32MB, destroyed on exit |
| `/proc` | **PID-scoped** | CLONE_NEWPID + `hidepid=2` |
| `/sys` | **Not mounted** | Agent cannot access sysfs |
| `/dev` | **Minimal** | null, zero, urandom, random only |
| Everything else | **Inaccessible** | `pivot_root` removes old root |

### overlayfs Trust-on-Pattern governance

When `fs_policy` is configured, overlayfs captures all file changes in a tmpfs upper layer. At session end, changes are classified:

| Classification | Default patterns | Behavior |
|---------------|-----------------|----------|
| **AutoMerge** | `*.csv, *.pdf, *.txt, *.png, *.jpg, *.xml` | Copied to host automatically |
| **ManualCommit** | `*.sh, *.py, *.js, *.ts, *.toml, *.yaml, *.json, *.conf, *.env` | Diff report shown, manual approval required |
| **Discard** | `/tmp/*, *.log, *.cache, __pycache__/*, *.pyc, .git/*` | Deleted, never reaches host |

Priority: Discard > ManualCommit > AutoMerge > default (consistent with SRR's `max_strict` principle).

Configuration:
```toml
[filesystem]
auto_merge = ["*.csv", "*.pdf", "*.txt"]
manual_commit = ["*.sh", "*.py", "*.js", "*.json"]
discard = ["/tmp/*", "*.log", "__pycache__/*"]
default = "manual_commit"
upper_size_mb = 256
```

Requires kernel 5.11+ (overlayfs in user namespace). Falls back to legacy mode on older kernels.

### Process governance

| Syscall | Allowed? | Mechanism |
|---------|----------|-----------|
| fork / clone (threads) | Allowed | Required for agent operation |
| exec | Allowed | Agent spawns interpreters |
| ptrace | **Killed** | seccomp KILL_PROCESS |
| process_vm_readv | **Killed** | seccomp KILL_PROCESS |
| mount / umount | **Killed** | seccomp KILL_PROCESS |
| bpf (load eBPF) | **Killed** | seccomp KILL_PROCESS |
| unshare / setns | **Killed** | seccomp KILL_PROCESS |
| open_by_handle_at | **Killed** | Container escape vector (CVE-2015-3627) |

~111 syscalls whitelisted. Default-deny: new kernel syscalls are automatically blocked.

### Resource governance

| Resource | Mechanism | Configuration |
|----------|-----------|---------------|
| Memory | cgroup v2 `memory.max` | `--memory 1g` (omit = unlimited) |
| CPU | cgroup v2 `cpu.max` | `--cpus 0.5` (omit = unlimited) |
| Filesystem | overlayfs upper tmpfs size | `upper_size_mb = 256` in fs_policy |
| `/tmp` | tmpfs size limit | 32MB (hardcoded) |
| Network connections | TC filter + iptables | Proxy-only TCP |
| PID count | PID namespace | Isolated PID table |

### CA private key isolation

The MITM CA private key **never enters the sandbox**:

| Location | CA key present? |
|----------|----------------|
| Proxy process memory (host) | Yes — required for leaf cert signing |
| Sandbox filesystem | **No** — only public certificate injected |
| Sandbox environment variables | **No** — cert path only |
| Sandbox `/proc` | **No** — PID namespace + seccomp blocks access |

The CLI downloads the public certificate from `GET /gvm/ca.pem` before sandbox launch. The proxy holds the private key exclusively.

---

## Admin API isolation

The proxy runs two separate listeners:

| Port | Audience | Endpoints |
|------|----------|-----------|
| **8080** (proxy) | Agent | health, check, vault, ca.pem, proxy handler |
| **9090** (admin) | Operator only | approve, pending, reload, info |

The agent only knows `HTTP_PROXY=...:8080`. The admin port is not injected into the agent environment. In `--sandbox`, iptables only allows TCP to the proxy port — admin port is unreachable.

This prevents a sandboxed agent from self-approving IC-3 (human approval) requests.

---

## What GVM does NOT govern

These are architectural boundaries, not missing features:

| Channel | Why not governed | Mitigation |
|---------|-----------------|------------|
| **Agent stdin/stdout** | Not network traffic | Agent spawned with `stdin(Stdio::null())` |
| **DNS content** | DNS queries via host resolver, not through HTTP proxy | Use DNS security tools (Route 53 DNS Firewall, Cloudflare Gateway). GVM logs DNS queries to WAL for audit. |
| **DNS tunneling** | DLP concern, not HTTP governance | DNS exfiltration prevention belongs to network-layer DNS security. GVM provides forensic visibility. |
| **Prompt injection detection** | Requires semantic analysis (ML/LLM) | Use an LLM WAF upstream. GVM + LLM WAF are complementary. |
| **Agent internal state** | SDK-only (agent must use `@ic()` decorator) | Tier 1 (proxy-only) governs actions; Tier 2 (SDK) adds intent verification |
| **LLM response content** | Privacy — response bodies not stored by default | Thinking hash stored for forensics (SHA-256, opt-in raw) |

---

## Mode comparison summary

| Capability | Cooperative | Contained (experimental) | Sandbox |
|-----------|-------------|-----------|---------|
| HTTP governance | Cooperative | Structural | Structural |
| HTTPS L7 inspection | Domain only | Full (MITM) | Full (MITM) |
| API key isolation | HTTP only | HTTP + HTTPS | HTTP + HTTPS |
| Network bypass prevention | None | Docker network | Kernel (TC + iptables + seccomp) |
| Filesystem governance | None | Read-only root | overlayfs Trust-on-Pattern |
| Resource limits | None | Docker limits | cgroup v2 |
| Syscall filtering | None | Docker default | Custom seccomp (~130 allowed) |
| IC-3 self-approval prevention | None | None | Admin port unreachable |
| Stability | **Production** | **Experimental** | **Production** |
| Platform | Any OS | Any OS + Docker | Linux (kernel ≥ 4.15, recommended ≥ 6.1) |

---

[← Reference](13-reference.md) | [Security Model →](11-security-model.md) | [Overview →](00-overview.md)
