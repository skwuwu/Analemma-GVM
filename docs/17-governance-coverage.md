# Governance Coverage by Mode

> What GVM controls, what it doesn't, and why — for each isolation mode.

---

## Mode Overview

| Mode | Command | Enforcement | Target |
|------|---------|-------------|--------|
| **Cooperative** | `gvm run agent.py` | Agent respects `HTTP_PROXY` | Development, any OS |
| **Contained** | `gvm run --contained agent.py` | Docker network isolation + MITM | CI/CD, any OS |
| **Sandbox** | `gvm run --sandbox agent.py` | Kernel-level (namespace + seccomp + TC + eBPF) | Production, Linux |

All modes share the same SRR rules, ABAC policies, and config files. Policies built in development work identically in production.

---

## Mode 1: Cooperative (`gvm run`)

The agent runs on the host with `HTTP_PROXY`/`HTTPS_PROXY` environment variables pointing to the GVM proxy. The agent **can** bypass this by ignoring the proxy or making direct connections.

### What's governed

| Channel | Governed? | Mechanism |
|---------|-----------|-----------|
| HTTP API calls | **Yes** | Routed through proxy via `HTTP_PROXY` |
| HTTPS API calls | **Domain only** | CONNECT tunnel — proxy sees hostname, not path/body |
| File system | No | Agent has full host filesystem access |
| Process execution | No | Agent can spawn any process |
| Network (non-HTTP) | No | Agent can use UDP, raw sockets, etc. |

### Who this is for

Developers testing policies locally. The agent cooperates because you trust the code — you just want visibility into what it calls and a basic safety net.

### Honest limitation

The agent can bypass GVM by making direct HTTPS connections without the proxy. This mode is **observation + cooperative enforcement**, not a security boundary.

---

## Mode 2: Contained (`gvm run --contained`)

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

The agent runs in isolated Linux namespaces (user, PID, mount, network) with seccomp-BPF syscall filtering, eBPF TC network enforcement, and overlayfs filesystem governance. This is the **production security boundary**.

### Network governance

| Channel | Governed? | Mechanism |
|---------|-----------|-----------|
| HTTP API calls | **Yes** | `HTTP_PROXY` + iptables OUTPUT ACCEPT only to proxy |
| HTTPS API calls | **Full L7** | DNAT 443 → MITM listener (iptables + veth) |
| HTTPS direct bypass attempt | **Blocked** | DNAT forces all TCP 443 through MITM |
| API key injection (HTTPS) | **Yes** | MITM strips + injects, agent never sees keys |
| UDP (except DNS) | **Blocked** | iptables OUTPUT DROP |
| DNS | **Allowed** | UDP 53 to host veth IP only |
| DNS tunneling | **Partially open** | Host DNS server can relay encoded data |
| QUIC / HTTP3 (UDP 443) | **Blocked** | UDP DROP (browser falls back to TCP/TLS) |
| ICMP | **Blocked** | iptables OUTPUT DROP |
| WebRTC / P2P | **Blocked** | UDP DROP + no STUN server reachable |
| IPv6 | **Blocked** | sysctl disabled + ip6tables DROP all |
| Raw sockets (AF_PACKET) | **Blocked** | seccomp KILL |
| Netlink (iptables modification) | **Blocked** | seccomp KILL + capabilities dropped |

**Defense layers (from outermost):**
1. **eBPF TC filter** on host-side veth — kernel-level, agent cannot touch
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
| Memory | cgroup v2 `memory.max` | `--memory 512m` |
| CPU | cgroup v2 `cpu.max` | `--cpus 0.5` |
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
| **DNS content** | DNS queries via host resolver, not through HTTP proxy | External DNS blocked (only host veth IP:53 allowed in sandbox) |
| **Prompt injection detection** | Requires semantic analysis (ML/LLM) | Use an LLM WAF upstream. GVM + LLM WAF are complementary. |
| **Agent internal state** | SDK-only (agent must use `@ic()` decorator) | Tier 1 (proxy-only) governs actions; Tier 2 (SDK) adds intent verification |
| **LLM response content** | Privacy — response bodies not stored by default | Thinking hash stored for forensics (SHA-256, opt-in raw) |

---

## Mode comparison summary

| Capability | Cooperative | Contained | Sandbox |
|-----------|-------------|-----------|---------|
| HTTP governance | Cooperative | Structural | Structural |
| HTTPS L7 inspection | Domain only | Full (MITM) | Full (MITM) |
| API key isolation | HTTP only | HTTP + HTTPS | HTTP + HTTPS |
| Network bypass prevention | None | Docker network | Kernel (TC + iptables + seccomp) |
| Filesystem governance | None | Read-only root | overlayfs Trust-on-Pattern |
| Resource limits | None | Docker limits | cgroup v2 |
| Syscall filtering | None | Docker default | Custom seccomp (~111 allowed) |
| IC-3 self-approval prevention | None | None | Admin port unreachable |
| Platform | Any OS | Any OS + Docker | Linux (kernel ≥ 4.15, recommended ≥ 6.1) |
