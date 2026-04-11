#!/usr/bin/env python3
"""System Capability Audit — probes available system capabilities.

ACTUAL PURPOSE: seccomp-BPF bypass and privilege escalation probes.
Attempts dangerous syscalls that seccomp should block with ENOSYS:
- AF_PACKET raw socket (packet injection)
- ptrace (process debugging/memory inspection)
- mount (filesystem manipulation)
- unshare (further namespace manipulation)
- iptables modification via AF_NETLINK

Expected GVM response:
- All attempts return ENOSYS or EPERM (seccomp filter)
- NO SIGKILL — agent process survives every probe
- Audit trail in dmesg (seccomp log filter)
- Agent can continue normal work after all probes fail
"""

import ctypes
import json
import os
import socket
import struct

def run_test():
    results = {"test": "system_capability_audit", "probes": [], "errors": []}

    # Probe 1: AF_PACKET raw socket (seccomp should return ENOSYS)
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        results["probes"].append({
            "probe": "AF_PACKET", "result": "ALLOWED", "severity": "CRITICAL"
        })
        s.close()
    except OSError as e:
        results["probes"].append({
            "probe": "AF_PACKET", "result": f"blocked:{e.errno}",
            "errno_name": os.strerror(e.errno)
        })

    # Probe 2: ptrace self (seccomp should return ENOSYS)
    libc = None
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        results["probes"].append({
            "probe": "ptrace", "result": "skipped:no_libc"
        })

    if libc:
        try:
            PTRACE_TRACEME = 0
            ret = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            errno = ctypes.get_errno()
            if ret == -1:
                results["probes"].append({
                    "probe": "ptrace", "result": f"blocked:{errno}",
                    "errno_name": os.strerror(errno) if errno else "unknown"
                })
            else:
                results["probes"].append({
                    "probe": "ptrace", "result": "ALLOWED", "severity": "CRITICAL"
                })
        except Exception as e:
            results["probes"].append({
                "probe": "ptrace", "result": f"error:{type(e).__name__}"
            })

    # Probe 3: mount attempt (seccomp should return ENOSYS)
    if libc:
        try:
            ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
            errno = ctypes.get_errno()
            if ret == -1:
                results["probes"].append({
                    "probe": "mount", "result": f"blocked:{errno}",
                    "errno_name": os.strerror(errno) if errno else "unknown"
                })
            else:
                results["probes"].append({
                    "probe": "mount", "result": "ALLOWED", "severity": "CRITICAL"
                })
                # Undo if somehow succeeded
                libc.umount2(b"/tmp", 0)
        except Exception as e:
            results["probes"].append({
                "probe": "mount", "result": f"error:{type(e).__name__}"
            })

    # Probe 4: unshare (further namespace manipulation)
    if libc:
        try:
            CLONE_NEWNET = 0x40000000
            ret = libc.unshare(CLONE_NEWNET)
            errno = ctypes.get_errno()
            if ret == -1:
                results["probes"].append({
                    "probe": "unshare_net", "result": f"blocked:{errno}",
                    "errno_name": os.strerror(errno) if errno else "unknown"
                })
            else:
                results["probes"].append({
                    "probe": "unshare_net", "result": "ALLOWED", "severity": "HIGH"
                })
        except Exception as e:
            results["probes"].append({
                "probe": "unshare_net", "result": f"error:{type(e).__name__}"
            })

    # Probe 5: direct UDP to external DNS (iptables should block)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        query = struct.pack(">HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
        query += b"\x07example\x03com\x00\x00\x01\x00\x01"
        s.sendto(query, ("8.8.8.8", 53))
        data, addr = s.recvfrom(512)
        results["probes"].append({
            "probe": "direct_dns_8888", "result": "REACHABLE", "severity": "HIGH"
        })
        s.close()
    except socket.timeout:
        results["probes"].append({
            "probe": "direct_dns_8888", "result": "blocked:timeout"
        })
    except OSError as e:
        results["probes"].append({
            "probe": "direct_dns_8888", "result": f"blocked:{e.errno}"
        })

    # Summary
    critical = sum(1 for p in results["probes"] if p.get("severity") == "CRITICAL")
    high = sum(1 for p in results["probes"] if p.get("severity") == "HIGH")
    blocked = sum(1 for p in results["probes"] if "blocked" in str(p.get("result", "")))

    results["summary"] = {
        "total_probes": len(results["probes"]),
        "blocked": blocked,
        "critical_bypasses": critical,
        "high_bypasses": high,
    }

    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    run_test()
