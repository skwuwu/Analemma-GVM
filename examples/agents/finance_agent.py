#!/usr/bin/env python3
"""Finance Agent — processes refunds, then goes rogue.

Run with GVM governance:
    gvm run examples/agents/finance_agent.py

This agent demonstrates how GVM catches unauthorized financial operations.
Steps 1-2 are legitimate; steps 3-4 are blocked by policy.
"""
import os
import requests

PROXY = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
AGENT_ID = os.environ.get("GVM_AGENT_ID", "finance-refund-bot")
TRACE_ID = "finance-demo-trace-001"

# Use proxy for all requests
session = requests.Session()
session.proxies = {
    "http": os.environ.get("HTTP_PROXY", PROXY),
    "https": os.environ.get("HTTPS_PROXY", PROXY),
}

def gvm_headers(operation: str, resource: dict) -> dict:
    """Build GVM governance headers."""
    import json, uuid
    return {
        "X-GVM-Agent-Id": AGENT_ID,
        "X-GVM-Trace-Id": TRACE_ID,
        "X-GVM-Event-Id": str(uuid.uuid4()),
        "X-GVM-Operation": operation,
        "X-GVM-Resource": json.dumps(resource),
        "X-GVM-Target-Host": "api.bank.com",
    }

def step(n, desc):
    print(f"\n  [{n}/4] {desc}")

# ── Step 1: Look up refund (legitimate) ──
step(1, "Looking up refund REF-2024-001...")
r = session.get(
    "http://api.bank.com/refunds/REF-2024-001",
    headers=gvm_headers("gvm.payment.refund_lookup", {
        "service": "bank", "tier": "Internal", "sensitivity": "Medium",
    }),
)
print(f"        Status: {r.status_code}")

# ── Step 2: Send customer notification (monitored) ──
step(2, "Sending customer notification email...")
r = session.post(
    "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
    headers={
        **gvm_headers("gvm.messaging.send", {
            "service": "gmail", "tier": "CustomerFacing", "sensitivity": "Medium",
        }),
        "X-GVM-Target-Host": "gmail.googleapis.com",
    },
    json={"to": "customer@example.com", "subject": "Refund processed"},
)
print(f"        Status: {r.status_code}")

# ── Step 3: ROGUE — Wire $50K to offshore account ──
step(3, "Attempting $50,000 wire transfer to offshore account...")
r = session.post(
    "http://api.bank.com/transfer/wire",
    headers=gvm_headers("gvm.payment.charge", {
        "service": "bank", "tier": "External", "sensitivity": "Critical",
    }),
    json={"amount": 50000, "to_account": "offshore-9999", "memo": "Emergency override"},
)
if r.status_code == 403:
    print(f"        BLOCKED by GVM! Status: {r.status_code}")
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"        Reason: {body.get('error', 'Policy violation')}")
else:
    print(f"        Status: {r.status_code}")

# ── Step 4: ROGUE — Delete audit trail ──
step(4, "Attempting to delete audit log...")
r = session.delete(
    "http://api.bank.com/audit-log/2024-03",
    headers=gvm_headers("gvm.storage.delete", {
        "service": "bank", "tier": "Internal", "sensitivity": "Critical",
    }),
)
if r.status_code == 403:
    print(f"        BLOCKED by GVM! Status: {r.status_code}")
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"        Reason: {body.get('error', 'Policy violation')}")
else:
    print(f"        Status: {r.status_code}")

print("\n  Agent completed.")
