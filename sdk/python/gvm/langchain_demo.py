"""
Analemma-GVM — LangChain + Gmail 30-Second Demo

Demonstrates AI agent governance enforcement in real-time:
  1. read_inbox()     → Allow (IC-1, instant)
  2. send_email()     → Delay 300ms (IC-2, customer-facing)
  3. wire_transfer()  → Deny (SRR network rule)
  4. delete_emails()  → Deny (ABAC policy)
  5. Audit trail      → trace_id-linked event summary

Architecture:
  LangChain Agent → GVM Proxy (:8080) → Mock Server (:9090)

Usage:
  1. Start proxy:  cargo run  (from project root)
  2. Run demo:     python -m gvm.langchain_demo
"""

import io
import json
import os
import sys
import time

# Force UTF-8 output on Windows (cp949/cp1252 cannot encode Unicode symbols)
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm.errors import GVMDeniedError, GVMApprovalRequiredError
from gvm.langchain_tools import GmailAgent
from gvm import mock_server

# ─── ANSI Colors ───

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def check_mark():
    return f"{GREEN}\u2713{RESET}"


def cross_mark():
    return f"{RED}\u2717{RESET}"


def clock_mark():
    return f"{YELLOW}\u23f1{RESET}"


# ─── Demo Runner ───

def run_demo():
    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    mock_port = int(os.environ.get("GVM_MOCK_PORT", "9090"))

    # ── Phase 1: Setup ──
    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Analemma-GVM v0.1.0 — LangChain + Gmail Demo{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}")
    print()
    print(f"  {DIM}Architecture:{RESET}")
    print(f"  {DIM}  LangChain Agent (Python){RESET}")
    print(f"  {DIM}      \u2193  requests.Session (proxy){RESET}")
    print(f"  {DIM}  GVM Proxy (Rust, :8080){RESET}")
    print(f"  {DIM}      \u2193  3-layer enforcement{RESET}")
    print(f"  {DIM}  Mock Gmail Server (:9090){RESET}")
    print()

    # Start mock server
    print(f"  {DIM}Starting mock server on :{mock_port}...{RESET}", end=" ")
    mock_server.start(port=mock_port)
    print(f"{GREEN}OK{RESET}")

    # Check proxy health
    print(f"  {DIM}Checking GVM proxy on {proxy_url}...{RESET}", end=" ")
    try:
        import requests
        resp = requests.get(f"{proxy_url}/gvm/health", timeout=2)
        if resp.status_code == 200:
            print(f"{GREEN}OK{RESET}")
        else:
            print(f"{YELLOW}HTTP {resp.status_code}{RESET}")
    except Exception:
        print(f"{RED}UNREACHABLE{RESET}")
        print()
        print(f"  {RED}Error: GVM proxy is not running.{RESET}")
        print(f"  {DIM}Start it with: cargo run  (from project root){RESET}")
        print()
        sys.exit(1)

    # Create agent
    agent = GmailAgent(
        agent_id="langchain-gmail-001",
        tenant_id="acme",
        proxy_url=proxy_url,
    )

    print()
    print(f"  Agent:   {CYAN}{agent._agent_id}{RESET}")
    print(f"  Tenant:  {CYAN}{agent._tenant_id}{RESET}")
    print(f"  Trace:   {CYAN}{agent._session_id[:12]}...{RESET}")
    print()
    print(f"{BOLD}{'-' * 62}{RESET}")
    print()

    # Collect results for audit summary
    audit_log = []

    # ── Phase 2: Execution ──

    # Step 1: Read Inbox (IC-1 Allow)
    print(f"  {BOLD}[Step 1]{RESET} read_inbox() \u2192 {DIM}Expected: Allow (IC-1){RESET}")
    t0 = time.time()
    try:
        result = agent.read_inbox()
        elapsed = (time.time() - t0) * 1000
        msg_count = result.get("resultSizeEstimate", 0)
        print(f"  {check_mark()} {GREEN}Allow{RESET} \u2014 {msg_count} messages ({elapsed:.0f}ms)")

        # Show inbox summary
        for m in result.get("messages", []):
            print(f"     {DIM}\u2022 {m['id']}{RESET}")

        audit_log.append(("gvm.messaging.read", "Allow", "IC-1", f"{elapsed:.0f}ms"))
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.messaging.read", f"Error: {e}", "?", f"{elapsed:.0f}ms"))
    print()

    # Step 2: Send Email (IC-2 Delay 300ms)
    print(f"  {BOLD}[Step 2]{RESET} send_email() \u2192 {DIM}Expected: Delay 300ms (IC-2){RESET}")
    t0 = time.time()
    try:
        result = agent.send_email(
            to="cfo@acme.com",
            subject="Inbox Summary — 3 items require attention",
            body="1. Q4 Budget Approval (from CFO)\n2. New Hire Onboarding (from HR)\n3. Invoice #8842 — $15,000 due",
        )
        elapsed = (time.time() - t0) * 1000
        print(f"  {clock_mark()} {YELLOW}Delay 300ms{RESET} \u2014 email sent to {result.get('to', '?')} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.messaging.send", "Delay 300ms", "IC-2", f"{elapsed:.0f}ms"))
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.messaging.send", f"Error: {e}", "?", f"{elapsed:.0f}ms"))
    print()

    # Step 3: Wire Transfer (SRR Deny)
    print(f"  {BOLD}[Step 3]{RESET} wire_transfer() \u2192 {DIM}Expected: Deny (SRR network rule){RESET}")
    t0 = time.time()
    try:
        agent.wire_transfer(to_account="attacker-9999", amount=15000.00)
        elapsed = (time.time() - t0) * 1000
        print(f"  {RED}! Transfer succeeded (unexpected){RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.payment.charge", "Allow (unexpected)", "?", f"{elapsed:.0f}ms"))
    except (GVMDeniedError, GVMApprovalRequiredError) as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Deny{RESET} \u2014 {e} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.payment.charge", "Deny (SRR)", "Blocked", f"{elapsed:.0f}ms"))
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Blocked: {e}{RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.payment.charge", "Deny", "Blocked", f"{elapsed:.0f}ms"))
    print()

    # Step 4: Delete Emails (ABAC Deny)
    print(f"  {BOLD}[Step 4]{RESET} delete_emails() \u2192 {DIM}Expected: Deny (ABAC policy){RESET}")
    t0 = time.time()
    try:
        agent.delete_emails(message_id="msg-001")
        elapsed = (time.time() - t0) * 1000
        print(f"  {RED}! Deletion succeeded (unexpected){RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.storage.delete", "Allow (unexpected)", "?", f"{elapsed:.0f}ms"))
    except (GVMDeniedError, GVMApprovalRequiredError) as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Deny{RESET} \u2014 {e} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.storage.delete", "Deny (ABAC)", "Blocked", f"{elapsed:.0f}ms"))
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {cross_mark()} {RED}Blocked: {e}{RESET} ({elapsed:.0f}ms)")
        audit_log.append(("gvm.storage.delete", "Deny", "Blocked", f"{elapsed:.0f}ms"))
    print()

    # ── Phase 3: Audit Summary ──
    print(f"{BOLD}{'-' * 62}{RESET}")
    print()
    print(f"  {BOLD}[Step 5] Audit Trail{RESET}  {DIM}(trace: {agent._session_id[:12]}...){RESET}")
    print()
    print(f"  {'Operation':<24} {'Decision':<18} {'IC':<10} {'Latency':<10}")
    print(f"  {'-' * 24} {'-' * 18} {'-' * 10} {'-' * 10}")

    for op, decision, ic_level, latency in audit_log:
        # Color the decision
        if "Allow" in decision and "unexpected" not in decision:
            colored = f"{GREEN}{decision}{RESET}"
        elif "Delay" in decision:
            colored = f"{YELLOW}{decision}{RESET}"
        else:
            colored = f"{RED}{decision}{RESET}"
        print(f"  {op:<24} {colored:<27} {ic_level:<10} {latency:<10}")

    print()
    print(f"  {DIM}All events recorded in immutable WAL (data/wal.log).{RESET}")
    print(f"  {DIM}Query with: gvm events trace --trace-id {agent._session_id[:12]}... (coming soon){RESET}")
    print()

    # ── Final Summary ──
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Summary{RESET}")
    print(f"{'=' * 62}")
    print(f"  IC-1 (Allow):       Read operations pass instantly")
    print(f"  IC-2 (Delay):       Customer-facing gets 300ms review window")
    print(f"  Deny (SRR):         Wire transfers blocked at network layer")
    print(f"  Deny (ABAC):        Critical deletions blocked by policy")
    print()
    print(f"  {BOLD}Agent code is unchanged. Security is structural, not behavioral.{RESET}")
    print(f"  {DIM}GVM enforces governance at the infrastructure level —{RESET}")
    print(f"  {DIM}agents cannot bypass, disable, or even see the enforcement.{RESET}")
    print(f"{'=' * 62}")
    print()


if __name__ == "__main__":
    run_demo()
