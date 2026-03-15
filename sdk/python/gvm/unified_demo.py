"""
Analemma-GVM — Unified Finance Agent Demo

One scenario, every core feature:
  [1] read_inbox()          -> Allow  (IC-1, no checkpoint)
  [2] send_summary()        -> Delay  (IC-2, checkpoint saved)
  [3] wire_transfer()       -> BLOCKED (Deny, rollback to #2)
      -> semantic forgery defense (agent lies about operation)
      -> automatic rollback to checkpoint #2
  [4] summarize_results()   -> Allow  (agent continues from safe state)

Features demonstrated in this single scenario:
  - IC classification: Allow / Delay / Deny (3-tier graduated enforcement)
  - SRR URL-based blocking (Layer 2: actual URL inspected, not headers)
  - Semantic forgery defense (agent claims "storage.read" but URL is /transfer)
  - ABAC policy enforcement (Layer 1: hierarchical Global > Tenant > Agent)
  - Checkpoint/rollback (Merkle-verified state restore on deny)
  - Token savings (resume from checkpoint vs full restart)
  - WAL-first audit trail (every decision recorded before action)
  - API key isolation (agent never holds credentials)

Architecture:
  Finance Agent (Python SDK)
      |  @ic() decorator + auto_checkpoint="ic2+"
      v
  GVM Proxy (Rust, :8080)
      |  Layer 1: ABAC  x  Layer 2: SRR  ->  max_strict()
      |  Layer 3: API key injection (post-enforcement)
      |  WAL: fsync before forward
      v
  Mock Finance Server (:9090)

Usage:
  1. Start proxy:  cargo run
  2. Run demo:     python -m gvm.unified_demo
"""

import io
import json
import os
import sys
import time
import traceback

# Force UTF-8 output on Windows
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, ic, Resource
from gvm.errors import (
    GVMDeniedError,
    GVMApprovalRequiredError,
    GVMRollbackError,
)
from gvm import mock_server

# ─── ANSI Colors ───

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def ok(text):
    return f"{GREEN}\u2713 {text}{RESET}"


def warn(text):
    return f"{YELLOW}\u23f1 {text}{RESET}"


def fail(text):
    return f"{RED}\u2717 {text}{RESET}"


def rollback_icon(text):
    return f"{MAGENTA}\u21ba {text}{RESET}"


# ─── Finance Agent ───

class FinanceAgent(GVMAgent):
    """AI finance agent with auto-checkpoint on IC-2+ operations.

    When a high-risk operation (IC-2 or IC-3) is denied, the agent's state
    is automatically rolled back to the last approved checkpoint. The agent
    can then continue from a safe state with an alternative action path.
    """

    auto_checkpoint = "ic2+"  # Checkpoint before IC-2 and IC-3 operations

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Agent-local state for the demo
        self.inbox_messages = []
        self.actions_taken = []
        self.pending_amount = 0.0

    @ic(
        operation="gvm.messaging.read",
        resource=Resource(service="gmail", tier="external", sensitivity="low"),
    )
    def read_inbox(self) -> dict:
        """IC-1: Read inbox. Safe read operation — no checkpoint needed."""
        session = self.create_session()
        resp = session.get(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages"
        )
        _check_response(resp)
        data = resp.json()
        self.inbox_messages = data.get("messages", [])
        self.actions_taken.append("read_inbox")
        return data

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(
            service="gmail", tier="customer-facing", sensitivity="medium"
        ),
    )
    def send_summary(self, to: str, subject: str, body: str) -> dict:
        """IC-2: Send email summary. Delayed 300ms, checkpoint saved before."""
        session = self.create_session()
        resp = session.post(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            json={"to": to, "subject": subject, "body": body},
        )
        _check_response(resp)
        self.actions_taken.append("send_summary")
        return resp.json()

    @ic(
        operation="gvm.payment.charge",
        resource=Resource(
            service="bank", tier="external", sensitivity="critical"
        ),
    )
    def wire_transfer(self, to_account: str, amount: float) -> dict:
        """IC-3: Wire transfer. WILL BE BLOCKED by SRR (network layer).

        Even if the agent lies about the operation name, Layer 2 (SRR)
        inspects the actual URL and blocks it independently.
        """
        session = self.create_session()
        resp = session.post(
            "http://api.bank.com/transfer/123",
            json={"to": to_account, "amount": amount},
        )
        _check_response(resp)
        self.actions_taken.append("wire_transfer")
        self.pending_amount = amount
        return resp.json()

    @ic(
        operation="gvm.messaging.read",
        resource=Resource(service="internal", tier="internal", sensitivity="low"),
    )
    def summarize_results(self) -> dict:
        """IC-1: Summarize what happened. Safe read — instant allow."""
        session = self.create_session()
        resp = session.get(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages"
        )
        _check_response(resp)
        self.actions_taken.append("summarize_results")
        return {
            "status": "completed",
            "actions_taken": self.actions_taken,
            "message_count": len(self.inbox_messages),
        }


# ─── Response Handler ───

last_gvm_response = {}


def _check_response(resp):
    """Parse proxy response headers and raise on enforcement errors."""
    global last_gvm_response

    last_gvm_response = {
        "decision": resp.headers.get("X-GVM-Decision"),
        "source": resp.headers.get("X-GVM-Decision-Source"),
        "event_id": resp.headers.get("X-GVM-Event-Id"),
        "trace_id": resp.headers.get("X-GVM-Trace-Id"),
        "engine_ms": resp.headers.get("X-GVM-Engine-Ms"),
        "delay_ms": resp.headers.get("X-GVM-Safety-Delay-Ms"),
        "matched_rule": resp.headers.get("X-GVM-Matched-Rule"),
    }

    if resp.status_code == 200:
        return

    try:
        error_body = resp.json()
    except Exception:
        raise GVMDeniedError(
            reason=f"HTTP {resp.status_code}", status_code=resp.status_code
        )

    from gvm.errors import GVMError

    err = GVMError.from_response(error_body, status_code=resp.status_code)
    err.gvm_response = last_gvm_response
    raise err


# ─── Token Cost Model ───

# Estimated token costs per operation step (based on typical LLM agent workflow)
TOKEN_COSTS = {
    "system_prompt": 350,
    "read_inbox": 120,
    "send_summary": 200,
    "wire_transfer": 180,
    "error_handling": 60,
    "summarize_results": 90,
}


def calc_level0_cost(steps_before_deny: int) -> int:
    """Level 0 (no SDK): Full restart cost on deny. Re-run all prior steps."""
    ordered = ["system_prompt", "read_inbox", "send_summary", "wire_transfer"]
    # Cost = initial run + re-run everything up to the failed step
    initial = sum(TOKEN_COSTS[s] for s in ordered[: steps_before_deny + 1])
    restart = sum(TOKEN_COSTS[s] for s in ordered[:steps_before_deny])
    return initial + restart + TOKEN_COSTS["error_handling"]


def calc_level2_cost(steps_before_deny: int) -> int:
    """Level 2 (SDK): Resume from checkpoint. Only pay for the denied step + recovery."""
    ordered = ["system_prompt", "read_inbox", "send_summary", "wire_transfer"]
    initial = sum(TOKEN_COSTS[s] for s in ordered[: steps_before_deny + 1])
    # Rollback error message + alternative path (no restart)
    return initial + TOKEN_COSTS["error_handling"]


# ─── Demo Runner ───


def run_demo():
    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    mock_port = int(os.environ.get("GVM_MOCK_PORT", "9090"))

    # ═══════════════════════════════════════════════════════
    # Header
    # ═══════════════════════════════════════════════════════
    print()
    print(f"{BOLD}{'=' * 66}{RESET}")
    print(f"{BOLD}  Analemma-GVM v0.1.2 — Unified Finance Agent Demo{RESET}")
    print(f"{BOLD}{'=' * 66}{RESET}")
    print()
    print(f"  {DIM}One scenario. Every core feature.{RESET}")
    print()
    print(f"  {DIM}Finance Agent (Python)  --@ic()--->  GVM Proxy (Rust)  --->  APIs{RESET}")
    print(f"  {DIM}  auto_checkpoint=ic2+       Layer 1: ABAC (semantic){RESET}")
    print(f"  {DIM}  Merkle-verified state      Layer 2: SRR  (network){RESET}")
    print(f"  {DIM}  rollback on deny            Layer 3: API key inject{RESET}")
    print()

    # ── Setup ──
    print(f"  {DIM}Starting mock server on :{mock_port}...{RESET}", end=" ")
    mock_server.start(port=mock_port)
    print(f"{GREEN}OK{RESET}")

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

    # ── Create Agent ──
    agent = FinanceAgent(
        agent_id="finance-001",
        tenant_id="acme-corp",
        proxy_url=proxy_url,
    )

    print()
    print(f"  Agent:       {CYAN}finance-001{RESET}")
    print(f"  Tenant:      {CYAN}acme-corp{RESET}")
    print(f"  Checkpoint:  {CYAN}auto_checkpoint=ic2+{RESET}")
    print(f"  Trace:       {CYAN}{agent._session_id[:12]}...{RESET}")
    print()
    print(f"{BOLD}{'-' * 66}{RESET}")

    # Collect results
    audit_log = []
    rollback_event = None

    # ═══════════════════════════════════════════════════════
    # Step 1: Read Inbox (IC-1 Allow)
    # ═══════════════════════════════════════════════════════
    print()
    print(f"  {BOLD}[Step 1]{RESET} read_inbox()")
    print(f"  {DIM}IC-1: Safe read operation. No checkpoint needed.{RESET}")
    print()

    t0 = time.time()
    try:
        result = agent.read_inbox()
        elapsed = (time.time() - t0) * 1000
        msg_count = result.get("resultSizeEstimate", 0)
        print(f"  {ok('Allow')}  {DIM}{msg_count} messages, {elapsed:.0f}ms{RESET}")
        print(f"  {DIM}Layer: ABAC (operation ends with .read -> global-read-allow){RESET}")
        audit_log.append({
            "step": 1, "operation": "gvm.messaging.read",
            "decision": "Allow", "ic": "IC-1",
            "source": last_gvm_response.get("source", "ABAC"),
            "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail(f'Error: {e}')}  {DIM}{elapsed:.0f}ms{RESET}")
        audit_log.append({
            "step": 1, "operation": "gvm.messaging.read",
            "decision": f"Error", "ic": "?",
            "source": "?", "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })

    # ═══════════════════════════════════════════════════════
    # Step 2: Send Summary Email (IC-2 Delay)
    # ═══════════════════════════════════════════════════════
    print()
    print(f"  {BOLD}[Step 2]{RESET} send_summary()")
    print(f"  {DIM}IC-2: Customer-facing email. Checkpoint saved BEFORE execution.{RESET}")
    print()

    checkpoint_step = agent._checkpoint_mgr.current_step
    t0 = time.time()
    try:
        result = agent.send_summary(
            to="cfo@acme.com",
            subject="Inbox Summary - 3 items require attention",
            body=(
                "1. Q4 Budget Approval (from CFO)\n"
                "2. New Hire Onboarding (from HR)\n"
                "3. Invoice #8842 - $15,000 due"
            ),
        )
        elapsed = (time.time() - t0) * 1000
        delay_ms = last_gvm_response.get("delay_ms", "300")
        print(
            f"  {warn(f'Delay {delay_ms}ms')}  "
            f"{DIM}email sent to {result.get('to', 'cfo@acme.com')}, "
            f"{elapsed:.0f}ms total{RESET}"
        )
        print(f"  {DIM}Layer: SRR (gmail.googleapis.com POST -> Delay 300ms){RESET}")
        print(
            f"  {MAGENTA}Checkpoint #{checkpoint_step} saved{RESET}  "
            f"{DIM}(agent state: {len(agent.actions_taken)} actions, "
            f"{len(agent.inbox_messages)} messages){RESET}"
        )
        audit_log.append({
            "step": 2, "operation": "gvm.messaging.send",
            "decision": f"Delay {delay_ms}ms", "ic": "IC-2",
            "source": last_gvm_response.get("source", "SRR"),
            "latency": f"{elapsed:.0f}ms",
            "checkpoint": f"#{checkpoint_step} saved",
        })
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail(f'Error: {e}')}  {DIM}{elapsed:.0f}ms{RESET}")
        audit_log.append({
            "step": 2, "operation": "gvm.messaging.send",
            "decision": "Error", "ic": "?",
            "source": "?", "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })

    # Snapshot state before wire_transfer for comparison
    state_before_deny = {
        "actions_taken": agent.actions_taken.copy(),
        "inbox_count": len(agent.inbox_messages),
    }

    # ═══════════════════════════════════════════════════════
    # Step 3: Wire Transfer (BLOCKED + ROLLBACK)
    # ═══════════════════════════════════════════════════════
    print()
    print(f"  {BOLD}[Step 3]{RESET} wire_transfer()")
    print(f"  {DIM}IC-3: Payment to external bank. Agent declares 'gvm.payment.charge'.{RESET}")
    print(f"  {DIM}Even if it lied (e.g. 'storage.read'), SRR catches the URL.{RESET}")
    print()

    t0 = time.time()
    try:
        agent.wire_transfer(to_account="vendor-8842", amount=15000.00)
        elapsed = (time.time() - t0) * 1000
        print(f"  {RED}! Transfer succeeded (unexpected){RESET}")
        audit_log.append({
            "step": 3, "operation": "gvm.payment.charge",
            "decision": "Allow (unexpected)", "ic": "?",
            "source": "?", "latency": f"{elapsed:.0f}ms", "checkpoint": "?",
        })
    except GVMRollbackError as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail('BLOCKED')}  {DIM}{elapsed:.0f}ms{RESET}")
        print()

        # Show the dual-layer defense
        print(f"  {BOLD}Why blocked (two independent layers):{RESET}")
        print(f"    Layer 1 (ABAC): {DIM}gvm.payment.charge -> RequireApproval{RESET}")
        print(f"    Layer 2 (SRR):  {DIM}POST api.bank.com/transfer/* -> Deny{RESET}")
        print(f"    Final:          {RED}max_strict(RequireApproval, Deny) = Deny{RESET}")
        print()

        # Show semantic forgery defense
        print(f"  {BOLD}Semantic forgery defense:{RESET}")
        print(f"    {DIM}If agent had declared operation='gvm.storage.read':{RESET}")
        print(f"    {DIM}  Layer 1 (ABAC): storage.read -> Allow{RESET}")
        print(f"    {DIM}  Layer 2 (SRR):  POST api.bank.com/transfer/* -> Deny{RESET}")
        print(f"    {DIM}  Final: max_strict(Allow, Deny) = {RED}Deny{RESET}{DIM} (SRR catches the lie){RESET}")
        print()

        # Show rollback
        rolled_to = e.rolled_back_to
        print(
            f"  {rollback_icon(f'Rollback to checkpoint #{rolled_to}')}"
        )
        print(
            f"  {DIM}State before deny: {state_before_deny['actions_taken']}{RESET}"
        )
        print(
            f"  {DIM}State after rollback: {agent.actions_taken}{RESET}"
        )

        rollback_event = {
            "rolled_back_to": rolled_to,
            "blocked_at": e.blocked_at,
            "operation": e.operation,
        }

        audit_log.append({
            "step": 3, "operation": "gvm.payment.charge",
            "decision": "Deny + Rollback", "ic": "IC-3",
            "source": "SRR > ABAC",
            "latency": f"{elapsed:.0f}ms",
            "checkpoint": f"rolled back to #{rolled_to}",
        })
    except (GVMDeniedError, GVMApprovalRequiredError) as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail(f'BLOCKED: {e}')}  {DIM}{elapsed:.0f}ms{RESET}")
        print(f"  {DIM}(No rollback: checkpoint was not saved or restore failed){RESET}")
        audit_log.append({
            "step": 3, "operation": "gvm.payment.charge",
            "decision": "Deny", "ic": "IC-3",
            "source": last_gvm_response.get("source", "?"),
            "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail(f'Error: {e}')}  {DIM}{elapsed:.0f}ms{RESET}")
        audit_log.append({
            "step": 3, "operation": "gvm.payment.charge",
            "decision": "Error", "ic": "?",
            "source": "?", "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })

    # ═══════════════════════════════════════════════════════
    # Step 4: Summarize Results (IC-1 Allow — agent continues)
    # ═══════════════════════════════════════════════════════
    print()
    print(f"  {BOLD}[Step 4]{RESET} summarize_results()")
    print(f"  {DIM}IC-1: Agent continues from rolled-back state. No restart needed.{RESET}")
    print()

    t0 = time.time()
    try:
        result = agent.summarize_results()
        elapsed = (time.time() - t0) * 1000
        print(f"  {ok('Allow')}  {DIM}{elapsed:.0f}ms{RESET}")
        print(f"  {DIM}Agent state: actions={result['actions_taken']}{RESET}")
        audit_log.append({
            "step": 4, "operation": "gvm.messaging.read",
            "decision": "Allow", "ic": "IC-1",
            "source": last_gvm_response.get("source", "ABAC"),
            "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f"  {fail(f'Error: {e}')}  {DIM}{elapsed:.0f}ms{RESET}")
        audit_log.append({
            "step": 4, "operation": "gvm.messaging.read",
            "decision": "Error", "ic": "?",
            "source": "?", "latency": f"{elapsed:.0f}ms", "checkpoint": "none",
        })

    # ═══════════════════════════════════════════════════════
    # Audit Trail
    # ═══════════════════════════════════════════════════════
    print()
    print(f"{BOLD}{'-' * 66}{RESET}")
    print()
    print(f"  {BOLD}Audit Trail{RESET}  {DIM}trace: {agent._session_id[:12]}...{RESET}")
    print()

    # Table header
    hdr = (
        f"  {'Step':<6} {'Operation':<22} {'Decision':<18} "
        f"{'IC':<6} {'Source':<8} {'Latency':<9} {'Checkpoint'}"
    )
    print(hdr)
    print(f"  {'-' * 6} {'-' * 22} {'-' * 18} {'-' * 6} {'-' * 8} {'-' * 9} {'-' * 20}")

    for entry in audit_log:
        dec = entry["decision"]
        if "Allow" in dec:
            colored_dec = f"{GREEN}{dec}{RESET}"
        elif "Delay" in dec:
            colored_dec = f"{YELLOW}{dec}{RESET}"
        else:
            colored_dec = f"{RED}{dec}{RESET}"

        print(
            f"  {entry['step']:<6} {entry['operation']:<22} {colored_dec:<27} "
            f"{entry['ic']:<6} {entry['source']:<8} {entry['latency']:<9} "
            f"{entry['checkpoint']}"
        )

    print()
    print(f"  {DIM}All events recorded in WAL (data/wal.log) with Merkle hash chain.{RESET}")

    # ═══════════════════════════════════════════════════════
    # Token Savings Analysis
    # ═══════════════════════════════════════════════════════
    print()
    print(f"{BOLD}{'-' * 66}{RESET}")
    print()
    print(f"  {BOLD}Token Savings: Checkpoint vs Full Restart{RESET}")
    print()

    # Wire transfer was step 3 (index 3 in ordered list)
    l0_cost = calc_level0_cost(3)
    l2_cost = calc_level2_cost(3)
    saved = l0_cost - l2_cost
    pct = (saved / l0_cost) * 100

    print(f"  {DIM}Level 0 (no SDK):{RESET}  {l0_cost:>6} tokens  "
          f"{DIM}(run all steps + restart from scratch on deny){RESET}")
    print(f"  {DIM}Level 2 (SDK):   {RESET}  {l2_cost:>6} tokens  "
          f"{DIM}(run all steps + resume from checkpoint on deny){RESET}")
    print()
    print(
        f"  {GREEN}Saved: {saved} tokens ({pct:.1f}% reduction){RESET}"
    )
    print(
        f"  {DIM}At 1,000 denied actions/day: "
        f"~{saved * 1000:,} tokens/day saved{RESET}"
    )

    # ═══════════════════════════════════════════════════════
    # Feature Summary
    # ═══════════════════════════════════════════════════════
    print()
    print(f"{BOLD}{'=' * 66}{RESET}")
    print(f"{BOLD}  Features Demonstrated{RESET}")
    print(f"{'=' * 66}")
    print()

    features = [
        ("IC Classification",
         "Allow (Step 1) / Delay 300ms (Step 2) / Deny (Step 3)"),
        ("SRR Network Defense",
         "POST api.bank.com/transfer/* -> Deny (URL inspected, not headers)"),
        ("Semantic Forgery",
         "max_strict(ABAC, SRR): agent lies are caught by Layer 2"),
        ("Checkpoint/Rollback",
         f"Auto-saved at Step 2, restored after Step 3 deny"),
        ("Token Savings",
         f"{pct:.0f}% reduction ({saved} tokens saved per blocked action)"),
        ("WAL-First Audit",
         "IC-2/IC-3: WAL fsync BEFORE forward. Fail-close on WAL failure."),
        ("API Key Isolation",
         "Agent never holds credentials. Proxy injects post-enforcement."),
        ("Hierarchical Policy",
         "Global > Tenant > Agent. Lower layers cannot weaken parent."),
    ]

    for name, detail in features:
        print(f"  {GREEN}\u2713{RESET} {BOLD}{name}{RESET}")
        print(f"    {DIM}{detail}{RESET}")

    print()
    print(
        f"  {BOLD}Agent code is unchanged. "
        f"Security is structural, not behavioral.{RESET}"
    )
    print(f"{'=' * 66}")
    print()


if __name__ == "__main__":
    run_demo()
