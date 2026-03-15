"""
Analemma-GVM — Checkpoint/Rollback Demo with Token Savings Analysis

Compares two modes of handling a denied operation:

  Level 0 (No SDK):  No rollback. Agent must restart entire workflow from scratch.
  Level 2 (SDK):     Auto-checkpoint before IC-2+ ops. On deny, roll back to last
                     checkpoint and resume from there.

Token Savings:
  Quantifies the cost difference between restarting from scratch (Level 0)
  vs. resuming from a checkpoint (Level 2) when a critical action is blocked.

Usage:
  1. Start proxy:  cargo run  (from project root)
  2. Run demo:     python -m gvm.rollback_demo
"""

import io
import json
import os
import sys
import time

# Force UTF-8 output on Windows
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm import GVMAgent, ic, Resource
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError
from gvm import mock_server

# ─── ANSI Colors ───

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ─── Token cost model ───
# Simulated token costs per operation (based on typical LLM agent workflows)

TOKEN_COSTS = {
    "system_prompt":     350,   # Initial system prompt + tool definitions
    "read_inbox":        120,   # Tool call + response parsing
    "analyze_emails":    280,   # LLM reasoning over email contents
    "send_email":        200,   # Compose + tool call + confirmation
    "wire_transfer":     180,   # Tool call (denied)
    "error_handling":     60,   # LLM processing denial error
    "alternative_path":  150,   # LLM choosing alternative action
}


# ─── Agent Definitions ───

class Level0Agent(GVMAgent):
    """No SDK rollback. Operations go through proxy but no checkpoints."""

    @ic(
        operation="gvm.messaging.read",
        resource=Resource(service="gmail", tier="external", sensitivity="low"),
    )
    def read_inbox(self) -> dict:
        session = self.create_session()
        resp = session.get("http://gmail.googleapis.com/gmail/v1/users/me/messages")
        resp.raise_for_status()
        return resp.json()

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="gmail", tier="customer-facing", sensitivity="medium"),
    )
    def send_email(self, to: str, subject: str, body: str) -> dict:
        session = self.create_session()
        resp = session.post(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            json={"to": to, "subject": subject, "body": body},
        )
        resp.raise_for_status()
        return resp.json()

    @ic(
        operation="gvm.payment.charge",
        resource=Resource(service="bank", tier="external", sensitivity="critical"),
    )
    def wire_transfer(self, to_account: str, amount: float) -> dict:
        session = self.create_session()
        resp = session.post(
            "http://api.bank.com/transfer/123",
            json={"to": to_account, "amount": amount},
        )
        resp.raise_for_status()
        return resp.json()


class Level2Agent(GVMAgent):
    """SDK with auto-checkpoint. Rollback on deny, resume from checkpoint."""
    auto_checkpoint = "ic2+"

    @ic(
        operation="gvm.messaging.read",
        resource=Resource(service="gmail", tier="external", sensitivity="low"),
    )
    def read_inbox(self) -> dict:
        session = self.create_session()
        resp = session.get("http://gmail.googleapis.com/gmail/v1/users/me/messages")
        resp.raise_for_status()
        return resp.json()

    @ic(
        operation="gvm.messaging.send",
        resource=Resource(service="gmail", tier="customer-facing", sensitivity="medium"),
    )
    def send_email(self, to: str, subject: str, body: str) -> dict:
        session = self.create_session()
        resp = session.post(
            "http://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            json={"to": to, "subject": subject, "body": body},
        )
        resp.raise_for_status()
        return resp.json()

    @ic(
        operation="gvm.payment.charge",
        resource=Resource(service="bank", tier="external", sensitivity="critical"),
    )
    def wire_transfer(self, to_account: str, amount: float) -> dict:
        session = self.create_session()
        resp = session.post(
            "http://api.bank.com/transfer/123",
            json={"to": to_account, "amount": amount},
        )
        resp.raise_for_status()
        return resp.json()


def _check_response(resp):
    """Check proxy response and raise appropriate GVM error."""
    if resp.status_code == 200:
        return
    try:
        error_body = resp.json()
    except Exception:
        raise GVMDeniedError(reason=f"HTTP {resp.status_code}", status_code=resp.status_code)
    from gvm.errors import GVMError
    raise GVMError.from_response(error_body, status_code=resp.status_code)


# ─── Demo Runner ───

def run_level0(proxy_url: str) -> dict:
    """Run Level 0 (no SDK rollback) workflow. Returns token accounting."""
    agent = Level0Agent(
        agent_id="level0-demo",
        tenant_id="acme",
        proxy_url=proxy_url,
        auto_checkpoint=None,  # Explicitly disable checkpoints
    )

    tokens_used = 0
    steps_completed = []

    print(f"  {BOLD}[Level 0] No SDK Rollback{RESET}")
    print(f"  {DIM}auto_checkpoint = None (no checkpoints){RESET}")
    print()

    # Step 1: Read inbox
    print(f"    [1] read_inbox()", end="")
    t0 = time.time()
    try:
        result = agent.read_inbox()
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["system_prompt"] + TOKEN_COSTS["read_inbox"]
        steps_completed.append("read_inbox")
        print(f" {GREEN}Allow{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['system_prompt'] + TOKEN_COSTS['read_inbox']} tokens")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

    # Step 2: Analyze emails (simulated LLM reasoning)
    tokens_used += TOKEN_COSTS["analyze_emails"]
    steps_completed.append("analyze_emails")
    print(f"    [2] analyze_emails() {CYAN}LLM reasoning{RESET} +{TOKEN_COSTS['analyze_emails']} tokens")

    # Step 3: Send email
    print(f"    [3] send_email()", end="")
    t0 = time.time()
    try:
        result = agent.send_email(
            to="cfo@acme.com",
            subject="Inbox Summary",
            body="3 items require attention.",
        )
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["send_email"]
        steps_completed.append("send_email")
        print(f" {YELLOW}Delay 300ms{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['send_email']} tokens")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

    # Step 4: Wire transfer (DENIED)
    print(f"    [4] wire_transfer()", end="")
    t0 = time.time()
    denied = False
    try:
        agent.wire_transfer(to_account="attacker-9999", amount=15000.00)
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        print(f" {RED}Unexpected allow{RESET} ({elapsed:.0f}ms)")
    except (GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError) as e:
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        denied = True
        print(f" {RED}DENIED{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['wire_transfer']} tokens")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        denied = True
        print(f" {RED}Blocked: {e}{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['wire_transfer']} tokens")

    if denied:
        # Level 0: No checkpoint exists. Must restart entire workflow.
        print()
        print(f"    {RED}No checkpoint available. Must restart from scratch.{RESET}")
        print(f"    {DIM}Re-running entire workflow...{RESET}")
        print()

        restart_tokens = 0

        # Re-run step 1
        print(f"    [1'] read_inbox()", end="")
        t0 = time.time()
        try:
            result = agent.read_inbox()
            elapsed = (time.time() - t0) * 1000
            restart_tokens += TOKEN_COSTS["system_prompt"] + TOKEN_COSTS["read_inbox"]
            print(f" {GREEN}Allow{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['system_prompt'] + TOKEN_COSTS['read_inbox']} tokens")
        except Exception as e:
            elapsed = (time.time() - t0) * 1000
            print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

        # Re-run step 2 (LLM reasoning)
        restart_tokens += TOKEN_COSTS["analyze_emails"]
        print(f"    [2'] analyze_emails() {CYAN}LLM reasoning{RESET} +{TOKEN_COSTS['analyze_emails']} tokens")

        # Re-run step 3
        print(f"    [3'] send_email()", end="")
        t0 = time.time()
        try:
            result = agent.send_email(
                to="cfo@acme.com",
                subject="Inbox Summary",
                body="3 items require attention.",
            )
            elapsed = (time.time() - t0) * 1000
            restart_tokens += TOKEN_COSTS["send_email"]
            print(f" {YELLOW}Delay 300ms{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['send_email']} tokens")
        except Exception as e:
            elapsed = (time.time() - t0) * 1000
            print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

        # Step 4': Choose alternative (no wire transfer)
        restart_tokens += TOKEN_COSTS["error_handling"] + TOKEN_COSTS["alternative_path"]
        print(f"    [4'] alternative_action() {CYAN}LLM re-plans{RESET} +{TOKEN_COSTS['error_handling'] + TOKEN_COSTS['alternative_path']} tokens")

        tokens_used += restart_tokens

    print()
    first_run_tokens = (
        TOKEN_COSTS["system_prompt"] + TOKEN_COSTS["read_inbox"]
        + TOKEN_COSTS["analyze_emails"]
        + TOKEN_COSTS["send_email"]
        + TOKEN_COSTS["wire_transfer"]
    )
    return {
        "total_tokens": tokens_used,
        "first_run_tokens": first_run_tokens,
        "restart_tokens": tokens_used - first_run_tokens,
        "steps": steps_completed,
        "had_restart": denied,
    }


def run_level2(proxy_url: str) -> dict:
    """Run Level 2 (SDK with rollback) workflow. Returns token accounting."""
    agent = Level2Agent(
        agent_id="level2-demo",
        tenant_id="acme",
        proxy_url=proxy_url,
    )

    tokens_used = 0
    steps_completed = []
    checkpoints_saved = []

    print(f"  {BOLD}[Level 2] SDK with Auto-Checkpoint + Rollback{RESET}")
    print(f"  {DIM}auto_checkpoint = \"ic2+\" (checkpoint before IC-2, IC-3){RESET}")
    print()

    # Step 1: Read inbox (IC-1, no checkpoint)
    print(f"    [1] read_inbox()", end="")
    t0 = time.time()
    try:
        result = agent.read_inbox()
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["system_prompt"] + TOKEN_COSTS["read_inbox"]
        steps_completed.append("read_inbox")
        print(f" {GREEN}Allow{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['system_prompt'] + TOKEN_COSTS['read_inbox']} tokens")
        print(f"         {DIM}IC-1: no checkpoint needed{RESET}")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

    # Step 2: Analyze emails (simulated LLM reasoning)
    tokens_used += TOKEN_COSTS["analyze_emails"]
    steps_completed.append("analyze_emails")
    print(f"    [2] analyze_emails() {CYAN}LLM reasoning{RESET} +{TOKEN_COSTS['analyze_emails']} tokens")

    # Step 3: Send email (IC-2, auto-checkpoint saved before execution)
    print(f"    [3] send_email()", end="")
    t0 = time.time()
    try:
        result = agent.send_email(
            to="cfo@acme.com",
            subject="Inbox Summary",
            body="3 items require attention.",
        )
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["send_email"]
        steps_completed.append("send_email")
        checkpoints_saved.append(("before send_email", "IC-2"))
        print(f" {YELLOW}Delay 300ms{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['send_email']} tokens")
        print(f"         {DIM}IC-2: checkpoint #0 saved before execution{RESET}")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        print(f" {RED}Error: {e}{RESET} ({elapsed:.0f}ms)")

    # Step 4: Wire transfer (IC-3, checkpoint saved, then DENIED + ROLLBACK)
    print(f"    [4] wire_transfer()", end="")
    t0 = time.time()
    rolled_back = False
    try:
        agent.wire_transfer(to_account="attacker-9999", amount=15000.00)
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        print(f" {RED}Unexpected allow{RESET} ({elapsed:.0f}ms)")
    except GVMRollbackError as e:
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        rolled_back = True
        print(f" {RED}DENIED + ROLLED BACK{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['wire_transfer']} tokens")
        print(f"         {DIM}IC-3: checkpoint #1 saved, then denied{RESET}")
        print(f"         {DIM}State restored to checkpoint #{e.rolled_back_to}{RESET}")
    except (GVMDeniedError, GVMApprovalRequiredError) as e:
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        rolled_back = True
        print(f" {RED}DENIED{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['wire_transfer']} tokens")
        print(f"         {DIM}IC-3: denied (rollback attempted){RESET}")
    except Exception as e:
        elapsed = (time.time() - t0) * 1000
        tokens_used += TOKEN_COSTS["wire_transfer"]
        rolled_back = True
        print(f" {RED}Blocked: {e}{RESET} ({elapsed:.0f}ms) +{TOKEN_COSTS['wire_transfer']} tokens")

    if rolled_back:
        # Level 2: Checkpoint exists. Resume from last approved state.
        print()
        print(f"    {GREEN}Checkpoint available. Resuming from last approved state.{RESET}")
        print(f"    {DIM}No restart needed: LLM context preserved, state intact.{RESET}")
        print()

        # Only need error handling + alternative path tokens
        resume_tokens = TOKEN_COSTS["error_handling"] + TOKEN_COSTS["alternative_path"]
        tokens_used += resume_tokens
        print(f"    [5] alternative_action() {CYAN}LLM re-plans from context{RESET} +{resume_tokens} tokens")
        print(f"         {DIM}LLM receives structured rollback error, chooses alternative{RESET}")

    print()
    first_run_tokens = (
        TOKEN_COSTS["system_prompt"] + TOKEN_COSTS["read_inbox"]
        + TOKEN_COSTS["analyze_emails"]
        + TOKEN_COSTS["send_email"]
        + TOKEN_COSTS["wire_transfer"]
    )
    return {
        "total_tokens": tokens_used,
        "first_run_tokens": first_run_tokens,
        "resume_tokens": tokens_used - first_run_tokens if rolled_back else 0,
        "steps": steps_completed,
        "checkpoints": checkpoints_saved,
        "had_rollback": rolled_back,
    }


def run_demo():
    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    mock_port = int(os.environ.get("GVM_MOCK_PORT", "9090"))

    print()
    print(f"{BOLD}{'=' * 66}{RESET}")
    print(f"{BOLD}  Analemma-GVM — Checkpoint/Rollback Demo{RESET}")
    print(f"{BOLD}  Token Savings: Level 0 (No SDK) vs Level 2 (SDK Rollback){RESET}")
    print(f"{BOLD}{'=' * 66}{RESET}")
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
        print(f"\n  {RED}Error: GVM proxy is not running.{RESET}")
        print(f"  {DIM}Start it with: cargo run  (from project root){RESET}\n")
        sys.exit(1)

    print()

    # ── Scenario ──
    print(f"  {BOLD}Scenario:{RESET}")
    print(f"  {DIM}An LLM agent performs a 4-step workflow:{RESET}")
    print(f"  {DIM}  1. read_inbox()       (IC-1: Allow){RESET}")
    print(f"  {DIM}  2. analyze_emails()   (LLM reasoning){RESET}")
    print(f"  {DIM}  3. send_email()       (IC-2: Delay 300ms){RESET}")
    print(f"  {DIM}  4. wire_transfer()    (IC-3: Deny by SRR){RESET}")
    print(f"  {DIM}Step 4 is denied. What happens next depends on rollback support.{RESET}")
    print()
    print(f"{BOLD}{'-' * 66}{RESET}")
    print()

    # ── Level 0 ──
    level0_result = run_level0(proxy_url)

    print(f"{BOLD}{'-' * 66}{RESET}")
    print()

    # ── Level 2 ──
    level2_result = run_level2(proxy_url)

    print(f"{BOLD}{'-' * 66}{RESET}")
    print()

    # ── Token Savings Comparison ──
    print(f"  {BOLD}Token Savings Analysis{RESET}")
    print(f"  {'=' * 60}")
    print()

    l0_total = level0_result["total_tokens"]
    l2_total = level2_result["total_tokens"]
    saved = l0_total - l2_total
    pct = (saved / l0_total * 100) if l0_total > 0 else 0

    # Breakdown table
    print(f"  {'Phase':<35} {'Level 0':>10} {'Level 2':>10}")
    print(f"  {'-' * 35} {'-' * 10} {'-' * 10}")

    first_run = level0_result["first_run_tokens"]
    print(f"  {'Initial workflow (steps 1-4)':<35} {first_run:>10} {first_run:>10}")

    l0_restart = level0_result.get("restart_tokens", 0)
    l2_resume = level2_result.get("resume_tokens", 0)

    if level0_result["had_restart"]:
        print(f"  {'Recovery: full restart':<35} {RED}{'+' + str(l0_restart):>10}{RESET} {'---':>10}")
    if level2_result["had_rollback"]:
        print(f"  {'Recovery: resume from checkpoint':<35} {'---':>10} {GREEN}{'+' + str(l2_resume):>10}{RESET}")

    print(f"  {'-' * 35} {'-' * 10} {'-' * 10}")
    print(f"  {'TOTAL':<35} {l0_total:>10} {GREEN}{l2_total:>10}{RESET}")
    print()

    print(f"  {BOLD}Tokens saved by rollback: {GREEN}{saved} tokens ({pct:.1f}% reduction){RESET}")
    print()

    # Cost estimation (GPT-4 pricing as reference)
    cost_per_1k = 0.03  # $0.03 per 1K tokens (input, GPT-4 class)
    l0_cost = l0_total / 1000 * cost_per_1k
    l2_cost = l2_total / 1000 * cost_per_1k
    cost_saved = l0_cost - l2_cost

    print(f"  {DIM}Estimated cost (at $0.03/1K tokens):{RESET}")
    print(f"  {DIM}  Level 0: ${l0_cost:.4f}{RESET}")
    print(f"  {DIM}  Level 2: ${l2_cost:.4f}{RESET}")
    print(f"  {DIM}  Saved:   ${cost_saved:.4f} per blocked action{RESET}")
    print()

    # Scaling projection
    print(f"  {BOLD}Scaling Impact{RESET}")
    print(f"  {DIM}At 1,000 denied actions/day:{RESET}")
    print(f"  {DIM}  Level 0: {l0_total * 1000:>12,} tokens/day (${l0_cost * 1000:.2f}/day){RESET}")
    print(f"  {DIM}  Level 2: {l2_total * 1000:>12,} tokens/day (${l2_cost * 1000:.2f}/day){RESET}")
    print(f"  {DIM}  Saved:   {saved * 1000:>12,} tokens/day (${cost_saved * 1000:.2f}/day){RESET}")
    print()

    # Architecture comparison
    print(f"  {BOLD}Architecture Comparison{RESET}")
    print(f"  {'=' * 60}")
    print()
    print(f"  {'Feature':<30} {'Level 0':>14} {'Level 2':>14}")
    print(f"  {'-' * 30} {'-' * 14} {'-' * 14}")
    print(f"  {'SDK required':<30} {'No':>14} {'Yes (@ic)':>14}")
    print(f"  {'Proxy enforcement':<30} {'Yes':>14} {'Yes':>14}")
    print(f"  {'Auto-checkpoint':<30} {RED}{'No':>14}{RESET} {GREEN}{'IC-2+ ops':>14}{RESET}")
    print(f"  {'State rollback':<30} {RED}{'No':>14}{RESET} {GREEN}{'Automatic':>14}{RESET}")
    print(f"  {'Recovery on deny':<30} {RED}{'Full restart':>14}{RESET} {GREEN}{'Resume':>14}{RESET}")
    print(f"  {'LLM context preserved':<30} {RED}{'No':>14}{RESET} {GREEN}{'Yes':>14}{RESET}")
    print(f"  {'Token overhead on deny':<30} {RED}{f'{l0_restart} tokens':>14}{RESET} {GREEN}{f'{l2_resume} tokens':>14}{RESET}")
    print()

    print(f"{BOLD}{'=' * 66}{RESET}")
    print(f"{BOLD}  Key Insight{RESET}")
    print(f"{'=' * 66}")
    print(f"  Level 0 provides governance enforcement without any SDK dependency.")
    print(f"  Level 2 adds @ic decorator (one line per method) to enable:")
    print(f"    - Automatic state checkpointing before risky operations")
    print(f"    - Merkle-verified rollback on deny (encrypted, tamper-proof)")
    print(f"    - {GREEN}{pct:.0f}% token savings{RESET} per denied action")
    print(f"    - LLM receives structured error with rollback context")
    print()
    print(f"  {BOLD}Governance is structural. Rollback is the SDK's value-add.{RESET}")
    print(f"{'=' * 66}")
    print()


if __name__ == "__main__":
    run_demo()
