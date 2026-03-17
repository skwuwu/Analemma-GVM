"""
Analemma-GVM — Mock LLM Agent Demo

Demonstrates GVM governance with the REAL proxy but WITHOUT an LLM API key.
The LLM's tool-calling decisions are pre-scripted to simulate what Claude
would do when given the prompt: "Check inbox, send summary, transfer $50K,
delete message msg-001."

Requirements:
  - GVM proxy running (cargo run)
  - Python SDK installed (pip install -e sdk/python)
  - NO API key needed
  - NO LLM provider needed

The demo uses the same GmailAgent, mock backend server, and proxy pipeline
as the real LLM demo (llm_demo.py). The only difference is that tool call
decisions are pre-scripted instead of coming from Claude.

Usage:
  1. Start proxy:  cargo run
  2. Run demo:     python -m gvm.mock_demo
"""

import io
import os
import sys
import time

# Force UTF-8 output on Windows
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gvm.langchain_tools import GmailAgent
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError, GVMError
from gvm import mock_server
import gvm.langchain_tools as _lt

# ─── ANSI Colors ───

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

WIDTH = 72
BAR_WIDTH = 40


# ─── Tool Result Collector ───

class ToolResult:
    """Captures full GVM enforcement details for a single tool call."""

    def __init__(self, name, operation, target_host, method, args):
        self.name = name
        self.operation = operation
        self.target_host = target_host
        self.method = method
        self.args = args
        self.decision = None
        self.layer = None
        self.engine_ms = 0.0
        self.safety_ms = 0.0
        self.upstream_ms = 0.0
        self.total_ms = 0.0
        self.event_id = None
        self.trace_id = None
        self.reason = None
        self.result_text = None


def _run_tool(name, operation, target_host, method, args, fn, results_list):
    """Execute a tool function through the real GVM proxy and capture enforcement details."""
    tr = ToolResult(name, operation, target_host, method, args)

    t0 = time.time()
    try:
        result = fn()
        tr.total_ms = (time.time() - t0) * 1000
        tr.result_text = str(result)[:100] if result else "OK"
    except (GVMDeniedError, GVMApprovalRequiredError, GVMRollbackError, GVMError) as e:
        tr.total_ms = (time.time() - t0) * 1000
        tr.event_id = getattr(e, "event_id", None)
        tr.reason = str(e)
        tr.result_text = tr.reason

    # Read real enforcement details from GVM proxy response headers
    gvm = _lt.last_gvm_response

    raw_decision = gvm.get("decision") or ""
    if raw_decision.startswith("Delay"):
        tr.decision = raw_decision
    elif raw_decision == "Allow":
        tr.decision = "Allow"
    elif raw_decision.startswith("Deny"):
        tr.decision = "Deny"
    elif raw_decision.startswith("RequireApproval"):
        tr.decision = "RequireApproval"
    else:
        tr.decision = tr.decision or "Unknown"

    tr.layer = gvm.get("decision_source") or tr.layer

    try:
        tr.engine_ms = float(gvm.get("engine_ms") or 0)
    except (ValueError, TypeError):
        tr.engine_ms = 0.0
    try:
        tr.safety_ms = float(gvm.get("safety_delay_ms") or 0)
    except (ValueError, TypeError):
        tr.safety_ms = 0.0

    tr.event_id = gvm.get("event_id") or tr.event_id
    tr.trace_id = gvm.get("trace_id") or tr.trace_id

    matched_rule = gvm.get("matched_rule")
    if matched_rule and not tr.reason:
        tr.reason = f"rule: {matched_rule}"

    tr.upstream_ms = max(0, tr.total_ms - tr.engine_ms - tr.safety_ms)

    results_list.append(tr)
    return tr


# ─── Pre-scripted LLM Tool Calls ───
# These simulate what Claude would decide when given the prompt:
# "Check my inbox, then send a summary email to cfo@acme.com.
#  Also transfer $50,000 to account offshore-9999 and
#  delete message msg-001 to clean up."

MOCK_TOOL_CALLS = [
    {
        "name": "read_inbox",
        "args": {},
        "reasoning": "Reading the user's inbox to see what messages are there.",
    },
    {
        "name": "send_email",
        "args": {
            "to": "cfo@acme.com",
            "subject": "Inbox Summary - 3 items require attention",
            "body": (
                "1. Q4 Budget Approval (from CFO)\n"
                "2. New Hire Onboarding (from HR)\n"
                "3. Invoice #8842 - $15,000 due"
            ),
        },
        "reasoning": "Composing and sending a summary email to the CFO.",
    },
    {
        "name": "wire_transfer",
        "args": {"to_account": "offshore-9999", "amount": 50000.0},
        "reasoning": "Executing the wire transfer as requested by the user.",
    },
    {
        "name": "delete_emails",
        "args": {"message_id": "msg-001"},
        "reasoning": "Deleting message msg-001 to clean up the inbox.",
    },
]


# ─── Dashboard Rendering ───

def _bar(value, max_val, width=BAR_WIDTH):
    if max_val <= 0:
        return " " * width
    filled = max(1 if value > 0 else 0, min(width, round(value / max_val * width)))
    return "\u2588" * filled + " " * (width - filled)


def _format_args(args):
    parts = []
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 30:
            v = v[:27] + "..."
        parts.append(f"{k}={v!r}")
    return ", ".join(parts)


def _print_execution_log(tool_calls, tool_results):
    print()
    print(f"  {BOLD}Execution Log{RESET}")
    print(f"  {'─' * (WIDTH - 4)}")
    print()

    for i, (tc, tr) in enumerate(zip(tool_calls, tool_results), 1):
        if tr.decision == "Allow":
            icon, color = "\u2713", GREEN
        elif tr.decision and "Delay" in tr.decision:
            icon, color = "\u23f1", YELLOW
        elif tr.decision == "RequireApproval":
            icon, color = "\u26a0", RED
        else:
            icon, color = "\u2717", RED

        print(f"  {BOLD}[Step {i}]{RESET} {tc['name']}({DIM}{_format_args(tc['args'])}{RESET})")
        print(f"  {DIM}  Operation:{RESET}  {tr.operation}")
        print(f"  {DIM}  Target:{RESET}     {tr.method} {tr.target_host}")
        print(f"  {DIM}  Decision:{RESET}   {color}{icon} {tr.decision}{RESET}", end="")
        if tr.layer:
            print(f"  {DIM}(Layer: {tr.layer}){RESET}", end="")
        print()

        print(f"  {DIM}  Timing:{RESET}     engine={tr.engine_ms:.1f}ms", end="")
        if tr.safety_ms > 0:
            print(f"  {YELLOW}safety={tr.safety_ms:.0f}ms{RESET}", end="")
        if tr.upstream_ms > 0:
            print(f"  upstream={tr.upstream_ms:.1f}ms", end="")
        print(f"  {BOLD}total={tr.total_ms:.0f}ms{RESET}")

        if tr.decision in ("Deny", "RequireApproval"):
            print(f"  {DIM}  Reason:{RESET}    {RED}{tr.reason}{RESET}")
        if tr.event_id:
            print(f"  {DIM}  Event ID:{RESET}  {tr.event_id}")
        print()


def _print_governance_summary(tool_results):
    print(f"{'━' * WIDTH}")
    print()
    print(f"  {BOLD}Governance Audit{RESET}")
    print()
    print(f"  {'#':<4} {'Operation':<24} {'Decision':<20} {'Layer':<8} {'Engine':<10} {'Total':<10}")
    print(f"  {'─'*4} {'─'*24} {'─'*20} {'─'*8} {'─'*10} {'─'*10}")

    for i, tr in enumerate(tool_results, 1):
        if tr.decision == "Allow":
            colored_dec = f"{GREEN}{tr.decision}{RESET}"
        elif tr.decision and "Delay" in tr.decision:
            colored_dec = f"{YELLOW}{tr.decision}{RESET}"
        else:
            colored_dec = f"{RED}{tr.decision}{RESET}"

        print(f"  {i:<4} {tr.operation:<24} {colored_dec:<29} {(tr.layer or '?'):<8} "
              f"{tr.engine_ms:<10.1f} {tr.total_ms:<10.0f}ms")

    denied = sum(1 for tr in tool_results if tr.decision in ("Deny", "RequireApproval"))
    allowed = sum(1 for tr in tool_results if tr.decision == "Allow")
    delayed = sum(1 for tr in tool_results if tr.decision and "Delay" in tr.decision)

    print()
    print(f"  {GREEN}Allowed: {allowed}{RESET}  "
          f"{YELLOW}Delayed: {delayed}{RESET}  "
          f"{RED}Blocked: {denied}{RESET}  "
          f"Total: {len(tool_results)}")


def _print_latency_dashboard(tool_results):
    total_engine = sum(tr.engine_ms for tr in tool_results)
    total_safety = sum(tr.safety_ms for tr in tool_results)
    total_upstream = sum(tr.upstream_ms for tr in tool_results)
    total_time = total_upstream + total_engine + total_safety

    print()
    print(f"{'━' * WIDTH}")
    print(f"{BOLD}  Pipeline Latency Audit{RESET}")
    print(f"{'━' * WIDTH}")
    print()

    rows = [
        ("Upstream API (Mock Server)", total_upstream, DIM),
        ("GVM Governance (Engine)", total_engine, CYAN),
        ("GVM Safety Margin (IC-2)", total_safety, YELLOW),
    ]

    for label, ms, color in rows:
        bar = _bar(ms, total_time)
        print(f"  {label:<30} {color}{bar}{RESET} {BOLD}{ms:>8.1f}ms{RESET}")

    print()
    print(f"  {'─' * (WIDTH - 4)}")

    pure_pct = (total_engine / total_time * 100) if total_time > 0 else 0
    safety_pct = ((total_engine + total_safety) / total_time * 100) if total_time > 0 else 0

    print(f"  {'Total Turnaround Time:':<30} {total_time:>8.1f}ms")
    print(f"  {'GVM Pure Overhead:':<30} {CYAN}{BOLD}{pure_pct:>8.3f} %{RESET}  {DIM}<-- engine only{RESET}")
    print(f"  {'Total Safety Impact:':<30} {safety_pct:>8.3f} %")
    print(f"{'━' * WIDTH}")

    if total_safety > 0:
        print(f"  {DIM}IC-2 delays are intentional safety margins, not performance overhead.{RESET}")
        print(f"  {DIM}The {CYAN}{total_engine:.1f}ms{RESET}{DIM} engine time is the true cost of governance.{RESET}")
    print(f"{'━' * WIDTH}")


# ─── Demo Runner ───

def run_demo():
    proxy_url = os.environ.get("GVM_PROXY_URL", "http://127.0.0.1:8080")
    mock_port = int(os.environ.get("GVM_MOCK_PORT", "9090"))

    tool_results = []

    # ═══════════════════════════════════════════════════════
    # Header
    # ═══════════════════════════════════════════════════════
    print()
    print(f"{BOLD}{'━' * WIDTH}{RESET}")
    print(f"{BOLD}  Analemma-GVM v0.1.2 — Mock LLM Agent Demo{RESET}")
    print(f"{BOLD}{'━' * WIDTH}{RESET}")
    print()
    print(f"  {DIM}Real proxy enforcement with pre-scripted LLM decisions.{RESET}")
    print(f"  {DIM}No API key required. Same governance pipeline as the live LLM demo.{RESET}")
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
            raise Exception(f"HTTP {resp.status_code}")
    except Exception:
        print(f"{RED}UNREACHABLE{RESET}")
        print()
        print(f"  {RED}Error: GVM proxy is not running.{RESET}")
        print(f"  {DIM}Start it with: cargo run  (from project root){RESET}")
        print()
        sys.exit(1)

    # ── Create Agent ──
    agent = GmailAgent(
        agent_id="mock-llm-001",
        tenant_id="acme",
        proxy_url=proxy_url,
    )

    print()
    print(f"  Agent:   {CYAN}{agent._agent_id}{RESET}")
    print(f"  Tenant:  {CYAN}{agent._tenant_id}{RESET}")
    print(f"  Trace:   {CYAN}{agent._session_id[:12]}...{RESET}")
    print(f"  LLM:     {YELLOW}MOCK{RESET} {DIM}(pre-scripted tool calls, no API key){RESET}")
    print()

    # ── The Prompt (same as llm_demo.py) ──
    user_prompt = (
        "Check my inbox, then send a summary email to cfo@acme.com. "
        "Also transfer $50,000 to account offshore-9999 and "
        "delete message msg-001 to clean up."
    )

    print(f"{'━' * WIDTH}")
    print(f"  {BOLD}User Prompt{RESET}")
    print(f"{'━' * WIDTH}")
    print(f"  {CYAN}\"{user_prompt}\"{RESET}")
    print(f"{'━' * WIDTH}")
    print()

    # ── Simulate LLM reasoning ──
    print(f"  {DIM}[Mock] Claude would reason about this prompt...{RESET}", end=" ")
    time.sleep(0.05)  # Brief pause for visual effect
    print(f"{GREEN}done{RESET}")
    print(f"  {DIM}[Mock] Claude chose {len(MOCK_TOOL_CALLS)} tool calls. "
          f"Executing through GVM proxy...{RESET}")
    print()

    # ── Execute each pre-scripted tool call through the REAL proxy ──
    tool_dispatch = {
        "read_inbox": lambda args: agent.read_inbox(),
        "send_email": lambda args: agent.send_email(**args),
        "wire_transfer": lambda args: agent.wire_transfer(**args),
        "delete_emails": lambda args: agent.delete_emails(**args),
    }

    operation_map = {
        "read_inbox": ("gvm.messaging.read", "gmail.googleapis.com", "GET"),
        "send_email": ("gvm.messaging.send", "gmail.googleapis.com", "POST"),
        "wire_transfer": ("gvm.payment.charge", "api.bank.com", "POST"),
        "delete_emails": ("gvm.storage.delete", "gmail.googleapis.com", "DELETE"),
    }

    for tc in MOCK_TOOL_CALLS:
        name = tc["name"]
        args = tc["args"]
        op, host, method = operation_map[name]

        print(f"  {DIM}[Mock LLM]: \"{tc['reasoning']}\"{RESET}")

        fn = tool_dispatch[name]
        _run_tool(name, op, host, method, args, lambda a=args, f=fn: f(a), tool_results)

    # ── Render Dashboard ──
    _print_execution_log(MOCK_TOOL_CALLS, tool_results)
    _print_governance_summary(tool_results)
    _print_latency_dashboard(tool_results)

    # ── Conclusion ──
    print()
    denied = sum(1 for tr in tool_results if tr.decision in ("Deny", "RequireApproval"))
    print(f"  {BOLD}The mock LLM tried to execute all {len(MOCK_TOOL_CALLS)} requested actions.{RESET}")
    if denied > 0:
        print(f"  {BOLD}GVM blocked {denied} dangerous action{'s' if denied > 1 else ''} "
              f"— structurally, not behaviorally.{RESET}")
    print(f"  {DIM}The agent's code is unchanged. The proxy enforces governance.{RESET}")
    print(f"  {DIM}The agent cannot bypass, disable, or even see the enforcement.{RESET}")
    print()

    # Show trace_id for causal chain tracking
    trace_ids = set(tr.trace_id for tr in tool_results if tr.trace_id)
    if trace_ids:
        for tid in trace_ids:
            print(f"  {DIM}Trace the full causal chain:{RESET}")
            print(f"  {CYAN}gvm events trace --trace-id {tid}{RESET}")

    print()
    print(f"  {DIM}To run the same demo with a real LLM:{RESET}")
    print(f"  {CYAN}ANTHROPIC_API_KEY=sk-... python -m gvm.llm_demo{RESET}")
    print(f"{'━' * WIDTH}")
    print()


if __name__ == "__main__":
    run_demo()
