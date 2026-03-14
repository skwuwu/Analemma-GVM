"""Shared LLM agent runner for GVM demos.

Provides the common ChatAnthropic + tool execution + dashboard pattern
used by all domain-specific LLM agents.
"""

import io
import os
import sys
import time

# Force UTF-8 output on Windows
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from dotenv import load_dotenv

load_dotenv()

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

import gvm.langchain_tools as _lt
from gvm.errors import GVMDeniedError, GVMApprovalRequiredError, GVMError
from gvm import mock_server

# ─── ANSI Colors ───
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
WIDTH = 72
BAR_WIDTH = 40


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


def run_tool(name, operation, target_host, method, args, fn, results_list):
    """Execute a tool function and capture GVM enforcement details."""
    tr = ToolResult(name, operation, target_host, method, args)

    t0 = time.time()
    try:
        result = fn()
        tr.total_ms = (time.time() - t0) * 1000
        tr.result_text = str(result)[:100] if result else "OK"
    except (GVMDeniedError, GVMApprovalRequiredError, GVMError) as e:
        tr.total_ms = (time.time() - t0) * 1000
        tr.event_id = getattr(e, "event_id", None)
        tr.reason = str(e)
        tr.result_text = tr.reason

    # Read enforcement details from GVM proxy response headers
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


def format_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 30:
            v = v[:27] + "..."
        parts.append(f"{k}={v!r}")
    return ", ".join(parts)


def _bar(value, max_val, width=BAR_WIDTH):
    if max_val <= 0:
        return " " * width
    filled = max(1 if value > 0 else 0, min(width, round(value / max_val * width)))
    return "\u2588" * filled + " " * (width - filled)


def print_dashboard(tool_calls, tool_results, llm_elapsed, title, agent_id):
    """Print the full execution log + governance audit + latency dashboard."""

    # ── Execution Log ──
    print()
    print(f"  {BOLD}Execution Log{RESET}")
    print(f"  {'─' * (WIDTH - 4)}")
    print()

    result_idx = 0
    for i, tc in enumerate(tool_calls, 1):
        if result_idx >= len(tool_results):
            break
        tr = tool_results[result_idx]
        result_idx += 1

        if tr.decision == "Allow":
            icon, color = "\u2713", GREEN
        elif tr.decision and "Delay" in tr.decision:
            icon, color = "\u23f1", YELLOW
        elif tr.decision == "RequireApproval":
            icon, color = "\u26a0", RED
        else:
            icon, color = "\u2717", RED

        print(f"  {BOLD}[Step {i}]{RESET} {tc['name']}({DIM}{format_args(tc['args'])}{RESET})")
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

    # ── Governance Audit ──
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
    print()

    # ── Latency Dashboard ──
    total_engine = sum(tr.engine_ms for tr in tool_results)
    total_safety = sum(tr.safety_ms for tr in tool_results)
    total_upstream = sum(tr.upstream_ms for tr in tool_results)
    total_time = llm_elapsed + total_upstream + total_engine + total_safety

    print(f"{'━' * WIDTH}")
    print(f"{BOLD}  Pipeline Latency Audit{RESET}")
    print(f"{'━' * WIDTH}")
    print()

    rows = [
        ("LLM Reasoning (Claude)", llm_elapsed, DIM),
        ("Upstream API (Mock)", total_upstream, DIM),
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

    # ── Conclusion ──
    print()
    print(f"  {BOLD}Claude tried to execute all {len(tool_calls)} requested actions.{RESET}")
    if denied > 0:
        print(f"  {BOLD}GVM blocked {denied} dangerous action{'s' if denied > 1 else ''} "
              f"— structurally, not behaviorally.{RESET}")
    print(f"  {DIM}The agent's code is unchanged. The proxy enforces governance.{RESET}")

    trace_ids = set(tr.trace_id for tr in tool_results if tr.trace_id)
    if trace_ids:
        print()
        for tid in trace_ids:
            print(f"  {DIM}Trace:{RESET} {CYAN}gvm events trace --trace-id {tid}{RESET}")
    print(f"{'━' * WIDTH}")
    print()


def run_agent_loop(title, system_prompt, user_prompt, tools, tool_results,
                   proxy_url=None, mock_port=None, max_steps=8):
    """Run a multi-turn LLM agent loop with governance dashboard.

    Claude calls tools one at a time, receives results, and decides
    the next action. This is how real LLM agents work.

    Args:
        title: Demo title displayed in the header
        system_prompt: System message for Claude
        user_prompt: User message that triggers tool calls
        tools: List of LangChain @tool functions
        tool_results: List to collect ToolResult objects (shared with @tool wrappers)
        proxy_url: GVM proxy URL
        mock_port: Mock server port
        max_steps: Maximum tool call iterations

    Returns:
        (all_tool_calls, llm_elapsed_total)
    """
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        api_key=api_key,
        max_tokens=1024,
    )
    llm_with_tools = llm.bind_tools(tools)
    tool_map = {t.name: t for t in tools}

    print(f"{'━' * WIDTH}")
    print(f"  {BOLD}User Prompt{RESET}")
    print(f"{'━' * WIDTH}")
    print(f"  {CYAN}\"{user_prompt}\"{RESET}")
    print(f"{'━' * WIDTH}")
    print()

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]

    all_tool_calls = []
    llm_elapsed_total = 0
    step = 0

    while step < max_steps:
        step += 1
        print(f"  {DIM}Claude is reasoning (step {step})...{RESET}", end=" ", flush=True)
        t0 = time.time()
        response = llm_with_tools.invoke(messages)
        elapsed = (time.time() - t0) * 1000
        llm_elapsed_total += elapsed

        tool_calls = response.tool_calls if hasattr(response, "tool_calls") else []

        if not tool_calls:
            print(f"{GREEN}done{RESET} ({elapsed:.0f}ms) — no more tool calls")
            break

        print(f"{GREEN}done{RESET} ({elapsed:.0f}ms) — {len(tool_calls)} tool call(s)")

        # Add AI message with tool calls to conversation
        messages.append(response)

        # Execute each tool and add results as ToolMessages
        for tc in tool_calls:
            all_tool_calls.append(tc)
            tool_fn = tool_map.get(tc["name"])
            if tool_fn:
                result = tool_fn.invoke(tc["args"])
                messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    return all_tool_calls, llm_elapsed_total
