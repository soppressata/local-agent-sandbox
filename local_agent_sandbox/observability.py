"""
Swarm Observability
Real-time topology, agent status, and message-flow visualization for swarms
built from dynamic hierarchical sub-agent spawning.
"""

import re
import sys
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .messaging import Message
from .tdl import AgentInstance, AgentStatus, SwarmLifecycleManager

_STATUS_COLORS = {
    "RUNNING": "\033[32m",
    "SPINNING_UP": "\033[33m",
    "CREATED": "\033[36m",
    "TERMINATING": "\033[33m",
    "TERMINATED": "\033[90m",
    "FAILED": "\033[31m",
    "PARTIAL": "\033[33m",
}
_RESET = "\033[0m"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _color_status(status: str, use_color: bool) -> str:
    """Wrap ``status`` in its ANSI color when color output is enabled."""
    if not use_color:
        return status
    color = _STATUS_COLORS.get(status, "")
    return f"{color}{status}{_RESET}"


def _plain_len(text: str) -> int:
    """Return the display width of ``text`` ignoring ANSI escape codes."""
    return len(_ANSI_RE.sub("", text))


def _pad(text: str, width: int) -> str:
    """Right-pad ``text`` to ``width`` columns, accounting for ANSI codes."""
    return text + " " * max(0, width - _plain_len(text))


def _truncate(text: str, max_len: int) -> str:
    """Truncate ``text`` with an ellipsis when it exceeds ``max_len``."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 2] + ".."


def _agent_node(agent: AgentInstance) -> Dict[str, Any]:
    """Build a nested tree node describing one agent and its sub-agents."""
    return {
        "agent_id": agent.agent_id,
        "name": agent.config.name,
        "role": agent.config.role,
        "status": agent.status.value,
        "parent_id": agent.parent_id,
        "subagent_count": len(agent.get_subagents()),
        "children": [_agent_node(child) for child in agent.get_subagents()],
    }


def build_topology(swarm: SwarmLifecycleManager) -> List[Dict[str, Any]]:
    """Return the hierarchical swarm topology as a nested tree.

    Agents without a parent are returned as roots; every dynamically spawned
    sub-agent appears nested beneath its parent.
    """
    return [_agent_node(agent) for agent in swarm.list_agents() if agent.parent_id is None]


def build_snapshot(swarm: SwarmLifecycleManager) -> Dict[str, Any]:
    """Return a JSON-compatible snapshot of the swarm's observable state.

    Includes the topology tree, per-status agent counts, bus counters, and the
    recent message-flow history.
    """
    agents = swarm.list_agents()
    status_counts = Counter(agent.status.value for agent in agents)
    return {
        "generated_at": time.time(),
        "swarm": {
            "topology_name": swarm.topology.name,
            "version": swarm.topology.version,
            "status": swarm.status.value,
            "total_agents": len(agents),
            "running_agents": sum(1 for a in agents if a.status == AgentStatus.RUNNING),
        },
        "status_counts": dict(status_counts),
        "bus": swarm.message_bus.stats(),
        "messages": [message.to_dict() for message in swarm.message_bus.history()],
        "topology": build_topology(swarm),
    }


def _render_node_lines(node: Dict[str, Any], prefix: str, use_color: bool,
                       is_last: bool = False, root: bool = False) -> List[str]:
    """Render one topology tree node and all of its descendants."""
    if root:
        connector = ""
        child_prefix = ""
    else:
        connector = prefix + ("`- " if is_last else "+- ")
        child_prefix = prefix + ("    " if is_last else "|   ")
    status_text = _color_status(node["status"], use_color)
    lines = [f"{connector}{node['name']} [{status_text}] ({node['role']})"]
    children = node["children"]
    for index, child in enumerate(children):
        last = index == len(children) - 1
        lines.extend(_render_node_lines(child, child_prefix, use_color, is_last=last, root=False))
    return lines


def _render_status_table(agents: List[AgentInstance], use_color: bool) -> List[str]:
    """Render the agent status table with aligned fixed-width columns."""
    headers = ["NAME", "ID", "ROLE", "STATUS", "UPTIME", "SUB"]
    rows = []
    for agent in agents:
        status = agent.get_status()
        rows.append([
            _truncate(agent.config.name, 22),
            _truncate(agent.agent_id, 22),
            _truncate(agent.config.role, 18),
            _color_status(agent.status.value, use_color),
            f"{status['uptime_seconds']:6.1f}s",
            str(status["subagent_count"]),
        ])
    col_widths = [
        max(len(header), max((_plain_len(row[i]) for row in rows), default=0))
        for i, header in enumerate(headers)
    ]
    lines = ["  ".join(_pad(cell, width) for cell, width in zip(headers, col_widths))]
    lines.append("-" * (sum(col_widths) + 2 * (len(col_widths) - 1)))
    for row in rows:
        lines.append("  ".join(_pad(cell, width) for cell, width in zip(row, col_widths)))
    return lines


def _render_message(message: Message, width: int, use_color: bool) -> str:
    """Render a single message-flow line."""
    body = str(message.body)
    max_body = max(10, width - 34)
    if len(body) > max_body:
        body = body[: max_body - 2] + ".."
    kind = message.kind.value.upper()
    return f"#{message.sequence:04d} {message.sender} -> {message.recipient} [{kind}]: {body}"


def render_dashboard(swarm: SwarmLifecycleManager, use_color: bool = False,
                     width: int = 100, message_limit: int = 8) -> str:
    """Render a single plain-text dashboard frame for the swarm.

    Visualizes the swarm topology tree, per-agent status, and recent message
    flows. Plain by default so output can be piped or asserted on; pass
    ``use_color=True`` for an ANSI-colorized terminal frame.
    """
    lines: List[str] = []
    rule = "=" * width
    summary = swarm.get_swarm_status()
    status_text = _color_status(summary["swarm_status"], use_color)
    bus_stats = swarm.message_bus.stats()

    lines.append("SWARM DASHBOARD")
    lines.append(rule)
    lines.append(
        f"Swarm: {summary['topology_name']}  Version: {summary['version']}  "
        f"Status: {status_text}"
    )
    lines.append(
        f"Agents: {summary['total_agents']} total | {summary['running_agents']} running | "
        f"Messages sent: {bus_stats['messages_sent']}"
    )
    lines.append("")
    lines.append("TOPOLOGY")
    lines.append("-" * width)
    topology = build_topology(swarm)
    if not topology:
        lines.append("(no agents)")
    for index, node in enumerate(topology):
        lines.extend(
            _render_node_lines(node, "", use_color, is_last=index == len(topology) - 1, root=True)
        )
    lines.append("")
    lines.append("AGENT STATUS")
    lines.append("-" * width)
    lines.extend(_render_status_table(swarm.list_agents(), use_color))
    lines.append("")
    lines.append(f"MESSAGE FLOW (recent {message_limit})")
    lines.append("-" * width)
    messages = swarm.message_bus.history(limit=message_limit)
    if not messages:
        lines.append("(no messages)")
    for message in messages:
        lines.append(_render_message(message, width, use_color))
    return "\n".join(lines) + "\n"


def monitor(swarm: SwarmLifecycleManager, interval: float = 1.0,
            max_frames: Optional[int] = None, once: bool = False,
            use_color: bool = True) -> None:
    """Render swarm dashboards in real time until interrupted or ``max_frames``.

    :param swarm: The swarm to observe.
    :param interval: Seconds between live refreshes.
    :param max_frames: Maximum number of frames to render, or None for unlimited.
    :param once: Render a single plain-text frame and return.
    :param use_color: Enable ANSI colors in live frames.
    """
    if interval < 0:
        raise ValueError("interval must not be negative")
    if max_frames is not None and max_frames < 1:
        raise ValueError("max_frames must be positive")

    if once:
        sys.stdout.write(render_dashboard(swarm, use_color=use_color))
        return
    if not sys.stdout.isatty() and max_frames is None:
        max_frames = 1

    frame = 0
    try:
        while max_frames is None or frame < max_frames:
            frame += 1
            dashboard = render_dashboard(swarm, use_color=use_color)
            if sys.stdout.isatty():
                sys.stdout.write("\033[2J\033[H")
            sys.stdout.write(dashboard)
            sys.stdout.flush()
            if max_frames is None:
                time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
