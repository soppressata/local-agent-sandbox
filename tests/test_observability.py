"""
Tests for dynamic hierarchical sub-agent spawning and swarm observability.
"""

import pytest
from click.testing import CliRunner

from local_agent_sandbox.cli import cli
from local_agent_sandbox.messaging import MessageBus
from local_agent_sandbox.observability import (
    build_snapshot,
    build_topology,
    monitor,
    render_dashboard,
)
from local_agent_sandbox.tdl import (
    AgentConfig,
    AgentStatus,
    SwarmLifecycleManager,
    ToolPermissions,
    parse_tdl,
)

TOPOLOGY_YAML = """
name: "observability-swarm"
version: "1.0"
agents:
  - name: "architect"
    role: "lead-architect"
    permissions:
      allowed_tools: ["*"]
  - name: "developer"
    role: "backend-developer"
    permissions:
      allowed_tools: ["*"]
"""


def test_agent_dynamic_subagent_spawning():
    """A running agent can spawn and register child sub-agents at runtime."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()

    architect = swarm.get_agent("architect")
    assert architect is not None
    assert len(swarm.list_agents()) == 2

    child = architect.spawn_subagent(
        AgentConfig(
            name="code-writer",
            role="writer",
            permissions=ToolPermissions(allowed_tools=["*"]),
        )
    )

    assert child.parent is architect
    assert child.parent_id == architect.agent_id
    assert child.status == AgentStatus.RUNNING
    assert architect.get_subagents() == [child]
    assert architect.get_child("code-writer") is child
    assert architect.get_descendants() == [child]
    assert architect.get_status()["subagent_count"] == 1
    assert architect.get_status()["parent_id"] is None
    assert child.get_status()["parent_id"] == architect.agent_id

    # Dynamically spawned agents are registered with the swarm for observation.
    assert swarm.get_agent("code-writer") is child
    assert len(swarm.list_agents()) == 3
    assert swarm.get_swarm_status()["total_agents"] == 3
    assert swarm.get_swarm_status()["running_agents"] == 3

    # Cascading teardown reaches spawned sub-agents.
    swarm.terminate_swarm()
    assert child.status == AgentStatus.TERMINATED
    assert architect.status == AgentStatus.TERMINATED


def test_spawn_requires_running_agent():
    """Sub-agents may only be spawned from a RUNNING agent."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    architect = swarm.get_agent("architect")
    with pytest.raises(RuntimeError, match="status"):
        architect.spawn_subagent(AgentConfig(name="child"))


def test_spawn_rejects_duplicate_subagent_name():
    """Spawning two sub-agents with the same name under one parent fails."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()
    architect = swarm.get_agent("architect")
    architect.spawn_subagent(AgentConfig(name="scout", role="scout"))
    with pytest.raises(ValueError, match="already exists"):
        architect.spawn_subagent(AgentConfig(name="scout", role="scout"))
    swarm.terminate_swarm()


def test_terminate_subagent():
    """terminate_subagent tears down and detaches a single child."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()
    architect = swarm.get_agent("architect")
    child = architect.spawn_subagent(AgentConfig(name="scout", role="scout"))

    assert architect.terminate_subagent("scout") is True
    assert child.status == AgentStatus.TERMINATED
    assert architect.get_child("scout") is None
    assert architect.terminate_subagent("scout") is False
    swarm.terminate_swarm()


def test_nested_subagent_hierarchy():
    """Sub-agents may themselves spawn children, forming a deep hierarchy."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()
    architect = swarm.get_agent("architect")
    lead = architect.spawn_subagent(AgentConfig(name="lead", role="lead"))
    intern = lead.spawn_subagent(AgentConfig(name="intern", role="intern"))

    assert lead.parent is architect
    assert intern.parent is lead
    assert intern.parent_id == lead.agent_id
    assert architect.get_descendants() == [lead, intern]
    assert len(swarm.list_agents()) == 4
    swarm.terminate_swarm()
    assert intern.status == AgentStatus.TERMINATED
    assert lead.status == AgentStatus.TERMINATED


def test_message_bus_history_tracks_flow():
    """The bus retains a bounded, ordered history of sent messages."""
    bus = MessageBus(history_size=5)
    bus.register_inbox("a")
    bus.register_inbox("b")
    bus.send("a", "b", "one")
    bus.send("a", "b", "two")
    bus.send("a", "b", "three")

    assert [m.body for m in bus.history()] == ["one", "two", "three"]
    assert [m.body for m in bus.history(limit=2)] == ["two", "three"]

    # The history is a ring buffer bounded by history_size.
    bus.send("a", "b", "four")
    bus.send("a", "b", "five")
    bus.send("a", "b", "six")
    assert len(bus.history()) == 5
    assert [m.body for m in bus.history()] == ["two", "three", "four", "five", "six"]

    bus.reset()
    assert bus.history() == []


def test_topology_snapshot_reflects_hierarchy():
    """build_topology and build_snapshot expose the full swarm hierarchy."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()

    architect = swarm.get_agent("architect")
    architect.spawn_subagent(AgentConfig(name="writer", role="writer"))
    swarm.send_message("architect", "developer", "status?")

    topology = build_topology(swarm)
    assert {node["name"] for node in topology} == {"architect", "developer"}
    arch_node = next(node for node in topology if node["name"] == "architect")
    assert arch_node["children"][0]["name"] == "writer"
    assert arch_node["children"][0]["parent_id"] == architect.agent_id
    assert arch_node["children"][0]["status"] == "RUNNING"

    snapshot = build_snapshot(swarm)
    assert snapshot["swarm"]["total_agents"] == 3
    assert snapshot["swarm"]["running_agents"] == 3
    assert snapshot["status_counts"]["RUNNING"] == 3
    assert snapshot["bus"]["messages_sent"] == 1
    assert snapshot["messages"][-1]["sender"] == "architect"
    assert snapshot["messages"][-1]["recipient"] == "developer"
    assert snapshot["messages"][-1]["body"] == "status?"
    swarm.terminate_swarm()


def test_render_dashboard_plain():
    """The plain dashboard frame shows topology, status, and message flow."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()
    swarm.get_agent("architect").spawn_subagent(AgentConfig(name="writer", role="writer"))
    swarm.send_message("architect", "developer", "please review")

    frame = render_dashboard(swarm, use_color=False)
    assert "SWARM DASHBOARD" in frame
    assert "observability-swarm" in frame
    assert "architect" in frame
    assert "writer" in frame
    assert "developer" in frame
    assert "architect -> developer" in frame
    assert "\x1b[" not in frame
    swarm.terminate_swarm()


def test_monitor_renders_finite_frames(capsys):
    """monitor renders exactly the requested number of frames."""
    swarm = SwarmLifecycleManager(topology=parse_tdl(TOPOLOGY_YAML))
    swarm.spin_up_swarm()
    monitor(swarm, max_frames=2, interval=0, use_color=False)
    captured = capsys.readouterr()
    assert captured.out.count("SWARM DASHBOARD") == 2
    swarm.terminate_swarm()


def test_cli_swarm_monitor_once(tmp_path):
    """`agent-sandbox swarm monitor --once` renders a dashboard for a TDL file."""
    topology_path = tmp_path / "topology.yaml"
    topology_path.write_text(TOPOLOGY_YAML)

    runner = CliRunner()
    result = runner.invoke(cli, ["swarm", "monitor", str(topology_path), "--once"])
    assert result.exit_code == 0
    assert "SWARM DASHBOARD" in result.output
    assert "observability-swarm" in result.output
    assert "architect" in result.output
