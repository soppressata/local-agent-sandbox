"""
Unit and integration tests for Topology Definition Language (TDL) parsing and agent lifecycle.
"""

import os
import tempfile
import pytest

from local_agent_sandbox.tdl import (
    TDLParser,
    TDLTopology,
    AgentConfig,
    ToolPermissions,
    AgentInstance,
    AgentStatus,
    SwarmLifecycleManager,
    SwarmStatus,
    TDLParseError,
    parse_tdl,
    parse_tdl_file,
)
from local_agent_sandbox.isolation import SecurityViolation
from local_agent_sandbox.orchestrator import UniverseOrchestrator


SAMPLE_TDL_YAML = """
version: "1.0"
name: "software-dev-swarm"
description: "A multi-agent swarm for automated code generation and auditing."
metadata:
  environment: "staging"

agents:
  - name: "architect"
    role: "lead-architect"
    system_prompt: "You are an expert system architect."
    tools:
      - "read_file"
      - "write_file"
      - "search_code"
    permissions:
      allowed_tools:
        - "read_file"
        - "write_file"
        - "search_code"
      denied_tools:
        - "execute_shell"
    quota:
      cpu_cores: 2.0
      memory_mb: 1024
      max_threads: 32
    environment:
      DEBUG: "true"

  - name: "developer"
    role: "backend-developer"
    system_prompt: "You are a Python software engineer."
    tools:
      - "read_file"
      - "write_file"
      - "execute_shell"
    permissions:
      allowed_tools:
        - "read_file"
        - "write_file"
        - "execute_shell"
      denied_tools: []

  - name: "auditor"
    role: "security-auditor"
    system_prompt: "You audit code security and permissions."
    tools:
      - "read_file"
"""


def test_parse_valid_tdl_yaml():
    topology = parse_tdl(SAMPLE_TDL_YAML)
    assert isinstance(topology, TDLTopology)
    assert topology.version == "1.0"
    assert topology.name == "software-dev-swarm"
    assert topology.description == "A multi-agent swarm for automated code generation and auditing."
    assert len(topology.agents) == 3

    arch_cfg = topology.get_agent_config("architect")
    assert arch_cfg is not None
    assert arch_cfg.role == "lead-architect"
    assert arch_cfg.system_prompt == "You are an expert system architect."
    assert "read_file" in arch_cfg.tools
    assert arch_cfg.quota.memory_mb == 1024
    assert arch_cfg.quota.cpu_cores == 2.0
    assert arch_cfg.permissions.is_tool_allowed("read_file") is True
    assert arch_cfg.permissions.is_tool_allowed("execute_shell") is False

    dev_cfg = topology.get_agent_config("developer")
    assert dev_cfg is not None
    assert dev_cfg.permissions.is_tool_allowed("execute_shell") is True


def test_parse_tdl_file():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(SAMPLE_TDL_YAML)
        temp_path = f.name

    try:
        topology = parse_tdl_file(temp_path)
        assert topology.name == "software-dev-swarm"
        assert len(topology.agents) == 3
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_tdl_parser_errors():
    with pytest.raises(TDLParseError, match="missing 'agents'"):
        parse_tdl("name: invalid-swarm\nversion: '1.0'")

    with pytest.raises(TDLParseError, match="missing required 'name'"):
        parse_tdl("agents:\n  - role: worker")

    with pytest.raises(TDLParseError, match="Duplicate agent name"):
        parse_tdl("agents:\n  - name: worker\n  - name: worker")

    with pytest.raises(TDLParseError):
        parse_tdl_file("/nonexistent/file/path/topology.yaml")


def test_tool_permissions_wildcards_and_defaults():
    # Wildcard allowed
    p1 = ToolPermissions(allowed_tools=["*"], denied_tools=["delete_database"])
    assert p1.is_tool_allowed("any_tool") is True
    assert p1.is_tool_allowed("delete_database") is False

    # Default deny
    p2 = ToolPermissions(allowed_tools=["read_file"], default_allow=False)
    assert p2.is_tool_allowed("read_file") is True
    assert p2.is_tool_allowed("write_file") is False

    # Default allow when empty
    p3 = ToolPermissions(default_allow=True)
    assert p3.is_tool_allowed("anything") is True


def test_agent_instance_lifecycle():
    orchestrator = UniverseOrchestrator()
    config = AgentConfig(
        name="test-agent",
        role="tester",
        system_prompt="Test agent prompt instructions.",
        tools=["read_file"],
        permissions=ToolPermissions(allowed_tools=["read_file"], denied_tools=["execute_shell"]),
    )

    agent = AgentInstance(config=config, orchestrator=orchestrator)
    assert agent.status == AgentStatus.CREATED

    # Spin-up
    assert agent.spin_up() is True
    assert agent.status == AgentStatus.RUNNING
    assert agent.universe is not None

    # Check system prompt in VFS
    vfs_prompt = agent.universe.read_virtual_file("/etc/system_prompt.txt")
    assert vfs_prompt == "Test agent prompt instructions."

    # Tool permission checking & execution
    assert agent.can_use_tool("read_file") is True
    assert agent.can_use_tool("execute_shell") is False

    res = agent.execute_tool("read_file", path="/tmp/env.json")
    assert res["status"] == "SUCCESS"

    with pytest.raises(SecurityViolation, match="lacks permission"):
        agent.execute_tool("execute_shell", command="rm -rf /")

    # Graceful termination
    assert agent.terminate(graceful=True) is True
    assert agent.status == AgentStatus.TERMINATED
    assert agent.universe is None

    orchestrator.close()


def test_swarm_lifecycle_manager():
    topology = parse_tdl(SAMPLE_TDL_YAML)
    orchestrator = UniverseOrchestrator()

    swarm = SwarmLifecycleManager(topology=topology, orchestrator=orchestrator)
    assert swarm.status == SwarmStatus.CREATED
    assert len(swarm.list_agents()) == 3

    # Spin up entire swarm
    active_agents = swarm.spin_up_swarm()
    assert len(active_agents) == 3
    assert swarm.status == SwarmStatus.RUNNING

    status_summary = swarm.get_swarm_status()
    assert status_summary["running_agents"] == 3
    assert status_summary["topology_name"] == "software-dev-swarm"

    # Verify agent instances have distinct prompts and permissions
    arch = swarm.get_agent("architect")
    dev = swarm.get_agent("developer")
    audit = swarm.get_agent("auditor")

    assert arch is not None and dev is not None and audit is not None
    assert arch.config.system_prompt != dev.config.system_prompt
    assert arch.can_use_tool("execute_shell") is False
    assert dev.can_use_tool("execute_shell") is True

    # Graceful termination
    term_res = swarm.terminate_swarm(graceful=True)
    assert all(term_res.values())
    assert swarm.status == SwarmStatus.TERMINATED

    orchestrator.close()


def test_agent_universe_isolation():
    """Each agent instance must be isolated in its own Universe filesystem."""
    orchestrator = UniverseOrchestrator()

    agent_a = AgentInstance(
        config=AgentConfig(
            name="writer",
            system_prompt="Writer agent.",
            permissions=ToolPermissions(allowed_tools=["*"]),
        ),
        orchestrator=orchestrator,
    )
    agent_b = AgentInstance(
        config=AgentConfig(
            name="reader",
            system_prompt="Reader agent.",
            permissions=ToolPermissions(allowed_tools=["*"]),
        ),
        orchestrator=orchestrator,
    )

    assert agent_a.spin_up() is True
    assert agent_b.spin_up() is True

    # Write a secret file into agent_a's universe
    agent_a.universe.write_virtual_file("/workspace/secret.txt", "agent-a-secret")

    # Verify agent_b cannot read agent_a's file
    with pytest.raises(FileNotFoundError):
        agent_b.universe.read_virtual_file("/workspace/secret.txt")

    # Verify agent_a can still read its own file
    assert agent_a.universe.read_virtual_file("/workspace/secret.txt") == "agent-a-secret"

    assert agent_a.terminate() is True
    assert agent_b.terminate() is True
    orchestrator.close()
