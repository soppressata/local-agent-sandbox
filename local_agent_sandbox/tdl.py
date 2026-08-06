"""
Topology Definition Language (TDL) Parser and Agent Lifecycle Engine.
Enables parsing topology.yaml definitions to instantiate isolated AI agent instances
with distinct system prompts, tool permissions, and lifecycle management (spin-up, execution, termination).
"""

import os
import time
import uuid
import yaml
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from pydantic import BaseModel, Field

from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig, SandboxResult


class TDLParseError(Exception):
    """Raised when parsing or validating a TDL topology document fails."""
    pass


class ToolPermissions(BaseModel):
    """Defines tool execution permissions for an agent instance."""
    allowed_tools: List[str] = Field(default_factory=list)
    denied_tools: List[str] = Field(default_factory=list)
    default_allow: bool = False

    def is_tool_allowed(self, tool_name: str) -> bool:
        """
        Check if a given tool name is allowed under current permission rules.

        :param tool_name: Name of tool to check.
        :return: True if allowed, False if denied.
        """
        if tool_name in self.denied_tools or "*" in self.denied_tools:
            return False
        if tool_name in self.allowed_tools or "*" in self.allowed_tools:
            return True
        return self.default_allow

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation of tool permissions."""
        return {
            "allowed_tools": self.allowed_tools,
            "denied_tools": self.denied_tools,
            "default_allow": self.default_allow,
        }


class ComputeQuota(BaseModel):
    """Resource quota for an agent instance."""
    cpu_cores: float = 1.0
    memory_mb: int = 512
    max_threads: int = 16


class AgentConfig(BaseModel):
    """Configuration for a single agent instance defined in TDL."""
    name: str
    role: str = ""
    system_prompt: str = ""
    tools: List[str] = Field(default_factory=list)
    permissions: ToolPermissions = Field(default_factory=ToolPermissions)
    quota: ComputeQuota = Field(default_factory=ComputeQuota)
    environment: Dict[str, str] = Field(default_factory=dict)


class TDLTopology(BaseModel):
    """Complete multi-agent topology configuration loaded from TDL."""
    version: str = "1.0"
    name: str
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    agents: List[AgentConfig] = Field(default_factory=list)

    def get_agent_config(self, name: str) -> Optional[AgentConfig]:
        """
        Retrieve agent configuration by name.

        :param name: Name of the agent.
        :return: AgentConfig if found, None otherwise.
        """
        for agent in self.agents:
            if agent.name == name:
                return agent
        return None


class TDLParser:
    """Parser for Topology Definition Language (TDL) YAML configurations."""

    @staticmethod
    def parse_str(yaml_content: str) -> TDLTopology:
        """
        Parse raw YAML content into a TDLTopology object.

        :param yaml_content: String containing YAML topology specification.
        :return: Validated TDLTopology instance.
        :raises TDLParseError: If syntax is invalid or required fields are missing.
        """
        if not yaml_content or not yaml_content.strip():
            raise TDLParseError("Empty TDL YAML content.")

        try:
            data = yaml.safe_load(yaml_content)
        except Exception as e:
            raise TDLParseError(f"YAML parsing error: {e}") from e

        if not isinstance(data, dict):
            raise TDLParseError("TDL content must be a YAML mapping/object.")

        if "name" not in data or not data["name"]:
            raise TDLParseError("TDL specification missing required 'name' field.")

        if "agents" not in data or not isinstance(data["agents"], list):
            raise TDLParseError("TDL specification missing 'agents' list.")

        agent_names: Set[str] = set()
        agents: List[AgentConfig] = []

        for idx, raw_agent in enumerate(data["agents"]):
            if not isinstance(raw_agent, dict):
                raise TDLParseError(f"Agent entry at index {idx} must be a dictionary.")

            name = raw_agent.get("name")
            if not name:
                raise TDLParseError(f"Agent at index {idx} missing required 'name' field.")

            if name in agent_names:
                raise TDLParseError(f"Duplicate agent name '{name}' found in TDL specification.")

            agent_names.add(name)

            # Parse permissions
            raw_perms = raw_agent.get("permissions", {})
            if isinstance(raw_perms, dict):
                permissions = ToolPermissions(
                    allowed_tools=raw_perms.get("allowed_tools", raw_agent.get("tools", [])),
                    denied_tools=raw_perms.get("denied_tools", []),
                    default_allow=raw_perms.get("default_allow", False),
                )
            else:
                permissions = ToolPermissions(
                    allowed_tools=raw_agent.get("tools", []),
                    denied_tools=[],
                    default_allow=False,
                )

            # Parse quota
            raw_quota = raw_agent.get("quota", {})
            if isinstance(raw_quota, dict):
                quota = ComputeQuota(
                    cpu_cores=float(raw_quota.get("cpu_cores", 1.0)),
                    memory_mb=int(raw_quota.get("memory_mb", 512)),
                    max_threads=int(raw_quota.get("max_threads", 16)),
                )
            else:
                quota = ComputeQuota()

            agents.append(
                AgentConfig(
                    name=name,
                    role=raw_agent.get("role", ""),
                    system_prompt=raw_agent.get("system_prompt", ""),
                    tools=raw_agent.get("tools", []),
                    permissions=permissions,
                    quota=quota,
                    environment=raw_agent.get("environment", {}),
                )
            )

        return TDLTopology(
            version=str(data.get("version", "1.0")),
            name=data["name"],
            description=data.get("description", ""),
            metadata=data.get("metadata", {}),
            agents=agents,
        )

    @staticmethod
    def parse_file(file_path: str) -> TDLTopology:
        """
        Parse a TDL YAML file into a TDLTopology object.

        :param file_path: Path to topology.yaml file.
        :return: Validated TDLTopology instance.
        :raises TDLParseError: If file is missing or invalid.
        """
        if not os.path.exists(file_path):
            raise TDLParseError(f"Topology file not found at path: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            raise TDLParseError(f"Error reading topology file '{file_path}': {e}") from e

        return TDLParser.parse_str(content)


def parse_tdl(yaml_content: str) -> TDLTopology:
    """Convenience function to parse raw YAML TDL string."""
    return TDLParser.parse_str(yaml_content)


def parse_tdl_file(file_path: str) -> TDLTopology:
    """Convenience function to parse TDL file."""
    return TDLParser.parse_file(file_path)


class AgentStatus(str, Enum):
    """Lifecycle status of an isolated agent instance."""
    CREATED = "CREATED"
    SPINNING_UP = "SPINNING_UP"
    RUNNING = "RUNNING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class AgentInstance:
    """
    Represents an active or provisioned isolated agent instance created from an AgentConfig.
    Manages agent sandbox spin-up, tool permission enforcement, and graceful termination.
    """

    def __init__(self, config: AgentConfig, sandbox_dir: Optional[str] = None):
        self.agent_id = f"agent-{uuid.uuid4().hex[:8]}"
        self.config = config
        self.status = AgentStatus.CREATED
        self.sandbox_dir = sandbox_dir
        self.sandbox: Optional[LocalAgentSandbox] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.logs: List[str] = []

    def _log(self, msg: str) -> None:
        entry = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ')}] [{self.config.name}] {msg}"
        self.logs.append(entry)

    def spin_up(self) -> bool:
        """
        Spins up the agent instance, initializing its isolated sandbox environment
        and writing its system prompt.

        :return: True if spin-up succeeded.
        """
        if self.status == AgentStatus.RUNNING:
            return True

        self.status = AgentStatus.SPINNING_UP
        self._log(f"Spinning up agent instance '{self.config.name}' (Role: {self.config.role})...")

        try:
            sb_config = SandboxConfig()
            self.sandbox = LocalAgentSandbox(config=sb_config, sandbox_dir=self.sandbox_dir)
            work_dir = self.sandbox._setup_sandbox_dir()

            # Write system prompt file inside agent sandbox directory
            prompt_file = os.path.join(work_dir, "system_prompt.txt")
            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write(self.config.system_prompt)

            self.status = AgentStatus.RUNNING
            self.started_at = time.time()
            self._log(f"Agent '{self.config.name}' active in sandbox directory '{work_dir}'.")
            return True
        except Exception as e:
            self.status = AgentStatus.FAILED
            self._log(f"Spin-up failed: {e}")
            raise

    def terminate(self, graceful: bool = True) -> bool:
        """
        Gracefully terminates the agent instance and tears down its isolated sandbox.

        :param graceful: Whether to perform graceful cleanup.
        :return: True if termination succeeded.
        """
        if self.status in (AgentStatus.TERMINATED, AgentStatus.FAILED):
            return True

        self.status = AgentStatus.TERMINATING
        self._log(f"Terminating agent instance '{self.config.name}' (graceful={graceful})...")

        if self.sandbox:
            self.sandbox.cleanup()
            self.sandbox = None

        self.status = AgentStatus.TERMINATED
        self.stopped_at = time.time()
        self._log(f"Agent '{self.config.name}' terminated successfully.")
        return True

    def can_use_tool(self, tool_name: str) -> bool:
        """
        Checks whether this agent instance is permitted to execute tool_name.

        :param tool_name: Name of tool to check.
        :return: True if allowed, False otherwise.
        """
        return self.config.permissions.is_tool_allowed(tool_name)

    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Validates permission and executes tool/command within agent sandbox.

        :param tool_name: Name of tool to execute.
        :return: Result dictionary or SandboxResult.
        :raises PermissionError: If tool execution is denied by permissions.
        :raises RuntimeError: If agent is not running.
        """
        if not self.can_use_tool(tool_name):
            self._log(f"PERMISSION DENIED: Tool '{tool_name}' execution blocked for agent '{self.config.name}'.")
            raise PermissionError(f"Agent '{self.config.name}' lacks permission to execute tool '{tool_name}'.")

        if self.status != AgentStatus.RUNNING:
            raise RuntimeError(f"Cannot execute tool on agent '{self.config.name}' with status '{self.status.value}'.")

        self._log(f"Executing tool '{tool_name}' with arguments {kwargs}")

        if tool_name == "execute_shell" and "command" in kwargs and self.sandbox:
            res = self.sandbox.execute(kwargs["command"], env_overrides=self.config.environment)
            return {
                "agent": self.config.name,
                "tool": tool_name,
                "exit_code": res.exit_code,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "status": "SUCCESS" if res.exit_code == 0 else "FAILED",
            }

        return {
            "agent": self.config.name,
            "tool": tool_name,
            "args": kwargs,
            "status": "SUCCESS",
            "timestamp": time.time(),
        }

    def get_status(self) -> Dict[str, Any]:
        """Return detailed status information for the agent instance."""
        return {
            "agent_id": self.agent_id,
            "name": self.config.name,
            "role": self.config.role,
            "status": self.status.value,
            "system_prompt": self.config.system_prompt,
            "tools": self.config.tools,
            "permissions": self.config.permissions.to_dict(),
            "uptime_seconds": round(time.time() - self.started_at, 2) if self.started_at and not self.stopped_at else 0.0,
            "logs_count": len(self.logs),
        }


class SwarmStatus(str, Enum):
    """Swarm lifecycle status."""
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    TERMINATED = "TERMINATED"


class SwarmLifecycleManager:
    """
    Lifecycle orchestrator for multi-agent swarms defined via TDL.
    Manages collective spin-up, monitoring, and graceful teardown of agent topologies.
    """

    def __init__(self, topology: TDLTopology):
        self.topology = topology
        self.agents: Dict[str, AgentInstance] = {}
        self.status = SwarmStatus.CREATED

        for agent_cfg in topology.agents:
            instance = AgentInstance(config=agent_cfg)
            self.agents[agent_cfg.name] = instance

    def spin_up_swarm(self) -> List[AgentInstance]:
        """
        Spins up all agent instances defined in the TDL topology.

        :return: List of active AgentInstance objects.
        """
        spun_up: List[AgentInstance] = []
        failures = 0

        for name, agent in self.agents.items():
            try:
                if agent.spin_up():
                    spun_up.append(agent)
            except Exception:
                failures += 1

        if failures == 0 and len(spun_up) == len(self.agents):
            self.status = SwarmStatus.RUNNING
        elif spun_up:
            self.status = SwarmStatus.PARTIAL
        else:
            self.status = SwarmStatus.CREATED

        return spun_up

    def terminate_swarm(self, graceful: bool = True) -> Dict[str, bool]:
        """
        Gracefully terminates all running agent instances in the swarm topology.

        :param graceful: Whether to perform graceful cleanup.
        :return: Dict mapping agent names to termination success status.
        """
        results: Dict[str, bool] = {}
        for name, agent in self.agents.items():
            results[name] = agent.terminate(graceful=graceful)

        self.status = SwarmStatus.TERMINATED
        return results

    def get_agent(self, name_or_id: str) -> Optional[AgentInstance]:
        """
        Returns an agent instance by name or agent_id.

        :param name_or_id: Agent name or unique ID.
        :return: AgentInstance if found, None otherwise.
        """
        if name_or_id in self.agents:
            return self.agents[name_or_id]
        for agent in self.agents.values():
            if agent.agent_id == name_or_id:
                return agent
        return None

    def list_agents(self) -> List[AgentInstance]:
        """Returns a list of all agent instances in the swarm."""
        return list(self.agents.values())

    def get_swarm_status(self) -> Dict[str, Any]:
        """Returns a dictionary summary of overall swarm health and state."""
        agent_statuses = [a.get_status() for a in self.agents.values()]
        running_count = sum(1 for a in self.agents.values() if a.status == AgentStatus.RUNNING)
        return {
            "topology_name": self.topology.name,
            "version": self.topology.version,
            "swarm_status": self.status.value,
            "total_agents": len(self.agents),
            "running_agents": running_count,
            "agents": agent_statuses,
        }
