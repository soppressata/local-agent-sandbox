"""
Topology Definition Language (TDL) parser and basic agent lifecycle management.

Parses topology.yaml configurations to instantiate isolated agent instances with
distinct system prompts and tool permission boundaries, and provides spin-up and
graceful termination lifecycle management.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

import yaml


class TDLParseError(ValueError):
    """Raised when TDL YAML content is malformed or invalid."""


class SecurityViolation(PermissionError):
    """Raised when an agent attempts a tool it is not permitted to use."""


@dataclass
class ToolPermissions:
    """Tool execution rights with allowed/denied lists and optional wildcards."""

    allowed_tools: List[str] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)
    default_allow: bool = False

    def is_tool_allowed(self, tool_name: str) -> bool:
        """
        Return whether execution of ``tool_name`` is permitted.

        :param tool_name: Name of the tool to validate.
        :return: True if allowed, False if denied.
        """
        if tool_name in self.denied_tools or "*" in self.denied_tools:
            return False
        if "*" in self.allowed_tools or tool_name in self.allowed_tools:
            return True
        if not self.allowed_tools:
            return self.default_allow
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize permissions to a dictionary."""
        return {
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
            "default_allow": self.default_allow,
        }

    @classmethod
    def from_dict(cls, data: Union[Dict[str, Any], List[str], None]) -> "ToolPermissions":
        """Parse ToolPermissions from a dict or list of allowed tools."""
        if data is None:
            return cls()
        if isinstance(data, list):
            return cls(allowed_tools=[str(t) for t in data])
        if isinstance(data, dict):
            allowed = data.get("allowed_tools") or data.get("allowed") or []
            denied = data.get("denied_tools") or data.get("denied") or []
            default_allow = bool(data.get("default_allow", False))
            if isinstance(allowed, str):
                allowed = [allowed]
            if isinstance(denied, str):
                denied = [denied]
            return cls(
                allowed_tools=[str(t) for t in allowed],
                denied_tools=[str(t) for t in denied],
                default_allow=default_allow,
            )
        return cls()


@dataclass
class ComputeQuota:
    """Optional resource quota for an agent instance."""

    cpu_cores: float = 1.0
    memory_mb: int = 512
    max_threads: int = 16
    max_processes: int = 8


@dataclass
class AgentConfig:
    """Configuration for a single agent instance within a TDL topology."""

    name: str
    role: str = "agent"
    system_prompt: str = ""
    tools: List[str] = field(default_factory=list)
    permissions: ToolPermissions = field(default_factory=ToolPermissions)
    quota: ComputeQuota = field(default_factory=ComputeQuota)
    environment: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert AgentConfig to a dictionary representation."""
        return {
            "name": self.name,
            "role": self.role,
            "system_prompt": self.system_prompt,
            "tools": list(self.tools),
            "permissions": self.permissions.to_dict(),
            "quota": {
                "cpu_cores": self.quota.cpu_cores,
                "memory_mb": self.quota.memory_mb,
                "max_threads": self.quota.max_threads,
                "max_processes": self.quota.max_processes,
            },
            "environment": dict(self.environment),
            "metadata": dict(self.metadata),
        }


@dataclass
class TDLTopology:
    """Parsed Topology Definition Language structure for an agent swarm."""

    version: str = "1.0"
    name: str = "swarm-topology"
    description: str = ""
    agents: List[AgentConfig] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_agent_config(self, name: str) -> Optional[AgentConfig]:
        """Return the AgentConfig with the given name, or None."""
        for agent in self.agents:
            if agent.name == name:
                return agent
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert topology to dictionary representation."""
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "agents": [a.to_dict() for a in self.agents],
            "metadata": dict(self.metadata),
        }


class TDLParser:
    """Parser for Topology Definition Language specifications (YAML or dict)."""

    @classmethod
    def parse_dict(cls, data: Dict[str, Any]) -> TDLTopology:
        """
        Parse a dictionary into a TDLTopology instance.

        :param data: Dictionary containing TDL topology fields.
        :return: TDLTopology instance.
        :raises TDLParseError: If parsing fails or required fields are missing.
        """
        if not isinstance(data, dict):
            raise TDLParseError("TDL document must be a key-value dictionary.")

        version = str(data.get("version", "1.0"))
        name = str(data.get("name") or data.get("topology_name") or "swarm-topology")
        description = str(data.get("description", ""))
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        raw_agents = data.get("agents")
        if raw_agents is None:
            raise TDLParseError("TDL configuration missing 'agents' list.")
        if not isinstance(raw_agents, list):
            raise TDLParseError("'agents' field in TDL topology must be a list.")

        agent_configs: List[AgentConfig] = []
        seen_names: Set[str] = set()

        for idx, agent_data in enumerate(raw_agents):
            if not isinstance(agent_data, dict):
                raise TDLParseError(f"Agent entry at index {idx} must be a dictionary.")

            agent_name = agent_data.get("name")
            if not agent_name:
                raise TDLParseError(
                    f"Agent entry at index {idx} missing required 'name' field."
                )
            agent_name = str(agent_name)

            if agent_name in seen_names:
                raise TDLParseError(f"Duplicate agent name '{agent_name}' in TDL topology.")
            seen_names.add(agent_name)

            role = str(agent_data.get("role", "agent"))
            system_prompt = str(
                agent_data.get("system_prompt") or agent_data.get("prompt") or ""
            )

            tools_raw = agent_data.get("tools") or []
            if isinstance(tools_raw, str):
                tools = [tools_raw]
            elif isinstance(tools_raw, list):
                tools = [str(t) for t in tools_raw]
            else:
                tools = []

            perm_data = agent_data.get("permissions") or agent_data.get("tool_permissions")
            if perm_data is not None:
                permissions = ToolPermissions.from_dict(perm_data)
            elif tools:
                permissions = ToolPermissions(allowed_tools=list(tools), default_allow=False)
            else:
                permissions = ToolPermissions(default_allow=True)

            quota_data = agent_data.get("quota") or agent_data.get("resources") or {}
            quota = ComputeQuota()
            if isinstance(quota_data, dict):
                if "cpu_cores" in quota_data or "cpus" in quota_data:
                    quota.cpu_cores = float(
                        quota_data.get("cpu_cores") or quota_data.get("cpus") or 1.0
                    )
                if "memory_mb" in quota_data or "memory" in quota_data:
                    quota.memory_mb = int(
                        quota_data.get("memory_mb") or quota_data.get("memory") or 512
                    )
                if "max_threads" in quota_data:
                    quota.max_threads = int(quota_data["max_threads"])
                if "max_processes" in quota_data:
                    quota.max_processes = int(quota_data["max_processes"])

            env_data = agent_data.get("environment") or agent_data.get("env") or {}
            if not isinstance(env_data, dict):
                env_data = {}
            env = {str(k): str(v) for k, v in env_data.items()}

            agent_meta = agent_data.get("metadata") or {}
            if not isinstance(agent_meta, dict):
                agent_meta = {}

            agent_configs.append(
                AgentConfig(
                    name=agent_name,
                    role=role,
                    system_prompt=system_prompt,
                    tools=tools,
                    permissions=permissions,
                    quota=quota,
                    environment=env,
                    metadata=agent_meta,
                )
            )

        return TDLTopology(
            version=version,
            name=name,
            description=description,
            agents=agent_configs,
            metadata=metadata,
        )

    @classmethod
    def parse_yaml(cls, yaml_str: str) -> TDLTopology:
        """
        Parse a YAML string into a TDLTopology instance.

        :param yaml_str: YAML formatted string.
        :return: TDLTopology instance.
        :raises TDLParseError: If YAML syntax or content validation fails.
        """
        try:
            parsed = yaml.safe_load(yaml_str)
        except Exception as err:
            raise TDLParseError(f"Failed to parse YAML content: {err}") from err

        if not parsed:
            raise TDLParseError("Empty TDL YAML document.")

        return cls.parse_dict(parsed)

    @classmethod
    def parse_file(cls, file_path: str) -> TDLTopology:
        """
        Read and parse a TDL topology file (YAML format).

        :param file_path: Path to topology file (e.g., topology.yaml).
        :return: TDLTopology instance.
        :raises TDLParseError: If file cannot be read or parsed.
        """
        if not os.path.exists(file_path):
            raise TDLParseError(f"Topology file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as err:
            raise TDLParseError(
                f"Failed to read topology file '{file_path}': {err}"
            ) from err

        return cls.parse_yaml(content)


def parse_tdl(content_or_dict: Union[str, Dict[str, Any]]) -> TDLTopology:
    """
    Parse TDL from a YAML string or dictionary.

    :param content_or_dict: TDL content as YAML string or parsed dict.
    :return: TDLTopology instance.
    """
    if isinstance(content_or_dict, dict):
        return TDLParser.parse_dict(content_or_dict)
    return TDLParser.parse_yaml(str(content_or_dict))


def parse_tdl_file(file_path: str) -> TDLTopology:
    """
    Parse TDL from a file path.

    :param file_path: Path to topology YAML file.
    :return: TDLTopology instance.
    """
    return TDLParser.parse_file(file_path)


class AgentStatus(str, Enum):
    """Lifecycle status of an agent instance."""

    CREATED = "CREATED"
    SPINNING_UP = "SPINNING_UP"
    RUNNING = "RUNNING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class AgentInstance:
    """
    Runtime instance of an agent specified by TDL.

    Holds system prompt, tool permission boundaries, and a lightweight isolated
    workspace used during the agent lifetime.
    """

    def __init__(self, config: AgentConfig, agent_id: Optional[str] = None):
        self.agent_id = agent_id or f"agent-{config.name}-{uuid.uuid4().hex[:6]}"
        self.config = config
        self.status = AgentStatus.CREATED
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.logs: List[str] = []
        self._workspace: Dict[str, str] = {}
        self._running = False

    def log(self, message: str) -> None:
        """Append a timestamped log entry."""
        entry = (
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
            f"[Agent:{self.config.name}] {message}"
        )
        self.logs.append(entry)

    def write_virtual_file(self, path: str, content: str) -> None:
        """Write content into the agent isolated workspace."""
        self._workspace[path] = content

    def read_virtual_file(self, path: str) -> Optional[str]:
        """Read content from the agent isolated workspace."""
        return self._workspace.get(path)

    def spin_up(self) -> bool:
        """
        Spin up the agent instance.

        Initializes isolated workspace state, stores the system prompt, and marks
        the agent as running.

        :return: True if spin-up succeeded.
        """
        if self.status == AgentStatus.RUNNING:
            return True

        self.status = AgentStatus.SPINNING_UP
        self.log(
            f"Spinning up agent instance '{self.config.name}' "
            f"(Role: {self.config.role})..."
        )

        try:
            self._workspace = {}
            if self.config.system_prompt:
                self.write_virtual_file("/etc/system_prompt.txt", self.config.system_prompt)
            if self.config.environment:
                env_blob = "\n".join(f"{k}={v}" for k, v in self.config.environment.items())
                self.write_virtual_file("/etc/environment", env_blob)

            self._running = True
            self.status = AgentStatus.RUNNING
            self.started_at = time.time()
            self.log(f"Agent instance '{self.config.name}' is now RUNNING.")
            return True
        except Exception as err:
            self.status = AgentStatus.FAILED
            self._running = False
            self.log(f"Spin-up failed for agent '{self.config.name}': {err}")
            raise

    def terminate(self, graceful: bool = True) -> bool:
        """
        Gracefully terminate the agent instance and clear its workspace.

        :param graceful: Whether to perform graceful cleanup.
        :return: True if termination succeeded.
        """
        if self.status in (AgentStatus.TERMINATED, AgentStatus.FAILED):
            return True

        self.status = AgentStatus.TERMINATING
        self.log(
            f"Terminating agent instance '{self.config.name}' (graceful={graceful})..."
        )

        self._workspace.clear()
        self._running = False
        self.status = AgentStatus.TERMINATED
        self.stopped_at = time.time()
        self.log(f"Agent instance '{self.config.name}' terminated successfully.")
        return True

    def can_use_tool(self, tool_name: str) -> bool:
        """
        Return whether this agent instance may execute ``tool_name``.

        :param tool_name: Name of the tool to query.
        :return: True if allowed.
        """
        return self.config.permissions.is_tool_allowed(tool_name)

    def execute_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """
        Validate permission and simulate tool execution within the agent boundary.

        :param tool_name: Name of tool to execute.
        :return: Execution summary dictionary.
        :raises SecurityViolation: If tool execution is denied by permissions.
        """
        if not self.can_use_tool(tool_name):
            self.log(
                f"SECURITY VIOLATION: Tool '{tool_name}' execution denied for "
                f"agent '{self.config.name}'."
            )
            raise SecurityViolation(
                f"Agent '{self.config.name}' lacks permission to execute tool '{tool_name}'."
            )

        if self.status != AgentStatus.RUNNING:
            raise RuntimeError(
                f"Cannot execute tool on agent '{self.config.name}' "
                f"with status '{self.status.value}'."
            )

        self.log(f"Executing tool '{tool_name}' with args {kwargs}")
        return {
            "agent": self.config.name,
            "tool": tool_name,
            "args": kwargs,
            "status": "SUCCESS",
            "timestamp": time.time(),
        }

    def get_status(self) -> Dict[str, Any]:
        """Return detailed status information for the agent instance."""
        uptime = 0.0
        if self.started_at and not self.stopped_at:
            uptime = round(time.time() - self.started_at, 2)
        return {
            "agent_id": self.agent_id,
            "name": self.config.name,
            "role": self.config.role,
            "status": self.status.value,
            "system_prompt": self.config.system_prompt,
            "tools": list(self.config.tools),
            "permissions": self.config.permissions.to_dict(),
            "running": self._running,
            "uptime_seconds": uptime,
            "logs_count": len(self.logs),
        }


class SwarmStatus(str, Enum):
    """Lifecycle status of a multi-agent swarm."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    TERMINATED = "TERMINATED"


class SwarmLifecycleManager:
    """
    Lifecycle manager for multi-agent swarms defined via TDL.

    Handles collective spin-up and graceful teardown of agent instances.
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
        Spin up all agent instances defined in the TDL topology.

        :return: List of successfully started AgentInstance objects.
        """
        spun_up: List[AgentInstance] = []
        failures = 0

        for agent in self.agents.values():
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
        Gracefully terminate all agent instances in the swarm.

        :param graceful: Whether to shut down gracefully.
        :return: Dict mapping agent names to termination success status.
        """
        results: Dict[str, bool] = {}
        for name, agent in self.agents.items():
            results[name] = agent.terminate(graceful=graceful)

        self.status = SwarmStatus.TERMINATED
        return results

    def get_agent(self, name_or_id: str) -> Optional[AgentInstance]:
        """Return an agent instance by name or agent_id."""
        if name_or_id in self.agents:
            return self.agents[name_or_id]
        for agent in self.agents.values():
            if agent.agent_id == name_or_id:
                return agent
        return None

    def list_agents(self) -> List[AgentInstance]:
        """Return a list of all agent instances in the swarm."""
        return list(self.agents.values())

    def get_swarm_status(self) -> Dict[str, Any]:
        """Return a summary of overall swarm health and state."""
        agent_statuses = [a.get_status() for a in self.agents.values()]
        running_count = sum(
            1 for a in self.agents.values() if a.status == AgentStatus.RUNNING
        )
        return {
            "topology_name": self.topology.name,
            "version": self.topology.version,
            "swarm_status": self.status.value,
            "total_agents": len(self.agents),
            "running_agents": running_count,
            "agents": agent_statuses,
        }
