"""
Topology Definition Language (TDL) Parser & Swarm Agent Lifecycle Engine.
Parses topology.yaml configurations to instantiate isolated agent instances with distinct
system prompts, resource quotas, and tool permission boundaries, providing basic spin-up
and graceful termination lifecycle management.
"""

import os
import threading
import time
import uuid
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
import yaml

from .orchestrator import UniverseOrchestrator, Universe, UniverseStatus, ComputeQuota
from .isolation import SecurityViolation
from .messaging import Message, MessageBus, VirtualInbox
from .shared_context import SearchResult, SharedContext, VectorEntry


class TDLParseError(ValueError):
    """Raised when TDL YAML content is malformed or invalid."""
    pass


@dataclass
class ToolPermissions:
    """
    Tool permissions definition for an agent.
    Controls tool execution rights with allowed/denied lists and wildcard support.
    """
    allowed_tools: List[str] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)
    default_allow: bool = False

    def is_tool_allowed(self, tool_name: str) -> bool:
        """
        Checks whether execution of tool_name is permitted.

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
        """Serializes permissions to a dictionary."""
        return {
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
            "default_allow": self.default_allow,
        }

    @classmethod
    def from_dict(cls, data: Union[Dict[str, Any], List[str], None]) -> "ToolPermissions":
        """
        Parses ToolPermissions from a dict or list of allowed tools.
        """
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
class AgentConfig:
    """
    Configuration specification for a single agent instance within a TDL topology.
    """
    name: str
    role: str = "agent"
    system_prompt: str = ""
    tools: List[str] = field(default_factory=list)
    permissions: ToolPermissions = field(default_factory=ToolPermissions)
    quota: ComputeQuota = field(default_factory=ComputeQuota)
    environment: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts AgentConfig to a dictionary representation."""
        return {
            "name": self.name,
            "role": self.role,
            "system_prompt": self.system_prompt,
            "tools": self.tools,
            "permissions": self.permissions.to_dict(),
            "quota": {
                "cpu_cores": self.quota.cpu_cores,
                "memory_mb": self.quota.memory_mb,
                "max_threads": self.quota.max_threads,
                "max_processes": self.quota.max_processes,
            },
            "environment": self.environment,
            "metadata": self.metadata,
        }


@dataclass
class TDLTopology:
    """
    Parsed Topology Definition Language structure for an agent swarm.
    """
    version: str = "1.0"
    name: str = "swarm-topology"
    description: str = ""
    agents: List[AgentConfig] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_agent_config(self, name: str) -> Optional[AgentConfig]:
        """Returns the AgentConfig with the given name if found."""
        for agent in self.agents:
            if agent.name == name:
                return agent
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Converts topology to dictionary representation."""
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "agents": [a.to_dict() for a in self.agents],
            "metadata": self.metadata,
        }


class TDLParser:
    """
    Parser for Topology Definition Language (TDL) specifications in YAML or dictionary format.
    """

    @classmethod
    def parse_dict(cls, data: Dict[str, Any]) -> TDLTopology:
        """
        Parses a dictionary into a TDLTopology instance.

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
                raise TDLParseError(f"Agent entry at index {idx} missing required 'name' field.")
            agent_name = str(agent_name)

            if agent_name in seen_names:
                raise TDLParseError(f"Duplicate agent name '{agent_name}' in TDL topology.")
            seen_names.add(agent_name)

            role = str(agent_data.get("role", "agent"))
            system_prompt = str(
                agent_data.get("system_prompt")
                or agent_data.get("prompt")
                or ""
            )

            tools_raw = agent_data.get("tools") or []
            if isinstance(tools_raw, str):
                tools = [tools_raw]
            elif isinstance(tools_raw, list):
                tools = [str(t) for t in tools_raw]
            else:
                tools = []

            # Permissions resolution
            perm_data = agent_data.get("permissions") or agent_data.get("tool_permissions")
            if perm_data is not None:
                permissions = ToolPermissions.from_dict(perm_data)
            elif tools:
                permissions = ToolPermissions(allowed_tools=tools, default_allow=False)
            else:
                permissions = ToolPermissions(default_allow=True)

            # Compute Quota resolution
            quota_data = agent_data.get("quota") or agent_data.get("resources") or {}
            quota = ComputeQuota()
            if isinstance(quota_data, dict):
                if "cpu_cores" in quota_data or "cpus" in quota_data:
                    quota.cpu_cores = float(quota_data.get("cpu_cores") or quota_data.get("cpus") or 1.0)
                if "memory_mb" in quota_data or "memory" in quota_data:
                    quota.memory_mb = int(quota_data.get("memory_mb") or quota_data.get("memory") or 512)
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
        Parses a YAML string into a TDLTopology instance.

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
        Reads and parses a TDL topology file (YAML format).

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
            raise TDLParseError(f"Failed to read topology file '{file_path}': {err}") from err

        return cls.parse_yaml(content)


def parse_tdl(content_or_dict: Union[str, Dict[str, Any]]) -> TDLTopology:
    """
    Convenience function to parse TDL from a YAML string or dictionary.

    :param content_or_dict: TDL content as YAML string or parsed dict.
    :return: TDLTopology instance.
    """
    if isinstance(content_or_dict, dict):
        return TDLParser.parse_dict(content_or_dict)
    return TDLParser.parse_yaml(str(content_or_dict))


def parse_tdl_file(file_path: str) -> TDLTopology:
    """
    Convenience function to parse TDL from a file path.

    :param file_path: Path to topology YAML file.
    :return: TDLTopology instance.
    """
    return TDLParser.parse_file(file_path)


class AgentStatus(str, Enum):
    CREATED = "CREATED"
    SPINNING_UP = "SPINNING_UP"
    RUNNING = "RUNNING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class AgentInstance:
    """
    An active runtime instance of an Agent specified by TDL.
    Encapsulates its isolated Universe sandbox, system prompt, and tool execution boundaries.
    """

    def __init__(
        self,
        config: AgentConfig,
        orchestrator: Optional[UniverseOrchestrator] = None,
        agent_id: Optional[str] = None,
        message_bus: Optional[MessageBus] = None,
        shared_context: Optional[SharedContext] = None,
    ):
        self.agent_id = agent_id or f"agent-{config.name}-{uuid.uuid4().hex[:6]}"
        self.config = config
        self.orchestrator = orchestrator or UniverseOrchestrator()
        self.status = AgentStatus.CREATED
        self.universe: Optional[Universe] = None
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.logs: List[str] = []
        self.message_bus = message_bus or MessageBus()
        self.inbox: Optional[VirtualInbox] = None
        self.shared_context = shared_context or SharedContext()
        self.parent: Optional["AgentInstance"] = None
        self.parent_id: Optional[str] = None
        self.swarm_manager: Optional["SwarmLifecycleManager"] = None
        self._children: Dict[str, "AgentInstance"] = {}
        self._children_lock = threading.RLock()

    def log(self, message: str):
        """Appends a timestamped log entry."""
        entry = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ')}] [Agent:{self.config.name}] {message}"
        self.logs.append(entry)

    def spin_up(self) -> bool:
        """
        Spins up the agent instance, initializing its isolated sandbox universe,
        writing its system prompt, and starting process capabilities.

        :return: True if spin-up succeeded.
        """
        if self.status == AgentStatus.RUNNING:
            return True

        self.status = AgentStatus.SPINNING_UP
        self.log(f"Spinning up agent instance '{self.config.name}' (Role: {self.config.role})...")

        try:
            uv = self.orchestrator.create_universe(
                name=f"sandbox-{self.config.name}",
                quota=self.config.quota,
                metadata={
                    "agent_id": self.agent_id,
                    "agent_name": self.config.name,
                    "role": self.config.role,
                    "tools": self.config.tools,
                    "environment": self.config.environment,
                },
            )
            self.universe = uv

            # Store system prompt in sandbox virtual filesystem
            if self.config.system_prompt:
                uv.write_virtual_file("/etc/system_prompt.txt", self.config.system_prompt)

            self.status = AgentStatus.RUNNING
            self.inbox = self.message_bus.register_inbox(self.config.name)
            self.started_at = time.time()
            self.log(f"Agent instance '{self.config.name}' active in sandbox Universe '{uv.id}'.")
            return True
        except Exception as err:
            self.status = AgentStatus.FAILED
            self.log(f"Spin-up failed for agent '{self.config.name}': {err}")
            raise

    def terminate(self, graceful: bool = True, recursive: bool = True) -> bool:
        """
        Gracefully terminates the agent instance and tears down its isolated sandbox.

        :param graceful: Whether to perform graceful cleanup.
        :param recursive: Whether to also terminate all spawned sub-agents first.
        :return: True if termination succeeded.
        """
        if self.status in (AgentStatus.TERMINATED, AgentStatus.FAILED):
            return True

        self.status = AgentStatus.TERMINATING
        self.log(f"Terminating agent instance '{self.config.name}' (graceful={graceful})...")

        if recursive:
            for child in self.get_subagents():
                self.terminate_subagent(child.config.name, graceful=graceful)

        if self.universe:
            self.orchestrator.stop_universe(self.universe.id)
            self.orchestrator.destroy_universe(self.universe.id)
            self.universe = None
        self.message_bus.deregister_inbox(self.config.name)
        self.inbox = None

        self.status = AgentStatus.TERMINATED
        self.stopped_at = time.time()
        self.log(f"Agent instance '{self.config.name}' terminated successfully.")
        return True

    def can_use_tool(self, tool_name: str) -> bool:
        """
        Checks whether this agent instance is permitted to execute tool_name.

        :param tool_name: Name of the tool to query.
        :return: True if allowed.
        """
        return self.config.permissions.is_tool_allowed(tool_name)

    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Validates permission and simulates execution of a tool within the agent's sandbox boundary.

        :param tool_name: Name of tool to execute.
        :return: Execution summary dictionary.
        :raises SecurityViolation: If tool execution is denied by permissions.
        """
        if not self.can_use_tool(tool_name):
            self.log(f"SECURITY VIOLATION: Tool '{tool_name}' execution denied for agent '{self.config.name}'.")
            raise SecurityViolation(
                f"Agent '{self.config.name}' lacks permission to execute tool '{tool_name}'."
            )

        if self.status != AgentStatus.RUNNING:
            raise RuntimeError(f"Cannot execute tool on agent '{self.config.name}' with status '{self.status.value}'.")

        self.log(f"Executing tool '{tool_name}' with args {kwargs}")
        return {
            "agent": self.config.name,
            "tool": tool_name,
            "args": kwargs,
            "status": "SUCCESS",
            "timestamp": time.time(),
        }

    def send_message(self, recipient: str, body: Any, metadata: Optional[Dict[str, Any]] = None) -> Message:
        """Send a direct message from this agent."""
        return self.message_bus.send(self.config.name, recipient, body, metadata)

    def receive_messages(self, limit: Optional[int] = None, mark_read: bool = False) -> List[Message]:
        """Read messages from this agent's inbox in strict delivery order."""
        if self.inbox is None:
            return []
        messages = self.inbox.poll(limit=limit)
        if mark_read:
            for message in messages:
                self.inbox.mark_read(message.message_id)
        return messages

    def broadcast_message(self, body: Any, metadata: Optional[Dict[str, Any]] = None) -> List[Message]:
        """Broadcast a message from this agent to the other active agents."""
        return self.message_bus.broadcast(self.config.name, body, metadata)

    def unread_message_count(self) -> int:
        """Return the number of unread messages for this agent."""
        return self.inbox.unread_count if self.inbox else 0

    def set_shared_state(self, key: str, value: Any, owner: Optional[str] = None) -> int:
        """Write a key-value pair into the shared swarm memory."""
        return self.shared_context.remember(key, value, owner=owner or self.config.name)

    def get_shared_state(self, key: str, default: Any = None) -> Any:
        """Read a value from the shared swarm memory."""
        return self.shared_context.recall(key, default)

    def compare_and_set_shared_state(self, key: str, expected: Any, value: Any) -> bool:
        """Atomically update shared state only when ``key`` still equals ``expected``."""
        return self.shared_context.state.compare_and_set(
            key, expected, value, owner=self.config.name
        )

    def store_shared_vector(self, vector_id: str, vector: List[float],
                            metadata: Optional[Dict[str, Any]] = None) -> VectorEntry:
        """Store a context vector into the shared memory of the swarm."""
        return self.shared_context.store_vector(
            vector_id, vector, metadata, owner=self.config.name
        )

    def search_shared_vectors(self, vector: List[float], top_k: int = 10,
                              min_score: float = 0.0) -> List[SearchResult]:
        """Search the swarm's shared vectors for the closest matches."""
        return self.shared_context.query_vector(vector, top_k=top_k, min_score=min_score)

    def get_status(self) -> Dict[str, Any]:
        """Returns detailed status information for the agent instance."""
        return {
            "agent_id": self.agent_id,
            "name": self.config.name,
            "role": self.config.role,
            "status": self.status.value,
            "system_prompt": self.config.system_prompt,
            "tools": self.config.tools,
            "permissions": self.config.permissions.to_dict(),
            "universe_id": self.universe.id if self.universe else None,
            "uptime_seconds": round(time.time() - self.started_at, 2) if self.started_at and not self.stopped_at else 0.0,
            "logs_count": len(self.logs),
            "parent_id": self.parent_id,
            "subagent_count": len(self.get_subagents()),
        }

    def spawn_subagent(
        self,
        config: AgentConfig,
        spin_up: bool = True,
        agent_id: Optional[str] = None,
    ) -> "AgentInstance":
        """
        Dynamically spawn a child sub-agent under this running agent.

        The child inherits this agent's orchestrator, message bus, and shared
        context so it can communicate and cooperate with the rest of the swarm.
        When this agent belongs to a :class:`SwarmLifecycleManager`, the spawned
        sub-agent is registered with the swarm for monitoring and bulk teardown.

        :param config: Configuration for the sub-agent to spawn.
        :param spin_up: Whether to immediately spin the sub-agent up.
        :param agent_id: Optional explicit agent id for the sub-agent.
        :return: The newly spawned :class:`AgentInstance`.
        :raises RuntimeError: If this agent is not currently RUNNING.
        :raises ValueError: If a sub-agent with the same name already exists
            beneath this agent, or the name is already tracked by the swarm.
        """
        if self.status != AgentStatus.RUNNING:
            raise RuntimeError(
                f"Cannot spawn sub-agent from agent '{self.config.name}' "
                f"with status '{self.status.value}'."
            )

        child = AgentInstance(
            config=config,
            orchestrator=self.orchestrator,
            agent_id=agent_id,
            message_bus=self.message_bus,
            shared_context=self.shared_context,
        )
        child.parent = self
        child.parent_id = self.agent_id
        with self._children_lock:
            if config.name in self._children:
                raise ValueError(
                    f"Sub-agent '{config.name}' already exists under agent "
                    f"'{self.config.name}'."
                )
            self._children[config.name] = child
        if self.swarm_manager is not None:
            self.swarm_manager.register_agent(child)
        self.log(f"Spawned sub-agent '{config.name}' (agent_id={child.agent_id}).")
        if spin_up:
            child.spin_up()
        return child

    def get_subagents(self) -> List["AgentInstance"]:
        """Return the sub-agents currently spawned directly under this agent."""
        with self._children_lock:
            return list(self._children.values())

    def get_child(self, name: str) -> Optional["AgentInstance"]:
        """Return a directly spawned sub-agent by name, or ``None`` when absent."""
        with self._children_lock:
            return self._children.get(name)

    def terminate_subagent(self, name: str, graceful: bool = True) -> bool:
        """
        Terminate and remove a directly spawned sub-agent by name.

        :param name: Name of the sub-agent to terminate.
        :param graceful: Whether to perform graceful cleanup.
        :return: True if the sub-agent existed and was terminated.
        """
        with self._children_lock:
            child = self._children.pop(name, None)
        if child is None:
            return False
        child.terminate(graceful=graceful, recursive=True)
        return True

    def get_descendants(self) -> List["AgentInstance"]:
        """Return every transitive sub-agent beneath this agent, depth-first."""
        descendants: List["AgentInstance"] = []
        for child in self.get_subagents():
            descendants.append(child)
            descendants.extend(child.get_descendants())
        return descendants


class SwarmStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    TERMINATED = "TERMINATED"


class SwarmLifecycleManager:
    """
    Lifecycle orchestrator for multi-agent swarms defined via TDL.
    Manages collective spin-up, monitoring, and graceful teardown of agent topologies.
    """

    def __init__(
        self,
        topology: TDLTopology,
        orchestrator: Optional[UniverseOrchestrator] = None,
        message_bus: Optional[MessageBus] = None,
        shared_context: Optional[SharedContext] = None,
    ):
        self.topology = topology
        self.orchestrator = orchestrator or UniverseOrchestrator()
        self.message_bus = message_bus or MessageBus()
        self.shared_context = shared_context or SharedContext()
        self.agents: Dict[str, AgentInstance] = {}
        self.status = SwarmStatus.CREATED

        for agent_cfg in topology.agents:
            instance = AgentInstance(
                config=agent_cfg,
                orchestrator=self.orchestrator,
                message_bus=self.message_bus,
                shared_context=self.shared_context,
            )
            instance.swarm_manager = self
            self.agents[agent_cfg.name] = instance

    def register_agent(self, agent: AgentInstance) -> None:
        """
        Register a dynamically spawned agent with this swarm for monitoring.

        :param agent: The spawned :class:`AgentInstance` to register.
        :raises ValueError: If an agent with the same name is already tracked.
        """
        if agent.config.name in self.agents:
            raise ValueError(
                f"Agent '{agent.config.name}' is already registered in this swarm."
            )
        agent.swarm_manager = self
        self.agents[agent.config.name] = agent

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

        :param graceful: Whether to shutdown gracefully.
        :return: Dict mapping agent names to termination success status.
        """
        results: Dict[str, bool] = {}
        for name, agent in self.agents.items():
            results[name] = agent.terminate(graceful=graceful)

        self.status = SwarmStatus.TERMINATED
        return results

    def get_agent(self, name_or_id: str) -> Optional[AgentInstance]:
        """Returns an agent instance by name or agent_id."""
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

    def send_message(self, sender: str, recipient: str, body: Any,
                     metadata: Optional[Dict[str, Any]] = None) -> Message:
        """Send a direct message between agents in this swarm."""
        return self.message_bus.send(sender, recipient, body, metadata)

    def broadcast_message(self, sender: str, body: Any,
                          metadata: Optional[Dict[str, Any]] = None) -> List[Message]:
        """Broadcast a message to all other active agents in this swarm."""
        return self.message_bus.broadcast(sender, body, metadata)

    def get_inbox(self, owner: str) -> Optional[VirtualInbox]:
        """Return the virtual inbox for a swarm agent."""
        return self.message_bus.get_inbox(owner)

    def get_shared_context(self) -> SharedContext:
        """Return the shared context (state + vector store) for this swarm."""
        return self.shared_context
