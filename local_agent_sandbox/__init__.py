"""
LocalAgentSandbox Package
Sub-10ms process isolation container for AI coding agents.
"""

__version__ = "0.1.0"

from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig, SandboxResult
from local_agent_sandbox.policy import PolicyMemoryEngine
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
from local_agent_sandbox.messaging import (
    MessageBus, VirtualInbox, Message, MessageKind, InboxNotFoundError,
    InboxOverflowError,
)
from local_agent_sandbox.shared_context import (
    SharedContext, SharedStateStore, SharedVectorStore, StateEntry,
    VectorEntry, SearchResult,
)
from local_agent_sandbox.observability import (
    build_topology,
    build_snapshot,
    render_dashboard,
    monitor,
)

__all__ = [
    "LocalAgentSandbox",
    "SandboxConfig",
    "SandboxResult",
    "PolicyMemoryEngine",
    "TDLParser",
    "TDLTopology",
    "AgentConfig",
    "ToolPermissions",
    "AgentInstance",
    "AgentStatus",
    "SwarmLifecycleManager",
    "SwarmStatus",
    "TDLParseError",
    "parse_tdl",
    "parse_tdl_file",
    "MessageBus",
    "VirtualInbox",
    "Message",
    "MessageKind",
    "InboxNotFoundError",
    "InboxOverflowError",
    "SharedContext",
    "SharedStateStore",
    "SharedVectorStore",
    "StateEntry",
    "VectorEntry",
    "SearchResult",
    "build_topology",
    "build_snapshot",
    "render_dashboard",
    "monitor",
]
