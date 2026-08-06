"""
LocalAgentSandbox Package
Sub-10ms process isolation container for AI coding agents.
"""

__version__ = "0.1.0"

from local_agent_sandbox.core import LocalAgentSandbox, SandboxConfig, SandboxResult
from local_agent_sandbox.policy import PolicyMemoryEngine

__all__ = [
    "LocalAgentSandbox",
    "SandboxConfig",
    "SandboxResult",
    "PolicyMemoryEngine"
]


"""
Local Agent Sandbox - The Multi-Verse Agent Ecology.
N-Dimensional Isolated Sandbox Meshing Architecture.
"""

__version__ = "1.0.0"

from .orchestrator import UniverseOrchestrator, Universe, UniverseStatus, ComputeQuota
from .mesh import MeshNetworkManager, TrustPolicy, TrustRule, MeshChannel, CertificateAuthority
from .graphql_api import GodModeGraphQLAPI
from .isolation import ResourceIsolationEngine, StorageJail, NetworkJail
from .wasm_runtime import WasmRuntime, WasmModule, WasmBoundaryBridge, WasmCapability
from .dashboard import DashboardServer
from .onboarding import OnboardingWizard
from .diagnostics import (
    AIDiagnosticsEngine,
    FailedStepContext,
    DiagnosisReport,
    BaseProviderAdapter,
    GoogleAdapter,
    OpenAIAdapter,
    AnthropicAdapter,
    get_provider_adapter,
)
from .pipeline_generator import (
    AIPipelineGenerator,
    AIPipelineResult,
    PipelineExecutionPlan,
    ArchitectureDocs,
    PipelineStep,
)
from .self_healing import (
    SelfHealingEngine,
    PatchGeneratorAgent,
    SelfHealingSandbox,
    GeneratedPatch,
    PatchVerificationResult,
    SelfHealingReport,
)
from .tdl import (
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

__all__ = [
    "UniverseOrchestrator",
    "Universe",
    "UniverseStatus",
    "ComputeQuota",
    "MeshNetworkManager",
    "TrustPolicy",
    "TrustRule",
    "MeshChannel",
    "CertificateAuthority",
    "GodModeGraphQLAPI",
    "ResourceIsolationEngine",
    "StorageJail",
    "NetworkJail",
    "WasmRuntime",
    "WasmModule",
    "WasmBoundaryBridge",
    "WasmCapability",
    "DashboardServer",
    "OnboardingWizard",
    "AIDiagnosticsEngine",
    "FailedStepContext",
    "DiagnosisReport",
    "BaseProviderAdapter",
    "GoogleAdapter",
    "OpenAIAdapter",
    "AnthropicAdapter",
    "get_provider_adapter",
    "AIPipelineGenerator",
    "AIPipelineResult",
    "PipelineExecutionPlan",
    "ArchitectureDocs",
    "PipelineStep",
    "SelfHealingEngine",
    "PatchGeneratorAgent",
    "SelfHealingSandbox",
    "GeneratedPatch",
    "PatchVerificationResult",
    "SelfHealingReport",
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
]


"""
Local Agent Sandbox - The Multi-Verse Agent Ecology.
N-Dimensional Isolated Sandbox Meshing Architecture.
"""

__version__ = "1.0.0"

from .orchestrator import UniverseOrchestrator, Universe, UniverseStatus, ComputeQuota
from .mesh import MeshNetworkManager, TrustPolicy, TrustRule, MeshChannel, CertificateAuthority
from .graphql_api import GodModeGraphQLAPI
from .isolation import ResourceIsolationEngine, StorageJail, NetworkJail
from .wasm_runtime import WasmRuntime, WasmModule, WasmBoundaryBridge, WasmCapability
from .dashboard import DashboardServer
from .onboarding import OnboardingWizard
from .diagnostics import (
    AIDiagnosticsEngine,
    FailedStepContext,
    DiagnosisReport,
    BaseProviderAdapter,
    GoogleAdapter,
    OpenAIAdapter,
    AnthropicAdapter,
    get_provider_adapter,
)
from .pipeline_generator import (
    AIPipelineGenerator,
    AIPipelineResult,
    PipelineExecutionPlan,
    ArchitectureDocs,
    PipelineStep,
)
from .self_healing import (
    SelfHealingEngine,
    PatchGeneratorAgent,
    SelfHealingSandbox,
    GeneratedPatch,
    PatchVerificationResult,
    SelfHealingReport,
)
from .tdl import (
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

__all__ = [
    "UniverseOrchestrator",
    "Universe",
    "UniverseStatus",
    "ComputeQuota",
    "MeshNetworkManager",
    "TrustPolicy",
    "TrustRule",
    "MeshChannel",
    "CertificateAuthority",
    "GodModeGraphQLAPI",
    "ResourceIsolationEngine",
    "StorageJail",
    "NetworkJail",
    "WasmRuntime",
    "WasmModule",
    "WasmBoundaryBridge",
    "WasmCapability",
    "DashboardServer",
    "OnboardingWizard",
    "AIDiagnosticsEngine",
    "FailedStepContext",
    "DiagnosisReport",
    "BaseProviderAdapter",
    "GoogleAdapter",
    "OpenAIAdapter",
    "AnthropicAdapter",
    "get_provider_adapter",
    "AIPipelineGenerator",
    "AIPipelineResult",
    "PipelineExecutionPlan",
    "ArchitectureDocs",
    "PipelineStep",
    "SelfHealingEngine",
    "PatchGeneratorAgent",
    "SelfHealingSandbox",
    "GeneratedPatch",
    "PatchVerificationResult",
    "SelfHealingReport",
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
]
