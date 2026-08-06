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
from local_agent_sandbox.trustfile import (
    DEFAULT_SYSCALLS,
    TRUSTFILE_SCHEMA_V1,
    EgressRule,
    Mount,
    NetworkPolicy,
    ResourceCaps,
    SecretRef,
    TrustfileSpec,
    TrustfileValidationError,
    apply_mounts,
    load_trustfile,
    parse_trustfile,
    sandbox_config_to_trustfile,
    trustfile_digest,
    validate_schema,
)
from local_agent_sandbox.receipt import (
    EnforcementSummary,
    NodeInfo,
    PolicyCheck,
    Receipt,
    ReceiptStore,
    SignedReceipt,
    generate_keypair,
    get_or_create_signing_key,
    key_id_from_public,
    load_public_key,
    receipt_to_sbom,
    sign_receipt,
    verify_receipt,
)
from local_agent_sandbox.query import (
    BinExpr,
    Expr,
    NotExpr,
    Predicate,
    QuerySyntaxError,
    filter_receipts,
    parse_query,
)
from local_agent_sandbox.run import (
    LocalNodeResolver,
    ProfileEnforcer,
    RunEngine,
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
    "DEFAULT_SYSCALLS",
    "TRUSTFILE_SCHEMA_V1",
    "EgressRule",
    "Mount",
    "NetworkPolicy",
    "ResourceCaps",
    "SecretRef",
    "TrustfileSpec",
    "TrustfileValidationError",
    "apply_mounts",
    "load_trustfile",
    "parse_trustfile",
    "sandbox_config_to_trustfile",
    "trustfile_digest",
    "validate_schema",
    "EnforcementSummary",
    "NodeInfo",
    "PolicyCheck",
    "Receipt",
    "ReceiptStore",
    "SignedReceipt",
    "generate_keypair",
    "get_or_create_signing_key",
    "key_id_from_public",
    "load_public_key",
    "receipt_to_sbom",
    "sign_receipt",
    "verify_receipt",
    "BinExpr",
    "Expr",
    "NotExpr",
    "Predicate",
    "QuerySyntaxError",
    "filter_receipts",
    "parse_query",
    "LocalNodeResolver",
    "ProfileEnforcer",
    "RunEngine",
]


"""
Local Agent Sandbox - The Multi-Verse Agent Ecology.
N-Dimensional Isolated Sandbox Meshing Architecture.
"""

__version__ = "1.0.0"

from .orchestrator import UniverseOrchestrator, Universe, UniverseStatus, ComputeQuota
from .mesh import MeshNetworkManager, TrustPolicy, TrustRule, MeshChannel, CertificateAuthority
from .graphql_api import GodModeGraphQLAPI
from .isolation import (
    ResourceIsolationEngine,
    StorageJail,
    NetworkJail,
    SecurityViolation,
    EnforcementCounters,
    GLOBAL_COUNTERS,
    RunReceipt,
    KernelPolicy,
    FilesystemPolicy,
    NetworkEgressProxy,
    SecretVault,
    PolicyEnforcementEngine,
    AntiRegressionSuite,
)
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
    "SecurityViolation",
    "EnforcementCounters",
    "GLOBAL_COUNTERS",
    "RunReceipt",
    "KernelPolicy",
    "FilesystemPolicy",
    "NetworkEgressProxy",
    "SecretVault",
    "PolicyEnforcementEngine",
    "AntiRegressionSuite",
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
