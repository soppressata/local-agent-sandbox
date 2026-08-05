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
]
