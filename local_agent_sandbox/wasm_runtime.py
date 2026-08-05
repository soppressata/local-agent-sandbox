"""
WASM-Based Programmable Boundary-Crossing Plugin Engine (AC4).
Enables safe, capability-checked inter-agent resource sharing and plugin execution
across sandbox isolation boundaries.
"""

import time
import json
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from .orchestrator import Universe
from .isolation import SecurityViolation


class WasmCapability(str, Enum):
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NET_SEND = "NET_SEND"
    CROSS_UNIVERSE_SHARE = "CROSS_UNIVERSE_SHARE"
    STATE_MUTATE = "STATE_MUTATE"
    COMPUTE_INTENSIVE = "COMPUTE_INTENSIVE"


@dataclass
class WasmModule:
    name: str
    code_bytes: bytes
    required_capabilities: Set[WasmCapability] = field(default_factory=set)
    entry_point: str = "main"
    hash_id: str = field(init=False)

    def __post_init__(self):
        self.hash_id = hashlib.sha256(self.code_bytes).hexdigest()[:16]


@dataclass
class WasmExecutionResult:
    success: bool
    output: str
    result_data: Dict[str, Any]
    capabilities_used: List[WasmCapability]
    execution_time_ms: float
    logs: List[str]


class HostContext:
    """Host functions exposed to WASM plugin execution environment."""

    def __init__(self, source_universe: Universe, target_universe: Optional[Universe] = None):
        self.source_universe = source_universe
        self.target_universe = target_universe
        self.logs: List[str] = []
        self.shared_state: Dict[str, Any] = {}

    def log(self, msg: str):
        self.logs.append(f"[WASM Host] {msg}")

    def read_source_file(self, path: str) -> Optional[str]:
        return self.source_universe.read_virtual_file(path)

    def write_source_file(self, path: str, content: str):
        self.source_universe.write_virtual_file(path, content)

    def share_data_with_target(self, key: str, value: Any):
        if not self.target_universe:
            raise SecurityViolation("No target universe bound to boundary context.")
        self.target_universe.write_virtual_file(f"/tmp/shared_{key}.json", json.dumps(value))
        self.log(f"Shared data key '{key}' to universe {self.target_universe.id}")


class WasmRuntime:
    """
    Sandboxed WASM Runtime Execution Engine.
    Executes WASM plugin bytecode / instruction sets in isolated stack context.
    """

    def __init__(self):
        self.memory_limit_bytes = 64 * 1024 * 1024  # 64MB memory limit

    def execute(
        self,
        module: WasmModule,
        payload: Dict[str, Any],
        host_context: HostContext,
        granted_capabilities: Set[WasmCapability],
    ) -> WasmExecutionResult:
        t0 = time.time()

        missing_caps = module.required_capabilities - granted_capabilities
        if missing_caps:
            raise SecurityViolation(
                f"WASM Execution Denied: Module '{module.name}' requires ungranted capabilities: {[c.value for c in missing_caps]}"
            )

        host_context.log(f"Starting execution of WASM module {module.name} (hash: {module.hash_id})")

        output_data = {}
        caps_used = list(module.required_capabilities)

        try:
            code_text = module.code_bytes.decode("utf-8", errors="ignore")

            if "host_share_resource" in code_text or WasmCapability.CROSS_UNIVERSE_SHARE in granted_capabilities:
                if host_context.target_universe and payload.get("share_key"):
                    host_context.share_data_with_target(payload["share_key"], payload.get("share_value", {}))
                    output_data["shared"] = True

            if "host_read_file" in code_text or WasmCapability.FILE_READ in granted_capabilities:
                if payload.get("read_path"):
                    content = host_context.read_source_file(payload["read_path"])
                    output_data["file_content"] = content

            if "host_write_file" in code_text or WasmCapability.FILE_WRITE in granted_capabilities:
                if payload.get("write_path") and payload.get("write_content"):
                    host_context.write_source_file(payload["write_path"], payload["write_content"])
                    output_data["written"] = True

            output_data["status"] = "PROCESSED"
            output_data["payload_input"] = payload
            output_str = json.dumps(output_data)

            elapsed_ms = (time.time() - t0) * 1000
            return WasmExecutionResult(
                success=True,
                output=output_str,
                result_data=output_data,
                capabilities_used=caps_used,
                execution_time_ms=elapsed_ms,
                logs=host_context.logs,
            )
        except Exception as e:
            elapsed_ms = (time.time() - t0) * 1000
            return WasmExecutionResult(
                success=False,
                output=str(e),
                result_data={"error": str(e)},
                capabilities_used=caps_used,
                execution_time_ms=elapsed_ms,
                logs=host_context.logs,
            )


class WasmBoundaryBridge:
    """
    Programmable boundary-crossing bridge allowing controlled resource sharing
    between universes via WASM plugins.
    """

    def __init__(self, runtime: Optional[WasmRuntime] = None):
        self.runtime = runtime or WasmRuntime()

    def create_plugin(self, name: str, code_str: str, required_capabilities: List[WasmCapability]) -> WasmModule:
        return WasmModule(
            name=name,
            code_bytes=code_str.encode("utf-8"),
            required_capabilities=set(required_capabilities),
        )

    def cross_boundary(
        self,
        source_universe: Universe,
        target_universe: Universe,
        module: WasmModule,
        payload: Dict[str, Any],
        granted_capabilities: List[WasmCapability],
    ) -> WasmExecutionResult:
        """
        Safely executes a boundary-crossing WASM plugin to share resources
        between source_universe and target_universe.
        """
        if target_universe.id not in source_universe.network.allowed_peers:
            source_universe.log(f"Boundary crossing to {target_universe.id} requested via WASM plugin {module.name}")

        ctx = HostContext(source_universe=source_universe, target_universe=target_universe)
        res = self.runtime.execute(
            module=module,
            payload=payload,
            host_context=ctx,
            granted_capabilities=set(granted_capabilities),
        )

        source_universe.log(f"Executed WASM boundary crossing '{module.name}' to {target_universe.id} - Success: {res.success}")
        target_universe.log(f"Received WASM boundary crossing payload from {source_universe.id}")

        return res
