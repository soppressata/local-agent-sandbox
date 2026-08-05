"""
Unit tests for Default Isolation and WASM Boundary Plugins (AC4).
"""

import pytest
from local_agent_sandbox.orchestrator import UniverseOrchestrator
from local_agent_sandbox.mesh import MeshNetworkManager
from local_agent_sandbox.isolation import ResourceIsolationEngine, SecurityViolation
from local_agent_sandbox.wasm_runtime import (
    WasmRuntime,
    WasmBoundaryBridge,
    WasmCapability,
)


def test_storage_and_network_isolation_enforcement():
    orchestrator = UniverseOrchestrator()
    uv1 = orchestrator.create_universe(name="iso-1")
    uv2 = orchestrator.create_universe(name="iso-2")

    iso_engine = ResourceIsolationEngine(uv1)

    with pytest.raises(SecurityViolation, match="Path traversal detected"):
        iso_engine.validate_file_write("../../../etc/passwd", 100)

    with pytest.raises(SecurityViolation, match="Storage quota exceeded"):
        iso_engine.validate_file_write("/large_blob.bin", 600 * 1024 * 1024)

    with pytest.raises(SecurityViolation, match="Network isolation active"):
        iso_engine.validate_network_transmit(target_universe_id=uv2.id, target_ip=uv2.network.virtual_ip)

    orchestrator.close()


def test_wasm_boundary_plugin_execution():
    orchestrator = UniverseOrchestrator()
    mesh = MeshNetworkManager()
    u1 = orchestrator.create_universe(name="wasm-src")
    u2 = orchestrator.create_universe(name="wasm-tgt")

    mesh.negotiate_channel(u1, u2)

    bridge = WasmBoundaryBridge()
    plugin_code = """
    (module
      (import "host" "host_share_resource" (func $host_share_resource))
      (func (export "main")
        call $host_share_resource
      )
    )
    """
    plugin = bridge.create_plugin(
        name="state-share-plugin",
        code_str=plugin_code,
        required_capabilities=[WasmCapability.CROSS_UNIVERSE_SHARE],
    )

    payload = {"share_key": "market_prices", "share_value": {"BTC": 95000, "ETH": 3500}}
    res = bridge.cross_boundary(
        source_universe=u1,
        target_universe=u2,
        module=plugin,
        payload=payload,
        granted_capabilities=[WasmCapability.CROSS_UNIVERSE_SHARE],
    )

    assert res.success is True
    assert res.result_data.get("shared") is True

    shared_data = u2.read_virtual_file("/tmp/shared_market_prices.json")
    assert shared_data is not None
    assert "95000" in shared_data

    with pytest.raises(SecurityViolation, match="requires ungranted capabilities"):
        bridge.cross_boundary(
            source_universe=u1,
            target_universe=u2,
            module=plugin,
            payload=payload,
            granted_capabilities=[],
        )

    orchestrator.close()
