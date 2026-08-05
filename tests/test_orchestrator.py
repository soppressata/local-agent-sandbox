"""
Unit tests for High-Performance Sandbox Orchestrator (AC1).
"""

import time
import pytest
from local_agent_sandbox.orchestrator import (
    UniverseOrchestrator,
    Universe,
    UniverseStatus,
    ComputeQuota,
)
from local_agent_sandbox.rust_orchestrator import RustOrchestratorBridge


def test_single_universe_creation_and_vfs():
    orchestrator = UniverseOrchestrator()
    uv = orchestrator.create_universe(name="test-uv-1")

    assert uv.id.startswith("uv-")
    assert uv.status == UniverseStatus.RUNNING
    assert uv.name == "test-uv-1"

    change = uv.write_virtual_file("/app/config.json", '{"key": "value"}')
    assert change.action == "CREATE"
    assert change.path == "/app/config.json"

    content = uv.read_virtual_file("/app/config.json")
    assert content == '{"key": "value"}'

    assert len(uv.filesystem_changes) == 1
    orchestrator.close()


def test_batch_creation_performance_10k_sandboxes():
    """AC1: Prove ability to launch 10,000 isolated agent sandboxes in under 5 seconds."""
    orchestrator = UniverseOrchestrator(max_workers=16)
    
    t0 = time.time()
    nodes = orchestrator.create_universes_batch(count=10000, name_prefix="perf-node")
    elapsed = time.time() - t0

    assert len(nodes) == 10000
    assert len(orchestrator.universes) == 10000
    assert elapsed < 5.0, f"Performance target breached! 10k sandboxes took {elapsed:.3f} seconds (target: <5.0s)"

    sample_first = orchestrator.get_universe("uv-00000")
    sample_last = orchestrator.get_universe("uv-09999")
    assert sample_first is not None
    assert sample_last is not None
    assert sample_first.status == UniverseStatus.RUNNING
    assert sample_last.status == UniverseStatus.RUNNING
    orchestrator.close()


def test_universe_lifecycle_ops():
    orchestrator = UniverseOrchestrator()
    uv = orchestrator.create_universe(name="lifecycle-test")

    assert uv.status == UniverseStatus.RUNNING

    orchestrator.pause_universe(uv.id)
    assert uv.status == UniverseStatus.PAUSED

    orchestrator.resume_universe(uv.id)
    assert uv.status == UniverseStatus.RUNNING

    orchestrator.destroy_universe(uv.id)
    assert orchestrator.get_universe(uv.id) is None
    assert uv.status == UniverseStatus.DESTROYED
    orchestrator.close()


def test_rust_orchestrator_bridge():
    bridge = RustOrchestratorBridge(use_rust=False)
    elapsed = bridge.benchmark_launch_time(count=1000)
    assert elapsed < 2.0
    assert len(bridge.orchestrator.universes) == 1000
    bridge.orchestrator.close()
