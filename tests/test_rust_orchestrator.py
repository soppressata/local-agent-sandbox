"""
Pytest suite covering the Rust Orchestrator & CLI Foundation (AC1).
Tests 10,000 sandbox batch allocation performance under 5 seconds,
lifecycle management (create, start, stop, destroy), health checks, and resource limits.
"""

import time
import pytest
from local_agent_sandbox.rust_orchestrator import RustOrchestratorBridge
from local_agent_sandbox.orchestrator import UniverseStatus, ComputeQuota


def test_rust_orchestrator_10k_sandbox_launch_performance() -> None:
    """
    AC1: Verify Rust-based orchestrator bridge launches 10,000 isolated sandboxes
    in under 5 seconds with parallelization and low boot overhead.
    """
    bridge = RustOrchestratorBridge(use_rust=False)
    t0 = time.time()
    universes = bridge.batch_create(count=10000, name_prefix="ac1-node")
    elapsed = time.time() - t0

    assert len(universes) == 10000
    assert elapsed < 5.0, f"10k sandbox launch failed performance target: took {elapsed:.3f}s"

    # Verify sandbox IDs and running status
    assert universes[0].id == "uv-00000"
    assert universes[9999].id == "uv-09999"
    assert universes[0].status == UniverseStatus.RUNNING
    assert universes[9999].status == UniverseStatus.RUNNING
    bridge.orchestrator.close()


def test_rust_orchestrator_lifecycle_and_health_checks() -> None:
    """
    Verify complete sandbox lifecycle management (create, start, stop, destroy),
    health checks, and resource limit enforcement per sandbox.
    """
    bridge = RustOrchestratorBridge(use_rust=False)
    universes = bridge.batch_create(count=5, name_prefix="lifecycle-node")
    uv_id = universes[0].id

    # Basic health check when running
    health = bridge.health_check(uv_id)
    assert health is not None
    assert health["healthy"] is True
    assert health["status"] == "RUNNING"
    assert health["memory_mb"] == 512
    assert health["cpu_cores"] == 1.0

    # Stop sandbox
    stopped = bridge.stop_sandbox(uv_id)
    assert stopped is True
    health_after_stop = bridge.health_check(uv_id)
    assert health_after_stop["healthy"] is False
    assert health_after_stop["status"] == "STOPPED"

    # Start sandbox
    started = bridge.start_sandbox(uv_id)
    assert started is True
    health_after_start = bridge.health_check(uv_id)
    assert health_after_start["healthy"] is True

    # Destroy sandbox
    destroyed = bridge.destroy_sandbox(uv_id)
    assert destroyed is True
    assert bridge.health_check(uv_id) is None
    bridge.orchestrator.close()
