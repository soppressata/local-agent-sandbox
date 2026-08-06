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

    # Test Virtual Filesystem (COW)
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

    # Verify random samples
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

    orchestrator.stop_universe(uv.id)
    assert uv.status == UniverseStatus.STOPPED

    orchestrator.start_universe(uv.id)
    assert uv.status == UniverseStatus.RUNNING

    orchestrator.destroy_universe(uv.id)
    assert orchestrator.get_universe(uv.id) is None
    assert uv.status == UniverseStatus.DESTROYED
    orchestrator.close()


def test_universe_health_and_resource_limits():
    orchestrator = UniverseOrchestrator()
    quota = ComputeQuota(cpu_cores=2.0, memory_mb=1024, max_threads=128, max_processes=32)
    uv = orchestrator.create_universe(name="health-test", quota=quota)

    health = uv.health_check()
    assert health["healthy"] is True
    assert health["status"] == "RUNNING"
    assert health["memory_mb"] == 1024
    assert health["cpu_cores"] == 2.0
    assert health["max_threads"] == 128
    assert health["max_processes"] == 32

    # Check orchestrator health query
    orch_health = orchestrator.get_universe_health(uv.id)
    assert orch_health is not None
    assert orch_health["healthy"] is True

    # Check serialization
    info = uv.to_dict()
    assert info["quota"]["max_threads"] == 128
    assert info["quota"]["max_processes"] == 32

    # Stop and verify health check reflects stopped state
    uv.stop()
    health_stopped = uv.health_check()
    assert health_stopped["healthy"] is False
    assert health_stopped["status"] == "STOPPED"

    orchestrator.close()


def test_rust_orchestrator_bridge():
    bridge = RustOrchestratorBridge(use_rust=False)
    elapsed = bridge.benchmark_launch_time(count=1000)
    assert elapsed < 2.0
    assert len(bridge.orchestrator.universes) == 1000

    uv_id = list(bridge.orchestrator.universes.keys())[0]
    health = bridge.health_check(uv_id)
    assert health is not None and health["healthy"] is True

    assert bridge.stop_sandbox(uv_id) is True
    assert bridge.start_sandbox(uv_id) is True
    assert bridge.destroy_sandbox(uv_id) is True
    bridge.orchestrator.close()


def test_rust_orchestrator_10k_batch_and_error_handling():
    """Verify 10,000 sandbox creation performance via Rust bridge and non-existent ID handling."""
    bridge = RustOrchestratorBridge(use_rust=False)
    t0 = time.time()
    nodes = bridge.batch_create(count=10000, name_prefix="rust-10k")
    elapsed = time.time() - t0

    assert len(nodes) == 10000
    assert elapsed < 5.0, f"10k sandboxes via Rust bridge took {elapsed:.3f}s"

    # Test health check and lifecycle on non-existent universe ID
    assert bridge.health_check("uv-nonexistent") is None
    assert bridge.start_sandbox("uv-nonexistent") is False
    assert bridge.stop_sandbox("uv-nonexistent") is False
    assert bridge.destroy_sandbox("uv-nonexistent") is False
    bridge.orchestrator.close()


def test_agent_task_execution_normal_and_default_timeout(tmp_path):
    """
    Tests that an agent task completes successfully and defaults to 3600 seconds timeout when unspecified.
    """
    orchestrator = UniverseOrchestrator()
    uv = orchestrator.create_universe(name="task-test-uv")
    log_file = str(tmp_path / "task_result.json")

    # Run quick command without specifying timeout (should default to 3600s)
    res = orchestrator.run_task(
        command="echo 'Task Execution Normal'",
        universe_id=uv.id,
        log_file=log_file,
    )

    assert res.status == "SUCCESS"
    assert res.exit_code == 0
    assert "Task Execution Normal" in res.stdout
    assert res.timeout_seconds == 3600
    assert res.error is None

    # Verify task result log file was created with TIMEOUT / SUCCESS status
    import json
    with open(log_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "SUCCESS"
    assert data["timeout_seconds"] == 3600

    orchestrator.close()


def test_agent_task_timeout_exceeded_and_process_termination(tmp_path):
    """
    Tests that when an agent task exceeds the configured timeout:
    1. The process and child processes spawned are gracefully terminated.
    2. The status is recorded as TIMEOUT_EXCEEDED in the task result log.
    """
    orchestrator = UniverseOrchestrator()
    uv = orchestrator.create_universe(name="timeout-test-uv")
    log_file = str(tmp_path / "timeout_result.json")

    # Launch a task with a child process that sleeps longer than configured timeout (0.5s)
    hanging_command = "python3 -c 'import time, subprocess; subprocess.Popen([\"sleep\", \"10\"]); time.sleep(10)'"

    t0 = time.time()
    res = orchestrator.run_task(
        command=hanging_command,
        timeout=1,
        universe_id=uv.id,
        log_file=log_file,
    )
    elapsed = time.time() - t0

    assert elapsed < 5.0  # Must be terminated quickly near timeout limit (1s)
    assert res.status == "TIMEOUT_EXCEEDED"
    assert res.timeout_seconds == 1
    assert "exceeded maximum execution timeout" in res.error

    # Verify error reporting in task result log file
    import json
    with open(log_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "TIMEOUT_EXCEEDED"
    assert data["timeout_seconds"] == 1
    assert "exceeded maximum execution timeout" in data["error"]

    # Verify universe log recorded timeout status
    assert any("TIMEOUT_EXCEEDED" in log for log in uv.logs)

    orchestrator.close()
