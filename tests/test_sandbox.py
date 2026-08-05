import os
import pytest
from local_agent_sandbox import LocalAgentSandbox, SandboxConfig, PolicyMemoryEngine


def test_basic_command_execution():
    sandbox = LocalAgentSandbox()
    res = sandbox.execute("echo 'Hello Sandbox'")
    assert res.exit_code == 0
    assert "Hello Sandbox" in res.stdout
    assert res.blocked is False
    assert res.duration_ms < 500.0
    sandbox.cleanup()


def test_dangerous_command_blocking():
    sandbox = LocalAgentSandbox()
    res = sandbox.execute("rm -rf /")
    assert res.blocked is True
    assert res.exit_code == 126
    assert "Forbidden dangerous command" in res.stderr
    sandbox.cleanup()


def test_execution_timeout():
    config = SandboxConfig(max_timeout_seconds=0.5)
    sandbox = LocalAgentSandbox(config=config)
    res = sandbox.execute("sleep 2")
    assert res.blocked is True
    assert res.exit_code == 124
    assert "timed out" in res.stderr
    sandbox.cleanup()


def test_policy_memory_engine():
    engine = PolicyMemoryEngine(enabled=True)
    engine.record_violation("rm -rf /", "Forbidden pattern")
    results = engine.search_policy_violations("Violation")
    assert isinstance(results, list)
