"""
Unit tests for configurable execution timeout per agent session.
"""

import time
import pytest
from local_agent_sandbox.orchestrator import (
    SandboxConfig,
    AgentSession,
    UniverseOrchestrator,
)


def test_sandbox_config_default_execution_timeout():
    """Acceptance Criteria 1: The sandbox configuration accepts execution_timeout_seconds (default: 3600)."""
    cfg = SandboxConfig()
    assert cfg.execution_timeout_seconds == 3600

    custom_cfg = SandboxConfig(execution_timeout_seconds=30)
    assert custom_cfg.execution_timeout_seconds == 30

    cfg_dict = custom_cfg.to_dict()
    assert cfg_dict["execution_timeout_seconds"] == 30

    restored = SandboxConfig.from_dict({"execution_timeout_seconds": 120, "cpu_cores": 2.0})
    assert restored.execution_timeout_seconds == 120
    assert restored.cpu_cores == 2.0


def test_agent_session_timeout_termination_and_status():
    """
    Acceptance Criteria 2 & 3:
    - If a session exceeds execution_timeout_seconds, terminates process and returns TimeoutError status.
    - Logged in session execution history.
    """
    config = SandboxConfig(execution_timeout_seconds=1)
    session = AgentSession(config=config)

    assert session.config.execution_timeout_seconds == 1
    assert session.status == "CREATED"
    assert len(session.execution_history) == 0

    res = session.execute(["sleep", "10"])

    assert res.status == "TimeoutError"
    assert session.status == "TimeoutError"
    assert "exceeded timeout" in res.error.lower()

    # Verify execution history logging
    assert len(session.execution_history) == 1
    event = session.execution_history[0]
    assert event["status"] == "TimeoutError"
    assert event["event"] == "timeout"
    assert event["timeout_seconds"] == 1
    assert "sleep" in str(event["command"])


def test_agent_session_successful_execution():
    """Verify normal task execution within time limit updates execution history and status."""
    config = SandboxConfig(execution_timeout_seconds=10)
    session = AgentSession(config=config)

    res = session.execute(["echo", "hello world"])

    assert res.status == "SUCCESS"
    assert res.exit_code == 0
    assert "hello world" in res.stdout
    assert session.status == "SUCCESS"

    assert len(session.execution_history) == 1
    event = session.execution_history[0]
    assert event["status"] == "SUCCESS"
    assert event["event"] == "execution_complete"


def test_orchestrator_create_session_with_timeout():
    """Verify UniverseOrchestrator creates AgentSession with custom timeout."""
    orchestrator = UniverseOrchestrator()
    session = orchestrator.create_session(execution_timeout_seconds=2)

    assert session.config.execution_timeout_seconds == 2
    res = session.run(["sleep", "5"])

    assert res.status == "TimeoutError"
    assert session.status == "TimeoutError"
    assert len(session.execution_history) == 1
    orchestrator.close()
