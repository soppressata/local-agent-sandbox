"""
Tests for Four-Layer Policy Enforcement, Secret Vault, Run Receipts,
Anti-Regression Suite, and Sandboxctl Live Enforcement Counters.
"""

import json
import pytest
from local_agent_sandbox.isolation import (
    KernelPolicy,
    FilesystemPolicy,
    NetworkEgressProxy,
    SecretVault,
    PolicyEnforcementEngine,
    RunReceipt,
    SecurityViolation,
    EnforcementCounters,
    GLOBAL_COUNTERS,
    AntiRegressionSuite,
)
from local_agent_sandbox.cli import main as cli_main


@pytest.fixture(autouse=True)
def reset_counters():
    GLOBAL_COUNTERS.reset()
    yield
    GLOBAL_COUNTERS.reset()


def test_kernel_policy_syscall_allowlist():
    policy = KernelPolicy(allowlist={"read", "write", "exit"})
    receipt = RunReceipt()

    # Allowed syscall
    assert policy.validate_syscall("read", receipt=receipt) is True
    assert len(receipt.events) == 1
    assert receipt.events[0]["allowed"] is True

    # Disallowed syscall
    with pytest.raises(SecurityViolation, match="Kernel isolation breach"):
        policy.validate_syscall("ptrace", receipt=receipt)

    assert GLOBAL_COUNTERS.kernel_violations == 1
    assert len(receipt.violations) == 1
    assert receipt.violations[0]["details"]["syscall"] == "ptrace"
    assert receipt.success is False


def test_filesystem_policy_mount_modes():
    fs_policy = FilesystemPolicy(mounts={
        "/": "ro",
        "/workspace": "rw",
        "/proc/kcore": "masked",
    })
    receipt = RunReceipt()

    # Read/write inside rw mount
    assert fs_policy.validate_access("/workspace/code.py", is_write=True, receipt=receipt) is True

    # Write inside ro mount
    with pytest.raises(SecurityViolation, match="Attempted write to read-only mount"):
        fs_policy.validate_access("/usr/bin/python", is_write=True, receipt=receipt)

    # Access inside masked mount
    with pytest.raises(SecurityViolation, match="masked mount"):
        fs_policy.validate_access("/proc/kcore", is_write=False, receipt=receipt)

    assert GLOBAL_COUNTERS.filesystem_violations == 2
    assert len(receipt.violations) == 2


def test_network_egress_proxy():
    proxy = NetworkEgressProxy(allowed_patterns=["*.github.com", "127.0.0.1"])
    receipt = RunReceipt()

    # Allowed egress
    assert proxy.validate_egress("api.github.com", port=443, receipt=receipt) is True
    assert GLOBAL_COUNTERS.network_egress_allowed == 1

    # Denied egress
    with pytest.raises(SecurityViolation, match="Network egress proxy breach"):
        proxy.validate_egress("evil-tracker.com", port=443, receipt=receipt)

    assert GLOBAL_COUNTERS.network_egress_denied == 1
    assert len(receipt.violations) == 1
    assert receipt.violations[0]["details"]["host"] == "evil-tracker.com"


def test_secret_vault_trustfile_negotiation_and_redaction():
    vault = SecretVault(trustfile_secret_key="secret-key")
    receipt = RunReceipt()

    # Unauthorized negotiation attempt
    with pytest.raises(SecurityViolation, match="Invalid trustfile signature"):
        vault.inject_secret("API_KEY", "super-secret-token-12345", "INVALID_SIG", receipt=receipt)

    # Authorized negotiation & injection
    key_hash = vault.inject_secret("API_KEY", "super-secret-token-12345", "TRUSTED_TEST_SIG", receipt=receipt)
    assert key_hash is not None
    assert receipt.secret_hashes["API_KEY"] == key_hash

    # Verify secret redaction: plaintext secrets must NEVER appear in receipts or logs
    raw_log = "Error accessing API_KEY with super-secret-token-12345 on line 10"
    redacted = receipt.redact_text(raw_log, raw_secrets={"API_KEY": "super-secret-token-12345"})
    assert "super-secret-token-12345" not in redacted
    assert "[REDACTED:" in redacted


def test_anti_regression_suite_four_workloads():
    suite = AntiRegressionSuite()
    all_passed, receipt = suite.run_all(universe_id="test-uv-001")

    assert all_passed is True
    assert receipt.success is False  # Receipts mark success=False when violations occur
    assert len(receipt.violations) >= 4

    # Verify all four workloads recorded their respective violations
    layers_violated = {v["layer"] for v in receipt.violations}
    assert "network" in layers_violated
    assert "filesystem" in layers_violated
    assert "kernel" in layers_violated
    assert "resource" in layers_violated

    metrics = receipt.metrics
    assert metrics["workload_a_passed"] is True
    assert metrics["workload_b_passed"] is True
    assert metrics["workload_c_passed"] is True
    assert metrics["workload_d_passed"] is True
    assert metrics["all_workloads_blocked_and_recorded"] is True


def test_sandboxctl_status_cli(capsys):
    # Perform operations to populate counters
    policy = KernelPolicy()
    try:
        policy.validate_syscall("reboot")
    except SecurityViolation:
        pass

    # Test status CLI output
    ret = cli_main(["status"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Kernel Syscall Violations:" in captured.out
    assert "Total Policy Violations:" in captured.out

    # Test JSON status CLI output
    ret_json = cli_main(["status", "--json"])
    assert ret_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert "kernel_violations" in data
    assert data["kernel_violations"] >= 1
