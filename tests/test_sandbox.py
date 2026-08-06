import os
import time
import pytest
import getpass
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
    # Test standard pattern
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


def test_execution_timeout_records_timout_status():
    config = SandboxConfig(max_timeout_seconds=0.5)
    sandbox = LocalAgentSandbox(config=config)
    res = sandbox.execute("sleep 2")
    assert res.status == "TIMEOUT_EXCEEDED"
    assert res.block_reason == "Execution timeout exceeded"
    sandbox.cleanup()


def test_timeout_terminates_child_processes():
    config = SandboxConfig(max_timeout_seconds=1.0)
    sandbox = LocalAgentSandbox(config=config)
    # Background a child, record its PID, then block the shell until the timeout.
    res = sandbox.execute("sleep 30 & echo $! > child.pid; wait")
    assert res.exit_code == 124
    assert res.status == "TIMEOUT_EXCEEDED"

    pid_file = os.path.join(res.sandboxed_dir, "child.pid")
    with open(pid_file) as f:
        child_pid = int(f.read().strip())

    # The spawned child must not survive the sandbox timeout.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail(f"child process {child_pid} survived the sandbox timeout")

    sandbox.cleanup()


def test_policy_memory_engine():
    engine = PolicyMemoryEngine(enabled=True)
    engine.record_violation("rm -rf /", "Forbidden pattern")
    results = engine.search_policy_violations("Violation")
    assert isinstance(results, list)


def test_isolate_filesystem_flag_behavior():
    # When isolate_filesystem is True, the process runs in a user namespace as 'nobody'
    config_isolated = SandboxConfig(isolate_filesystem=True)
    sandbox_isolated = LocalAgentSandbox(config=config_isolated)
    res_isolated = sandbox_isolated.execute("whoami")
    assert res_isolated.exit_code == 0
    assert "nobody" in res_isolated.stdout.strip()
    sandbox_isolated.cleanup()

    # When isolate_filesystem is False, it runs as the host user
    config_host = SandboxConfig(isolate_filesystem=False)
    sandbox_host = LocalAgentSandbox(config=config_host)
    res_host = sandbox_host.execute("whoami")
    assert res_host.exit_code == 0
    current_user = getpass.getuser()
    assert current_user in res_host.stdout.strip()
    sandbox_host.cleanup()


def test_resource_limits_enforcement():
    # We can test timeout limit and file size limit
    # The default file size limit in core.py is 100MB, but let's test if we can run within limits
    # and if we trigger timeout
    config = SandboxConfig(max_timeout_seconds=1.0)
    sandbox = LocalAgentSandbox(config=config)
    
    # Writing a small file should succeed
    res = sandbox.execute("echo 'small content' > small.txt && cat small.txt")
    assert res.exit_code == 0
    assert "small content" in res.stdout
    
    # Try writing a file larger than 100MB limit (or check limit triggering via dd)
    # The file size limit is 100MB, writing 110MB should trigger File size limit exceeded
    # 110 * 1024 * 1024 / 1024 / 1024 = 110
    res_large = sandbox.execute("dd if=/dev/zero of=large.bin bs=1M count=110")
    # It should be terminated by signal 25 (SIGXFSZ) or fail
    assert res_large.exit_code != 0
    assert "File size limit exceeded" in res_large.stderr or res_large.exit_code in [-25, 153, 254]
    
    sandbox.cleanup()


def test_robust_guardrails_blocked_bypasses():
    sandbox = LocalAgentSandbox()
    
    # Guardrail bypasses that must be blocked
    bypasses = [
        "rm -rf /*",
        "rm -fr /",
        "rm -rf *",
        "find / -delete",
        "find /etc -delete",
        "find ~/.ssh -delete",
        "printf 'key' > /etc/shadow",
        "echo 'pubkey' >> ~/.ssh/authorized_keys",
        "cat exploit &> ~/.aws/credentials",
        "echo 'data' | tee /etc/shadow",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "dd if=/dev/zero of=~/.ssh/id_rsa",
        "shutdown -h now",
        "reboot",
        ":(){ :|:& };:",
        " : ( ) { : | : & } ; : "
    ]
    
    for cmd in bypasses:
        res = sandbox.execute(cmd)
        assert res.blocked is True
        assert res.exit_code == 126
        assert "Forbidden dangerous command" in res.stderr
        
    sandbox.cleanup()
