import os
import tempfile
import time
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
    assert res.status == "TIMEOUT_EXCEEDED"
    sandbox.cleanup()


def test_default_timeout_is_one_hour():
    assert SandboxConfig().max_timeout_seconds == 3600.0


def test_successful_run_has_success_status():
    sandbox = LocalAgentSandbox()
    res = sandbox.execute("echo ok")
    assert res.status == "SUCCESS"
    sandbox.cleanup()


def test_timeout_terminates_child_processes(tmp_path):
    # The timed-out command spawns a background child (via `sleep 5 &`) that
    # outlives the parent shell unless the whole process group is signalled.
    # Have the child write a marker file after it wakes up; if the child was
    # properly killed, the marker must never appear.
    marker = tmp_path / "child_survived"
    config = SandboxConfig(max_timeout_seconds=0.5, isolate_filesystem=False)
    sandbox = LocalAgentSandbox(config=config)
    res = sandbox.execute(f"(sleep 1 && touch {marker}) & sleep 2")
    assert res.status == "TIMEOUT_EXCEEDED"
    time.sleep(1.5)  # give the child a chance to run if it wasn't actually killed
    assert not marker.exists(), "child process survived the timeout and wrote its marker"
    sandbox.cleanup()


def test_policy_memory_engine():
    engine = PolicyMemoryEngine(enabled=True)
    engine.record_violation("rm -rf /", "Forbidden pattern")
    results = engine.search_policy_violations("Violation")
    assert isinstance(results, list)


def test_isolate_filesystem_flag_behavior():
    config_isolated = SandboxConfig(isolate_filesystem=True)
    sandbox_isolated = LocalAgentSandbox(config=config_isolated)
    res_uid = sandbox_isolated.execute("id -u")
    res_gid = sandbox_isolated.execute("id -g")
    assert res_uid.exit_code == 0, res_uid.stderr
    assert res_gid.exit_code == 0, res_gid.stderr
    assert res_uid.stdout.strip() == "65534"
    assert res_gid.stdout.strip() == "65534"
    sandbox_isolated.cleanup()

    config_host = SandboxConfig(isolate_filesystem=False)
    sandbox_host = LocalAgentSandbox(config=config_host)
    res_host = sandbox_host.execute("whoami")
    assert res_host.exit_code == 0
    current_user = getpass.getuser()
    assert current_user in res_host.stdout.strip()
    sandbox_host.cleanup()


def test_resource_limits_enforcement():
    config = SandboxConfig(max_timeout_seconds=1.0)
    sandbox = LocalAgentSandbox(config=config)

    res = sandbox.execute("echo 'small content' > small.txt && cat small.txt")
    assert res.exit_code == 0, res.stderr
    assert "small content" in res.stdout

    res_large = sandbox.execute("dd if=/dev/zero of=large.bin bs=1M count=110")
    assert res_large.exit_code != 0
    err = res_large.stderr.lower()
    assert (
        "file size limit exceeded" in err
        or "file too large" in err
        or res_large.exit_code in [-25, 153, 254]
    )

    sandbox.cleanup()


def test_robust_guardrails_blocked_bypasses():
    sandbox = LocalAgentSandbox()

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


def test_isolation_blocks_host_file_writes():
    fd, host_path = tempfile.mkstemp(prefix="las_host_probe_")
    os.close(fd)
    original = b"untouched-host-content\n"
    with open(host_path, "wb") as f:
        f.write(original)

    sandbox = LocalAgentSandbox(config=SandboxConfig(isolate_filesystem=True))
    try:
        res = sandbox.execute(f"echo pwned > {host_path}")
        assert res.blocked is False, res.stderr
        with open(host_path, "rb") as f:
            assert f.read() == original
    finally:
        sandbox.cleanup()
        os.unlink(host_path)


def test_isolation_drops_to_nobody():
    sandbox = LocalAgentSandbox(config=SandboxConfig(isolate_filesystem=True))
    try:
        res_u = sandbox.execute("id -u")
        res_g = sandbox.execute("id -g")
        assert res_u.exit_code == 0, res_u.stderr
        assert res_g.exit_code == 0, res_g.stderr
        assert res_u.stdout.strip() == "65534"
        assert res_g.stdout.strip() == "65534"
    finally:
        sandbox.cleanup()


def test_isolation_hides_host_paths():
    sandbox = LocalAgentSandbox(config=SandboxConfig(isolate_filesystem=True))
    try:
        res_shadow = sandbox.execute("cat /etc/shadow")
        assert res_shadow.exit_code != 0
        assert res_shadow.blocked is False
        combined = (res_shadow.stdout + res_shadow.stderr).lower()
        assert "no such file" in combined or "not found" in combined or "cannot open" in combined

        res_os = sandbox.execute("cat /etc/os-release")
        assert res_os.exit_code != 0
        combined_os = (res_os.stdout + res_os.stderr).lower()
        assert "no such file" in combined_os or "not found" in combined_os or "cannot open" in combined_os
    finally:
        sandbox.cleanup()


def test_workspace_is_writable_inside_jail():
    sandbox = LocalAgentSandbox(config=SandboxConfig(isolate_filesystem=True))
    try:
        res = sandbox.execute("echo hello > out.txt && cat out.txt && id -u")
        assert res.exit_code == 0, res.stderr
        assert "hello" in res.stdout
        assert "65534" in res.stdout
    finally:
        sandbox.cleanup()
