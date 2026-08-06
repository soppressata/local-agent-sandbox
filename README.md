<div align="center">

  <h1>local-agent-sandbox</h1>

  <p>Sub-10ms process isolation container for AI coding agents.</p>

  <p>
    <a href="https://github.com/soppressata/local-agent-sandbox">
      <img src="https://img.shields.io/badge/version-v0.1.0-0F172A?style=for-the-badge&labelColor=1E293B" alt="Version" />
    </a>
    <a href="https://github.com/soppressata/local-agent-sandbox">
      <img src="https://img.shields.io/badge/License-MIT-0F172A?style=for-the-badge&labelColor=1E293B" alt="License" />
    </a>
  </p>

</div>

---

### Overview

`local-agent-sandbox` is a lightweight, zero-dependency process isolation container built for AI coding agents executing untrusted bash commands. It leverages Linux namespaces and resource limits as the primary security boundaries, supplemented by robust token-parsing command filters as defense-in-depth.

### Key Features

- **Sub-10ms Startup**: Launches isolated process sandboxes without heavy virtual machine or container daemon overhead.
- **Namespace Isolation**: When `isolate_filesystem` is `True` (default), the sandbox unshares user, mount, UTS, and IPC namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`). This runs the sandboxed process as `nobody:nogroup` to isolate it from modifying the host system.
- **Resource Limits**: Restricts the process using `resource.setrlimit` on CPU time, virtual memory address space (RLIMIT_AS, defaulted to 1GB), maximum file size (RLIMIT_FSIZE, defaulted to 100MB), and process count (RLIMIT_NPROC, defaulted to 4096).
- **Dangerous Command Guardrails**: A secondary defense-in-depth tokenizer parses commands using `shlex.split` to block dangerous command patterns (such as bypasses of `rm -rf /*`, `find / -delete`, redirects or writing to `/etc/shadow`, `.ssh`, `.aws`, and fork bombs).
- **Execution Timeouts**: Enforces hard wall-clock timeouts on long-running commands.
- **Environment Isolation**: Sanitizes environment variables to prevent host API key leakage.
- **Optional `rmbr` Integration**: Stores security policy violations in local `rmbr` memory.

### Installation

```bash
pip install local-agent-sandbox
```

### Quickstart

```python
from local_agent_sandbox import LocalAgentSandbox, SandboxConfig

sandbox = LocalAgentSandbox(config=SandboxConfig(max_timeout_seconds=10.0))

# Execute bash command safely
result = sandbox.execute("echo 'Running in sandbox'")
print(f"Exit Code: {result.exit_code} ({result.duration_ms:.1f}ms)")
print(result.stdout)

sandbox.cleanup()
```

### CLI Usage

```bash
agent-sandbox run "ls -la"
```

---

<div align="center">
  <sub>Maintained by soppressata. Zero bloat, maximum performance.</sub>
</div>
