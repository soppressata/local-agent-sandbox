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

`local-agent-sandbox` is a lightweight, zero-dependency process isolation container built for AI coding agents executing untrusted bash commands.

### Key Features

- **Sub-10ms Startup**: Launches isolated process sandboxes without heavy Docker container overhead.
- **Dangerous Command Guardrails**: Prevents destructive operations (`rm -rf /`, system file alteration).
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
