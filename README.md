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
- **Namespace Isolation**: When `isolate_filesystem` is `True` (default), the sandbox builds a real rootless jail:
  1. Unshares user, mount, UTS, and IPC namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWUTS`, `CLONE_NEWIPC`).
  2. Writes `/proc/self/uid_map` and `/proc/self/gid_map` so the process is fake-root only inside its own user namespace.
  3. Makes mounts private, then chroots into a minimal jail whose root contains **read-only** bind mounts of host `/bin`, `/usr`, `/lib`, and `/lib64` (whichever exist), a minimal `/dev` (null/zero/full/random/urandom/tty), and a **read-write** bind of the sandbox work directory at `/workspace`.
  4. Drops privileges with `setgid(65534)` / `setuid(65534)` (`nobody:nogroup`).
  Host paths outside those bind mounts (e.g. `/etc`, `/home`, `/tmp`) are invisible inside the jail. If any isolation step fails, execution is refused (no silent fallback to an unisolated process).
- **Resource Limits**: Restricts the process using `resource.setrlimit` on CPU time, virtual memory address space (RLIMIT_AS, defaulted to 1GB), maximum file size (RLIMIT_FSIZE, defaulted to 100MB), and process count (RLIMIT_NPROC, defaulted to 4096).
- **Dangerous Command Guardrails**: A secondary defense-in-depth tokenizer parses commands using `shlex.split` to block dangerous command patterns (such as bypasses of `rm -rf /*`, `find / -delete`, redirects or writing to `/etc/shadow`, `.ssh`, `.aws`, and fork bombs).
- **Execution Timeouts**: Enforces hard wall-clock timeouts on long-running commands.
- **Environment Isolation**: Sanitizes environment variables to prevent host API key leakage.
- **Optional `rmbr` Integration**: Stores security policy violations in local `rmbr` memory.

---

### Getting Started

Follow these four quick steps to set up and run your first secure sandbox command in under 5 minutes.

#### Step 1: Installation

Install the package via `pip`:

```bash
pip install local-agent-sandbox
```

*Note: If you plan to use `rmbr` security memory integration, install with the optional dependency group:*
```bash
pip install "local-agent-sandbox[memory]"
```

#### Step 2: First Run (CLI)

Verify your installation by running a simple echo command in the sandbox CLI:

```bash
agent-sandbox run "echo 'Hello from CLI sandbox!'"
```

#### Step 3: First Run (Python API)

Create a Python script (e.g. `quickstart.py`) with the following copy-pasteable, complete, and verified code to run your first command and inspect the result:

```python
from local_agent_sandbox import LocalAgentSandbox, SandboxConfig

# 1. Initialize the sandbox with a 10-second timeout limit
config = SandboxConfig(max_timeout_seconds=10.0)
sandbox = LocalAgentSandbox(config=config)

try:
    # 2. Execute a basic bash command safely
    result = sandbox.execute("echo 'Hello from the sandbox!'")
    
    # 3. Print all properties of the returned SandboxResult object
    print("--- SandboxResult Properties ---")
    print(f"Command:      {result.command}")
    print(f"Exit Code:    {result.exit_code}")
    print(f"Stdout:       {result.stdout.strip()}")
    print(f"Stderr:       {result.stderr.strip()}")
    print(f"Duration:     {result.duration_ms:.2f} ms")
    print(f"Sandbox Dir:  {result.sandboxed_dir}")
    print(f"Blocked:      {result.blocked}")
    print(f"Block Reason: {result.block_reason}")

finally:
    # 4. Always clean up temporary directories to prevent disk clutter
    sandbox.cleanup()
```

#### Step 4: Troubleshooting & Common Gotchas

Here are key patterns and behaviors to keep in mind when working with the sandbox:

1. **Namespace Isolation Permission Issues**:
   Filesystem isolation requires:
   - Linux unprivileged user namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`)
   - The `uidmap` package (`newuidmap` / `newgidmap`) plus subordinate ID ranges in `/etc/subuid` and `/etc/subgid` (so the jail can map and drop to `nobody` / 65534)
   If isolation cannot be established, the command is refused — it will **not** silently run unisolated. Enable user namespaces and install helpers:
   ```bash
   sysctl -w kernel.unprivileged_userns_clone=1
   sudo apt-get install -y uidmap   # Debian/Ubuntu
   ```
   Or disable filesystem isolation explicitly if not needed (command blocklist still applies):
   ```python
   config = SandboxConfig(isolate_filesystem=False)
   ```
   Inside the jail only these host paths are visible: `/bin`, `/usr`, `/lib`, `/lib64` (read-only, if present on the host), a synthetic `/dev`, and the sandbox work directory mounted read-write at `/workspace`.

2. **Cleaning Up Temp Directories**:
   The sandbox creates dynamic directories under `/tmp` to isolate workspace files. To avoid filling up disk space, **always** call `sandbox.cleanup()` (ideally in a `try...finally` block).

3. **Environment Variable Filtering**:
   To prevent host API key leakage, the sandbox runs commands with a highly restricted set of environment variables (by default: `PATH`, `LANG`, `LC_ALL`, `PYTHONPATH`, `HOME`, `TERM`).
   - If your commands require specific environment variables, pass them explicitly using `env_overrides`:
     ```python
     result = sandbox.execute("echo $API_KEY", env_overrides={"API_KEY": "secret_key"})
     ```
   - Alternatively, add custom variables to the allowed list in `SandboxConfig`:
     ```python
     config = SandboxConfig(allowed_env_vars=["PATH", "CUSTOM_VAR"])
     ```

---

### Detailed Usage Examples

#### Handling Blocked Commands

The sandbox includes robust defense-in-depth safety filters. If a command tries to touch sensitive paths (e.g. `/etc/shadow`, `.ssh`, `.aws`) or perform dangerous operations, the execution is blocked immediately before starting the process:

```python
from local_agent_sandbox import LocalAgentSandbox

sandbox = LocalAgentSandbox()

try:
    result = sandbox.execute("rm -rf /etc/shadow")
    if result.blocked:
        print(f"❌ Command Blocked! Reason: {result.block_reason}")
        print(f"Exit Code: {result.exit_code}")  # Blocked commands return exit code 126
finally:
    sandbox.cleanup()
```

#### Handling Execution Timeouts

You can set wall-clock limits on long-running commands to prevent hung processes:

```python
from local_agent_sandbox import LocalAgentSandbox, SandboxConfig

# Set a strict 2-second timeout
config = SandboxConfig(max_timeout_seconds=2.0)
sandbox = LocalAgentSandbox(config=config)

try:
    result = sandbox.execute("sleep 5")
    if result.exit_code == 124:
        print("🕒 Command execution timed out!")
        print(f"Stderr: {result.stderr}")
finally:
    sandbox.cleanup()
```

---

### CLI Usage

The CLI tool allows running command-line sandboxing out of the box.

```bash
# Execute command with default configuration
agent-sandbox run "ls -la"

# Execute command with customized timeout and directory
agent-sandbox run "sleep 5" --timeout 10.0 --dir "/tmp/my_custom_sandbox"
```

---

<div align="center">
  <sub>Maintained by soppressata. Zero bloat, maximum performance.</sub>
</div>
