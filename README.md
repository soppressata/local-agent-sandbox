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
   Under the hood, filesystem isolation requires Linux user and mount namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`). If your environment (e.g. some Docker containers, CI pipelines, or specific Linux configurations) restricts unprivileged user namespaces, the sandbox will try to fall back gracefully. If you require strict namespace isolation, ensure your Linux kernel has user namespace cloning enabled:
   ```bash
   sysctl -w kernel.unprivileged_userns_clone=1
   ```
   Or disable filesystem namespace isolation explicitly if not needed:
   ```python
   config = SandboxConfig(isolate_filesystem=False)
   ```

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

### Trustfile-governed runs with `sandboxctl`

`sandboxctl` is the policy-first control plane. Every run is governed by a
`trustfile.yaml` v1 profile, produces a machine-readable receipt, and appends
that receipt to a versioned, Ed25519-signed JSONL ledger.

```bash
# Run an image under a trustfile profile; exits 0 only if the policy was fully enforced
sandboxctl run trustfile.yaml "python build.py"

# Inspect a stored receipt, filter the ledger, and export an SBOM for audit
sandboxctl logs <receipt-id>
sandboxctl query 'exit_code=0 and fully_enforced=true'
sandboxctl query 'image contains "build"'
sandboxctl sbom <receipt-id> --pubkey keys/ed25519_public.pem
```

Receipts are stored under `<XDG_DATA_HOME>/local-agent-sandbox/receipts/v1/`
(default `~/.local/share/...`) and the node signing keypair under
`<XDG_CONFIG_HOME>/local-agent-sandbox/keys/`. Override both with
`--receipt-dir` and `--keys-dir`.

---

### Migration guide: legacy `SandboxConfig` to `trustfile.yaml`

Prior to `sandboxctl`, sandboxing was configured programmatically with
`SandboxConfig` (or the `agent-sandbox run` options). A trustfile v1 profile is
the declarative, auditable replacement: it is validated against a JSON Schema,
reproducibly digested, and recorded in every signed receipt.

#### 1. Field-by-field mapping

| `SandboxConfig` field | `trustfile.yaml v1` location | Notes |
| --------------------- | ---------------------------- | ----- |
| `max_timeout_seconds` | `resources.time_s` | Wall-clock cap in seconds. |
| `max_memory_mb` | `resources.mem_mb` | Address-space (RLIMIT_AS) cap in MiB. |
| `max_disk_mb` | `resources.disk_mb` | File-size (RLIMIT_FSIZE) cap in MiB. |
| `max_cpu_cores` | `resources.cpu` | CPU cores pinned via `sched_setaffinity`. |
| `blocked_commands` | *(guardrail layer)* | Still enforced by the local backend; recorded as a `guardrails` check. |
| `isolate_filesystem` | *(backend behavior)* | Namespace isolation remains a backend property, not a profile field. |
| `allowed_env_vars` | *(backend behavior)* | Environment sanitization remains a backend property. |

#### 2. Automatic conversion

`sandboxctl migrate-config` converts a legacy config file (JSON or YAML) into a
trustfile v1 profile:

```bash
# Write the migrated trustfile to a file
sandboxctl migrate-config sandbox_config.json trustfile.yaml

# Or print it to stdout
sandboxctl migrate-config sandbox_config.yaml
```

#### 3. Manual example

Given this legacy config:

```python
config = SandboxConfig(
    max_timeout_seconds=60.0,
    max_memory_mb=512,
    max_disk_mb=200,
    max_cpu_cores=2,
)
```

the equivalent trustfile is:

```yaml
version: "1"
name: "migrated"
resources:
  cpu: 2.0
  mem_mb: 512
  disk_mb: 200
  time_s: 60.0
```

To go further than the legacy model could express, add `syscalls`, `network`
egress rules, `mounts`, `secrets`, and an optional `expiry` to the same file.

#### 4. Behavior changes to expect

- **Exit code contract**: `agent-sandbox run` returns the sandboxed command's
  exit code. `sandboxctl run` returns `0` only when the trustfile policy was
  *fully enforced*; `1` when a check failed (or the local backend could not
  enforce a declared policy dimension and it failed closed); `2` for an invalid
  trustfile.
- **Receipts are the audit trail**: every `sandboxctl run` records a signed
  receipt (image, node, resource caps, enforcement checks, mounts). Keep the
  ledger and keypair — `sandboxctl query` and `sandboxctl sbom` depend on them.
- **No silent enforcement**: if the local backend cannot apply a declared rule
  (e.g. a custom syscall allowlist or an egress `deny` rule), the run fails
  closed rather than proceeding unenforced.

---

<div align="center">
  <sub>Maintained by soppressata. Zero bloat, maximum performance.</sub>
</div>
