"""
LocalAgentSandbox Core Engine
Lightweight, zero-dependency local process sandbox for AI coding agents.
"""

import os
import re
import resource
import shutil
import shlex
import signal
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

from local_agent_sandbox.jail import JailSetupError, run_jailed



class SandboxResult(BaseModel):
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    sandboxed_dir: str
    blocked: bool = False
    block_reason: Optional[str] = None
    status: str = "SUCCESS"


class SandboxConfig(BaseModel):
    max_timeout_seconds: float = 3600.0
    allowed_env_vars: List[str] = Field(default_factory=lambda: ["PATH", "LANG", "LC_ALL", "PYTHONPATH", "HOME", "TERM"])
    blocked_commands: List[str] = Field(default_factory=lambda: [
        "rm -rf /", "rm -rf ~", "rm -rf *", "mkfs", "dd if=/dev/zero",
        ":(){ :|:& };:", "shutdown", "reboot", "> /dev/sda"
    ])
    isolate_filesystem: bool = True
    enable_rmbr_memory: bool = False


class LocalAgentSandbox:
    """Sub-10ms local process isolation container for AI agents."""

    def __init__(self, config: Optional[SandboxConfig] = None, sandbox_dir: Optional[str] = None):
        self.config = config or SandboxConfig()
        self.custom_dir = sandbox_dir
        self.temp_dir: Optional[str] = None

    def _setup_sandbox_dir(self) -> str:
        if self.custom_dir:
            os.makedirs(self.custom_dir, exist_ok=True)
            return self.custom_dir
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="agent_sandbox_")
        return self.temp_dir

    def is_command_blocked(self, command: str) -> Optional[str]:
        cmd_stripped = command.strip()
        
        # Fork bomb detection
        fork_bomb_pattern = re.compile(r':\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:')
        if fork_bomb_pattern.search(cmd_stripped) or ":(){ :|:& };:" in cmd_stripped.replace(" ", ""):
            return "Forbidden dangerous command pattern detected: fork bomb"

        # Base substring match for a few hardcoded patterns that may not parse easily
        for blocked in self.config.blocked_commands:
            if blocked.lower() in cmd_stripped.lower():
                if blocked in ["shutdown", "reboot", "mkfs"]:
                    return f"Forbidden dangerous command pattern detected: '{blocked}'"

        try:
            tokens = shlex.split(cmd_stripped)
        except Exception:
            tokens = cmd_stripped.split()

        normalized_tokens = [t.strip() for t in tokens]
        
        system_prefixes = ['/etc', '/bin', '/boot', '/dev', '/lib', '/opt', '/run', '/sbin', '/sys', '/usr', '/var', '/proc', '/root']

        def is_sensitive_path(path: str) -> bool:
            p = path.lower()
            if p in ['/', '/*', '~', '~/*', '*']:
                return True
            if any(x in p for x in ['.ssh', '.aws', '/etc/shadow']):
                return True
            for sys_pref in system_prefixes:
                if p == sys_pref or p.startswith(sys_pref + '/'):
                    return True
            return False

        for i, token in enumerate(normalized_tokens):
            token_lower = token.lower()
            token_base = token_lower.split('/')[-1]

            # 1. rm checks
            if token_base == 'rm':
                for sub_token in normalized_tokens[i+1:]:
                    if sub_token.startswith('-'):
                        continue
                    if is_sensitive_path(sub_token):
                        return f"Forbidden dangerous command pattern detected: rm on sensitive path '{sub_token}'"
                if '*' in cmd_stripped:
                    return "Forbidden dangerous command pattern detected: rm with glob '*'"

            # 2. find checks
            if token_base == 'find':
                has_delete = '-delete' in normalized_tokens[i+1:]
                if has_delete:
                    for sub_token in normalized_tokens[i+1:]:
                        if sub_token == '-delete':
                            break
                        if sub_token.startswith('-'):
                            continue
                        if is_sensitive_path(sub_token):
                            return f"Forbidden dangerous command pattern detected: find on sensitive path '{sub_token}' with -delete"

            # 3. Redirect checks
            if any(op in token for op in ['>', '>>', '&>', '1>', '2>']):
                if i + 1 < len(normalized_tokens):
                    target = normalized_tokens[i+1]
                    if is_sensitive_path(target):
                        return f"Forbidden dangerous command pattern detected: redirect to sensitive path '{target}'"

            # 4. tee checks
            if token_base == 'tee':
                for sub_token in normalized_tokens[i+1:]:
                    if sub_token.startswith('-'):
                        continue
                    if is_sensitive_path(sub_token):
                        return f"Forbidden dangerous command pattern detected: tee to sensitive path '{sub_token}'"

            # 5. dd checks
            if token_base == 'dd':
                for sub_token in normalized_tokens[i+1:]:
                    if sub_token.lower().startswith('of='):
                        target = sub_token.split('=', 1)[1]
                        if is_sensitive_path(target):
                            return f"Forbidden dangerous command pattern detected: dd writing to '{sub_token}'"

            # 6. Basic command names
            if token_base in ['mkfs', 'shutdown', 'reboot']:
                return f"Forbidden dangerous command pattern detected: '{token_base}'"

        return None

    def execute(self, command: str, env_overrides: Optional[Dict[str, str]] = None) -> SandboxResult:
        """Execute command inside isolated sandbox environment."""
        start_time = time.time()
        
        # Check command safety guardrails
        block_reason = self.is_command_blocked(command)
        if block_reason:
            return SandboxResult(
                command=command,
                exit_code=126,
                stdout="",
                stderr=block_reason,
                duration_ms=(time.time() - start_time) * 1000,
                sandboxed_dir="",
                blocked=True,
                block_reason=block_reason
            )

        work_dir = self._setup_sandbox_dir()

        # Build clean environment variables
        clean_env = {}
        for var in self.config.allowed_env_vars:
            if var in os.environ:
                clean_env[var] = os.environ[var]
        
        if env_overrides:
            clean_env.update(env_overrides)
        
        timeout_s = self.config.max_timeout_seconds

        def _apply_rlimits():
            cpu_limit = int(timeout_s) + 5
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 5))
            except Exception:
                pass

            mem_limit = 1024 * 1024 * 1024  # 1 GB
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
            except Exception:
                pass

            fsize_limit = 100 * 1024 * 1024  # 100 MB
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_limit, fsize_limit))
            except Exception:
                pass

            nproc_limit = 4096
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (nproc_limit, nproc_limit))
            except Exception:
                pass

        try:
            if self.config.isolate_filesystem:
                clean_env["TMPDIR"] = "/workspace"
                clean_env["TEMP"] = "/workspace"
                clean_env["TMP"] = "/workspace"
                clean_env["HOME"] = "/workspace"
                if "PATH" not in clean_env:
                    clean_env["PATH"] = "/usr/bin:/bin"

                code, stdout, stderr = run_jailed(
                    command=command,
                    work_dir=work_dir,
                    env=clean_env,
                    timeout_seconds=timeout_s,
                    pre_exec=_apply_rlimits,
                )
                duration_ms = (time.time() - start_time) * 1000
                if code == 124 and "timed out" in stderr:
                    return SandboxResult(
                        command=command,
                        exit_code=124,
                        stdout=stdout,
                        stderr=stderr,
                        duration_ms=duration_ms,
                        sandboxed_dir=work_dir,
                        blocked=True,
                        block_reason="Execution timeout exceeded",
                        status="TIMEOUT_EXCEEDED",
                    )
                return SandboxResult(
                    command=command,
                    exit_code=code,
                    stdout=stdout,
                    stderr=stderr,
                    duration_ms=duration_ms,
                    sandboxed_dir=work_dir,
                    blocked=False,
                )

            clean_env["TMPDIR"] = work_dir
            clean_env["TEMP"] = work_dir
            clean_env["TMP"] = work_dir

            # start_new_session=True puts the command in its own process group so that
            # on timeout we can signal the whole group, not just the direct child -
            # otherwise any process the command itself spawns (e.g. a shell pipeline,
            # or the command backgrounding work) survives the timeout and keeps
            # running, which is exactly what AC2 ("terminates the agent process and
            # any child processes it spawned") requires we not allow.
            proc = subprocess.Popen(
                command,
                shell=True,
                executable="/bin/bash",
                cwd=work_dir,
                env=clean_env,
                preexec_fn=_apply_rlimits,
                start_new_session=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=self.config.max_timeout_seconds)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    stdout, stderr = proc.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    stdout, stderr = proc.communicate()
                duration_ms = (time.time() - start_time) * 1000
                return SandboxResult(
                    command=command,
                    exit_code=124,
                    stdout=stdout or "",
                    stderr=(stderr or "") + f"\nCommand execution timed out after "
                                             f"{self.config.max_timeout_seconds} seconds.",
                    duration_ms=duration_ms,
                    sandboxed_dir=work_dir,
                    blocked=True,
                    block_reason="Execution timeout exceeded",
                    status="TIMEOUT_EXCEEDED",
                )
            duration_ms = (time.time() - start_time) * 1000
            return SandboxResult(
                command=command,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                sandboxed_dir=work_dir,
                blocked=False,
            )
        except JailSetupError as e:
            duration_ms = (time.time() - start_time) * 1000
            return SandboxResult(
                command=command,
                exit_code=1,
                stdout="",
                stderr=f"Sandbox isolation error: {e}",
                duration_ms=duration_ms,
                sandboxed_dir=work_dir,
                blocked=True,
                block_reason=str(e),
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return SandboxResult(
                command=command,
                exit_code=1,
                stdout="",
                stderr=f"Sandbox execution error: {str(e)}",
                duration_ms=duration_ms,
                sandboxed_dir=work_dir,
                blocked=True,
                block_reason=str(e),
            )

    def cleanup(self):
        """Clean up temporary sandbox directories."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass
            self.temp_dir = None
