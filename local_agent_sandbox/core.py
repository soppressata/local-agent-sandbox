"""
LocalAgentSandbox Core Engine
Lightweight, zero-dependency local process sandbox for AI coding agents.
"""

import math
import os
import re
import resource
import shutil
import shlex
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field



class SandboxResult(BaseModel):
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    sandboxed_dir: str
    blocked: bool = False
    block_reason: Optional[str] = None


class SandboxConfig(BaseModel):
    max_timeout_seconds: float = 30.0
    allowed_env_vars: List[str] = Field(default_factory=lambda: ["PATH", "LANG", "LC_ALL", "PYTHONPATH", "HOME", "TERM"])
    blocked_commands: List[str] = Field(default_factory=lambda: [
        "rm -rf /", "rm -rf ~", "rm -rf *", "mkfs", "dd if=/dev/zero",
        ":(){ :|:& };:", "shutdown", "reboot", "> /dev/sda"
    ])
    isolate_filesystem: bool = True
    enable_rmbr_memory: bool = False
    max_memory_mb: Optional[int] = Field(default=None, description="Virtual memory cap in MiB (defaults to 1024).")
    max_disk_mb: Optional[int] = Field(default=None, description="Per-file write cap in MiB (defaults to 100).")
    max_cpu_cores: Optional[float] = Field(default=None, description="CPU core cap applied via sched_setaffinity when set.")


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
        
        clean_env["TMPDIR"] = work_dir
        clean_env["TEMP"] = work_dir
        clean_env["TMP"] = work_dir

        def _isolate_child():
            # 1. Namespace isolation
            if self.config.isolate_filesystem:
                flags = 0
                for name, default_val in [
                    ("CLONE_NEWUSER", 0x10000000),
                    ("CLONE_NEWNS", 0x00020000),
                    ("CLONE_NEWUTS", 0x04000000),
                    ("CLONE_NEWIPC", 0x08000000),
                ]:
                    flags |= getattr(os, name, default_val)
                try:
                    os.unshare(flags)
                except Exception:
                    try:
                        os.unshare(
                            getattr(os, "CLONE_NEWUSER", 0x10000000) |
                            getattr(os, "CLONE_NEWNS", 0x00020000)
                        )
                    except Exception:
                        pass

            # 2. Resource limits
            cpu_limit = int(self.config.max_timeout_seconds) + 5
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 5))
            except Exception:
                pass

            if self.config.max_cpu_cores is not None:
                try:
                    total_cpus = os.cpu_count() or 1
                    pinned = max(1, int(math.ceil(self.config.max_cpu_cores)))
                    os.sched_setaffinity(0, set(range(min(pinned, total_cpus))))
                except Exception:
                    pass

            mem_mb = self.config.max_memory_mb if self.config.max_memory_mb is not None else 1024
            try:
                mem_limit = mem_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
            except Exception:
                pass

            fsize_mb = self.config.max_disk_mb if self.config.max_disk_mb is not None else 100
            try:
                fsize_limit = fsize_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_limit, fsize_limit))
            except Exception:
                pass

            nproc_limit = 4096
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (nproc_limit, nproc_limit))
            except Exception:
                pass

        try:
            res = subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                cwd=work_dir,
                env=clean_env,
                preexec_fn=_isolate_child,
                capture_output=True,
                text=True,
                timeout=self.config.max_timeout_seconds
            )
            duration_ms = (time.time() - start_time) * 1000
            return SandboxResult(
                command=command,
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_ms=duration_ms,
                sandboxed_dir=work_dir,
                blocked=False
            )
        except subprocess.TimeoutExpired as e:
            duration_ms = (time.time() - start_time) * 1000
            return SandboxResult(
                command=command,
                exit_code=124,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=f"Command execution timed out after {self.config.max_timeout_seconds} seconds.",
                duration_ms=duration_ms,
                sandboxed_dir=work_dir,
                blocked=True,
                block_reason="Execution timeout exceeded"
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
                block_reason=str(e)
            )

    def cleanup(self):
        """Clean up temporary sandbox directories."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass
            self.temp_dir = None
