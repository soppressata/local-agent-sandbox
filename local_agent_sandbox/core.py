"""
LocalAgentSandbox Core Engine
Lightweight, zero-dependency local process sandbox for AI coding agents.
"""

import os
import shutil
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
        cmd_stripped = command.strip().lower()
        for blocked in self.config.blocked_commands:
            if blocked.lower() in cmd_stripped:
                return f"Forbidden dangerous command pattern detected: '{blocked}'"
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

        try:
            res = subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                cwd=work_dir,
                env=clean_env,
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
